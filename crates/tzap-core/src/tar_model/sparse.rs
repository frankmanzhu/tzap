use super::restore::{
    create_new_file_options, read_member_bytes, remove_existing_leaf_if_needed,
    PreparedDestination, TarMemberStreamHandler,
};
#[cfg(not(windows))]
use super::restore::sync_directory;
use super::*;

#[cfg(target_os = "linux")]
pub(crate) fn punch_linux_sparse_holes(
    file: &fs::File,
    logical_size: u64,
    extents: &[SparseExtent],
) -> Result<(), FormatError> {
    let mut cursor = 0u64;
    for extent in extents {
        if extent.offset > cursor {
            punch_linux_sparse_hole(file, cursor, extent.offset - cursor)?;
        }
        cursor = extent
            .offset
            .checked_add(extent.length)
            .ok_or(FormatError::InvalidArchive("sparse extent overflow"))?;
    }
    if cursor < logical_size {
        punch_linux_sparse_hole(file, cursor, logical_size - cursor)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn punch_linux_sparse_hole(file: &fs::File, offset: u64, length: u64) -> Result<(), FormatError> {
    if length == 0 {
        return Ok(());
    }
    let offset = libc::off_t::try_from(offset)
        .map_err(|_| FormatError::ReaderUnsupported("sparse offset exceeds Linux off_t"))?;
    let length = libc::off_t::try_from(length)
        .map_err(|_| FormatError::ReaderUnsupported("sparse length exceeds Linux off_t"))?;
    // SAFETY: the descriptor is live and the checked range lies within the logical file.
    if unsafe {
        libc::fallocate(
            file.as_raw_fd(),
            libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
            offset,
            length,
        )
    } != 0
    {
        return Err(FormatError::FilesystemExtractionFailed(
            "failed to preserve Linux sparse holes",
        ));
    }
    Ok(())
}
pub(crate) fn stream_sparse_primary_payload<R, H>(
    reader: &mut R,
    stored_size: u64,
    logical_size: u64,
    remaining: &mut u64,
    handler: &mut H,
) -> Result<(), ExtractError>
where
    R: TarMemberGroupReader,
    H: TarMemberStreamHandler,
{
    if stored_size < TAR_BLOCK_LEN as u64 {
        return Err(FormatError::InvalidArchive("sparse primary map is truncated").into());
    }
    let mut validator = SparseStreamValidator::new(logical_size);
    let mut consumed = 0u64;
    let layout = loop {
        if consumed
            .checked_add(TAR_BLOCK_LEN as u64)
            .is_none_or(|value| value > stored_size)
        {
            return Err(FormatError::InvalidArchive("sparse primary map is truncated").into());
        }
        let mut block = [0u8; TAR_BLOCK_LEN];
        read_member_bytes(reader, &mut block, remaining)?;
        consumed += TAR_BLOCK_LEN as u64;
        validator.observe(&block)?;
        if let Some(layout) = validator.layout_if_map_complete() {
            if layout.map_and_padding_size as u64 == consumed {
                break layout;
            }
        }
    };
    let extent_bytes = layout.extents.iter().try_fold(0u64, |sum, extent| {
        sum.checked_add(extent.length)
            .ok_or(FormatError::InvalidArchive(
                "sparse extent byte count overflow",
            ))
    })?;
    if consumed
        .checked_add(extent_bytes)
        .is_none_or(|value| value != stored_size)
    {
        return Err(FormatError::InvalidArchive(
            "sparse primary stored size does not match its map",
        )
        .into());
    }

    let native_output = handler.begin_sparse_payload(logical_size, &layout.extents)?;
    let zeros = [0u8; 64 * 1024];
    let mut logical_cursor = 0u64;
    let mut buf = [0u8; 64 * 1024];
    for extent in &layout.extents {
        if !native_output {
            write_zero_run(handler, &zeros, extent.offset - logical_cursor)?;
        }
        let mut extent_remaining = extent.length;
        let mut extent_consumed = 0u64;
        while extent_remaining > 0 {
            let chunk_len = extent_remaining.min(buf.len() as u64) as usize;
            read_member_bytes(reader, &mut buf[..chunk_len], remaining)?;
            validator.observe(&buf[..chunk_len])?;
            if native_output {
                handler.write_sparse_extent(extent.offset + extent_consumed, &buf[..chunk_len])?;
            } else {
                handler.write_regular_payload(&buf[..chunk_len])?;
            }
            extent_remaining -= chunk_len as u64;
            extent_consumed += chunk_len as u64;
        }
        logical_cursor = extent.offset + extent.length;
    }
    if native_output {
        handler.finish_sparse_payload()?;
    } else {
        write_zero_run(handler, &zeros, logical_size - logical_cursor)?;
    }
    validator.finish()?;
    Ok(())
}

fn write_zero_run<H: TarMemberStreamHandler>(
    handler: &mut H,
    zeros: &[u8],
    mut len: u64,
) -> Result<(), ExtractError> {
    while len > 0 {
        let chunk_len = len.min(zeros.len() as u64) as usize;
        handler.write_regular_payload(&zeros[..chunk_len])?;
        len -= chunk_len as u64;
    }
    Ok(())
}

pub(crate) fn create_temp_regular_file(
    destination: &PreparedDestination,
) -> Result<(PathBuf, fs::File), FormatError> {
    for _ in 0..1000u32 {
        let mut candidate = destination.leaf.as_os_str().to_os_string();
        candidate.push(format!(".tzap-tmp-{}", uuid::Uuid::new_v4()));
        let leaf = PathBuf::from(candidate);
        match destination
            .parent
            .open_with(&leaf, &create_new_file_options())
        {
            Ok(file) => return Ok((leaf, file.into_std())),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => {
                return Err(FormatError::FilesystemExtractionFailed(
                    "failed to create regular file",
                ));
            }
        }
    }
    Err(FormatError::FilesystemExtractionFailed(
        "failed to create regular file",
    ))
}

#[cfg(windows)]
pub(crate) fn prepare_windows_sparse_file(
    file: &fs::File,
    logical_size: u64,
) -> Result<(), FormatError> {
    use std::os::windows::io::AsRawHandle;
    use std::ptr;
    use windows_sys::Win32::System::Ioctl::FSCTL_SET_SPARSE;
    use windows_sys::Win32::System::IO::DeviceIoControl;

    let mut bytes_returned = 0u32;
    // SAFETY: the file handle is live; FSCTL_SET_SPARSE accepts null input and output buffers for
    // the default "set sparse" operation, and the call is synchronous.
    if unsafe {
        DeviceIoControl(
            file.as_raw_handle().cast(),
            FSCTL_SET_SPARSE,
            ptr::null(),
            0,
            ptr::null_mut(),
            0,
            &mut bytes_returned,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(FormatError::FilesystemExtractionFailed(
            "destination filesystem cannot mark sparse output",
        ));
    }
    file.set_len(logical_size)
        .map_err(|_| FormatError::FilesystemExtractionFailed("failed to size sparse output"))
}

#[cfg(windows)]
pub(crate) fn query_windows_sparse_ranges(
    file: &fs::File,
    logical_size: u64,
) -> Result<Vec<SparseExtent>, FormatError> {
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;
    use std::ptr;
    use windows_sys::Win32::Foundation::ERROR_MORE_DATA;
    use windows_sys::Win32::System::Ioctl::{
        FILE_ALLOCATED_RANGE_BUFFER, FSCTL_QUERY_ALLOCATED_RANGES,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;

    const QUERY_BATCH: usize = 1024;
    if logical_size == 0 {
        return Ok(Vec::new());
    }
    let logical_size_i64 = i64::try_from(logical_size).map_err(|_| {
        FormatError::FilesystemExtractionFailed("sparse logical size exceeds Windows range API")
    })?;
    let mut query_start = 0u64;
    let mut extents = Vec::<SparseExtent>::new();
    while query_start < logical_size {
        let mut query = FILE_ALLOCATED_RANGE_BUFFER {
            FileOffset: query_start as i64,
            Length: logical_size_i64 - query_start as i64,
        };
        let mut output = [FILE_ALLOCATED_RANGE_BUFFER::default(); QUERY_BATCH];
        let mut bytes_returned = 0u32;
        // SAFETY: the live handle and fixed-size buffers remain valid for this synchronous call.
        let success = unsafe {
            DeviceIoControl(
                file.as_raw_handle().cast(),
                FSCTL_QUERY_ALLOCATED_RANGES,
                (&mut query as *mut FILE_ALLOCATED_RANGE_BUFFER).cast(),
                size_of::<FILE_ALLOCATED_RANGE_BUFFER>() as u32,
                output.as_mut_ptr().cast(),
                size_of::<[FILE_ALLOCATED_RANGE_BUFFER; QUERY_BATCH]>() as u32,
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };
        let error = std::io::Error::last_os_error();
        if success == 0 && error.raw_os_error() != Some(ERROR_MORE_DATA as i32) {
            return Err(FormatError::FilesystemExtractionFailed(
                "failed to query restored sparse ranges",
            ));
        }
        if bytes_returned as usize % size_of::<FILE_ALLOCATED_RANGE_BUFFER>() != 0 {
            return Err(FormatError::FilesystemExtractionFailed(
                "Windows returned a truncated restored sparse range",
            ));
        }
        let count = bytes_returned as usize / size_of::<FILE_ALLOCATED_RANGE_BUFFER>();
        if count > QUERY_BATCH || (success == 0 && count == 0) {
            return Err(FormatError::FilesystemExtractionFailed(
                "restored sparse range query made no progress",
            ));
        }
        let mut next_query_start = query_start;
        for range in &output[..count] {
            if range.FileOffset < 0 || range.Length <= 0 {
                return Err(FormatError::FilesystemExtractionFailed(
                    "Windows returned an invalid restored sparse range",
                ));
            }
            let offset = range.FileOffset as u64;
            let end = offset
                .checked_add(range.Length as u64)
                .ok_or(FormatError::FilesystemExtractionFailed(
                    "restored sparse range overflow",
                ))?
                .min(logical_size);
            if offset >= logical_size || end <= offset {
                return Err(FormatError::FilesystemExtractionFailed(
                    "Windows returned an out-of-bounds restored sparse range",
                ));
            }
            if let Some(previous) = extents.last_mut() {
                let previous_end = previous.offset + previous.length;
                if offset <= previous_end {
                    previous.length = previous_end.max(end) - previous.offset;
                } else {
                    extents.push(SparseExtent {
                        offset,
                        length: end - offset,
                    });
                }
            } else {
                extents.push(SparseExtent {
                    offset,
                    length: end - offset,
                });
            }
            next_query_start = next_query_start.max(end);
        }
        if success != 0 {
            break;
        }
        if next_query_start <= query_start {
            return Err(FormatError::FilesystemExtractionFailed(
                "restored sparse range query did not advance",
            ));
        }
        query_start = next_query_start;
    }
    Ok(extents)
}

#[cfg(windows)]
pub(crate) fn windows_file_system_is_refs(file: &fs::File) -> Result<bool, FormatError> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::GetVolumeInformationByHandleW;

    let mut name = [0u16; 32];
    // SAFETY: the file handle is live, optional outputs are null, and `name` is a writable buffer
    // whose capacity is passed exactly to the synchronous query.
    if unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle().cast(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            name.as_mut_ptr(),
            name.len() as u32,
        )
    } == 0
    {
        return Err(FormatError::FilesystemExtractionFailed(
            "failed to identify Windows destination filesystem",
        ));
    }
    let length = name
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(name.len());
    Ok(String::from_utf16_lossy(&name[..length]).eq_ignore_ascii_case("refs"))
}

#[cfg(windows)]
pub(crate) fn verify_windows_sparse_file(
    file: &fs::File,
    logical_size: u64,
    expected_extents: &[SparseExtent],
) -> Result<(), FormatError> {
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileBasicInfo, GetFileInformationByHandleEx, FILE_BASIC_INFO,
    };

    const FILE_ATTRIBUTE_SPARSE_FILE: u32 = 0x0000_0200;
    let mut basic = FILE_BASIC_INFO::default();
    // SAFETY: the handle is live and the output points to a correctly sized FILE_BASIC_INFO.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle().cast(),
            FileBasicInfo,
            (&mut basic as *mut FILE_BASIC_INFO).cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
        || basic.FileAttributes & FILE_ATTRIBUTE_SPARSE_FILE == 0
    {
        return Err(FormatError::FilesystemExtractionFailed(
            "restored file is not marked sparse",
        ));
    }
    if query_windows_sparse_ranges(file, logical_size)? != expected_extents
        && !windows_file_system_is_refs(file)?
    {
        return Err(FormatError::FilesystemExtractionFailed(
            "restored sparse ranges do not match archive",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn rename_open_file_noreplace(
    file: &fs::File,
    destination_parent: &CapDir,
    destination_leaf: &Path,
) -> Result<(), FormatError> {
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileRenameInfo, GetFinalPathNameByHandleW, SetFileInformationByHandle,
        FILE_NAME_NORMALIZED, FILE_RENAME_INFO, VOLUME_NAME_DOS,
    };

    let leaf = destination_leaf
        .as_os_str()
        .encode_wide()
        .collect::<Vec<_>>();
    if leaf.is_empty() || leaf.contains(&0) {
        return Err(FormatError::UnsafeArchivePath);
    }
    let mut capacity = 512usize;
    let mut name = loop {
        let mut buffer = vec![0u16; capacity];
        // SAFETY: the directory handle is live and `buffer` is writable for its declared length.
        let length = unsafe {
            GetFinalPathNameByHandleW(
                destination_parent.as_raw_handle().cast(),
                buffer.as_mut_ptr(),
                u32::try_from(buffer.len()).map_err(|_| {
                    FormatError::FilesystemExtractionFailed(
                        "destination path buffer exceeds Windows limit",
                    )
                })?,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        } as usize;
        if length == 0 {
            return Err(FormatError::FilesystemExtractionFailed(
                "failed to resolve destination directory handle",
            ));
        }
        if length < buffer.len() {
            buffer.truncate(length);
            break buffer;
        }
        capacity = length
            .checked_add(1)
            .ok_or(FormatError::FilesystemExtractionFailed(
                "destination path length overflow",
            ))?;
    };
    if !name.ends_with(&[b'\\' as u16]) {
        name.push(b'\\' as u16);
    }
    name.extend_from_slice(&leaf);
    let name_byte_len =
        name.len()
            .checked_mul(size_of::<u16>())
            .ok_or(FormatError::FilesystemExtractionFailed(
                "destination file name is too large to publish",
            ))?;
    // Windows' documented FILE_RENAME_INFO allocation formula includes the structure's embedded
    // one-unit FileName field in addition to FileNameLength. Preserve that trailing zeroed space:
    // on ARM64, passing only offset_of(FileName) + FileNameLength can make NTFS consume adjacent
    // bytes as an unintended filename suffix when the exact allocation ends on an 8-byte boundary.
    let byte_len = size_of::<FILE_RENAME_INFO>()
        .checked_add(name_byte_len)
        .ok_or(FormatError::FilesystemExtractionFailed(
            "destination rename buffer overflow",
        ))?;
    let storage_len = byte_len.div_ceil(size_of::<usize>());
    let mut storage = vec![0usize; storage_len];
    let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: `storage` is pointer-aligned and large enough for the fixed structure plus every
    // UTF-16 filename unit. ReplaceIfExists=false gives the required no-clobber publication.
    unsafe {
        (*info).Anonymous.ReplaceIfExists = false;
        (*info).RootDirectory = std::ptr::null_mut();
        (*info).FileNameLength = u32::try_from(name.len() * size_of::<u16>()).map_err(|_| {
            FormatError::FilesystemExtractionFailed("destination filename exceeds Windows limit")
        })?;
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
            name.len(),
        );
        if SetFileInformationByHandle(
            file.as_raw_handle().cast(),
            FileRenameInfo,
            info.cast(),
            u32::try_from(byte_len).map_err(|_| {
                FormatError::FilesystemExtractionFailed(
                    "destination rename buffer exceeds Windows limit",
                )
            })?,
        ) == 0
        {
            let error = std::io::Error::last_os_error();
            return if matches!(error.raw_os_error(), Some(80 | 183)) {
                Err(FormatError::UnsafeOverwrite)
            } else {
                Err(FormatError::FilesystemExtractionFailed(
                    "failed to publish allocation-preserving output",
                ))
            };
        }
    }
    Ok(())
}

pub(crate) fn publish_regular_file(
    destination: &PreparedDestination,
    temp_leaf: &Path,
    temp_file: fs::File,
    options: SafeExtractionOptions,
) -> Result<fs::File, FormatError> {
    if options.overwrite_existing {
        remove_existing_leaf_if_needed(destination)?;
    }

    #[cfg(windows)]
    {
        temp_file.sync_data().map_err(|_| {
            FormatError::FilesystemExtractionFailed("failed to sync regular file data")
        })?;
        if let Err(error) =
            rename_open_file_noreplace(&temp_file, &destination.parent, &destination.leaf)
        {
            let _ = destination.parent.remove_file_or_symlink(temp_leaf);
            return Err(error);
        }
        Ok(temp_file)
    }

    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt as _;

        temp_file.sync_data().map_err(|_| {
            FormatError::FilesystemExtractionFailed("failed to sync regular file data")
        })?;
        let source = CString::new(temp_leaf.as_os_str().as_bytes())
            .map_err(|_| FormatError::UnsafeArchivePath)?;
        let target = CString::new(destination.leaf.as_os_str().as_bytes())
            .map_err(|_| FormatError::UnsafeArchivePath)?;
        // libc does not expose renameat2 on every Linux libc target, so invoke the
        // kernel interface directly. Both names are validated single components
        // beneath the same pinned parent.
        if unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                destination.parent.as_raw_fd(),
                source.as_ptr(),
                destination.parent.as_raw_fd(),
                target.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } != 0
        {
            let error = std::io::Error::last_os_error();
            let _ = destination.parent.remove_file_or_symlink(temp_leaf);
            return if error.raw_os_error() == Some(libc::EEXIST) {
                Err(FormatError::UnsafeOverwrite)
            } else {
                Err(FormatError::FilesystemExtractionFailed(
                    "failed to publish allocation-preserving output",
                ))
            };
        }
        #[cfg(not(windows))]
        {
            // Persist the rename before reporting success: the file data is already
            // synced, and the directory fsync makes the entry durable against power loss.
            sync_directory(&destination.parent)?;
            Ok(temp_file)
        }
    }

    #[cfg(all(not(windows), not(target_os = "linux")))]
    let mut output = match destination
        .parent
        .open_with(&destination.leaf, &create_new_file_options())
    {
        Ok(file) => file.into_std(),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = destination.parent.remove_file_or_symlink(temp_leaf);
            return Err(FormatError::UnsafeOverwrite);
        }
        Err(_) => {
            let _ = destination.parent.remove_file_or_symlink(temp_leaf);
            return Err(FormatError::FilesystemExtractionFailed(
                "failed to create regular file",
            ));
        }
    };

    // The Windows and Linux publish paths never mutate `temp_file`, so the parameter is
    // declared without `mut`; the copy-based path rebinds it mutable.
    #[cfg(all(not(windows), not(target_os = "linux")))]
    let mut temp_file = temp_file;

    #[cfg(all(not(windows), not(target_os = "linux")))]
    let copy_result = temp_file
        .seek(SeekFrom::Start(0))
        .and_then(|_| std::io::copy(&mut temp_file, &mut output))
        .and_then(|_| output.sync_data());

    #[cfg(all(not(windows), not(target_os = "linux")))]
    if copy_result.is_err() {
        let _ = destination.parent.remove_file_or_symlink(&destination.leaf);
        let _ = destination.parent.remove_file_or_symlink(temp_leaf);
        return Err(FormatError::FilesystemExtractionFailed(
            "failed to write regular file",
        ));
    }

    #[cfg(all(not(windows), not(target_os = "linux")))]
    {
        // Persist the directory entry before reporting success, matching the
        // sync-then-rename ordering of the other publish paths.
        sync_directory(&destination.parent)?;
        let _ = destination.parent.remove_file_or_symlink(temp_leaf);
        Ok(output)
    }
}
