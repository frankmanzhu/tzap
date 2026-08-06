use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
#[cfg(windows)]
use tzap_core::encode_v45_sparse_map;
#[cfg(unix)]
use tzap_core::PortablePosixOwner;
#[cfg(target_os = "macos")]
use tzap_core::{canonical_base64_encode, encode_percent_name};
use tzap_core::{
    ArchiveTimestamp, NativeFileMetadata, PortableFileMetadata, PortableModeOrigin, SparseExtent,
};
#[cfg(any(target_os = "macos", windows))]
use tzap_core::{NativeAuxiliaryMetadata, NativeAuxiliaryNameEncoding, RestoreClass};

#[cfg(unix)]
pub(crate) fn readonly_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o7777
}
#[cfg(not(unix))]
pub(crate) fn readonly_mode(metadata: &fs::Metadata) -> u32 {
    if metadata.permissions().readonly() {
        0o444
    } else {
        0o644
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct InputIdentity {
    pub(crate) len: u64,
    pub(crate) mtime: ArchiveTimestamp,
    pub(crate) mode: u32,
    pub(crate) attributes: Option<u32>,
    #[cfg(unix)]
    pub(crate) uid: u64,
    #[cfg(unix)]
    pub(crate) gid: u64,
    #[cfg(unix)]
    pub(crate) raw_mode: u32,
    #[cfg(unix)]
    pub(crate) link_count: u64,
    #[cfg(unix)]
    pub(crate) change_time_seconds: i64,
    #[cfg(unix)]
    pub(crate) change_time_nanoseconds: i64,
    #[cfg(unix)]
    pub(crate) creation_time: Option<ArchiveTimestamp>,
    #[cfg(unix)]
    pub(crate) dev: u64,
    #[cfg(unix)]
    pub(crate) ino: u64,
    #[cfg(windows)]
    pub(crate) creation_time_100ns: u64,
    #[cfg(windows)]
    pub(crate) last_access_time_100ns: u64,
    #[cfg(windows)]
    pub(crate) change_time_100ns: u64,
    #[cfg(windows)]
    pub(crate) file_attributes: u32,
    #[cfg(windows)]
    pub(crate) link_count: u64,
    #[cfg(windows)]
    pub(crate) volume_serial: u64,
    #[cfg(windows)]
    pub(crate) file_index: u64,
}

#[derive(Debug)]
#[cfg(windows)]
pub(crate) fn add_windows_refs_sparse_layout_omission(native: &mut NativeFileMetadata) {
    const HEADER: &str = "tzap-capture-report-v1\n";
    const ROW: &str = "windows-backup-v1\tsparse-layout\tunsupported-filesystem\tReFS%20does%20not%20expose%20exact%20sparse%20ranges";
    if let Some(report) = native
        .auxiliary_records
        .iter_mut()
        .find(|record| record.kind == "tzap.capture-report")
    {
        let text = std::str::from_utf8(&report.payload)
            .expect("internally generated capture reports are UTF-8");
        let mut rows = text
            .strip_prefix(HEADER)
            .expect("internally generated capture report has canonical header")
            .split_terminator('\n')
            .collect::<Vec<_>>();
        rows.push(ROW);
        rows.sort_unstable();
        rows.dedup();
        report.payload = format!("{HEADER}{}\n", rows.join("\n")).into_bytes();
        report.logical_size = report.payload.len() as u64;
        return;
    }
    let payload = format!("{HEADER}{ROW}\n").into_bytes();
    let mut report = NativeAuxiliaryMetadata::new(
        "tzap.capture-report",
        "tzap-core-v1",
        RestoreClass::None,
        payload,
    );
    report.native = false;
    native.auxiliary_records.push(report);
}

#[cfg(target_os = "linux")]
pub(crate) fn query_linux_sparse_extents(
    file: &File,
    logical_size: u64,
) -> io::Result<Option<Vec<SparseExtent>>> {
    use std::os::fd::AsRawFd;

    if logical_size == 0 {
        return Ok(None);
    }
    let end = libc::off_t::try_from(logical_size)
        .map_err(|_| io::Error::other("file size exceeds Linux off_t"))?;
    let fd = file.as_raw_fd();
    let mut cursor: libc::off_t = 0;
    let mut extents = Vec::new();
    while cursor < end {
        // SAFETY: `fd` is live and SEEK_DATA does not mutate caller memory.
        let data = unsafe { libc::lseek(fd, cursor, libc::SEEK_DATA) };
        if data < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENXIO) {
                break;
            }
            if cursor == 0
                && error.raw_os_error().is_some_and(|code| {
                    code == libc::EINVAL || code == libc::EOPNOTSUPP || code == libc::ENOTSUP
                })
            {
                return Ok(None);
            }
            return Err(error);
        }
        // SAFETY: as above, SEEK_HOLE only updates the descriptor offset.
        let hole = unsafe { libc::lseek(fd, data, libc::SEEK_HOLE) };
        if hole < 0 {
            return Err(io::Error::last_os_error());
        }
        let data = u64::try_from(data).map_err(|_| io::Error::other("negative data offset"))?;
        let hole = u64::try_from(hole).map_err(|_| io::Error::other("negative hole offset"))?;
        let hole = hole.min(logical_size);
        if hole <= data {
            return Err(io::Error::other("Linux sparse-range query did not advance"));
        }
        extents.push(SparseExtent {
            offset: data,
            length: hole - data,
        });
        cursor = libc::off_t::try_from(hole)
            .map_err(|_| io::Error::other("sparse offset exceeds Linux off_t"))?;
    }

    let allocated = extents.iter().try_fold(0u64, |sum, extent| {
        sum.checked_add(extent.length)
            .ok_or_else(|| io::Error::other("sparse extent length overflow"))
    })?;
    Ok((allocated < logical_size).then_some(extents))
}

#[cfg(windows)]
pub(crate) fn collect_windows_known_reparse_input(
    input: &Path,
    archive_path: &Path,
    metadata: fs::Metadata,
    out: &mut Vec<InputSpec>,
) -> Result<()> {
    let file = open_windows_metadata_handle(input)
        .with_context(|| format!("failed to open Windows reparse point {}", input.display()))?;
    let mut identity = input_identity(&metadata)
        .with_context(|| format!("failed to identify reparse point {}", input.display()))?;
    augment_windows_input_identity(&mut identity, &file)
        .with_context(|| format!("failed to identify reparse point {}", input.display()))?;
    let reparse_data = query_windows_reparse_data(&file)
        .with_context(|| format!("failed to query reparse point {}", input.display()))?;
    let known = validate_windows_known_reparse_data(&reparse_data)
        .with_context(|| format!("unsupported Windows reparse point {}", input.display()))?;
    let archive_path = archive_path_to_string(archive_path)?;
    let mut portable_metadata = portable_input_metadata(identity, input)?;
    match known {
        WindowsKnownReparse::RelativeSymlink { portable_target } => {
            out.push(InputSpec {
                source: input.to_owned(),
                archive_path,
                entry_kind: SourceEntryKind::Symlink,
                link_target: Some(portable_target),
                mode: readonly_mode(&metadata),
                mtime: identity.mtime,
                portable_metadata,
                size: 0,
                sparse_extents: None,
                identity,
            });
        }
        WindowsKnownReparse::Junction => {
            portable_metadata
                .native
                .primary_pax_records
                .insert("TZAP.windows.reparse-placeholder".into(), b"1".to_vec());
            out.push(InputSpec {
                source: input.to_owned(),
                archive_path,
                entry_kind: SourceEntryKind::ReparseDirectory,
                link_target: None,
                mode: readonly_mode(&metadata),
                mtime: identity.mtime,
                portable_metadata,
                size: 0,
                sparse_extents: None,
                identity,
            });
        }
        WindowsKnownReparse::Opaque => {
            portable_metadata
                .native
                .primary_pax_records
                .insert("TZAP.windows.reparse-placeholder".into(), b"1".to_vec());
            out.push(InputSpec {
                source: input.to_owned(),
                archive_path,
                entry_kind: if metadata.is_dir() {
                    SourceEntryKind::ReparseDirectory
                } else {
                    SourceEntryKind::ReparseRegular
                },
                link_target: None,
                mode: readonly_mode(&metadata),
                mtime: identity.mtime,
                portable_metadata,
                size: 0,
                sparse_extents: None,
                identity,
            });
        }
    }
    Ok(())
}

#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WindowsKnownReparse {
    RelativeSymlink { portable_target: Vec<u8> },
    Junction,
    Opaque,
}

#[cfg(windows)]
pub(crate) fn query_windows_reparse_data(file: &File) -> io::Result<Vec<u8>> {
    use std::os::windows::io::AsRawHandle;
    use std::ptr;
    use windows_sys::Win32::System::Ioctl::FSCTL_GET_REPARSE_POINT;
    use windows_sys::Win32::System::IO::DeviceIoControl;

    const MAX_REPARSE_DATA_BUFFER_SIZE: usize = 16 * 1024;
    let mut buffer = vec![0u8; MAX_REPARSE_DATA_BUFFER_SIZE];
    let mut bytes_returned = 0u32;
    // SAFETY: the handle is live and the fixed output allocation remains valid for this
    // synchronous call. FSCTL_GET_REPARSE_POINT has no input buffer.
    if unsafe {
        DeviceIoControl(
            file.as_raw_handle().cast(),
            FSCTL_GET_REPARSE_POINT,
            ptr::null(),
            0,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
            &mut bytes_returned,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    buffer.truncate(bytes_returned as usize);
    if buffer.len() < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "reparse buffer is truncated",
        ));
    }
    let tag = u32::from_le_bytes(buffer[0..4].try_into().unwrap());
    let declared = usize::from(u16::from_le_bytes([buffer[4], buffer[5]]));
    let header_len = if tag & 0x8000_0000 == 0 { 24 } else { 8 };
    if declared + header_len != buffer.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "reparse buffer length is inconsistent",
        ));
    }
    Ok(buffer)
}

#[cfg(windows)]
pub(crate) fn validate_windows_known_reparse_data(data: &[u8]) -> io::Result<WindowsKnownReparse> {
    const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
    const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
    const SYMLINK_FLAG_RELATIVE: u32 = 1;

    let invalid = |message| io::Error::new(io::ErrorKind::InvalidData, message);
    if data.len() < 8 {
        return Err(invalid("reparse buffer is truncated"));
    }
    let tag = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let payload_len = usize::from(u16::from_le_bytes(data[4..6].try_into().unwrap()));
    let header_len = if tag & 0x8000_0000 == 0 { 24 } else { 8 };
    if payload_len + header_len != data.len() {
        return Err(invalid("reparse buffer length is inconsistent"));
    }
    let (fixed_len, flags) = match tag {
        IO_REPARSE_TAG_SYMLINK => {
            if payload_len < 12 {
                return Err(invalid("symbolic-link reparse payload is truncated"));
            }
            (
                12usize,
                u32::from_le_bytes(data[16..20].try_into().unwrap()),
            )
        }
        IO_REPARSE_TAG_MOUNT_POINT => {
            if payload_len < 8 {
                return Err(invalid("mount-point reparse payload is truncated"));
            }
            (8usize, 0)
        }
        _ => return Ok(WindowsKnownReparse::Opaque),
    };
    let substitute_offset = usize::from(u16::from_le_bytes(data[8..10].try_into().unwrap()));
    let substitute_len = usize::from(u16::from_le_bytes(data[10..12].try_into().unwrap()));
    let print_offset = usize::from(u16::from_le_bytes(data[12..14].try_into().unwrap()));
    let print_len = usize::from(u16::from_le_bytes(data[14..16].try_into().unwrap()));
    if substitute_offset % 2 != 0
        || substitute_len % 2 != 0
        || print_offset % 2 != 0
        || print_len % 2 != 0
    {
        return Err(invalid("reparse path fields are not UTF-16 aligned"));
    }
    let path_buffer = &data[8 + fixed_len..];
    let decode_name = |offset: usize, len: usize| -> io::Result<String> {
        let end = offset
            .checked_add(len)
            .ok_or_else(|| invalid("reparse path range overflows"))?;
        let bytes = path_buffer
            .get(offset..end)
            .ok_or_else(|| invalid("reparse path range exceeds the payload"))?;
        let units = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        let text =
            String::from_utf16(&units).map_err(|_| invalid("reparse path is not valid UTF-16"))?;
        if text.contains('\0') {
            return Err(invalid("reparse path contains NUL"));
        }
        Ok(text)
    };
    let substitute = decode_name(substitute_offset, substitute_len)?;
    let print = decode_name(print_offset, print_len)?;
    if substitute.is_empty() {
        return Err(invalid("reparse substitute name is empty"));
    }

    if tag == IO_REPARSE_TAG_SYMLINK {
        if flags != SYMLINK_FLAG_RELATIVE {
            return Err(invalid(
                "only relative Windows symbolic links are supported",
            ));
        }
        let target = if print.is_empty() { substitute } else { print };
        let target = target.replace('\\', "/").into_bytes();
        if target.is_empty() || target[0] == b'/' || target.contains(&b':') {
            return Err(invalid("Windows symbolic-link target is absolute"));
        }
        Ok(WindowsKnownReparse::RelativeSymlink {
            portable_target: target,
        })
    } else {
        if !substitute.starts_with("\\??\\") || print.is_empty() {
            return Err(invalid("junction path fields are not canonical"));
        }
        Ok(WindowsKnownReparse::Junction)
    }
}

pub(crate) fn input_identity(metadata: &fs::Metadata) -> io::Result<InputIdentity> {
    Ok(InputIdentity {
        len: metadata.len(),
        mtime: archive_timestamp(metadata.modified()?)?,
        mode: readonly_mode(metadata),
        attributes: portable_attributes(metadata),
        #[cfg(unix)]
        uid: {
            use std::os::unix::fs::MetadataExt;
            metadata.uid() as u64
        },
        #[cfg(unix)]
        gid: {
            use std::os::unix::fs::MetadataExt;
            metadata.gid() as u64
        },
        #[cfg(unix)]
        raw_mode: {
            use std::os::unix::fs::MetadataExt;
            metadata.mode()
        },
        #[cfg(unix)]
        link_count: {
            use std::os::unix::fs::MetadataExt;
            metadata.nlink()
        },
        #[cfg(unix)]
        change_time_seconds: {
            use std::os::unix::fs::MetadataExt;
            metadata.ctime()
        },
        #[cfg(unix)]
        change_time_nanoseconds: {
            use std::os::unix::fs::MetadataExt;
            metadata.ctime_nsec()
        },
        #[cfg(unix)]
        creation_time: metadata
            .created()
            .ok()
            .and_then(|time| archive_timestamp(time).ok()),
        #[cfg(unix)]
        dev: {
            use std::os::unix::fs::MetadataExt;
            metadata.dev()
        },
        #[cfg(unix)]
        ino: {
            use std::os::unix::fs::MetadataExt;
            metadata.ino()
        },
        #[cfg(windows)]
        creation_time_100ns: {
            use std::os::windows::fs::MetadataExt;
            metadata.creation_time()
        },
        #[cfg(windows)]
        last_access_time_100ns: {
            use std::os::windows::fs::MetadataExt;
            metadata.last_access_time()
        },
        #[cfg(windows)]
        change_time_100ns: 0,
        #[cfg(windows)]
        file_attributes: {
            use std::os::windows::fs::MetadataExt;
            metadata.file_attributes()
        },
        #[cfg(windows)]
        link_count: 0,
        #[cfg(windows)]
        volume_serial: 0,
        #[cfg(windows)]
        file_index: 0,
    })
}

pub(crate) fn validate_opened_input_identity(
    file: &File,
    expected: InputIdentity,
) -> io::Result<()> {
    let actual_metadata = file.metadata()?;
    let actual = input_identity(&actual_metadata)?;
    #[cfg(windows)]
    let actual = {
        let mut actual = actual;
        augment_windows_input_identity(&mut actual, file)?;
        actual
    };
    if !input_identity_matches_after_read(expected, actual) {
        return Err(io::Error::other("input changed after scan"));
    }
    Ok(())
}

pub(crate) fn input_identity_matches_after_read(
    expected: InputIdentity,
    actual: InputIdentity,
) -> bool {
    #[cfg(windows)]
    {
        let mut expected = expected;
        let mut actual = actual;
        // Opening and reading the file may update LastAccessTime. Preserve the pre-read value in
        // the archive, but exclude this self-induced field from the final source identity check.
        expected.last_access_time_100ns = 0;
        actual.last_access_time_100ns = 0;
        expected == actual
    }
    #[cfg(all(unix, not(windows)))]
    {
        expected == actual
    }
    #[cfg(not(any(unix, windows)))]
    {
        expected == actual
    }
}

#[cfg(windows)]
pub(crate) fn augment_windows_input_identity(
    identity: &mut InputIdentity,
    file: &File,
) -> io::Result<()> {
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileBasicInfo, GetFileInformationByHandle, GetFileInformationByHandleEx,
        BY_HANDLE_FILE_INFORMATION, FILE_BASIC_INFO,
    };

    let handle = file.as_raw_handle().cast();
    let mut basic = FILE_BASIC_INFO::default();
    // SAFETY: `handle` is live and both output pointers reference correctly sized structures.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileBasicInfo,
            (&mut basic as *mut FILE_BASIC_INFO).cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut by_handle = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `handle` is live and `by_handle` is a valid writable output structure.
    if unsafe { GetFileInformationByHandle(handle, &mut by_handle) } == 0 {
        return Err(io::Error::last_os_error());
    }
    identity.creation_time_100ns = basic.CreationTime as u64;
    identity.last_access_time_100ns = basic.LastAccessTime as u64;
    identity.change_time_100ns = basic.ChangeTime as u64;
    identity.file_attributes = basic.FileAttributes;
    identity.link_count = u64::from(by_handle.nNumberOfLinks);
    identity.volume_serial = u64::from(by_handle.dwVolumeSerialNumber);
    identity.file_index =
        (u64::from(by_handle.nFileIndexHigh) << 32) | u64::from(by_handle.nFileIndexLow);
    Ok(())
}

#[cfg(windows)]
pub(crate) fn query_windows_allocated_ranges(
    file: &File,
    logical_size: u64,
) -> io::Result<Vec<SparseExtent>> {
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;
    use std::ptr;
    use windows_sys::Win32::Foundation::ERROR_MORE_DATA;
    use windows_sys::Win32::System::Ioctl::{
        FILE_ALLOCATED_RANGE_BUFFER, FSCTL_QUERY_ALLOCATED_RANGES,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;

    const QUERY_BATCH: usize = 1024;
    const MAX_EXTENTS: usize = 1_048_576;
    if logical_size == 0 {
        return Ok(Vec::new());
    }
    // FSCTL_QUERY_ALLOCATED_RANGES is not supported by ReFS. Retrieval pointers do not resolve
    // the ambiguity: ReFS reports LCN -1 for a run that may be either a hole or partially
    // allocated. Materialize the logical bytes and pair this fallback with an authenticated
    // sparse-layout omission so the archive cannot claim exact storage-layout fidelity.
    if windows_file_system_is_refs(file)? {
        return Ok(vec![SparseExtent {
            offset: 0,
            length: logical_size,
        }]);
    }
    let logical_size_i64 = i64::try_from(logical_size)
        .map_err(|_| io::Error::other("sparse logical size exceeds Windows range API"))?;
    let mut query_start = 0u64;
    let mut extents = Vec::<SparseExtent>::new();
    while query_start < logical_size {
        let mut query = FILE_ALLOCATED_RANGE_BUFFER {
            FileOffset: i64::try_from(query_start)
                .map_err(|_| io::Error::other("sparse query offset exceeds Windows range API"))?,
            Length: logical_size_i64 - query_start as i64,
        };
        let mut output = [FILE_ALLOCATED_RANGE_BUFFER::default(); QUERY_BATCH];
        let mut bytes_returned = 0u32;
        // SAFETY: the live file handle and fixed-size input/output buffers remain valid for the
        // synchronous DeviceIoControl call, and the byte lengths exactly match those buffers.
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
        let error = io::Error::last_os_error();
        if success == 0 && error.raw_os_error() != Some(ERROR_MORE_DATA as i32) {
            return Err(error);
        }
        if bytes_returned as usize % size_of::<FILE_ALLOCATED_RANGE_BUFFER>() != 0 {
            return Err(io::Error::other(
                "Windows returned a truncated allocated-range row",
            ));
        }
        let count = bytes_returned as usize / size_of::<FILE_ALLOCATED_RANGE_BUFFER>();
        if count > QUERY_BATCH || (success == 0 && count == 0) {
            return Err(io::Error::other(
                "Windows allocated-range query made no progress",
            ));
        }
        let mut next_query_start = query_start;
        for range in &output[..count] {
            if range.FileOffset < 0 || range.Length <= 0 {
                return Err(io::Error::other(
                    "Windows returned an invalid allocated range",
                ));
            }
            let offset = range.FileOffset as u64;
            let end = offset
                .checked_add(range.Length as u64)
                .ok_or_else(|| io::Error::other("Windows allocated range overflow"))?
                .min(logical_size);
            if offset >= logical_size || end <= offset {
                return Err(io::Error::other(
                    "Windows returned an out-of-bounds allocated range",
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
            if extents.len() > MAX_EXTENTS {
                return Err(io::Error::other(
                    "sparse extent count exceeds revision-45 limit",
                ));
            }
            next_query_start = next_query_start.max(end);
        }
        if success != 0 {
            break;
        }
        if next_query_start <= query_start {
            return Err(io::Error::other(
                "Windows allocated-range query did not advance",
            ));
        }
        query_start = next_query_start;
    }
    Ok(extents)
}

#[cfg(windows)]
pub(crate) fn windows_file_system_is_refs(file: &File) -> io::Result<bool> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::GetVolumeInformationByHandleW;

    let mut name = [0u16; 32];
    // SAFETY: the file handle is live, optional outputs are null, and `name` is writable for the
    // exact capacity supplied to this synchronous query.
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
        return Err(io::Error::last_os_error());
    }
    let length = name
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(name.len());
    Ok(String::from_utf16_lossy(&name[..length]).eq_ignore_ascii_case("refs"))
}

#[cfg(windows)]
pub(crate) fn open_windows_metadata_handle(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

pub(crate) struct IdentityCheckedInputReader {
    pub(crate) file: File,
    pub(crate) expected: InputIdentity,
    pub(crate) remaining: u64,
    pub(crate) validated: bool,
}

pub(crate) struct SparseExtentInputReader<'a> {
    pub(crate) file: File,
    pub(crate) expected: InputIdentity,
    pub(crate) expected_extents: &'a [SparseExtent],
    pub(crate) extent_index: usize,
    pub(crate) extent_remaining: u64,
    pub(crate) validated: bool,
}

#[cfg(target_os = "macos")]
pub(crate) enum MacosResourceForkSource {
    File { owner: File, fork: File },
    Symlink(File),
}

#[cfg(target_os = "macos")]
pub(crate) fn open_macos_symlink(input: &Path) -> io::Result<File> {
    use std::ffi::CString;
    use std::os::fd::FromRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;

    const O_SYMLINK: libc::c_int = 0x0020_0000;
    let path = CString::new(input.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))?;
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC | O_SYMLINK) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn open_macos_resource_fork_for_read(
    owner: File,
) -> io::Result<MacosResourceForkSource> {
    use std::ffi::OsString;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::ffi::OsStringExt as _;
    use std::os::unix::fs::MetadataExt as _;

    let mut path = vec![0u8; libc::PATH_MAX as usize];
    if unsafe { libc::fcntl(owner.as_raw_fd(), libc::F_GETPATH, path.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let length = path.iter().position(|byte| *byte == 0).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "macOS returned an unterminated descriptor path",
        )
    })?;
    path.truncate(length);
    path.extend_from_slice(b"/..namedfork/rsrc");
    let fork = File::open(PathBuf::from(OsString::from_vec(path)))?;
    let owner_metadata = owner.metadata()?;
    let fork_metadata = fork.metadata()?;
    if owner_metadata.dev() != fork_metadata.dev() || owner_metadata.ino() != fork_metadata.ino() {
        return Err(io::Error::other(
            "resource fork path no longer identifies the pinned file",
        ));
    }
    Ok(MacosResourceForkSource::File { owner, fork })
}

#[cfg(target_os = "macos")]
pub(crate) struct MacosResourceForkReader {
    pub(crate) source: MacosResourceForkSource,
    pub(crate) expected: InputIdentity,
    pub(crate) logical_size: u64,
    pub(crate) offset: u64,
    pub(crate) validated: bool,
}

#[cfg(target_os = "macos")]
impl MacosResourceForkReader {
    pub(crate) fn new(
        source: MacosResourceForkSource,
        expected: InputIdentity,
        expected_size: Option<u64>,
    ) -> io::Result<Self> {
        let actual = Self::identity(&source)?;
        if actual != expected {
            return Err(io::Error::other(
                "macOS resource-fork owner changed before read",
            ));
        }
        let logical_size = macos_resource_fork_size(&source)?;
        if expected_size.is_some_and(|size| size != logical_size) {
            return Err(io::Error::other(
                "macOS resource fork changed after metadata scan",
            ));
        }
        if matches!(&source, MacosResourceForkSource::Symlink(_))
            && logical_size > u64::from(u32::MAX)
        {
            return Err(io::Error::other(
                "macOS resource fork exceeds Darwin positional xattr limits",
            ));
        }
        Ok(Self {
            source,
            expected,
            logical_size,
            offset: 0,
            validated: false,
        })
    }

    fn identity(source: &MacosResourceForkSource) -> io::Result<InputIdentity> {
        match source {
            MacosResourceForkSource::File { owner, .. } => input_identity(&owner.metadata()?),
            MacosResourceForkSource::Symlink(file) => {
                let metadata = file.metadata()?;
                if !metadata.file_type().is_symlink() {
                    return Err(io::Error::other(
                        "macOS resource-fork owner is no longer a symlink",
                    ));
                }
                input_identity(&metadata)
            }
        }
    }

    fn validate_finished(&mut self) -> io::Result<()> {
        if !self.validated {
            if Self::identity(&self.source)? != self.expected
                || macos_resource_fork_size(&self.source)? != self.logical_size
            {
                return Err(io::Error::other("macOS resource fork changed during read"));
            }
            self.validated = true;
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
impl Read for MacosResourceForkReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.offset == self.logical_size {
            self.validate_finished()?;
            return Ok(0);
        }
        let count =
            usize::try_from((self.logical_size - self.offset).min(out.len() as u64)).unwrap();
        let read = macos_read_resource_fork(&self.source, self.offset, &mut out[..count])?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "macOS resource fork ended before its scanned size",
            ));
        }
        self.offset += read as u64;
        if self.offset == self.logical_size {
            self.validate_finished()?;
        }
        Ok(read)
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_resource_fork_size(source: &MacosResourceForkSource) -> io::Result<u64> {
    use std::ffi::{c_char, c_int, c_void};
    use std::os::fd::AsRawFd as _;

    extern "C" {
        fn fgetxattr(
            fd: c_int,
            name: *const c_char,
            value: *mut c_void,
            size: usize,
            position: u32,
            options: c_int,
        ) -> libc::ssize_t;
    }
    const RESOURCE_FORK: &[u8] = b"com.apple.ResourceFork\0";
    let size = match source {
        MacosResourceForkSource::File { fork, .. } => return Ok(fork.metadata()?.len()),
        MacosResourceForkSource::Symlink(file) => unsafe {
            fgetxattr(
                file.as_raw_fd(),
                RESOURCE_FORK.as_ptr().cast(),
                std::ptr::null_mut(),
                0,
                0,
                0,
            )
        },
    };
    if size < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(size as u64)
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_read_resource_fork(
    source: &MacosResourceForkSource,
    position: u64,
    out: &mut [u8],
) -> io::Result<usize> {
    use std::ffi::{c_char, c_int, c_void};
    use std::os::fd::AsRawFd as _;

    extern "C" {
        fn fgetxattr(
            fd: c_int,
            name: *const c_char,
            value: *mut c_void,
            size: usize,
            position: u32,
            options: c_int,
        ) -> libc::ssize_t;
    }
    const RESOURCE_FORK: &[u8] = b"com.apple.ResourceFork\0";
    let read = match source {
        MacosResourceForkSource::File { fork, .. } => {
            use std::os::unix::fs::FileExt as _;
            return fork.read_at(out, position);
        }
        MacosResourceForkSource::Symlink(file) => unsafe {
            fgetxattr(
                file.as_raw_fd(),
                RESOURCE_FORK.as_ptr().cast(),
                out.as_mut_ptr().cast(),
                out.len(),
                u32::try_from(position).map_err(|_| {
                    io::Error::other("macOS symlink resource fork exceeds Darwin positional limits")
                })?,
                0,
            )
        },
    };
    if read < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(read as usize)
    }
}

#[cfg(windows)]
pub(crate) fn windows_alternate_stream_path(base: &Path, name: &[u8]) -> io::Result<PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};

    if name.len() % 2 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows alternate stream name is not UTF-16LE",
        ));
    }
    let mut stream_path = base.as_os_str().encode_wide().collect::<Vec<_>>();
    stream_path.extend(
        name.chunks_exact(2)
            .map(|unit| u16::from_le_bytes([unit[0], unit[1]])),
    );
    Ok(PathBuf::from(OsString::from_wide(&stream_path)))
}

#[cfg(windows)]
pub(crate) struct WindowsSparseAlternateStreamReader {
    pub(crate) file: File,
    pub(crate) logical_size: u64,
    pub(crate) expected_extents: Vec<SparseExtent>,
    pub(crate) extent_index: usize,
    pub(crate) extent_remaining: u64,
    pub(crate) validated: bool,
}

#[cfg(windows)]
impl WindowsSparseAlternateStreamReader {
    fn validate_finished(&mut self) -> io::Result<()> {
        if !self.validated {
            if self.file.metadata()?.len() != self.logical_size
                || query_windows_allocated_ranges(&self.file, self.logical_size)?
                    != self.expected_extents
            {
                return Err(io::Error::other(
                    "sparse Windows alternate stream changed after scan",
                ));
            }
            self.validated = true;
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Read for WindowsSparseAlternateStreamReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let mut written = 0usize;
        while written < out.len() {
            if self.extent_remaining == 0 {
                let Some(extent) = self.expected_extents.get(self.extent_index) else {
                    self.validate_finished()?;
                    break;
                };
                self.file.seek(SeekFrom::Start(extent.offset))?;
                self.extent_remaining = extent.length;
            }
            let count = (out.len() - written)
                .min(usize::try_from(self.extent_remaining).unwrap_or(usize::MAX));
            let read = self.file.read(&mut out[written..written + count])?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "sparse Windows alternate extent ended before its scanned size",
                ));
            }
            written += read;
            self.extent_remaining -= read as u64;
            if self.extent_remaining == 0 {
                self.extent_index += 1;
            }
        }
        if self.extent_index == self.expected_extents.len() && self.extent_remaining == 0 {
            self.validate_finished()?;
        }
        Ok(written)
    }
}

impl SparseExtentInputReader<'_> {
    fn validate_finished(&mut self) -> io::Result<()> {
        if self.validated {
            return Ok(());
        }
        validate_opened_input_identity(&self.file, self.expected)?;
        #[cfg(windows)]
        if query_windows_allocated_ranges(&self.file, self.expected.len)? != self.expected_extents {
            return Err(io::Error::other(
                "sparse allocated ranges changed after scan",
            ));
        }
        self.validated = true;
        Ok(())
    }
}

impl Read for SparseExtentInputReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let mut written = 0usize;
        while written < out.len() {
            if self.extent_remaining == 0 {
                let Some(extent) = self.expected_extents.get(self.extent_index) else {
                    self.validate_finished()?;
                    break;
                };
                self.file.seek(SeekFrom::Start(extent.offset))?;
                self.extent_remaining = extent.length;
            }
            let count = (out.len() - written)
                .min(usize::try_from(self.extent_remaining).unwrap_or(usize::MAX));
            let read = self.file.read(&mut out[written..written + count])?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "sparse extent ended before its scanned size",
                ));
            }
            written += read;
            self.extent_remaining -= read as u64;
            if self.extent_remaining == 0 {
                self.extent_index += 1;
            }
        }
        if self.extent_index == self.expected_extents.len() && self.extent_remaining == 0 {
            self.validate_finished()?;
        }
        Ok(written)
    }
}

impl Read for IdentityCheckedInputReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            if !self.validated {
                validate_opened_input_identity(&self.file, self.expected)?;
                self.validated = true;
            }
            return Ok(0);
        }
        let max_read = out
            .len()
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        let count = self.file.read(&mut out[..max_read])?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "input ended before its scanned size",
            ));
        }
        self.remaining -= count as u64;
        if self.remaining == 0 {
            validate_opened_input_identity(&self.file, self.expected)?;
            self.validated = true;
        }
        Ok(count)
    }
}

pub(crate) fn archive_timestamp(time: SystemTime) -> io::Result<ArchiveTimestamp> {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => Ok(ArchiveTimestamp::new(
            i64::try_from(duration.as_secs())
                .map_err(|_| io::Error::other("input mtime exceeds revision-45 i64 range"))?,
            duration.subsec_nanos(),
        )),
        Err(error) => {
            let duration = error.duration();
            let (seconds, nanoseconds) = if duration.subsec_nanos() == 0 {
                (-i128::from(duration.as_secs()), 0)
            } else {
                (
                    -i128::from(duration.as_secs()) - 1,
                    1_000_000_000 - duration.subsec_nanos(),
                )
            };
            let seconds = i64::try_from(seconds)
                .map_err(|_| io::Error::other("input mtime exceeds revision-45 i64 range"))?;
            Ok(ArchiveTimestamp::new(seconds, nanoseconds))
        }
    }
}

#[cfg(windows)]
pub(crate) fn reject_unsupported_windows_regular_file(
    metadata: &fs::Metadata,
    input: &Path,
) -> Result<()> {
    use std::os::windows::fs::MetadataExt;

    let attributes = metadata.file_attributes();
    if let Some(reason) = unsupported_windows_file_attribute_reason(attributes) {
        bail!(
            "Windows metadata capture does not support {}: {reason}",
            input.display()
        );
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn unsupported_windows_file_attribute_reason(attributes: u32) -> Option<&'static str> {
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    const FILE_ATTRIBUTE_OFFLINE: u32 = 0x0000_1000;
    [
        (
            FILE_ATTRIBUTE_REPARSE_POINT,
            "reparse points require exact reparse-data capture",
        ),
        (
            FILE_ATTRIBUTE_OFFLINE,
            "offline/cloud placeholders require an explicit hydration policy",
        ),
    ]
    .into_iter()
    .find_map(|(flag, reason)| (attributes & flag != 0).then_some(reason))
}

pub(crate) fn portable_input_metadata(
    identity: InputIdentity,
    input: &Path,
) -> Result<PortableFileMetadata> {
    let metadata = fs::symlink_metadata(input)?;
    let created = metadata
        .created()
        .ok()
        .and_then(|t| archive_timestamp(t).ok());
    let accessed = metadata
        .accessed()
        .ok()
        .and_then(|t| archive_timestamp(t).ok());
    Ok(PortableFileMetadata {
        source_os: source_os_label().into(),
        source_filesystem: "unknown".into(),
        mode_origin: if cfg!(unix) {
            PortableModeOrigin::Native
        } else {
            PortableModeOrigin::Projected
        },
        #[cfg(unix)]
        posix_owner: Some(PortablePosixOwner {
            uid: identity.uid,
            gid: identity.gid,
            uname: None,
            gname: None,
        }),
        #[cfg(not(unix))]
        posix_owner: None,
        attributes: identity.attributes,
        created,
        accessed,
        native: capture_native_file_metadata(input, identity)?,
    })
}

pub(crate) fn portable_symlink_metadata(
    identity: InputIdentity,
    _input: &Path,
) -> Result<PortableFileMetadata> {
    Ok(PortableFileMetadata {
        source_os: source_os_label().into(),
        source_filesystem: "unknown".into(),
        mode_origin: if cfg!(unix) {
            PortableModeOrigin::Native
        } else {
            PortableModeOrigin::Projected
        },
        #[cfg(unix)]
        posix_owner: Some(PortablePosixOwner {
            uid: identity.uid,
            gid: identity.gid,
            uname: None,
            gname: None,
        }),
        #[cfg(not(unix))]
        posix_owner: None,
        attributes: identity.attributes,
        created: None,
        accessed: None,
        #[cfg(target_os = "linux")]
        native: capture_linux_symlink_metadata(_input, identity)?,
        #[cfg(target_os = "macos")]
        native: capture_macos_symlink_metadata(_input, identity)?,
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        native: NativeFileMetadata::default(),
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn capture_linux_symlink_metadata(
    input: &Path,
    _identity: InputIdentity,
) -> Result<NativeFileMetadata> {
    tzap_core::linux_metadata::capture_linux_metadata(input, true).map_err(Into::into)
}

#[cfg(unix)]
pub(crate) fn symlink_target_bytes(path: &Path) -> io::Result<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    Ok(fs::read_link(path)?.as_os_str().as_bytes().to_vec())
}

#[cfg(not(unix))]
pub(crate) fn symlink_target_bytes(path: &Path) -> io::Result<Vec<u8>> {
    fs::read_link(path)?
        .to_str()
        .map(|target| target.as_bytes().to_vec())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "symlink target is not UTF-8"))
}

#[cfg(target_os = "linux")]
pub(crate) fn capture_native_file_metadata(
    input: &Path,
    _identity: InputIdentity,
) -> Result<NativeFileMetadata> {
    tzap_core::linux_metadata::capture_linux_metadata(input, false).map_err(Into::into)
}

#[cfg(target_os = "macos")]
pub(crate) fn open_macos_metadata_file(input: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    const O_EVTONLY: libc::c_int = 0x0000_8000;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK | O_EVTONLY)
        .open(input)
}

#[cfg(target_os = "macos")]
pub(crate) fn capture_native_file_metadata(
    input: &Path,
    identity: InputIdentity,
) -> Result<NativeFileMetadata> {
    use std::os::macos::fs::MetadataExt;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::FileTypeExt as _;
    use xattr::FileExt as _;

    // Leave ample room below the 64 MiB local-PAX cap for declarations and
    // caller-owned native records. Xattrs beyond this aggregate budget use
    // the format's hashed auxiliary representation instead.
    const INLINE_XATTR_BUDGET: usize = 32 * 1024 * 1024;

    let file = open_macos_metadata_file(input)
        .with_context(|| format!("failed to open {} for metadata capture", input.display()))?;
    let opened_identity = input_identity(&file.metadata().with_context(|| {
        format!(
            "failed to identify opened metadata object {}",
            input.display()
        )
    })?)?;
    if opened_identity != identity {
        bail!("input changed before metadata capture: {}", input.display());
    }
    let mut native = NativeFileMetadata::default();
    let mut inline_xattr_bytes = 0usize;
    let file_type = file.metadata()?.file_type();
    let device_without_metadata_api = file_type.is_char_device() || file_type.is_block_device();
    native.primary_pax_records.insert(
        "TZAP.macos.st-flags".into(),
        format!("{:016x}", file.metadata()?.st_flags()).into_bytes(),
    );
    native.primary_pax_records.insert(
        "TZAP.unix.ctime-observed".into(),
        ArchiveTimestamp::new(
            identity.change_time_seconds,
            identity.change_time_nanoseconds as u32,
        )
        .canonical_pax_value()
        .map_err(|error| anyhow!(error))?,
    );
    if let Some(creation_time) = identity.creation_time {
        native.primary_pax_records.insert(
            "LIBARCHIVE.creationtime".into(),
            creation_time
                .canonical_pax_value()
                .map_err(|error| anyhow!(error))?,
        );
    }

    let xattr_names = match file.list_xattr() {
        Ok(names) => names.collect::<Vec<_>>(),
        Err(error)
            if device_without_metadata_api
                && error
                    .raw_os_error()
                    .is_some_and(|code| code == libc::EPERM || code == libc::ENOTSUP) =>
        {
            Vec::new()
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to list xattrs for {}", input.display()));
        }
    };
    for name in xattr_names {
        let name_bytes = name.as_bytes();
        if name_bytes == b"com.apple.ResourceFork" {
            native.auxiliary_records.push(
                capture_macos_resource_fork(
                    open_macos_resource_fork_for_read(file.try_clone()?)?,
                    identity,
                )
                .with_context(|| {
                    format!("failed to capture resource fork for {}", input.display())
                })?,
            );
            continue;
        }
        let Some(value) = file
            .get_xattr(&name)
            .with_context(|| format!("failed to read xattr on {}", input.display()))?
        else {
            bail!("xattr changed while scanning {}", input.display());
        };
        match name_bytes {
            b"com.apple.FinderInfo" => {
                if value.len() != 32 {
                    bail!("FinderInfo on {} is not exactly 32 bytes", input.display());
                }
                native.auxiliary_records.push(NativeAuxiliaryMetadata::new(
                    "macos.finder-info",
                    "macos-backup-v1",
                    RestoreClass::SameOs,
                    value,
                ));
            }
            _ if inline_xattr_bytes
                .saturating_add(name_bytes.len())
                .saturating_add(value.len().saturating_mul(4).div_ceil(3))
                > INLINE_XATTR_BUDGET =>
            {
                let profile = if name_bytes.starts_with(b"com.apple.") {
                    "macos-backup-v1"
                } else {
                    "posix-backup-v1"
                };
                let mut record = NativeAuxiliaryMetadata::new(
                    "generic.xattr",
                    profile,
                    if macos_system_xattr(name_bytes) {
                        RestoreClass::System
                    } else {
                        RestoreClass::SameOs
                    },
                    value,
                );
                record.name_encoding = NativeAuxiliaryNameEncoding::Bytes;
                record.name = name_bytes.to_vec();
                native.auxiliary_records.push(record);
            }
            _ => {
                let encoded_name =
                    encode_percent_name(name_bytes).map_err(|error| anyhow!(error))?;
                native.primary_pax_records.insert(
                    format!("LIBARCHIVE.xattr.{encoded_name}"),
                    canonical_base64_encode(&value),
                );
                inline_xattr_bytes = inline_xattr_bytes
                    .saturating_add(encoded_name.len())
                    .saturating_add(value.len().saturating_mul(4).div_ceil(3));
            }
        }
    }

    let acl = match capture_macos_acl(&file) {
        Ok(acl) => acl,
        Err(error)
            if device_without_metadata_api
                && error
                    .raw_os_error()
                    .is_some_and(|code| code == libc::EPERM || code == libc::ENOTSUP) =>
        {
            None
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to capture ACL for {}", input.display()));
        }
    };
    if let Some(acl) = acl {
        let mut record = NativeAuxiliaryMetadata::new(
            "macos.acl-native",
            "macos-backup-v1",
            RestoreClass::SameOs,
            acl,
        );
        record.meta.insert(
            "TZAP.aux.meta.acl-format".into(),
            b"darwin-acl-external-v1".to_vec(),
        );
        native.auxiliary_records.push(record);
        native
            .primary_pax_records
            .insert("TZAP.acl.projection".into(), b"none".to_vec());
    }

    native.auxiliary_records.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.name.cmp(&right.name))
    });
    native.required_profiles.push("macos-backup-v1".into());
    native.required_profiles.push("posix-backup-v1".into());
    native.required_profiles.sort();
    let final_identity =
        input_identity(&file.metadata().with_context(|| {
            format!("failed to reidentify metadata object {}", input.display())
        })?)?;
    if final_identity != identity {
        bail!("input changed during metadata capture: {}", input.display());
    }
    Ok(native)
}

#[cfg(target_os = "macos")]
pub(crate) fn capture_macos_symlink_metadata(
    input: &Path,
    identity: InputIdentity,
) -> Result<NativeFileMetadata> {
    use std::os::macos::fs::MetadataExt as _;
    use std::os::unix::ffi::OsStrExt as _;
    use xattr::FileExt as _;

    const INLINE_XATTR_BUDGET: usize = 32 * 1024 * 1024;
    let file = open_macos_symlink(input)
        .with_context(|| format!("failed to open symlink {}", input.display()))?;
    let current = file
        .metadata()
        .with_context(|| format!("failed to identify symlink {}", input.display()))?;
    if !current.file_type().is_symlink() || input_identity(&current)? != identity {
        bail!(
            "symlink changed before metadata capture: {}",
            input.display()
        );
    }

    let mut native = NativeFileMetadata::default();
    let mut inline_xattr_bytes = 0usize;
    native.primary_pax_records.insert(
        "TZAP.macos.st-flags".into(),
        format!("{:016x}", current.st_flags()).into_bytes(),
    );
    native.primary_pax_records.insert(
        "TZAP.unix.ctime-observed".into(),
        ArchiveTimestamp::new(
            identity.change_time_seconds,
            identity.change_time_nanoseconds as u32,
        )
        .canonical_pax_value()
        .map_err(|error| anyhow!(error))?,
    );
    if let Some(creation_time) = identity.creation_time {
        native.primary_pax_records.insert(
            "LIBARCHIVE.creationtime".into(),
            creation_time
                .canonical_pax_value()
                .map_err(|error| anyhow!(error))?,
        );
    }

    for name in file
        .list_xattr()
        .with_context(|| format!("failed to list symlink xattrs for {}", input.display()))?
    {
        let name_bytes = name.as_bytes();
        if name_bytes == b"com.apple.ResourceFork" {
            native.auxiliary_records.push(
                capture_macos_resource_fork(
                    MacosResourceForkSource::Symlink(file.try_clone()?),
                    identity,
                )
                .with_context(|| {
                    format!(
                        "failed to capture symlink resource fork for {}",
                        input.display()
                    )
                })?,
            );
            continue;
        }
        let Some(value) = file
            .get_xattr(&name)
            .with_context(|| format!("failed to read symlink xattr on {}", input.display()))?
        else {
            bail!("symlink xattr changed while scanning {}", input.display());
        };
        match name_bytes {
            b"com.apple.FinderInfo" => {
                if value.len() != 32 {
                    bail!("FinderInfo on {} is not exactly 32 bytes", input.display());
                }
                native.auxiliary_records.push(NativeAuxiliaryMetadata::new(
                    "macos.finder-info",
                    "macos-backup-v1",
                    RestoreClass::SameOs,
                    value,
                ));
            }
            _ if inline_xattr_bytes
                .saturating_add(name_bytes.len())
                .saturating_add(value.len().saturating_mul(4).div_ceil(3))
                > INLINE_XATTR_BUDGET =>
            {
                let profile = if name_bytes.starts_with(b"com.apple.") {
                    "macos-backup-v1"
                } else {
                    "posix-backup-v1"
                };
                let mut record = NativeAuxiliaryMetadata::new(
                    "generic.xattr",
                    profile,
                    if macos_system_xattr(name_bytes) {
                        RestoreClass::System
                    } else {
                        RestoreClass::SameOs
                    },
                    value,
                );
                record.name_encoding = NativeAuxiliaryNameEncoding::Bytes;
                record.name = name_bytes.to_vec();
                native.auxiliary_records.push(record);
            }
            _ => {
                let encoded_name =
                    encode_percent_name(name_bytes).map_err(|error| anyhow!(error))?;
                let encoded_value = canonical_base64_encode(&value);
                inline_xattr_bytes = inline_xattr_bytes
                    .saturating_add(encoded_name.len())
                    .saturating_add(encoded_value.len());
                native
                    .primary_pax_records
                    .insert(format!("LIBARCHIVE.xattr.{encoded_name}"), encoded_value);
            }
        }
    }

    if let Some(acl) = capture_macos_acl(&file)? {
        let mut record = NativeAuxiliaryMetadata::new(
            "macos.acl-native",
            "macos-backup-v1",
            RestoreClass::SameOs,
            acl,
        );
        record.meta.insert(
            "TZAP.aux.meta.acl-format".into(),
            b"darwin-acl-external-v1".to_vec(),
        );
        native.auxiliary_records.push(record);
        native
            .primary_pax_records
            .insert("TZAP.acl.projection".into(), b"none".to_vec());
    }
    native.required_profiles = vec!["macos-backup-v1".into(), "posix-backup-v1".into()];
    native.auxiliary_records.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.name.cmp(&right.name))
    });
    let final_metadata = file
        .metadata()
        .with_context(|| format!("failed to reidentify symlink {}", input.display()))?;
    if !final_metadata.file_type().is_symlink() || input_identity(&final_metadata)? != identity {
        bail!(
            "symlink changed during metadata capture: {}",
            input.display()
        );
    }
    Ok(native)
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_system_xattr(name: &[u8]) -> bool {
    name.starts_with(b"security.") || name.starts_with(b"trusted.") || name.starts_with(b"system.")
}

#[cfg(target_os = "macos")]
pub(crate) fn capture_macos_resource_fork(
    source: MacosResourceForkSource,
    identity: InputIdentity,
) -> Result<NativeAuxiliaryMetadata> {
    use sha2::{Digest as _, Sha256};

    let mut reader = MacosResourceForkReader::new(source, identity, None)?;
    let logical_size = reader.logical_size;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(NativeAuxiliaryMetadata::new_streamed(
        "macos.resource-fork",
        "macos-backup-v1",
        RestoreClass::SameOs,
        logical_size,
        hasher.finalize().into(),
    ))
}

#[cfg(target_os = "macos")]
pub(crate) fn capture_macos_acl(file: &File) -> io::Result<Option<Vec<u8>>> {
    use std::os::fd::AsRawFd;
    use std::ptr;

    type Acl = *mut libc::c_void;
    type AclEntry = *mut libc::c_void;
    const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;
    const ACL_FIRST_ENTRY: libc::c_int = 0;

    extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, acl_type: libc::c_int) -> Acl;
        fn acl_get_entry(acl: Acl, entry_id: libc::c_int, entry: *mut AclEntry) -> libc::c_int;
        fn acl_size(acl: Acl) -> libc::ssize_t;
        fn acl_copy_ext(buffer: *mut libc::c_void, acl: Acl, size: libc::ssize_t) -> libc::ssize_t;
        fn acl_free(object: *mut libc::c_void) -> libc::c_int;
    }

    // SAFETY: `file` owns a live descriptor and the returned ACL is released on every path.
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ENOENT) {
            Ok(None)
        } else {
            Err(error)
        };
    }
    let result = (|| {
        let mut first: AclEntry = ptr::null_mut();
        // SAFETY: `acl` is valid and `first` points to writable storage for one entry pointer.
        match unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, &mut first) } {
            1 => return Ok(None),
            0 => {}
            _ => return Err(io::Error::last_os_error()),
        }
        // SAFETY: `acl` remains valid for the duration of this scope.
        let size = unsafe { acl_size(acl) };
        if size < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut external = vec![
            0u8;
            usize::try_from(size).map_err(|_| {
                io::Error::other("macOS ACL external form exceeds platform limits")
            })?
        ];
        // SAFETY: the destination has exactly `size` writable bytes and `acl` is valid.
        let copied = unsafe { acl_copy_ext(external.as_mut_ptr().cast(), acl, size) };
        if copied < 0 {
            return Err(io::Error::last_os_error());
        }
        external
            .truncate(usize::try_from(copied).map_err(|_| {
                io::Error::other("macOS ACL external form exceeds platform limits")
            })?);
        Ok(Some(external))
    })();
    // SAFETY: `acl` was returned by `acl_get_fd_np` and has not yet been freed.
    unsafe { acl_free(acl) };
    result
}

#[cfg(windows)]
pub(crate) fn capture_native_file_metadata(
    input: &Path,
    identity: InputIdentity,
) -> Result<NativeFileMetadata> {
    let file = open_windows_metadata_handle(input).with_context(|| {
        format!(
            "failed to open {} for Windows metadata capture",
            input.display()
        )
    })?;
    let mut native = NativeFileMetadata::default();
    native.primary_pax_records.insert(
        "TZAP.windows.file-attributes".into(),
        format!("{:08x}", identity.file_attributes).into_bytes(),
    );
    native.primary_pax_records.insert(
        "atime".into(),
        windows_filetime_timestamp(identity.last_access_time_100ns)?
            .canonical_pax_value()
            .map_err(|error| anyhow!(error))?,
    );
    native.primary_pax_records.insert(
        "LIBARCHIVE.creationtime".into(),
        windows_filetime_timestamp(identity.creation_time_100ns)?
            .canonical_pax_value()
            .map_err(|error| anyhow!(error))?,
    );
    native.primary_pax_records.insert(
        "TZAP.windows.change-time".into(),
        windows_filetime_timestamp(identity.change_time_100ns)?
            .canonical_pax_value()
            .map_err(|error| anyhow!(error))?,
    );
    let reparse_data = if identity.file_attributes & 0x0000_0400 != 0 {
        let data = query_windows_reparse_data(&file).with_context(|| {
            format!(
                "failed to read Windows reparse data for {}",
                input.display()
            )
        })?;
        validate_windows_known_reparse_data(&data).with_context(|| {
            format!(
                "failed to validate Windows reparse data for {}",
                input.display()
            )
        })?;
        let tag = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let mut record = NativeAuxiliaryMetadata::new(
            "windows.reparse-data",
            "windows-backup-v1",
            RestoreClass::System,
            data.clone(),
        );
        record.meta.insert(
            "TZAP.aux.meta.reparse-tag".into(),
            format!("{tag:08x}").into_bytes(),
        );
        native.auxiliary_records.push(record);
        Some(data)
    } else {
        None
    };
    native
        .auxiliary_records
        .push(capture_windows_security_descriptor(&file).with_context(|| {
            format!(
                "failed to capture Windows security descriptor for {}",
                input.display()
            )
        })?);
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
    if identity.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        if let Some(case_sensitive) = query_windows_directory_case_sensitive(&file)? {
            native.primary_pax_records.insert(
                "TZAP.windows.directory-case-sensitive".into(),
                if case_sensitive { b"1" } else { b"0" }.to_vec(),
            );
        }
    }
    const FILE_ATTRIBUTE_ENCRYPTED: u32 = 0x0000_4000;
    let (data_stream_attributes, mut streams) =
        capture_windows_backup_streams(input, &file, reparse_data.as_deref()).with_context(
            || {
                format!(
                    "failed to enumerate Windows streams for {}",
                    input.display()
                )
            },
        )?;
    if identity.file_attributes & FILE_ATTRIBUTE_ENCRYPTED != 0 {
        // The raw EFS APIs reject export while an ordinary handle to the encrypted file is open,
        // even when that handle permits all sharing modes. Enumerate every registered BackupRead
        // stream first, then release the handle before opening the raw export context.
        drop(file);
        native.auxiliary_records.push(
            capture_windows_efs_raw(input, identity).with_context(|| {
                format!("failed to capture raw EFS data for {}", input.display())
            })?,
        );
    }
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    if identity.file_attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) == 0 {
        native.primary_pax_records.insert(
            "TZAP.windows.data-stream-attributes".into(),
            format!("{data_stream_attributes:08x}").into_bytes(),
        );
    }
    native.auxiliary_records.append(&mut streams);
    native.auxiliary_records.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.name.cmp(&right.name))
    });
    native.required_profiles.push("windows-backup-v1".into());
    Ok(native)
}

#[cfg(windows)]
pub(crate) fn query_windows_directory_case_sensitive(file: &File) -> io::Result<Option<bool>> {
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{
        ERROR_INVALID_FUNCTION, ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FileCaseSensitiveInfo, GetFileInformationByHandleEx, FILE_CASE_SENSITIVE_INFO,
    };
    use windows_sys::Win32::System::SystemServices::FILE_CS_FLAG_CASE_SENSITIVE_DIR;

    let mut info = FILE_CASE_SENSITIVE_INFO::default();
    // SAFETY: the handle is live and `info` is a correctly sized writable structure.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle().cast(),
            FileCaseSensitiveInfo,
            (&mut info as *mut FILE_CASE_SENSITIVE_INFO).cast(),
            size_of::<FILE_CASE_SENSITIVE_INFO>() as u32,
        )
    } == 0
    {
        let error = io::Error::last_os_error();
        if matches!(
            error.raw_os_error(),
            Some(code)
                if code == ERROR_INVALID_FUNCTION as i32
                    || code == ERROR_INVALID_PARAMETER as i32
                    || code == ERROR_NOT_SUPPORTED as i32
        ) {
            return Ok(None);
        }
        return Err(error);
    }
    if info.Flags & !FILE_CS_FLAG_CASE_SENSITIVE_DIR != 0 {
        return Err(io::Error::other(
            "Windows returned unknown directory case-sensitivity flags",
        ));
    }
    Ok(Some(info.Flags & FILE_CS_FLAG_CASE_SENSITIVE_DIR != 0))
}

#[cfg(windows)]
pub(crate) fn windows_filetime_timestamp(value_100ns: u64) -> Result<ArchiveTimestamp> {
    const WINDOWS_TO_UNIX_EPOCH_100NS: i128 = 116_444_736_000_000_000;
    const TICKS_PER_SECOND: i128 = 10_000_000;
    let unix_100ns = i128::from(value_100ns) - WINDOWS_TO_UNIX_EPOCH_100NS;
    let seconds = i64::try_from(unix_100ns.div_euclid(TICKS_PER_SECOND))
        .map_err(|_| anyhow!("Windows timestamp exceeds revision-45 i64 range"))?;
    let nanoseconds = (unix_100ns.rem_euclid(TICKS_PER_SECOND) * 100) as u32;
    Ok(ArchiveTimestamp::new(seconds, nanoseconds))
}

#[cfg(windows)]
pub(crate) fn windows_sacl_capture_enabled() -> bool {
    use std::sync::OnceLock;
    use windows_sys::Win32::Security::SE_SECURITY_NAME;

    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| enable_windows_privilege(SE_SECURITY_NAME))
}

#[cfg(windows)]
pub(crate) fn windows_backup_capture_enabled() -> bool {
    use std::sync::OnceLock;
    use windows_sys::Win32::Security::SE_BACKUP_NAME;

    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| enable_windows_privilege(SE_BACKUP_NAME))
}

#[cfg(windows)]
pub(crate) fn enable_windows_privilege(name: *const u16) -> bool {
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, SetLastError, ERROR_SUCCESS};
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = ptr::null_mut();
    // SAFETY: `token` is a valid output pointer and the pseudo process handle is always live.
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
            &mut token,
        )
    } == 0
    {
        return false;
    }
    let enabled = {
        let mut privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            ..Default::default()
        };
        // SAFETY: the one-element privilege array provides a valid LUID output slot.
        if unsafe { LookupPrivilegeValueW(ptr::null(), name, &mut privileges.Privileges[0].Luid) }
            == 0
        {
            false
        } else {
            privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            unsafe { SetLastError(ERROR_SUCCESS) };
            // SAFETY: `token` is live and `privileges` is a valid one-entry input structure.
            unsafe {
                AdjustTokenPrivileges(token, 0, &privileges, 0, ptr::null_mut(), ptr::null_mut())
                    != 0
                    && GetLastError() == ERROR_SUCCESS
            }
        }
    };
    // SAFETY: `token` was returned by OpenProcessToken and is closed exactly once.
    unsafe { CloseHandle(token) };
    enabled
}

#[cfg(windows)]
pub(crate) struct WindowsRawEfsContext(*mut std::ffi::c_void);

#[cfg(windows)]
impl Drop for WindowsRawEfsContext {
    fn drop(&mut self) {
        use windows_sys::Win32::Storage::FileSystem::CloseEncryptedFileRaw;

        if !self.0.is_null() {
            // SAFETY: this context was returned by OpenEncryptedFileRawW and is closed once.
            unsafe { CloseEncryptedFileRaw(self.0) };
        }
    }
}

#[cfg(windows)]
pub(crate) fn open_windows_raw_efs(path: &Path, flags: u32) -> io::Result<WindowsRawEfsContext> {
    use std::os::windows::ffi::OsStrExt as _;
    use std::ptr;
    use windows_sys::Win32::Storage::FileSystem::OpenEncryptedFileRawW;

    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut context = ptr::null_mut();
    // SAFETY: the path is NUL-terminated and `context` is a valid output pointer.
    let status = unsafe { OpenEncryptedFileRawW(wide.as_ptr(), flags, &mut context) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(WindowsRawEfsContext(context))
}

#[cfg(windows)]
pub(crate) struct WindowsRawEfsDigest {
    pub(crate) hasher: sha2::Sha256,
    pub(crate) size: u64,
}

#[cfg(windows)]
unsafe extern "system" fn hash_windows_raw_efs_callback(
    data: *const u8,
    context: *const std::ffi::c_void,
    length: u32,
) -> u32 {
    use sha2::Digest as _;
    use windows_sys::Win32::Foundation::{ERROR_ARITHMETIC_OVERFLOW, ERROR_SUCCESS};

    if length == 0 {
        return ERROR_SUCCESS;
    }
    if data.is_null() || context.is_null() {
        return windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER;
    }
    // SAFETY: EFS supplies `length` readable bytes and the caller supplied this digest context.
    let bytes = unsafe { std::slice::from_raw_parts(data, length as usize) };
    let state = unsafe { &mut *context.cast_mut().cast::<WindowsRawEfsDigest>() };
    let Some(size) = state.size.checked_add(u64::from(length)) else {
        return ERROR_ARITHMETIC_OVERFLOW;
    };
    state.hasher.update(bytes);
    state.size = size;
    ERROR_SUCCESS
}

#[cfg(windows)]
pub(crate) fn hash_windows_raw_efs(path: &Path) -> io::Result<(u64, [u8; 32])> {
    use sha2::Digest as _;
    use windows_sys::Win32::Storage::FileSystem::ReadEncryptedFileRaw;

    let _ = windows_backup_capture_enabled();
    let context = open_windows_raw_efs(path, 0)?;
    let mut state = WindowsRawEfsDigest {
        hasher: sha2::Sha256::new(),
        size: 0,
    };
    // SAFETY: callback state and raw EFS context remain live for the synchronous export.
    let status = unsafe {
        ReadEncryptedFileRaw(
            Some(hash_windows_raw_efs_callback),
            (&mut state as *mut WindowsRawEfsDigest).cast(),
            context.0,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok((state.size, state.hasher.finalize().into()))
}

#[cfg(windows)]
pub(crate) enum WindowsRawEfsMessage {
    Data(Vec<u8>),
    Done(io::Result<()>),
}

#[cfg(windows)]
pub(crate) struct WindowsRawEfsSendContext {
    pub(crate) sender: std::sync::mpsc::SyncSender<WindowsRawEfsMessage>,
}

#[cfg(windows)]
unsafe extern "system" fn send_windows_raw_efs_callback(
    data: *const u8,
    context: *const std::ffi::c_void,
    length: u32,
) -> u32 {
    use windows_sys::Win32::Foundation::{ERROR_INVALID_PARAMETER, ERROR_OPERATION_ABORTED};

    if length == 0 {
        return 0;
    }
    if data.is_null() || context.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    // SAFETY: EFS supplies readable callback bytes and the caller supplied this send context.
    let bytes = unsafe { std::slice::from_raw_parts(data, length as usize) };
    let state = unsafe { &*context.cast::<WindowsRawEfsSendContext>() };
    for chunk in bytes.chunks(64 * 1024) {
        if state
            .sender
            .send(WindowsRawEfsMessage::Data(chunk.to_vec()))
            .is_err()
        {
            return ERROR_OPERATION_ABORTED;
        }
    }
    0
}

#[cfg(windows)]
pub(crate) fn validate_windows_input_path_identity(
    path: &Path,
    expected: InputIdentity,
) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    let mut actual = input_identity(&metadata)?;
    let file = open_windows_metadata_handle(path)?;
    augment_windows_input_identity(&mut actual, &file)?;
    if input_identity_matches_after_read(expected, actual) {
        Ok(())
    } else {
        Err(io::Error::other(
            "Windows input changed during raw EFS export",
        ))
    }
}

#[cfg(windows)]
pub(crate) fn export_windows_raw_efs_to_sender(
    path: &Path,
    expected: InputIdentity,
    sender: std::sync::mpsc::SyncSender<WindowsRawEfsMessage>,
) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::ReadEncryptedFileRaw;

    validate_windows_input_path_identity(path, expected)?;
    let _ = windows_backup_capture_enabled();
    let context = open_windows_raw_efs(path, 0)?;
    let state = WindowsRawEfsSendContext { sender };
    // SAFETY: callback state and raw EFS context remain live for the synchronous export.
    let status = unsafe {
        ReadEncryptedFileRaw(
            Some(send_windows_raw_efs_callback),
            (&state as *const WindowsRawEfsSendContext).cast(),
            context.0,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    drop(context);
    validate_windows_input_path_identity(path, expected)
}

#[cfg(windows)]
pub(crate) struct WindowsRawEfsReader {
    pub(crate) receiver: Option<std::sync::mpsc::Receiver<WindowsRawEfsMessage>>,
    pub(crate) current: Vec<u8>,
    pub(crate) current_offset: usize,
    pub(crate) remaining: u64,
    pub(crate) finished: bool,
    pub(crate) pending_error: Option<io::Error>,
    pub(crate) thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(windows)]
impl WindowsRawEfsReader {
    fn spawn(path: PathBuf, expected: InputIdentity, size: u64) -> Self {
        let (sender, receiver) = std::sync::mpsc::sync_channel(2);
        let completion = sender.clone();
        let thread = std::thread::spawn(move || {
            let result = export_windows_raw_efs_to_sender(&path, expected, sender);
            let _ = completion.send(WindowsRawEfsMessage::Done(result));
        });
        Self {
            receiver: Some(receiver),
            current: Vec::new(),
            current_offset: 0,
            remaining: size,
            finished: false,
            pending_error: None,
            thread: Some(thread),
        }
    }
}

#[cfg(windows)]
impl Read for WindowsRawEfsReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if let Some(error) = self.pending_error.take() {
            return Err(error);
        }
        let mut written = 0usize;
        while written < out.len() {
            if self.current_offset < self.current.len() {
                let count = (self.current.len() - self.current_offset).min(out.len() - written);
                if count as u64 > self.remaining {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "raw EFS export exceeded its declared size",
                    ));
                }
                out[written..written + count].copy_from_slice(
                    &self.current[self.current_offset..self.current_offset + count],
                );
                self.current_offset += count;
                self.remaining -= count as u64;
                written += count;
                continue;
            }
            if self.finished {
                break;
            }
            let message = self
                .receiver
                .as_ref()
                .ok_or_else(|| io::Error::other("raw EFS export channel is closed"))?
                .recv()
                .map_err(|_| io::Error::other("raw EFS export terminated unexpectedly"))?;
            match message {
                WindowsRawEfsMessage::Data(bytes) => {
                    self.current = bytes;
                    self.current_offset = 0;
                }
                WindowsRawEfsMessage::Done(result) => {
                    self.finished = true;
                    if let Err(error) = result {
                        if written == 0 {
                            return Err(error);
                        }
                        self.pending_error = Some(error);
                    } else if self.remaining != 0 {
                        let error = io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "raw EFS export ended before its declared size",
                        );
                        if written == 0 {
                            return Err(error);
                        }
                        self.pending_error = Some(error);
                    }
                }
            }
        }
        Ok(written)
    }
}

#[cfg(windows)]
impl Drop for WindowsRawEfsReader {
    fn drop(&mut self) {
        self.receiver.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(windows)]
pub(crate) fn capture_windows_efs_raw(
    path: &Path,
    expected: InputIdentity,
) -> Result<NativeAuxiliaryMetadata> {
    validate_windows_input_path_identity(path, expected)?;
    let (size, sha256) = hash_windows_raw_efs(path)?;
    validate_windows_input_path_identity(path, expected)?;
    let mut record = NativeAuxiliaryMetadata::new_streamed(
        "windows.efs-raw",
        "windows-backup-v1",
        RestoreClass::System,
        size,
        sha256,
    );
    record
        .meta
        .insert("TZAP.aux.meta.efs-version".into(), b"1".to_vec());
    Ok(record)
}

#[cfg(windows)]
pub(crate) fn capture_windows_security_descriptor(file: &File) -> Result<NativeAuxiliaryMetadata> {
    use std::os::windows::io::AsRawHandle;
    use std::ptr;
    use windows_sys::Win32::Foundation::{
        CloseHandle, LocalFree, ERROR_SUCCESS, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorLength, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        PROTECTED_SACL_SECURITY_INFORMATION, SACL_SECURITY_INFORMATION,
        UNPROTECTED_DACL_SECURITY_INFORMATION, UNPROTECTED_SACL_SECURITY_INFORMATION,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        ReOpenFile, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL,
    };
    use windows_sys::Win32::System::SystemServices::ACCESS_SYSTEM_SECURITY;

    const BASE_SECURITY_INFORMATION: u32 =
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let original_handle = file.as_raw_handle().cast();
    let sacl_handle = if windows_sacl_capture_enabled() {
        // The handle returned by File::open has READ_CONTROL but not ACCESS_SYSTEM_SECURITY.
        // ReOpenFile preserves object identity while requesting the access needed for SACLs.
        // SAFETY: `original_handle` is live and all flags are valid for a regular file.
        let handle = unsafe {
            ReOpenFile(
                original_handle,
                READ_CONTROL | ACCESS_SYSTEM_SECURITY,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                0,
            )
        };
        (handle != INVALID_HANDLE_VALUE).then_some(handle)
    } else {
        None
    };
    let security_information = if sacl_handle.is_some() {
        BASE_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION
    } else {
        BASE_SECURITY_INFORMATION
    };
    let security_handle = sacl_handle.unwrap_or(original_handle);
    let mut descriptor = ptr::null_mut();
    // SAFETY: the file handle is live, optional component outputs are null, and the returned
    // descriptor is released with LocalFree below as required by GetSecurityInfo.
    let status = unsafe {
        GetSecurityInfo(
            security_handle,
            SE_FILE_OBJECT,
            security_information,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if let Some(handle) = sacl_handle {
        // SAFETY: `handle` was returned by ReOpenFile and is closed exactly once.
        unsafe { CloseHandle(handle) };
    }
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32).into());
    }
    if descriptor.is_null() {
        bail!("GetSecurityInfo returned an empty security descriptor");
    }
    // SAFETY: GetSecurityInfo returned a valid self-relative security descriptor.
    let length = unsafe { GetSecurityDescriptorLength(descriptor) } as usize;
    // SAFETY: `descriptor` references `length` readable bytes until LocalFree.
    let payload = unsafe { std::slice::from_raw_parts(descriptor.cast::<u8>(), length) }.to_vec();
    // SAFETY: `descriptor` was allocated by GetSecurityInfo and has not been freed.
    let free_result = unsafe { LocalFree(descriptor) };
    if !free_result.is_null() {
        bail!("failed to release Windows security descriptor");
    }
    if payload.len() < 20 {
        bail!("GetSecurityInfo returned a truncated self-relative descriptor");
    }
    let control = u16::from_le_bytes(payload[2..4].try_into().unwrap());
    let owner_offset = u32::from_le_bytes(payload[4..8].try_into().unwrap());
    let group_offset = u32::from_le_bytes(payload[8..12].try_into().unwrap());
    let mut captured_security_information = 0u32;
    if owner_offset != 0 {
        captured_security_information |= OWNER_SECURITY_INFORMATION;
    }
    if group_offset != 0 {
        captured_security_information |= GROUP_SECURITY_INFORMATION;
    }
    if control & 0x0004 != 0 {
        captured_security_information |= DACL_SECURITY_INFORMATION;
        captured_security_information |= if control & 0x1000 != 0 {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_DACL_SECURITY_INFORMATION
        };
    }
    if control & 0x0010 != 0 {
        captured_security_information |= SACL_SECURITY_INFORMATION;
        captured_security_information |= if control & 0x2000 != 0 {
            PROTECTED_SACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_SACL_SECURITY_INFORMATION
        };
    }
    let required_identity = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION;
    if captured_security_information & required_identity != required_identity {
        bail!("Windows security descriptor lacks requested owner or group metadata");
    }
    let mut auxiliary = NativeAuxiliaryMetadata::new(
        "windows.security-descriptor",
        "windows-backup-v1",
        RestoreClass::System,
        payload,
    );
    auxiliary.meta.insert(
        "TZAP.aux.meta.security-information".into(),
        format!("{captured_security_information:08x}").into_bytes(),
    );
    Ok(auxiliary)
}

#[cfg(windows)]
pub(crate) struct WindowsBackupReader {
    pub(crate) handle: windows_sys::Win32::Foundation::HANDLE,
    pub(crate) context: *mut std::ffi::c_void,
}

#[cfg(windows)]
impl WindowsBackupReader {
    pub(crate) fn new(file: &File) -> Self {
        use std::os::windows::io::AsRawHandle;
        Self {
            handle: file.as_raw_handle().cast(),
            context: std::ptr::null_mut(),
        }
    }

    fn read_optional_exact(&mut self, out: &mut [u8]) -> io::Result<bool> {
        use windows_sys::Win32::Storage::FileSystem::BackupRead;

        let mut offset = 0usize;
        while offset < out.len() {
            let mut read = 0u32;
            // SAFETY: the handle is live, the output slice is writable, and `context` is owned
            // by this reader until its Drop implementation aborts the backup operation.
            if unsafe {
                BackupRead(
                    self.handle,
                    out[offset..].as_mut_ptr(),
                    u32::try_from(out.len() - offset)
                        .map_err(|_| io::Error::other("BackupRead request exceeds u32"))?,
                    &mut read,
                    0,
                    0,
                    &mut self.context,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            if read == 0 {
                if offset == 0 {
                    return Ok(false);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Windows backup stream ended mid-record",
                ));
            }
            offset += read as usize;
        }
        Ok(true)
    }

    fn read_vec(&mut self, size: u64) -> io::Result<Vec<u8>> {
        let size = usize::try_from(size)
            .map_err(|_| io::Error::other("Windows backup stream exceeds address space"))?;
        let mut payload = vec![0u8; size];
        if size != 0 && !self.read_optional_exact(&mut payload)? {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Windows backup stream payload is missing",
            ));
        }
        Ok(payload)
    }

    fn read_sha256(&mut self, mut size: u64) -> io::Result<[u8; 32]> {
        use sha2::{Digest as _, Sha256};

        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        while size > 0 {
            let count = buffer
                .len()
                .min(usize::try_from(size).unwrap_or(usize::MAX));
            if !self.read_optional_exact(&mut buffer[..count])? {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Windows backup stream payload is missing",
                ));
            }
            hasher.update(&buffer[..count]);
            size -= count as u64;
        }
        Ok(hasher.finalize().into())
    }

    fn skip(&mut self, size: u64) -> io::Result<()> {
        use windows_sys::Win32::Storage::FileSystem::BackupSeek;

        let mut low = 0u32;
        let mut high = 0u32;
        // SAFETY: the handle and context belong to this backup operation and output counters
        // are valid writable pointers.
        if unsafe {
            BackupSeek(
                self.handle,
                size as u32,
                (size >> 32) as u32,
                &mut low,
                &mut high,
                &mut self.context,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let skipped = (u64::from(high) << 32) | u64::from(low);
        if skipped != size {
            return Err(io::Error::other(
                "Windows backup stream could not be skipped completely",
            ));
        }
        Ok(())
    }

    fn discard(&mut self, mut size: u64) -> io::Result<()> {
        let mut buffer = [0u8; 64 * 1024];
        while size > 0 {
            let take = size.min(buffer.len() as u64) as usize;
            if !self.read_optional_exact(&mut buffer[..take])? {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Windows backup stream payload is missing",
                ));
            }
            size -= take as u64;
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for WindowsBackupReader {
    fn drop(&mut self) {
        use windows_sys::Win32::Storage::FileSystem::BackupRead;

        let mut ignored = 0u32;
        // SAFETY: aborting with a null zero-length buffer releases the context owned here.
        unsafe {
            BackupRead(
                self.handle,
                std::ptr::null_mut(),
                0,
                &mut ignored,
                1,
                0,
                &mut self.context,
            );
        }
    }
}

#[cfg(windows)]
pub(crate) fn capture_windows_backup_streams(
    input: &Path,
    file: &File,
    expected_reparse_data: Option<&[u8]>,
) -> Result<(u32, Vec<NativeAuxiliaryMetadata>)> {
    use std::os::windows::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        BACKUP_ALTERNATE_DATA, BACKUP_DATA, BACKUP_EA_DATA, BACKUP_LINK, BACKUP_OBJECT_ID,
        BACKUP_PROPERTY_DATA, BACKUP_REPARSE_DATA, BACKUP_SECURITY_DATA, BACKUP_SPARSE_BLOCK,
        BACKUP_TXFS_DATA,
    };

    const FIXED_STREAM_HEADER_LEN: usize = 20;
    const MAX_RETAINED_BACKUP_STREAM: u64 = 64 * 1024 * 1024;
    const MAX_REPARSE_DATA_BUFFER_SIZE: u64 = 16 * 1024;
    const MAX_BACKUP_STREAM_NAME_SIZE: usize = 65_534;
    const STREAM_MODIFIED_WHEN_READ: u32 = 0x0000_0001;
    let mut reader = WindowsBackupReader::new(file);
    let mut data_stream_attributes = None;
    let mut auxiliary = Vec::new();
    let mut sparse_alternate = Vec::new();
    let mut active_sparse_alternate = None;
    loop {
        let mut header = [0u8; FIXED_STREAM_HEADER_LEN];
        if !reader.read_optional_exact(&mut header)? {
            break;
        }
        let stream_id = u32::from_le_bytes(header[0..4].try_into().unwrap());
        let attributes = u32::from_le_bytes(header[4..8].try_into().unwrap());
        if attributes & STREAM_MODIFIED_WHEN_READ != 0 {
            bail!(
                "Windows backup stream {stream_id} changes when read and cannot be captured consistently"
            );
        }
        let signed_size = i64::from_le_bytes(header[8..16].try_into().unwrap());
        if signed_size < 0 {
            bail!("Windows BackupRead returned a negative stream size");
        }
        let size = signed_size as u64;
        let name_size = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
        if name_size % 2 != 0 || name_size > MAX_BACKUP_STREAM_NAME_SIZE {
            bail!("Windows BackupRead returned an invalid UTF-16 stream-name length");
        }
        let name = reader.read_vec(name_size as u64)?;
        if stream_id != BACKUP_SPARSE_BLOCK {
            active_sparse_alternate = None;
        }
        match stream_id {
            BACKUP_DATA => {
                if data_stream_attributes.replace(attributes).is_some() {
                    bail!("Windows BackupRead returned duplicate default data streams");
                }
                if !name.is_empty() {
                    bail!("Windows default data stream unexpectedly has a name");
                }
                reader.skip(size).with_context(|| {
                    format!("failed to skip Windows default data stream ({size} bytes)")
                })?;
            }
            BACKUP_SECURITY_DATA => reader.skip(size).with_context(|| {
                format!("failed to skip Windows security stream ({size} bytes)")
            })?,
            BACKUP_ALTERNATE_DATA => {
                let restore_class = if attributes & 0x0000_0002 != 0 {
                    RestoreClass::System
                } else {
                    RestoreClass::SameOs
                };
                if attributes & 0x0000_0008 != 0 {
                    reader.skip(size).with_context(|| {
                        format!("failed to skip sparse Windows alternate stream ({size} bytes)")
                    })?;
                    sparse_alternate.push((name, attributes, restore_class, Vec::new()));
                    active_sparse_alternate = Some(sparse_alternate.len() - 1);
                    continue;
                }
                let sha256 = reader.read_sha256(size)?;
                let mut record = NativeAuxiliaryMetadata::new_streamed(
                    "windows.alternate-data",
                    "windows-backup-v1",
                    restore_class,
                    size,
                    sha256,
                );
                record.name_encoding = NativeAuxiliaryNameEncoding::Utf16Le;
                record.name = name;
                record
                    .meta
                    .insert("TZAP.aux.meta.stream-type".into(), b"00000004".to_vec());
                record.meta.insert(
                    "TZAP.aux.meta.stream-attributes".into(),
                    format!("{attributes:08x}").into_bytes(),
                );
                auxiliary.push(record);
            }
            BACKUP_EA_DATA | BACKUP_PROPERTY_DATA | BACKUP_OBJECT_ID => {
                if !name.is_empty() {
                    bail!("unnamed Windows backup stream unexpectedly has a name");
                }
                if stream_id == BACKUP_OBJECT_ID && size != 64 {
                    bail!("Windows object-ID backup stream is not exactly 64 bytes");
                }
                if size > MAX_RETAINED_BACKUP_STREAM {
                    bail!("Windows backup metadata stream exceeds the retained payload cap");
                }
                let payload = reader.read_vec(size)?;
                let (kind, stream_type, restore_class) = match stream_id {
                    BACKUP_EA_DATA => (
                        "windows.ea-data",
                        "00000002",
                        if attributes & 0x0000_0002 != 0 {
                            RestoreClass::System
                        } else {
                            RestoreClass::SameOs
                        },
                    ),
                    BACKUP_PROPERTY_DATA => (
                        "windows.property-data",
                        "00000006",
                        if attributes & 0x0000_0002 != 0 {
                            RestoreClass::System
                        } else {
                            RestoreClass::SameOs
                        },
                    ),
                    _ => ("windows.object-id", "00000007", RestoreClass::System),
                };
                let mut record =
                    NativeAuxiliaryMetadata::new(kind, "windows-backup-v1", restore_class, payload);
                record.meta.insert(
                    "TZAP.aux.meta.stream-type".into(),
                    stream_type.as_bytes().to_vec(),
                );
                record.meta.insert(
                    "TZAP.aux.meta.stream-attributes".into(),
                    format!("{attributes:08x}").into_bytes(),
                );
                if attributes & 0x0000_0008 != 0 {
                    bail!("Windows metadata stream carried an invalid sparse-data attribute");
                }
                auxiliary.push(record);
            }
            BACKUP_REPARSE_DATA => {
                if !name.is_empty() {
                    bail!("Windows reparse stream unexpectedly has a name");
                }
                if size > MAX_REPARSE_DATA_BUFFER_SIZE {
                    bail!("Windows reparse stream exceeds the platform buffer limit");
                }
                let payload = reader.read_vec(size)?;
                if expected_reparse_data != Some(payload.as_slice()) {
                    bail!("Windows reparse stream disagrees with FSCTL_GET_REPARSE_POINT");
                }
            }
            BACKUP_SPARSE_BLOCK => {
                if !name.is_empty() {
                    bail!("Windows sparse-block stream unexpectedly has a name");
                }
                if size < 8 {
                    bail!("Windows sparse-block stream is shorter than its offset (size={size})");
                }
                let offset = reader.read_vec(8)?;
                let offset = u64::from_le_bytes(offset.try_into().unwrap());
                let length = size - 8;
                reader.discard(length).with_context(|| {
                    format!("failed to discard Windows sparse-block data ({length} bytes)")
                })?;
                if length != 0 {
                    if let Some(index) = active_sparse_alternate {
                        push_windows_backup_sparse_extent(
                            &mut sparse_alternate[index].3,
                            offset,
                            length,
                        )?;
                    }
                }
            }
            BACKUP_LINK => {
                if !name.is_empty() {
                    bail!("Windows hardlink stream unexpectedly has a name");
                }
                reader.discard(size).with_context(|| {
                    format!("failed to discard Windows hardlink topology stream ({size} bytes)")
                })?;
            }
            BACKUP_TXFS_DATA => {
                bail!("Windows transactional backup streams are not representable in v45")
            }
            _ => bail!("Windows BackupRead returned unsupported stream id {stream_id}"),
        }
    }
    let file_metadata = file.metadata()?;
    let data_stream_attributes = match data_stream_attributes {
        Some(attributes) => attributes,
        // Raw EFS owns encrypted data streams, which BackupRead omits even when the logical file
        // is nonempty. FILE_ATTRIBUTE_SPARSE_FILE supplies the one independently observable
        // default-stream attribute represented by v45 sparse framing.
        None if file_metadata.file_attributes() & 0x0000_4000 != 0 => {
            if file_metadata.file_attributes() & 0x0000_0200 != 0 {
                0x0000_0008
            } else {
                0
            }
        }
        // BackupRead may omit BACKUP_DATA entirely for a zero-length unnamed stream. Successful
        // enumeration still proves there are no stream attributes to preserve in that case.
        None if file_metadata.len() == 0 => 0,
        None => bail!("Windows BackupRead did not return the default data stream"),
    };
    let sparse_layout_partial = !sparse_alternate.is_empty() && windows_file_system_is_refs(file)?;
    drop(reader);
    for (name, attributes, restore_class, mut extents) in sparse_alternate {
        let stream_path = windows_alternate_stream_path(input, &name)?;
        let mut stream = File::open(stream_path)?;
        let logical_size = stream.metadata()?.len();
        if sparse_layout_partial && logical_size != 0 {
            // ReFS does not expose an authoritative allocated-range map. Materialize every
            // logical byte even if BackupRead returned a non-empty but potentially incomplete
            // sparse-block list; the authenticated omission records layout degradation only.
            extents = vec![SparseExtent {
                offset: 0,
                length: logical_size,
            }];
        } else if extents.is_empty() && logical_size != 0 {
            extents = query_windows_allocated_ranges(&stream, logical_size)?;
        }
        if extents
            .last()
            .is_some_and(|extent| extent.offset + extent.length > logical_size)
        {
            bail!("Windows sparse-block stream exceeds its logical stream size");
        }
        let map = encode_v45_sparse_map(&extents, logical_size).map_err(|error| anyhow!(error))?;
        let sha256 =
            hash_windows_sparse_alternate_stream(&mut stream, &map, &extents, logical_size)?;
        let mut record = NativeAuxiliaryMetadata::new_streamed_sparse(
            "windows.alternate-data",
            "windows-backup-v1",
            restore_class,
            logical_size,
            extents,
            sha256,
        )
        .map_err(|error| anyhow!(error))?;
        record.name_encoding = NativeAuxiliaryNameEncoding::Utf16Le;
        record.name = name;
        record
            .meta
            .insert("TZAP.aux.meta.stream-type".into(), b"00000004".to_vec());
        record.meta.insert(
            "TZAP.aux.meta.stream-attributes".into(),
            format!("{attributes:08x}").into_bytes(),
        );
        auxiliary.push(record);
    }
    if sparse_layout_partial {
        let mut partial = NativeFileMetadata {
            auxiliary_records: auxiliary,
            ..NativeFileMetadata::default()
        };
        add_windows_refs_sparse_layout_omission(&mut partial);
        auxiliary = partial.auxiliary_records;
    }
    Ok((data_stream_attributes, auxiliary))
}

#[cfg(windows)]
pub(crate) fn push_windows_backup_sparse_extent(
    extents: &mut Vec<SparseExtent>,
    offset: u64,
    length: u64,
) -> Result<()> {
    const MAX_SPARSE_EXTENTS: usize = 1_048_576;
    let end = offset
        .checked_add(length)
        .ok_or_else(|| anyhow!("Windows sparse-block range overflow"))?;
    if let Some(previous) = extents.last_mut() {
        let previous_end = previous.offset + previous.length;
        if offset < previous_end {
            bail!("Windows sparse-block ranges overlap or are out of order");
        }
        if offset == previous_end {
            previous.length = end - previous.offset;
            return Ok(());
        }
    }
    if extents.len() >= MAX_SPARSE_EXTENTS {
        bail!("Windows sparse extent count exceeds the revision-45 limit");
    }
    extents.push(SparseExtent { offset, length });
    Ok(())
}

#[cfg(windows)]
pub(crate) fn hash_windows_sparse_alternate_stream(
    stream: &mut File,
    map: &[u8],
    extents: &[SparseExtent],
    logical_size: u64,
) -> Result<[u8; 32]> {
    use sha2::{Digest as _, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(map);
    let mut buffer = [0u8; 64 * 1024];
    for extent in extents {
        stream.seek(SeekFrom::Start(extent.offset))?;
        let mut remaining = extent.length;
        while remaining > 0 {
            let count = buffer
                .len()
                .min(usize::try_from(remaining).unwrap_or(usize::MAX));
            stream.read_exact(&mut buffer[..count])?;
            hasher.update(&buffer[..count]);
            remaining -= count as u64;
        }
    }
    if stream.metadata()?.len() != logical_size
        || query_windows_allocated_ranges(stream, logical_size)? != extents
    {
        bail!("Windows sparse alternate stream changed while hashing");
    }
    Ok(hasher.finalize().into())
}

#[cfg(all(not(target_os = "linux"), not(target_os = "macos"), not(windows)))]
pub(crate) fn capture_native_file_metadata(
    _input: &Path,
    _identity: InputIdentity,
) -> Result<NativeFileMetadata> {
    Ok(NativeFileMetadata::default())
}

pub(crate) fn source_os_label() -> &'static str {
    if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "freebsd") {
        "freebsd"
    } else if cfg!(target_os = "netbsd") {
        "netbsd"
    } else if cfg!(target_os = "openbsd") {
        "openbsd"
    } else if cfg!(target_os = "solaris") {
        "solaris"
    } else if cfg!(target_family = "unix") {
        "other-unix"
    } else {
        "other"
    }
}

pub(crate) fn portable_attributes(metadata: &fs::Metadata) -> Option<u32> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        let attributes = metadata.file_attributes();
        let mut projection = 0u32;
        projection |= u32::from(attributes & 0x0000_0001 != 0);
        projection |= u32::from(attributes & 0x0000_0002 != 0) << 1;
        projection |= u32::from(attributes & 0x0000_0004 != 0) << 2;
        projection |= u32::from(attributes & 0x0000_0020 != 0) << 3;
        Some(projection)
    }

    #[cfg(target_os = "macos")]
    {
        let _ = metadata;
        // Exact BSD flags are carried by TZAP.macos.st-flags. The portable
        // four-bit projection is Windows-specific and cannot be restored
        // faithfully on macOS.
        None
    }

    #[cfg(all(unix, not(target_os = "macos"), not(windows)))]
    {
        let _ = metadata;
        None
    }
}
