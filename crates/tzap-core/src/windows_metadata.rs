use crate::{
    ArchiveTimestamp, NativeAuxiliaryMetadata, NativeAuxiliaryNameEncoding, NativeFileMetadata,
    RestoreClass,
};
use std::fs::{self, File};
use std::io;
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::AsRawHandle as _;
use std::path::Path;

/// Captures Windows basic information, security, reparse data, case-sensitivity,
/// alternate data, EA/property data, and object IDs into TZAP v45 metadata.
pub fn capture_windows_metadata(input: &Path) -> io::Result<NativeFileMetadata> {
    use std::mem::size_of;
    use windows_sys::Win32::Storage::FileSystem::{
        FileBasicInfo, GetFileInformationByHandleEx, FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
    };

    let file = fs::OpenOptions::new()
        .access_mode(FILE_GENERIC_READ)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(input)?;
    let mut basic = FILE_BASIC_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle().cast(),
            FileBasicInfo,
            (&mut basic as *mut FILE_BASIC_INFO).cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }

    let mut native = NativeFileMetadata::default();
    native.primary_pax_records.insert(
        "TZAP.windows.file-attributes".into(),
        format!("{:08x}", basic.FileAttributes).into_bytes(),
    );
    for (key, value) in [
        ("atime", basic.LastAccessTime),
        ("LIBARCHIVE.creationtime", basic.CreationTime),
        ("TZAP.windows.change-time", basic.ChangeTime),
    ] {
        native.primary_pax_records.insert(
            key.into(),
            windows_filetime_timestamp(value as u64)?
                .canonical_pax_value()
                .map_err(io::Error::other)?,
        );
    }

    let reparse_data = if basic.FileAttributes & 0x0000_0400 != 0 {
        let data = query_windows_reparse_data(&file)?;
        if data.len() < 8 {
            return Err(io::Error::other("Windows reparse data is truncated"));
        }
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
        .push(capture_windows_security_descriptor(&file)?);
    if basic.FileAttributes & 0x0000_0010 != 0 {
        if let Some(case_sensitive) = query_windows_directory_case_sensitive(&file)? {
            native.primary_pax_records.insert(
                "TZAP.windows.directory-case-sensitive".into(),
                if case_sensitive { b"1" } else { b"0" }.to_vec(),
            );
        }
    }
    let (data_stream_attributes, mut streams) =
        capture_windows_backup_streams(&file, reparse_data.as_deref())?;
    if basic.FileAttributes & (0x0000_0010 | 0x0000_0400) == 0 {
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

fn windows_filetime_timestamp(value_100ns: u64) -> io::Result<ArchiveTimestamp> {
    const WINDOWS_TO_UNIX_EPOCH_100NS: i128 = 116_444_736_000_000_000;
    const TICKS_PER_SECOND: i128 = 10_000_000;
    let unix_100ns = i128::from(value_100ns) - WINDOWS_TO_UNIX_EPOCH_100NS;
    let seconds = i64::try_from(unix_100ns.div_euclid(TICKS_PER_SECOND))
        .map_err(|_| io::Error::other("Windows timestamp exceeds TZAP range"))?;
    let nanoseconds = (unix_100ns.rem_euclid(TICKS_PER_SECOND) * 100) as u32;
    Ok(ArchiveTimestamp::new(seconds, nanoseconds))
}

fn query_windows_reparse_data(file: &File) -> io::Result<Vec<u8>> {
    use windows_sys::Win32::System::Ioctl::FSCTL_GET_REPARSE_POINT;
    use windows_sys::Win32::System::IO::DeviceIoControl;

    let mut buffer = vec![0u8; 16 * 1024];
    let mut returned = 0u32;
    if unsafe {
        DeviceIoControl(
            file.as_raw_handle().cast(),
            FSCTL_GET_REPARSE_POINT,
            std::ptr::null_mut(),
            0,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    buffer.truncate(returned as usize);
    Ok(buffer)
}

fn query_windows_directory_case_sensitive(file: &File) -> io::Result<Option<bool>> {
    use std::mem::size_of;
    use windows_sys::Win32::Foundation::{
        ERROR_INVALID_FUNCTION, ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FileCaseSensitiveInfo, GetFileInformationByHandleEx, FILE_CASE_SENSITIVE_INFO,
    };
    use windows_sys::Win32::System::SystemServices::FILE_CS_FLAG_CASE_SENSITIVE_DIR;

    let mut info = FILE_CASE_SENSITIVE_INFO::default();
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
            "Windows returned unknown case-sensitivity flags",
        ));
    }
    Ok(Some(info.Flags & FILE_CS_FLAG_CASE_SENSITIVE_DIR != 0))
}

fn capture_windows_security_descriptor(file: &File) -> io::Result<NativeAuxiliaryMetadata> {
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, INVALID_HANDLE_VALUE};
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

    const BASE: u32 =
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let original = file.as_raw_handle().cast();
    let sacl_handle = if enable_windows_privilege(windows_sys::Win32::Security::SE_SECURITY_NAME) {
        let handle = unsafe {
            ReOpenFile(
                original,
                READ_CONTROL | ACCESS_SYSTEM_SECURITY,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                0,
            )
        };
        (handle != INVALID_HANDLE_VALUE).then_some(handle)
    } else {
        None
    };
    let requested = BASE
        | if sacl_handle.is_some() {
            SACL_SECURITY_INFORMATION
        } else {
            0
        };
    let mut descriptor = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            sacl_handle.unwrap_or(original),
            SE_FILE_OBJECT,
            requested,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if let Some(handle) = sacl_handle {
        unsafe {
            CloseHandle(handle);
        }
    }
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    if descriptor.is_null() {
        return Err(io::Error::other(
            "Windows returned an empty security descriptor",
        ));
    }
    let length = unsafe { GetSecurityDescriptorLength(descriptor) } as usize;
    let payload = unsafe { std::slice::from_raw_parts(descriptor.cast::<u8>(), length) }.to_vec();
    if !unsafe { LocalFree(descriptor) }.is_null() {
        return Err(io::Error::other(
            "failed to release Windows security descriptor",
        ));
    }
    if payload.len() < 20 {
        return Err(io::Error::other("Windows security descriptor is truncated"));
    }
    let control = u16::from_le_bytes(payload[2..4].try_into().unwrap());
    let mut represented = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION;
    if control & 0x0004 != 0 {
        represented |= DACL_SECURITY_INFORMATION;
        represented |= if control & 0x1000 != 0 {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_DACL_SECURITY_INFORMATION
        };
    }
    if control & 0x0010 != 0 {
        represented |= SACL_SECURITY_INFORMATION;
        represented |= if control & 0x2000 != 0 {
            PROTECTED_SACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_SACL_SECURITY_INFORMATION
        };
    }
    let mut record = NativeAuxiliaryMetadata::new(
        "windows.security-descriptor",
        "windows-backup-v1",
        RestoreClass::System,
        payload,
    );
    record.meta.insert(
        "TZAP.aux.meta.security-information".into(),
        format!("{represented:08x}").into_bytes(),
    );
    Ok(record)
}

fn enable_windows_privilege(name: *const u16) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, SetLastError};
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = std::ptr::null_mut();
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
    let mut privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        ..Default::default()
    };
    let enabled = if unsafe {
        LookupPrivilegeValueW(std::ptr::null(), name, &mut privileges.Privileges[0].Luid)
    } == 0
    {
        false
    } else {
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        unsafe {
            SetLastError(0);
        }
        unsafe {
            AdjustTokenPrivileges(
                token,
                0,
                &privileges,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ) != 0
                && GetLastError() == 0
        }
    };
    unsafe {
        CloseHandle(token);
    }
    enabled
}

struct WindowsBackupReader {
    handle: windows_sys::Win32::Foundation::HANDLE,
    context: *mut std::ffi::c_void,
}

impl WindowsBackupReader {
    fn new(file: &File) -> Self {
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
                return if offset == 0 {
                    Ok(false)
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Windows backup stream ended mid-record",
                    ))
                };
            }
            offset += read as usize;
        }
        Ok(true)
    }

    fn read_vec(&mut self, size: u64) -> io::Result<Vec<u8>> {
        let size = usize::try_from(size)
            .map_err(|_| io::Error::other("Windows backup stream exceeds address space"))?;
        let mut payload = vec![0; size];
        if size != 0 && !self.read_optional_exact(&mut payload)? {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Windows backup stream payload is missing",
            ));
        }
        Ok(payload)
    }

    fn skip(&mut self, size: u64) -> io::Result<()> {
        use windows_sys::Win32::Storage::FileSystem::BackupSeek;
        let mut low = 0u32;
        let mut high = 0u32;
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
        if (u64::from(high) << 32) | u64::from(low) != size {
            return Err(io::Error::other(
                "Windows backup stream could not be skipped completely",
            ));
        }
        Ok(())
    }
}

impl Drop for WindowsBackupReader {
    fn drop(&mut self) {
        use windows_sys::Win32::Storage::FileSystem::BackupRead;
        let mut ignored = 0;
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

fn capture_windows_backup_streams(
    file: &File,
    expected_reparse: Option<&[u8]>,
) -> io::Result<(u32, Vec<NativeAuxiliaryMetadata>)> {
    use std::os::windows::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        BACKUP_ALTERNATE_DATA, BACKUP_DATA, BACKUP_EA_DATA, BACKUP_LINK, BACKUP_OBJECT_ID,
        BACKUP_PROPERTY_DATA, BACKUP_REPARSE_DATA, BACKUP_SECURITY_DATA, BACKUP_SPARSE_BLOCK,
        BACKUP_TXFS_DATA,
    };

    const HEADER_LEN: usize = 20;
    const RETAINED_CAP: u64 = 64 * 1024 * 1024;
    let mut reader = WindowsBackupReader::new(file);
    let mut data_attributes = None;
    let mut auxiliary = Vec::new();
    loop {
        let mut header = [0u8; HEADER_LEN];
        if !reader.read_optional_exact(&mut header)? {
            break;
        }
        let stream_id = u32::from_le_bytes(header[0..4].try_into().unwrap());
        let attributes = u32::from_le_bytes(header[4..8].try_into().unwrap());
        let signed_size = i64::from_le_bytes(header[8..16].try_into().unwrap());
        if signed_size < 0 {
            return Err(io::Error::other(
                "Windows BackupRead returned a negative stream size",
            ));
        }
        let size = signed_size as u64;
        let name_size = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
        if name_size % 2 != 0 || name_size > 65_534 {
            return Err(io::Error::other(
                "Windows BackupRead returned an invalid stream name",
            ));
        }
        let name = reader.read_vec(name_size as u64)?;
        match stream_id {
            BACKUP_DATA => {
                data_attributes = Some(attributes);
                reader.skip(size)?;
            }
            BACKUP_SECURITY_DATA | BACKUP_LINK | BACKUP_SPARSE_BLOCK => reader.skip(size)?,
            BACKUP_REPARSE_DATA => {
                let payload = reader.read_vec(size)?;
                if expected_reparse != Some(payload.as_slice()) {
                    return Err(io::Error::other(
                        "Windows reparse stream disagrees with the pinned handle",
                    ));
                }
            }
            BACKUP_ALTERNATE_DATA | BACKUP_EA_DATA | BACKUP_PROPERTY_DATA | BACKUP_OBJECT_ID => {
                if size > RETAINED_CAP {
                    return Err(io::Error::other(
                        "Windows metadata stream exceeds the retained payload cap",
                    ));
                }
                let payload = reader.read_vec(size)?;
                let (kind, stream_type, restore_class) = match stream_id {
                    BACKUP_ALTERNATE_DATA => (
                        "windows.alternate-data",
                        "00000004",
                        if attributes & 2 != 0 {
                            RestoreClass::System
                        } else {
                            RestoreClass::SameOs
                        },
                    ),
                    BACKUP_EA_DATA => (
                        "windows.ea-data",
                        "00000002",
                        if attributes & 2 != 0 {
                            RestoreClass::System
                        } else {
                            RestoreClass::SameOs
                        },
                    ),
                    BACKUP_PROPERTY_DATA => (
                        "windows.property-data",
                        "00000006",
                        if attributes & 2 != 0 {
                            RestoreClass::System
                        } else {
                            RestoreClass::SameOs
                        },
                    ),
                    _ => ("windows.object-id", "00000007", RestoreClass::System),
                };
                let mut record =
                    NativeAuxiliaryMetadata::new(kind, "windows-backup-v1", restore_class, payload);
                if stream_id == BACKUP_ALTERNATE_DATA {
                    record.name_encoding = NativeAuxiliaryNameEncoding::Utf16Le;
                    record.name = name;
                } else if !name.is_empty() {
                    return Err(io::Error::other(
                        "unnamed Windows metadata stream had a name",
                    ));
                }
                record.meta.insert(
                    "TZAP.aux.meta.stream-type".into(),
                    stream_type.as_bytes().to_vec(),
                );
                record.meta.insert(
                    "TZAP.aux.meta.stream-attributes".into(),
                    format!("{attributes:08x}").into_bytes(),
                );
                auxiliary.push(record);
            }
            BACKUP_TXFS_DATA => {
                return Err(io::Error::other(
                    "Windows transactional streams are not representable",
                ));
            }
            _ => {
                return Err(io::Error::other(format!(
                    "unsupported Windows backup stream {stream_id}"
                )));
            }
        }
    }
    let metadata = file.metadata()?;
    let data_attributes = data_attributes.unwrap_or_else(|| {
        if metadata.file_attributes() & 0x0000_0200 != 0 {
            8
        } else {
            0
        }
    });
    Ok((data_attributes, auxiliary))
}
