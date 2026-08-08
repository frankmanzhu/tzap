use crate::{
    canonical_base64_encode, encode_percent_name, linux_posix_acl_xattr_to_schily, ArchiveTimestamp, NativeAuxiliaryMetadata, NativeAuxiliaryNameEncoding,
    NativeFileMetadata, RestoreClass,
};
use std::fs::{self, File};
use std::io;
use std::os::fd::AsRawFd as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use xattr::FileExt as _;

const INLINE_XATTR_BUDGET: usize = 32 * 1024 * 1024;

/// Captures every Linux metadata class represented by TZAP's native profiles.
///
/// Symlink capture addresses the link object. Other entry kinds are pinned by
/// an `O_NOFOLLOW` descriptor and reidentified after capture.
pub fn capture_linux_metadata(input: &Path, symlink: bool) -> io::Result<NativeFileMetadata> {
    if symlink {
        return capture_linux_symlink_metadata(input);
    }

    let expected = identity(&fs::symlink_metadata(input)?);
    let (file, metadata_only) = open_linux_metadata_file(input)?;
    if identity(&file.metadata()?) != expected {
        return Err(io::Error::other("input changed before metadata capture"));
    }

    let mut native = NativeFileMetadata::default();
    let mut inline_xattr_bytes = 0usize;
    let mut captured_posix_acl = false;
    let metadata_path = metadata_only.then(|| PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd())));
    for name in if let Some(path) = &metadata_path {
        xattr::list_deref(path)
    } else {
        file.list_xattr()
    }? {
        let name_bytes = name.as_bytes();
        let Some(value) = if let Some(path) = &metadata_path {
            xattr::get_deref(path, &name)
        } else {
            file.get_xattr(&name)
        }?
        else {
            return Err(io::Error::other("xattr changed during metadata capture"));
        };
        if name_bytes == b"system.posix_acl_access" || name_bytes == b"system.posix_acl_default" {
            let key = if name_bytes.ends_with(b"access") {
                "SCHILY.acl.access"
            } else {
                "SCHILY.acl.default"
            };
            native
                .primary_pax_records
                .insert(key.into(), linux_posix_acl_xattr_to_schily(&value).map_err(io::Error::other)?);
            captured_posix_acl = true;
            native.required_profiles.push("posix-backup-v1".into());
            continue;
        }
        capture_xattr(&mut native, name_bytes, value, &mut inline_xattr_bytes)?;
    }
    if captured_posix_acl {
        native.primary_pax_records.insert("TZAP.acl.projection".into(), b"exact".to_vec());
        native
            .primary_pax_records
            .insert("TZAP.acl.syntax".into(), b"schily-posix1e-extra-id-v1".to_vec());
    }
    if !metadata_only {
        capture_linux_inode_flags(&file, &mut native)?;
        capture_linux_project_id(&file, &mut native)?;
    }
    capture_linux_times(expected, &mut native)?;
    finish_native(&mut native);
    if identity(&file.metadata()?) != expected {
        return Err(io::Error::other("input changed during metadata capture"));
    }
    Ok(native)
}

fn capture_linux_symlink_metadata(input: &Path) -> io::Result<NativeFileMetadata> {
    let expected = identity(&fs::symlink_metadata(input)?);
    let mut native = NativeFileMetadata::default();
    let mut inline_xattr_bytes = 0usize;
    for name in xattr::list(input)? {
        let Some(value) = xattr::get(input, &name)? else {
            return Err(io::Error::other("symlink xattr changed during metadata capture"));
        };
        capture_xattr(&mut native, name.as_bytes(), value, &mut inline_xattr_bytes)?;
    }
    capture_linux_times(expected, &mut native)?;
    finish_native(&mut native);
    if identity(&fs::symlink_metadata(input)?) != expected {
        return Err(io::Error::other("symlink changed during metadata capture"));
    }
    Ok(native)
}

fn capture_xattr(native: &mut NativeFileMetadata, name: &[u8], value: Vec<u8>, inline_xattr_bytes: &mut usize) -> io::Result<()> {
    let profile = if name.starts_with(b"security.") || name.starts_with(b"trusted.") || name.starts_with(b"system.") {
        "linux-backup-v1"
    } else if name.starts_with(b"com.apple.") {
        "macos-backup-v1"
    } else {
        "posix-backup-v1"
    };
    let encoded_name = encode_percent_name(name).map_err(io::Error::other)?;
    let encoded_value = canonical_base64_encode(&value);
    if inline_xattr_bytes.saturating_add(encoded_name.len()).saturating_add(encoded_value.len()) > INLINE_XATTR_BUDGET {
        let mut record = NativeAuxiliaryMetadata::new(
            "generic.xattr",
            profile,
            if profile == "linux-backup-v1" {
                RestoreClass::System
            } else {
                RestoreClass::SameOs
            },
            value,
        );
        record.name_encoding = NativeAuxiliaryNameEncoding::Bytes;
        record.name = name.to_vec();
        native.auxiliary_records.push(record);
    } else {
        *inline_xattr_bytes = inline_xattr_bytes.saturating_add(encoded_name.len()).saturating_add(encoded_value.len());
        native.primary_pax_records.insert(format!("LIBARCHIVE.xattr.{encoded_name}"), encoded_value);
    }
    native.required_profiles.push(profile.into());
    Ok(())
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct LinuxIdentity {
    dev: u64,
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
    created: Option<ArchiveTimestamp>,
}

fn identity(metadata: &fs::Metadata) -> LinuxIdentity {
    LinuxIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
        mode: metadata.mode(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        size: metadata.size(),
        mtime: (metadata.mtime(), metadata.mtime_nsec()),
        ctime: (metadata.ctime(), metadata.ctime_nsec()),
        created: metadata.created().ok().and_then(system_time_timestamp),
    }
}

fn system_time_timestamp(time: std::time::SystemTime) -> Option<ArchiveTimestamp> {
    match time.duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => Some(ArchiveTimestamp::new(i64::try_from(duration.as_secs()).ok()?, duration.subsec_nanos())),
        Err(error) => {
            let duration = error.duration();
            if duration.as_secs() == 0 && duration.subsec_nanos() != 0 {
                return None;
            }
            Some(ArchiveTimestamp::new(
                i64::try_from(-i128::from(duration.as_secs())).ok()?,
                duration.subsec_nanos(),
            ))
        }
    }
}

fn capture_linux_times(identity: LinuxIdentity, native: &mut NativeFileMetadata) -> io::Result<()> {
    native.primary_pax_records.insert(
        "TZAP.unix.ctime-observed".into(),
        ArchiveTimestamp::new(identity.ctime.0, identity.ctime.1 as u32)
            .canonical_pax_value()
            .map_err(io::Error::other)?,
    );
    // The ctime-observed record above always belongs to the linux-backup-v1
    // profile, so that profile must be selected whenever this capture runs.
    // (Selecting it only alongside `created` made archives invalid on libcs
    // where std cannot expose the birth time, e.g. musl.)
    native.required_profiles.push("linux-backup-v1".into());
    if let Some(created) = identity.created {
        native
            .primary_pax_records
            .insert("LIBARCHIVE.creationtime".into(), created.canonical_pax_value().map_err(io::Error::other)?);
    }
    native.required_profiles.push("posix-backup-v1".into());
    Ok(())
}

fn finish_native(native: &mut NativeFileMetadata) {
    native.required_profiles.sort();
    native.required_profiles.dedup();
    native
        .auxiliary_records
        .sort_by(|left, right| left.kind.cmp(&right.kind).then_with(|| left.name.cmp(&right.name)));
}

fn open_linux_metadata_file(input: &Path) -> io::Result<(File, bool)> {
    match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(input)
    {
        Ok(file) => Ok((file, false)),
        Err(error) if error.raw_os_error() == Some(libc::ENXIO) || error.raw_os_error() == Some(libc::ENODEV) => {
            use std::ffi::CString;
            use std::os::fd::FromRawFd as _;

            let path = CString::new(input.as_os_str().as_bytes()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))?;
            let fd = unsafe { libc::open(path.as_ptr(), libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_PATH) };
            if fd < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok((unsafe { File::from_raw_fd(fd) }, true))
            }
        }
        Err(error) => Err(error),
    }
}

fn capture_linux_inode_flags(file: &File, native: &mut NativeFileMetadata) -> io::Result<()> {
    let mut flags: libc::c_long = 0;
    if unsafe { libc::ioctl(file.as_raw_fd(), libc::FS_IOC_GETFLAGS, &mut flags) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOTTY) || error.raw_os_error() == Some(libc::EOPNOTSUPP) {
            return Ok(());
        }
        return Err(error);
    }
    native
        .primary_pax_records
        .insert("TZAP.linux.fsflags".into(), format!("{:016x}", flags as u64).into_bytes());
    native.required_profiles.push("linux-backup-v1".into());
    Ok(())
}

fn capture_linux_project_id(file: &File, native: &mut NativeFileMetadata) -> io::Result<()> {
    let mut attributes: linux_raw_sys::general::fsxattr = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(file.as_raw_fd(), linux_raw_sys::ioctl::FS_IOC_FSGETXATTR as libc::Ioctl, &mut attributes) } != 0 {
        let error = io::Error::last_os_error();
        if linux_project_id_ioctl_unavailable(&error) {
            return Ok(());
        }
        return Err(error);
    }
    if attributes.fsx_projid != 0 {
        native
            .primary_pax_records
            .insert("TZAP.linux.project-id".into(), attributes.fsx_projid.to_string().into_bytes());
        native.required_profiles.push("linux-backup-v1".into());
    }
    Ok(())
}

fn linux_project_id_ioctl_unavailable(error: &io::Error) -> bool {
    error
        .raw_os_error()
        .is_some_and(|code| code == libc::ENOTTY || code == libc::EOPNOTSUPP || code == libc::EINVAL || code == libc::ENOSYS)
}

#[cfg(test)]
mod tests {
    use super::linux_project_id_ioctl_unavailable;
    use std::io;

    #[test]
    fn project_id_capture_treats_missing_ioctl_as_unavailable() {
        for code in [libc::ENOTTY, libc::EOPNOTSUPP, libc::EINVAL, libc::ENOSYS] {
            assert!(linux_project_id_ioctl_unavailable(&io::Error::from_raw_os_error(code)));
        }
        assert!(!linux_project_id_ioctl_unavailable(&io::Error::from_raw_os_error(libc::EIO)));
    }
}
