use crate::{
    canonical_base64_encode, encode_percent_name, ArchiveTimestamp, NativeAuxiliaryMetadata,
    NativeAuxiliaryNameEncoding, NativeFileMetadata, RestoreClass,
};
use sha2::{Digest as _, Sha256};
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::macos::fs::MetadataExt as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use xattr::FileExt as _;

const INLINE_XATTR_BUDGET: usize = 32 * 1024 * 1024;
const O_SYMLINK: libc::c_int = 0x0020_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacosMetadataIdentity {
    len: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    dev: u64,
    ino: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
    created_seconds: i64,
    created_nanoseconds: i64,
    flags: u32,
    symlink: bool,
}

pub struct CapturedMacosMetadata {
    pub native: NativeFileMetadata,
    pub identity: MacosMetadataIdentity,
}

pub fn capture_macos_metadata(input: &Path, symlink: bool) -> io::Result<CapturedMacosMetadata> {
    let file = if symlink {
        open_symlink(input)?
    } else {
        open_metadata_file(input)?
    };
    let metadata = file.metadata()?;
    if metadata.file_type().is_symlink() != symlink {
        return Err(io::Error::other(
            "input kind changed before metadata capture",
        ));
    }
    let identity = metadata_identity(&metadata);
    let native = capture_from_file(input, &file, identity, symlink)?;
    let final_metadata = file.metadata()?;
    if metadata_identity(&final_metadata) != identity {
        return Err(io::Error::other("input changed during metadata capture"));
    }
    Ok(CapturedMacosMetadata { native, identity })
}

pub fn open_macos_resource_fork(
    input: &Path,
    symlink: bool,
    expected_identity: MacosMetadataIdentity,
    expected_size: u64,
) -> io::Result<Box<dyn Read>> {
    let source = if symlink {
        ResourceForkSource::Symlink(open_symlink(input)?)
    } else {
        ResourceForkSource::File(open_regular_resource_fork(input)?)
    };
    Ok(Box::new(ResourceForkReader::new(
        source,
        expected_identity,
        Some(expected_size),
    )?))
}

fn capture_from_file(
    input: &Path,
    file: &File,
    identity: MacosMetadataIdentity,
    symlink: bool,
) -> io::Result<NativeFileMetadata> {
    use std::os::unix::fs::FileTypeExt as _;

    let mut native = NativeFileMetadata::default();
    native.primary_pax_records.insert(
        "TZAP.macos.st-flags".into(),
        format!("{:016x}", identity.flags).into_bytes(),
    );
    native.primary_pax_records.insert(
        "TZAP.unix.ctime-observed".into(),
        ArchiveTimestamp::new(
            identity.changed_seconds,
            u32::try_from(identity.changed_nanoseconds)
                .map_err(|_| io::Error::other("negative macOS ctime nanoseconds"))?,
        )
        .canonical_pax_value()
        .map_err(invalid_metadata)?,
    );
    native.primary_pax_records.insert(
        "LIBARCHIVE.creationtime".into(),
        ArchiveTimestamp::new(
            identity.created_seconds,
            u32::try_from(identity.created_nanoseconds)
                .map_err(|_| io::Error::other("negative macOS birthtime nanoseconds"))?,
        )
        .canonical_pax_value()
        .map_err(invalid_metadata)?,
    );

    let metadata = file.metadata()?;
    let device_without_metadata_api =
        metadata.file_type().is_char_device() || metadata.file_type().is_block_device();
    let names = match file.list_xattr() {
        Ok(names) => names.collect::<Vec<_>>(),
        Err(error)
            if device_without_metadata_api
                && error
                    .raw_os_error()
                    .is_some_and(|code| code == libc::EPERM || code == libc::ENOTSUP) =>
        {
            Vec::new()
        }
        Err(error) => return Err(error),
    };

    let mut inline_xattr_bytes = 0usize;
    for name in names {
        let name_bytes = name.as_bytes();
        if name_bytes == b"com.apple.ResourceFork" {
            let source = if symlink {
                ResourceForkSource::Symlink(file.try_clone()?)
            } else {
                ResourceForkSource::File(open_regular_resource_fork(input)?)
            };
            native
                .auxiliary_records
                .push(capture_resource_fork(source, identity)?);
            continue;
        }

        let value = file
            .get_xattr(&name)?
            .ok_or_else(|| io::Error::other("xattr changed during metadata capture"))?;
        if name_bytes == b"com.apple.FinderInfo" {
            if value.len() != 32 {
                return Err(io::Error::other("FinderInfo is not exactly 32 bytes"));
            }
            native.auxiliary_records.push(NativeAuxiliaryMetadata::new(
                "macos.finder-info",
                "macos-backup-v1",
                RestoreClass::SameOs,
                value,
            ));
            continue;
        }

        let encoded_size = value.len().saturating_mul(4).div_ceil(3);
        if inline_xattr_bytes
            .saturating_add(name_bytes.len())
            .saturating_add(encoded_size)
            > INLINE_XATTR_BUDGET
        {
            let mut record = NativeAuxiliaryMetadata::new(
                "generic.xattr",
                if name_bytes.starts_with(b"com.apple.") {
                    "macos-backup-v1"
                } else {
                    "posix-backup-v1"
                },
                if is_system_xattr(name_bytes) {
                    RestoreClass::System
                } else {
                    RestoreClass::SameOs
                },
                value,
            );
            record.name_encoding = NativeAuxiliaryNameEncoding::Bytes;
            record.name = name_bytes.to_vec();
            native.auxiliary_records.push(record);
        } else {
            let encoded_name = encode_percent_name(name_bytes).map_err(invalid_metadata)?;
            let encoded_value = canonical_base64_encode(&value);
            inline_xattr_bytes = inline_xattr_bytes
                .saturating_add(encoded_name.len())
                .saturating_add(encoded_value.len());
            native
                .primary_pax_records
                .insert(format!("LIBARCHIVE.xattr.{encoded_name}"), encoded_value);
        }
    }

    let acl = match capture_acl(file) {
        Ok(acl) => acl,
        Err(error)
            if device_without_metadata_api
                && error
                    .raw_os_error()
                    .is_some_and(|code| code == libc::EPERM || code == libc::ENOTSUP) =>
        {
            None
        }
        Err(error) => return Err(error),
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

    native.required_profiles = vec!["macos-backup-v1".into(), "posix-backup-v1".into()];
    native.auxiliary_records.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.name.cmp(&right.name))
    });
    Ok(native)
}

fn metadata_identity(metadata: &fs::Metadata) -> MacosMetadataIdentity {
    MacosMetadataIdentity {
        len: metadata.len(),
        mode: metadata.mode(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        dev: metadata.dev(),
        ino: metadata.ino(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
        created_seconds: metadata.st_birthtime(),
        created_nanoseconds: metadata.st_birthtime_nsec(),
        flags: metadata.st_flags(),
        symlink: metadata.file_type().is_symlink(),
    }
}

fn open_metadata_file(input: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    const O_EVTONLY: libc::c_int = 0x0000_8000;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK | O_EVTONLY)
        .open(input)
}

fn open_symlink(input: &Path) -> io::Result<File> {
    let path = CString::new(input.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))?;
    // SAFETY: `path` is NUL-terminated and the returned descriptor is uniquely owned.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC | O_SYMLINK) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: `fd` was just opened successfully and ownership moves to File.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn open_regular_resource_fork(input: &Path) -> io::Result<File> {
    let mut fork_path = PathBuf::from(input);
    fork_path.push("..namedfork/rsrc");
    File::open(fork_path)
}

enum ResourceForkSource {
    File(File),
    Symlink(File),
}

struct ResourceForkReader {
    source: ResourceForkSource,
    expected_identity: MacosMetadataIdentity,
    logical_size: u64,
    offset: u64,
    validated: bool,
}

impl ResourceForkReader {
    fn new(
        source: ResourceForkSource,
        expected_identity: MacosMetadataIdentity,
        expected_size: Option<u64>,
    ) -> io::Result<Self> {
        if resource_fork_identity(&source)? != expected_identity {
            return Err(io::Error::other(
                "macOS resource-fork owner changed before read",
            ));
        }
        let logical_size = resource_fork_size(&source)?;
        if expected_size.is_some_and(|size| size != logical_size) {
            return Err(io::Error::other(
                "macOS resource fork changed after metadata scan",
            ));
        }
        Ok(Self {
            source,
            expected_identity,
            logical_size,
            offset: 0,
            validated: false,
        })
    }

    fn validate_finished(&mut self) -> io::Result<()> {
        if !self.validated {
            if resource_fork_identity(&self.source)? != self.expected_identity
                || resource_fork_size(&self.source)? != self.logical_size
            {
                return Err(io::Error::other("macOS resource fork changed during read"));
            }
            self.validated = true;
        }
        Ok(())
    }
}

impl Read for ResourceForkReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.offset == self.logical_size {
            self.validate_finished()?;
            return Ok(0);
        }
        let count = usize::try_from((self.logical_size - self.offset).min(output.len() as u64))
            .map_err(|_| io::Error::other("resource fork read size overflow"))?;
        let read = read_resource_fork(&self.source, self.offset, &mut output[..count])?;
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

fn capture_resource_fork(
    source: ResourceForkSource,
    identity: MacosMetadataIdentity,
) -> io::Result<NativeAuxiliaryMetadata> {
    let mut reader = ResourceForkReader::new(source, identity, None)?;
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

fn resource_fork_identity(source: &ResourceForkSource) -> io::Result<MacosMetadataIdentity> {
    match source {
        ResourceForkSource::File(fork) => {
            let path = descriptor_path(fork)?;
            let owner = path
                .parent()
                .and_then(Path::parent)
                .ok_or_else(|| io::Error::other("invalid named-fork descriptor path"))?;
            Ok(metadata_identity(&fs::metadata(owner)?))
        }
        ResourceForkSource::Symlink(file) => Ok(metadata_identity(&file.metadata()?)),
    }
}

fn descriptor_path(file: &File) -> io::Result<PathBuf> {
    use std::os::unix::ffi::OsStringExt as _;

    let mut path = vec![0u8; libc::PATH_MAX as usize];
    // SAFETY: the output buffer is writable for PATH_MAX bytes and fd is live.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, path.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let length = path
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| io::Error::other("unterminated descriptor path"))?;
    path.truncate(length);
    Ok(PathBuf::from(std::ffi::OsString::from_vec(path)))
}

fn resource_fork_size(source: &ResourceForkSource) -> io::Result<u64> {
    match source {
        ResourceForkSource::File(file) => Ok(file.metadata()?.len()),
        ResourceForkSource::Symlink(file) => {
            let size = symlink_resource_fork_read(file, 0, None)?;
            u64::try_from(size).map_err(|_| io::Error::other("negative resource fork size"))
        }
    }
}

fn read_resource_fork(
    source: &ResourceForkSource,
    position: u64,
    output: &mut [u8],
) -> io::Result<usize> {
    match source {
        ResourceForkSource::File(file) => {
            use std::os::unix::fs::FileExt as _;
            file.read_at(output, position)
        }
        ResourceForkSource::Symlink(file) => {
            symlink_resource_fork_read(file, position, Some(output))
        }
    }
}

fn symlink_resource_fork_read(
    file: &File,
    position: u64,
    output: Option<&mut [u8]>,
) -> io::Result<usize> {
    use std::ffi::{c_char, c_int, c_void};

    unsafe extern "C" {
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
    let position = u32::try_from(position)
        .map_err(|_| io::Error::other("resource fork position exceeds Darwin limits"))?;
    let (pointer, length) = output.map_or((std::ptr::null_mut(), 0), |buffer| {
        (buffer.as_mut_ptr().cast(), buffer.len())
    });
    // SAFETY: fd is live, name is NUL-terminated, and the optional output
    // buffer remains writable for `length` bytes for the duration of the call.
    let result = unsafe {
        fgetxattr(
            file.as_raw_fd(),
            RESOURCE_FORK.as_ptr().cast(),
            pointer,
            length,
            position,
            0,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        usize::try_from(result).map_err(|_| io::Error::other("resource fork size overflow"))
    }
}

fn capture_acl(file: &File) -> io::Result<Option<Vec<u8>>> {
    use std::ptr;

    type Acl = *mut libc::c_void;
    type AclEntry = *mut libc::c_void;
    const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;
    const ACL_FIRST_ENTRY: libc::c_int = 0;

    unsafe extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, acl_type: libc::c_int) -> Acl;
        fn acl_get_entry(acl: Acl, entry_id: libc::c_int, entry: *mut AclEntry) -> libc::c_int;
        fn acl_size(acl: Acl) -> libc::ssize_t;
        fn acl_copy_ext(buffer: *mut libc::c_void, acl: Acl, size: libc::ssize_t) -> libc::ssize_t;
        fn acl_free(object: *mut libc::c_void) -> libc::c_int;
    }

    // SAFETY: `file` owns a live descriptor. The returned ACL is freed below.
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
        // SAFETY: `acl` is valid and `first` points to writable storage.
        match unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, &mut first) } {
            1 => return Ok(None),
            0 => {}
            _ => return Err(io::Error::last_os_error()),
        }
        // SAFETY: `acl` remains valid.
        let size = unsafe { acl_size(acl) };
        if size < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut external = vec![
            0u8;
            usize::try_from(size).map_err(|_| io::Error::other(
                "macOS ACL exceeds platform limits"
            ))?
        ];
        // SAFETY: the destination contains exactly `size` writable bytes.
        let copied = unsafe { acl_copy_ext(external.as_mut_ptr().cast(), acl, size) };
        if copied < 0 {
            return Err(io::Error::last_os_error());
        }
        external.truncate(
            usize::try_from(copied)
                .map_err(|_| io::Error::other("macOS ACL exceeds platform limits"))?,
        );
        Ok(Some(external))
    })();
    // SAFETY: `acl` was returned by acl_get_fd_np and is not used afterward.
    unsafe {
        acl_free(acl);
    }
    result
}

fn is_system_xattr(name: &[u8]) -> bool {
    name.starts_with(b"security.") || name.starts_with(b"trusted.") || name.starts_with(b"system.")
}

fn invalid_metadata(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}
