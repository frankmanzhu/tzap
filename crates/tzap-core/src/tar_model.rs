use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt, SystemTimeSpec};
use cap_std::ambient_authority;
use cap_std::fs::{Dir as CapDir, OpenOptions as CapOpenOptions};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use unicode_normalization::UnicodeNormalization;

#[cfg(unix)]
use crate::entry_metadata::canonical_base64_decode;
#[cfg(any(windows, target_os = "macos"))]
use crate::entry_metadata::parse_timestamp;
#[cfg(target_os = "linux")]
use crate::entry_metadata::schily_posix_acl_to_linux_xattr;
#[cfg(windows)]
use cap_std::fs::OpenOptionsExt as _;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    FileBasicInfo, GetFileInformationByHandleEx, SetFileInformationByHandle, DELETE,
    FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_WRITE_ATTRIBUTES,
};

use crate::entry_metadata::{
    decode_percent_name, parse_auxiliary_record, parse_canonical_pax, parse_primary_metadata,
    parse_sparse_payload, validate_group_metadata, ArchiveTimestamp, AuxiliaryRecord,
    AuxiliaryStreamValidator, CaptureReportRow, CaptureStatus, MemberMetadata, PaxRecords,
    PortableMetadataMirror, PrimaryMetadata, RestoreClass, RestorePolicy, SparseExtent,
    SparseStreamValidator, CAPTURE_REPORT_KIND, HAS_NATIVE_METADATA, HAS_SPARSE_EXTENTS,
    MAX_AGGREGATE_PAX_PAYLOAD, MAX_LOCAL_PAX_PAYLOAD, REQUIRES_SYSTEM_RESTORE,
};
use crate::format::{ExtractError, FormatError};
use crate::metadata::validate_file_path_bytes;

const TAR_BLOCK_LEN: usize = 512;
const MACOS_SETTABLE_ORDINARY_FLAGS: u32 = 0x0000_800f;
const MACOS_SETTABLE_SYSTEM_FLAGS: u32 = 0x0007_0000;
// UF_IMMUTABLE/UF_APPEND, entitlement-protected UF_DATAVAULT, and every
// Darwin SF_SUPPORTED bit have System-class restore semantics even when this
// reader deliberately does not register the bit for built-in application.
const MACOS_SYSTEM_CLASS_FLAGS: u32 = 0x009f_0086;
const MACOS_KNOWN_SETTABLE_FLAGS: u32 = MACOS_SETTABLE_ORDINARY_FLAGS | MACOS_SETTABLE_SYSTEM_FLAGS;

fn parse_macos_flags(encoded: &[u8]) -> Result<u32, FormatError> {
    std::str::from_utf8(encoded)
        .ok()
        .and_then(|value| u64::from_str_radix(value, 16).ok())
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(FormatError::InvalidArchive("invalid macOS file flags"))
}

fn macos_flags_supported(flags: u32) -> bool {
    flags & !MACOS_KNOWN_SETTABLE_FLAGS == 0
}

fn macos_flags_require_system(flags: u32) -> bool {
    flags & MACOS_SYSTEM_CLASS_FLAGS != 0
}

fn macos_system_flags_privileges_available(flags: u32) -> bool {
    if flags & MACOS_SETTABLE_SYSTEM_FLAGS == 0 {
        return true;
    }
    #[cfg(target_os = "macos")]
    {
        // Setting system file flags is restricted to the superuser by Darwin.
        (unsafe { libc::geteuid() }) == 0
    }
    #[cfg(not(target_os = "macos"))]
    false
}

fn special_object_restore_supported(kind: TarEntryKind) -> bool {
    #[cfg(target_os = "linux")]
    {
        let _ = kind;
        true
    }
    #[cfg(target_os = "macos")]
    {
        kind == TarEntryKind::Fifo || (unsafe { libc::geteuid() }) == 0
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = kind;
        false
    }
}

#[cfg(target_os = "macos")]
fn validate_darwin_acl_external(value: &[u8]) -> Result<(), FormatError> {
    const ACL_MAX_ENTRIES: usize = 128;
    const DARWIN_EXTERNAL_ACL_HEADER: usize = 40;
    const DARWIN_EXTERNAL_ACE_SIZE: usize = 28;
    const DARWIN_EXTERNAL_ACL_MAGIC: [u8; 4] = [0x01, 0x2c, 0xc1, 0x6d];
    if value.get(..4) != Some(DARWIN_EXTERNAL_ACL_MAGIC.as_slice()) {
        return Err(FormatError::InvalidArchive(
            "macOS ACL external form has an invalid magic value",
        ));
    }
    let entry_count = value
        .get(36..40)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or(FormatError::InvalidArchive(
            "macOS ACL external form is truncated",
        ))? as usize;
    let expected = DARWIN_EXTERNAL_ACL_HEADER
        .checked_add(entry_count.checked_mul(DARWIN_EXTERNAL_ACE_SIZE).ok_or(
            FormatError::InvalidArchive("macOS ACL entry count overflows"),
        )?)
        .ok_or(FormatError::InvalidArchive("macOS ACL size overflows"))?;
    if entry_count > ACL_MAX_ENTRIES || expected != value.len() {
        return Err(FormatError::InvalidArchive(
            "macOS ACL external form has an invalid size",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
const LINUX_KNOWN_FSFLAGS: u64 = (linux_raw_sys::general::FS_SECRM_FL
    | linux_raw_sys::general::FS_UNRM_FL
    | linux_raw_sys::general::FS_COMPR_FL
    | linux_raw_sys::general::FS_SYNC_FL
    | linux_raw_sys::general::FS_IMMUTABLE_FL
    | linux_raw_sys::general::FS_APPEND_FL
    | linux_raw_sys::general::FS_NODUMP_FL
    | linux_raw_sys::general::FS_NOATIME_FL
    | linux_raw_sys::general::FS_DIRTY_FL
    | linux_raw_sys::general::FS_COMPRBLK_FL
    | linux_raw_sys::general::FS_NOCOMP_FL
    | linux_raw_sys::general::FS_ENCRYPT_FL
    | linux_raw_sys::general::FS_BTREE_FL
    | linux_raw_sys::general::FS_IMAGIC_FL
    | linux_raw_sys::general::FS_JOURNAL_DATA_FL
    | linux_raw_sys::general::FS_NOTAIL_FL
    | linux_raw_sys::general::FS_DIRSYNC_FL
    | linux_raw_sys::general::FS_TOPDIR_FL
    | linux_raw_sys::general::FS_HUGE_FILE_FL
    | linux_raw_sys::general::FS_EXTENT_FL
    | linux_raw_sys::general::FS_VERITY_FL
    | linux_raw_sys::general::FS_EA_INODE_FL
    | linux_raw_sys::general::FS_EOFBLOCKS_FL
    | linux_raw_sys::general::FS_NOCOW_FL
    | linux_raw_sys::general::FS_DAX_FL
    | linux_raw_sys::general::FS_INLINE_DATA_FL
    | linux_raw_sys::general::FS_PROJINHERIT_FL
    | linux_raw_sys::general::FS_CASEFOLD_FL) as u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TarEntryKind {
    Regular,
    Directory,
    Symlink,
    Hardlink,
    CharacterDevice,
    BlockDevice,
    Fifo,
}

impl TarEntryKind {
    pub fn to_u8(self) -> u8 {
        match self {
            TarEntryKind::Regular => 0,
            TarEntryKind::Directory => 5,
            TarEntryKind::Symlink => 2,
            TarEntryKind::Hardlink => 1,
            TarEntryKind::CharacterDevice => 3,
            TarEntryKind::BlockDevice => 4,
            TarEntryKind::Fifo => 6,
        }
    }

    pub fn from_u8(val: u8) -> Self {
        match val {
            5 => TarEntryKind::Directory,
            2 => TarEntryKind::Symlink,
            1 => TarEntryKind::Hardlink,
            3 => TarEntryKind::CharacterDevice,
            4 => TarEntryKind::BlockDevice,
            6 => TarEntryKind::Fifo,
            _ => TarEntryKind::Regular,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataOperation {
    Capture,
    Parse,
    Verify,
    Plan,
    Restore,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataDiagnosticStatus {
    Partial,
    Unsupported,
    Skipped,
    Materialized,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataDiagnostic {
    pub path: Vec<u8>,
    pub profile: String,
    pub metadata_class: String,
    pub operation: MetadataOperation,
    pub status: MetadataDiagnosticStatus,
    pub message: String,
    pub restore_policy: Option<RestorePolicy>,
    pub restore_phase: Option<u8>,
    pub native_host_error: Option<String>,
    pub bytes_staged: Option<u64>,
    pub bytes_committed: Option<u64>,
}

impl MetadataDiagnostic {
    fn new(
        path: &[u8],
        profile: impl Into<String>,
        metadata_class: impl Into<String>,
        operation: MetadataOperation,
        status: MetadataDiagnosticStatus,
        message: impl Into<String>,
    ) -> Self {
        Self {
            path: path.to_vec(),
            profile: profile.into(),
            metadata_class: metadata_class.into(),
            operation,
            status,
            message: message.into(),
            restore_policy: None,
            restore_phase: None,
            native_host_error: None,
            bytes_staged: None,
            bytes_committed: None,
        }
    }

    fn for_restore(mut self, policy: RestorePolicy, phase: u8) -> Self {
        self.restore_policy = Some(policy);
        self.restore_phase = Some(phase);
        self
    }

    fn with_native_error(mut self, error: &std::io::Error) -> Self {
        self.native_host_error = Some(error.to_string());
        self
    }

    fn with_bytes(mut self, staged: u64, committed: u64) -> Self {
        self.bytes_staged = Some(staged);
        self.bytes_committed = Some(committed);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestorePolicyCapability {
    pub policy: RestorePolicy,
    pub policy_complete: bool,
    pub degraded_restore_available: bool,
    pub reason: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryMetadataVerification {
    pub path: Vec<u8>,
    pub capture_status: CaptureStatus,
    pub required_profiles: Vec<String>,
    pub optional_profiles: Vec<String>,
    pub auxiliary_kinds: Vec<String>,
    pub policy_capabilities: Vec<RestorePolicyCapability>,
    pub full_fidelity_possible: bool,
    pub diagnostics: Vec<MetadataDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataVerificationReport {
    pub all_capture_complete: bool,
    pub full_fidelity_possible: bool,
    pub profiles_present: Vec<String>,
    pub auxiliary_kinds_present: Vec<String>,
    pub entries: Vec<EntryMetadataVerification>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedTarMember {
    pub path: Vec<u8>,
    pub kind: TarEntryKind,
    pub data: Vec<u8>,
    pub link_target: Option<Vec<u8>>,
    pub mode: u32,
    pub mtime: ArchiveTimestamp,
    pub logical_size: u64,
    pub reparse_placeholder: bool,
    pub v45_metadata: Option<MemberMetadata>,
    pub diagnostics: Vec<MetadataDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTarMember<'a> {
    pub path: Vec<u8>,
    pub kind: TarEntryKind,
    pub data: &'a [u8],
    pub link_target: Option<Vec<u8>>,
    pub mode: u32,
    pub mtime: ArchiveTimestamp,
    pub logical_size: u64,
    pub reparse_placeholder: bool,
    pub diagnostics: Vec<MetadataDiagnostic>,
    pub v45_metadata: MemberMetadata,
}

impl ParsedTarMember<'_> {
    pub fn to_owned_member(&self) -> Result<OwnedTarMember, FormatError> {
        let data = if let Some(layout) = &self.v45_metadata.sparse_layout {
            let logical_len = usize::try_from(layout.logical_size).map_err(|_| {
                FormatError::ReaderUnsupported("sparse logical size exceeds platform limits")
            })?;
            let mut logical = vec![0u8; logical_len];
            let mut stored_cursor = layout.map_and_padding_size;
            for extent in &layout.extents {
                let extent_len = usize::try_from(extent.length).map_err(|_| {
                    FormatError::ReaderUnsupported("sparse extent exceeds platform limits")
                })?;
                let stored_end = stored_cursor
                    .checked_add(extent_len)
                    .ok_or(FormatError::InvalidArchive("sparse stored range overflow"))?;
                let logical_start = usize::try_from(extent.offset).map_err(|_| {
                    FormatError::ReaderUnsupported("sparse offset exceeds platform limits")
                })?;
                let logical_end = logical_start
                    .checked_add(extent_len)
                    .ok_or(FormatError::InvalidArchive("sparse logical range overflow"))?;
                logical
                    .get_mut(logical_start..logical_end)
                    .ok_or(FormatError::InvalidArchive(
                        "sparse logical range is invalid",
                    ))?
                    .copy_from_slice(self.data.get(stored_cursor..stored_end).ok_or(
                        FormatError::InvalidArchive("sparse stored range is invalid"),
                    )?);
                stored_cursor = stored_end;
            }
            logical
        } else {
            self.data.to_vec()
        };
        Ok(OwnedTarMember {
            path: self.path.clone(),
            kind: self.kind,
            data,
            link_target: self.link_target.clone(),
            mode: self.mode,
            mtime: self.mtime,
            logical_size: self.logical_size,
            reparse_placeholder: self.reparse_placeholder,
            v45_metadata: Some(self.v45_metadata.clone()),
            diagnostics: self.diagnostics.clone(),
        })
    }

    pub(crate) fn to_owned_metadata(&self) -> OwnedTarMember {
        OwnedTarMember {
            path: self.path.clone(),
            kind: self.kind,
            data: Vec::new(),
            link_target: self.link_target.clone(),
            mode: self.mode,
            mtime: self.mtime,
            logical_size: self.logical_size,
            reparse_placeholder: self.reparse_placeholder,
            v45_metadata: Some(self.v45_metadata.clone()),
            diagnostics: self.diagnostics.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SafeExtractionOptions {
    pub overwrite_existing: bool,
    pub restore_policy: RestorePolicy,
    /// Permit a requested same-OS/system operation to skip unsupported
    /// authenticated metadata with durable diagnostics.
    pub allow_degraded: bool,
    /// Explicit caller authorization for system-class restoration. The core
    /// implementation still applies only system items it understands.
    pub system_authorized: bool,
    /// Permit absolute symlinks to be extracted. If false, an error will be returned when an absolute symlink is encountered during extraction.
    pub allow_absolute_symlinks: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StreamedTarMemberMetadata {
    pub path: Vec<u8>,
    pub kind: TarEntryKind,
    pub link_target: Option<Vec<u8>>,
    pub mode: u32,
    pub mtime: ArchiveTimestamp,
    pub logical_size: u64,
    pub file_entry_flags: u32,
    pub reparse_placeholder: bool,
    pub v45_metadata: MemberMetadata,
    pub diagnostics: Vec<MetadataDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TarStreamMemberSummary {
    pub path: Vec<u8>,
    pub kind: TarEntryKind,
    pub link_target: Option<Vec<u8>>,
    pub mode: u32,
    pub mtime: ArchiveTimestamp,
    pub logical_size: u64,
    pub file_entry_flags: u32,
    pub reparse_placeholder: bool,
    pub v45_metadata: MemberMetadata,
    pub diagnostics: Vec<MetadataDiagnostic>,
    pub group_start: u64,
    pub group_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TarStreamSummary {
    pub members: Vec<TarStreamMemberSummary>,
    pub tar_total_size: u64,
    pub total_extraction_size: u64,
}

pub(crate) trait TarMemberGroupReader {
    fn read_some_member_bytes(&mut self, buf: &mut [u8]) -> Result<usize, ExtractError>;

    fn read_exact_member_bytes(&mut self, mut buf: &mut [u8]) -> Result<(), ExtractError> {
        while !buf.is_empty() {
            let read = self.read_some_member_bytes(buf)?;
            if read == 0 {
                return Err(
                    FormatError::InvalidArchive("tar member group exceeds frame range").into(),
                );
            }
            let (_, rest) = buf.split_at_mut(read);
            buf = rest;
        }
        Ok(())
    }
}

trait TarMemberStreamHandler {
    fn on_member(&mut self, member: &StreamedTarMemberMetadata) -> Result<(), ExtractError>;
    fn write_regular_payload(&mut self, bytes: &[u8]) -> Result<(), ExtractError>;
    fn begin_auxiliary_payload(&mut self, _record: &AuxiliaryRecord) -> Result<bool, ExtractError> {
        Ok(false)
    }
    fn write_auxiliary_payload(&mut self, _bytes: &[u8]) -> Result<(), ExtractError> {
        Ok(())
    }
    fn finish_auxiliary_payload(&mut self, _record: &AuxiliaryRecord) -> Result<(), ExtractError> {
        Ok(())
    }
    fn begin_sparse_payload(
        &mut self,
        _logical_size: u64,
        _extents: &[SparseExtent],
    ) -> Result<bool, ExtractError> {
        Ok(false)
    }
    fn write_sparse_extent(&mut self, _offset: u64, _bytes: &[u8]) -> Result<(), ExtractError> {
        Err(FormatError::InvalidArchive("sparse output was not initialized").into())
    }
    fn finish_sparse_payload(&mut self) -> Result<(), ExtractError> {
        Ok(())
    }
}

pub(crate) trait TarStreamObserver {
    fn on_member_start(&mut self, _member: &StreamedTarMemberMetadata) -> Result<(), FormatError> {
        Ok(())
    }

    fn on_regular_payload(&mut self, _bytes: &[u8]) -> Result<(), FormatError> {
        Ok(())
    }

    fn on_auxiliary_start(&mut self, _record: &AuxiliaryRecord) -> Result<bool, FormatError> {
        Ok(false)
    }

    fn on_auxiliary_payload(&mut self, _bytes: &[u8]) -> Result<(), FormatError> {
        Ok(())
    }

    fn on_auxiliary_complete(&mut self, _record: &AuxiliaryRecord) -> Result<(), FormatError> {
        Ok(())
    }

    fn on_sparse_layout(
        &mut self,
        _logical_size: u64,
        _extents: &[SparseExtent],
    ) -> Result<bool, FormatError> {
        Ok(false)
    }

    fn on_sparse_extent(&mut self, _offset: u64, _bytes: &[u8]) -> Result<(), FormatError> {
        Err(FormatError::InvalidArchive(
            "sparse observer output was not initialized",
        ))
    }

    fn on_sparse_complete(&mut self) -> Result<(), FormatError> {
        Ok(())
    }

    fn on_member_complete(
        &mut self,
        member: &StreamedTarMemberMetadata,
    ) -> Result<Vec<MetadataDiagnostic>, FormatError> {
        Ok(member.diagnostics.clone())
    }

    fn on_archive_complete(&mut self) -> Result<Vec<MetadataDiagnostic>, FormatError> {
        Ok(Vec::new())
    }
}

pub(crate) struct NoopTarStreamObserver;

impl TarStreamObserver for NoopTarStreamObserver {}

pub(crate) struct TarStreamFilesystemRestoreObserver<'a> {
    handler: FilesystemRestoreHandler<'a>,
}

impl<'a> TarStreamFilesystemRestoreObserver<'a> {
    pub(crate) fn new(root: &'a Path, options: SafeExtractionOptions) -> Self {
        Self {
            handler: FilesystemRestoreHandler::new_deferred(root, options),
        }
    }
}

impl TarStreamObserver for TarStreamFilesystemRestoreObserver<'_> {
    fn on_auxiliary_start(&mut self, record: &AuxiliaryRecord) -> Result<bool, FormatError> {
        self.handler
            .begin_auxiliary_payload(record)
            .map_err(format_error_from_extract_error)
    }

    fn on_auxiliary_payload(&mut self, bytes: &[u8]) -> Result<(), FormatError> {
        self.handler
            .write_auxiliary_payload(bytes)
            .map_err(format_error_from_extract_error)
    }

    fn on_auxiliary_complete(&mut self, record: &AuxiliaryRecord) -> Result<(), FormatError> {
        self.handler
            .finish_auxiliary_payload(record)
            .map_err(format_error_from_extract_error)
    }

    fn on_member_start(&mut self, member: &StreamedTarMemberMetadata) -> Result<(), FormatError> {
        self.handler
            .on_member(member)
            .map_err(format_error_from_extract_error)
    }

    fn on_regular_payload(&mut self, bytes: &[u8]) -> Result<(), FormatError> {
        self.handler
            .write_regular_payload(bytes)
            .map_err(format_error_from_extract_error)
    }

    fn on_sparse_layout(
        &mut self,
        logical_size: u64,
        extents: &[SparseExtent],
    ) -> Result<bool, FormatError> {
        self.handler
            .begin_sparse_payload(logical_size, extents)
            .map_err(format_error_from_extract_error)
    }

    fn on_sparse_extent(&mut self, offset: u64, bytes: &[u8]) -> Result<(), FormatError> {
        self.handler
            .write_sparse_extent(offset, bytes)
            .map_err(format_error_from_extract_error)
    }

    fn on_sparse_complete(&mut self) -> Result<(), FormatError> {
        self.handler
            .finish_sparse_payload()
            .map_err(format_error_from_extract_error)
    }

    fn on_member_complete(
        &mut self,
        member: &StreamedTarMemberMetadata,
    ) -> Result<Vec<MetadataDiagnostic>, FormatError> {
        self.handler
            .finish(member)
            .map_err(format_error_from_extract_error)
    }

    fn on_archive_complete(&mut self) -> Result<Vec<MetadataDiagnostic>, FormatError> {
        self.handler.finish_archive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum V45PaxKind {
    Primary,
    Auxiliary(u32),
}

#[derive(Default)]
struct V45StreamingGroup {
    pending: Option<(V45PaxKind, PaxRecords)>,
    auxiliary: Vec<AuxiliaryRecord>,
    aggregate_pax_bytes: usize,
}

struct StreamingSparsePrimary {
    validator: SparseStreamValidator,
    layout: Option<crate::entry_metadata::SparseLayout>,
    extent_index: usize,
    extent_consumed: u64,
    logical_cursor: u64,
    native_output: Option<bool>,
}

impl StreamingSparsePrimary {
    fn new(logical_size: u64) -> Self {
        Self {
            validator: SparseStreamValidator::new(logical_size),
            layout: None,
            extent_index: 0,
            extent_consumed: 0,
            logical_cursor: 0,
            native_output: None,
        }
    }

    fn observe<O: TarStreamObserver>(
        &mut self,
        bytes: &[u8],
        observer: &mut O,
    ) -> Result<(), FormatError> {
        let before = self.validator.position();
        self.validator.observe(bytes)?;
        if self.layout.is_none() {
            self.layout = self.validator.layout_if_map_complete();
        }
        let Some(layout) = &self.layout else {
            return Ok(());
        };
        let native_output = match self.native_output {
            Some(native_output) => native_output,
            None => {
                let native_output =
                    observer.on_sparse_layout(layout.logical_size, &layout.extents)?;
                self.native_output = Some(native_output);
                native_output
            }
        };
        let padded = layout.map_and_padding_size as u64;
        let data_offset = if before >= padded {
            0
        } else {
            usize::try_from((padded - before).min(bytes.len() as u64))
                .map_err(|_| FormatError::InvalidArchive("sparse offset exceeds usize"))?
        };
        let mut data = &bytes[data_offset..];
        while !data.is_empty() {
            let extent =
                layout
                    .extents
                    .get(self.extent_index)
                    .ok_or(FormatError::InvalidArchive(
                        "sparse primary has trailing extent bytes",
                    ))?;
            if self.extent_consumed == 0 && !native_output {
                observer_write_zeros(observer, extent.offset - self.logical_cursor)?;
            }
            let available = extent.length - self.extent_consumed;
            let take = usize::try_from(available.min(data.len() as u64))
                .map_err(|_| FormatError::InvalidArchive("sparse extent exceeds usize"))?;
            if native_output {
                observer.on_sparse_extent(extent.offset + self.extent_consumed, &data[..take])?;
            } else {
                observer.on_regular_payload(&data[..take])?;
            }
            self.extent_consumed += take as u64;
            data = &data[take..];
            if self.extent_consumed == extent.length {
                self.logical_cursor = extent.offset + extent.length;
                self.extent_index += 1;
                self.extent_consumed = 0;
            }
        }
        Ok(())
    }

    fn finish<O: TarStreamObserver>(self, observer: &mut O) -> Result<(), FormatError> {
        let layout = self.validator.finish()?;
        if self.extent_index != layout.extents.len() || self.extent_consumed != 0 {
            return Err(FormatError::InvalidArchive(
                "sparse primary extent data is incomplete",
            ));
        }
        let native_output = match self.native_output {
            Some(native_output) => native_output,
            None => observer.on_sparse_layout(layout.logical_size, &layout.extents)?,
        };
        if native_output {
            observer.on_sparse_complete()
        } else {
            observer_write_zeros(observer, layout.logical_size - self.logical_cursor)
        }
    }
}

fn observer_write_zeros<O: TarStreamObserver>(
    observer: &mut O,
    mut len: u64,
) -> Result<(), FormatError> {
    let zeros = [0u8; 64 * 1024];
    while len > 0 {
        let take = len.min(zeros.len() as u64) as usize;
        observer.on_regular_payload(&zeros[..take])?;
        len -= take as u64;
    }
    Ok(())
}

pub fn parse_tar_member_group<'a>(
    group: &'a [u8],
    max_path_length: u32,
) -> Result<ParsedTarMember<'a>, FormatError> {
    if group.len() < TAR_BLOCK_LEN * 3 || group.len() % TAR_BLOCK_LEN != 0 {
        return Err(FormatError::InvalidArchive(
            "tar member group is not block aligned",
        ));
    }

    let mut cursor = 0usize;
    let mut pending: Option<(V45PaxKind, PaxRecords)> = None;
    let mut auxiliary = Vec::<AuxiliaryRecord>::new();
    let mut aggregate_pax_bytes = 0usize;

    loop {
        let header = slice(group, cursor, TAR_BLOCK_LEN)?;
        if header.iter().all(|byte| *byte == 0) {
            return Err(FormatError::InvalidArchive("tar member header is empty"));
        }
        verify_tar_checksum(header)?;
        let typeflag = header[156];
        let header_size = parse_tar_octal(&header[124..136])?;
        let effective_size = pending
            .as_ref()
            .and_then(|(_, records)| records.get("size"))
            .map(|value| parse_minimal_decimal_u64(value, "PAX size"))
            .transpose()?
            .unwrap_or(header_size);
        let payload_start = checked_add(cursor, TAR_BLOCK_LEN)?;
        let payload_len = to_usize(effective_size)?;
        let payload_end = checked_add(payload_start, payload_len)?;
        let padded_end = checked_add(payload_end, padding_to_512(payload_len))?;
        let payload = slice(group, payload_start, payload_len)?;
        if padded_end > group.len() {
            return Err(FormatError::InvalidArchive(
                "tar member payload exceeds group",
            ));
        }
        if group[payload_end..padded_end].iter().any(|byte| *byte != 0) {
            return Err(FormatError::InvalidArchive(
                "tar member padding is non-zero",
            ));
        }

        match typeflag {
            b'x' => {
                if pending.is_some() {
                    return Err(FormatError::InvalidArchive(
                        "PAX header is not immediately consumed",
                    ));
                }
                validate_v45_metadata_header(header)?;
                aggregate_pax_bytes = aggregate_pax_bytes
                    .checked_add(payload.len())
                    .ok_or(FormatError::InvalidArchive("aggregate PAX size overflow"))?;
                if aggregate_pax_bytes > MAX_AGGREGATE_PAX_PAYLOAD {
                    return Err(FormatError::ReaderResourceLimitExceeded {
                        field: "aggregate local PAX payload bytes per member group",
                        cap: MAX_AGGREGATE_PAX_PAYLOAD as u64,
                        actual: aggregate_pax_bytes as u64,
                    });
                }
                let records = parse_canonical_pax(payload)?;
                let label = ustar_path(header);
                let kind = if label == b"TZAP-PAX/PRIMARY" {
                    V45PaxKind::Primary
                } else if let Some(ordinal) = parse_auxiliary_pax_label(&label) {
                    if ordinal != auxiliary.len() as u32 {
                        return Err(FormatError::InvalidArchive(
                            "auxiliary PAX ordinal is not contiguous",
                        ));
                    }
                    V45PaxKind::Auxiliary(ordinal)
                } else {
                    return Err(FormatError::InvalidArchive(
                        "revision-45 PAX header has a non-canonical internal name",
                    ));
                };
                pending = Some((kind, records));
                cursor = padded_end;
            }
            b'Z' => {
                let Some((V45PaxKind::Auxiliary(ordinal), records)) = pending.take() else {
                    return Err(FormatError::InvalidArchive(
                        "auxiliary entry is missing its local PAX header",
                    ));
                };
                validate_v45_auxiliary_header(header, ordinal, header_size, effective_size)?;
                auxiliary.push(parse_auxiliary_record(
                    &records,
                    ordinal,
                    effective_size,
                    payload,
                )?);
                cursor = padded_end;
            }
            b'g' | b'L' | b'K' | b'V' | b'M' | b'N' | b'S' => {
                return Err(FormatError::InvalidArchive(
                    "global or GNU tar metadata is forbidden in revision 45",
                ));
            }
            0 | b'0' | b'5' | b'2' | b'1' | b'3' | b'4' | b'6' => {
                let Some((V45PaxKind::Primary, records)) = pending.take() else {
                    return Err(FormatError::InvalidArchive(
                        "primary entry is missing its canonical local PAX header",
                    ));
                };
                if padded_end != group.len() {
                    return Err(FormatError::InvalidArchive(
                        "tar member group has bytes after main entry",
                    ));
                }
                let kind = match typeflag {
                    b'5' => TarEntryKind::Directory,
                    b'2' => TarEntryKind::Symlink,
                    b'1' => TarEntryKind::Hardlink,
                    b'3' => TarEntryKind::CharacterDevice,
                    b'4' => TarEntryKind::BlockDevice,
                    b'6' => TarEntryKind::Fifo,
                    _ => TarEntryKind::Regular,
                };
                let primary = parse_primary_metadata(&records)?;
                validate_v45_primary_header(
                    header,
                    kind,
                    header_size,
                    effective_size,
                    &primary,
                    &records,
                )?;
                let path = v45_primary_path(header, kind, &records, &primary, max_path_length)?;
                let link_target =
                    v45_primary_link_target(header, kind, &path, &primary, max_path_length)?;
                let is_sparse = primary.sparse_logical_size.is_some();
                let reparse_placeholder = records.contains_key("TZAP.windows.reparse-placeholder");
                if kind != TarEntryKind::Regular && effective_size != 0 {
                    return Err(FormatError::InvalidArchive(
                        "non-regular tar entry has non-zero payload size",
                    ));
                }
                if reparse_placeholder && effective_size != 0 {
                    return Err(FormatError::InvalidArchive(
                        "reparse placeholder has non-zero primary payload",
                    ));
                }
                let sparse_layout = if let Some(logical_size) = primary.sparse_logical_size {
                    if kind != TarEntryKind::Regular || reparse_placeholder {
                        return Err(FormatError::InvalidArchive(
                            "sparse metadata is not valid for this primary type",
                        ));
                    }
                    Some(parse_sparse_payload(payload, logical_size)?)
                } else {
                    None
                };
                let logical_size = if kind == TarEntryKind::Regular && !reparse_placeholder {
                    primary.sparse_logical_size.unwrap_or(effective_size)
                } else {
                    0
                };
                let (file_entry_flags, capture_report) =
                    v45_group_flags(&primary, &auxiliary, kind)?;
                validate_v45_primary_cross_fields(
                    kind,
                    &records,
                    &primary,
                    &auxiliary,
                    V45PrimaryLink {
                        path: &path,
                        target: link_target.as_deref(),
                    },
                    is_sparse,
                    capture_report.as_deref(),
                )?;
                let diagnostics = Vec::new();
                let mtime = decoded_mtime(&primary, header)?;
                let v45_metadata = MemberMetadata {
                    declaration: primary.declaration.clone(),
                    primary_records: records.clone(),
                    auxiliary,
                    file_entry_flags,
                    sparse_layout,
                    capture_report,
                    primary_has_native_scalar: primary.has_native_scalar,
                    primary_requires_system_restore: primary.requires_system_restore,
                    portable_mirror: portable_metadata_mirror(header, &records, &primary)?,
                };
                return Ok(ParsedTarMember {
                    path,
                    kind,
                    data: if kind == TarEntryKind::Regular {
                        payload
                    } else {
                        &[]
                    },
                    mode: primary.declaration.portable_mode,
                    mtime,
                    link_target,
                    logical_size,
                    reparse_placeholder,
                    diagnostics,
                    v45_metadata,
                });
            }
            _ => {
                return Err(FormatError::InvalidArchive(
                    "unsupported revision-45 tar entry type",
                ));
            }
        }

        if cursor >= group.len() {
            return Err(FormatError::InvalidArchive(
                "tar member group has metadata records but no main entry",
            ));
        }
    }
}

fn validate_v45_metadata_header(header: &[u8]) -> Result<(), FormatError> {
    validate_ustar_header(header)?;
    if parse_tar_octal(&header[100..108])? != 0
        || parse_tar_octal(&header[108..116])? != 0
        || parse_tar_octal(&header[116..124])? != 0
        || parse_tar_octal(&header[136..148])? != 0
        || !nul_trimmed(&header[157..257]).is_empty()
        || !nul_trimmed(&header[265..297]).is_empty()
        || !nul_trimmed(&header[297..329]).is_empty()
        || parse_tar_octal(&header[329..337])? != 0
        || parse_tar_octal(&header[337..345])? != 0
        || !nul_trimmed(&header[345..500]).is_empty()
    {
        return Err(FormatError::InvalidArchive(
            "revision-45 local PAX header has non-zero metadata fields",
        ));
    }
    Ok(())
}

fn validate_ustar_header(header: &[u8]) -> Result<(), FormatError> {
    if &header[257..263] != b"ustar\0" || &header[263..265] != b"00" {
        return Err(FormatError::InvalidArchive(
            "tar header is not canonical ustar",
        ));
    }
    for field in [
        &header[0..100],
        &header[157..257],
        &header[265..297],
        &header[297..329],
        &header[345..500],
    ] {
        validate_nul_terminated_field(field)?;
    }
    if header[500..512].iter().any(|byte| *byte != 0) {
        return Err(FormatError::InvalidArchive(
            "tar header has non-zero reserved bytes",
        ));
    }
    Ok(())
}

fn validate_nul_terminated_field(field: &[u8]) -> Result<(), FormatError> {
    if let Some(nul) = field.iter().position(|byte| *byte == 0) {
        if field[nul..].iter().any(|byte| *byte != 0) {
            return Err(FormatError::InvalidArchive(
                "ustar string field has bytes after NUL",
            ));
        }
    }
    Ok(())
}

fn parse_auxiliary_pax_label(label: &[u8]) -> Option<u32> {
    let suffix = label.strip_prefix(b"TZAP-PAX/AUX/")?;
    if suffix.len() != 8
        || !suffix
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return None;
    }
    u32::from_str_radix(std::str::from_utf8(suffix).ok()?, 16).ok()
}

fn validate_v45_auxiliary_header(
    header: &[u8],
    ordinal: u32,
    header_size: u64,
    effective_size: u64,
) -> Result<(), FormatError> {
    validate_ustar_header(header)?;
    let expected = format!("TZAP-AUX/{ordinal:08x}");
    if ustar_path(header) != expected.as_bytes()
        || parse_tar_octal(&header[100..108])? != 0
        || parse_tar_octal(&header[108..116])? != 0
        || parse_tar_octal(&header[116..124])? != 0
        || parse_tar_octal(&header[136..148])? != 0
        || !nul_trimmed(&header[157..257]).is_empty()
        || !nul_trimmed(&header[265..297]).is_empty()
        || !nul_trimmed(&header[297..329]).is_empty()
        || parse_tar_octal(&header[329..337])? != 0
        || parse_tar_octal(&header[337..345])? != 0
        || !nul_trimmed(&header[345..500]).is_empty()
        || (header_size != effective_size && header_size != 0)
    {
        return Err(FormatError::InvalidArchive(
            "revision-45 auxiliary tar header is not canonical",
        ));
    }
    Ok(())
}

fn validate_v45_primary_header(
    header: &[u8],
    kind: TarEntryKind,
    header_size: u64,
    effective_size: u64,
    primary: &PrimaryMetadata,
    records: &PaxRecords,
) -> Result<(), FormatError> {
    validate_ustar_header(header)?;
    if parse_tar_octal(&header[100..108])? != primary.declaration.portable_mode as u64 {
        return Err(FormatError::InvalidArchive(
            "ustar mode does not match TZAP.portable.mode",
        ));
    }
    if primary.stored_size.is_some() {
        if header_size != 0 && header_size != effective_size {
            return Err(FormatError::InvalidArchive(
                "ustar size conflicts with PAX size",
            ));
        }
    } else if header_size != effective_size {
        return Err(FormatError::InvalidArchive("ustar size is inconsistent"));
    }
    if !primary.declaration.owner_kind_posix
        && (parse_tar_octal(&header[108..116])? != 0
            || parse_tar_octal(&header[116..124])? != 0
            || !nul_trimmed(&header[265..297]).is_empty()
            || !nul_trimmed(&header[297..329]).is_empty())
    {
        return Err(FormatError::InvalidArchive(
            "owner-kind none has non-zero ustar ownership fields",
        ));
    }
    if primary.declaration.owner_kind_posix {
        validate_numeric_pax_header_match(records, "uid", &header[108..116], "UID")?;
        validate_numeric_pax_header_match(records, "gid", &header[116..124], "GID")?;
        validate_string_pax_header_match(records, "uname", &header[265..297], "user name")?;
        validate_string_pax_header_match(records, "gname", &header[297..329], "group name")?;
    }
    if let Some((seconds, _)) = primary.mtime {
        let header_mtime = parse_tar_octal(&header[136..148])?;
        if header_mtime != 0 && (seconds < 0 || u64::try_from(seconds).ok() != Some(header_mtime)) {
            return Err(FormatError::InvalidArchive(
                "ustar mtime conflicts with PAX mtime",
            ));
        }
    }
    let is_device = matches!(
        kind,
        TarEntryKind::CharacterDevice | TarEntryKind::BlockDevice
    );
    if !is_device
        && (parse_tar_octal(&header[329..337])? != 0 || parse_tar_octal(&header[337..345])? != 0)
    {
        return Err(FormatError::InvalidArchive(
            "non-device primary has device numbers",
        ));
    }
    if is_device {
        validate_numeric_pax_header_match(
            records,
            "TZAP.posix.device-major",
            &header[329..337],
            "device major",
        )?;
        validate_numeric_pax_header_match(
            records,
            "TZAP.posix.device-minor",
            &header[337..345],
            "device minor",
        )?;
    }
    Ok(())
}

fn decoded_mtime(
    primary: &PrimaryMetadata,
    header: &[u8],
) -> Result<ArchiveTimestamp, FormatError> {
    let (seconds, nanoseconds) = match primary.mtime {
        Some(value) => value,
        None => (
            i64::try_from(parse_tar_octal(&header[136..148])?)
                .map_err(|_| FormatError::InvalidArchive("ustar mtime exceeds i64"))?,
            0,
        ),
    };
    Ok(ArchiveTimestamp::new(seconds, nanoseconds))
}

fn portable_metadata_mirror(
    header: &[u8],
    records: &PaxRecords,
    primary: &PrimaryMetadata,
) -> Result<PortableMetadataMirror, FormatError> {
    let numeric = |key: &'static str, field: &[u8]| -> Result<Option<u64>, FormatError> {
        if !primary.declaration.owner_kind_posix {
            return Ok(None);
        }
        if let Some(value) = records.get(key) {
            Ok(Some(parse_minimal_decimal_u64(value, key)?))
        } else {
            Ok(Some(parse_tar_octal(field)?))
        }
    };
    let string = |key: &str, field: &[u8]| -> Option<Vec<u8>> {
        if !primary.declaration.owner_kind_posix {
            return None;
        }
        let value = records
            .get(key)
            .map(Vec::as_slice)
            .unwrap_or_else(|| nul_trimmed(field));
        (!value.is_empty()).then(|| value.to_vec())
    };
    let mtime = if let Some(value) = primary.mtime {
        value
    } else {
        (
            i64::try_from(parse_tar_octal(&header[136..148])?)
                .map_err(|_| FormatError::InvalidArchive("ustar mtime exceeds i64"))?,
            0,
        )
    };
    Ok(PortableMetadataMirror {
        owner_kind_posix: primary.declaration.owner_kind_posix,
        mode_origin_native: primary.declaration.mode_origin_native,
        mode: primary.declaration.portable_mode,
        attributes: primary.declaration.portable_attributes,
        uid: numeric("uid", &header[108..116])?,
        gid: numeric("gid", &header[116..124])?,
        uname: string("uname", &header[265..297]),
        gname: string("gname", &header[297..329]),
        mtime,
    })
}

fn validate_numeric_pax_header_match(
    records: &PaxRecords,
    key: &'static str,
    header_field: &[u8],
    label: &'static str,
) -> Result<(), FormatError> {
    let Some(value) = records.get(key) else {
        return Ok(());
    };
    let pax = parse_minimal_decimal_u64(value, key)?;
    let header = parse_tar_octal(header_field)?;
    if header != 0 && header != pax {
        return Err(FormatError::InvalidMetadata {
            structure: label,
            reason: "ustar field conflicts with PAX value",
        });
    }
    Ok(())
}

fn validate_string_pax_header_match(
    records: &PaxRecords,
    key: &'static str,
    header_field: &[u8],
    label: &'static str,
) -> Result<(), FormatError> {
    if let Some(value) = records.get(key) {
        let header = nul_trimmed(header_field);
        if !header.is_empty() && header != value {
            return Err(FormatError::InvalidMetadata {
                structure: label,
                reason: "ustar field conflicts with PAX value",
            });
        }
    }
    Ok(())
}

fn v45_primary_path(
    header: &[u8],
    kind: TarEntryKind,
    records: &PaxRecords,
    primary: &PrimaryMetadata,
    max_path_length: u32,
) -> Result<Vec<u8>, FormatError> {
    let sparse_name = records.get("GNU.sparse.name");
    let mut path = if let Some(name) = sparse_name {
        if primary.path.is_some() || ustar_path(header) != b"GNUSparseFile.0/TZAP" {
            return Err(FormatError::InvalidArchive(
                "GNU sparse primary path framing is not canonical",
            ));
        }
        name.clone()
    } else if let Some(path) = &primary.path {
        if ustar_path(header) != b"TZAP-PRIMARY" {
            return Err(FormatError::InvalidArchive(
                "PAX path override lacks canonical ustar placeholder",
            ));
        }
        path.clone()
    } else {
        ustar_path(header)
    };
    if kind == TarEntryKind::Directory && path.ends_with(b"/") {
        path.pop();
    }
    validate_file_path_bytes(&path, max_path_length)?;
    Ok(path)
}

fn v45_primary_link_target(
    header: &[u8],
    kind: TarEntryKind,
    path: &[u8],
    primary: &PrimaryMetadata,
    max_path_length: u32,
) -> Result<Option<Vec<u8>>, FormatError> {
    let header_target = nul_trimmed(&header[157..257]);
    match kind {
        TarEntryKind::Symlink | TarEntryKind::Hardlink => {
            let target = if let Some(target) = &primary.linkpath {
                if !header_target.is_empty() {
                    return Err(FormatError::InvalidArchive(
                        "PAX linkpath override has non-empty ustar linkname",
                    ));
                }
                target.clone()
            } else {
                header_target.to_vec()
            };
            if target.is_empty() || target.contains(&0) {
                return Err(FormatError::InvalidArchive("tar link target is empty"));
            }
            if kind == TarEntryKind::Hardlink {
                validate_file_path_bytes(&target, max_path_length)?;
            } else {
                validate_symlink_target(path, &target)?;
            }
            Ok(Some(target))
        }
        _ => {
            if primary.linkpath.is_some() || !header_target.is_empty() {
                return Err(FormatError::InvalidArchive(
                    "non-link primary has a link target",
                ));
            }
            Ok(None)
        }
    }
}

#[derive(Clone, Copy)]
struct V45PrimaryLink<'a> {
    path: &'a [u8],
    target: Option<&'a [u8]>,
}

fn validate_v45_primary_cross_fields(
    kind: TarEntryKind,
    records: &PaxRecords,
    primary: &PrimaryMetadata,
    auxiliary: &[AuxiliaryRecord],
    link: V45PrimaryLink<'_>,
    sparse: bool,
    capture_report: Option<&[CaptureReportRow]>,
) -> Result<(), FormatError> {
    let is_device = matches!(
        kind,
        TarEntryKind::CharacterDevice | TarEntryKind::BlockDevice
    );
    let has_device_major = records.contains_key("TZAP.posix.device-major");
    let has_device_minor = records.contains_key("TZAP.posix.device-minor");
    if is_device != (has_device_major && has_device_minor) {
        return Err(FormatError::InvalidArchive(
            "device primary and device-number metadata disagree",
        ));
    }
    if (kind == TarEntryKind::Fifo || is_device)
        && !primary.declaration.profile_selected("posix-backup-v1")
    {
        return Err(FormatError::InvalidArchive(
            "special POSIX primary lacks posix-backup-v1",
        ));
    }
    if records.contains_key("TZAP.linux.whiteout") {
        let major = records
            .get("TZAP.posix.device-major")
            .map(|value| parse_minimal_decimal_u64(value, "device major"))
            .transpose()?;
        let minor = records
            .get("TZAP.posix.device-minor")
            .map(|value| parse_minimal_decimal_u64(value, "device minor"))
            .transpose()?;
        if kind != TarEntryKind::CharacterDevice || major != Some(0) || minor != Some(0) {
            return Err(FormatError::InvalidArchive(
                "Linux whiteout is not a character device with major/minor zero",
            ));
        }
    }
    if sparse && kind != TarEntryKind::Regular {
        return Err(FormatError::InvalidArchive(
            "non-regular primary carries sparse metadata",
        ));
    }
    if kind == TarEntryKind::Hardlink {
        if primary.declaration.required_profiles != ["portable-v1"]
            || !primary.declaration.optional_profiles.is_empty()
            || sparse
            || auxiliary
                .iter()
                .any(|record| record.kind != CAPTURE_REPORT_KIND)
        {
            return Err(FormatError::InvalidArchive(
                "hardlink alias carries forbidden native or inode metadata",
            ));
        }
        if link.target == Some(link.path) {
            return Err(FormatError::InvalidArchive("hardlink aliases itself"));
        }
    }
    if records.contains_key("TZAP.windows.directory-case-sensitive")
        && kind != TarEntryKind::Directory
    {
        return Err(FormatError::InvalidArchive(
            "Windows directory case-sensitive state is attached to a non-directory",
        ));
    }
    if records.contains_key("SCHILY.acl.default") && kind != TarEntryKind::Directory {
        return Err(FormatError::InvalidArchive(
            "default POSIX ACL is attached to a non-directory",
        ));
    }
    if records.contains_key("TZAP.macos.clone-group") && kind != TarEntryKind::Regular {
        return Err(FormatError::InvalidArchive(
            "macOS clone group is attached to a non-regular primary",
        ));
    }
    validate_windows_cross_fields(kind, records, primary, auxiliary, sparse, capture_report)?;
    let has_textual_acl = records.contains_key("SCHILY.acl.access")
        || records.contains_key("SCHILY.acl.default")
        || records.contains_key("SCHILY.acl.ace");
    let has_native_macos_acl = auxiliary
        .iter()
        .any(|record| record.kind == "macos.acl-native");
    let acl_projection_none = records
        .get("TZAP.acl.projection")
        .is_some_and(|value| value == b"none");
    if (!has_textual_acl && has_native_macos_acl) != acl_projection_none {
        return Err(FormatError::InvalidArchive(
            "native-only ACL declaration and projection=none disagree",
        ));
    }
    if auxiliary.iter().any(|record| {
        record.kind == "generic.xattr"
            && primary
                .xattr_names
                .iter()
                .any(|name| name == &record.decoded_name)
    }) {
        return Err(FormatError::InvalidArchive(
            "xattr is duplicated in primary and auxiliary metadata",
        ));
    }
    if has_textual_acl
        && (primary.xattr_names.iter().any(|name| {
            matches!(
                name.as_slice(),
                b"system.posix_acl_access"
                    | b"system.posix_acl_default"
                    | b"com.apple.system.Security"
            )
        }) || auxiliary.iter().any(|record| {
            record.kind == "generic.xattr"
                && matches!(
                    record.decoded_name.as_slice(),
                    b"system.posix_acl_access"
                        | b"system.posix_acl_default"
                        | b"com.apple.system.Security"
                )
        }))
    {
        return Err(FormatError::InvalidArchive(
            "filesystem ACL backing xattr duplicates declared ACL metadata",
        ));
    }
    Ok(())
}

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
const FILE_ATTRIBUTE_SYSTEM: u32 = 0x0000_0004;
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x0000_0100;
const FILE_ATTRIBUTE_SPARSE_FILE: u32 = 0x0000_0200;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const FILE_ATTRIBUTE_COMPRESSED: u32 = 0x0000_0800;
const FILE_ATTRIBUTE_NOT_CONTENT_INDEXED: u32 = 0x0000_2000;
const FILE_ATTRIBUTE_ENCRYPTED: u32 = 0x0000_4000;
const WINDOWS_ESSENTIAL_SETTABLE_ATTRIBUTES: u32 = FILE_ATTRIBUTE_READONLY
    | FILE_ATTRIBUTE_HIDDEN
    | FILE_ATTRIBUTE_SYSTEM
    | FILE_ATTRIBUTE_ARCHIVE
    | FILE_ATTRIBUTE_TEMPORARY
    | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
const WINDOWS_ESSENTIAL_INTRINSIC_ATTRIBUTES: u32 = FILE_ATTRIBUTE_DIRECTORY
    | FILE_ATTRIBUTE_SPARSE_FILE
    | FILE_ATTRIBUTE_REPARSE_POINT
    | FILE_ATTRIBUTE_COMPRESSED
    | FILE_ATTRIBUTE_ENCRYPTED;
const STREAM_MODIFIED_WHEN_READ: u32 = 0x0000_0001;
const STREAM_CONTAINS_SECURITY: u32 = 0x0000_0002;
const STREAM_SPARSE_ATTRIBUTE: u32 = 0x0000_0008;

fn validate_windows_essential_reparse_data(data: &[u8]) -> Result<u32, FormatError> {
    const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
    const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
    if data.len() < 8 {
        return Err(FormatError::InvalidArchive("reparse buffer is truncated"));
    }
    let tag = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let payload_len = usize::from(u16::from_le_bytes(data[4..6].try_into().unwrap()));
    let header_len = if tag & 0x8000_0000 == 0 { 24 } else { 8 };
    if payload_len + header_len != data.len() {
        return Err(FormatError::InvalidArchive(
            "reparse buffer length is inconsistent",
        ));
    }
    let fixed_len = match tag {
        IO_REPARSE_TAG_SYMLINK if payload_len >= 12 => {
            if u32::from_le_bytes(data[16..20].try_into().unwrap()) != 1 {
                return Err(FormatError::InvalidArchive(
                    "only relative Windows symbolic links are supported",
                ));
            }
            12
        }
        IO_REPARSE_TAG_MOUNT_POINT if payload_len >= 8 => 8,
        IO_REPARSE_TAG_SYMLINK | IO_REPARSE_TAG_MOUNT_POINT => {
            return Err(FormatError::InvalidArchive("reparse payload is truncated"));
        }
        // Opaque registered or user-defined tags have tag-specific payloads that cannot be
        // decoded here. The common header and exact length were validated above; preserve the
        // bytes without interpreting or following the reparse point.
        _ => return Ok(tag),
    };
    let substitute_offset = usize::from(u16::from_le_bytes(data[8..10].try_into().unwrap()));
    let substitute_len = usize::from(u16::from_le_bytes(data[10..12].try_into().unwrap()));
    let print_offset = usize::from(u16::from_le_bytes(data[12..14].try_into().unwrap()));
    let print_len = usize::from(u16::from_le_bytes(data[14..16].try_into().unwrap()));
    if [substitute_offset, substitute_len, print_offset, print_len]
        .iter()
        .any(|value| value % 2 != 0)
    {
        return Err(FormatError::InvalidArchive(
            "reparse path fields are not UTF-16 aligned",
        ));
    }
    let path_buffer = &data[8 + fixed_len..];
    let decode = |offset: usize, len: usize| -> Result<String, FormatError> {
        let end = offset
            .checked_add(len)
            .ok_or(FormatError::InvalidArchive("reparse path range overflows"))?;
        let bytes = path_buffer
            .get(offset..end)
            .ok_or(FormatError::InvalidArchive(
                "reparse path range exceeds payload",
            ))?;
        let units = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        let text = String::from_utf16(&units)
            .map_err(|_| FormatError::InvalidArchive("reparse path is not valid UTF-16"))?;
        if text.contains('\0') {
            return Err(FormatError::InvalidArchive("reparse path contains NUL"));
        }
        Ok(text)
    };
    let substitute = decode(substitute_offset, substitute_len)?;
    let print = decode(print_offset, print_len)?;
    if substitute.is_empty() {
        return Err(FormatError::InvalidArchive(
            "reparse substitute name is empty",
        ));
    }
    if tag == IO_REPARSE_TAG_SYMLINK {
        let target = if print.is_empty() {
            &substitute
        } else {
            &print
        };
        let target = target.replace('\\', "/");
        if target.is_empty() || target.starts_with('/') || target.contains(':') {
            return Err(FormatError::UnsafeArchivePath);
        }
    } else if !substitute.starts_with("\\??\\") || print.is_empty() {
        return Err(FormatError::InvalidArchive(
            "junction path fields are not canonical",
        ));
    }
    Ok(tag)
}

fn validate_windows_cross_fields(
    kind: TarEntryKind,
    records: &PaxRecords,
    primary: &PrimaryMetadata,
    auxiliary: &[AuxiliaryRecord],
    sparse: bool,
    capture_report: Option<&[CaptureReportRow]>,
) -> Result<(), FormatError> {
    let selected = primary.declaration.profile_selected("windows-backup-v1");
    let file_attributes = records
        .get("TZAP.windows.file-attributes")
        .map(|value| parse_lower_hex_u32(value, "Windows file attributes"))
        .transpose()?;
    let stream_attributes = records
        .get("TZAP.windows.data-stream-attributes")
        .map(|value| parse_lower_hex_u32(value, "Windows data-stream attributes"))
        .transpose()?;
    let placeholder = records.contains_key("TZAP.windows.reparse-placeholder");
    let reparse_count = auxiliary
        .iter()
        .filter(|record| record.kind == "windows.reparse-data")
        .count();
    let security_descriptor_count = auxiliary
        .iter()
        .filter(|record| record.kind == "windows.security-descriptor")
        .count();
    let efs_count = auxiliary
        .iter()
        .filter(|record| record.kind == "windows.efs-raw")
        .count();

    if !selected {
        if file_attributes.is_some()
            || stream_attributes.is_some()
            || placeholder
            || reparse_count != 0
            || security_descriptor_count != 0
            || efs_count != 0
        {
            return Err(FormatError::InvalidArchive(
                "Windows metadata is present without windows-backup-v1",
            ));
        }
        return Ok(());
    }

    let complete = primary.declaration.capture_status == CaptureStatus::Complete;
    if file_attributes.is_none()
        && (complete
            || !has_capture_omission(capture_report, "windows-backup-v1", "file-attributes"))
    {
        return Err(FormatError::InvalidArchive(
            "windows-backup-v1 lacks exact file attributes or a matching omission",
        ));
    }
    if security_descriptor_count == 0
        && (complete
            || !has_capture_omission(capture_report, "windows-backup-v1", "security-descriptor"))
    {
        return Err(FormatError::InvalidArchive(
            "windows-backup-v1 lacks a security descriptor or a matching omission",
        ));
    }
    if let Some(attributes) = file_attributes {
        let is_directory = kind == TarEntryKind::Directory;
        if kind != TarEntryKind::Symlink
            && (attributes & FILE_ATTRIBUTE_DIRECTORY != 0) != is_directory
        {
            return Err(FormatError::InvalidArchive(
                "Windows directory attribute disagrees with primary type",
            ));
        }
        let is_reparse = attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
        if reparse_count != 0 && !is_reparse {
            return Err(FormatError::InvalidArchive(
                "Windows reparse data lacks FILE_ATTRIBUTE_REPARSE_POINT",
            ));
        }
        if is_reparse
            && reparse_count == 0
            && (complete
                || !has_capture_omission(capture_report, "windows-backup-v1", "reparse-data")
                || (kind != TarEntryKind::Symlink && !placeholder))
        {
            return Err(FormatError::InvalidArchive(
                "Windows reparse attribute lacks exact data or a safe partial placeholder",
            ));
        }
        if placeholder
            && (!is_reparse || !matches!(kind, TarEntryKind::Regular | TarEntryKind::Directory))
        {
            return Err(FormatError::InvalidArchive(
                "Windows reparse placeholder has invalid attributes or primary type",
            ));
        }
        if attributes & FILE_ATTRIBUTE_ENCRYPTED != 0
            && efs_count == 0
            && (complete || !has_capture_omission(capture_report, "windows-backup-v1", "efs-raw"))
        {
            return Err(FormatError::InvalidArchive(
                "encrypted Windows entry lacks raw EFS data or a matching omission",
            ));
        }
    } else if placeholder || reparse_count != 0 || efs_count != 0 {
        return Err(FormatError::InvalidArchive(
            "Windows native records cannot be checked without file attributes",
        ));
    }

    let ordinary_regular = kind == TarEntryKind::Regular && !placeholder;
    if !ordinary_regular && stream_attributes.is_some() {
        return Err(FormatError::InvalidArchive(
            "Windows default-data-stream attributes disagree with primary type",
        ));
    }
    if ordinary_regular
        && stream_attributes.is_none()
        && (complete
            || !has_capture_omission(
                capture_report,
                "windows-backup-v1",
                "data-stream-attributes",
            ))
    {
        return Err(FormatError::InvalidArchive(
            "Windows regular primary lacks default-data-stream attributes or an omission",
        ));
    }
    if let Some(attributes) = stream_attributes {
        if (attributes & STREAM_SPARSE_ATTRIBUTE != 0) != sparse {
            let fallback = !sparse
                && primary.declaration.capture_status == CaptureStatus::Partial
                && has_capture_omission(capture_report, "windows-backup-v1", "sparse-layout");
            if !fallback {
                return Err(FormatError::InvalidArchive(
                    "Windows primary sparse attribute disagrees with sparse framing",
                ));
            }
        }
        let _requires_system = attributes & STREAM_CONTAINS_SECURITY != 0;
    } else if sparse
        && !has_capture_omission(
            capture_report,
            "windows-backup-v1",
            "data-stream-attributes",
        )
    {
        return Err(FormatError::InvalidArchive(
            "sparse Windows primary lacks default-stream attributes",
        ));
    }
    Ok(())
}

fn has_capture_omission(
    report: Option<&[CaptureReportRow]>,
    profile: &str,
    metadata_class: &str,
) -> bool {
    report.is_some_and(|rows| {
        rows.iter()
            .any(|row| row.profile == profile && row.metadata_class == metadata_class)
    })
}

fn parse_lower_hex_u32(value: &[u8], structure: &'static str) -> Result<u32, FormatError> {
    if value.len() != 8
        || !value
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(FormatError::InvalidMetadata {
            structure,
            reason: "value is not eight lowercase hexadecimal digits",
        });
    }
    std::str::from_utf8(value)
        .ok()
        .and_then(|text| u32::from_str_radix(text, 16).ok())
        .ok_or(FormatError::InvalidMetadata {
            structure,
            reason: "hexadecimal value exceeds u32",
        })
}

fn v45_group_flags(
    primary: &PrimaryMetadata,
    auxiliary: &[AuxiliaryRecord],
    kind: TarEntryKind,
) -> Result<(u32, Option<Vec<crate::entry_metadata::CaptureReportRow>>), FormatError> {
    let (mut flags, capture_report) = validate_group_metadata(primary, auxiliary)?;
    if matches!(
        kind,
        TarEntryKind::CharacterDevice | TarEntryKind::BlockDevice | TarEntryKind::Fifo
    ) {
        flags |= REQUIRES_SYSTEM_RESTORE;
    }
    Ok((flags, capture_report))
}

fn parse_minimal_decimal_u64(value: &[u8], structure: &'static str) -> Result<u64, FormatError> {
    if value.is_empty()
        || !value.iter().all(u8::is_ascii_digit)
        || (value.len() > 1 && value[0] == b'0')
    {
        return Err(FormatError::InvalidMetadata {
            structure,
            reason: "value is not minimal unsigned decimal",
        });
    }
    std::str::from_utf8(value)
        .ok()
        .and_then(|text| text.parse().ok())
        .ok_or(FormatError::InvalidMetadata {
            structure,
            reason: "value exceeds u64",
        })
}

pub fn validate_tar_stream_total_extraction_size(
    stream: &[u8],
    max_path_length: u32,
    cap: u64,
) -> Result<(), FormatError> {
    if stream.len() % TAR_BLOCK_LEN != 0 {
        return Err(FormatError::InvalidArchive(
            "tar stream is not block aligned",
        ));
    }

    let mut cursor = 0usize;
    let mut total = 0u64;
    while cursor < stream.len() {
        let group_end = tar_member_group_end(stream, cursor)?;
        let member = parse_tar_member_group(&stream[cursor..group_end], max_path_length)?;
        if member.kind == TarEntryKind::Regular {
            total = total
                .checked_add(member.logical_size)
                .ok_or(FormatError::InvalidArchive(
                    "total extraction size overflow",
                ))?;
            if total > cap {
                return Err(FormatError::ReaderUnsupported(
                    "total extraction size exceeds configured cap",
                ));
            }
        }
        cursor = group_end;
    }
    Ok(())
}

pub(crate) struct TarStreamTotalExtractionSizeValidator {
    cursor: usize,
    total: u64,
    max_path_length: u32,
    cap: u64,
}

impl TarStreamTotalExtractionSizeValidator {
    pub(crate) fn new(max_path_length: u32, cap: u64) -> Self {
        Self {
            cursor: 0,
            total: 0,
            max_path_length,
            cap,
        }
    }

    pub(crate) fn observe(&mut self, stream: &[u8]) -> Result<(), FormatError> {
        while self.cursor < stream.len() {
            let Some(group_end) = try_tar_member_group_end(stream, self.cursor)? else {
                return Ok(());
            };
            let member =
                parse_tar_member_group(&stream[self.cursor..group_end], self.max_path_length)?;
            if member.kind == TarEntryKind::Regular {
                self.total = self.total.checked_add(member.logical_size).ok_or(
                    FormatError::InvalidArchive("total extraction size overflow"),
                )?;
                if self.total > self.cap {
                    return Err(FormatError::ReaderUnsupported(
                        "total extraction size exceeds configured cap",
                    ));
                }
            }
            self.cursor = group_end;
        }
        Ok(())
    }
}

pub(crate) struct TarStreamSummaryValidator<O = NoopTarStreamObserver> {
    state: StreamingTarState,
    max_path_length: u32,
    total_extraction_size: u64,
    extraction_cap: u64,
    max_metadata_payload_bytes: usize,
    max_member_count: u64,
    members: Vec<TarStreamMemberSummary>,
    observer: O,
}

impl<O: TarStreamObserver> TarStreamSummaryValidator<O> {
    pub(crate) fn with_observer(
        max_path_length: u32,
        extraction_cap: u64,
        max_metadata_payload_bytes: usize,
        max_member_count: u64,
        observer: O,
    ) -> Self {
        Self {
            state: StreamingTarState::new_member(0),
            max_path_length,
            total_extraction_size: 0,
            extraction_cap,
            max_metadata_payload_bytes,
            max_member_count,
            members: Vec::new(),
            observer,
        }
    }

    pub(crate) fn observe(&mut self, mut input: &[u8]) -> Result<(), FormatError> {
        while !input.is_empty() {
            let state = std::mem::replace(&mut self.state, StreamingTarState::new_member(0));
            let (consumed, next) = self.consume_state(state, input)?;
            self.state = self.resolve_ready_state(next)?;
            input = &input[consumed..];
        }
        Ok(())
    }

    fn consume_state(
        &mut self,
        state: StreamingTarState,
        input: &[u8],
    ) -> Result<(usize, StreamingTarState), FormatError> {
        match state {
            StreamingTarState::Header {
                metadata,
                group_start,
                mut group_size,
                mut header,
            } => {
                let needed = TAR_BLOCK_LEN - header.len();
                let take = needed.min(input.len());
                header.extend_from_slice(&input[..take]);
                group_size = checked_u64_add(group_size, take as u64)?;
                checked_u64_add(group_start, group_size)?;
                let next = if header.len() == TAR_BLOCK_LEN {
                    let mut header_bytes = [0u8; TAR_BLOCK_LEN];
                    header_bytes.copy_from_slice(&header);
                    self.state_after_header(metadata, group_start, group_size, header_bytes)?
                } else {
                    StreamingTarState::Header {
                        metadata,
                        group_start,
                        group_size,
                        header,
                    }
                };
                Ok((take, next))
            }
            StreamingTarState::Payload {
                metadata,
                group_start,
                mut group_size,
                mut entry,
                mut remaining,
                padding_remaining,
            } => {
                let take = remaining.min(input.len() as u64) as usize;
                match &mut entry {
                    PendingTarEntry::LocalPax { payload, .. } => {
                        let next_len = checked_add(payload.len(), take)?;
                        let cap = self.max_metadata_payload_bytes.min(MAX_LOCAL_PAX_PAYLOAD);
                        if next_len > cap {
                            return Err(FormatError::ReaderUnsupported(
                                "tar metadata payload exceeds configured streaming cap",
                            ));
                        }
                        payload.extend_from_slice(&input[..take]);
                    }
                    PendingTarEntry::Auxiliary {
                        validator,
                        stream_to_observer,
                    } => {
                        validator.observe(&input[..take])?;
                        if *stream_to_observer {
                            self.observer.on_auxiliary_payload(&input[..take])?;
                        }
                    }
                    PendingTarEntry::Main { member, sparse, .. }
                        if take > 0 && member.kind == TarEntryKind::Regular =>
                    {
                        if let Some(sparse) = sparse {
                            sparse.observe(&input[..take], &mut self.observer)?;
                        } else {
                            self.observer.on_regular_payload(&input[..take])?;
                        }
                    }
                    PendingTarEntry::Main { .. } => {}
                }
                remaining -= take as u64;
                group_size = checked_u64_add(group_size, take as u64)?;
                checked_u64_add(group_start, group_size)?;
                let next = if remaining == 0 {
                    StreamingTarState::Padding {
                        metadata,
                        group_start,
                        group_size,
                        entry,
                        remaining: padding_remaining,
                    }
                } else {
                    StreamingTarState::Payload {
                        metadata,
                        group_start,
                        group_size,
                        entry,
                        remaining,
                        padding_remaining,
                    }
                };
                Ok((take, next))
            }
            StreamingTarState::Padding {
                metadata,
                group_start,
                mut group_size,
                entry,
                mut remaining,
            } => {
                let take = remaining.min(input.len() as u64) as usize;
                if input[..take].iter().any(|byte| *byte != 0) {
                    return Err(FormatError::InvalidArchive(
                        "tar member padding is non-zero",
                    ));
                }
                remaining -= take as u64;
                group_size = checked_u64_add(group_size, take as u64)?;
                checked_u64_add(group_start, group_size)?;
                let next = if remaining == 0 {
                    self.finish_entry_parts(metadata, group_start, group_size, entry)?
                } else {
                    StreamingTarState::Padding {
                        metadata,
                        group_start,
                        group_size,
                        entry,
                        remaining,
                    }
                };
                Ok((take, next))
            }
        }
    }

    fn resolve_ready_state(
        &mut self,
        mut state: StreamingTarState,
    ) -> Result<StreamingTarState, FormatError> {
        loop {
            state = match state {
                StreamingTarState::Payload {
                    metadata,
                    group_start,
                    group_size,
                    entry,
                    remaining: 0,
                    padding_remaining,
                } => StreamingTarState::Padding {
                    metadata,
                    group_start,
                    group_size,
                    entry,
                    remaining: padding_remaining,
                },
                StreamingTarState::Padding {
                    metadata,
                    group_start,
                    group_size,
                    entry,
                    remaining: 0,
                } => self.finish_entry_parts(metadata, group_start, group_size, entry)?,
                other => return Ok(other),
            };
        }
    }

    pub(crate) fn tar_total_size(&self) -> u64 {
        match &self.state {
            StreamingTarState::Header {
                group_start,
                group_size,
                ..
            }
            | StreamingTarState::Payload {
                group_start,
                group_size,
                ..
            }
            | StreamingTarState::Padding {
                group_start,
                group_size,
                ..
            } => group_start + group_size,
        }
    }

    pub(crate) fn finish(mut self) -> Result<TarStreamSummary, FormatError> {
        let tar_total_size = self.tar_total_size();
        match self.state {
            StreamingTarState::Header {
                header, group_size, ..
            } if header.is_empty() && group_size == 0 => {
                validate_v45_member_graph(&self.members)?;
                let late_diagnostics = self.observer.on_archive_complete()?;
                for diagnostic in late_diagnostics {
                    let member = self
                        .members
                        .iter_mut()
                        .find(|member| member.path == diagnostic.path)
                        .ok_or(FormatError::InvalidArchive(
                            "archive-finalization diagnostic path is missing",
                        ))?;
                    member.diagnostics.push(diagnostic);
                }
                Ok(TarStreamSummary {
                    members: self.members,
                    tar_total_size,
                    total_extraction_size: self.total_extraction_size,
                })
            }
            _ => Err(FormatError::InvalidArchive(
                "tar stream ended inside member group",
            )),
        }
    }

    fn state_after_header(
        &mut self,
        mut metadata: V45StreamingGroup,
        group_start: u64,
        group_size: u64,
        header: [u8; TAR_BLOCK_LEN],
    ) -> Result<StreamingTarState, FormatError> {
        if header.iter().all(|byte| *byte == 0) {
            return Err(FormatError::InvalidArchive("tar member header is empty"));
        }
        verify_tar_checksum(&header)?;
        let typeflag = header[156];
        let header_size = parse_tar_octal(&header[124..136])?;
        let effective_size = metadata
            .pending
            .as_ref()
            .and_then(|(_, records)| records.get("size"))
            .map(|value| parse_minimal_decimal_u64(value, "PAX size"))
            .transpose()?
            .unwrap_or(header_size);
        let padding_remaining = padding_to_512_u64(effective_size);

        let entry = match typeflag {
            b'x' => {
                if metadata.pending.is_some() {
                    return Err(FormatError::InvalidArchive(
                        "PAX header is not immediately consumed",
                    ));
                }
                validate_v45_metadata_header(&header)?;
                if effective_size > MAX_LOCAL_PAX_PAYLOAD as u64
                    || effective_size > self.max_metadata_payload_bytes as u64
                {
                    return Err(FormatError::ReaderUnsupported(
                        "tar metadata payload exceeds configured streaming cap",
                    ));
                }
                let label = ustar_path(&header);
                let kind = if label == b"TZAP-PAX/PRIMARY" {
                    V45PaxKind::Primary
                } else if let Some(ordinal) = parse_auxiliary_pax_label(&label) {
                    if ordinal != metadata.auxiliary.len() as u32 {
                        return Err(FormatError::InvalidArchive(
                            "auxiliary PAX ordinal is not contiguous",
                        ));
                    }
                    V45PaxKind::Auxiliary(ordinal)
                } else {
                    return Err(FormatError::InvalidArchive(
                        "revision-45 PAX header has a non-canonical internal name",
                    ));
                };
                PendingTarEntry::LocalPax {
                    kind,
                    payload: Vec::new(),
                }
            }
            b'Z' => {
                let Some((V45PaxKind::Auxiliary(ordinal), records)) = metadata.pending.take()
                else {
                    return Err(FormatError::InvalidArchive(
                        "auxiliary entry is missing its local PAX header",
                    ));
                };
                validate_v45_auxiliary_header(&header, ordinal, header_size, effective_size)?;
                let validator = AuxiliaryStreamValidator::new(&records, ordinal, effective_size)?;
                let stream_to_observer =
                    self.observer.on_auxiliary_start(validator.declaration())?;
                PendingTarEntry::Auxiliary {
                    validator,
                    stream_to_observer,
                }
            }
            b'g' | b'L' | b'K' | b'V' | b'M' | b'N' | b'S' => {
                return Err(FormatError::InvalidArchive(
                    "global or GNU tar metadata is forbidden in revision 45",
                ));
            }
            0 | b'0' | b'5' | b'2' | b'1' | b'3' | b'4' | b'6' => {
                let Some((V45PaxKind::Primary, records)) = metadata.pending.take() else {
                    return Err(FormatError::InvalidArchive(
                        "primary entry is missing its canonical local PAX header",
                    ));
                };
                let kind = match typeflag {
                    b'5' => TarEntryKind::Directory,
                    b'2' => TarEntryKind::Symlink,
                    b'1' => TarEntryKind::Hardlink,
                    b'3' => TarEntryKind::CharacterDevice,
                    b'4' => TarEntryKind::BlockDevice,
                    b'6' => TarEntryKind::Fifo,
                    _ => TarEntryKind::Regular,
                };
                let primary = parse_primary_metadata(&records)?;
                validate_v45_primary_header(
                    &header,
                    kind,
                    header_size,
                    effective_size,
                    &primary,
                    &records,
                )?;
                let path =
                    v45_primary_path(&header, kind, &records, &primary, self.max_path_length)?;
                let link_target =
                    v45_primary_link_target(&header, kind, &path, &primary, self.max_path_length)?;
                let is_sparse = primary.sparse_logical_size.is_some();
                let reparse_placeholder = records.contains_key("TZAP.windows.reparse-placeholder");
                if kind != TarEntryKind::Regular && effective_size != 0 {
                    return Err(FormatError::InvalidArchive(
                        "non-regular tar entry has non-zero payload size",
                    ));
                }
                if reparse_placeholder && effective_size != 0 {
                    return Err(FormatError::InvalidArchive(
                        "reparse placeholder has non-zero primary payload",
                    ));
                }
                let logical_size = if kind == TarEntryKind::Regular && !reparse_placeholder {
                    primary.sparse_logical_size.unwrap_or(effective_size)
                } else {
                    0
                };
                let (file_entry_flags, capture_report) =
                    v45_group_flags(&primary, &metadata.auxiliary, kind)?;
                validate_v45_primary_cross_fields(
                    kind,
                    &records,
                    &primary,
                    &metadata.auxiliary,
                    V45PrimaryLink {
                        path: &path,
                        target: link_target.as_deref(),
                    },
                    is_sparse,
                    capture_report.as_deref(),
                )?;
                if kind == TarEntryKind::Regular {
                    self.total_extraction_size =
                        self.total_extraction_size.checked_add(logical_size).ok_or(
                            FormatError::InvalidArchive("total extraction size overflow"),
                        )?;
                    if self.total_extraction_size > self.extraction_cap {
                        return Err(FormatError::ReaderUnsupported(
                            "total extraction size exceeds configured cap",
                        ));
                    }
                }
                let diagnostics = Vec::new();
                let mtime = decoded_mtime(&primary, &header)?;
                let member = StreamedTarMemberMetadata {
                    path,
                    kind,
                    link_target,
                    mode: primary.declaration.portable_mode,
                    mtime,
                    logical_size,
                    file_entry_flags,
                    reparse_placeholder,
                    v45_metadata: MemberMetadata {
                        declaration: primary.declaration.clone(),
                        primary_records: records.clone(),
                        auxiliary: metadata.auxiliary.clone(),
                        file_entry_flags,
                        sparse_layout: None,
                        capture_report,
                        primary_has_native_scalar: primary.has_native_scalar,
                        primary_requires_system_restore: primary.requires_system_restore,
                        portable_mirror: portable_metadata_mirror(&header, &records, &primary)?,
                    },
                    diagnostics,
                };
                self.observer.on_member_start(&member)?;
                PendingTarEntry::Main {
                    member,
                    group_start,
                    sparse: primary.sparse_logical_size.map(StreamingSparsePrimary::new),
                }
            }
            _ => {
                return Err(FormatError::InvalidArchive(
                    "unsupported revision-45 tar entry type",
                ));
            }
        };

        self.resolve_ready_state(StreamingTarState::Payload {
            metadata,
            group_start,
            group_size,
            entry,
            remaining: effective_size,
            padding_remaining,
        })
    }

    fn finish_entry_parts(
        &mut self,
        mut metadata: V45StreamingGroup,
        group_start: u64,
        group_size: u64,
        entry: PendingTarEntry,
    ) -> Result<StreamingTarState, FormatError> {
        match entry {
            PendingTarEntry::LocalPax { kind, payload } => {
                metadata.aggregate_pax_bytes = metadata
                    .aggregate_pax_bytes
                    .checked_add(payload.len())
                    .ok_or(FormatError::InvalidArchive("aggregate PAX size overflow"))?;
                if metadata.aggregate_pax_bytes > MAX_AGGREGATE_PAX_PAYLOAD {
                    return Err(FormatError::ReaderResourceLimitExceeded {
                        field: "aggregate local PAX payload bytes per member group",
                        cap: MAX_AGGREGATE_PAX_PAYLOAD as u64,
                        actual: metadata.aggregate_pax_bytes as u64,
                    });
                }
                metadata.pending = Some((kind, parse_canonical_pax(&payload)?));
                Ok(StreamingTarState::Header {
                    metadata,
                    group_start,
                    group_size,
                    header: Vec::new(),
                })
            }
            PendingTarEntry::Auxiliary {
                validator,
                stream_to_observer,
            } => {
                let record = validator.finish()?;
                if stream_to_observer {
                    self.observer.on_auxiliary_complete(&record)?;
                }
                metadata.auxiliary.push(record);
                Ok(StreamingTarState::Header {
                    metadata,
                    group_start,
                    group_size,
                    header: Vec::new(),
                })
            }
            PendingTarEntry::Main {
                member,
                group_start,
                sparse,
            } => {
                if self.members.len() as u64 >= self.max_member_count {
                    return Err(FormatError::ReaderUnsupported(
                        "tar member count exceeds configured streaming cap",
                    ));
                }
                if let Some(sparse) = sparse {
                    sparse.finish(&mut self.observer)?;
                }
                let diagnostics = self.observer.on_member_complete(&member)?;
                self.members.push(TarStreamMemberSummary {
                    path: member.path,
                    kind: member.kind,
                    link_target: member.link_target,
                    mode: member.mode,
                    mtime: member.mtime,
                    logical_size: member.logical_size,
                    file_entry_flags: member.file_entry_flags,
                    reparse_placeholder: member.reparse_placeholder,
                    v45_metadata: member.v45_metadata,
                    diagnostics,
                    group_start,
                    group_size,
                });
                Ok(StreamingTarState::new_member(checked_u64_add(
                    group_start,
                    group_size,
                )?))
            }
        }
    }
}

pub(crate) fn validate_v45_member_graph(
    members: &[TarStreamMemberSummary],
) -> Result<(), FormatError> {
    let mut selected = BTreeMap::<&[u8], &TarStreamMemberSummary>::new();
    for member in members {
        let replace = selected
            .get(member.path.as_slice())
            .is_none_or(|existing| existing.group_start < member.group_start);
        if replace {
            selected.insert(member.path.as_slice(), member);
        }
    }
    for member in selected.values() {
        if member.kind == TarEntryKind::Hardlink {
            let target_path = member
                .link_target
                .as_deref()
                .ok_or(FormatError::InvalidArchive("hardlink target is missing"))?;
            let target = selected
                .get(target_path)
                .ok_or(FormatError::InvalidArchive(
                    "hardlink target is not present in the selected archive graph",
                ))?;
            if target.kind != TarEntryKind::Regular || target.reparse_placeholder {
                return Err(FormatError::InvalidArchive(
                    "hardlink target is not a canonical regular primary",
                ));
            }
            if member.v45_metadata.portable_mirror != target.v45_metadata.portable_mirror {
                return Err(FormatError::InvalidArchive(
                    "hardlink portable metadata mirror differs from canonical target",
                ));
            }
        }

        let mut ancestor = Vec::new();
        let components: Vec<_> = member.path.split(|byte| *byte == b'/').collect();
        for component in components.iter().take(components.len().saturating_sub(1)) {
            if !ancestor.is_empty() {
                ancestor.push(b'/');
            }
            ancestor.extend_from_slice(component);
            if let Some(parent) = selected.get(ancestor.as_slice()) {
                if parent.reparse_placeholder || parent.kind == TarEntryKind::Symlink {
                    return Err(FormatError::InvalidArchive(
                        "selected path graph traverses a symlink or reparse ancestor",
                    ));
                }
                if parent.kind != TarEntryKind::Directory {
                    return Err(FormatError::InvalidArchive(
                        "selected path graph traverses a non-directory ancestor",
                    ));
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_owned_restore_plan(
    members: &[&OwnedTarMember],
    options: SafeExtractionOptions,
) -> Result<(), FormatError> {
    let mut selected = BTreeMap::<&[u8], &OwnedTarMember>::new();
    for &member in members {
        if selected.insert(member.path.as_slice(), member).is_some() {
            return Err(FormatError::InvalidArchive(
                "restore plan contains duplicate selected paths",
            ));
        }
        plan_owned_member_restore(member, options)?;
    }
    for member in selected.values() {
        if member.kind == TarEntryKind::Hardlink {
            let target_path = member
                .link_target
                .as_deref()
                .ok_or(FormatError::InvalidArchive("hardlink target is missing"))?;
            let target = selected
                .get(target_path)
                .ok_or(FormatError::InvalidArchive(
                    "hardlink target is not present in the selected restore graph",
                ))?;
            if target.kind != TarEntryKind::Regular || target.reparse_placeholder {
                return Err(FormatError::InvalidArchive(
                    "hardlink target is not a canonical regular primary",
                ));
            }
            let alias_metadata = member.v45_metadata.as_ref().expect("checked above");
            let target_metadata = target.v45_metadata.as_ref().expect("checked above");
            if alias_metadata.portable_mirror != target_metadata.portable_mirror {
                return Err(FormatError::InvalidArchive(
                    "hardlink portable metadata mirror differs from canonical target",
                ));
            }
        }

        let mut ancestor = Vec::new();
        let components: Vec<_> = member.path.split(|byte| *byte == b'/').collect();
        for component in components.iter().take(components.len().saturating_sub(1)) {
            if !ancestor.is_empty() {
                ancestor.push(b'/');
            }
            ancestor.extend_from_slice(component);
            if let Some(parent) = selected.get(ancestor.as_slice()) {
                if parent.reparse_placeholder || parent.kind == TarEntryKind::Symlink {
                    return Err(FormatError::InvalidArchive(
                        "restore path traverses a selected symlink or reparse ancestor",
                    ));
                }
                if parent.kind != TarEntryKind::Directory {
                    return Err(FormatError::InvalidArchive(
                        "restore path traverses a selected non-directory ancestor",
                    ));
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn plan_owned_member_restore(
    member: &OwnedTarMember,
    options: SafeExtractionOptions,
) -> Result<Vec<MetadataDiagnostic>, FormatError> {
    let metadata = member
        .v45_metadata
        .as_ref()
        .ok_or(FormatError::InvalidArchive(
            "revision-45 member metadata is missing",
        ))?;
    plan_restore(
        &member.path,
        metadata,
        member.kind,
        member.reparse_placeholder,
        options,
    )
}

pub(crate) fn restore_phase(member: &OwnedTarMember) -> u8 {
    restore_phase_for_kind(member.kind, member.reparse_placeholder)
}

fn restore_phase_for_kind(kind: TarEntryKind, reparse_placeholder: bool) -> u8 {
    if reparse_placeholder {
        return 3;
    }
    match kind {
        TarEntryKind::Directory => 4,
        TarEntryKind::Regular => 1,
        TarEntryKind::Symlink
        | TarEntryKind::CharacterDevice
        | TarEntryKind::BlockDevice
        | TarEntryKind::Fifo => 2,
        TarEntryKind::Hardlink => 3,
    }
}

enum StreamingTarState {
    Header {
        metadata: V45StreamingGroup,
        group_start: u64,
        group_size: u64,
        header: Vec<u8>,
    },
    Payload {
        metadata: V45StreamingGroup,
        group_start: u64,
        group_size: u64,
        entry: PendingTarEntry,
        remaining: u64,
        padding_remaining: u64,
    },
    Padding {
        metadata: V45StreamingGroup,
        group_start: u64,
        group_size: u64,
        entry: PendingTarEntry,
        remaining: u64,
    },
}

impl StreamingTarState {
    fn new_member(group_start: u64) -> Self {
        Self::Header {
            metadata: V45StreamingGroup::default(),
            group_start,
            group_size: 0,
            header: Vec::new(),
        }
    }
}

enum PendingTarEntry {
    LocalPax {
        kind: V45PaxKind,
        payload: Vec<u8>,
    },
    Auxiliary {
        validator: AuxiliaryStreamValidator,
        stream_to_observer: bool,
    },
    Main {
        member: StreamedTarMemberMetadata,
        group_start: u64,
        sparse: Option<StreamingSparsePrimary>,
    },
}

fn checked_u64_add(lhs: u64, rhs: u64) -> Result<u64, FormatError> {
    lhs.checked_add(rhs).ok_or(FormatError::InvalidArchive(
        "tar member arithmetic overflow",
    ))
}

pub(crate) fn try_tar_member_group_end(
    stream: &[u8],
    start: usize,
) -> Result<Option<usize>, FormatError> {
    let mut cursor = start;
    let mut pending: Option<(V45PaxKind, PaxRecords)> = None;
    let mut auxiliary_count = 0u32;
    let mut aggregate_pax_bytes = 0usize;

    loop {
        let Some(header) = try_slice(stream, cursor, TAR_BLOCK_LEN)? else {
            return Ok(None);
        };
        if header.iter().all(|byte| *byte == 0) {
            return Err(FormatError::InvalidArchive("tar member header is empty"));
        }
        verify_tar_checksum(header)?;
        let typeflag = header[156];
        let header_size = parse_tar_octal(&header[124..136])?;
        let effective_size = pending
            .as_ref()
            .and_then(|(_, records)| records.get("size"))
            .map(|value| parse_minimal_decimal_u64(value, "PAX size"))
            .transpose()?
            .unwrap_or(header_size);
        let payload_start = checked_add(cursor, TAR_BLOCK_LEN)?;
        let payload_len = to_usize(effective_size)?;
        let payload_end = checked_add(payload_start, payload_len)?;
        let padded_end = checked_add(payload_end, padding_to_512(payload_len))?;
        let Some(payload) = try_slice(stream, payload_start, payload_len)? else {
            return Ok(None);
        };
        if padded_end > stream.len() {
            return Ok(None);
        }
        if stream[payload_end..padded_end]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(FormatError::InvalidArchive(
                "tar member padding is non-zero",
            ));
        }

        match typeflag {
            b'x' => {
                if pending.is_some() {
                    return Err(FormatError::InvalidArchive(
                        "PAX header is not immediately consumed",
                    ));
                }
                validate_v45_metadata_header(header)?;
                aggregate_pax_bytes = aggregate_pax_bytes
                    .checked_add(payload.len())
                    .ok_or(FormatError::InvalidArchive("aggregate PAX size overflow"))?;
                if aggregate_pax_bytes > MAX_AGGREGATE_PAX_PAYLOAD {
                    return Err(FormatError::ReaderResourceLimitExceeded {
                        field: "aggregate local PAX payload bytes per member group",
                        cap: MAX_AGGREGATE_PAX_PAYLOAD as u64,
                        actual: aggregate_pax_bytes as u64,
                    });
                }
                let records = parse_canonical_pax(payload)?;
                let label = ustar_path(header);
                let kind = if label == b"TZAP-PAX/PRIMARY" {
                    V45PaxKind::Primary
                } else if let Some(ordinal) = parse_auxiliary_pax_label(&label) {
                    if ordinal != auxiliary_count {
                        return Err(FormatError::InvalidArchive(
                            "auxiliary PAX ordinal is not contiguous",
                        ));
                    }
                    V45PaxKind::Auxiliary(ordinal)
                } else {
                    return Err(FormatError::InvalidArchive(
                        "revision-45 PAX header has a non-canonical internal name",
                    ));
                };
                pending = Some((kind, records));
                cursor = padded_end;
            }
            b'Z' => {
                let Some((V45PaxKind::Auxiliary(ordinal), _)) = pending.take() else {
                    return Err(FormatError::InvalidArchive(
                        "auxiliary entry is missing its local PAX header",
                    ));
                };
                validate_v45_auxiliary_header(header, ordinal, header_size, effective_size)?;
                auxiliary_count = auxiliary_count
                    .checked_add(1)
                    .ok_or(FormatError::InvalidArchive("auxiliary count overflow"))?;
                cursor = padded_end;
            }
            b'g' | b'L' | b'K' | b'V' | b'M' | b'N' | b'S' => {
                return Err(FormatError::InvalidArchive(
                    "global or GNU tar metadata is forbidden in revision 45",
                ));
            }
            0 | b'0' | b'5' | b'2' | b'1' | b'3' | b'4' | b'6' => {
                if !matches!(pending, Some((V45PaxKind::Primary, _))) {
                    return Err(FormatError::InvalidArchive(
                        "primary entry is missing its canonical local PAX header",
                    ));
                }
                return Ok(Some(padded_end));
            }
            _ => {
                return Err(FormatError::InvalidArchive(
                    "unsupported revision-45 tar entry type",
                ));
            }
        }

        if cursor >= stream.len() {
            return Ok(None);
        }
    }
}

fn try_slice(stream: &[u8], offset: usize, len: usize) -> Result<Option<&[u8]>, FormatError> {
    let end = checked_add(offset, len)?;
    if end > stream.len() {
        return Ok(None);
    }
    Ok(Some(&stream[offset..end]))
}

pub(crate) fn stream_regular_tar_member_group_to_writer<R, W>(
    reader: &mut R,
    expected_path: &[u8],
    expected_file_data_size: u64,
    expected_file_flags: u32,
    group_len: u64,
    max_path_length: u32,
    writer: &mut W,
) -> Result<Vec<MetadataDiagnostic>, ExtractError>
where
    R: TarMemberGroupReader,
    W: Write,
{
    let mut handler = RegularWriterHandler { writer };
    let member = stream_tar_member_group(
        reader,
        expected_path,
        expected_file_data_size,
        expected_file_flags,
        group_len,
        max_path_length,
        &mut handler,
    )?;
    Ok(member.diagnostics)
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct StreamingMemberExpectation<'a> {
    pub path: &'a [u8],
    pub file_data_size: u64,
    pub file_flags: u32,
    pub group_len: u64,
    pub max_path_length: u32,
}

pub(crate) fn restore_streaming_tar_member_group<R>(
    root: &Path,
    expected: StreamingMemberExpectation<'_>,
    options: SafeExtractionOptions,
    reader: &mut R,
) -> Result<Vec<MetadataDiagnostic>, ExtractError>
where
    R: TarMemberGroupReader,
{
    let mut handler = FilesystemRestoreHandler::new(root, options);
    let member = stream_tar_member_group(
        reader,
        expected.path,
        expected.file_data_size,
        expected.file_flags,
        expected.group_len,
        expected.max_path_length,
        &mut handler,
    )?;
    handler.finish(&member)
}

fn stream_tar_member_group<R, H>(
    reader: &mut R,
    expected_path: &[u8],
    expected_file_data_size: u64,
    expected_file_flags: u32,
    group_len: u64,
    max_path_length: u32,
    handler: &mut H,
) -> Result<StreamedTarMemberMetadata, ExtractError>
where
    R: TarMemberGroupReader,
    H: TarMemberStreamHandler,
{
    if group_len < (TAR_BLOCK_LEN * 3) as u64 || group_len % TAR_BLOCK_LEN as u64 != 0 {
        return Err(FormatError::InvalidArchive("tar member group is not block aligned").into());
    }

    let mut remaining = group_len;
    let mut pending: Option<(V45PaxKind, PaxRecords)> = None;
    let mut auxiliary = Vec::<AuxiliaryRecord>::new();
    let mut aggregate_pax_bytes = 0usize;

    loop {
        let mut header = [0u8; TAR_BLOCK_LEN];
        read_member_bytes(reader, &mut header, &mut remaining)?;
        if header.iter().all(|byte| *byte == 0) {
            return Err(FormatError::InvalidArchive("tar member header is empty").into());
        }
        verify_tar_checksum(&header)?;

        let typeflag = header[156];
        let header_size = parse_tar_octal(&header[124..136])?;
        let effective_size = pending
            .as_ref()
            .and_then(|(_, records)| records.get("size"))
            .map(|value| parse_minimal_decimal_u64(value, "PAX size"))
            .transpose()?
            .unwrap_or(header_size);
        let padding_len = padding_to_512_u64(effective_size);
        let entry_payload_len =
            effective_size
                .checked_add(padding_len)
                .ok_or(FormatError::InvalidArchive(
                    "tar member arithmetic overflow",
                ))?;
        if entry_payload_len > remaining {
            return Err(FormatError::InvalidArchive("tar member payload exceeds group").into());
        }

        match typeflag {
            b'x' => {
                if pending.is_some() {
                    return Err(FormatError::InvalidArchive(
                        "PAX header is not immediately consumed",
                    )
                    .into());
                }
                validate_v45_metadata_header(&header)?;
                if effective_size > MAX_LOCAL_PAX_PAYLOAD as u64 {
                    return Err(FormatError::ReaderResourceLimitExceeded {
                        field: "local PAX payload bytes",
                        cap: MAX_LOCAL_PAX_PAYLOAD as u64,
                        actual: effective_size,
                    }
                    .into());
                }
                let payload = read_member_vec(reader, effective_size, &mut remaining)?;
                read_zero_padding(reader, padding_len, &mut remaining)?;
                aggregate_pax_bytes = aggregate_pax_bytes
                    .checked_add(payload.len())
                    .ok_or(FormatError::InvalidArchive("aggregate PAX size overflow"))?;
                if aggregate_pax_bytes > MAX_AGGREGATE_PAX_PAYLOAD {
                    return Err(FormatError::ReaderResourceLimitExceeded {
                        field: "aggregate local PAX payload bytes per member group",
                        cap: MAX_AGGREGATE_PAX_PAYLOAD as u64,
                        actual: aggregate_pax_bytes as u64,
                    }
                    .into());
                }
                let records = parse_canonical_pax(&payload)?;
                let label = ustar_path(&header);
                let kind = if label == b"TZAP-PAX/PRIMARY" {
                    V45PaxKind::Primary
                } else if let Some(ordinal) = parse_auxiliary_pax_label(&label) {
                    if ordinal != auxiliary.len() as u32 {
                        return Err(FormatError::InvalidArchive(
                            "auxiliary PAX ordinal is not contiguous",
                        )
                        .into());
                    }
                    V45PaxKind::Auxiliary(ordinal)
                } else {
                    return Err(FormatError::InvalidArchive(
                        "revision-45 PAX header has a non-canonical internal name",
                    )
                    .into());
                };
                pending = Some((kind, records));
            }
            b'Z' => {
                let Some((V45PaxKind::Auxiliary(ordinal), records)) = pending.take() else {
                    return Err(FormatError::InvalidArchive(
                        "auxiliary entry is missing its local PAX header",
                    )
                    .into());
                };
                validate_v45_auxiliary_header(&header, ordinal, header_size, effective_size)?;
                let mut validator =
                    AuxiliaryStreamValidator::new(&records, ordinal, effective_size)?;
                let stream_to_handler = handler.begin_auxiliary_payload(validator.declaration())?;
                stream_auxiliary_payload(
                    reader,
                    effective_size,
                    &mut remaining,
                    &mut validator,
                    stream_to_handler.then_some(handler),
                )?;
                read_zero_padding(reader, padding_len, &mut remaining)?;
                let record = validator.finish()?;
                if stream_to_handler {
                    handler.finish_auxiliary_payload(&record)?;
                }
                auxiliary.push(record);
            }
            b'g' | b'L' | b'K' | b'V' | b'M' | b'N' | b'S' => {
                return Err(FormatError::InvalidArchive(
                    "global or GNU tar metadata is forbidden in revision 45",
                )
                .into());
            }
            0 | b'0' | b'5' | b'2' | b'1' | b'3' | b'4' | b'6' => {
                let Some((V45PaxKind::Primary, records)) = pending.take() else {
                    return Err(FormatError::InvalidArchive(
                        "primary entry is missing its canonical local PAX header",
                    )
                    .into());
                };
                let kind = match typeflag {
                    b'5' => TarEntryKind::Directory,
                    b'2' => TarEntryKind::Symlink,
                    b'1' => TarEntryKind::Hardlink,
                    b'3' => TarEntryKind::CharacterDevice,
                    b'4' => TarEntryKind::BlockDevice,
                    b'6' => TarEntryKind::Fifo,
                    _ => TarEntryKind::Regular,
                };
                let primary = parse_primary_metadata(&records)?;
                validate_v45_primary_header(
                    &header,
                    kind,
                    header_size,
                    effective_size,
                    &primary,
                    &records,
                )?;
                let path = v45_primary_path(&header, kind, &records, &primary, max_path_length)?;
                let link_target =
                    v45_primary_link_target(&header, kind, &path, &primary, max_path_length)?;
                let sparse = primary.sparse_logical_size.is_some();
                let reparse_placeholder = records.contains_key("TZAP.windows.reparse-placeholder");
                if kind != TarEntryKind::Regular && effective_size != 0 {
                    return Err(FormatError::InvalidArchive(
                        "non-regular tar entry has non-zero payload size",
                    )
                    .into());
                }
                if reparse_placeholder && effective_size != 0 {
                    return Err(FormatError::InvalidArchive(
                        "reparse placeholder has non-zero primary payload",
                    )
                    .into());
                }
                let logical_size = if kind == TarEntryKind::Regular && !reparse_placeholder {
                    primary.sparse_logical_size.unwrap_or(effective_size)
                } else {
                    0
                };
                let (file_entry_flags, capture_report) =
                    v45_group_flags(&primary, &auxiliary, kind)?;
                if file_entry_flags != expected_file_flags {
                    return Err(FormatError::InvalidArchive(
                        "tar member metadata flags do not match FileEntry flags",
                    )
                    .into());
                }
                validate_v45_primary_cross_fields(
                    kind,
                    &records,
                    &primary,
                    &auxiliary,
                    V45PrimaryLink {
                        path: &path,
                        target: link_target.as_deref(),
                    },
                    sparse,
                    capture_report.as_deref(),
                )?;
                let diagnostics = Vec::new();
                let mtime = decoded_mtime(&primary, &header)?;
                let member = StreamedTarMemberMetadata {
                    path,
                    kind,
                    link_target,
                    mode: primary.declaration.portable_mode,
                    mtime,
                    logical_size,
                    file_entry_flags,
                    reparse_placeholder,
                    v45_metadata: MemberMetadata {
                        declaration: primary.declaration.clone(),
                        primary_records: records.clone(),
                        auxiliary: auxiliary.clone(),
                        file_entry_flags,
                        sparse_layout: None,
                        capture_report,
                        primary_has_native_scalar: primary.has_native_scalar,
                        primary_requires_system_restore: primary.requires_system_restore,
                        portable_mirror: portable_metadata_mirror(&header, &records, &primary)?,
                    },
                    diagnostics,
                };
                if member.path != expected_path {
                    return Err(FormatError::InvalidArchive(
                        "tar member path does not match FileEntry path",
                    )
                    .into());
                }
                if member.logical_size != expected_file_data_size {
                    return Err(FormatError::InvalidArchive(
                        "tar member size does not match FileEntry file_data_size",
                    )
                    .into());
                }
                handler.on_member(&member)?;
                if member.kind == TarEntryKind::Regular {
                    if let Some(logical_size) = primary.sparse_logical_size {
                        stream_sparse_primary_payload(
                            reader,
                            effective_size,
                            logical_size,
                            &mut remaining,
                            handler,
                        )?;
                    } else {
                        stream_regular_payload(reader, effective_size, &mut remaining, handler)?;
                    }
                }
                read_zero_padding(reader, padding_len, &mut remaining)?;
                if remaining != 0 {
                    return Err(FormatError::InvalidArchive(
                        "tar member group has bytes after main entry",
                    )
                    .into());
                }
                return Ok(member);
            }
            _ => {
                return Err(
                    FormatError::InvalidArchive("unsupported revision-45 tar entry type").into(),
                );
            }
        }

        if remaining == 0 {
            return Err(FormatError::InvalidArchive(
                "tar member group has metadata records but no main entry",
            )
            .into());
        }
    }
}

fn plan_restore(
    path: &[u8],
    metadata: &MemberMetadata,
    kind: TarEntryKind,
    reparse_placeholder: bool,
    options: SafeExtractionOptions,
) -> Result<Vec<MetadataDiagnostic>, FormatError> {
    if options.restore_policy == RestorePolicy::System && !options.system_authorized {
        return Err(FormatError::ReaderUnsupported(
            "system restore policy requires explicit caller authorization",
        ));
    }

    let mut diagnostics = Vec::new();
    if metadata.declaration.capture_status == CaptureStatus::Partial {
        diagnostics.push(
            MetadataDiagnostic::new(
                path,
                "tzap-core-v1",
                "capture-completeness",
                MetadataOperation::Plan,
                MetadataDiagnosticStatus::Partial,
                "entry capture is partial; full-fidelity restoration is impossible",
            )
            .for_restore(
                options.restore_policy,
                restore_phase_for_kind(kind, reparse_placeholder),
            ),
        );
        if let Some(rows) = &metadata.capture_report {
            diagnostics.extend(rows.iter().map(|row| {
                let message = if row.encoded_detail.is_empty() {
                    format!("capture omission: {}", row.reason)
                } else {
                    format!(
                        "capture omission: {}; detail={}",
                        row.reason, row.encoded_detail
                    )
                };
                MetadataDiagnostic::new(
                    path,
                    &row.profile,
                    &row.metadata_class,
                    MetadataOperation::Capture,
                    MetadataDiagnosticStatus::Partial,
                    message,
                )
                .for_restore(
                    options.restore_policy,
                    restore_phase_for_kind(kind, reparse_placeholder),
                )
            }));
        }
        let required_omission = metadata.capture_report.as_ref().is_some_and(|rows| {
            rows.iter().any(|row| {
                metadata
                    .declaration
                    .required_profiles
                    .binary_search(&row.profile)
                    .is_ok()
            })
        });
        if required_omission && !options.allow_degraded {
            return Err(FormatError::ReaderUnsupported(
                "required-profile capture omission needs explicit degraded restore",
            ));
        }
    }
    let unknown_required_profiles = metadata
        .declaration
        .unknown_required_profiles()
        .collect::<Vec<_>>();
    if !unknown_required_profiles.is_empty() {
        if !options.allow_degraded {
            return Err(FormatError::ReaderUnsupported(
                "requested restore policy requires an unsupported required profile",
            ));
        }
        diagnostics.extend(unknown_required_profiles.into_iter().map(|profile| {
            MetadataDiagnostic::new(
                path,
                profile,
                "required-profile",
                MetadataOperation::Plan,
                MetadataDiagnosticStatus::Unsupported,
                "unsupported required profile was preserved but not restored",
            )
            .for_restore(
                options.restore_policy,
                restore_phase_for_kind(kind, reparse_placeholder),
            )
        }));
    }
    diagnostics.extend(
        metadata
            .declaration
            .unknown_optional_profiles()
            .map(|profile| {
                MetadataDiagnostic::new(
                    path,
                    profile,
                    "optional-profile",
                    MetadataOperation::Plan,
                    MetadataDiagnosticStatus::Skipped,
                    "unsupported optional profile was preserved but not restored",
                )
                .for_restore(
                    options.restore_policy,
                    restore_phase_for_kind(kind, reparse_placeholder),
                )
            }),
    );

    if options.restore_policy == RestorePolicy::Content {
        for (metadata_class, message) in [
            ("mode", "portable mode is outside content restore policy"),
            (
                "mtime",
                "modification time is outside content restore policy",
            ),
        ] {
            diagnostics.push(
                MetadataDiagnostic::new(
                    path,
                    "portable-v1",
                    metadata_class,
                    MetadataOperation::Plan,
                    MetadataDiagnosticStatus::Skipped,
                    message,
                )
                .for_restore(options.restore_policy, 4),
            );
        }
    }

    if options.restore_policy == RestorePolicy::Content && kind == TarEntryKind::Symlink {
        diagnostics.push(
            MetadataDiagnostic::new(
                path,
                "portable-v1",
                "symlink",
                MetadataOperation::Plan,
                MetadataDiagnosticStatus::Skipped,
                "symlink skipped by content restore policy",
            )
            .for_restore(options.restore_policy, 2),
        );
    }
    if reparse_placeholder
        && !(cfg!(windows)
            && options.restore_policy == RestorePolicy::System
            && windows_reparse_metadata_supported(metadata))
    {
        diagnostics.push(
            MetadataDiagnostic::new(
                path,
                "windows-backup-v1",
                "reparse-data",
                MetadataOperation::Plan,
                MetadataDiagnosticStatus::Skipped,
                if options.restore_policy == RestorePolicy::System {
                    "reparse placeholder restoration is unsupported on this host"
                } else {
                    "reparse placeholder is outside the selected restore policy"
                },
            )
            .for_restore(options.restore_policy, 3),
        );
    }
    if matches!(
        kind,
        TarEntryKind::CharacterDevice | TarEntryKind::BlockDevice | TarEntryKind::Fifo
    ) && !(cfg!(any(target_os = "linux", target_os = "macos"))
        && options.restore_policy == RestorePolicy::System
        && options.system_authorized)
    {
        diagnostics.push(
            MetadataDiagnostic::new(
                path,
                "posix-backup-v1",
                "special-object",
                MetadataOperation::Plan,
                MetadataDiagnosticStatus::Skipped,
                if options.restore_policy == RestorePolicy::System {
                    "special object restoration is unsupported on this host"
                } else {
                    "special object is outside the selected restore policy"
                },
            )
            .for_restore(options.restore_policy, 2),
        );
    }
    if metadata.file_entry_flags & HAS_SPARSE_EXTENTS != 0 {
        let native_sparse_supported = cfg!(any(windows, target_os = "linux"));
        if options.restore_policy != RestorePolicy::Content
            && !native_sparse_supported
            && !options.allow_degraded
        {
            return Err(FormatError::ReaderUnsupported(
                "sparse layout materialization needs explicit degraded restore",
            ));
        }
        if options.restore_policy == RestorePolicy::Content || !native_sparse_supported {
            diagnostics.push(
                MetadataDiagnostic::new(
                    path,
                    "portable-v1",
                    "sparse-layout",
                    MetadataOperation::Plan,
                    MetadataDiagnosticStatus::Materialized,
                    if options.restore_policy == RestorePolicy::Content {
                        "sparse layout is outside content policy; logical bytes will be materialized"
                    } else {
                        "sparse layout will be materialized as logical zero bytes"
                    },
                )
                .for_restore(options.restore_policy, 1),
            );
        }
    }

    if options.restore_policy != RestorePolicy::Content
        && !cfg!(unix)
        && metadata.declaration.mode_origin_native
        && !matches!(metadata.declaration.portable_mode & 0o1777, 0o444 | 0o666)
    {
        if !options.allow_degraded {
            return Err(FormatError::ReaderUnsupported(
                "portable mode cannot be represented exactly on this host",
            ));
        }
        diagnostics.push(
            MetadataDiagnostic::new(
                path,
                "portable-v1",
                "mode",
                MetadataOperation::Plan,
                MetadataDiagnosticStatus::Partial,
                "portable mode can only be projected to host readonly state",
            )
            .for_restore(options.restore_policy, 4),
        );
    }

    if metadata.declaration.owner_kind_posix && options.restore_policy != RestorePolicy::System {
        diagnostics.push(
            MetadataDiagnostic::new(
                path,
                "portable-v1",
                "numeric-ownership",
                MetadataOperation::Plan,
                MetadataDiagnosticStatus::Skipped,
                "numeric ownership is outside the selected restore policy",
            )
            .for_restore(options.restore_policy, 4),
        );
    } else if metadata.declaration.owner_kind_posix && !numeric_ownership_supported(metadata) {
        if !options.allow_degraded {
            return Err(FormatError::ReaderUnsupported(
                "numeric ownership cannot be represented on this host",
            ));
        }
        diagnostics.push(
            MetadataDiagnostic::new(
                path,
                "portable-v1",
                "numeric-ownership",
                MetadataOperation::Plan,
                MetadataDiagnosticStatus::Unsupported,
                "numeric ownership cannot be represented on this host",
            )
            .for_restore(options.restore_policy, 4),
        );
    }
    if metadata.declaration.portable_mode & 0o6000 != 0
        && options.restore_policy != RestorePolicy::System
    {
        diagnostics.push(
            MetadataDiagnostic::new(
                path,
                "portable-v1",
                "setid-mode",
                MetadataOperation::Plan,
                MetadataDiagnosticStatus::Skipped,
                "setuid/setgid mode bits are outside the selected restore policy",
            )
            .for_restore(options.restore_policy, 4),
        );
    }
    if let Some(attributes) = metadata.declaration.portable_attributes {
        let portable_bits = attributes & 0x03;
        let same_os_bits = attributes & 0x0c;
        let unsupported_requested = match options.restore_policy {
            RestorePolicy::Content => false,
            RestorePolicy::Portable => {
                portable_bits != 0 && (!cfg!(windows) || portable_bits & !1 != 0)
            }
            RestorePolicy::SameOs | RestorePolicy::System => {
                (portable_bits != 0
                    && !(cfg!(windows) && metadata.declaration.source_os == "windows")
                    && (!cfg!(windows) || portable_bits & !1 != 0))
                    || (same_os_bits != 0
                        && !(cfg!(windows) && metadata.declaration.source_os == "windows"))
            }
        };
        if unsupported_requested && !options.allow_degraded {
            return Err(FormatError::ReaderUnsupported(
                "requested portable attribute projection needs explicit degraded restore",
            ));
        }
        if options.restore_policy == RestorePolicy::Content
            || unsupported_requested
            || (options.restore_policy == RestorePolicy::Portable && same_os_bits != 0)
        {
            diagnostics.push(
                MetadataDiagnostic::new(
                    path,
                    "portable-v1",
                    "portable-attributes",
                    MetadataOperation::Plan,
                    MetadataDiagnosticStatus::Skipped,
                    "portable attribute projection was wholly or partly outside host policy capability",
                )
                .for_restore(options.restore_policy, 4),
            );
        }
    }

    let requests_same_os = matches!(
        options.restore_policy,
        RestorePolicy::SameOs | RestorePolicy::System
    );
    let requests_system = options.restore_policy == RestorePolicy::System;
    if metadata.primary_records.contains_key("atime") && metadata.declaration.source_os != "windows"
    {
        diagnostics.push(
            MetadataDiagnostic::new(
                path,
                "posix-backup-v1",
                "atime",
                MetadataOperation::Plan,
                MetadataDiagnosticStatus::Skipped,
                "access time restoration was not explicitly requested",
            )
            .for_restore(options.restore_policy, 4),
        );
    }
    if requests_same_os && !requests_system {
        for key in metadata
            .primary_records
            .keys()
            .filter(|key| key.starts_with("LIBARCHIVE.xattr."))
        {
            let name = decode_percent_name(&key.as_bytes()["LIBARCHIVE.xattr.".len()..])?;
            if system_xattr_name(&name, &metadata.declaration.source_os) {
                diagnostics.push(
                    MetadataDiagnostic::new(
                        path,
                        "linux-backup-v1",
                        "system-extended-attribute",
                        MetadataOperation::Plan,
                        MetadataDiagnosticStatus::Skipped,
                        "system-class extended attribute is outside same-os restore policy",
                    )
                    .for_restore(options.restore_policy, 4),
                );
            }
        }
        if metadata
            .primary_records
            .get("TZAP.linux.fsflags")
            .and_then(|value| std::str::from_utf8(value).ok())
            .and_then(|value| u64::from_str_radix(value, 16).ok())
            .is_some_and(|flags| flags & 0x30 != 0)
        {
            diagnostics.push(
                MetadataDiagnostic::new(
                    path,
                    "linux-backup-v1",
                    "no-change-inode-flags",
                    MetadataOperation::Plan,
                    MetadataDiagnosticStatus::Skipped,
                    "immutable/append-only inode flags are outside same-os restore policy",
                )
                .for_restore(options.restore_policy, 4),
            );
        }
        if metadata
            .primary_records
            .get("TZAP.macos.st-flags")
            .and_then(|value| parse_macos_flags(value).ok())
            .is_some_and(macos_flags_require_system)
        {
            diagnostics.push(
                MetadataDiagnostic::new(
                    path,
                    "macos-backup-v1",
                    "system-file-flags",
                    MetadataOperation::Plan,
                    MetadataDiagnosticStatus::Skipped,
                    "system-class macOS file flags are outside same-os restore policy",
                )
                .for_restore(options.restore_policy, 4),
            );
        }
    }
    if requests_same_os
        && metadata
            .primary_records
            .get("TZAP.macos.st-flags")
            .and_then(|value| parse_macos_flags(value).ok())
            .is_some_and(|flags| !macos_flags_supported(flags))
    {
        diagnostics.push(
            MetadataDiagnostic::new(
                path,
                "macos-backup-v1",
                "unrecognized-file-flags",
                MetadataOperation::Plan,
                MetadataDiagnosticStatus::Skipped,
                "unrecognized macOS file flags were preserved but will not be applied",
            )
            .for_restore(options.restore_policy, 4),
        );
    }
    let profile_is_required = |profile: &str| {
        metadata
            .declaration
            .required_profiles
            .binary_search_by(|candidate| candidate.as_str().cmp(profile))
            .is_ok()
    };
    let native_profile = metadata
        .auxiliary
        .iter()
        .find(|record| record.native || record.restore_class >= RestoreClass::SameOs)
        .map(|record| record.profile.as_str())
        .or_else(|| {
            metadata
                .declaration
                .required_profiles
                .iter()
                .chain(&metadata.declaration.optional_profiles)
                .find(|profile| profile.as_str() != "portable-v1")
                .map(String::as_str)
        })
        .unwrap_or("portable-v1");
    let required_native_scalar = metadata.primary_has_native_scalar
        && metadata
            .declaration
            .required_profiles
            .iter()
            .any(|profile| profile != "portable-v1");
    let required_native_profile = metadata
        .declaration
        .required_profiles
        .iter()
        .any(|profile| profile != "portable-v1");
    let native_source_matches_host =
        source_os_matches_current_host(&metadata.declaration.source_os);
    let unsupported_primary_same_os = native_primary_restore_unsupported(metadata, false);
    let unsupported_primary_system = native_primary_restore_unsupported(metadata, true);
    let unsupported_same_os = metadata.auxiliary.iter().any(|record| {
        record.restore_class == RestoreClass::SameOs
            && profile_is_required(&record.profile)
            && !native_auxiliary_restore_supported(record, false, Some(kind))
    }) || (required_native_scalar && unsupported_primary_same_os)
        || (required_native_profile && !native_source_matches_host);
    let unsupported_system = metadata.auxiliary.iter().any(|record| {
        record.restore_class == RestoreClass::System
            && profile_is_required(&record.profile)
            && !native_auxiliary_restore_supported(record, true, Some(kind))
    }) || (metadata.declaration.owner_kind_posix
        && !numeric_ownership_supported(metadata))
        || (metadata.declaration.portable_mode & 0o6000 != 0 && !cfg!(unix))
        || (required_native_scalar && unsupported_primary_system)
        || (reparse_placeholder && !windows_reparse_metadata_supported(metadata))
        || (matches!(
            kind,
            TarEntryKind::CharacterDevice | TarEntryKind::BlockDevice | TarEntryKind::Fifo
        ) && !special_object_restore_supported(kind))
        || (required_native_profile && !native_source_matches_host);

    if (!requests_system && requests_same_os && unsupported_same_os)
        || (requests_system && unsupported_system)
    {
        if !options.allow_degraded {
            return Err(FormatError::ReaderUnsupported(
                "requested native metadata is not supported by this conformance class",
            ));
        }
        diagnostics.push(
            MetadataDiagnostic::new(
                path,
                native_profile,
                "native-metadata",
                MetadataOperation::Plan,
                MetadataDiagnosticStatus::Skipped,
                "requested native metadata was skipped under explicit degraded restore",
            )
            .for_restore(
                options.restore_policy,
                restore_phase_for_kind(kind, reparse_placeholder),
            ),
        );
    }

    if metadata.file_entry_flags & HAS_NATIVE_METADATA != 0 && !requests_same_os {
        diagnostics.push(
            MetadataDiagnostic::new(
                path,
                native_profile,
                "native-metadata",
                MetadataOperation::Plan,
                MetadataDiagnosticStatus::Skipped,
                "authenticated native metadata is outside the selected restore policy",
            )
            .for_restore(
                options.restore_policy,
                restore_phase_for_kind(kind, reparse_placeholder),
            ),
        );
    }
    if requests_same_os
        && metadata.primary_has_native_scalar
        && !required_native_scalar
        && (native_primary_restore_unsupported(metadata, requests_system)
            || !native_source_matches_host)
    {
        diagnostics.push(
            MetadataDiagnostic::new(
                path,
                native_profile,
                "optional-native-scalar",
                MetadataOperation::Plan,
                MetadataDiagnosticStatus::Skipped,
                "optional native scalar metadata is unsupported on this host",
            )
            .for_restore(
                options.restore_policy,
                restore_phase_for_kind(kind, reparse_placeholder),
            ),
        );
    }
    for record in &metadata.auxiliary {
        let requested = match options.restore_policy {
            RestorePolicy::Content => record.restore_class == RestoreClass::None,
            RestorePolicy::Portable => record.restore_class <= RestoreClass::Portable,
            RestorePolicy::SameOs => record.restore_class <= RestoreClass::SameOs,
            RestorePolicy::System => true,
        };
        if requested
            && record.restore_class != RestoreClass::None
            && !profile_is_required(&record.profile)
        {
            diagnostics.push(
                MetadataDiagnostic::new(
                    path,
                    &record.profile,
                    &record.kind,
                    MetadataOperation::Plan,
                    MetadataDiagnosticStatus::Skipped,
                    "optional auxiliary record is unsupported on this host",
                )
                .for_restore(
                    options.restore_policy,
                    restore_phase_for_kind(kind, reparse_placeholder),
                ),
            );
        } else if !requested && record.restore_class != RestoreClass::None {
            diagnostics.push(
                MetadataDiagnostic::new(
                    path,
                    &record.profile,
                    &record.kind,
                    MetadataOperation::Plan,
                    MetadataDiagnosticStatus::Skipped,
                    "authenticated auxiliary record is outside the selected restore policy",
                )
                .for_restore(
                    options.restore_policy,
                    restore_phase_for_kind(kind, reparse_placeholder),
                ),
            );
        }
    }
    Ok(diagnostics)
}

fn native_auxiliary_restore_supported(
    record: &AuxiliaryRecord,
    include_system: bool,
    kind: Option<TarEntryKind>,
) -> bool {
    if cfg!(target_os = "macos") {
        return match record.kind.as_str() {
            "macos.resource-fork" => {
                record.restore_class == RestoreClass::SameOs
                    && match kind {
                        Some(TarEntryKind::Symlink) => record.logical_size <= u64::from(u32::MAX),
                        Some(TarEntryKind::Regular | TarEntryKind::Directory) | None => true,
                        Some(_) => false,
                    }
            }
            "macos.finder-info" => record.restore_class == RestoreClass::SameOs,
            "macos.acl-native" => {
                record.restore_class == RestoreClass::SameOs
                    && record
                        .meta
                        .get("TZAP.aux.meta.acl-format")
                        .is_some_and(|value| value == b"darwin-acl-external-v1")
            }
            "generic.xattr" => {
                record.restore_class == RestoreClass::SameOs
                    || include_system && record.restore_class == RestoreClass::System
            }
            _ => false,
        };
    }
    if cfg!(target_os = "linux") && record.kind == "generic.xattr" {
        return record.restore_class == RestoreClass::SameOs
            || (include_system && record.restore_class == RestoreClass::System);
    }
    if !cfg!(windows) {
        return false;
    }
    if record.kind == "windows.alternate-data" {
        return record.restore_class == RestoreClass::SameOs
            && record
                .meta
                .get("TZAP.aux.meta.stream-attributes")
                .is_some_and(|value| {
                    value == b"00000000" && record.flags == 0
                        || value == b"00000008" && record.flags == 1
                });
    }
    if matches!(
        record.kind.as_str(),
        "windows.ea-data" | "windows.property-data" | "windows.object-id"
    ) {
        let expected_type = match record.kind.as_str() {
            "windows.ea-data" => b"00000002".as_slice(),
            "windows.property-data" => b"00000006".as_slice(),
            "windows.object-id" => b"00000007".as_slice(),
            _ => unreachable!(),
        };
        return (record.restore_class == RestoreClass::SameOs
            || include_system && record.restore_class == RestoreClass::System)
            && (record.restore_class != RestoreClass::System
                || windows_security_restore_privileges_available(0))
            && record.flags == 0
            && record.name_encoding == "none"
            && record.decoded_name.is_empty()
            && record
                .meta
                .get("TZAP.aux.meta.stream-type")
                .is_some_and(|value| value == expected_type)
            && record
                .meta
                .get("TZAP.aux.meta.stream-attributes")
                .and_then(|value| parse_lower_hex_u32(value, "Windows stream attributes").ok())
                .is_some_and(|attributes| {
                    attributes & !(STREAM_MODIFIED_WHEN_READ | STREAM_CONTAINS_SECURITY) == 0
                        && (record.kind == "windows.object-id"
                            || attributes & STREAM_CONTAINS_SECURITY != 0)
                            == (record.restore_class == RestoreClass::System)
                });
    }
    if !include_system {
        return false;
    }
    if record.kind == "windows.efs-raw" {
        return record.restore_class == RestoreClass::System
            && record
                .meta
                .get("TZAP.aux.meta.efs-version")
                .is_some_and(|value| value == b"1");
    }
    if record.kind == "windows.reparse-data" {
        return record
            .capture_report_payload
            .as_deref()
            .is_some_and(|payload| validate_windows_essential_reparse_data(payload).is_ok());
    }
    if record.kind == "windows.security-descriptor" {
        return record.capture_report_payload.is_some()
            && record
                .meta
                .get("TZAP.aux.meta.security-information")
                .and_then(|value| parse_lower_hex_u32(value, "Windows security information").ok())
                .is_some_and(windows_security_restore_privileges_available);
    }
    false
}

#[cfg(windows)]
fn windows_security_restore_privileges_available(security_information: u32) -> bool {
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, SetLastError, ERROR_SUCCESS};
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, SE_BACKUP_NAME, SE_PRIVILEGE_ENABLED,
        SE_RESTORE_NAME, SE_SECURITY_NAME, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = ptr::null_mut();
    // SAFETY: `token` is a valid output slot and the process pseudo-handle is live.
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
    let enable = |name| {
        let mut privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            ..Default::default()
        };
        // SAFETY: the one-element privilege array provides valid input/output storage.
        if unsafe { LookupPrivilegeValueW(ptr::null(), name, &mut privileges.Privileges[0].Luid) }
            == 0
        {
            return false;
        }
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        unsafe { SetLastError(ERROR_SUCCESS) };
        // SAFETY: `token` is live and the initialized one-entry structure is readable.
        unsafe {
            AdjustTokenPrivileges(token, 0, &privileges, 0, ptr::null_mut(), ptr::null_mut()) != 0
                && GetLastError() == ERROR_SUCCESS
        }
    };
    let available = enable(SE_BACKUP_NAME)
        && enable(SE_RESTORE_NAME)
        && (security_information & 0x0000_0008 == 0 || enable(SE_SECURITY_NAME));
    // SAFETY: `token` was returned by OpenProcessToken and is closed once.
    unsafe { CloseHandle(token) };
    available
}

#[cfg(not(windows))]
fn windows_security_restore_privileges_available(_security_information: u32) -> bool {
    false
}

fn windows_reparse_metadata_supported(metadata: &MemberMetadata) -> bool {
    metadata.declaration.source_os == "windows"
        && metadata
            .auxiliary
            .iter()
            .find(|record| record.kind == "windows.reparse-data")
            .is_some_and(|record| native_auxiliary_restore_supported(record, true, None))
}

fn native_primary_restore_unsupported(metadata: &MemberMetadata, include_system: bool) -> bool {
    metadata.primary_records.keys().any(|key| {
        let native = key.starts_with("TZAP.linux.")
            || key.starts_with("TZAP.macos.")
            || key.starts_with("TZAP.windows.")
            || key.starts_with("TZAP.posix.")
            || key.starts_with("LIBARCHIVE.")
            || key.starts_with("SCHILY.")
            || key == "TZAP.unix.ctime-observed";
        if !native {
            return false;
        }
        if key == "TZAP.unix.ctime-observed" {
            return false;
        }
        if key == "TZAP.linux.fsflags" {
            return linux_inode_flags_restore_unsupported(
                metadata.primary_records.get(key).map(Vec::as_slice),
            );
        }
        if key == "TZAP.linux.project-id" {
            return !cfg!(target_os = "linux") || !include_system;
        }
        if key == "TZAP.linux.whiteout" {
            return !cfg!(target_os = "linux") || !include_system;
        }
        if key.starts_with("TZAP.posix.device-") {
            return !cfg!(any(target_os = "linux", target_os = "macos")) || !include_system;
        }
        if key == "TZAP.windows.file-attributes" {
            if !cfg!(windows) || metadata.declaration.source_os != "windows" {
                return true;
            }
            return metadata
                .primary_records
                .get(key)
                .and_then(|value| parse_lower_hex_u32(value, "Windows file attributes").ok())
                .is_none_or(|attributes| {
                    attributes
                        & !(WINDOWS_ESSENTIAL_SETTABLE_ATTRIBUTES
                            | WINDOWS_ESSENTIAL_INTRINSIC_ATTRIBUTES
                            | FILE_ATTRIBUTE_NORMAL)
                        != 0
                });
        }
        if key == "TZAP.windows.change-time" {
            return !cfg!(windows) || metadata.declaration.source_os != "windows";
        }
        if key == "TZAP.windows.data-stream-attributes" {
            return !cfg!(windows)
                || metadata.declaration.source_os != "windows"
                || metadata
                    .primary_records
                    .get(key)
                    .is_none_or(|value| value != b"00000000" && value != b"00000008");
        }
        if key == "TZAP.windows.reparse-placeholder" {
            return !cfg!(windows)
                || !include_system
                || !windows_reparse_metadata_supported(metadata);
        }
        if key == "TZAP.windows.directory-case-sensitive" {
            return include_system
                && (!cfg!(windows) || metadata.declaration.source_os != "windows");
        }
        if key == "LIBARCHIVE.creationtime" && metadata.declaration.source_os == "windows" {
            return !cfg!(windows);
        }
        if key == "LIBARCHIVE.creationtime" && metadata.declaration.source_os == "macos" {
            return !cfg!(target_os = "macos");
        }
        if key == "TZAP.macos.st-flags" {
            let flags = metadata
                .primary_records
                .get(key)
                .and_then(|value| parse_macos_flags(value).ok());
            return !cfg!(target_os = "macos")
                || metadata.declaration.source_os != "macos"
                || flags.is_none_or(|flags| {
                    if macos_flags_require_system(flags) && !include_system {
                        false
                    } else {
                        !macos_flags_supported(flags)
                            || include_system && !macos_system_flags_privileges_available(flags)
                    }
                });
        }
        if key.starts_with("SCHILY.acl.") || key.starts_with("TZAP.acl.") {
            return !cfg!(target_os = "linux");
        }
        if let Some(encoded_name) = key.strip_prefix("LIBARCHIVE.xattr.") {
            let system = decode_percent_name(encoded_name.as_bytes())
                .ok()
                .is_some_and(|name| system_xattr_name(&name, &metadata.declaration.source_os));
            return !cfg!(unix) && (!system || include_system);
        }
        true
    })
}

#[cfg(target_os = "linux")]
fn linux_inode_flags_restore_unsupported(encoded: Option<&[u8]>) -> bool {
    encoded
        .and_then(|value| std::str::from_utf8(value).ok())
        .and_then(|value| u64::from_str_radix(value, 16).ok())
        .is_none_or(|flags| flags & !LINUX_KNOWN_FSFLAGS != 0)
}

#[cfg(not(target_os = "linux"))]
fn linux_inode_flags_restore_unsupported(_encoded: Option<&[u8]>) -> bool {
    true
}

fn source_os_matches_current_host(source_os: &str) -> bool {
    source_os == current_host_os()
}

#[cfg(target_os = "linux")]
fn current_host_os() -> &'static str {
    "linux"
}

#[cfg(target_os = "macos")]
fn current_host_os() -> &'static str {
    "macos"
}

#[cfg(target_os = "windows")]
fn current_host_os() -> &'static str {
    "windows"
}

#[cfg(target_os = "freebsd")]
fn current_host_os() -> &'static str {
    "freebsd"
}

#[cfg(target_os = "netbsd")]
fn current_host_os() -> &'static str {
    "netbsd"
}

#[cfg(target_os = "openbsd")]
fn current_host_os() -> &'static str {
    "openbsd"
}

#[cfg(target_os = "solaris")]
fn current_host_os() -> &'static str {
    "solaris"
}

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "solaris"
    ))
))]
fn current_host_os() -> &'static str {
    "other-unix"
}

#[cfg(not(any(unix, windows)))]
fn current_host_os() -> &'static str {
    "other"
}

#[cfg(unix)]
fn numeric_ownership_supported(metadata: &MemberMetadata) -> bool {
    metadata
        .portable_mirror
        .uid
        .and_then(|uid| libc::uid_t::try_from(uid).ok())
        .is_some()
        && metadata
            .portable_mirror
            .gid
            .and_then(|gid| libc::gid_t::try_from(gid).ok())
            .is_some()
}

#[cfg(not(unix))]
fn numeric_ownership_supported(_metadata: &MemberMetadata) -> bool {
    false
}

pub(crate) fn metadata_verification_report(
    members: &[TarStreamMemberSummary],
) -> Result<MetadataVerificationReport, FormatError> {
    let mut profiles_present = std::collections::BTreeSet::new();
    let mut auxiliary_kinds_present = std::collections::BTreeSet::new();
    let mut entries = Vec::with_capacity(members.len());

    for member in members {
        let metadata = &member.v45_metadata;
        profiles_present.extend(metadata.declaration.required_profiles.iter().cloned());
        profiles_present.extend(metadata.declaration.optional_profiles.iter().cloned());
        let mut auxiliary_kinds = metadata
            .auxiliary
            .iter()
            .map(|record| record.kind.clone())
            .collect::<Vec<_>>();
        auxiliary_kinds.sort();
        auxiliary_kinds.dedup();
        auxiliary_kinds_present.extend(auxiliary_kinds.iter().cloned());

        let mut policy_capabilities = Vec::with_capacity(4);
        for policy in [
            RestorePolicy::Content,
            RestorePolicy::Portable,
            RestorePolicy::SameOs,
            RestorePolicy::System,
        ] {
            let strict = SafeExtractionOptions {
                restore_policy: policy,
                allow_degraded: false,
                system_authorized: policy == RestorePolicy::System,
                ..SafeExtractionOptions::default()
            };
            let (policy_complete, reason) = match plan_restore(
                &member.path,
                metadata,
                member.kind,
                member.reparse_placeholder,
                strict,
            ) {
                Ok(_) => (true, None),
                Err(FormatError::ReaderUnsupported(reason)) => (false, Some(reason)),
                Err(error) => return Err(error),
            };
            let degraded_restore_available = if policy_complete {
                true
            } else {
                plan_restore(
                    &member.path,
                    metadata,
                    member.kind,
                    member.reparse_placeholder,
                    SafeExtractionOptions {
                        allow_degraded: true,
                        ..strict
                    },
                )
                .is_ok()
            };
            policy_capabilities.push(RestorePolicyCapability {
                policy,
                policy_complete,
                degraded_restore_available,
                reason,
            });
        }

        let mut diagnostics = member.diagnostics.clone();
        diagnostics.extend(plan_restore(
            &member.path,
            metadata,
            member.kind,
            member.reparse_placeholder,
            SafeExtractionOptions {
                allow_degraded: true,
                ..SafeExtractionOptions::default()
            },
        )?);
        let system_complete = policy_capabilities
            .iter()
            .find(|capability| capability.policy == RestorePolicy::System)
            .is_some_and(|capability| capability.policy_complete);
        let full_fidelity_possible = metadata.declaration.capture_status == CaptureStatus::Complete
            && system_complete
            && !diagnostics.iter().any(|diagnostic| {
                matches!(
                    diagnostic.status,
                    MetadataDiagnosticStatus::Materialized
                        | MetadataDiagnosticStatus::Unsupported
                        | MetadataDiagnosticStatus::Failed
                )
            });
        entries.push(EntryMetadataVerification {
            path: member.path.clone(),
            capture_status: metadata.declaration.capture_status,
            required_profiles: metadata.declaration.required_profiles.clone(),
            optional_profiles: metadata.declaration.optional_profiles.clone(),
            auxiliary_kinds,
            policy_capabilities,
            full_fidelity_possible,
            diagnostics,
        });
    }

    Ok(MetadataVerificationReport {
        all_capture_complete: entries
            .iter()
            .all(|entry| entry.capture_status == CaptureStatus::Complete),
        full_fidelity_possible: entries.iter().all(|entry| entry.full_fidelity_possible),
        profiles_present: profiles_present.into_iter().collect(),
        auxiliary_kinds_present: auxiliary_kinds_present.into_iter().collect(),
        entries,
    })
}

struct RegularWriterHandler<'a, W> {
    writer: &'a mut W,
}

impl<W: Write> TarMemberStreamHandler for RegularWriterHandler<'_, W> {
    fn on_member(&mut self, member: &StreamedTarMemberMetadata) -> Result<(), ExtractError> {
        if member.kind != TarEntryKind::Regular || member.reparse_placeholder {
            return Err(FormatError::ReaderUnsupported(
                "extract_file_to_writer returns only regular file payloads",
            )
            .into());
        }
        Ok(())
    }

    fn write_regular_payload(&mut self, bytes: &[u8]) -> Result<(), ExtractError> {
        self.writer.write_all(bytes).map_err(ExtractError::Output)
    }
}

struct FilesystemRestoreHandler<'a> {
    root: &'a Path,
    options: SafeExtractionOptions,
    destination: Option<PreparedDestination>,
    temp_leaf: Option<PathBuf>,
    file: Option<fs::File>,
    skipped_reparse_placeholder: bool,
    skipped_by_policy: bool,
    materialized_hardlink: bool,
    native_sparse_active: bool,
    sparse_logical_size: u64,
    sparse_extents: Vec<SparseExtent>,
    planned_diagnostics: Vec<MetadataDiagnostic>,
    defer_hardlinks: bool,
    deferred_hardlinks: Vec<(Vec<u8>, Vec<u8>)>,
    defer_directories: bool,
    deferred_directories: Vec<(Vec<u8>, MemberMetadata, Vec<StagedAuxiliary>)>,
    #[cfg(windows)]
    deferred_windows_objects: Vec<(Vec<u8>, TarEntryKind, MemberMetadata)>,
    active_auxiliary: Option<StagedAuxiliary>,
    staged_auxiliary: Vec<StagedAuxiliary>,
}

struct StagedAuxiliary {
    record: AuxiliaryRecord,
    file: fs::File,
}

impl<'a> FilesystemRestoreHandler<'a> {
    fn new(root: &'a Path, options: SafeExtractionOptions) -> Self {
        Self {
            root,
            options,
            destination: None,
            temp_leaf: None,
            file: None,
            skipped_reparse_placeholder: false,
            skipped_by_policy: false,
            materialized_hardlink: false,
            native_sparse_active: false,
            sparse_logical_size: 0,
            sparse_extents: Vec::new(),
            planned_diagnostics: Vec::new(),
            defer_hardlinks: false,
            deferred_hardlinks: Vec::new(),
            defer_directories: false,
            deferred_directories: Vec::new(),
            #[cfg(windows)]
            deferred_windows_objects: Vec::new(),
            active_auxiliary: None,
            staged_auxiliary: Vec::new(),
        }
    }

    fn new_deferred(root: &'a Path, options: SafeExtractionOptions) -> Self {
        let mut handler = Self::new(root, options);
        handler.defer_hardlinks = true;
        handler.defer_directories = true;
        handler
    }

    fn finish_archive(&mut self) -> Result<Vec<MetadataDiagnostic>, FormatError> {
        if self.active_auxiliary.is_some() || !self.staged_auxiliary.is_empty() {
            return Err(FormatError::InvalidArchive(
                "native auxiliary payload was not attached to an archive member",
            ));
        }
        let mut diagnostics = Vec::new();
        for (path, target) in std::mem::take(&mut self.deferred_hardlinks) {
            let destination =
                prepare_destination(self.root, &path, TarEntryKind::Hardlink, self.options)?;
            let target_path = existing_safe_regular_path(self.root, &target)?;
            if self.options.restore_policy == RestorePolicy::Content {
                let (temp_leaf, mut output) = create_temp_regular_file(&destination)?;
                let mut input = open_existing_regular_file(&target_path)?;
                if std::io::copy(&mut input, &mut output).is_err() {
                    let _ = destination.parent.remove_file_or_symlink(&temp_leaf);
                    return Err(FormatError::FilesystemExtractionFailed(
                        "failed to materialize hardlink target",
                    ));
                }
                output.flush().map_err(|_| {
                    FormatError::FilesystemExtractionFailed(
                        "failed to write materialized hardlink target",
                    )
                })?;
                publish_regular_file(&destination, &temp_leaf, output, self.options)?;
            } else {
                create_hardlink(&destination, &target_path, self.options)?;
            }
        }
        let mut directories = std::mem::take(&mut self.deferred_directories);
        directories.sort_by(|left, right| {
            right
                .0
                .iter()
                .filter(|byte| **byte == b'/')
                .count()
                .cmp(&left.0.iter().filter(|byte| **byte == b'/').count())
                .then_with(|| left.0.cmp(&right.0))
        });
        if self.options.restore_policy != RestorePolicy::Content {
            for (path, metadata, mut staged) in directories {
                apply_restored_directory_metadata(
                    self.root,
                    &path,
                    &metadata,
                    Some(&mut staged),
                    self.options,
                    &mut diagnostics,
                )?;
                if !staged.is_empty() {
                    return Err(FormatError::InvalidArchive(
                        "native auxiliary payload was not restored for its directory member",
                    ));
                }
            }
        }
        #[cfg(windows)]
        for (path, kind, metadata) in std::mem::take(&mut self.deferred_windows_objects) {
            replay_windows_descendant_metadata(
                self.root,
                &path,
                kind,
                &metadata,
                self.options,
                &mut diagnostics,
            )?;
        }
        Ok(diagnostics)
    }

    fn finish(
        &mut self,
        member: &StreamedTarMemberMetadata,
    ) -> Result<Vec<MetadataDiagnostic>, ExtractError> {
        let mut diagnostics = member.diagnostics.clone();
        for diagnostic in &mut diagnostics {
            if diagnostic.operation == MetadataOperation::Restore
                && diagnostic.restore_policy.is_none()
            {
                diagnostic.restore_policy = Some(self.options.restore_policy);
                diagnostic.restore_phase = Some(restore_phase_for_kind(
                    member.kind,
                    member.reparse_placeholder,
                ));
            }
        }
        diagnostics.append(&mut self.planned_diagnostics);
        if self.skipped_reparse_placeholder || self.skipped_by_policy {
            self.staged_auxiliary.clear();
            return Ok(diagnostics);
        }
        if !matches!(member.kind, TarEntryKind::Regular | TarEntryKind::Directory)
            && !self.staged_auxiliary.is_empty()
        {
            return Err(FormatError::InvalidArchive(
                "native auxiliary payload was not restored for its archive member",
            )
            .into());
        }
        #[cfg(windows)]
        if self.defer_directories
            && self.options.restore_policy == RestorePolicy::System
            && self.options.system_authorized
            && matches!(member.kind, TarEntryKind::Regular | TarEntryKind::Symlink)
        {
            self.deferred_windows_objects.push((
                member.path.clone(),
                member.kind,
                member.v45_metadata.clone(),
            ));
        }
        if member.reparse_placeholder {
            return Ok(diagnostics);
        }
        if member.kind == TarEntryKind::Directory {
            if !self.defer_directories && self.options.restore_policy != RestorePolicy::Content {
                apply_restored_directory_metadata(
                    self.root,
                    &member.path,
                    &member.v45_metadata,
                    Some(&mut self.staged_auxiliary),
                    self.options,
                    &mut diagnostics,
                )?;
                if !self.staged_auxiliary.is_empty() {
                    return Err(FormatError::InvalidArchive(
                        "native auxiliary payload was not restored for its directory member",
                    )
                    .into());
                }
            }
            return Ok(diagnostics);
        }
        if member.kind != TarEntryKind::Regular && !self.materialized_hardlink {
            return Ok(diagnostics);
        }

        let mut file = self.file.take().ok_or(FormatError::InvalidArchive(
            "regular file output is missing",
        ))?;
        file.flush()
            .map_err(|_| FormatError::FilesystemExtractionFailed("failed to write regular file"))?;

        let destination = self.destination.take().ok_or(FormatError::InvalidArchive(
            "regular file destination is missing",
        ))?;
        let temp_leaf = self.temp_leaf.take().ok_or(FormatError::InvalidArchive(
            "regular file temp path is missing",
        ))?;
        let file = match restore_windows_efs_temp(
            &destination,
            &temp_leaf,
            file,
            &mut self.staged_auxiliary,
            self.options,
        ) {
            Ok(file) => file,
            Err(error) => {
                let _ = destination.parent.remove_file_or_symlink(&temp_leaf);
                return Err(error.into());
            }
        };
        let file = publish_regular_file(&destination, &temp_leaf, file, self.options)?;
        if self.options.restore_policy != RestorePolicy::Content {
            if let Err(error) = apply_windows_alternate_streams(
                &file,
                &member.path,
                &mut self.staged_auxiliary,
                self.options,
                &mut diagnostics,
            ) {
                drop(file);
                let _ = destination.parent.remove_file_or_symlink(&destination.leaf);
                return Err(error.into());
            }
            if let Err(error) = apply_restored_regular_file_metadata_parts(
                &file,
                &member.path,
                RestoredRegularMetadata::from(&member.v45_metadata.portable_mirror),
                Some(&member.v45_metadata),
                Some(&mut self.staged_auxiliary),
                self.options,
                &mut diagnostics,
            ) {
                drop(file);
                let _ = destination.parent.remove_file_or_symlink(&destination.leaf);
                return Err(error.into());
            }
            if !self.staged_auxiliary.is_empty() {
                drop(file);
                let _ = destination.parent.remove_file_or_symlink(&destination.leaf);
                return Err(FormatError::InvalidArchive(
                    "native auxiliary payload was not restored for its regular-file member",
                )
                .into());
            }
        }
        Ok(diagnostics)
    }
}

impl Drop for FilesystemRestoreHandler<'_> {
    fn drop(&mut self) {
        if let (Some(destination), Some(temp_leaf)) =
            (self.destination.as_ref(), self.temp_leaf.take())
        {
            let _ = destination.parent.remove_file_or_symlink(temp_leaf);
        }
    }
}

impl TarMemberStreamHandler for FilesystemRestoreHandler<'_> {
    fn begin_auxiliary_payload(&mut self, record: &AuxiliaryRecord) -> Result<bool, ExtractError> {
        if self.active_auxiliary.is_some() {
            return Err(FormatError::InvalidArchive(
                "previous auxiliary payload was not finalized",
            )
            .into());
        }
        let requested = match self.options.restore_policy {
            RestorePolicy::Content | RestorePolicy::Portable => false,
            RestorePolicy::SameOs => record.restore_class <= RestoreClass::SameOs,
            RestorePolicy::System => true,
        };
        if !requested
            || !native_auxiliary_restore_supported(
                record,
                self.options.restore_policy == RestorePolicy::System,
                None,
            )
            || !matches!(
                record.kind.as_str(),
                "windows.alternate-data"
                    | "windows.ea-data"
                    | "windows.property-data"
                    | "windows.object-id"
                    | "windows.efs-raw"
                    | "macos.resource-fork"
                    | "macos.finder-info"
                    | "macos.acl-native"
                    | "generic.xattr"
            )
        {
            return Ok(false);
        }
        let file = tempfile::tempfile().map_err(|_| {
            FormatError::FilesystemExtractionFailed("failed to stage native auxiliary payload")
        })?;
        self.active_auxiliary = Some(StagedAuxiliary {
            record: record.clone(),
            file,
        });
        Ok(true)
    }

    fn write_auxiliary_payload(&mut self, bytes: &[u8]) -> Result<(), ExtractError> {
        self.active_auxiliary
            .as_mut()
            .ok_or(FormatError::InvalidArchive(
                "auxiliary staging output is missing",
            ))?
            .file
            .write_all(bytes)
            .map_err(|_| {
                FormatError::FilesystemExtractionFailed("failed to stage native auxiliary payload")
                    .into()
            })
    }

    fn finish_auxiliary_payload(&mut self, record: &AuxiliaryRecord) -> Result<(), ExtractError> {
        let mut staged = self
            .active_auxiliary
            .take()
            .ok_or(FormatError::InvalidArchive(
                "auxiliary staging output is missing",
            ))?;
        if staged.record.ordinal != record.ordinal || staged.record.kind != record.kind {
            return Err(FormatError::InvalidArchive(
                "staged auxiliary declaration changed during validation",
            )
            .into());
        }
        staged.file.flush().map_err(|_| {
            FormatError::FilesystemExtractionFailed("failed to flush native auxiliary staging")
        })?;
        staged.file.seek(SeekFrom::Start(0)).map_err(|_| {
            FormatError::FilesystemExtractionFailed("failed to rewind native auxiliary staging")
        })?;
        staged.record = record.clone();
        self.staged_auxiliary.push(staged);
        Ok(())
    }

    fn on_member(&mut self, member: &StreamedTarMemberMetadata) -> Result<(), ExtractError> {
        if self.destination.is_some()
            || self.temp_leaf.is_some()
            || self.file.is_some()
            || self.active_auxiliary.is_some()
        {
            return Err(FormatError::InvalidArchive(
                "previous streamed restore member was not finalized",
            )
            .into());
        }
        self.skipped_reparse_placeholder = false;
        self.skipped_by_policy = false;
        self.materialized_hardlink = false;
        self.native_sparse_active = false;
        self.sparse_logical_size = 0;
        self.sparse_extents.clear();
        self.planned_diagnostics.clear();
        self.planned_diagnostics = plan_restore(
            &member.path,
            &member.v45_metadata,
            member.kind,
            member.reparse_placeholder,
            self.options,
        )?;
        self.staged_auxiliary.retain(|item| {
            native_auxiliary_restore_supported(
                &item.record,
                self.options.restore_policy == RestorePolicy::System,
                Some(member.kind),
            )
        });
        let restore_exact_windows_reparse = cfg!(windows)
            && self.options.restore_policy == RestorePolicy::System
            && self.options.system_authorized
            && windows_reparse_metadata_supported(&member.v45_metadata);
        if member.reparse_placeholder && !restore_exact_windows_reparse {
            self.skipped_reparse_placeholder = true;
            return Ok(());
        }
        if member.kind == TarEntryKind::Symlink
            && self.options.restore_policy == RestorePolicy::Content
        {
            self.skipped_by_policy = true;
            return Ok(());
        }
        let restore_posix_special = cfg!(any(target_os = "linux", target_os = "macos"))
            && self.options.restore_policy == RestorePolicy::System
            && self.options.system_authorized;
        if matches!(
            member.kind,
            TarEntryKind::CharacterDevice | TarEntryKind::BlockDevice | TarEntryKind::Fifo
        ) && !restore_posix_special
        {
            self.skipped_by_policy = true;
            return Ok(());
        }
        let destination = prepare_destination(self.root, &member.path, member.kind, self.options)?;
        match member.kind {
            TarEntryKind::Regular => {
                if member.reparse_placeholder {
                    #[cfg(windows)]
                    {
                        create_windows_reparse_object(
                            &destination,
                            &member.path,
                            member.kind,
                            &member.v45_metadata,
                            &mut self.staged_auxiliary,
                            self.options,
                            &mut self.planned_diagnostics,
                        )?;
                        if !self.staged_auxiliary.is_empty() {
                            let reparse = open_existing_windows_reparse(&destination)?;
                            apply_windows_alternate_streams(
                                &reparse,
                                &member.path,
                                &mut self.staged_auxiliary,
                                self.options,
                                &mut self.planned_diagnostics,
                            )?;
                        }
                    }
                    #[cfg(not(windows))]
                    unreachable!("exact Windows reparse restore is Windows-only");
                } else {
                    let (temp_leaf, file) = create_temp_regular_file(&destination)?;
                    self.destination = Some(destination);
                    self.temp_leaf = Some(temp_leaf);
                    self.file = Some(file);
                }
            }
            TarEntryKind::Directory => {
                if member.reparse_placeholder {
                    #[cfg(windows)]
                    create_windows_reparse_object(
                        &destination,
                        &member.path,
                        member.kind,
                        &member.v45_metadata,
                        &mut self.staged_auxiliary,
                        self.options,
                        &mut self.planned_diagnostics,
                    )?;
                    #[cfg(not(windows))]
                    unreachable!("exact Windows reparse restore is Windows-only");
                } else {
                    create_directory(&destination)?;
                }
                #[cfg(windows)]
                if !self.staged_auxiliary.is_empty() {
                    let directory = if member.reparse_placeholder {
                        open_existing_windows_reparse(&destination)?
                    } else {
                        open_existing_directory(&destination)?
                    };
                    apply_generic_xattr_auxiliaries(
                        &directory,
                        &member.path,
                        &mut self.staged_auxiliary,
                        self.options,
                        &mut self.planned_diagnostics,
                    )?;
                    apply_windows_alternate_streams(
                        &directory,
                        &member.path,
                        &mut self.staged_auxiliary,
                        self.options,
                        &mut self.planned_diagnostics,
                    )?;
                }
                if self.defer_directories {
                    self.deferred_directories.push((
                        member.path.clone(),
                        member.v45_metadata.clone(),
                        std::mem::take(&mut self.staged_auxiliary),
                    ));
                }
            }
            TarEntryKind::Symlink => {
                let target = member
                    .link_target
                    .as_deref()
                    .ok_or(FormatError::InvalidArchive("symlink target is missing"))?;
                validate_symlink_target(&member.path, target)?;
                if restore_exact_windows_reparse {
                    #[cfg(windows)]
                    create_windows_reparse_object(
                        &destination,
                        &member.path,
                        member.kind,
                        &member.v45_metadata,
                        &mut self.staged_auxiliary,
                        self.options,
                        &mut self.planned_diagnostics,
                    )?;
                    #[cfg(not(windows))]
                    unreachable!("exact Windows reparse restore is Windows-only");
                } else {
                    create_symlink(&destination, target, self.options)?;
                    let result = (|| {
                        if !self.staged_auxiliary.is_empty() {
                            #[cfg(windows)]
                            {
                                let reparse = open_existing_windows_reparse(&destination)?;
                                apply_windows_alternate_streams(
                                    &reparse,
                                    &member.path,
                                    &mut self.staged_auxiliary,
                                    self.options,
                                    &mut self.planned_diagnostics,
                                )?;
                            }
                            #[cfg(all(
                                not(windows),
                                not(target_os = "linux"),
                                not(target_os = "macos")
                            ))]
                            self.staged_auxiliary.clear();
                        }
                        if self.options.restore_policy != RestorePolicy::Content {
                            apply_restored_linux_symlink_metadata(
                                &destination,
                                &member.path,
                                &member.v45_metadata,
                                self.options,
                                &mut self.planned_diagnostics,
                            )?;
                            #[cfg(target_os = "linux")]
                            if !self.staged_auxiliary.is_empty() {
                                let mut proc_path = PathBuf::from(format!(
                                    "/proc/self/fd/{}",
                                    destination.parent.as_raw_fd()
                                ));
                                proc_path.push(&destination.leaf);
                                apply_generic_xattr_auxiliaries_to_path(
                                    &proc_path,
                                    false,
                                    &member.path,
                                    &mut self.staged_auxiliary,
                                    self.options,
                                    &mut self.planned_diagnostics,
                                )?;
                            }
                            apply_restored_macos_symlink_metadata(
                                &destination,
                                &member.path,
                                &member.v45_metadata,
                                &mut self.staged_auxiliary,
                                self.options,
                                &mut self.planned_diagnostics,
                            )?;
                            if member.v45_metadata.declaration.source_os != "macos"
                                || !matches!(
                                    self.options.restore_policy,
                                    RestorePolicy::SameOs | RestorePolicy::System
                                )
                            {
                                apply_restored_symlink_mtime(
                                    &destination,
                                    &member.path,
                                    member.v45_metadata.portable_mirror.mtime,
                                    self.options,
                                    &mut self.planned_diagnostics,
                                )?;
                            }
                        }
                        #[cfg(windows)]
                        if member.v45_metadata.declaration.source_os == "windows"
                            && matches!(
                                self.options.restore_policy,
                                RestorePolicy::SameOs | RestorePolicy::System
                            )
                        {
                            let reparse = open_existing_windows_reparse(&destination)?;
                            apply_windows_basic_metadata(
                                &reparse,
                                &member.path,
                                &member.v45_metadata,
                                self.options,
                                &mut self.planned_diagnostics,
                            )?;
                        }
                        Ok(())
                    })();
                    if let Err(error) = result {
                        let _ = destination.parent.remove_file_or_symlink(&destination.leaf);
                        return Err(error);
                    }
                }
            }
            TarEntryKind::Hardlink => {
                let target = member
                    .link_target
                    .as_deref()
                    .ok_or(FormatError::InvalidArchive("hardlink target is missing"))?;
                if self.defer_hardlinks {
                    self.deferred_hardlinks
                        .push((member.path.clone(), target.to_vec()));
                    self.skipped_by_policy = true;
                    if self.options.restore_policy == RestorePolicy::Content {
                        self.planned_diagnostics.push(
                            MetadataDiagnostic::new(
                                &member.path,
                                "portable-v1",
                                "hardlink-topology",
                                MetadataOperation::Restore,
                                MetadataDiagnosticStatus::Materialized,
                                "hardlink topology was materialized by content restore policy",
                            )
                            .for_restore(self.options.restore_policy, 3),
                        );
                    }
                    return Ok(());
                }
                let target_path = existing_safe_regular_path(self.root, target)?;
                if self.options.restore_policy == RestorePolicy::Content {
                    let (temp_leaf, mut output) = create_temp_regular_file(&destination)?;
                    let mut input = open_existing_regular_file(&target_path)?;
                    let materialized_bytes =
                        std::io::copy(&mut input, &mut output).map_err(|_| {
                            FormatError::FilesystemExtractionFailed(
                                "failed to materialize hardlink target",
                            )
                        })?;
                    self.destination = Some(destination);
                    self.temp_leaf = Some(temp_leaf);
                    self.file = Some(output);
                    self.materialized_hardlink = true;
                    self.planned_diagnostics.push(
                        MetadataDiagnostic::new(
                            &member.path,
                            "portable-v1",
                            "hardlink-topology",
                            MetadataOperation::Restore,
                            MetadataDiagnosticStatus::Materialized,
                            "hardlink topology was materialized by content restore policy",
                        )
                        .for_restore(self.options.restore_policy, 3)
                        .with_bytes(materialized_bytes, materialized_bytes),
                    );
                } else {
                    create_hardlink(&destination, &target_path, self.options)?;
                }
            }
            TarEntryKind::CharacterDevice | TarEntryKind::BlockDevice | TarEntryKind::Fifo => {
                if self.options.restore_policy != RestorePolicy::System {
                    return Ok(());
                }
                if let Err(error) = create_posix_special_object(
                    &destination,
                    &member.path,
                    member.kind,
                    &member.v45_metadata,
                    &mut self.staged_auxiliary,
                    self.options,
                    &mut self.planned_diagnostics,
                ) {
                    let _ = destination.parent.remove_file_or_symlink(&destination.leaf);
                    return Err(error.into());
                }
            }
        }
        Ok(())
    }

    fn write_regular_payload(&mut self, bytes: &[u8]) -> Result<(), ExtractError> {
        let file = self.file.as_mut().ok_or(FormatError::InvalidArchive(
            "regular file output is missing",
        ))?;
        file.write_all(bytes)
            .map_err(|_| FormatError::FilesystemExtractionFailed("failed to write regular file"))?;
        Ok(())
    }

    fn begin_sparse_payload(
        &mut self,
        logical_size: u64,
        extents: &[SparseExtent],
    ) -> Result<bool, ExtractError> {
        #[cfg(windows)]
        {
            if self.options.restore_policy == RestorePolicy::Content {
                return Ok(false);
            }
            let file = self.file.as_mut().ok_or(FormatError::InvalidArchive(
                "regular file output is missing",
            ))?;
            prepare_windows_sparse_file(file, logical_size)?;
            self.native_sparse_active = true;
            self.sparse_logical_size = logical_size;
            self.sparse_extents = extents.to_vec();
            Ok(true)
        }
        #[cfg(target_os = "linux")]
        {
            let file = self.file.as_mut().ok_or(FormatError::InvalidArchive(
                "regular file output is missing",
            ))?;
            file.set_len(logical_size).map_err(|_| {
                FormatError::FilesystemExtractionFailed(
                    "failed to set Linux sparse output logical size",
                )
            })?;
            self.native_sparse_active = true;
            self.sparse_logical_size = logical_size;
            self.sparse_extents = extents.to_vec();
            Ok(true)
        }
        #[cfg(all(not(windows), not(target_os = "linux")))]
        {
            let _ = (logical_size, extents);
            Ok(false)
        }
    }

    fn write_sparse_extent(&mut self, offset: u64, bytes: &[u8]) -> Result<(), ExtractError> {
        if !self.native_sparse_active {
            return Err(FormatError::InvalidArchive("sparse output was not initialized").into());
        }
        let file = self.file.as_mut().ok_or(FormatError::InvalidArchive(
            "regular file output is missing",
        ))?;
        file.seek(SeekFrom::Start(offset)).map_err(|_| {
            FormatError::FilesystemExtractionFailed("failed to seek sparse output extent")
        })?;
        file.write_all(bytes).map_err(|_| {
            FormatError::FilesystemExtractionFailed("failed to write sparse output extent")
        })?;
        Ok(())
    }

    fn finish_sparse_payload(&mut self) -> Result<(), ExtractError> {
        if !self.native_sparse_active {
            return Ok(());
        }
        let file = self.file.as_mut().ok_or(FormatError::InvalidArchive(
            "regular file output is missing",
        ))?;
        file.flush().map_err(|_| {
            FormatError::FilesystemExtractionFailed("failed to flush sparse output")
        })?;
        if file
            .metadata()
            .map_err(|_| {
                FormatError::FilesystemExtractionFailed("failed to inspect sparse output")
            })?
            .len()
            != self.sparse_logical_size
        {
            return Err(FormatError::FilesystemExtractionFailed(
                "sparse output logical size does not match archive",
            )
            .into());
        }
        #[cfg(windows)]
        verify_windows_sparse_file(file, self.sparse_logical_size, &self.sparse_extents)?;
        #[cfg(target_os = "linux")]
        punch_linux_sparse_holes(file, self.sparse_logical_size, &self.sparse_extents)?;
        self.native_sparse_active = false;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn punch_linux_sparse_holes(
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

fn format_error_from_extract_error(error: ExtractError) -> FormatError {
    match error {
        ExtractError::Format(error) => error,
        ExtractError::Output(_) => {
            FormatError::FilesystemExtractionFailed("failed to write regular file")
        }
    }
}

fn read_member_bytes<R: TarMemberGroupReader>(
    reader: &mut R,
    buf: &mut [u8],
    remaining: &mut u64,
) -> Result<(), ExtractError> {
    if buf.len() as u64 > *remaining {
        return Err(FormatError::InvalidArchive("tar member payload exceeds group").into());
    }
    reader.read_exact_member_bytes(buf)?;
    *remaining -= buf.len() as u64;
    Ok(())
}

fn read_member_vec<R: TarMemberGroupReader>(
    reader: &mut R,
    len: u64,
    remaining: &mut u64,
) -> Result<Vec<u8>, ExtractError> {
    let mut out = vec![0u8; to_usize(len)?];
    read_member_bytes(reader, &mut out, remaining)?;
    Ok(out)
}

fn read_zero_padding<R: TarMemberGroupReader>(
    reader: &mut R,
    len: u64,
    remaining: &mut u64,
) -> Result<(), ExtractError> {
    let mut pending = len;
    let mut buf = [0u8; 8192];
    while pending > 0 {
        let chunk_len = pending.min(buf.len() as u64) as usize;
        read_member_bytes(reader, &mut buf[..chunk_len], remaining)?;
        if buf[..chunk_len].iter().any(|byte| *byte != 0) {
            return Err(FormatError::InvalidArchive("tar member padding is non-zero").into());
        }
        pending -= chunk_len as u64;
    }
    Ok(())
}

fn stream_regular_payload<R, H>(
    reader: &mut R,
    len: u64,
    remaining: &mut u64,
    handler: &mut H,
) -> Result<(), ExtractError>
where
    R: TarMemberGroupReader,
    H: TarMemberStreamHandler,
{
    let mut pending = len;
    let mut buf = [0u8; 64 * 1024];
    while pending > 0 {
        let chunk_len = pending.min(buf.len() as u64).min(*remaining) as usize;
        let read = reader.read_some_member_bytes(&mut buf[..chunk_len])?;
        if read == 0 {
            return Err(FormatError::InvalidArchive("tar member group exceeds frame range").into());
        }
        *remaining -= read as u64;
        pending -= read as u64;
        handler.write_regular_payload(&buf[..read])?;
    }
    Ok(())
}

fn stream_auxiliary_payload<R: TarMemberGroupReader, H: TarMemberStreamHandler>(
    reader: &mut R,
    len: u64,
    remaining: &mut u64,
    validator: &mut AuxiliaryStreamValidator,
    mut handler: Option<&mut H>,
) -> Result<(), ExtractError> {
    let mut pending = len;
    let mut buf = [0u8; 64 * 1024];
    while pending > 0 {
        let chunk_len = pending.min(buf.len() as u64).min(*remaining) as usize;
        let read = reader.read_some_member_bytes(&mut buf[..chunk_len])?;
        if read == 0 {
            return Err(FormatError::InvalidArchive("tar member group exceeds frame range").into());
        }
        *remaining -= read as u64;
        pending -= read as u64;
        validator.observe(&buf[..read])?;
        if let Some(handler) = handler.as_deref_mut() {
            handler.write_auxiliary_payload(&buf[..read])?;
        }
    }
    Ok(())
}

fn stream_sparse_primary_payload<R, H>(
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

fn tar_member_group_end(stream: &[u8], start: usize) -> Result<usize, FormatError> {
    try_tar_member_group_end(stream, start)?.ok_or(FormatError::InvalidArchive(
        "tar member payload exceeds stream",
    ))
}

#[cfg(test)]
fn restore_tar_member(
    root: &Path,
    member: &OwnedTarMember,
    options: SafeExtractionOptions,
) -> Result<Vec<MetadataDiagnostic>, FormatError> {
    let mut diagnostics = member.diagnostics.clone();
    if let Some(metadata) = &member.v45_metadata {
        diagnostics.extend(plan_restore(
            &member.path,
            metadata,
            member.kind,
            member.reparse_placeholder,
            options,
        )?);
    }
    if member.reparse_placeholder {
        diagnostics.push(
            MetadataDiagnostic::new(
                &member.path,
                "windows-backup-v1",
                "reparse-data",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Skipped,
                "reparse placeholder skipped by portable restore policy",
            )
            .for_restore(options.restore_policy, 3),
        );
        return Ok(diagnostics);
    }
    if member.kind == TarEntryKind::Symlink && options.restore_policy == RestorePolicy::Content {
        return Ok(diagnostics);
    }
    if matches!(
        member.kind,
        TarEntryKind::CharacterDevice | TarEntryKind::BlockDevice | TarEntryKind::Fifo
    ) {
        diagnostics.push(
            MetadataDiagnostic::new(
                &member.path,
                "posix-backup-v1",
                "special-object",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Skipped,
                "special object skipped by portable restore policy",
            )
            .for_restore(
                options.restore_policy,
                restore_phase_for_kind(member.kind, member.reparse_placeholder),
            ),
        );
        return Ok(diagnostics);
    }
    let destination = prepare_destination(root, &member.path, member.kind, options)?;
    match member.kind {
        TarEntryKind::Regular => {
            let (temp_leaf, mut file) = create_temp_regular_file(&destination)?;
            file.write_all(&member.data).map_err(|_| {
                FormatError::FilesystemExtractionFailed("failed to write regular file")
            })?;
            file.flush().map_err(|_| {
                FormatError::FilesystemExtractionFailed("failed to write regular file")
            })?;
            let file = publish_regular_file(&destination, &temp_leaf, file, options)?;
            if options.restore_policy != RestorePolicy::Content {
                if let Err(error) =
                    apply_restored_regular_file_metadata(&file, member, options, &mut diagnostics)
                {
                    drop(file);
                    let _ = destination.parent.remove_file_or_symlink(&destination.leaf);
                    return Err(error);
                }
            }
        }
        TarEntryKind::Directory => {
            create_directory(&destination)?;
            if options.restore_policy != RestorePolicy::Content {
                let metadata = member
                    .v45_metadata
                    .as_ref()
                    .ok_or(FormatError::InvalidArchive(
                        "revision-45 member metadata is missing",
                    ))?;
                apply_restored_directory_metadata(
                    root,
                    &member.path,
                    metadata,
                    None,
                    options,
                    &mut diagnostics,
                )?;
            }
        }
        TarEntryKind::Symlink => {
            let target = member
                .link_target
                .as_deref()
                .ok_or(FormatError::InvalidArchive("symlink target is missing"))?;
            validate_symlink_target(&member.path, target)?;
            create_symlink(&destination, target, options)?;
            if options.restore_policy != RestorePolicy::Content {
                let metadata = member
                    .v45_metadata
                    .as_ref()
                    .ok_or(FormatError::InvalidArchive(
                        "revision-45 member metadata is missing",
                    ))?;
                apply_restored_linux_symlink_metadata(
                    &destination,
                    &member.path,
                    metadata,
                    options,
                    &mut diagnostics,
                )?;
                let mut staged = Vec::new();
                apply_restored_macos_symlink_metadata(
                    &destination,
                    &member.path,
                    metadata,
                    &mut staged,
                    options,
                    &mut diagnostics,
                )?;
                if metadata.declaration.source_os != "macos"
                    || !matches!(
                        options.restore_policy,
                        RestorePolicy::SameOs | RestorePolicy::System
                    )
                {
                    apply_restored_symlink_mtime(
                        &destination,
                        &member.path,
                        metadata.portable_mirror.mtime,
                        options,
                        &mut diagnostics,
                    )?;
                }
            }
        }
        TarEntryKind::Hardlink => {
            let target = member
                .link_target
                .as_deref()
                .ok_or(FormatError::InvalidArchive("hardlink target is missing"))?;
            let target_path = existing_safe_regular_path(root, target)?;
            if options.restore_policy == RestorePolicy::Content {
                let (temp_leaf, mut output) = create_temp_regular_file(&destination)?;
                let mut input = open_existing_regular_file(&target_path)?;
                let materialized_bytes = std::io::copy(&mut input, &mut output).map_err(|_| {
                    FormatError::FilesystemExtractionFailed("failed to materialize hardlink target")
                })?;
                output.flush().map_err(|_| {
                    FormatError::FilesystemExtractionFailed("failed to materialize hardlink target")
                })?;
                publish_regular_file(&destination, &temp_leaf, output, options)?;
                diagnostics.push(
                    MetadataDiagnostic::new(
                        &member.path,
                        "portable-v1",
                        "hardlink-topology",
                        MetadataOperation::Restore,
                        MetadataDiagnosticStatus::Materialized,
                        "hardlink topology was materialized by content restore policy",
                    )
                    .for_restore(options.restore_policy, 3)
                    .with_bytes(materialized_bytes, materialized_bytes),
                );
            } else {
                create_hardlink(&destination, &target_path, options)?;
            }
        }
        TarEntryKind::CharacterDevice | TarEntryKind::BlockDevice | TarEntryKind::Fifo => {
            unreachable!("special objects return before destination preparation")
        }
    }
    Ok(diagnostics)
}

pub(crate) fn restore_regular_file_metadata_to_open_file(
    file: &fs::File,
    member: &OwnedTarMember,
    options: SafeExtractionOptions,
) -> Result<Vec<MetadataDiagnostic>, FormatError> {
    if member.kind != TarEntryKind::Regular {
        return Err(FormatError::ReaderUnsupported(
            "open-file metadata restore requires a regular archive member",
        ));
    }
    let metadata = member
        .v45_metadata
        .as_ref()
        .ok_or(FormatError::InvalidArchive(
            "revision-45 member metadata is missing",
        ))?;
    let mut diagnostics = plan_owned_member_restore(member, options)?;
    if options.restore_policy != RestorePolicy::Content {
        apply_restored_regular_file_metadata_parts(
            file,
            &member.path,
            RestoredRegularMetadata::from(&metadata.portable_mirror),
            Some(metadata),
            None,
            options,
            &mut diagnostics,
        )?;
    }
    Ok(diagnostics)
}

#[cfg(test)]
fn apply_restored_regular_file_metadata(
    file: &fs::File,
    member: &OwnedTarMember,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    if member.v45_metadata.is_some() {
        diagnostics.extend(restore_regular_file_metadata_to_open_file(
            file, member, options,
        )?);
        return Ok(());
    }
    apply_restored_regular_file_metadata_parts(
        file,
        &member.path,
        RestoredRegularMetadata {
            mode: member.mode,
            mtime: (member.mtime.seconds, member.mtime.nanoseconds),
            attributes: None,
            mode_origin_native: false,
            uid: None,
            gid: None,
        },
        None,
        None,
        options,
        diagnostics,
    )
}

#[derive(Clone, Copy)]
struct RestoredRegularMetadata {
    mode: u32,
    mtime: (i64, u32),
    attributes: Option<u32>,
    mode_origin_native: bool,
    uid: Option<u64>,
    gid: Option<u64>,
}

impl From<&PortableMetadataMirror> for RestoredRegularMetadata {
    fn from(metadata: &PortableMetadataMirror) -> Self {
        Self {
            mode: metadata.mode,
            mtime: metadata.mtime,
            attributes: metadata.attributes,
            mode_origin_native: metadata.mode_origin_native,
            uid: metadata.uid,
            gid: metadata.gid,
        }
    }
}

fn apply_restored_regular_file_metadata_parts(
    file: &fs::File,
    path: &[u8],
    metadata: RestoredRegularMetadata,
    member_metadata: Option<&MemberMetadata>,
    staged_auxiliary: Option<&mut Vec<StagedAuxiliary>>,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    let RestoredRegularMetadata {
        mode,
        mtime,
        attributes,
        mode_origin_native,
        uid,
        gid,
    } = metadata;
    apply_regular_file_ownership(file, path, uid, gid, options, diagnostics)?;
    let mode = if options.restore_policy == RestorePolicy::System && options.system_authorized {
        mode
    } else {
        mode & !0o6000
    };
    apply_regular_file_mode(file, path, mode, mode_origin_native, options, diagnostics)?;
    if let Some(member_metadata) = member_metadata {
        apply_regular_file_posix_acl(file, path, member_metadata, options, diagnostics)?;
        if let Some(staged) = staged_auxiliary {
            apply_macos_native_metadata(file, path, member_metadata, staged, options, diagnostics)?;
            apply_generic_xattr_auxiliaries(file, path, staged, options, diagnostics)?;
        }
        apply_regular_file_xattrs(file, path, member_metadata, options, diagnostics)?;
    }
    if member_metadata.is_some_and(|metadata| {
        metadata.declaration.source_os == "macos"
            && matches!(
                options.restore_policy,
                RestorePolicy::SameOs | RestorePolicy::System
            )
    }) {
        apply_macos_file_timestamps(
            file,
            path,
            member_metadata.unwrap(),
            mtime,
            options,
            diagnostics,
        )?;
    } else {
        apply_regular_file_mtime(file, path, mtime, options, diagnostics)?;
    }
    apply_regular_file_attributes(file, path, attributes, options, diagnostics)?;
    if let Some(member_metadata) = member_metadata {
        apply_windows_security_descriptor(file, path, member_metadata, options, diagnostics)?;
        apply_windows_basic_metadata(file, path, member_metadata, options, diagnostics)?;
        apply_linux_project_id(file, path, member_metadata, options, diagnostics)?;
        apply_linux_inode_flags(file, path, member_metadata, options, diagnostics)?;
        apply_macos_file_flags(file, path, member_metadata, options, diagnostics)?;
    }
    Ok(())
}

#[cfg(windows)]
struct WindowsAlternateStreamRollback {
    paths: Vec<Vec<u16>>,
    committed: bool,
}

#[cfg(windows)]
impl Drop for WindowsAlternateStreamRollback {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        use windows_sys::Win32::Storage::FileSystem::DeleteFileW;
        for path in self.paths.iter().rev() {
            // SAFETY: every path is retained as a NUL-terminated UTF-16 buffer until this call.
            unsafe {
                DeleteFileW(path.as_ptr());
            }
        }
    }
}

#[cfg(windows)]
struct WindowsRawEfsContext(*mut std::ffi::c_void);

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
fn windows_final_path(file: &fs::File, description: &'static str) -> Result<Vec<u16>, FormatError> {
    use windows_sys::Win32::Storage::FileSystem::{
        GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED, VOLUME_NAME_DOS,
    };

    let handle = file.as_raw_handle().cast();
    // SAFETY: the handle is live; the zero-length query returns the required UTF-16 count.
    let required = unsafe {
        GetFinalPathNameByHandleW(
            handle,
            std::ptr::null_mut(),
            0,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
        )
    };
    if required == 0 {
        return Err(FormatError::FilesystemExtractionFailed(description));
    }
    let mut path = vec![0u16; required as usize + 1];
    // SAFETY: `path` provides the queried capacity and remains writable for the call.
    let written = unsafe {
        GetFinalPathNameByHandleW(
            handle,
            path.as_mut_ptr(),
            path.len() as u32,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
        )
    };
    if written == 0 || written as usize >= path.len() {
        return Err(FormatError::FilesystemExtractionFailed(description));
    }
    path.truncate(written as usize);
    path.push(0);
    Ok(path)
}

#[cfg(windows)]
fn open_windows_raw_efs(path: &[u16], flags: u32) -> Result<WindowsRawEfsContext, FormatError> {
    use windows_sys::Win32::Storage::FileSystem::OpenEncryptedFileRawW;

    let mut context = std::ptr::null_mut();
    // SAFETY: `path` is NUL-terminated and `context` is a writable output slot.
    let status = unsafe { OpenEncryptedFileRawW(path.as_ptr(), flags, &mut context) };
    if status != 0 {
        return Err(FormatError::FilesystemExtractionFailed(
            "failed to open Windows raw EFS stream",
        ));
    }
    Ok(WindowsRawEfsContext(context))
}

#[cfg(windows)]
struct WindowsRawEfsImport<'a> {
    file: &'a mut fs::File,
    bytes: u64,
    error: Option<std::io::Error>,
}

#[cfg(windows)]
unsafe extern "system" fn windows_raw_efs_import_callback(
    buffer: *mut u8,
    context: *const std::ffi::c_void,
    length: *mut u32,
) -> u32 {
    use windows_sys::Win32::Foundation::{ERROR_READ_FAULT, ERROR_SUCCESS};

    if buffer.is_null() || context.is_null() || length.is_null() {
        return ERROR_READ_FAULT;
    }
    // SAFETY: WriteEncryptedFileRaw passes back the context pointer supplied by the caller for
    // the duration of the synchronous call, and provides a writable buffer of `*length` bytes.
    let state = unsafe { &mut *context.cast_mut().cast::<WindowsRawEfsImport<'_>>() };
    let requested = unsafe { *length } as usize;
    let output = unsafe { std::slice::from_raw_parts_mut(buffer, requested) };
    match state.file.read(output) {
        Ok(count) => {
            unsafe { *length = count as u32 };
            state.bytes = state.bytes.saturating_add(count as u64);
            ERROR_SUCCESS
        }
        Err(error) => {
            state.error = Some(error);
            unsafe { *length = 0 };
            ERROR_READ_FAULT
        }
    }
}

#[cfg(windows)]
struct WindowsRawEfsDigest {
    hasher: sha2::Sha256,
    bytes: u64,
}

#[cfg(windows)]
unsafe extern "system" fn windows_raw_efs_digest_callback(
    bytes: *const u8,
    context: *const std::ffi::c_void,
    length: u32,
) -> u32 {
    use windows_sys::Win32::Foundation::{ERROR_READ_FAULT, ERROR_SUCCESS};

    if length == 0 {
        return ERROR_SUCCESS;
    }
    if context.is_null() || bytes.is_null() {
        return ERROR_READ_FAULT;
    }
    // SAFETY: ReadEncryptedFileRaw passes back the context pointer supplied by the caller and a
    // readable byte range for the duration of this synchronous callback.
    let state = unsafe { &mut *context.cast_mut().cast::<WindowsRawEfsDigest>() };
    let input = unsafe { std::slice::from_raw_parts(bytes, length as usize) };
    sha2::Digest::update(&mut state.hasher, input);
    state.bytes = state.bytes.saturating_add(length as u64);
    ERROR_SUCCESS
}

#[cfg(windows)]
fn verify_windows_raw_efs(path: &[u16], record: &AuxiliaryRecord) -> Result<(), FormatError> {
    use sha2::Digest as _;
    use windows_sys::Win32::Storage::FileSystem::ReadEncryptedFileRaw;

    let context = open_windows_raw_efs(path, 0)?;
    let mut digest = WindowsRawEfsDigest {
        hasher: sha2::Sha256::new(),
        bytes: 0,
    };
    // SAFETY: the callback and its stack context remain live for this synchronous export.
    let status = unsafe {
        ReadEncryptedFileRaw(
            Some(windows_raw_efs_digest_callback),
            (&mut digest as *mut WindowsRawEfsDigest).cast(),
            context.0,
        )
    };
    if status != 0 {
        return Err(FormatError::FilesystemExtractionFailed(
            "failed to verify restored Windows raw EFS stream",
        ));
    }
    if digest.bytes != record.stored_size || digest.hasher.finalize().as_slice() != record.sha256 {
        return Err(FormatError::FilesystemExtractionFailed(
            "restored Windows raw EFS stream did not verify",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn restore_windows_efs_temp(
    destination: &PreparedDestination,
    temp_leaf: &Path,
    mut output: fs::File,
    staged: &mut Vec<StagedAuxiliary>,
    options: SafeExtractionOptions,
) -> Result<fs::File, FormatError> {
    use std::os::windows::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::WriteEncryptedFileRaw;
    use windows_sys::Win32::System::WindowsProgramming::CREATE_FOR_IMPORT;

    let Some(index) = staged
        .iter()
        .position(|item| item.record.kind == "windows.efs-raw")
    else {
        return Ok(output);
    };
    if options.restore_policy != RestorePolicy::System || !options.system_authorized {
        return Err(FormatError::FilesystemExtractionFailed(
            "Windows raw EFS restoration requires authorized system policy",
        ));
    }
    output.flush().map_err(|_| {
        FormatError::FilesystemExtractionFailed("failed to flush Windows raw EFS temporary file")
    })?;
    let raw_path = windows_final_path(&output, "failed to resolve Windows raw EFS temporary file")?;
    drop(output);
    destination
        .parent
        .remove_file_or_symlink(temp_leaf)
        .map_err(|_| {
            FormatError::FilesystemExtractionFailed(
                "failed to replace temporary file with Windows raw EFS data",
            )
        })?;

    let StagedAuxiliary {
        record,
        file: mut staged_file,
    } = staged.remove(index);
    let staged_len = staged_file
        .metadata()
        .map_err(|_| {
            FormatError::FilesystemExtractionFailed("failed to inspect staged Windows raw EFS data")
        })?
        .len();
    if staged_len != record.stored_size {
        return Err(FormatError::InvalidArchive(
            "staged Windows raw EFS size is inconsistent",
        ));
    }
    staged_file.seek(SeekFrom::Start(0)).map_err(|_| {
        FormatError::FilesystemExtractionFailed("failed to rewind staged Windows raw EFS data")
    })?;

    let context = open_windows_raw_efs(&raw_path, CREATE_FOR_IMPORT)?;
    let mut import = WindowsRawEfsImport {
        file: &mut staged_file,
        bytes: 0,
        error: None,
    };
    // SAFETY: the callback, staged file, and callback context remain live for this synchronous
    // import, and `context` is an import context returned for the resolved temporary path.
    let status = unsafe {
        WriteEncryptedFileRaw(
            Some(windows_raw_efs_import_callback),
            (&mut import as *mut WindowsRawEfsImport<'_>).cast(),
            context.0,
        )
    };
    if status != 0 || import.error.is_some() || import.bytes != record.stored_size {
        return Err(FormatError::FilesystemExtractionFailed(
            "failed to restore Windows raw EFS data",
        ));
    }
    drop(context);
    verify_windows_raw_efs(&raw_path, &record)?;

    let mut reopen = CapOpenOptions::new();
    reopen
        .read(true)
        .write(true)
        .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .follow(FollowSymlinks::No);
    let output = destination
        .parent
        .open_with(temp_leaf, &reopen)
        .map(cap_std::fs::File::into_std)
        .map_err(|_| {
            FormatError::FilesystemExtractionFailed(
                "failed to reopen restored Windows raw EFS temporary file",
            )
        })?;
    let metadata = output.metadata().map_err(|_| {
        FormatError::FilesystemExtractionFailed("failed to inspect restored Windows raw EFS file")
    })?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_ENCRYPTED == 0
    {
        return Err(FormatError::FilesystemExtractionFailed(
            "restored Windows raw EFS file is not encrypted",
        ));
    }
    Ok(output)
}

#[cfg(not(windows))]
fn restore_windows_efs_temp(
    _destination: &PreparedDestination,
    _temp_leaf: &Path,
    output: fs::File,
    staged: &mut [StagedAuxiliary],
    _options: SafeExtractionOptions,
) -> Result<fs::File, FormatError> {
    if staged
        .iter()
        .any(|item| item.record.kind == "windows.efs-raw")
    {
        return Err(FormatError::FilesystemExtractionFailed(
            "Windows raw EFS restore is unavailable on this host",
        ));
    }
    Ok(output)
}

#[cfg(windows)]
fn apply_windows_alternate_streams(
    base_file: &fs::File,
    path: &[u8],
    staged: &mut Vec<StagedAuxiliary>,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    use std::os::windows::io::FromRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, GetFinalPathNameByHandleW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL,
        FILE_NAME_NORMALIZED, VOLUME_NAME_DOS,
    };

    if staged.is_empty() {
        return Ok(());
    }
    if !matches!(
        options.restore_policy,
        RestorePolicy::SameOs | RestorePolicy::System
    ) {
        staged.clear();
        return Ok(());
    }
    let handle = base_file.as_raw_handle().cast();
    // SAFETY: the handle is live; the zero-length query returns the required UTF-16 count.
    let required = unsafe {
        GetFinalPathNameByHandleW(
            handle,
            std::ptr::null_mut(),
            0,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
        )
    };
    if required == 0 {
        return Err(FormatError::FilesystemExtractionFailed(
            "failed to resolve restored object for alternate-stream creation",
        ));
    }
    let mut base_path = vec![0u16; required as usize + 1];
    // SAFETY: `base_path` provides the queried capacity and remains writable for the call.
    let written = unsafe {
        GetFinalPathNameByHandleW(
            handle,
            base_path.as_mut_ptr(),
            base_path.len() as u32,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
        )
    };
    if written == 0 || written as usize >= base_path.len() {
        return Err(FormatError::FilesystemExtractionFailed(
            "failed to resolve restored object for alternate-stream creation",
        ));
    }
    base_path.truncate(written as usize);
    let mut rollback = WindowsAlternateStreamRollback {
        paths: Vec::new(),
        committed: false,
    };

    for staged_record in std::mem::take(staged) {
        let StagedAuxiliary { record, mut file } = staged_record;
        if record.kind != "windows.alternate-data" {
            restore_windows_backup_metadata_stream(
                base_file,
                path,
                &record,
                &mut file,
                options,
                diagnostics,
            )?;
            continue;
        }
        if record.decoded_name.len() % 2 != 0 {
            return Err(FormatError::InvalidArchive(
                "Windows alternate stream name is not UTF-16LE",
            ));
        }
        let stream_name = record
            .decoded_name
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        let mut stream_path = Vec::with_capacity(base_path.len() + stream_name.len() + 1);
        stream_path.extend_from_slice(&base_path);
        stream_path.extend_from_slice(&stream_name);
        stream_path.push(0);
        // SAFETY: the base path comes from the pinned destination handle and the suffix passed
        // built-in UTF-16 alternate-stream grammar validation during archive parsing.
        let stream_handle = unsafe {
            CreateFileW(
                stream_path.as_ptr(),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        if stream_handle.is_null() || stream_handle as isize == -1 {
            let error = std::io::Error::last_os_error();
            return record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    "windows-backup-v1",
                    "alternate-data",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    "failed to create Windows alternate data stream",
                )
                .for_restore(options.restore_policy, 2)
                .with_native_error(&error),
                options,
                "failed to create Windows alternate data stream",
            );
        }
        // SAFETY: ownership of the newly created handle transfers to `stream` exactly once.
        let mut stream = unsafe { fs::File::from_raw_handle(stream_handle.cast()) };
        rollback.paths.push(stream_path);
        restore_windows_alternate_stream_payload(&mut file, &mut stream, &record)?;
    }
    rollback.committed = true;
    Ok(())
}

#[cfg(windows)]
fn restore_windows_backup_metadata_stream(
    base_file: &fs::File,
    path: &[u8],
    record: &AuxiliaryRecord,
    payload: &mut fs::File,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::ptr;
    use windows_sys::Win32::Storage::FileSystem::{
        BackupWrite, ReOpenFile, FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let stream_type = record
        .meta
        .get("TZAP.aux.meta.stream-type")
        .ok_or(FormatError::InvalidArchive(
            "Windows backup metadata stream type is missing",
        ))
        .and_then(|value| parse_lower_hex_u32(value, "Windows backup stream type"))?;
    let stream_attributes = record
        .meta
        .get("TZAP.aux.meta.stream-attributes")
        .ok_or(FormatError::InvalidArchive(
            "Windows backup metadata stream attributes are missing",
        ))
        .and_then(|value| parse_lower_hex_u32(value, "Windows backup stream attributes"))?;
    let expected_type = match record.kind.as_str() {
        "windows.ea-data" => 2,
        "windows.property-data" => 6,
        "windows.object-id" => 7,
        _ => {
            return Err(FormatError::InvalidArchive(
                "staged Windows backup metadata stream has unsupported framing",
            ));
        }
    };
    if stream_type != expected_type
        || record.flags != 0
        || record.logical_size != record.stored_size
        || !record.decoded_name.is_empty()
    {
        return Err(FormatError::InvalidArchive(
            "Windows backup metadata stream declaration is inconsistent",
        ));
    }
    if record.kind == "windows.object-id" {
        return restore_windows_object_id(base_file, path, record, payload, options, diagnostics);
    }
    // SAFETY: the source handle is live; the returned handle, if valid, receives independent
    // ownership and is converted to `File` exactly once.
    let reopened = unsafe {
        ReOpenFile(
            base_file.as_raw_handle().cast(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_FLAG_BACKUP_SEMANTICS,
        )
    };
    if reopened.is_null() || reopened as isize == -1 {
        let error = std::io::Error::last_os_error();
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "windows-backup-v1",
                &record.kind,
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to reopen Windows object for backup-stream restoration",
            )
            .for_restore(options.restore_policy, 2)
            .with_native_error(&error),
            options,
            "failed to reopen Windows object for backup-stream restoration",
        );
    }
    // SAFETY: ownership of the newly reopened handle transfers to `destination` once.
    let destination = unsafe { fs::File::from_raw_handle(reopened.cast()) };
    let mut context = ptr::null_mut();
    let signed_size = i64::try_from(record.logical_size).map_err(|_| {
        FormatError::ReaderUnsupported("Windows backup metadata stream exceeds i64")
    })?;
    let mut header = [0u8; 20];
    header[0..4].copy_from_slice(&stream_type.to_le_bytes());
    header[4..8].copy_from_slice(&stream_attributes.to_le_bytes());
    header[8..16].copy_from_slice(&signed_size.to_le_bytes());
    let result = (|| {
        windows_backup_write_all(&destination, &mut context, &header)?;
        payload.seek(SeekFrom::Start(0)).map_err(|_| {
            FormatError::FilesystemExtractionFailed(
                "failed to rewind staged Windows backup metadata stream",
            )
        })?;
        let mut buffer = [0u8; 64 * 1024];
        let mut remaining = record.logical_size;
        while remaining != 0 {
            let count = buffer
                .len()
                .min(usize::try_from(remaining).unwrap_or(usize::MAX));
            payload.read_exact(&mut buffer[..count]).map_err(|_| {
                FormatError::FilesystemExtractionFailed(
                    "staged Windows backup metadata stream ended early",
                )
            })?;
            windows_backup_write_all(&destination, &mut context, &buffer[..count])?;
            remaining -= count as u64;
        }
        Ok(())
    })();
    let mut ignored = 0u32;
    // SAFETY: aborting with an empty buffer releases exactly this BackupWrite context.
    let abort_ok = unsafe {
        BackupWrite(
            destination.as_raw_handle().cast(),
            ptr::null(),
            0,
            &mut ignored,
            1,
            0,
            &mut context,
        )
    } != 0;
    let result = if result.is_ok() && !abort_ok {
        Err(FormatError::FilesystemExtractionFailed(
            "failed to finalize Windows backup metadata stream restoration",
        ))
    } else {
        result
    };
    match result {
        Ok(()) => Ok(()),
        Err(error @ FormatError::FilesystemExtractionFailed(_)) => {
            record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    "windows-backup-v1",
                    &record.kind,
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    error.to_string(),
                )
                .for_restore(options.restore_policy, 2),
                options,
                "failed to restore Windows backup metadata stream",
            )
        }
        Err(error) => Err(error),
    }
}

#[cfg(windows)]
fn restore_windows_object_id(
    destination: &fs::File,
    path: &[u8],
    record: &AuxiliaryRecord,
    payload: &mut fs::File,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    use std::mem::size_of;
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
    use windows_sys::Win32::Storage::FileSystem::{
        ReOpenFile, FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    use windows_sys::Win32::System::Ioctl::{
        FILE_OBJECTID_BUFFER, FSCTL_GET_OBJECT_ID, FSCTL_SET_OBJECT_ID,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;

    let size = size_of::<FILE_OBJECTID_BUFFER>();
    if record.logical_size != size as u64 {
        return Err(FormatError::InvalidArchive(
            "Windows object-ID backup stream is not exactly 64 bytes",
        ));
    }
    let mut desired = FILE_OBJECTID_BUFFER::default();
    payload.seek(SeekFrom::Start(0)).map_err(|_| {
        FormatError::FilesystemExtractionFailed("failed to rewind staged Windows object ID")
    })?;
    {
        // SAFETY: `desired` is live and writable, and the slice covers exactly its object
        // representation so the authenticated 64-byte stream can be copied without alignment loss.
        let desired_bytes = unsafe {
            std::slice::from_raw_parts_mut(
                (&mut desired as *mut FILE_OBJECTID_BUFFER).cast::<u8>(),
                size,
            )
        };
        payload.read_exact(desired_bytes).map_err(|_| {
            FormatError::FilesystemExtractionFailed("staged Windows object ID ended early")
        })?;
    }

    let reopened_handle = unsafe {
        ReOpenFile(
            destination.as_raw_handle().cast(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_FLAG_BACKUP_SEMANTICS,
        )
    };
    if reopened_handle.is_null() || reopened_handle as isize == -1 {
        let error = std::io::Error::last_os_error();
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "windows-backup-v1",
                &record.kind,
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to reopen Windows object for object-ID restoration",
            )
            .for_restore(options.restore_policy, 2)
            .with_native_error(&error),
            options,
            "failed to reopen Windows object for object-ID restoration",
        );
    }
    let reopened = unsafe { fs::File::from_raw_handle(reopened_handle.cast()) };

    let mut returned = 0u32;
    // SAFETY: the destination handle is live and `desired` is a fully initialized fixed-size
    // FILE_OBJECTID_BUFFER retained for the duration of this synchronous control request.
    let set_ok = unsafe {
        DeviceIoControl(
            reopened.as_raw_handle().cast(),
            FSCTL_SET_OBJECT_ID,
            (&mut desired as *mut FILE_OBJECTID_BUFFER).cast(),
            size as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    } != 0;
    let set_error = (!set_ok).then(std::io::Error::last_os_error);
    let mut actual = FILE_OBJECTID_BUFFER::default();
    returned = 0;
    // SAFETY: the destination handle and writable `actual` output buffer remain live for this
    // synchronous request, with the exact structure size supplied to the kernel.
    let get_ok = unsafe {
        DeviceIoControl(
            reopened.as_raw_handle().cast(),
            FSCTL_GET_OBJECT_ID,
            std::ptr::null(),
            0,
            (&mut actual as *mut FILE_OBJECTID_BUFFER).cast(),
            size as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    } != 0;
    // SAFETY: both initialized structures remain live and are viewed over their exact object
    // representations solely for byte-for-byte verification.
    let actual_bytes = unsafe {
        std::slice::from_raw_parts((&actual as *const FILE_OBJECTID_BUFFER).cast::<u8>(), size)
    };
    let desired_bytes = unsafe {
        std::slice::from_raw_parts((&desired as *const FILE_OBJECTID_BUFFER).cast::<u8>(), size)
    };
    if get_ok && returned as usize == size && actual_bytes == desired_bytes {
        return Ok(());
    }
    let error = set_error.unwrap_or_else(std::io::Error::last_os_error);
    record_metadata_application_failure(
        diagnostics,
        MetadataDiagnostic::new(
            path,
            "windows-backup-v1",
            "windows.object-id",
            MetadataOperation::Restore,
            MetadataDiagnosticStatus::Failed,
            "failed to restore and verify Windows object ID",
        )
        .for_restore(options.restore_policy, 2)
        .with_native_error(&error),
        options,
        "failed to restore and verify Windows object ID",
    )
}

#[cfg(windows)]
fn windows_backup_write_all(
    destination: &fs::File,
    context: &mut *mut std::ffi::c_void,
    mut bytes: &[u8],
) -> Result<(), FormatError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::BackupWrite;

    while !bytes.is_empty() {
        let count = bytes.len().min(u32::MAX as usize);
        let mut written = 0u32;
        // SAFETY: the destination and context are live, and the input slice is readable for the
        // exact requested byte count during this synchronous call.
        if unsafe {
            BackupWrite(
                destination.as_raw_handle().cast(),
                bytes.as_ptr(),
                count as u32,
                &mut written,
                0,
                0,
                context,
            )
        } == 0
        {
            return Err(FormatError::FilesystemExtractionFailed(
                "failed to restore Windows backup metadata stream",
            ));
        }
        if written == 0 || written as usize > count {
            return Err(FormatError::FilesystemExtractionFailed(
                "Windows BackupWrite made no progress",
            ));
        }
        bytes = &bytes[written as usize..];
    }
    Ok(())
}

#[cfg(windows)]
fn restore_windows_alternate_stream_payload(
    staged: &mut fs::File,
    stream: &mut fs::File,
    record: &AuxiliaryRecord,
) -> Result<(), FormatError> {
    let sparse_layout = record.sparse_layout.as_ref();
    let extents = sparse_layout.map(|layout| layout.extents.as_slice());
    let extent_bytes = extents
        .unwrap_or_default()
        .iter()
        .try_fold(0u64, |sum, extent| sum.checked_add(extent.length))
        .ok_or(FormatError::InvalidArchive(
            "sparse Windows alternate stream extent size overflow",
        ))?;
    let data_offset = if let Some(extents) = extents {
        let map_size = sparse_layout
            .expect("sparse extents require a layout")
            .map_and_padding_size as u64;
        if map_size.checked_add(extent_bytes) != Some(record.stored_size) {
            return Err(FormatError::InvalidArchive(
                "sparse Windows alternate stream stored size is inconsistent",
            ));
        }
        prepare_windows_sparse_file(stream, record.logical_size)?;
        staged.seek(SeekFrom::Start(map_size)).map_err(|_| {
            FormatError::FilesystemExtractionFailed("failed to seek staged sparse alternate stream")
        })?;
        for extent in extents {
            stream.seek(SeekFrom::Start(extent.offset)).map_err(|_| {
                FormatError::FilesystemExtractionFailed("failed to seek sparse alternate stream")
            })?;
            copy_exact_bytes(
                staged,
                stream,
                extent.length,
                "Windows sparse alternate stream",
            )?;
        }
        map_size
    } else {
        staged.seek(SeekFrom::Start(0)).map_err(|_| {
            FormatError::FilesystemExtractionFailed("failed to rewind staged alternate stream")
        })?;
        copy_exact_bytes(
            staged,
            stream,
            record.logical_size,
            "Windows alternate stream",
        )?;
        0
    };
    stream.flush().map_err(|_| {
        FormatError::FilesystemExtractionFailed("failed to flush Windows alternate stream")
    })?;
    if stream
        .metadata()
        .map_err(|_| {
            FormatError::FilesystemExtractionFailed("failed to inspect Windows alternate stream")
        })?
        .len()
        != record.logical_size
    {
        return Err(FormatError::FilesystemExtractionFailed(
            "Windows alternate stream logical size did not verify",
        ));
    }
    if let Some(extents) = extents {
        let actual_extents = query_windows_sparse_ranges(stream, record.logical_size)?;
        if actual_extents != extents && !windows_file_system_is_refs(stream)? {
            return Err(FormatError::FilesystemExtractionFailed(
                "Windows sparse alternate stream ranges did not verify",
            ));
        }
    }
    staged.seek(SeekFrom::Start(data_offset)).map_err(|_| {
        FormatError::FilesystemExtractionFailed("failed to rewind staged alternate stream data")
    })?;
    if let Some(extents) = extents {
        for extent in extents {
            stream.seek(SeekFrom::Start(extent.offset)).map_err(|_| {
                FormatError::FilesystemExtractionFailed(
                    "failed to seek restored sparse alternate stream",
                )
            })?;
            compare_exact_bytes(
                staged,
                stream,
                extent.length,
                "Windows sparse alternate stream",
            )?;
        }
    } else {
        stream.seek(SeekFrom::Start(0)).map_err(|_| {
            FormatError::FilesystemExtractionFailed("failed to rewind Windows alternate stream")
        })?;
        compare_exact_bytes(
            staged,
            stream,
            record.logical_size,
            "Windows alternate stream",
        )?;
    }
    Ok(())
}

#[cfg(windows)]
fn copy_exact_bytes(
    input: &mut fs::File,
    output: &mut fs::File,
    mut remaining: u64,
    description: &'static str,
) -> Result<(), FormatError> {
    let mut buffer = [0u8; 64 * 1024];
    while remaining > 0 {
        let count = buffer
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        input.read_exact(&mut buffer[..count]).map_err(|_| {
            FormatError::FilesystemExtractionFailed("staged auxiliary payload ended early")
        })?;
        output
            .write_all(&buffer[..count])
            .map_err(|_| FormatError::FilesystemExtractionFailed(description))?;
        remaining -= count as u64;
    }
    Ok(())
}

#[cfg(windows)]
fn compare_exact_bytes(
    expected: &mut fs::File,
    actual: &mut fs::File,
    mut remaining: u64,
    description: &'static str,
) -> Result<(), FormatError> {
    let mut expected_buffer = [0u8; 64 * 1024];
    let mut actual_buffer = [0u8; 64 * 1024];
    while remaining > 0 {
        let count = expected_buffer
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        expected
            .read_exact(&mut expected_buffer[..count])
            .map_err(|_| {
                FormatError::FilesystemExtractionFailed("failed to read staged auxiliary payload")
            })?;
        actual
            .read_exact(&mut actual_buffer[..count])
            .map_err(|_| {
                FormatError::FilesystemExtractionFailed("failed to read restored auxiliary payload")
            })?;
        if expected_buffer[..count] != actual_buffer[..count] {
            return Err(FormatError::FilesystemExtractionFailed(description));
        }
        remaining -= count as u64;
    }
    Ok(())
}

#[cfg(unix)]
fn apply_generic_xattr_auxiliaries(
    base_file: &fs::File,
    path: &[u8],
    staged: &mut Vec<StagedAuxiliary>,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use xattr::FileExt as _;

    let mut remaining = Vec::new();
    for mut item in std::mem::take(staged) {
        if item.record.kind != "generic.xattr" {
            remaining.push(item);
            continue;
        }
        if item.record.restore_class == RestoreClass::System
            && !(options.restore_policy == RestorePolicy::System && options.system_authorized)
        {
            continue;
        }
        item.file.seek(SeekFrom::Start(0)).map_err(|_| {
            FormatError::FilesystemExtractionFailed("failed to rewind staged extended attribute")
        })?;
        let value_len = usize::try_from(item.record.logical_size).map_err(|_| {
            FormatError::ReaderUnsupported("extended attribute exceeds platform limits")
        })?;
        let mut value = vec![0u8; value_len];
        item.file.read_exact(&mut value).map_err(|_| {
            FormatError::FilesystemExtractionFailed("failed to read staged extended attribute")
        })?;
        let name = OsStr::from_bytes(&item.record.decoded_name);
        if let Err(error) = base_file.set_xattr(name, &value) {
            record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    &item.record.profile,
                    "extended-attribute",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    "failed to apply auxiliary extended attribute",
                )
                .for_restore(options.restore_policy, 4)
                .with_native_error(&error),
                options,
                "failed to apply auxiliary extended attribute",
            )?;
            continue;
        }
        if base_file.get_xattr(name).ok().flatten().as_deref() != Some(value.as_slice()) {
            record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    &item.record.profile,
                    "extended-attribute",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    "auxiliary extended attribute did not verify after restoration",
                )
                .for_restore(options.restore_policy, 4),
                options,
                "auxiliary extended attribute did not verify after restoration",
            )?;
        }
    }
    *staged = remaining;
    Ok(())
}

#[cfg(target_os = "macos")]
fn open_macos_resource_fork(file: &fs::File, write: bool) -> std::io::Result<fs::File> {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt as _;
    use std::os::unix::fs::MetadataExt as _;

    let mut path = vec![0u8; libc::PATH_MAX as usize];
    // SAFETY: `path` is writable for PATH_MAX bytes and F_GETPATH writes a NUL-terminated path.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, path.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let length = path.iter().position(|byte| *byte == 0).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "macOS returned an unterminated descriptor path",
        )
    })?;
    path.truncate(length);
    path.extend_from_slice(b"/..namedfork/rsrc");
    let path = PathBuf::from(OsString::from_vec(path));
    let mut options = fs::OpenOptions::new();
    options.read(true);
    if write {
        options.write(true).truncate(true).create(true);
    }
    let fork = options.open(path)?;
    let owner = file.metadata()?;
    let fork_metadata = fork.metadata()?;
    #[allow(clippy::unnecessary_cast)]
    if owner.dev() != fork_metadata.dev() || owner.ino() != fork_metadata.ino() {
        return Err(std::io::Error::other(
            "resource fork path no longer identifies the pinned file",
        ));
    }
    Ok(fork)
}

#[cfg(target_os = "macos")]
fn apply_macos_native_metadata(
    file: &fs::File,
    path: &[u8],
    metadata: &MemberMetadata,
    staged: &mut Vec<StagedAuxiliary>,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    use std::ffi::{c_int, c_void, OsStr};
    use std::os::unix::ffi::OsStrExt as _;
    use xattr::FileExt as _;

    if metadata.declaration.source_os != "macos"
        || !matches!(
            options.restore_policy,
            RestorePolicy::SameOs | RestorePolicy::System
        )
    {
        return Ok(());
    }

    extern "C" {
        fn acl_copy_int(buffer: *const c_void) -> *mut c_void;
        fn acl_copy_ext(
            buffer: *mut c_void,
            acl: *mut c_void,
            size: libc::ssize_t,
        ) -> libc::ssize_t;
        fn acl_size(acl: *mut c_void) -> libc::ssize_t;
        fn acl_set_fd_np(fd: c_int, acl: *mut c_void, acl_type: c_int) -> c_int;
        fn acl_get_fd_np(fd: c_int, acl_type: c_int) -> *mut c_void;
        fn acl_free(object: *mut c_void) -> c_int;
    }

    const ACL_TYPE_EXTENDED: c_int = 0x0000_0100;

    let fail = |diagnostics: &mut Vec<MetadataDiagnostic>,
                class: &'static str,
                message: &'static str,
                error: Option<&std::io::Error>| {
        let mut diagnostic = MetadataDiagnostic::new(
            path,
            "macos-backup-v1",
            class,
            MetadataOperation::Restore,
            MetadataDiagnosticStatus::Failed,
            message,
        )
        .for_restore(options.restore_policy, 4);
        if let Some(error) = error {
            diagnostic = diagnostic.with_native_error(error);
        }
        record_metadata_application_failure(diagnostics, diagnostic, options, message)
    };

    let mut items = std::mem::take(staged);
    items.sort_by_key(|item| match item.record.kind.as_str() {
        "macos.resource-fork" => 0,
        "macos.acl-native" => 1,
        "macos.finder-info" => 2,
        _ => 3,
    });
    let mut remaining = Vec::new();
    for mut item in items {
        match item.record.kind.as_str() {
            "macos.finder-info" => {
                if item.record.logical_size != 32 {
                    return Err(FormatError::InvalidArchive(
                        "macOS FinderInfo is not exactly 32 bytes",
                    ));
                }
                let mut value = [0u8; 32];
                item.file.seek(SeekFrom::Start(0)).map_err(|_| {
                    FormatError::FilesystemExtractionFailed(
                        "failed to rewind staged macOS FinderInfo",
                    )
                })?;
                item.file.read_exact(&mut value).map_err(|_| {
                    FormatError::FilesystemExtractionFailed(
                        "failed to read staged macOS FinderInfo",
                    )
                })?;
                let name = OsStr::from_bytes(b"com.apple.FinderInfo");
                if let Err(error) = file.set_xattr(name, &value) {
                    fail(
                        diagnostics,
                        "finder-info",
                        "failed to apply macOS FinderInfo",
                        Some(&error),
                    )?;
                } else if file.get_xattr(name).ok().flatten().as_deref() != Some(value.as_slice()) {
                    fail(
                        diagnostics,
                        "finder-info",
                        "macOS FinderInfo did not verify after restoration",
                        None,
                    )?;
                }
            }
            "macos.resource-fork" => {
                item.file.seek(SeekFrom::Start(0)).map_err(|_| {
                    FormatError::FilesystemExtractionFailed(
                        "failed to rewind staged macOS resource fork",
                    )
                })?;
                let mut fork = match open_macos_resource_fork(file, true) {
                    Ok(fork) => fork,
                    Err(error) => {
                        fail(
                            diagnostics,
                            "resource-fork",
                            "failed to open macOS resource fork",
                            Some(&error),
                        )?;
                        continue;
                    }
                };
                if std::io::copy(&mut item.file, &mut fork)
                    .ok()
                    .is_none_or(|copied| copied != item.record.logical_size)
                    || fork.sync_all().is_err()
                {
                    fail(
                        diagnostics,
                        "resource-fork",
                        "failed to write macOS resource fork",
                        None,
                    )?;
                } else {
                    drop(fork);
                    let mut fork = open_macos_resource_fork(file, false).map_err(|_| {
                        FormatError::FilesystemExtractionFailed(
                            "failed to reopen macOS resource fork for verification",
                        )
                    })?;
                    item.file.seek(SeekFrom::Start(0)).map_err(|_| {
                        FormatError::FilesystemExtractionFailed(
                            "failed to rewind staged macOS resource fork",
                        )
                    })?;
                    let mut expected = vec![0u8; 1024 * 1024];
                    let mut actual = vec![0u8; 1024 * 1024];
                    let mut remaining = item.record.logical_size;
                    let mut verified = true;
                    while remaining > 0 {
                        let count = expected
                            .len()
                            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
                        if item.file.read_exact(&mut expected[..count]).is_err()
                            || fork.read_exact(&mut actual[..count]).is_err()
                            || expected[..count] != actual[..count]
                        {
                            verified = false;
                            break;
                        }
                        remaining -= count as u64;
                    }
                    let mut trailing = [0u8; 1];
                    if verified && fork.read(&mut trailing).ok() != Some(0) {
                        verified = false;
                    }
                    if !verified {
                        fail(
                            diagnostics,
                            "resource-fork",
                            "macOS resource fork content did not verify after restoration",
                            None,
                        )?;
                    }
                }
            }
            "macos.acl-native" => {
                let size = usize::try_from(item.record.logical_size).map_err(|_| {
                    FormatError::ReaderUnsupported("macOS ACL exceeds platform limits")
                })?;
                let mut value = vec![0u8; size];
                item.file.seek(SeekFrom::Start(0)).map_err(|_| {
                    FormatError::FilesystemExtractionFailed("failed to rewind staged macOS ACL")
                })?;
                item.file.read_exact(&mut value).map_err(|_| {
                    FormatError::FilesystemExtractionFailed("failed to read staged macOS ACL")
                })?;
                validate_darwin_acl_external(&value)?;
                // SAFETY: the external form was structurally bounded above; returned ACLs are freed.
                let acl = unsafe { acl_copy_int(value.as_ptr().cast()) };
                if acl.is_null() || unsafe { acl_size(acl) } != size as libc::ssize_t {
                    if !acl.is_null() {
                        unsafe { acl_free(acl) };
                    }
                    return Err(FormatError::InvalidArchive(
                        "macOS ACL external form is invalid",
                    ));
                }
                if unsafe { acl_set_fd_np(file.as_raw_fd(), acl, ACL_TYPE_EXTENDED) } != 0 {
                    let error = std::io::Error::last_os_error();
                    unsafe { acl_free(acl) };
                    fail(
                        diagnostics,
                        "acl-native",
                        "failed to apply native macOS ACL",
                        Some(&error),
                    )?;
                    continue;
                }
                unsafe { acl_free(acl) };
                let restored = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
                if restored.is_null() || unsafe { acl_size(restored) } != size as libc::ssize_t {
                    if !restored.is_null() {
                        unsafe { acl_free(restored) };
                    }
                    fail(
                        diagnostics,
                        "acl-native",
                        "native macOS ACL did not verify after restoration",
                        None,
                    )?;
                    continue;
                }
                let mut actual = vec![0u8; size];
                let copied = unsafe {
                    acl_copy_ext(actual.as_mut_ptr().cast(), restored, size as libc::ssize_t)
                };
                unsafe { acl_free(restored) };
                if copied != size as libc::ssize_t || actual != value {
                    fail(
                        diagnostics,
                        "acl-native",
                        "native macOS ACL did not verify after restoration",
                        None,
                    )?;
                }
            }
            _ => remaining.push(item),
        }
    }
    *staged = remaining;

    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn apply_macos_native_metadata(
    _file: &fs::File,
    _path: &[u8],
    _metadata: &MemberMetadata,
    _staged: &mut Vec<StagedAuxiliary>,
    _options: SafeExtractionOptions,
    _diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    Ok(())
}

#[cfg(target_os = "macos")]
fn apply_macos_file_timestamps(
    file: &fs::File,
    path: &[u8],
    metadata: &MemberMetadata,
    mtime: (i64, u32),
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    use std::ffi::{c_int, c_void};
    use std::os::macos::fs::MetadataExt as _;

    #[repr(C)]
    struct AttrList {
        bitmap_count: u16,
        reserved: u16,
        common_attr: u32,
        volume_attr: u32,
        directory_attr: u32,
        file_attr: u32,
        fork_attr: u32,
    }
    extern "C" {
        fn fsetattrlist(
            fd: c_int,
            attributes: *const c_void,
            buffer: *const c_void,
            size: usize,
            options: u32,
        ) -> c_int;
    }
    let mut common_attr = 0x0000_0400;
    let mut times = Vec::<libc::timespec>::new();
    let creation_time = metadata
        .primary_records
        .get("LIBARCHIVE.creationtime")
        .map(|encoded| parse_timestamp(encoded))
        .transpose()?;
    if let Some((seconds, nanoseconds)) = creation_time {
        common_attr |= 0x0000_0200;
        times.push(libc::timespec {
            tv_sec: seconds,
            tv_nsec: i64::from(nanoseconds),
        });
    }
    times.push(libc::timespec {
        tv_sec: mtime.0,
        tv_nsec: i64::from(mtime.1),
    });
    let attributes = AttrList {
        bitmap_count: 5,
        reserved: 0,
        common_attr,
        volume_attr: 0,
        directory_attr: 0,
        file_attr: 0,
        fork_attr: 0,
    };
    if unsafe {
        fsetattrlist(
            file.as_raw_fd(),
            (&attributes as *const AttrList).cast(),
            times.as_ptr().cast(),
            times.len() * std::mem::size_of::<libc::timespec>(),
            0,
        )
    } != 0
    {
        let error = std::io::Error::last_os_error();
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "macos-backup-v1",
                "timestamps",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to apply macOS timestamps",
            )
            .for_restore(options.restore_policy, 4)
            .with_native_error(&error),
            options,
            "failed to apply macOS timestamps",
        );
    }
    let actual = file.metadata().map_err(|_| {
        FormatError::FilesystemExtractionFailed("failed to inspect restored macOS timestamps")
    })?;
    if (actual.st_mtime(), actual.st_mtime_nsec() as u32) != mtime
        || creation_time.is_some_and(|creation| {
            (actual.st_birthtime(), actual.st_birthtime_nsec() as u32) != creation
        })
    {
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "macos-backup-v1",
                "timestamps",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "macOS timestamps did not verify after restoration",
            )
            .for_restore(options.restore_policy, 4),
            options,
            "macOS timestamps did not verify after restoration",
        );
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn apply_macos_file_timestamps(
    _file: &fs::File,
    _path: &[u8],
    _metadata: &MemberMetadata,
    _mtime: (i64, u32),
    _options: SafeExtractionOptions,
    _diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    Ok(())
}

#[cfg(target_os = "macos")]
fn apply_macos_file_flags(
    file: &fs::File,
    path: &[u8],
    metadata: &MemberMetadata,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    use std::os::macos::fs::MetadataExt as _;

    if metadata.declaration.source_os != "macos"
        || !matches!(
            options.restore_policy,
            RestorePolicy::SameOs | RestorePolicy::System
        )
    {
        return Ok(());
    }
    let Some(encoded) = metadata.primary_records.get("TZAP.macos.st-flags") else {
        return Ok(());
    };
    let desired = parse_macos_flags(encoded)? & MACOS_KNOWN_SETTABLE_FLAGS;
    if macos_flags_require_system(desired)
        && !(options.restore_policy == RestorePolicy::System && options.system_authorized)
    {
        return Ok(());
    }
    let retained_unknown = file
        .metadata()
        .map(|value| value.st_flags() & !MACOS_KNOWN_SETTABLE_FLAGS)
        .unwrap_or(0);
    let applied = retained_unknown | desired;
    // SAFETY: `file` owns a live descriptor and the desired value was range checked.
    if unsafe { libc::fchflags(file.as_raw_fd(), applied) } != 0 {
        let error = std::io::Error::last_os_error();
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "macos-backup-v1",
                "file-flags",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to apply macOS file flags",
            )
            .for_restore(options.restore_policy, 4)
            .with_native_error(&error),
            options,
            "failed to apply macOS file flags",
        );
    }
    if file
        .metadata()
        .map(|value| value.st_flags() & MACOS_KNOWN_SETTABLE_FLAGS)
        .ok()
        != Some(desired)
    {
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "macos-backup-v1",
                "file-flags",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "macOS file flags did not verify after restoration",
            )
            .for_restore(options.restore_policy, 4),
            options,
            "macOS file flags did not verify after restoration",
        );
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn apply_macos_file_flags(
    _file: &fs::File,
    _path: &[u8],
    _metadata: &MemberMetadata,
    _options: SafeExtractionOptions,
    _diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_generic_xattr_auxiliaries_to_path(
    base_path: &Path,
    dereference: bool,
    path: &[u8],
    staged: &mut Vec<StagedAuxiliary>,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let mut remaining = Vec::new();
    for mut item in std::mem::take(staged) {
        if item.record.kind != "generic.xattr" {
            remaining.push(item);
            continue;
        }
        if item.record.restore_class == RestoreClass::System
            && !(options.restore_policy == RestorePolicy::System && options.system_authorized)
        {
            continue;
        }
        item.file.seek(SeekFrom::Start(0)).map_err(|_| {
            FormatError::FilesystemExtractionFailed("failed to rewind staged extended attribute")
        })?;
        let value_len = usize::try_from(item.record.logical_size).map_err(|_| {
            FormatError::ReaderUnsupported("extended attribute exceeds platform limits")
        })?;
        let mut value = vec![0u8; value_len];
        item.file.read_exact(&mut value).map_err(|_| {
            FormatError::FilesystemExtractionFailed("failed to read staged extended attribute")
        })?;
        let name = OsStr::from_bytes(&item.record.decoded_name);
        let set_result = if dereference {
            xattr::set_deref(base_path, name, &value)
        } else {
            xattr::set(base_path, name, &value)
        };
        if let Err(error) = set_result {
            record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    &item.record.profile,
                    "extended-attribute",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    "failed to apply auxiliary extended attribute",
                )
                .for_restore(options.restore_policy, 4)
                .with_native_error(&error),
                options,
                "failed to apply auxiliary extended attribute",
            )?;
            continue;
        }
        let restored = if dereference {
            xattr::get_deref(base_path, name)
        } else {
            xattr::get(base_path, name)
        };
        if restored.ok().flatten().as_deref() != Some(value.as_slice()) {
            record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    &item.record.profile,
                    "extended-attribute",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    "auxiliary extended attribute did not verify after restoration",
                )
                .for_restore(options.restore_policy, 4),
                options,
                "auxiliary extended attribute did not verify after restoration",
            )?;
        }
    }
    *staged = remaining;
    Ok(())
}

#[cfg(not(unix))]
fn apply_generic_xattr_auxiliaries(
    _base_file: &fs::File,
    _path: &[u8],
    _staged: &mut Vec<StagedAuxiliary>,
    _options: SafeExtractionOptions,
    _diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    Ok(())
}

#[cfg(not(windows))]
fn apply_windows_alternate_streams(
    _base_file: &fs::File,
    _path: &[u8],
    _staged: &mut Vec<StagedAuxiliary>,
    _options: SafeExtractionOptions,
    _diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    Ok(())
}

#[cfg(windows)]
fn apply_windows_security_descriptor(
    file: &fs::File,
    path: &[u8],
    metadata: &MemberMetadata,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER};
    use windows_sys::Win32::Security::Authorization::{SetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        GetKernelObjectSecurity, GetSecurityDescriptorDacl, GetSecurityDescriptorGroup,
        GetSecurityDescriptorOwner, GetSecurityDescriptorSacl, SetKernelObjectSecurity,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        ReOpenFile, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
    };
    use windows_sys::Win32::System::SystemServices::ACCESS_SYSTEM_SECURITY;

    if metadata.declaration.source_os != "windows"
        || options.restore_policy != RestorePolicy::System
        || !options.system_authorized
    {
        return Ok(());
    }
    let Some(record) = metadata
        .auxiliary
        .iter()
        .find(|record| record.kind == "windows.security-descriptor")
    else {
        return Ok(());
    };
    let payload = record
        .capture_report_payload
        .as_deref()
        .ok_or(FormatError::InvalidArchive(
            "Windows security descriptor was not retained",
        ))?;
    let security_information = record
        .meta
        .get("TZAP.aux.meta.security-information")
        .map(|value| parse_lower_hex_u32(value, "Windows security information"))
        .transpose()?
        .ok_or(FormatError::InvalidArchive(
            "Windows security descriptor lacks its information mask",
        ))?;
    let query_security_information = security_information & 0x0000_000f;
    let control = u16::from_le_bytes([payload[2], payload[3]]);
    let mut application_security_information = security_information;
    if security_information & 0x0000_0004 != 0 && security_information & 0xa000_0000 == 0 {
        application_security_information |= if control & 0x1000 != 0 {
            0x8000_0000
        } else {
            0x2000_0000
        };
    }
    if security_information & 0x0000_0008 != 0 && security_information & 0x5000_0000 == 0 {
        application_security_information |= if control & 0x2000 != 0 {
            0x4000_0000
        } else {
            0x1000_0000
        };
    }
    if !windows_security_restore_privileges_available(security_information) {
        let diagnostic = MetadataDiagnostic::new(
            path,
            "windows-backup-v1",
            "security-descriptor",
            MetadataOperation::Restore,
            MetadataDiagnosticStatus::Unsupported,
            "required Windows restore privilege is unavailable",
        )
        .for_restore(options.restore_policy, 4);
        if options.allow_degraded {
            diagnostics.push(diagnostic);
            return Ok(());
        }
        return Err(FormatError::ReaderUnsupported(
            "Windows security restoration requires SeBackupPrivilege, SeRestorePrivilege, and optional SeSecurityPrivilege",
        ));
    }
    let desired_access = READ_CONTROL
        | WRITE_DAC
        | WRITE_OWNER
        | if security_information & 0x0000_0008 != 0 {
            ACCESS_SYSTEM_SECURITY
        } else {
            0
        };
    // SAFETY: the original handle is live and flags preserve no-follow access to its object.
    let reopened_security_handle = unsafe {
        ReOpenFile(
            file.as_raw_handle().cast(),
            desired_access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        )
    };
    let (security_handle, owns_security_handle) =
        if reopened_security_handle.is_null() || reopened_security_handle as isize == -1 {
            if file.metadata().is_ok_and(|metadata| metadata.is_dir()) {
                // Directory finalization opens its pinned handle with the
                // security access mask up front. ReOpenFile can still reject
                // directory handles even with backup semantics, so retain the
                // already-authorized pinned handle.
                (file.as_raw_handle().cast(), false)
            } else {
                (reopened_security_handle, true)
            }
        } else {
            (reopened_security_handle, true)
        };
    if security_handle.is_null() || security_handle as isize == -1 {
        let error = std::io::Error::last_os_error();
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "windows-backup-v1",
                "security-descriptor",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to open object for Windows security restoration",
            )
            .for_restore(options.restore_policy, 4)
            .with_native_error(&error),
            options,
            "failed to open object for Windows security restoration",
        );
    }
    let descriptor = payload.as_ptr().cast_mut().cast();
    let mut owner = ptr::null_mut();
    let mut group = ptr::null_mut();
    let mut dacl = ptr::null_mut();
    let mut sacl = ptr::null_mut();
    let mut owner_defaulted = 0;
    let mut group_defaulted = 0;
    let mut dacl_present = 0;
    let mut dacl_defaulted = 0;
    let mut sacl_present = 0;
    let mut sacl_defaulted = 0;
    // SAFETY: the parser-validated self-relative descriptor remains readable and every
    // component output points to initialized local storage for these calls.
    let descriptor_components_ok = unsafe {
        GetSecurityDescriptorOwner(descriptor, &mut owner, &mut owner_defaulted) != 0
            && GetSecurityDescriptorGroup(descriptor, &mut group, &mut group_defaulted) != 0
            && GetSecurityDescriptorDacl(
                descriptor,
                &mut dacl_present,
                &mut dacl,
                &mut dacl_defaulted,
            ) != 0
            && GetSecurityDescriptorSacl(
                descriptor,
                &mut sacl_present,
                &mut sacl,
                &mut sacl_defaulted,
            ) != 0
    };
    if !descriptor_components_ok {
        if owns_security_handle {
            unsafe { CloseHandle(security_handle) };
        }
        return Err(FormatError::InvalidArchive(
            "Windows security descriptor components are invalid",
        ));
    }
    let mut set_error = None;
    let owner_group_information = application_security_information & 0x0000_0003;
    if owner_group_information != 0
        // SAFETY: the handle is live and the validated descriptor contains the selected fields.
        && unsafe { SetKernelObjectSecurity(security_handle, owner_group_information, descriptor) }
            == 0
    {
        set_error = Some(std::io::Error::last_os_error());
    }
    let dacl_information = application_security_information & 0xa000_0004;
    if set_error.is_none() && dacl_information & 0x0000_0004 != 0 {
        if dacl_present == 0 || control & 0x0400 != 0 {
            // SAFETY: the handle and DACL pointer remain live for automatic-inheritance apply.
            let status = unsafe {
                SetSecurityInfo(
                    security_handle,
                    SE_FILE_OBJECT,
                    dacl_information,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    dacl,
                    ptr::null_mut(),
                )
            };
            if status != 0 {
                set_error = Some(std::io::Error::from_raw_os_error(status as i32));
            }
        } else if unsafe {
            // SAFETY: the handle is live and the validated descriptor contains the DACL.
            SetKernelObjectSecurity(security_handle, dacl_information, descriptor)
        } == 0
        {
            set_error = Some(std::io::Error::last_os_error());
        }
    }
    let sacl_information = application_security_information & 0x5000_0008;
    if set_error.is_none() && sacl_information & 0x0000_0008 != 0 {
        if sacl_present == 0 || control & 0x0800 != 0 {
            // SAFETY: the handle and SACL pointer remain live for automatic-inheritance apply.
            let status = unsafe {
                SetSecurityInfo(
                    security_handle,
                    SE_FILE_OBJECT,
                    sacl_information,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    sacl,
                )
            };
            if status != 0 {
                set_error = Some(std::io::Error::from_raw_os_error(status as i32));
            }
        } else if unsafe {
            // SAFETY: the handle is live and the validated descriptor contains the SACL.
            SetKernelObjectSecurity(security_handle, sacl_information, descriptor)
        } == 0
        {
            set_error = Some(std::io::Error::last_os_error());
        }
    }
    if let Some(set_error) = set_error {
        if owns_security_handle {
            unsafe { CloseHandle(security_handle) };
        }
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "windows-backup-v1",
                "security-descriptor",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to apply Windows security descriptor",
            )
            .for_restore(options.restore_policy, 4)
            .with_native_error(&set_error),
            options,
            "failed to apply Windows security descriptor",
        );
    }

    let mut needed = 0u32;
    // SAFETY: the null-buffer query returns the descriptor size through `needed`.
    let first = unsafe {
        GetKernelObjectSecurity(
            security_handle,
            query_security_information,
            ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    let first_error = std::io::Error::last_os_error();
    let mut actual = vec![0u8; needed as usize];
    // SAFETY: `actual` has the queried size and remains writable for the call.
    let get_ok = first == 0
        && first_error.raw_os_error() == Some(ERROR_INSUFFICIENT_BUFFER as i32)
        && needed != 0
        && unsafe {
            GetKernelObjectSecurity(
                security_handle,
                query_security_information,
                actual.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } != 0;
    if owns_security_handle {
        unsafe { CloseHandle(security_handle) };
    }
    if get_ok && actual != payload && windows_security_descriptors_equivalent(payload, &actual) {
        diagnostics.push(
            MetadataDiagnostic::new(
                path,
                "windows-backup-v1",
                "security-descriptor",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Materialized,
                "Windows returned a semantically equivalent security descriptor with normalized self-relative layout or absent-ACL protection; all represented components verified",
            )
            .for_restore(options.restore_policy, 4),
        );
        return Ok(());
    }
    if !get_ok || actual != payload {
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "windows-backup-v1",
                "security-descriptor",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "Windows security descriptor did not verify after restoration",
            )
            .for_restore(options.restore_policy, 4),
            options,
            "Windows security descriptor did not verify after restoration",
        );
    }
    Ok(())
}

#[cfg(windows)]
fn windows_security_descriptors_equivalent(expected: &[u8], actual: &[u8]) -> bool {
    const DACL_PRESENT: u16 = 0x0004;
    const SACL_PRESENT: u16 = 0x0010;
    const DACL_AUTO_INHERIT_REQ: u16 = 0x0100;
    const SACL_AUTO_INHERIT_REQ: u16 = 0x0200;
    const DACL_AUTO_INHERITED: u16 = 0x0400;
    const SACL_AUTO_INHERITED: u16 = 0x0800;
    const DACL_PROTECTED: u16 = 0x1000;
    const SACL_PROTECTED: u16 = 0x2000;

    if expected.len() < 20 || actual.len() < 20 || expected[..2] != actual[..2] {
        return false;
    }
    let expected_control = u16::from_le_bytes([expected[2], expected[3]]);
    let actual_control = u16::from_le_bytes([actual[2], actual[3]]);
    let mut ignorable =
        DACL_AUTO_INHERIT_REQ | SACL_AUTO_INHERIT_REQ | DACL_AUTO_INHERITED | SACL_AUTO_INHERITED;
    if expected_control & DACL_PRESENT == 0 && actual_control & DACL_PRESENT == 0 {
        ignorable |= DACL_PROTECTED;
    }
    if expected_control & SACL_PRESENT == 0 && actual_control & SACL_PRESENT == 0 {
        ignorable |= SACL_PROTECTED;
    }
    if (expected_control ^ actual_control) & !ignorable != 0 {
        return false;
    }

    // A self-relative descriptor does not prescribe component order or offsets. In particular,
    // EFS import followed by GetKernelObjectSecurity can return the same SIDs and ACLs in a
    // differently packed buffer than GetSecurityInfo used during capture. Compare the represented
    // components rather than requiring byte-identical offset fields and padding.
    for (offset_field, acl, represented) in [
        (4usize, false, true),
        (8, false, true),
        (12, true, expected_control & SACL_PRESENT != 0),
        (16, true, expected_control & DACL_PRESENT != 0),
    ] {
        if represented {
            let Some(expected_component) =
                security_descriptor_component(expected, offset_field, acl)
            else {
                return false;
            };
            let Some(actual_component) = security_descriptor_component(actual, offset_field, acl)
            else {
                return false;
            };
            if expected_component != actual_component {
                return false;
            }
        }
    }
    true
}

#[cfg(windows)]
fn security_descriptor_component(
    descriptor: &[u8],
    offset_field: usize,
    acl: bool,
) -> Option<&[u8]> {
    let offset_bytes = descriptor.get(offset_field..offset_field.checked_add(4)?)?;
    let offset = u32::from_le_bytes(offset_bytes.try_into().ok()?) as usize;
    if offset == 0 {
        return Some(&[]);
    }
    let length = if acl {
        let header = descriptor.get(offset..offset.checked_add(4)?)?;
        u16::from_le_bytes([header[2], header[3]]) as usize
    } else {
        let header = descriptor.get(offset..offset.checked_add(8)?)?;
        8usize.checked_add(usize::from(header[1]).checked_mul(4)?)?
    };
    descriptor.get(offset..offset.checked_add(length)?)
}

#[cfg(not(windows))]
fn apply_windows_security_descriptor(
    _file: &fs::File,
    _path: &[u8],
    _metadata: &MemberMetadata,
    _options: SafeExtractionOptions,
    _diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    Ok(())
}

#[cfg(windows)]
fn pax_timestamp_to_windows_filetime(timestamp: (i64, u32)) -> Result<i64, FormatError> {
    const WINDOWS_TO_UNIX_EPOCH_100NS: i128 = 116_444_736_000_000_000;
    let (seconds, nanoseconds) = timestamp;
    if nanoseconds % 100 != 0 {
        return Err(FormatError::FilesystemExtractionFailed(
            "Windows timestamp is not representable at 100-nanosecond precision",
        ));
    }
    let ticks = i128::from(seconds)
        .checked_mul(10_000_000)
        .and_then(|value| value.checked_add(i128::from(nanoseconds / 100)))
        .and_then(|value| value.checked_add(WINDOWS_TO_UNIX_EPOCH_100NS))
        .and_then(|value| i64::try_from(value).ok())
        .ok_or(FormatError::FilesystemExtractionFailed(
            "Windows timestamp is outside the FILETIME range",
        ))?;
    if ticks < 0 {
        return Err(FormatError::FilesystemExtractionFailed(
            "Windows timestamp predates the FILETIME epoch",
        ));
    }
    Ok(ticks)
}

#[cfg(windows)]
fn apply_windows_basic_metadata(
    file: &fs::File,
    path: &[u8],
    metadata: &MemberMetadata,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    if metadata.declaration.source_os != "windows"
        || !matches!(
            options.restore_policy,
            RestorePolicy::SameOs | RestorePolicy::System
        )
    {
        return Ok(());
    }

    apply_windows_directory_case_sensitive(file, path, metadata, options, diagnostics)?;

    let desired_attributes = metadata
        .primary_records
        .get("TZAP.windows.file-attributes")
        .map(|value| parse_lower_hex_u32(value, "Windows file attributes"))
        .transpose()?;
    let compression_exact = if let Some(desired) = desired_attributes {
        apply_windows_compression(
            file,
            path,
            desired & FILE_ATTRIBUTE_COMPRESSED != 0,
            options,
            diagnostics,
        )?
    } else {
        true
    };
    let intrinsic_verification_mask = WINDOWS_ESSENTIAL_INTRINSIC_ATTRIBUTES
        & if options.restore_policy == RestorePolicy::System {
            u32::MAX
        } else {
            !FILE_ATTRIBUTE_ENCRYPTED
        }
        & if compression_exact {
            u32::MAX
        } else {
            !FILE_ATTRIBUTE_COMPRESSED
        };
    let attribute_verification_mask =
        WINDOWS_ESSENTIAL_SETTABLE_ATTRIBUTES | intrinsic_verification_mask;
    let parse_optional_timestamp = |key: &str| {
        metadata
            .primary_records
            .get(key)
            .map(|value| parse_timestamp(value).and_then(pax_timestamp_to_windows_filetime))
            .transpose()
    };
    let creation_time = parse_optional_timestamp("LIBARCHIVE.creationtime")?;
    let access_time = parse_optional_timestamp("atime")?;
    let write_time = Some(pax_timestamp_to_windows_filetime(
        metadata.portable_mirror.mtime,
    )?);
    let change_time = parse_optional_timestamp("TZAP.windows.change-time")?;

    let mut current = FILE_BASIC_INFO::default();
    let handle = file.as_raw_handle().cast();
    // SAFETY: `handle` is live and `current` is a correctly sized writable structure.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileBasicInfo,
            (&mut current as *mut FILE_BASIC_INFO).cast(),
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        let error = std::io::Error::last_os_error();
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "windows-backup-v1",
                "basic-metadata",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to inspect Windows basic metadata",
            )
            .for_restore(options.restore_policy, 4)
            .with_native_error(&error),
            options,
            "failed to inspect Windows basic metadata",
        );
    }

    let mut restored = current;
    if let Some(value) = creation_time {
        restored.CreationTime = value;
    }
    if let Some(value) = access_time {
        restored.LastAccessTime = value;
    }
    if let Some(value) = write_time {
        restored.LastWriteTime = value;
    }
    if let Some(value) = change_time {
        restored.ChangeTime = value;
    }
    if let Some(desired) = desired_attributes {
        let unsupported = desired
            & !(WINDOWS_ESSENTIAL_SETTABLE_ATTRIBUTES
                | WINDOWS_ESSENTIAL_INTRINSIC_ATTRIBUTES
                | FILE_ATTRIBUTE_NORMAL);
        if unsupported != 0 {
            let diagnostic = MetadataDiagnostic::new(
                path,
                "windows-backup-v1",
                "file-attributes",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Unsupported,
                format!("unsupported Windows attribute bits were not applied: {unsupported:08x}"),
            )
            .for_restore(options.restore_policy, 4);
            if options.allow_degraded {
                diagnostics.push(diagnostic);
            } else {
                return Err(FormatError::ReaderUnsupported(
                    "Windows file attributes contain unsupported bits",
                ));
            }
        }
        let intrinsic_mismatch = (current.FileAttributes ^ desired) & intrinsic_verification_mask;
        if intrinsic_mismatch != 0 {
            record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    "windows-backup-v1",
                    "file-attributes",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    format!(
                        "restored Windows object has mismatched intrinsic attributes: {intrinsic_mismatch:08x}"
                    ),
                )
                .for_restore(options.restore_policy, 4),
                options,
                "restored Windows object has mismatched intrinsic attributes",
            )?;
        }
        restored.FileAttributes = (current.FileAttributes & !WINDOWS_ESSENTIAL_SETTABLE_ATTRIBUTES)
            | (desired & WINDOWS_ESSENTIAL_SETTABLE_ATTRIBUTES);
        if restored.FileAttributes
            & (WINDOWS_ESSENTIAL_SETTABLE_ATTRIBUTES | WINDOWS_ESSENTIAL_INTRINSIC_ATTRIBUTES)
            == 0
        {
            restored.FileAttributes |= FILE_ATTRIBUTE_NORMAL;
        } else {
            restored.FileAttributes &= !FILE_ATTRIBUTE_NORMAL;
        }
    }

    // SAFETY: `handle` is live and `restored` is a correctly sized initialized structure.
    if unsafe {
        SetFileInformationByHandle(
            handle,
            FileBasicInfo,
            (&restored as *const FILE_BASIC_INFO).cast(),
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        let error = std::io::Error::last_os_error();
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "windows-backup-v1",
                "basic-metadata",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to apply Windows basic metadata",
            )
            .for_restore(options.restore_policy, 4)
            .with_native_error(&error),
            options,
            "failed to apply Windows basic metadata",
        );
    }

    let mut actual = FILE_BASIC_INFO::default();
    // SAFETY: `handle` is live and `actual` is a correctly sized writable structure.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileBasicInfo,
            (&mut actual as *mut FILE_BASIC_INFO).cast(),
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
        || actual.CreationTime != restored.CreationTime
        || actual.LastAccessTime != restored.LastAccessTime
        || actual.LastWriteTime != restored.LastWriteTime
        || actual.ChangeTime != restored.ChangeTime
        || actual.FileAttributes & attribute_verification_mask
            != restored.FileAttributes & attribute_verification_mask
    {
        let error = std::io::Error::last_os_error();
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "windows-backup-v1",
                "basic-metadata",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "Windows basic metadata did not verify after restoration",
            )
            .for_restore(options.restore_policy, 4)
            .with_native_error(&error),
            options,
            "Windows basic metadata did not verify after restoration",
        );
    }
    Ok(())
}

#[cfg(windows)]
fn apply_windows_compression(
    file: &fs::File,
    path: &[u8],
    compressed: bool,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<bool, FormatError> {
    use std::os::windows::io::AsRawHandle;
    use std::ptr;
    use windows_sys::Win32::Storage::FileSystem::{
        FileBasicInfo, GetFileInformationByHandleEx, COMPRESSION_FORMAT_DEFAULT,
        COMPRESSION_FORMAT_NONE, FILE_BASIC_INFO,
    };
    use windows_sys::Win32::System::Ioctl::FSCTL_SET_COMPRESSION;
    use windows_sys::Win32::System::IO::DeviceIoControl;

    let handle = file.as_raw_handle().cast();
    let mut current = FILE_BASIC_INFO::default();
    // SAFETY: the handle is live and `current` is correctly sized and writable.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileBasicInfo,
            (&mut current as *mut FILE_BASIC_INFO).cast(),
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(FormatError::FilesystemExtractionFailed(
            "failed to inspect Windows compression state",
        ));
    }
    if (current.FileAttributes & FILE_ATTRIBUTE_COMPRESSED != 0) == compressed {
        return Ok(true);
    }
    let mut format = if compressed {
        COMPRESSION_FORMAT_DEFAULT
    } else {
        COMPRESSION_FORMAT_NONE
    };
    let mut ignored = 0u32;
    // SAFETY: the handle is live, the compression-format input is initialized, and this
    // synchronous FSCTL has no output buffer.
    if unsafe {
        DeviceIoControl(
            handle,
            FSCTL_SET_COMPRESSION,
            (&mut format as *mut u16).cast(),
            std::mem::size_of::<u16>() as u32,
            ptr::null_mut(),
            0,
            &mut ignored,
            ptr::null_mut(),
        )
    } == 0
    {
        let error = std::io::Error::last_os_error();
        record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "windows-backup-v1",
                "compression-layout",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Materialized,
                if compressed {
                    "native Windows compression could not be recreated"
                } else {
                    "native Windows compression could not be removed"
                },
            )
            .for_restore(options.restore_policy, 4)
            .with_native_error(&error),
            options,
            "failed to apply native Windows compression state",
        )?;
        return Ok(false);
    }
    Ok(true)
}

#[cfg(windows)]
fn apply_windows_directory_case_sensitive(
    file: &fs::File,
    path: &[u8],
    metadata: &MemberMetadata,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileCaseSensitiveInfo, GetFileInformationByHandleEx, SetFileInformationByHandle,
        FILE_CASE_SENSITIVE_INFO,
    };
    use windows_sys::Win32::System::SystemServices::FILE_CS_FLAG_CASE_SENSITIVE_DIR;

    let Some(encoded) = metadata
        .primary_records
        .get("TZAP.windows.directory-case-sensitive")
    else {
        return Ok(());
    };
    let desired = match encoded.as_slice() {
        b"0" => 0,
        b"1" => FILE_CS_FLAG_CASE_SENSITIVE_DIR,
        _ => {
            return Err(FormatError::InvalidArchive(
                "invalid Windows directory case-sensitivity state",
            ));
        }
    };
    let handle = file.as_raw_handle().cast();
    let mut current = FILE_CASE_SENSITIVE_INFO::default();
    // SAFETY: the handle is live and `current` is correctly sized and writable.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileCaseSensitiveInfo,
            (&mut current as *mut FILE_CASE_SENSITIVE_INFO).cast(),
            std::mem::size_of::<FILE_CASE_SENSITIVE_INFO>() as u32,
        )
    } == 0
    {
        let error = std::io::Error::last_os_error();
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "windows-backup-v1",
                "directory-case-sensitive",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to inspect Windows directory case-sensitivity state",
            )
            .for_restore(options.restore_policy, 4)
            .with_native_error(&error),
            options,
            "failed to inspect Windows directory case-sensitivity state",
        );
    }
    if current.Flags == desired {
        return Ok(());
    }
    if options.restore_policy != RestorePolicy::System || !options.system_authorized {
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "windows-backup-v1",
                "directory-case-sensitive",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Unsupported,
                "changing Windows directory case-sensitivity requires authorized System restore",
            )
            .for_restore(options.restore_policy, 4),
            options,
            "Windows directory case-sensitivity state requires authorized System restore",
        );
    }
    let updated = FILE_CASE_SENSITIVE_INFO { Flags: desired };
    // SAFETY: the handle is live and `updated` is a correctly sized initialized structure.
    if unsafe {
        SetFileInformationByHandle(
            handle,
            FileCaseSensitiveInfo,
            (&updated as *const FILE_CASE_SENSITIVE_INFO).cast(),
            std::mem::size_of::<FILE_CASE_SENSITIVE_INFO>() as u32,
        )
    } == 0
    {
        let error = std::io::Error::last_os_error();
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "windows-backup-v1",
                "directory-case-sensitive",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to apply Windows directory case-sensitivity state",
            )
            .for_restore(options.restore_policy, 4)
            .with_native_error(&error),
            options,
            "failed to apply Windows directory case-sensitivity state",
        );
    }
    let mut actual = FILE_CASE_SENSITIVE_INFO::default();
    // SAFETY: the handle is live and `actual` is correctly sized and writable.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileCaseSensitiveInfo,
            (&mut actual as *mut FILE_CASE_SENSITIVE_INFO).cast(),
            std::mem::size_of::<FILE_CASE_SENSITIVE_INFO>() as u32,
        )
    } == 0
        || actual.Flags != desired
    {
        let error = std::io::Error::last_os_error();
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "windows-backup-v1",
                "directory-case-sensitive",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "Windows directory case-sensitivity state did not verify after restoration",
            )
            .for_restore(options.restore_policy, 4)
            .with_native_error(&error),
            options,
            "Windows directory case-sensitivity state did not verify after restoration",
        );
    }
    Ok(())
}

#[cfg(not(windows))]
fn apply_windows_basic_metadata(
    _file: &fs::File,
    _path: &[u8],
    _metadata: &MemberMetadata,
    _options: SafeExtractionOptions,
    _diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_linux_inode_flags(
    file: &fs::File,
    path: &[u8],
    metadata: &MemberMetadata,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    if !source_os_matches_current_host(&metadata.declaration.source_os) {
        return Ok(());
    }
    let Some(encoded) = metadata.primary_records.get("TZAP.linux.fsflags") else {
        return Ok(());
    };
    let text = std::str::from_utf8(encoded)
        .map_err(|_| FormatError::InvalidArchive("Linux inode flags are not ASCII"))?;
    let desired = u64::from_str_radix(text, 16)
        .map_err(|_| FormatError::InvalidArchive("Linux inode flags are invalid"))?;
    let no_change = desired
        & u64::from(linux_raw_sys::general::FS_IMMUTABLE_FL | linux_raw_sys::general::FS_APPEND_FL)
        != 0;
    if !matches!(
        options.restore_policy,
        RestorePolicy::SameOs | RestorePolicy::System
    ) || (no_change
        && !(options.restore_policy == RestorePolicy::System && options.system_authorized))
    {
        return Ok(());
    }
    let apply_result = (|| -> std::io::Result<()> {
        if desired & !LINUX_KNOWN_FSFLAGS != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "archive contains unrecognized Linux inode flag bits",
            ));
        }
        let mut current: libc::c_long = 0;
        // SAFETY: these ioctls read/write one c_long through valid pointers and
        // operate on the live descriptor owned by `file`.
        if unsafe { libc::ioctl(file.as_raw_fd(), libc::FS_IOC_GETFLAGS, &mut current) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let modifiable = u64::from(linux_raw_sys::general::FS_FL_USER_MODIFIABLE);
        let mut restored =
            ((current as u64 & !modifiable) | (desired & modifiable)) as libc::c_long;
        // SAFETY: as above, SETFLAGS reads the initialized c_long value.
        if unsafe { libc::ioctl(file.as_raw_fd(), libc::FS_IOC_SETFLAGS, &mut restored) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut actual: libc::c_long = 0;
        if unsafe { libc::ioctl(file.as_raw_fd(), libc::FS_IOC_GETFLAGS, &mut actual) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if actual as u64 != desired {
            return Err(std::io::Error::other(format!(
                "Linux inode flags did not verify: wanted {desired:016x}, got {:016x}",
                actual as u64
            )));
        }
        Ok(())
    })();
    if apply_result.is_ok() {
        return Ok(());
    }
    let error = apply_result.unwrap_err();
    record_metadata_application_failure(
        diagnostics,
        MetadataDiagnostic::new(
            path,
            "linux-backup-v1",
            "inode-flags",
            MetadataOperation::Restore,
            MetadataDiagnosticStatus::Failed,
            "failed to apply Linux inode flags",
        )
        .for_restore(options.restore_policy, 4)
        .with_native_error(&error),
        options,
        "failed to apply Linux inode flags",
    )
}

#[cfg(target_os = "linux")]
fn apply_linux_project_id(
    file: &fs::File,
    path: &[u8],
    metadata: &MemberMetadata,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    if metadata.declaration.source_os != "linux"
        || options.restore_policy != RestorePolicy::System
        || !options.system_authorized
    {
        return Ok(());
    }
    let Some(encoded) = metadata.primary_records.get("TZAP.linux.project-id") else {
        return Ok(());
    };
    let desired = std::str::from_utf8(encoded)
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or(FormatError::InvalidArchive("Linux project ID is invalid"))?;
    // fsxattr consists only of integer and reserved-byte fields; zero is valid initialization.
    let mut attributes: linux_raw_sys::general::fsxattr = unsafe { std::mem::zeroed() };
    let get_result = unsafe {
        libc::ioctl(
            file.as_raw_fd(),
            linux_raw_sys::ioctl::FS_IOC_FSGETXATTR as libc::Ioctl,
            &mut attributes,
        )
    };
    if get_result == 0 {
        attributes.fsx_projid = desired;
        if unsafe {
            libc::ioctl(
                file.as_raw_fd(),
                linux_raw_sys::ioctl::FS_IOC_FSSETXATTR as libc::Ioctl,
                &attributes,
            )
        } == 0
        {
            let mut actual: linux_raw_sys::general::fsxattr = unsafe { std::mem::zeroed() };
            if unsafe {
                libc::ioctl(
                    file.as_raw_fd(),
                    linux_raw_sys::ioctl::FS_IOC_FSGETXATTR as libc::Ioctl,
                    &mut actual,
                )
            } == 0
                && actual.fsx_projid == desired
            {
                return Ok(());
            }
        }
    }
    let error = std::io::Error::last_os_error();
    record_metadata_application_failure(
        diagnostics,
        MetadataDiagnostic::new(
            path,
            "linux-backup-v1",
            "project-id",
            MetadataOperation::Restore,
            MetadataDiagnosticStatus::Failed,
            "failed to apply Linux project ID",
        )
        .for_restore(options.restore_policy, 4)
        .with_native_error(&error),
        options,
        "failed to apply Linux project ID",
    )
}

#[cfg(not(target_os = "linux"))]
fn apply_linux_project_id(
    _file: &fs::File,
    _path: &[u8],
    _metadata: &MemberMetadata,
    _options: SafeExtractionOptions,
    _diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn apply_linux_inode_flags(
    _file: &fs::File,
    _path: &[u8],
    _metadata: &MemberMetadata,
    _options: SafeExtractionOptions,
    _diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_regular_file_posix_acl(
    file: &fs::File,
    path: &[u8],
    metadata: &MemberMetadata,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    use xattr::FileExt as _;

    if !source_os_matches_current_host(&metadata.declaration.source_os)
        || !matches!(
            options.restore_policy,
            RestorePolicy::SameOs | RestorePolicy::System
        )
    {
        return Ok(());
    }
    for (key, name) in [
        ("SCHILY.acl.access", "system.posix_acl_access"),
        ("SCHILY.acl.default", "system.posix_acl_default"),
    ] {
        let Some(text) = metadata.primary_records.get(key) else {
            continue;
        };
        let value = schily_posix_acl_to_linux_xattr(text)?;
        if let Err(error) = file.set_xattr(name, &value) {
            record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    "posix-backup-v1",
                    "posix-acl",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    "failed to apply POSIX ACL",
                )
                .for_restore(options.restore_policy, 4)
                .with_native_error(&error),
                options,
                "failed to apply POSIX ACL",
            )?;
            continue;
        }
        if file.get_xattr(name).ok().flatten().as_deref() != Some(value.as_slice()) {
            record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    "posix-backup-v1",
                    "posix-acl",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    "POSIX ACL did not verify after restoration",
                )
                .for_restore(options.restore_policy, 4),
                options,
                "POSIX ACL did not verify after restoration",
            )?;
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn apply_regular_file_posix_acl(
    _file: &fs::File,
    _path: &[u8],
    _metadata: &MemberMetadata,
    _options: SafeExtractionOptions,
    _diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    Ok(())
}

#[cfg(unix)]
fn apply_regular_file_xattrs(
    file: &fs::File,
    path: &[u8],
    metadata: &MemberMetadata,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use xattr::FileExt as _;

    if !source_os_matches_current_host(&metadata.declaration.source_os)
        || !matches!(
            options.restore_policy,
            RestorePolicy::SameOs | RestorePolicy::System
        )
    {
        return Ok(());
    }
    for (key, encoded) in metadata
        .primary_records
        .iter()
        .filter(|(key, _)| key.starts_with("LIBARCHIVE.xattr."))
    {
        let name = decode_percent_name(&key.as_bytes()["LIBARCHIVE.xattr.".len()..])?;
        let system = system_xattr_name(&name, &metadata.declaration.source_os);
        if system && !(options.restore_policy == RestorePolicy::System && options.system_authorized)
        {
            continue;
        }
        let value = canonical_base64_decode(encoded)?;
        if let Err(error) = file.set_xattr(OsStr::from_bytes(&name), &value) {
            record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    if system && metadata.declaration.source_os == "macos" {
                        "macos-backup-v1"
                    } else if system {
                        "linux-backup-v1"
                    } else {
                        "posix-backup-v1"
                    },
                    "extended-attribute",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    "failed to apply extended attribute",
                )
                .for_restore(options.restore_policy, 4)
                .with_native_error(&error),
                options,
                "failed to apply extended attribute",
            )?;
            continue;
        }
        if file
            .get_xattr(OsStr::from_bytes(&name))
            .ok()
            .flatten()
            .as_deref()
            != Some(value.as_slice())
        {
            record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    if system && metadata.declaration.source_os == "macos" {
                        "macos-backup-v1"
                    } else if system {
                        "linux-backup-v1"
                    } else {
                        "posix-backup-v1"
                    },
                    "extended-attribute",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    "extended attribute did not verify after restoration",
                )
                .for_restore(options.restore_policy, 4),
                options,
                "extended attribute did not verify after restoration",
            )?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn apply_regular_file_xattrs(
    _file: &fs::File,
    _path: &[u8],
    _metadata: &MemberMetadata,
    _options: SafeExtractionOptions,
    _diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    Ok(())
}

fn system_xattr_name(name: &[u8], source_os: &str) -> bool {
    name.starts_with(b"security.")
        || name.starts_with(b"trusted.")
        || name.starts_with(b"system.")
        || (source_os == "linux" && !name.starts_with(b"user.") && !name.starts_with(b"com.apple."))
}

#[cfg(unix)]
fn apply_regular_file_ownership(
    file: &fs::File,
    path: &[u8],
    uid: Option<u64>,
    gid: Option<u64>,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    if options.restore_policy != RestorePolicy::System || !options.system_authorized {
        return Ok(());
    }
    let (Some(uid), Some(gid)) = (uid, gid) else {
        return Ok(());
    };
    let uid = libc::uid_t::try_from(uid)
        .map_err(|_| FormatError::FilesystemExtractionFailed("archived UID exceeds host uid_t"))?;
    let gid = libc::gid_t::try_from(gid)
        .map_err(|_| FormatError::FilesystemExtractionFailed("archived GID exceeds host gid_t"))?;

    // SAFETY: fchown only observes the valid descriptor owned by `file`; both
    // numeric arguments were range-checked for this host ABI.
    if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
        let error = std::io::Error::last_os_error();
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "portable-v1",
                "numeric-ownership",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to apply numeric ownership",
            )
            .for_restore(options.restore_policy, 4)
            .with_native_error(&error),
            options,
            "failed to apply numeric ownership",
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn apply_regular_file_ownership(
    _file: &fs::File,
    _path: &[u8],
    _uid: Option<u64>,
    _gid: Option<u64>,
    _options: SafeExtractionOptions,
    _diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    Ok(())
}

#[cfg(windows)]
fn apply_regular_file_attributes(
    file: &fs::File,
    path: &[u8],
    attributes: Option<u32>,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    let Some(attributes) = attributes else {
        return Ok(());
    };
    let metadata = match file.metadata() {
        Ok(metadata) => metadata,
        Err(error) => {
            return record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    "portable-v1",
                    "portable-attributes",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    "failed to inspect file before applying readonly attribute projection",
                )
                .for_restore(options.restore_policy, 4)
                .with_native_error(&error),
                options,
                "failed to inspect file before applying readonly attribute projection",
            );
        }
    };
    let mut permissions = metadata.permissions();
    permissions.set_readonly(attributes & 1 != 0);
    if let Err(error) = file.set_permissions(permissions) {
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "portable-v1",
                "portable-attributes",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to apply readonly attribute projection",
            )
            .for_restore(options.restore_policy, 4)
            .with_native_error(&error),
            options,
            "failed to apply readonly attribute projection",
        );
    }
    Ok(())
}

#[cfg(not(windows))]
fn apply_regular_file_attributes(
    _file: &fs::File,
    _path: &[u8],
    _attributes: Option<u32>,
    _options: SafeExtractionOptions,
    _diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    Ok(())
}

#[cfg(unix)]
fn apply_regular_file_mode(
    file: &fs::File,
    path: &[u8],
    mode: u32,
    _mode_origin_native: bool,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    match file.metadata() {
        Ok(metadata) => {
            let mut permissions = metadata.permissions();
            permissions.set_mode(mode & 0o7777);
            if let Err(error) = file.set_permissions(permissions) {
                return record_metadata_application_failure(
                    diagnostics,
                    MetadataDiagnostic::new(
                        path,
                        "portable-v1",
                        "mode",
                        MetadataOperation::Restore,
                        MetadataDiagnosticStatus::Failed,
                        "failed to apply mode metadata",
                    )
                    .for_restore(options.restore_policy, 4)
                    .with_native_error(&error),
                    options,
                    "failed to apply mode metadata",
                );
            }
        }
        Err(error) => {
            return record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    "portable-v1",
                    "mode",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    "failed to inspect file before applying mode metadata",
                )
                .for_restore(options.restore_policy, 4)
                .with_native_error(&error),
                options,
                "failed to inspect file before applying mode metadata",
            );
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn apply_regular_file_mode(
    file: &fs::File,
    path: &[u8],
    mode: u32,
    mode_origin_native: bool,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    match file.metadata() {
        Ok(metadata) => {
            let mut permissions = metadata.permissions();
            permissions.set_readonly(mode & 0o222 == 0);
            if let Err(error) = file.set_permissions(permissions) {
                return record_metadata_application_failure(
                    diagnostics,
                    MetadataDiagnostic::new(
                        path,
                        "portable-v1",
                        "mode",
                        MetadataOperation::Restore,
                        MetadataDiagnosticStatus::Failed,
                        "failed to apply mode metadata",
                    )
                    .for_restore(options.restore_policy, 4)
                    .with_native_error(&error),
                    options,
                    "failed to apply mode metadata",
                );
            }
            if mode_origin_native && mode & 0o777 != 0o444 && mode & 0o777 != 0o666 {
                let diagnostic = MetadataDiagnostic::new(
                    path,
                    "portable-v1",
                    "mode",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Partial,
                    "mode metadata was only partially applied on this platform",
                )
                .for_restore(options.restore_policy, 4);
                if options.allow_degraded {
                    diagnostics.push(diagnostic);
                } else {
                    return Err(FormatError::FilesystemExtractionFailed(
                        "portable mode cannot be represented exactly on this host",
                    ));
                }
            }
        }
        Err(error) => {
            return record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    "portable-v1",
                    "mode",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    "failed to inspect file before applying mode metadata",
                )
                .for_restore(options.restore_policy, 4)
                .with_native_error(&error),
                options,
                "failed to inspect file before applying mode metadata",
            );
        }
    }
    Ok(())
}

fn apply_regular_file_mtime(
    file: &fs::File,
    path: &[u8],
    (seconds, nanoseconds): (i64, u32),
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    let duration = Duration::new(seconds.unsigned_abs(), nanoseconds);
    let modified = if seconds < 0 {
        SystemTime::UNIX_EPOCH.checked_sub(duration)
    } else {
        SystemTime::UNIX_EPOCH.checked_add(duration)
    };
    let Some(modified) = modified else {
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "portable-v1",
                "mtime",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to apply mtime metadata",
            )
            .for_restore(options.restore_policy, 4),
            options,
            "mtime cannot be represented on this host",
        );
    };
    let times = fs::FileTimes::new().set_modified(modified);
    if let Err(error) = file.set_times(times) {
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "portable-v1",
                "mtime",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to apply mtime metadata",
            )
            .for_restore(options.restore_policy, 4)
            .with_native_error(&error),
            options,
            "failed to apply mtime metadata",
        );
    }
    Ok(())
}

fn record_metadata_application_failure(
    diagnostics: &mut Vec<MetadataDiagnostic>,
    diagnostic: MetadataDiagnostic,
    options: SafeExtractionOptions,
    strict_error: &'static str,
) -> Result<(), FormatError> {
    if options.allow_degraded {
        diagnostics.push(diagnostic);
        Ok(())
    } else {
        Err(FormatError::FilesystemExtractionFailed(strict_error))
    }
}

pub(crate) fn validate_symlink_target(link_path: &[u8], target: &[u8]) -> Result<(), FormatError> {
    if target.is_empty() || target.contains(&0) || target.contains(&b'\\') || target.contains(&b':')
    {
        return Err(FormatError::UnsafeArchivePath);
    }
    let target = std::str::from_utf8(target).map_err(|_| FormatError::UnsafeArchivePath)?;
    let link_path = std::str::from_utf8(link_path).map_err(|_| FormatError::UnsafeArchivePath)?;
    if target.nfc().collect::<String>() != target {
        return Err(FormatError::UnsafeArchivePath);
    }
    if target.starts_with('/') {
        return Ok(());
    }
    let mut stack = link_path
        .split('/')
        .take(link_path.split('/').count().saturating_sub(1))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    for component in target.split('/') {
        if component.is_empty() || component == "." {
            return Err(FormatError::UnsafeArchivePath);
        }
        if component == ".." {
            if stack.pop().is_none() {
                return Err(FormatError::UnsafeArchivePath);
            }
        } else {
            validate_file_path_bytes(component.as_bytes(), u32::MAX)?;
            stack.push(component.to_owned());
        }
    }
    Ok(())
}

struct PreparedDestination {
    parent: CapDir,
    leaf: PathBuf,
}

fn prepare_destination(
    root: &Path,
    archive_path: &[u8],
    kind: TarEntryKind,
    options: SafeExtractionOptions,
) -> Result<PreparedDestination, FormatError> {
    let components = path_components(archive_path)?;
    let mut parent = open_extraction_root(root)?;
    for component in &components[..components.len().saturating_sub(1)] {
        parent = open_or_create_safe_child_dir(&parent, component)?;
    }

    let leaf = PathBuf::from(components.last().ok_or(FormatError::UnsafeArchivePath)?);
    match parent.symlink_metadata(&leaf) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                return Err(FormatError::UnsafeArchivePath);
            }
            if kind == TarEntryKind::Directory {
                if file_type.is_dir() {
                    return Ok(PreparedDestination { parent, leaf });
                }
                return Err(FormatError::UnsafeOverwrite);
            }
            if file_type.is_dir() {
                return Err(FormatError::UnsafeOverwrite);
            }
            if !options.overwrite_existing {
                return Err(FormatError::UnsafeOverwrite);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {
            return Err(FormatError::FilesystemExtractionFailed(
                "failed to inspect destination",
            ));
        }
    }
    Ok(PreparedDestination { parent, leaf })
}

fn open_extraction_root(root: &Path) -> Result<CapDir, FormatError> {
    let metadata = fs::symlink_metadata(root).map_err(|_| {
        FormatError::FilesystemExtractionFailed("extraction root must already exist")
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(FormatError::UnsafeArchivePath);
    }
    CapDir::open_ambient_dir(root, ambient_authority())
        .map_err(|_| FormatError::FilesystemExtractionFailed("extraction root must already exist"))
}

fn open_or_create_safe_child_dir(parent: &CapDir, component: &str) -> Result<CapDir, FormatError> {
    match parent.open_dir_nofollow(component) {
        Ok(child) => return Ok(child),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(FormatError::UnsafeArchivePath),
    }

    match parent.create_dir(component) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => {
            return Err(FormatError::FilesystemExtractionFailed(
                "failed to create parent directory",
            ));
        }
    }
    parent
        .open_dir_nofollow(component)
        .map_err(|_| FormatError::UnsafeArchivePath)
}

fn existing_safe_regular_path(
    root: &Path,
    archive_path: &[u8],
) -> Result<PreparedDestination, FormatError> {
    validate_file_path_bytes(archive_path, u32::MAX)?;
    let components = path_components(archive_path)?;
    let mut parent = open_extraction_root(root)?;
    for component in &components[..components.len().saturating_sub(1)] {
        parent = parent
            .open_dir_nofollow(component)
            .map_err(|_| FormatError::UnsafeArchivePath)?;
    }

    let leaf = PathBuf::from(components.last().ok_or(FormatError::UnsafeArchivePath)?);
    let metadata = parent
        .symlink_metadata(&leaf)
        .map_err(|_| FormatError::UnsafeArchivePath)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(FormatError::UnsafeArchivePath);
    }
    Ok(PreparedDestination { parent, leaf })
}

#[cfg(windows)]
fn existing_safe_windows_reparse_path(
    root: &Path,
    archive_path: &[u8],
) -> Result<PreparedDestination, FormatError> {
    validate_file_path_bytes(archive_path, u32::MAX)?;
    let components = path_components(archive_path)?;
    let mut parent = open_extraction_root(root)?;
    for component in &components[..components.len().saturating_sub(1)] {
        parent = parent
            .open_dir_nofollow(component)
            .map_err(|_| FormatError::UnsafeArchivePath)?;
    }

    let leaf = PathBuf::from(components.last().ok_or(FormatError::UnsafeArchivePath)?);
    let destination = PreparedDestination { parent, leaf };
    // Pin and validate the final leaf without following it. This deliberately differs from
    // `prepare_destination`: an exact Windows reparse restore has already created this leaf, and
    // directory finalization must address the reparse object itself rather than reject it as an
    // alias. Every ancestor remains subject to the ordinary no-follow traversal checks above.
    drop(open_existing_windows_reparse(&destination)?);
    Ok(destination)
}

fn create_new_file_options() -> CapOpenOptions {
    let mut options = CapOpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    #[cfg(windows)]
    options.access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE);
    options
}

fn open_existing_regular_file(target: &PreparedDestination) -> Result<fs::File, FormatError> {
    let mut options = CapOpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    target
        .parent
        .open_with(&target.leaf, &options)
        .map(cap_std::fs::File::into_std)
        .map_err(|_| {
            FormatError::FilesystemExtractionFailed(
                "failed to open hardlink target for materialization",
            )
        })
}

fn open_existing_directory(target: &PreparedDestination) -> Result<fs::File, FormatError> {
    #[cfg(windows)]
    {
        open_existing_windows_directory_with_access(target, 0)
    }

    #[cfg(not(windows))]
    let directory = target.parent.open_dir_nofollow(&target.leaf).map_err(|_| {
        FormatError::FilesystemExtractionFailed("failed to open directory for metadata restoration")
    })?;
    #[cfg(unix)]
    {
        directory
            .open(".")
            .map(cap_std::fs::File::into_std)
            .map_err(|_| {
                FormatError::FilesystemExtractionFailed(
                    "failed to reopen directory for metadata restoration",
                )
            })
    }
    #[cfg(all(not(unix), not(windows)))]
    {
        Ok(directory.into_std_file())
    }
}

#[cfg(windows)]
fn open_existing_windows_directory_with_access(
    target: &PreparedDestination,
    additional_access: u32,
) -> Result<fs::File, FormatError> {
    let mut options = CapOpenOptions::new();
    options
        .access_mode(FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | additional_access)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .follow(FollowSymlinks::No);
    let directory = target
        .parent
        .open_with(&target.leaf, &options)
        .map(cap_std::fs::File::into_std)
        .map_err(|_| {
            FormatError::FilesystemExtractionFailed(
                "failed to open directory for metadata restoration",
            )
        })?;
    let metadata = directory.metadata().map_err(|_| {
        FormatError::FilesystemExtractionFailed(
            "failed to inspect directory for metadata restoration",
        )
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(FormatError::UnsafeArchivePath);
    }
    Ok(directory)
}

#[cfg(windows)]
fn open_existing_windows_regular_with_access(
    target: &PreparedDestination,
    additional_access: u32,
) -> Result<fs::File, FormatError> {
    let mut options = CapOpenOptions::new();
    options
        .access_mode(FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | additional_access)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .follow(FollowSymlinks::No);
    let file = target
        .parent
        .open_with(&target.leaf, &options)
        .map(cap_std::fs::File::into_std)
        .map_err(|_| {
            FormatError::FilesystemExtractionFailed(
                "failed to reopen regular file for final Windows metadata restoration",
            )
        })?;
    let metadata = file.metadata().map_err(|_| {
        FormatError::FilesystemExtractionFailed(
            "failed to inspect regular file for final Windows metadata restoration",
        )
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(FormatError::UnsafeArchivePath);
    }
    Ok(file)
}

#[cfg(windows)]
fn windows_security_access(
    metadata: &MemberMetadata,
    options: SafeExtractionOptions,
) -> Result<u32, FormatError> {
    use windows_sys::Win32::Storage::FileSystem::{READ_CONTROL, WRITE_DAC, WRITE_OWNER};
    use windows_sys::Win32::System::SystemServices::ACCESS_SYSTEM_SECURITY;

    if metadata.declaration.source_os != "windows"
        || options.restore_policy != RestorePolicy::System
        || !options.system_authorized
    {
        return Ok(0);
    }
    let Some(record) = metadata
        .auxiliary
        .iter()
        .find(|record| record.kind == "windows.security-descriptor")
    else {
        return Ok(0);
    };
    let security_information = record
        .meta
        .get("TZAP.aux.meta.security-information")
        .map(|value| parse_lower_hex_u32(value, "Windows security information"))
        .transpose()?
        .ok_or(FormatError::InvalidArchive(
            "Windows security descriptor lacks its information mask",
        ))?;
    if !windows_security_restore_privileges_available(security_information) {
        return Ok(0);
    }
    Ok(READ_CONTROL
        | WRITE_DAC
        | WRITE_OWNER
        | if security_information & 0x0000_0008 != 0 {
            ACCESS_SYSTEM_SECURITY
        } else {
            0
        })
}

#[cfg(windows)]
fn open_existing_windows_reparse(target: &PreparedDestination) -> Result<fs::File, FormatError> {
    open_existing_windows_reparse_with_access(target, 0)
}

#[cfg(windows)]
fn open_existing_windows_reparse_with_access(
    target: &PreparedDestination,
    additional_access: u32,
) -> Result<fs::File, FormatError> {
    let mut options = CapOpenOptions::new();
    options
        .access_mode(FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | additional_access)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .follow(FollowSymlinks::No);
    let reparse = target
        .parent
        .open_with(&target.leaf, &options)
        .map(cap_std::fs::File::into_std)
        .map_err(|_| {
            FormatError::FilesystemExtractionFailed(
                "failed to open Windows reparse object for metadata restoration",
            )
        })?;
    let mut basic = FILE_BASIC_INFO::default();
    // SAFETY: `reparse` owns a live handle and `basic` is a correctly sized writable output.
    if unsafe {
        GetFileInformationByHandleEx(
            reparse.as_raw_handle().cast(),
            FileBasicInfo,
            (&mut basic as *mut FILE_BASIC_INFO).cast(),
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
        || basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
    {
        return Err(FormatError::UnsafeArchivePath);
    }
    Ok(reparse)
}

fn apply_restored_directory_metadata(
    root: &Path,
    path: &[u8],
    metadata: &MemberMetadata,
    staged_auxiliary: Option<&mut Vec<StagedAuxiliary>>,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    #[cfg(windows)]
    let exact_reparse = options.restore_policy == RestorePolicy::System
        && options.system_authorized
        && windows_reparse_metadata_supported(metadata);
    #[cfg(windows)]
    let destination = if exact_reparse {
        existing_safe_windows_reparse_path(root, path)?
    } else {
        prepare_destination(root, path, TarEntryKind::Directory, options)?
    };
    #[cfg(not(windows))]
    let destination = prepare_destination(root, path, TarEntryKind::Directory, options)?;
    #[cfg(windows)]
    let directory = if exact_reparse {
        open_existing_windows_reparse(&destination)?
    } else {
        open_existing_windows_directory_with_access(
            &destination,
            windows_security_access(metadata, options)?,
        )?
    };
    #[cfg(not(windows))]
    let directory = open_existing_directory(&destination)?;
    apply_restored_regular_file_metadata_parts(
        &directory,
        path,
        RestoredRegularMetadata::from(&metadata.portable_mirror),
        Some(metadata),
        staged_auxiliary,
        options,
        diagnostics,
    )
}

#[cfg(windows)]
pub(crate) fn replay_windows_descendant_metadata(
    root: &Path,
    path: &[u8],
    kind: TarEntryKind,
    metadata: &MemberMetadata,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    let access = windows_security_access(metadata, options)?;
    let file = match kind {
        TarEntryKind::Regular => {
            let destination = existing_safe_regular_path(root, path)?;
            open_existing_windows_regular_with_access(&destination, access)?
        }
        TarEntryKind::Symlink => {
            let destination = existing_safe_windows_reparse_path(root, path)?;
            open_existing_windows_reparse_with_access(&destination, access)?
        }
        _ => return Ok(()),
    };
    apply_windows_security_descriptor(&file, path, metadata, options, diagnostics)?;
    apply_windows_basic_metadata(&file, path, metadata, options, diagnostics)
}

pub(crate) fn finalize_committed_directory_metadata(
    root: &Path,
    members: &mut [TarStreamMemberSummary],
    merged_directory_paths: &[Vec<u8>],
    options: SafeExtractionOptions,
) -> Result<(), FormatError> {
    if options.restore_policy == RestorePolicy::Content {
        return Ok(());
    }
    let mut directory_indices = members
        .iter()
        .enumerate()
        .filter_map(|(index, member)| {
            (member.kind == TarEntryKind::Directory
                && merged_directory_paths.contains(&member.path))
            .then_some(index)
        })
        .collect::<Vec<_>>();
    directory_indices.sort_by(|left, right| {
        let left_path = &members[*left].path;
        let right_path = &members[*right].path;
        right_path
            .iter()
            .filter(|byte| **byte == b'/')
            .count()
            .cmp(&left_path.iter().filter(|byte| **byte == b'/').count())
            .then_with(|| left_path.cmp(right_path))
    });
    for index in directory_indices {
        let member = &mut members[index];
        apply_restored_directory_metadata(
            root,
            &member.path,
            &member.v45_metadata,
            None,
            options,
            &mut member.diagnostics,
        )?;
    }
    #[cfg(windows)]
    if options.restore_policy == RestorePolicy::System && options.system_authorized {
        // Applying an inherited directory DACL can update a descendant's
        // security descriptor and Windows ChangeTime. Replay exact file and
        // reparse metadata after every directory has reached its final
        // security state.
        for member in members
            .iter_mut()
            .filter(|member| matches!(member.kind, TarEntryKind::Regular | TarEntryKind::Symlink))
        {
            replay_windows_descendant_metadata(
                root,
                &member.path,
                member.kind,
                &member.v45_metadata,
                options,
                &mut member.diagnostics,
            )?;
        }
    }
    Ok(())
}

fn apply_restored_symlink_mtime(
    destination: &PreparedDestination,
    path: &[u8],
    (seconds, nanoseconds): (i64, u32),
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    let duration = Duration::new(seconds.unsigned_abs(), nanoseconds);
    let modified = if seconds < 0 {
        SystemTime::UNIX_EPOCH.checked_sub(duration)
    } else {
        SystemTime::UNIX_EPOCH.checked_add(duration)
    };
    let Some(modified) = modified else {
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "portable-v1",
                "mtime",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to apply symlink mtime metadata",
            )
            .for_restore(options.restore_policy, 4),
            options,
            "symlink mtime cannot be represented on this host",
        );
    };
    if let Err(error) = destination.parent.set_symlink_times(
        &destination.leaf,
        None,
        Some(SystemTimeSpec::Absolute(
            cap_std::time::SystemTime::from_std(modified),
        )),
    ) {
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "portable-v1",
                "mtime",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to apply symlink mtime metadata",
            )
            .for_restore(options.restore_policy, 4)
            .with_native_error(&error),
            options,
            "failed to apply symlink mtime metadata",
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_restored_linux_symlink_metadata(
    destination: &PreparedDestination,
    path: &[u8],
    metadata: &MemberMetadata,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    use std::ffi::{CString, OsStr};
    use std::os::unix::ffi::OsStrExt;

    if metadata.declaration.source_os != "linux"
        || !matches!(
            options.restore_policy,
            RestorePolicy::SameOs | RestorePolicy::System
        )
    {
        return Ok(());
    }
    let leaf = destination.leaf.as_os_str().as_bytes();
    let leaf_c = CString::new(leaf).map_err(|_| FormatError::UnsafeArchivePath)?;
    let current = destination
        .parent
        .symlink_metadata(&destination.leaf)
        .map_err(|_| FormatError::UnsafeArchivePath)?;
    if !current.file_type().is_symlink() {
        return Err(FormatError::UnsafeArchivePath);
    }

    if options.restore_policy == RestorePolicy::System && options.system_authorized {
        if let (Some(uid), Some(gid)) = (metadata.portable_mirror.uid, metadata.portable_mirror.gid)
        {
            let uid = libc::uid_t::try_from(uid).map_err(|_| {
                FormatError::FilesystemExtractionFailed("archived UID exceeds host uid_t")
            })?;
            let gid = libc::gid_t::try_from(gid).map_err(|_| {
                FormatError::FilesystemExtractionFailed("archived GID exceeds host gid_t")
            })?;
            // SAFETY: the pinned parent fd and validated leaf name identify the symlink itself.
            if unsafe {
                libc::fchownat(
                    destination.parent.as_raw_fd(),
                    leaf_c.as_ptr(),
                    uid,
                    gid,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                let error = std::io::Error::last_os_error();
                record_metadata_application_failure(
                    diagnostics,
                    MetadataDiagnostic::new(
                        path,
                        "portable-v1",
                        "numeric-ownership",
                        MetadataOperation::Restore,
                        MetadataDiagnosticStatus::Failed,
                        "failed to apply symlink numeric ownership",
                    )
                    .for_restore(options.restore_policy, 4)
                    .with_native_error(&error),
                    options,
                    "failed to apply symlink numeric ownership",
                )?;
            }
        }
    }

    let mut proc_path = PathBuf::from(format!("/proc/self/fd/{}", destination.parent.as_raw_fd()));
    proc_path.push(&destination.leaf);
    for (key, encoded) in metadata
        .primary_records
        .iter()
        .filter(|(key, _)| key.starts_with("LIBARCHIVE.xattr."))
    {
        let name = decode_percent_name(&key.as_bytes()["LIBARCHIVE.xattr.".len()..])?;
        let system = system_xattr_name(&name, "linux");
        if system && !(options.restore_policy == RestorePolicy::System && options.system_authorized)
        {
            continue;
        }
        let value = canonical_base64_decode(encoded)?;
        let name = OsStr::from_bytes(&name);
        if let Err(error) = xattr::set(&proc_path, name, &value) {
            record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    if system {
                        "linux-backup-v1"
                    } else {
                        "posix-backup-v1"
                    },
                    "extended-attribute",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    "failed to apply symlink extended attribute",
                )
                .for_restore(options.restore_policy, 4)
                .with_native_error(&error),
                options,
                "failed to apply symlink extended attribute",
            )?;
            continue;
        }
        if xattr::get(&proc_path, name).ok().flatten().as_deref() != Some(value.as_slice()) {
            record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    if system {
                        "linux-backup-v1"
                    } else {
                        "posix-backup-v1"
                    },
                    "extended-attribute",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    "symlink extended attribute did not verify after restoration",
                )
                .for_restore(options.restore_policy, 4),
                options,
                "symlink extended attribute did not verify after restoration",
            )?;
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn apply_restored_linux_symlink_metadata(
    _destination: &PreparedDestination,
    _path: &[u8],
    _metadata: &MemberMetadata,
    _options: SafeExtractionOptions,
    _diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    Ok(())
}

#[cfg(target_os = "macos")]
fn apply_restored_macos_symlink_metadata(
    destination: &PreparedDestination,
    path: &[u8],
    metadata: &MemberMetadata,
    staged: &mut Vec<StagedAuxiliary>,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    use std::ffi::{c_char, c_int, c_void, CString};
    use std::os::fd::{FromRawFd as _, OwnedFd};
    use std::os::unix::ffi::OsStrExt as _;

    if metadata.declaration.source_os != "macos"
        || !matches!(
            options.restore_policy,
            RestorePolicy::SameOs | RestorePolicy::System
        )
    {
        return Ok(());
    }
    let current = destination
        .parent
        .symlink_metadata(&destination.leaf)
        .map_err(|_| FormatError::UnsafeArchivePath)?;
    if !current.file_type().is_symlink() {
        return Err(FormatError::UnsafeArchivePath);
    }
    let leaf = destination.leaf.as_os_str().as_bytes();
    let leaf_c = CString::new(leaf).map_err(|_| FormatError::UnsafeArchivePath)?;
    const O_SYMLINK: c_int = 0x0020_0000;
    // SAFETY: the parent directory is pinned and `leaf_c` is a validated single path component.
    let link_fd = unsafe {
        libc::openat(
            destination.parent.as_raw_fd(),
            leaf_c.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | O_SYMLINK | 0x0000_1000,
        )
    };
    if link_fd < 0 {
        return Err(FormatError::UnsafeArchivePath);
    }
    // SAFETY: `openat` returned a new owned descriptor.
    let link_fd = unsafe { OwnedFd::from_raw_fd(link_fd) };
    let mut pinned_stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(link_fd.as_raw_fd(), pinned_stat.as_mut_ptr()) } != 0
        || unsafe { pinned_stat.assume_init() }.st_mode & libc::S_IFMT != libc::S_IFLNK
    {
        return Err(FormatError::UnsafeArchivePath);
    }

    extern "C" {
        fn fgetxattr(
            fd: c_int,
            name: *const c_char,
            value: *mut c_void,
            size: usize,
            position: u32,
            options: c_int,
        ) -> libc::ssize_t;
        fn fsetxattr(
            fd: c_int,
            name: *const c_char,
            value: *const c_void,
            size: usize,
            position: u32,
            options: c_int,
        ) -> c_int;
        fn fremovexattr(fd: c_int, name: *const c_char, options: c_int) -> c_int;
        fn acl_copy_int(buffer: *const c_void) -> *mut c_void;
        fn acl_copy_ext(
            buffer: *mut c_void,
            acl: *mut c_void,
            size: libc::ssize_t,
        ) -> libc::ssize_t;
        fn acl_size(acl: *mut c_void) -> libc::ssize_t;
        fn acl_set_fd_np(fd: c_int, acl: *mut c_void, acl_type: c_int) -> c_int;
        fn acl_get_fd_np(fd: c_int, acl_type: c_int) -> *mut c_void;
        fn acl_free(object: *mut c_void) -> c_int;
        fn fsetattrlist(
            fd: c_int,
            attributes: *const c_void,
            buffer: *const c_void,
            size: usize,
            options: u32,
        ) -> c_int;
        fn fchflags(fd: c_int, flags: u32) -> c_int;
    }
    const XATTR_CREATE: c_int = 0x0002;
    const ACL_TYPE_EXTENDED: c_int = 0x0000_0100;
    const RESOURCE_FORK: &[u8] = b"com.apple.ResourceFork\0";
    const FINDER_INFO: &[u8] = b"com.apple.FinderInfo\0";

    let fail = |diagnostics: &mut Vec<MetadataDiagnostic>,
                class: &'static str,
                message: &'static str,
                error: Option<&std::io::Error>| {
        let mut diagnostic = MetadataDiagnostic::new(
            path,
            "macos-backup-v1",
            class,
            MetadataOperation::Restore,
            MetadataDiagnosticStatus::Failed,
            message,
        )
        .for_restore(options.restore_policy, 4);
        if let Some(error) = error {
            diagnostic = diagnostic.with_native_error(error);
        }
        record_metadata_application_failure(diagnostics, diagnostic, options, message)
    };

    if options.restore_policy == RestorePolicy::System && options.system_authorized {
        if let (Some(uid), Some(gid)) = (metadata.portable_mirror.uid, metadata.portable_mirror.gid)
        {
            let uid = libc::uid_t::try_from(uid).map_err(|_| {
                FormatError::FilesystemExtractionFailed("archived UID exceeds host uid_t")
            })?;
            let gid = libc::gid_t::try_from(gid).map_err(|_| {
                FormatError::FilesystemExtractionFailed("archived GID exceeds host gid_t")
            })?;
            if unsafe { libc::fchown(link_fd.as_raw_fd(), uid, gid) } != 0 {
                let error = std::io::Error::last_os_error();
                fail(
                    diagnostics,
                    "numeric-ownership",
                    "failed to apply macOS symlink ownership",
                    Some(&error),
                )?;
            }
        }
    }

    let mut items = std::mem::take(staged);
    items.sort_by_key(|item| match item.record.kind.as_str() {
        "macos.resource-fork" => 0,
        "macos.acl-native" => 1,
        "macos.finder-info" => 2,
        "generic.xattr" => 3,
        _ => 4,
    });
    let mut remaining = Vec::new();
    for mut item in items {
        if item.record.restore_class == RestoreClass::System
            && !(options.restore_policy == RestorePolicy::System && options.system_authorized)
        {
            continue;
        }
        match item.record.kind.as_str() {
            "macos.resource-fork" => {
                let name = RESOURCE_FORK.as_ptr().cast::<c_char>();
                if unsafe { fremovexattr(link_fd.as_raw_fd(), name, 0) } != 0 {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() != Some(libc::ENOATTR) {
                        fail(
                            diagnostics,
                            "resource-fork",
                            "failed to replace macOS symlink resource fork",
                            Some(&error),
                        )?;
                        continue;
                    }
                }
                item.file.seek(SeekFrom::Start(0)).map_err(|_| {
                    FormatError::FilesystemExtractionFailed(
                        "failed to rewind staged macOS symlink resource fork",
                    )
                })?;
                let mut offset = 0u64;
                let mut buffer = vec![0u8; 1024 * 1024];
                if item.record.logical_size == 0
                    && unsafe {
                        fsetxattr(
                            link_fd.as_raw_fd(),
                            name,
                            std::ptr::null(),
                            0,
                            0,
                            XATTR_CREATE,
                        )
                    } != 0
                {
                    let error = std::io::Error::last_os_error();
                    fail(
                        diagnostics,
                        "resource-fork",
                        "failed to create macOS symlink resource fork",
                        Some(&error),
                    )?;
                    continue;
                }
                while offset < item.record.logical_size {
                    let count = usize::try_from(
                        (item.record.logical_size - offset).min(buffer.len() as u64),
                    )
                    .unwrap();
                    item.file.read_exact(&mut buffer[..count]).map_err(|_| {
                        FormatError::FilesystemExtractionFailed(
                            "failed to read staged macOS symlink resource fork",
                        )
                    })?;
                    if unsafe {
                        fsetxattr(
                            link_fd.as_raw_fd(),
                            name,
                            buffer.as_ptr().cast(),
                            count,
                            u32::try_from(offset).map_err(|_| {
                                FormatError::ReaderUnsupported(
                                    "macOS resource fork exceeds Darwin xattr position range",
                                )
                            })?,
                            if offset == 0 { XATTR_CREATE } else { 0 },
                        )
                    } != 0
                    {
                        let error = std::io::Error::last_os_error();
                        fail(
                            diagnostics,
                            "resource-fork",
                            "failed to write macOS symlink resource fork",
                            Some(&error),
                        )?;
                        break;
                    }
                    offset += count as u64;
                }
                let actual =
                    unsafe { fgetxattr(link_fd.as_raw_fd(), name, std::ptr::null_mut(), 0, 0, 0) };
                if actual < 0 || actual as u64 != item.record.logical_size {
                    fail(
                        diagnostics,
                        "resource-fork",
                        "macOS symlink resource fork did not verify after restoration",
                        None,
                    )?;
                } else {
                    item.file.seek(SeekFrom::Start(0)).map_err(|_| {
                        FormatError::FilesystemExtractionFailed(
                            "failed to rewind staged macOS symlink resource fork",
                        )
                    })?;
                    let mut expected = vec![0u8; 1024 * 1024];
                    let mut restored = vec![0u8; 1024 * 1024];
                    let mut verify_offset = 0u64;
                    while verify_offset < item.record.logical_size {
                        let count = usize::try_from(
                            (item.record.logical_size - verify_offset).min(expected.len() as u64),
                        )
                        .unwrap();
                        item.file.read_exact(&mut expected[..count]).map_err(|_| {
                            FormatError::FilesystemExtractionFailed(
                                "failed to read staged macOS symlink resource fork",
                            )
                        })?;
                        let copied = unsafe {
                            fgetxattr(
                                link_fd.as_raw_fd(),
                                name,
                                restored.as_mut_ptr().cast(),
                                count,
                                u32::try_from(verify_offset).map_err(|_| {
                                    FormatError::ReaderUnsupported(
                                        "macOS resource fork exceeds Darwin xattr position range",
                                    )
                                })?,
                                0,
                            )
                        };
                        if copied != count as libc::ssize_t
                            || restored[..count] != expected[..count]
                        {
                            fail(
                                diagnostics,
                                "resource-fork",
                                "macOS symlink resource fork did not verify after restoration",
                                None,
                            )?;
                            break;
                        }
                        verify_offset += count as u64;
                    }
                }
            }
            "macos.acl-native" => {
                let size = usize::try_from(item.record.logical_size).map_err(|_| {
                    FormatError::ReaderUnsupported("macOS ACL exceeds platform limits")
                })?;
                let mut value = vec![0u8; size];
                item.file.seek(SeekFrom::Start(0)).map_err(|_| {
                    FormatError::FilesystemExtractionFailed("failed to rewind staged macOS ACL")
                })?;
                item.file.read_exact(&mut value).map_err(|_| {
                    FormatError::FilesystemExtractionFailed("failed to read staged macOS ACL")
                })?;
                validate_darwin_acl_external(&value)?;
                let acl = unsafe { acl_copy_int(value.as_ptr().cast()) };
                if acl.is_null() {
                    return Err(FormatError::InvalidArchive(
                        "macOS ACL external form is invalid",
                    ));
                }
                if unsafe { acl_set_fd_np(link_fd.as_raw_fd(), acl, ACL_TYPE_EXTENDED) } != 0 {
                    let error = std::io::Error::last_os_error();
                    unsafe { acl_free(acl) };
                    fail(
                        diagnostics,
                        "acl-native",
                        "failed to apply native macOS symlink ACL",
                        Some(&error),
                    )?;
                    continue;
                }
                unsafe { acl_free(acl) };
                let restored = unsafe { acl_get_fd_np(link_fd.as_raw_fd(), ACL_TYPE_EXTENDED) };
                if restored.is_null() || unsafe { acl_size(restored) } != size as libc::ssize_t {
                    if !restored.is_null() {
                        unsafe { acl_free(restored) };
                    }
                    fail(
                        diagnostics,
                        "acl-native",
                        "native macOS symlink ACL did not verify after restoration",
                        None,
                    )?;
                    continue;
                }
                let mut actual = vec![0u8; size];
                let copied = unsafe {
                    acl_copy_ext(actual.as_mut_ptr().cast(), restored, size as libc::ssize_t)
                };
                unsafe { acl_free(restored) };
                if copied != size as libc::ssize_t || actual != value {
                    fail(
                        diagnostics,
                        "acl-native",
                        "native macOS symlink ACL did not verify after restoration",
                        None,
                    )?;
                }
            }
            "macos.finder-info" | "generic.xattr" => {
                let (name, class) = if item.record.kind == "macos.finder-info" {
                    (FINDER_INFO.to_vec(), "finder-info")
                } else {
                    let mut name = item.record.decoded_name.clone();
                    name.push(0);
                    (name, "extended-attribute")
                };
                let value_len = usize::try_from(item.record.logical_size).map_err(|_| {
                    FormatError::ReaderUnsupported("extended attribute exceeds platform limits")
                })?;
                let mut value = vec![0u8; value_len];
                item.file.seek(SeekFrom::Start(0)).map_err(|_| {
                    FormatError::FilesystemExtractionFailed(
                        "failed to rewind staged macOS symlink xattr",
                    )
                })?;
                item.file.read_exact(&mut value).map_err(|_| {
                    FormatError::FilesystemExtractionFailed(
                        "failed to read staged macOS symlink xattr",
                    )
                })?;
                if item.record.kind == "macos.finder-info" && value.len() != 32 {
                    return Err(FormatError::InvalidArchive(
                        "macOS FinderInfo is not exactly 32 bytes",
                    ));
                }
                if unsafe {
                    fsetxattr(
                        link_fd.as_raw_fd(),
                        name.as_ptr().cast(),
                        value.as_ptr().cast(),
                        value.len(),
                        0,
                        0,
                    )
                } != 0
                {
                    let error = std::io::Error::last_os_error();
                    fail(
                        diagnostics,
                        class,
                        "failed to apply macOS symlink extended attribute",
                        Some(&error),
                    )?;
                    continue;
                }
                let actual_len = unsafe {
                    fgetxattr(
                        link_fd.as_raw_fd(),
                        name.as_ptr().cast(),
                        std::ptr::null_mut(),
                        0,
                        0,
                        0,
                    )
                };
                let mut actual = vec![0u8; value.len()];
                let copied = if actual_len == value.len() as libc::ssize_t {
                    unsafe {
                        fgetxattr(
                            link_fd.as_raw_fd(),
                            name.as_ptr().cast(),
                            actual.as_mut_ptr().cast(),
                            actual.len(),
                            0,
                            0,
                        )
                    }
                } else {
                    -1
                };
                if copied != value.len() as libc::ssize_t || actual != value {
                    fail(
                        diagnostics,
                        class,
                        "macOS symlink extended attribute did not verify after restoration",
                        None,
                    )?;
                }
            }
            _ => remaining.push(item),
        }
    }
    *staged = remaining;

    for (key, encoded) in metadata
        .primary_records
        .iter()
        .filter(|(key, _)| key.starts_with("LIBARCHIVE.xattr."))
    {
        let name = decode_percent_name(&key.as_bytes()["LIBARCHIVE.xattr.".len()..])?;
        let system = system_xattr_name(&name, "macos");
        if system && !(options.restore_policy == RestorePolicy::System && options.system_authorized)
        {
            continue;
        }
        let value = canonical_base64_decode(encoded)?;
        let name = CString::new(name)
            .map_err(|_| FormatError::InvalidArchive("xattr name contains NUL"))?;
        if unsafe {
            fsetxattr(
                link_fd.as_raw_fd(),
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
                0,
            )
        } != 0
        {
            let error = std::io::Error::last_os_error();
            fail(
                diagnostics,
                "extended-attribute",
                "failed to apply macOS symlink extended attribute",
                Some(&error),
            )?;
            continue;
        }
        let mut actual = vec![0u8; value.len()];
        let copied = unsafe {
            fgetxattr(
                link_fd.as_raw_fd(),
                name.as_ptr(),
                actual.as_mut_ptr().cast(),
                actual.len(),
                0,
                0,
            )
        };
        if copied != value.len() as libc::ssize_t || actual != value {
            fail(
                diagnostics,
                "extended-attribute",
                "macOS symlink extended attribute did not verify after restoration",
                None,
            )?;
        }
    }

    #[repr(C)]
    struct AttrList {
        bitmap_count: u16,
        reserved: u16,
        common_attr: u32,
        volume_attr: u32,
        directory_attr: u32,
        file_attr: u32,
        fork_attr: u32,
    }
    let mut common_attr = 0x0000_0400;
    let mut times = Vec::<libc::timespec>::new();
    if let Some(encoded) = metadata.primary_records.get("LIBARCHIVE.creationtime") {
        let (seconds, nanoseconds) = parse_timestamp(encoded)?;
        common_attr |= 0x0000_0200;
        times.push(libc::timespec {
            tv_sec: seconds,
            tv_nsec: i64::from(nanoseconds),
        });
    }
    let (seconds, nanoseconds) = metadata.portable_mirror.mtime;
    times.push(libc::timespec {
        tv_sec: seconds,
        tv_nsec: i64::from(nanoseconds),
    });
    let attributes = AttrList {
        bitmap_count: 5,
        reserved: 0,
        common_attr,
        volume_attr: 0,
        directory_attr: 0,
        file_attr: 0,
        fork_attr: 0,
    };
    if unsafe {
        fsetattrlist(
            link_fd.as_raw_fd(),
            (&attributes as *const AttrList).cast(),
            times.as_ptr().cast(),
            times.len() * std::mem::size_of::<libc::timespec>(),
            0,
        )
    } != 0
    {
        let error = std::io::Error::last_os_error();
        fail(
            diagnostics,
            "timestamps",
            "failed to apply macOS symlink timestamps",
            Some(&error),
        )?;
    } else {
        let mut actual = std::mem::MaybeUninit::<libc::stat>::uninit();
        let status = unsafe { libc::fstat(link_fd.as_raw_fd(), actual.as_mut_ptr()) };
        let verified = if status == 0 {
            let actual = unsafe { actual.assume_init() };
            actual.st_mtime == seconds
                && actual.st_mtime_nsec == i64::from(nanoseconds)
                && metadata
                    .primary_records
                    .get("LIBARCHIVE.creationtime")
                    .map(|encoded| parse_timestamp(encoded))
                    .transpose()?
                    .is_none_or(|(birth_seconds, birth_nanoseconds)| {
                        actual.st_birthtime == birth_seconds
                            && actual.st_birthtime_nsec == i64::from(birth_nanoseconds)
                    })
        } else {
            false
        };
        if !verified {
            fail(
                diagnostics,
                "timestamps",
                "macOS symlink timestamps did not verify after restoration",
                None,
            )?;
        }
    }

    if let Some(encoded) = metadata.primary_records.get("TZAP.macos.st-flags") {
        let desired = parse_macos_flags(encoded)? & MACOS_KNOWN_SETTABLE_FLAGS;
        if !macos_flags_require_system(desired)
            || options.restore_policy == RestorePolicy::System && options.system_authorized
        {
            let mut before = std::mem::MaybeUninit::<libc::stat>::uninit();
            let retained_unknown =
                if unsafe { libc::fstat(link_fd.as_raw_fd(), before.as_mut_ptr()) } == 0 {
                    unsafe { before.assume_init() }.st_flags & !MACOS_KNOWN_SETTABLE_FLAGS
                } else {
                    0
                };
            if unsafe { fchflags(link_fd.as_raw_fd(), retained_unknown | desired) } != 0 {
                let error = std::io::Error::last_os_error();
                fail(
                    diagnostics,
                    "file-flags",
                    "failed to apply macOS symlink flags",
                    Some(&error),
                )?;
            } else {
                let mut actual = std::mem::MaybeUninit::<libc::stat>::uninit();
                let status = unsafe { libc::fstat(link_fd.as_raw_fd(), actual.as_mut_ptr()) };
                let verified = status == 0
                    && unsafe { actual.assume_init() }.st_flags & MACOS_KNOWN_SETTABLE_FLAGS
                        == desired;
                if !verified {
                    fail(
                        diagnostics,
                        "file-flags",
                        "macOS symlink flags did not verify after restoration",
                        None,
                    )?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn apply_restored_macos_symlink_metadata(
    _destination: &PreparedDestination,
    _path: &[u8],
    _metadata: &MemberMetadata,
    _staged: &mut Vec<StagedAuxiliary>,
    _options: SafeExtractionOptions,
    _diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    Ok(())
}

fn create_temp_regular_file(
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
fn prepare_windows_sparse_file(file: &fs::File, logical_size: u64) -> Result<(), FormatError> {
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
fn query_windows_sparse_ranges(
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
fn windows_file_system_is_refs(file: &fs::File) -> Result<bool, FormatError> {
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
fn verify_windows_sparse_file(
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

fn publish_regular_file(
    destination: &PreparedDestination,
    temp_leaf: &Path,
    mut temp_file: fs::File,
    options: SafeExtractionOptions,
) -> Result<fs::File, FormatError> {
    if options.overwrite_existing {
        remove_existing_leaf_if_needed(destination)?;
    }

    #[cfg(windows)]
    {
        temp_file
            .flush()
            .map_err(|_| FormatError::FilesystemExtractionFailed("failed to flush regular file"))?;
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

        temp_file
            .flush()
            .map_err(|_| FormatError::FilesystemExtractionFailed("failed to flush regular file"))?;
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
        Ok(temp_file)
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

    #[cfg(all(not(windows), not(target_os = "linux")))]
    let copy_result = temp_file
        .seek(SeekFrom::Start(0))
        .and_then(|_| std::io::copy(&mut temp_file, &mut output))
        .and_then(|_| output.flush());

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
        let _ = destination.parent.remove_file_or_symlink(temp_leaf);
        Ok(output)
    }
}

fn remove_existing_leaf_if_needed(destination: &PreparedDestination) -> Result<(), FormatError> {
    match destination.parent.symlink_metadata(&destination.leaf) {
        Ok(metadata) => {
            if metadata.file_type().is_dir() {
                return Err(FormatError::UnsafeOverwrite);
            }
            destination
                .parent
                .remove_file_or_symlink(&destination.leaf)
                .map_err(|_| FormatError::FilesystemExtractionFailed("failed to remove old file"))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(FormatError::FilesystemExtractionFailed(
            "failed to inspect destination",
        )),
    }
}

fn create_directory(destination: &PreparedDestination) -> Result<(), FormatError> {
    match destination.parent.create_dir(&destination.leaf) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = destination
                .parent
                .symlink_metadata(&destination.leaf)
                .map_err(|_| FormatError::UnsafeOverwrite)?;
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                Err(FormatError::UnsafeArchivePath)
            } else if file_type.is_dir() {
                Ok(())
            } else {
                Err(FormatError::UnsafeOverwrite)
            }
        }
        Err(_) => Err(FormatError::FilesystemExtractionFailed(
            "failed to create directory",
        )),
    }
}

fn create_hardlink(
    destination: &PreparedDestination,
    target: &PreparedDestination,
    options: SafeExtractionOptions,
) -> Result<(), FormatError> {
    if options.overwrite_existing {
        remove_existing_leaf_if_needed(destination)?;
    }
    match target
        .parent
        .hard_link(&target.leaf, &destination.parent, &destination.leaf)
    {
        Ok(()) => {
            let metadata = destination
                .parent
                .symlink_metadata(&destination.leaf)
                .map_err(|_| {
                    FormatError::FilesystemExtractionFailed("failed to inspect hardlink")
                })?;
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                let _ = destination.parent.remove_file_or_symlink(&destination.leaf);
                return Err(FormatError::UnsafeArchivePath);
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(FormatError::UnsafeOverwrite)
        }
        Err(_) => Err(FormatError::FilesystemExtractionFailed(
            "failed to create hardlink",
        )),
    }
}

#[cfg(unix)]
fn do_create_symlink(destination: &PreparedDestination, target: &str) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::AsRawFd;

    let target_c = CString::new(target.as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "nul in target"))?;
    let leaf_c = CString::new(destination.leaf.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "nul in leaf"))?;

    let res = unsafe {
        libc::symlinkat(
            target_c.as_ptr(),
            destination.parent.as_raw_fd(),
            leaf_c.as_ptr(),
        )
    };
    if res == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn do_create_symlink(destination: &PreparedDestination, target: &str) -> std::io::Result<()> {
    destination.parent.symlink_file(target, &destination.leaf)
}

fn create_symlink(
    destination: &PreparedDestination,
    target: &[u8],
    options: SafeExtractionOptions,
) -> Result<(), FormatError> {
    if options.overwrite_existing {
        remove_existing_leaf_if_needed(destination)?;
    }
    let target = std::str::from_utf8(target).map_err(|_| FormatError::UnsafeArchivePath)?;
    if target.starts_with('/') && !options.allow_absolute_symlinks {
        return Err(FormatError::UnsafeArchivePath);
    }
    let res = if target.starts_with('/') {
        do_create_symlink(destination, target)
    } else {
        destination.parent.symlink_file(target, &destination.leaf)
    };
    match res {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(FormatError::UnsafeOverwrite)
        }
        Err(_) => Err(FormatError::FilesystemExtractionFailed(
            "failed to create symlink",
        )),
    }
}

#[cfg(target_os = "linux")]
fn create_posix_special_object(
    destination: &PreparedDestination,
    path: &[u8],
    kind: TarEntryKind,
    metadata: &MemberMetadata,
    staged: &mut Vec<StagedAuxiliary>,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    use std::ffi::{CString, OsStr};
    use std::os::fd::FromRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;

    if options.restore_policy != RestorePolicy::System || !options.system_authorized {
        return Err(FormatError::ReaderUnsupported(
            "special POSIX objects require authorized system restore",
        ));
    }
    if options.overwrite_existing {
        remove_existing_leaf_if_needed(destination)?;
    }
    let leaf = CString::new(destination.leaf.as_os_str().as_bytes())
        .map_err(|_| FormatError::UnsafeArchivePath)?;
    let permission_mode = metadata.portable_mirror.mode & 0o7777;
    let (object_mode, device) = match kind {
        TarEntryKind::Fifo => (libc::S_IFIFO | permission_mode, 0),
        TarEntryKind::CharacterDevice | TarEntryKind::BlockDevice => {
            let major = metadata
                .primary_records
                .get("TZAP.posix.device-major")
                .ok_or(FormatError::InvalidArchive(
                    "device major number is missing",
                ))?;
            let minor = metadata
                .primary_records
                .get("TZAP.posix.device-minor")
                .ok_or(FormatError::InvalidArchive(
                    "device minor number is missing",
                ))?;
            let major = parse_minimal_decimal_u64(major, "device major")?;
            let minor = parse_minimal_decimal_u64(minor, "device minor")?;
            let major = libc::c_uint::try_from(major)
                .map_err(|_| FormatError::ReaderUnsupported("device major exceeds host ABI"))?;
            let minor = libc::c_uint::try_from(minor)
                .map_err(|_| FormatError::ReaderUnsupported("device minor exceeds host ABI"))?;
            let type_mode = if kind == TarEntryKind::CharacterDevice {
                libc::S_IFCHR
            } else {
                libc::S_IFBLK
            };
            (type_mode | permission_mode, libc::makedev(major, minor))
        }
        _ => {
            return Err(FormatError::WriterInvariant(
                "non-special member reached Linux special-object creation",
            ));
        }
    };
    // SAFETY: the parent directory is pinned and `leaf` is a validated single component.
    if unsafe {
        libc::mknodat(
            destination.parent.as_raw_fd(),
            leaf.as_ptr(),
            object_mode as libc::mode_t,
            device,
        )
    } != 0
    {
        let error = std::io::Error::last_os_error();
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "posix-backup-v1",
                "special-object",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to create Linux special object",
            )
            .for_restore(options.restore_policy, 2)
            .with_native_error(&error),
            options,
            "failed to create Linux special object",
        );
    }

    // Pin the newly created object without opening a device or blocking on a FIFO.
    let fd = unsafe {
        libc::openat(
            destination.parent.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let _ = destination.parent.remove_file_or_symlink(&destination.leaf);
        return Err(FormatError::FilesystemExtractionFailed(
            "failed to pin restored Linux special object",
        ));
    }
    // SAFETY: `fd` is newly owned and transferred exactly once.
    let pinned = unsafe { fs::File::from_raw_fd(fd) };
    let proc_path = PathBuf::from(format!("/proc/self/fd/{}", pinned.as_raw_fd()));
    let proc_c = CString::new(proc_path.as_os_str().as_bytes())
        .map_err(|_| FormatError::UnsafeArchivePath)?;

    if let (Some(uid), Some(gid)) = (metadata.portable_mirror.uid, metadata.portable_mirror.gid) {
        let uid = libc::uid_t::try_from(uid)
            .map_err(|_| FormatError::ReaderUnsupported("archived UID exceeds host uid_t"))?;
        let gid = libc::gid_t::try_from(gid)
            .map_err(|_| FormatError::ReaderUnsupported("archived GID exceeds host gid_t"))?;
        // SAFETY: the procfs magic link refers to the pinned special object.
        if unsafe { libc::chown(proc_c.as_ptr(), uid, gid) } != 0 {
            let error = std::io::Error::last_os_error();
            record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    "portable-v1",
                    "numeric-ownership",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    "failed to apply special-object ownership",
                )
                .for_restore(options.restore_policy, 4)
                .with_native_error(&error),
                options,
                "failed to apply special-object ownership",
            )?;
        }
    }
    // SAFETY: as above, chmod follows the procfs magic link to the pinned object.
    if unsafe { libc::chmod(proc_c.as_ptr(), permission_mode as libc::mode_t) } != 0 {
        let error = std::io::Error::last_os_error();
        record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "portable-v1",
                "mode",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to apply special-object mode",
            )
            .for_restore(options.restore_policy, 4)
            .with_native_error(&error),
            options,
            "failed to apply special-object mode",
        )?;
    }
    for (key, name) in [
        ("SCHILY.acl.access", "system.posix_acl_access"),
        ("SCHILY.acl.default", "system.posix_acl_default"),
    ] {
        let Some(text) = metadata.primary_records.get(key) else {
            continue;
        };
        let value = schily_posix_acl_to_linux_xattr(text)?;
        if let Err(error) = xattr::set_deref(&proc_path, name, &value) {
            record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    "posix-backup-v1",
                    "posix-acl",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    "failed to apply special-object POSIX ACL",
                )
                .for_restore(options.restore_policy, 4)
                .with_native_error(&error),
                options,
                "failed to apply special-object POSIX ACL",
            )?;
            continue;
        }
        if xattr::get_deref(&proc_path, name).ok().flatten().as_deref() != Some(value.as_slice()) {
            record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    "posix-backup-v1",
                    "posix-acl",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    "special-object POSIX ACL did not verify after restoration",
                )
                .for_restore(options.restore_policy, 4),
                options,
                "special-object POSIX ACL did not verify after restoration",
            )?;
        }
    }
    apply_generic_xattr_auxiliaries_to_path(&proc_path, true, path, staged, options, diagnostics)?;
    for (key, encoded) in metadata
        .primary_records
        .iter()
        .filter(|(key, _)| key.starts_with("LIBARCHIVE.xattr."))
    {
        let name = decode_percent_name(&key.as_bytes()["LIBARCHIVE.xattr.".len()..])?;
        let value = canonical_base64_decode(encoded)?;
        if let Err(error) = xattr::set_deref(&proc_path, OsStr::from_bytes(&name), &value) {
            record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    if system_xattr_name(&name, "linux") {
                        "linux-backup-v1"
                    } else {
                        "posix-backup-v1"
                    },
                    "extended-attribute",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    "failed to apply special-object extended attribute",
                )
                .for_restore(options.restore_policy, 4)
                .with_native_error(&error),
                options,
                "failed to apply special-object extended attribute",
            )?;
            continue;
        }
        if xattr::get_deref(&proc_path, OsStr::from_bytes(&name))
            .ok()
            .flatten()
            .as_deref()
            != Some(value.as_slice())
        {
            record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    if system_xattr_name(&name, "linux") {
                        "linux-backup-v1"
                    } else {
                        "posix-backup-v1"
                    },
                    "extended-attribute",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    "special-object extended attribute did not verify after restoration",
                )
                .for_restore(options.restore_policy, 4),
                options,
                "special-object extended attribute did not verify after restoration",
            )?;
        }
    }
    let (seconds, nanoseconds) = metadata.portable_mirror.mtime;
    let times = [
        libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        },
        libc::timespec {
            tv_sec: seconds as _,
            tv_nsec: nanoseconds as libc::c_long,
        },
    ];
    // SAFETY: the path points to the pinned object and `times` contains two valid timespecs.
    if unsafe { libc::utimensat(libc::AT_FDCWD, proc_c.as_ptr(), times.as_ptr(), 0) } != 0 {
        let error = std::io::Error::last_os_error();
        record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "portable-v1",
                "mtime",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to apply special-object mtime",
            )
            .for_restore(options.restore_policy, 4)
            .with_native_error(&error),
            options,
            "failed to apply special-object mtime",
        )?;
    }
    if kind == TarEntryKind::Fifo {
        let fd = unsafe {
            libc::openat(
                destination.parent.as_raw_fd(),
                leaf.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            return record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    "linux-backup-v1",
                    "fifo-native-metadata",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    "failed to open restored FIFO for native metadata",
                )
                .for_restore(options.restore_policy, 4)
                .with_native_error(&error),
                options,
                "failed to open restored FIFO for native metadata",
            );
        }
        let fifo = unsafe { fs::File::from_raw_fd(fd) };
        apply_linux_project_id(&fifo, path, metadata, options, diagnostics)?;
        apply_linux_inode_flags(&fifo, path, metadata, options, diagnostics)?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn create_posix_special_object(
    destination: &PreparedDestination,
    path: &[u8],
    kind: TarEntryKind,
    metadata: &MemberMetadata,
    staged: &mut Vec<StagedAuxiliary>,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    use std::ffi::CString;
    use std::os::fd::FromRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;

    if options.restore_policy != RestorePolicy::System || !options.system_authorized {
        return Err(FormatError::ReaderUnsupported(
            "special POSIX objects require authorized system restore",
        ));
    }
    if options.overwrite_existing {
        remove_existing_leaf_if_needed(destination)?;
    }
    let leaf = CString::new(destination.leaf.as_os_str().as_bytes())
        .map_err(|_| FormatError::UnsafeArchivePath)?;
    let permission_mode = metadata.portable_mirror.mode & 0o7777;
    let (object_mode, device) = match kind {
        TarEntryKind::Fifo => (u32::from(libc::S_IFIFO) | permission_mode, 0),
        TarEntryKind::CharacterDevice | TarEntryKind::BlockDevice => {
            let major = metadata
                .primary_records
                .get("TZAP.posix.device-major")
                .ok_or(FormatError::InvalidArchive(
                    "device major number is missing",
                ))?;
            let minor = metadata
                .primary_records
                .get("TZAP.posix.device-minor")
                .ok_or(FormatError::InvalidArchive(
                    "device minor number is missing",
                ))?;
            let major = libc::c_int::try_from(parse_minimal_decimal_u64(major, "device major")?)
                .map_err(|_| FormatError::ReaderUnsupported("device major exceeds host ABI"))?;
            let minor = libc::c_int::try_from(parse_minimal_decimal_u64(minor, "device minor")?)
                .map_err(|_| FormatError::ReaderUnsupported("device minor exceeds host ABI"))?;
            let type_mode = if kind == TarEntryKind::CharacterDevice {
                libc::S_IFCHR
            } else {
                libc::S_IFBLK
            };
            (
                u32::from(type_mode) | permission_mode,
                libc::makedev(major, minor),
            )
        }
        _ => {
            return Err(FormatError::WriterInvariant(
                "non-special member reached macOS special-object creation",
            ));
        }
    };
    if unsafe {
        libc::mknodat(
            destination.parent.as_raw_fd(),
            leaf.as_ptr(),
            object_mode as libc::mode_t,
            device,
        )
    } != 0
    {
        let error = std::io::Error::last_os_error();
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "posix-backup-v1",
                "special-object",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to create macOS special object",
            )
            .for_restore(options.restore_policy, 2)
            .with_native_error(&error),
            options,
            "failed to create macOS special object",
        );
    }

    const O_EVTONLY: libc::c_int = 0x0000_8000;
    let open_flags = if kind == TarEntryKind::Fifo {
        libc::O_RDWR | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC
    } else {
        libc::O_RDONLY | O_EVTONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC
    };
    let fd = unsafe { libc::openat(destination.parent.as_raw_fd(), leaf.as_ptr(), open_flags) };
    if fd < 0 {
        let _ = destination.parent.remove_file_or_symlink(&destination.leaf);
        return Err(FormatError::FilesystemExtractionFailed(
            "failed to pin restored macOS special object",
        ));
    }
    let pinned = unsafe { fs::File::from_raw_fd(fd) };
    apply_restored_regular_file_metadata_parts(
        &pinned,
        path,
        RestoredRegularMetadata::from(&metadata.portable_mirror),
        Some(metadata),
        Some(staged),
        options,
        diagnostics,
    )
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn create_posix_special_object(
    _destination: &PreparedDestination,
    _path: &[u8],
    _kind: TarEntryKind,
    _metadata: &MemberMetadata,
    _staged: &mut Vec<StagedAuxiliary>,
    _options: SafeExtractionOptions,
    _diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    Err(FormatError::ReaderUnsupported(
        "POSIX special-object restore is unavailable on this host",
    ))
}

#[cfg(windows)]
struct WindowsReparseRollback<'a> {
    destination: &'a PreparedDestination,
    directory: bool,
    armed: bool,
}

#[cfg(windows)]
impl Drop for WindowsReparseRollback<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if self.directory {
            let _ = self.destination.parent.remove_dir(&self.destination.leaf);
        } else {
            let _ = self
                .destination
                .parent
                .remove_file_or_symlink(&self.destination.leaf);
        }
    }
}

#[cfg(windows)]
fn create_windows_reparse_object(
    destination: &PreparedDestination,
    path: &[u8],
    kind: TarEntryKind,
    metadata: &MemberMetadata,
    staged_auxiliary: &mut Vec<StagedAuxiliary>,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    use std::ptr;
    use windows_sys::Win32::System::Ioctl::{FSCTL_GET_REPARSE_POINT, FSCTL_SET_REPARSE_POINT};
    use windows_sys::Win32::System::IO::DeviceIoControl;

    let record = metadata
        .auxiliary
        .iter()
        .find(|record| record.kind == "windows.reparse-data")
        .ok_or(FormatError::InvalidArchive(
            "Windows reparse object lacks exact reparse data",
        ))?;
    let payload = record
        .capture_report_payload
        .as_deref()
        .ok_or(FormatError::InvalidArchive(
            "Windows reparse data was not retained",
        ))?;
    let tag = validate_windows_essential_reparse_data(payload)?;
    const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
    if (kind == TarEntryKind::Symlink) != (tag == IO_REPARSE_TAG_SYMLINK) {
        return Err(FormatError::InvalidArchive(
            "Windows reparse tag disagrees with primary object kind",
        ));
    }
    let attributes = metadata
        .primary_records
        .get("TZAP.windows.file-attributes")
        .map(|value| parse_lower_hex_u32(value, "Windows file attributes"))
        .transpose()?
        .ok_or(FormatError::InvalidArchive(
            "Windows reparse object lacks file attributes",
        ))?;
    let directory_object = attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    if kind == TarEntryKind::Directory && !directory_object {
        return Err(FormatError::InvalidArchive(
            "Windows junction is not a directory reparse object",
        ));
    }
    if options.overwrite_existing {
        remove_existing_leaf_if_needed(destination)?;
    }
    let mut rollback = WindowsReparseRollback {
        destination,
        directory: directory_object,
        armed: false,
    };

    let file = if directory_object {
        destination
            .parent
            .create_dir(&destination.leaf)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    FormatError::UnsafeOverwrite
                } else {
                    FormatError::FilesystemExtractionFailed(
                        "failed to create Windows reparse directory",
                    )
                }
            })?;
        let mut open = CapOpenOptions::new();
        open.access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .follow(FollowSymlinks::No);
        destination
            .parent
            .open_with(&destination.leaf, &open)
            .map(cap_std::fs::File::into_std)
            .map_err(|_| {
                FormatError::FilesystemExtractionFailed("failed to open Windows reparse directory")
            })?
    } else {
        let mut open = create_new_file_options();
        open.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
        destination
            .parent
            .open_with(&destination.leaf, &open)
            .map(cap_std::fs::File::into_std)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    FormatError::UnsafeOverwrite
                } else {
                    FormatError::FilesystemExtractionFailed("failed to create Windows reparse file")
                }
            })?
    };
    rollback.armed = true;

    let handle = file.as_raw_handle().cast();
    let mut bytes_returned = 0u32;
    // SAFETY: the handle is live and the authenticated payload is retained for the synchronous
    // control call. FSCTL_SET_REPARSE_POINT has no output buffer.
    if unsafe {
        DeviceIoControl(
            handle,
            FSCTL_SET_REPARSE_POINT,
            payload.as_ptr().cast(),
            payload.len() as u32,
            ptr::null_mut(),
            0,
            &mut bytes_returned,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(FormatError::FilesystemExtractionFailed(
            "failed to set Windows reparse data",
        ));
    }

    let mut actual = vec![0u8; 16 * 1024];
    // SAFETY: the handle is live and the output allocation remains valid for the synchronous call.
    if unsafe {
        DeviceIoControl(
            handle,
            FSCTL_GET_REPARSE_POINT,
            ptr::null(),
            0,
            actual.as_mut_ptr().cast(),
            actual.len() as u32,
            &mut bytes_returned,
            ptr::null_mut(),
        )
    } == 0
        || actual.get(..bytes_returned as usize) != Some(payload)
    {
        return Err(FormatError::FilesystemExtractionFailed(
            "Windows reparse data did not verify after creation",
        ));
    }
    apply_windows_alternate_streams(&file, path, staged_auxiliary, options, diagnostics)?;
    apply_windows_security_descriptor(&file, path, metadata, options, diagnostics)?;
    apply_windows_basic_metadata(&file, path, metadata, options, diagnostics)?;
    rollback.armed = false;
    Ok(())
}

fn path_components(path: &[u8]) -> Result<Vec<String>, FormatError> {
    validate_file_path_bytes(path, u32::MAX)?;
    let path = std::str::from_utf8(path).map_err(|_| FormatError::UnsafeArchivePath)?;
    Ok(path.split('/').map(str::to_owned).collect())
}

fn ustar_path(header: &[u8]) -> Vec<u8> {
    let name = nul_trimmed(&header[0..100]);
    let prefix = nul_trimmed(&header[345..500]);
    if prefix.is_empty() {
        name.to_vec()
    } else {
        let mut out = Vec::with_capacity(prefix.len() + 1 + name.len());
        out.extend_from_slice(prefix);
        out.push(b'/');
        out.extend_from_slice(name);
        out
    }
}

fn verify_tar_checksum(header: &[u8]) -> Result<(), FormatError> {
    let stored = parse_tar_octal(&header[148..156])?;
    let mut sum = 0u64;
    for (idx, byte) in header.iter().enumerate() {
        if (148..156).contains(&idx) {
            sum += b' ' as u64;
        } else {
            sum += *byte as u64;
        }
    }
    if stored != sum {
        return Err(FormatError::InvalidArchive("tar header checksum mismatch"));
    }
    Ok(())
}

fn parse_tar_octal(field: &[u8]) -> Result<u64, FormatError> {
    let mut value = 0u64;
    let mut saw_digit = false;
    for byte in field {
        match *byte {
            0 | b' ' if saw_digit => break,
            0 | b' ' => {}
            b'0'..=b'7' => {
                saw_digit = true;
                value = value
                    .checked_mul(8)
                    .and_then(|acc| acc.checked_add((*byte - b'0') as u64))
                    .ok_or(FormatError::InvalidArchive("tar octal field overflow"))?;
            }
            _ => return Err(FormatError::InvalidArchive("malformed tar octal field")),
        }
    }
    Ok(value)
}

fn nul_trimmed(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    &bytes[..end]
}

fn padding_to_512(len: usize) -> usize {
    let remainder = len % TAR_BLOCK_LEN;
    if remainder == 0 {
        0
    } else {
        TAR_BLOCK_LEN - remainder
    }
}

fn padding_to_512_u64(len: u64) -> u64 {
    let remainder = len % TAR_BLOCK_LEN as u64;
    if remainder == 0 {
        0
    } else {
        TAR_BLOCK_LEN as u64 - remainder
    }
}

fn slice(bytes: &[u8], offset: usize, len: usize) -> Result<&[u8], FormatError> {
    let end = checked_add(offset, len)?;
    bytes.get(offset..end).ok_or(FormatError::InvalidLength {
        structure: "tar member",
        expected: end,
        actual: bytes.len(),
    })
}

fn checked_add(lhs: usize, rhs: usize) -> Result<usize, FormatError> {
    lhs.checked_add(rhs).ok_or(FormatError::InvalidArchive(
        "tar member arithmetic overflow",
    ))
}

fn to_usize(value: u64) -> Result<usize, FormatError> {
    usize::try_from(value).map_err(|_| FormatError::InvalidArchive("tar member size overflow"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn header(path: &[u8], kind: u8, size: usize, link: &[u8]) -> [u8; TAR_BLOCK_LEN] {
        let mut header = [0u8; TAR_BLOCK_LEN];
        header[..path.len()].copy_from_slice(path);
        write_octal(&mut header[100..108], 0o644);
        write_octal(&mut header[108..116], 0);
        write_octal(&mut header[116..124], 0);
        write_octal(&mut header[124..136], size as u64);
        write_octal(&mut header[136..148], 0);
        header[148..156].fill(b' ');
        header[156] = kind;
        header[157..157 + link.len()].copy_from_slice(link);
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum = header.iter().map(|byte| *byte as u64).sum::<u64>();
        write_checksum(&mut header[148..156], checksum);
        header
    }

    fn member(path: &[u8], kind: u8, data: &[u8], link: &[u8]) -> Vec<u8> {
        member_with_declared_size(path, kind, data.len(), data, link)
    }

    fn member_with_declared_size(
        path: &[u8],
        kind: u8,
        declared_size: usize,
        data: &[u8],
        link: &[u8],
    ) -> Vec<u8> {
        let records =
            crate::entry_metadata::portable_primary_pax(path, 0o644, "other", false).unwrap();
        let pax = crate::entry_metadata::encode_canonical_pax(&records).unwrap();
        let mut pax_header = header(b"TZAP-PAX/PRIMARY", b'x', pax.len(), b"");
        write_octal(&mut pax_header[100..108], 0);
        pax_header[148..156].fill(b' ');
        let checksum = pax_header.iter().map(|byte| *byte as u64).sum::<u64>();
        write_checksum(&mut pax_header[148..156], checksum);
        let mut out = Vec::new();
        out.extend_from_slice(&pax_header);
        out.extend_from_slice(&pax);
        out.resize(out.len() + padding_to_512(pax.len()), 0);
        out.extend_from_slice(&header(path, kind, declared_size, link));
        out.extend_from_slice(data);
        out.resize(out.len() + padding_to_512(data.len()), 0);
        out
    }

    fn member_with_prefix(prefix: &[u8], path: &[u8], kind: u8, data: &[u8]) -> Vec<u8> {
        let mut full_path = prefix.to_vec();
        full_path.push(b'/');
        full_path.extend_from_slice(path);
        let records =
            crate::entry_metadata::portable_primary_pax(&full_path, 0o644, "other", false).unwrap();
        let pax = crate::entry_metadata::encode_canonical_pax(&records).unwrap();
        let mut pax_header = header(b"TZAP-PAX/PRIMARY", b'x', pax.len(), b"");
        write_octal(&mut pax_header[100..108], 0);
        pax_header[148..156].fill(b' ');
        let checksum = pax_header.iter().map(|byte| *byte as u64).sum::<u64>();
        write_checksum(&mut pax_header[148..156], checksum);
        let mut header = header(path, kind, data.len(), b"");
        header[345..345 + prefix.len()].copy_from_slice(prefix);
        header[148..156].fill(b' ');
        let checksum = header.iter().map(|byte| *byte as u64).sum::<u64>();
        write_checksum(&mut header[148..156], checksum);

        let mut out = Vec::new();
        out.extend_from_slice(&pax_header);
        out.extend_from_slice(&pax);
        out.resize(out.len() + padding_to_512(pax.len()), 0);
        out.extend_from_slice(&header);
        out.extend_from_slice(data);
        out.resize(out.len() + padding_to_512(data.len()), 0);
        out
    }

    fn pax_record(key: &str, value: &[u8]) -> Vec<u8> {
        let mut len = key.len() + value.len() + 4;
        loop {
            let candidate = len.to_string().len() + 1 + key.len() + 1 + value.len() + 1;
            if candidate == len {
                break;
            }
            len = candidate;
        }
        let mut out = Vec::new();
        out.extend_from_slice(len.to_string().as_bytes());
        out.push(b' ');
        out.extend_from_slice(key.as_bytes());
        out.push(b'=');
        out.extend_from_slice(value);
        out.push(b'\n');
        out
    }

    fn write_octal(field: &mut [u8], value: u64) {
        let digits = format!("{value:o}");
        field.fill(0);
        let start = field.len() - 1 - digits.len();
        field[..start].fill(b'0');
        field[start..start + digits.len()].copy_from_slice(digits.as_bytes());
    }

    fn write_checksum(field: &mut [u8], value: u64) {
        let digits = format!("{value:06o}");
        field[0..6].copy_from_slice(digits.as_bytes());
        field[6] = 0;
        field[7] = b' ';
    }

    #[cfg(windows)]
    #[test]
    fn security_descriptor_equivalence_only_normalizes_protection_on_absent_acls() {
        let descriptor = |control: u16| {
            let mut bytes = vec![1, 0];
            bytes.extend_from_slice(&control.to_le_bytes());
            bytes.extend_from_slice(&[0; 16]);
            bytes
        };
        let base = 0x8004u16;
        assert!(windows_security_descriptors_equivalent(
            &descriptor(base | 0x2000),
            &descriptor(base)
        ));
        assert!(windows_security_descriptors_equivalent(
            &descriptor(base | 0x0400),
            &descriptor(base | 0x0100)
        ));
        assert!(!windows_security_descriptors_equivalent(
            &descriptor(base | 0x1000),
            &descriptor(base)
        ));
        assert!(!windows_security_descriptors_equivalent(
            &descriptor(base),
            &descriptor(base | 0x0008)
        ));
        let mut changed_body = descriptor(base | 0x2000);
        changed_body[10] = 1;
        assert!(!windows_security_descriptors_equivalent(
            &changed_body,
            &descriptor(base)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn security_descriptor_equivalence_ignores_self_relative_component_layout() {
        let owner = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        let group = [1, 1, 0, 0, 0, 0, 0, 5, 32, 2, 0, 0];
        let dacl = [2, 0, 8, 0, 0, 0, 0, 0];
        let descriptor = |order: [usize; 3]| {
            let components: [&[u8]; 3] = [&owner, &group, &dacl];
            let mut bytes = vec![0u8; 20];
            bytes[0] = 1;
            bytes[2..4].copy_from_slice(&0x8004u16.to_le_bytes());
            for index in order {
                let offset = bytes.len() as u32;
                let field = match index {
                    0 => 4,
                    1 => 8,
                    2 => 16,
                    _ => unreachable!(),
                };
                bytes[field..field + 4].copy_from_slice(&offset.to_le_bytes());
                bytes.extend_from_slice(components[index]);
            }
            bytes
        };
        let expected = descriptor([0, 1, 2]);
        let actual = descriptor([2, 1, 0]);
        assert_ne!(expected, actual);
        assert!(windows_security_descriptors_equivalent(&expected, &actual));

        let mut changed_dacl = actual;
        let dacl_offset = u32::from_le_bytes(changed_dacl[16..20].try_into().unwrap()) as usize;
        changed_dacl[dacl_offset] = 4;
        assert!(!windows_security_descriptors_equivalent(
            &expected,
            &changed_dacl
        ));
    }

    #[test]
    fn parses_ustar_regular_member() {
        let bytes = member(b"dir/file.txt", b'0', b"hello", b"");
        let parsed = parse_tar_member_group(&bytes, 4096).unwrap();

        assert_eq!(parsed.kind, TarEntryKind::Regular);
        assert_eq!(parsed.path, b"dir/file.txt");
        assert_eq!(parsed.data, b"hello");
        assert_eq!(parsed.logical_size, 5);
    }

    #[test]
    fn canonicalizes_one_directory_trailing_slash_only_for_directories() {
        let dir = member(b"dir/", b'5', b"", b"");
        assert_eq!(parse_tar_member_group(&dir, 4096).unwrap().path, b"dir");

        let file = member(b"dir/", b'0', b"", b"");
        assert_eq!(
            parse_tar_member_group(&file, 4096).unwrap_err(),
            FormatError::UnsafeArchivePath
        );
    }

    #[test]
    fn rejects_global_pax_headers() {
        let bytes = member(b"pax", b'g', b"11 path=x\n", b"");
        assert_eq!(
            parse_tar_member_group(&bytes, 4096).unwrap_err(),
            FormatError::InvalidArchive("global or GNU tar metadata is forbidden in revision 45")
        );
    }

    #[test]
    fn rejects_global_pax_before_main_entry() {
        let global_pax = pax_record("path", b"poisoned.txt");
        let mut bytes = member(b"GlobalHead/path", b'g', &global_pax, b"");
        bytes.extend_from_slice(&member(b"safe.txt", b'0', b"abc", b""));

        assert_eq!(
            parse_tar_member_group(&bytes, 4096).unwrap_err(),
            FormatError::InvalidArchive("global or GNU tar metadata is forbidden in revision 45")
        );
    }

    #[test]
    fn rejects_global_gnu_headers() {
        for typeflag in *b"VMN" {
            let bytes = member(b"global", typeflag, b"archive-label", b"");

            assert_eq!(
                parse_tar_member_group(&bytes, 4096).unwrap_err(),
                FormatError::InvalidArchive(
                    "global or GNU tar metadata is forbidden in revision 45"
                ),
                "typeflag {typeflag:?}"
            );
        }
    }

    #[test]
    fn rejects_unsupported_gnu_sparse_entry_type() {
        let bytes = member(b"sparse.bin", b'S', b"", b"");

        assert_eq!(
            parse_tar_member_group(&bytes, 4096).unwrap_err(),
            FormatError::InvalidArchive("global or GNU tar metadata is forbidden in revision 45")
        );
    }

    #[test]
    fn rejects_noncanonical_extra_local_pax_path_and_size() {
        let pax = pax_record("path", b"long/name.txt");
        let mut bytes = member(b"PaxHeaders/name", b'x', &pax, b"");
        bytes.extend_from_slice(&member(b"short", b'0', b"abc", b""));

        assert!(parse_tar_member_group(&bytes, 4096).is_err());
    }

    #[test]
    fn rejects_gnu_long_name_and_link_records() {
        let mut named = member(b"././@LongLink", b'L', b"long/path.txt\0", b"");
        named.extend_from_slice(&member(b"short", b'0', b"abc", b""));
        assert!(parse_tar_member_group(&named, 4096).is_err());

        let mut linked = member(b"././@LongLink", b'K', b"target/file.txt\0", b"");
        linked.extend_from_slice(&member(b"short-link", b'2', b"", b"fallback"));
        assert!(parse_tar_member_group(&linked, 4096).is_err());
    }

    #[test]
    fn supported_tar_metadata_profile_matrix_matches_buffered_and_streaming_parsers() {
        struct Case {
            name: &'static str,
            bytes: Vec<u8>,
            expected_path: &'static [u8],
            expected_kind: TarEntryKind,
            expected_data: &'static [u8],
            expected_link_target: Option<&'static [u8]>,
            expected_logical_size: u64,
        }

        let cases = vec![
            Case {
                name: "regular ustar member",
                bytes: member(b"dir/file.txt", b'0', b"hello", b""),
                expected_path: b"dir/file.txt",
                expected_kind: TarEntryKind::Regular,
                expected_data: b"hello",
                expected_link_target: None,
                expected_logical_size: 5,
            },
            Case {
                name: "ustar prefix plus name",
                bytes: member_with_prefix(b"dir/prefix", b"file.txt", b'0', b"abc"),
                expected_path: b"dir/prefix/file.txt",
                expected_kind: TarEntryKind::Regular,
                expected_data: b"abc",
                expected_link_target: None,
                expected_logical_size: 3,
            },
            Case {
                name: "directory trailing slash",
                bytes: member(b"dir/", b'5', b"", b""),
                expected_path: b"dir",
                expected_kind: TarEntryKind::Directory,
                expected_data: b"",
                expected_link_target: None,
                expected_logical_size: 0,
            },
            Case {
                name: "canonical symlink",
                bytes: member(b"links/link", b'2', b"", b"target/file.txt"),
                expected_path: b"links/link",
                expected_kind: TarEntryKind::Symlink,
                expected_data: b"",
                expected_link_target: Some(b"target/file.txt"),
                expected_logical_size: 0,
            },
        ];

        for case in cases {
            let parsed = parse_tar_member_group(&case.bytes, 4096).unwrap_or_else(|err| {
                panic!("{} should parse in buffered tar parser: {err:?}", case.name)
            });
            assert_eq!(parsed.path, case.expected_path, "{}", case.name);
            assert_eq!(parsed.kind, case.expected_kind, "{}", case.name);
            assert_eq!(parsed.data, case.expected_data, "{}", case.name);
            assert_eq!(
                parsed.link_target.as_deref(),
                case.expected_link_target,
                "{}",
                case.name
            );
            assert_eq!(
                parsed.logical_size, case.expected_logical_size,
                "{}",
                case.name
            );

            let mut streaming = TarStreamSummaryValidator::with_observer(
                4096,
                u64::MAX,
                4096,
                16,
                NoopTarStreamObserver,
            );
            streaming.observe(&case.bytes).unwrap_or_else(|err| {
                panic!(
                    "{} should parse in streaming tar parser: {err:?}",
                    case.name
                )
            });
            let summary = streaming.finish().unwrap_or_else(|err| {
                panic!(
                    "{} should finish in streaming tar parser: {err:?}",
                    case.name
                )
            });
            assert_eq!(summary.members.len(), 1, "{}", case.name);
            let member = &summary.members[0];
            assert_eq!(member.path, case.expected_path, "{}", case.name);
            assert_eq!(member.kind, case.expected_kind, "{}", case.name);
            assert_eq!(
                member.link_target.as_deref(),
                case.expected_link_target,
                "{}",
                case.name
            );
            assert_eq!(
                member.logical_size, case.expected_logical_size,
                "{}",
                case.name
            );
        }
    }

    #[test]
    fn tar_metadata_rejects_unsafe_or_inconsistent_overrides_matrix() {
        let mut pax_absolute_path = member(
            b"PaxHeaders/file",
            b'x',
            &pax_record("path", b"/absolute"),
            b"",
        );
        pax_absolute_path.extend_from_slice(&member(b"fallback", b'0', b"abc", b""));

        let mut pax_parent_path = member(
            b"PaxHeaders/file",
            b'x',
            &pax_record("path", b"../escape"),
            b"",
        );
        pax_parent_path.extend_from_slice(&member(b"fallback", b'0', b"abc", b""));

        let mut pax_absolute_link = member(
            b"PaxHeaders/link",
            b'x',
            &pax_record("linkpath", b"/target"),
            b"",
        );
        pax_absolute_link.extend_from_slice(&member(b"links/link", b'2', b"", b"safe"));

        let mut gnu_unsafe_name = member(b"././@LongLink", b'L', b"bad:name.txt\0", b"");
        gnu_unsafe_name.extend_from_slice(&member(b"fallback", b'0', b"abc", b""));

        let mut gnu_parent_hardlink = member(b"././@LongLink", b'K', b"../target.txt\0", b"");
        gnu_parent_hardlink.extend_from_slice(&member(b"links/hard", b'1', b"", b"safe"));

        let mut pax_size_on_directory =
            member(b"PaxHeaders/dir", b'x', &pax_record("size", b"1"), b"");
        pax_size_on_directory
            .extend_from_slice(&member_with_declared_size(b"dir", b'5', 0, b"x", b""));

        for (name, bytes) in [
            ("pax absolute path", pax_absolute_path),
            ("pax parent path", pax_parent_path),
            ("pax absolute symlink target", pax_absolute_link),
            ("gnu unsafe long name", gnu_unsafe_name),
            ("gnu hardlink parent target", gnu_parent_hardlink),
            ("pax size on directory", pax_size_on_directory),
        ] {
            assert!(parse_tar_member_group(&bytes, 4096).is_err(), "{name}");

            let mut streaming = TarStreamSummaryValidator::with_observer(
                4096,
                u64::MAX,
                4096,
                16,
                NoopTarStreamObserver,
            );
            assert!(streaming.observe(&bytes).is_err(), "{name}");
        }
    }

    #[test]
    fn pax_size_exceeding_available_group_is_rejected_by_buffered_and_streaming_parsers() {
        let mut bytes = member(b"PaxHeaders/file", b'x', &pax_record("size", b"4096"), b"");
        bytes.extend_from_slice(&member_with_declared_size(b"file", b'0', 0, b"short", b""));

        assert!(parse_tar_member_group(&bytes, 4096).is_err());

        let mut streaming = TarStreamSummaryValidator::with_observer(
            4096,
            u64::MAX,
            4096,
            16,
            NoopTarStreamObserver,
        );
        assert!(streaming.observe(&bytes).is_err());
    }

    #[test]
    fn malformed_pax_record_matrix_rejects_before_metadata_is_trusted() {
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("missing length", b"path=file\n".to_vec()),
            ("missing space", b"12path=file\n".to_vec()),
            ("record too short", b"3 a\n".to_vec()),
            ("missing newline", b"11 path=file".to_vec()),
            ("missing equals", b"10 pathfile\n".to_vec()),
            ("non utf8 key", vec![7, b' ', 0xff, b'=', b'x', b'\n']),
            ("bad size value", pax_record("size", b"12x")),
        ];

        for (name, payload) in cases {
            let mut bytes = member(b"PaxHeaders/file", b'x', &payload, b"");
            bytes.extend_from_slice(&member(b"file", b'0', b"abc", b""));

            assert!(
                matches!(
                    parse_tar_member_group(&bytes, 4096).unwrap_err(),
                    FormatError::InvalidArchive(_)
                ),
                "{name}"
            );

            let mut streaming = TarStreamSummaryValidator::with_observer(
                4096,
                u64::MAX,
                4096,
                16,
                NoopTarStreamObserver,
            );
            assert!(
                matches!(
                    streaming.observe(&bytes).unwrap_err(),
                    FormatError::InvalidArchive(_)
                ),
                "{name}"
            );
        }
    }

    #[test]
    fn rejects_unregistered_legacy_xattr_and_acl_pax_keys() {
        let mut pax = Vec::new();
        pax.extend_from_slice(&pax_record("SCHILY.xattr.user.comment", b"hello"));
        pax.extend_from_slice(&pax_record("LIBARCHIVE.xattr.user.comment", b"hello"));
        pax.extend_from_slice(&pax_record("SCHILY.acl.access", b"user::rw-"));
        pax.extend_from_slice(&pax_record("LIBARCHIVE.acl.access", b"user::rw-"));
        let mut bytes = member(b"PaxHeaders/file", b'x', &pax, b"");
        bytes.extend_from_slice(&member(b"file.txt", b'0', b"abc", b""));

        assert!(parse_tar_member_group(&bytes, 4096).is_err());
    }

    #[test]
    fn rejects_unregistered_legacy_timestamp_pax_keys() {
        let mut pax = Vec::new();
        pax.extend_from_slice(&pax_record("atime", b"1.123456789"));
        pax.extend_from_slice(&pax_record("ctime", b"2.123456789"));
        pax.extend_from_slice(&pax_record("mtime", b"3.123456789"));
        let mut bytes = member(b"PaxHeaders/file", b'x', &pax, b"");
        bytes.extend_from_slice(&member(b"file.txt", b'0', b"abc", b""));

        assert!(parse_tar_member_group(&bytes, 4096).is_err());
    }

    #[test]
    fn rejects_noncanonical_sparse_and_unknown_pax_keys() {
        let mut pax = Vec::new();
        pax.extend_from_slice(&pax_record("GNU.sparse.realsize", b"1024"));
        pax.extend_from_slice(&pax_record("GNU.sparse.map", b"0,1"));
        pax.extend_from_slice(&pax_record("comment", b"ignored"));
        let mut bytes = member(b"PaxHeaders/file", b'x', &pax, b"");
        bytes.extend_from_slice(&member(b"file.txt", b'0', b"abc", b""));

        assert!(parse_tar_member_group(&bytes, 4096).is_err());
    }

    #[test]
    fn rejects_mixed_unregistered_local_pax_keys() {
        let mut pax = Vec::new();
        pax.extend_from_slice(&pax_record("SCHILY.xattr.user.comment", b"hello"));
        pax.extend_from_slice(&pax_record("GNU.sparse.realsize", b"1024"));
        pax.extend_from_slice(&pax_record("mtime", b"1.123456789"));
        pax.extend_from_slice(&pax_record("comment", b"ignored"));
        let mut bytes = member(b"PaxHeaders/file", b'x', &pax, b"");
        bytes.extend_from_slice(&member(b"file.txt", b'0', b"abc", b""));

        assert!(parse_tar_member_group(&bytes, 4096).is_err());
    }

    #[test]
    fn rejects_platform_escape_paths() {
        for path in [
            b"/abs".as_slice(),
            b"../up".as_slice(),
            b"a//b".as_slice(),
            b"a\\b".as_slice(),
            b"a:b".as_slice(),
            b"CON".as_slice(),
        ] {
            let bytes = member(path, b'0', b"", b"");
            assert_eq!(
                parse_tar_member_group(&bytes, 4096).unwrap_err(),
                FormatError::UnsafeArchivePath
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn safe_restore_rejects_symlink_parent() {
        let tmp = tempdir().unwrap();
        let outside = tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), tmp.path().join("link")).unwrap();

        let member = OwnedTarMember {
            path: b"link/file.txt".to_vec(),
            kind: TarEntryKind::Regular,
            data: b"blocked".to_vec(),
            link_target: None,
            mode: 0o644,
            mtime: ArchiveTimestamp::UNIX_EPOCH,
            logical_size: 7,
            reparse_placeholder: false,
            v45_metadata: None,
            diagnostics: Vec::new(),
        };

        assert_eq!(
            restore_tar_member(tmp.path(), &member, SafeExtractionOptions::default()).unwrap_err(),
            FormatError::UnsafeArchivePath
        );
    }

    #[cfg(unix)]
    #[test]
    fn prepared_regular_file_uses_open_parent_after_parent_path_swap() {
        let tmp = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let original_parent = tmp.path().join("a");
        let held_parent = tmp.path().join("held");
        fs::create_dir(&original_parent).unwrap();

        let destination = prepare_destination(
            tmp.path(),
            b"a/file.txt",
            TarEntryKind::Regular,
            SafeExtractionOptions::default(),
        )
        .unwrap();

        fs::rename(&original_parent, &held_parent).unwrap();
        std::os::unix::fs::symlink(outside.path(), &original_parent).unwrap();

        let (temp_leaf, mut file) = create_temp_regular_file(&destination).unwrap();
        file.write_all(b"inside").unwrap();
        publish_regular_file(
            &destination,
            &temp_leaf,
            file,
            SafeExtractionOptions::default(),
        )
        .unwrap();

        assert_eq!(fs::read(held_parent.join("file.txt")).unwrap(), b"inside");
        assert!(!outside.path().join("file.txt").exists());
    }

    #[cfg(windows)]
    #[test]
    fn open_file_publication_preserves_even_and_odd_length_names() {
        let tmp = tempdir().unwrap();
        for name in ["a", "bb"] {
            let destination = prepare_destination(
                tmp.path(),
                name.as_bytes(),
                TarEntryKind::Regular,
                SafeExtractionOptions::default(),
            )
            .unwrap();
            let (temp_leaf, mut file) = create_temp_regular_file(&destination).unwrap();
            file.write_all(name.as_bytes()).unwrap();
            publish_regular_file(
                &destination,
                &temp_leaf,
                file,
                SafeExtractionOptions::default(),
            )
            .unwrap();
            assert_eq!(fs::read(tmp.path().join(name)).unwrap(), name.as_bytes());
        }
        let mut names = fs::read_dir(tmp.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(names, ["a", "bb"]);
    }

    #[cfg(unix)]
    #[test]
    fn create_directory_rechecks_leaf_without_following_symlink() {
        let tmp = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let destination = prepare_destination(
            tmp.path(),
            b"dir",
            TarEntryKind::Directory,
            SafeExtractionOptions::default(),
        )
        .unwrap();

        std::os::unix::fs::symlink(outside.path(), tmp.path().join("dir")).unwrap();

        assert_eq!(
            create_directory(&destination).unwrap_err(),
            FormatError::UnsafeArchivePath
        );
        assert!(outside.path().read_dir().unwrap().next().is_none());
    }

    #[test]
    fn safe_restore_requires_hardlink_target_to_be_existing_regular_file() {
        let tmp = tempdir().unwrap();
        fs::write(tmp.path().join("target.txt"), b"target").unwrap();
        let member = OwnedTarMember {
            path: b"linked.txt".to_vec(),
            kind: TarEntryKind::Hardlink,
            data: Vec::new(),
            link_target: Some(b"target.txt".to_vec()),
            mode: 0o644,
            mtime: ArchiveTimestamp::UNIX_EPOCH,
            logical_size: 0,
            reparse_placeholder: false,
            v45_metadata: None,
            diagnostics: Vec::new(),
        };

        restore_tar_member(tmp.path(), &member, SafeExtractionOptions::default()).unwrap();
        assert_eq!(fs::read(tmp.path().join("linked.txt")).unwrap(), b"target");
    }

    #[cfg(unix)]
    #[test]
    fn restore_applies_regular_file_mode_metadata() {
        let tmp = tempdir().unwrap();
        let member = OwnedTarMember {
            path: b"script.sh".to_vec(),
            kind: TarEntryKind::Regular,
            data: b"#!/bin/sh\n".to_vec(),
            link_target: None,
            mode: 0o755,
            mtime: ArchiveTimestamp::UNIX_EPOCH,
            logical_size: 10,
            reparse_placeholder: false,
            v45_metadata: None,
            diagnostics: Vec::new(),
        };

        let diagnostics =
            restore_tar_member(tmp.path(), &member, SafeExtractionOptions::default()).unwrap();

        assert!(diagnostics.is_empty());
        let mode = fs::metadata(tmp.path().join("script.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755);
    }

    #[test]
    fn restore_applies_regular_file_mtime_metadata() {
        let tmp = tempdir().unwrap();
        let member = OwnedTarMember {
            path: b"dated.txt".to_vec(),
            kind: TarEntryKind::Regular,
            data: b"dated".to_vec(),
            link_target: None,
            mode: 0o666,
            mtime: ArchiveTimestamp::from_seconds(1_700_000_000),
            logical_size: 5,
            reparse_placeholder: false,
            v45_metadata: None,
            diagnostics: Vec::new(),
        };

        let diagnostics =
            restore_tar_member(tmp.path(), &member, SafeExtractionOptions::default()).unwrap();

        assert!(diagnostics.is_empty());
        let modified = fs::metadata(tmp.path().join("dated.txt"))
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(modified, 1_700_000_000);
    }

    #[test]
    fn restore_revalidates_symlink_targets_from_owned_members() {
        let tmp = tempdir().unwrap();
        let member = OwnedTarMember {
            path: b"link".to_vec(),
            kind: TarEntryKind::Symlink,
            data: Vec::new(),
            link_target: Some(b"/outside".to_vec()),
            mode: 0o644,
            mtime: ArchiveTimestamp::UNIX_EPOCH,
            logical_size: 0,
            reparse_placeholder: false,
            v45_metadata: None,
            diagnostics: Vec::new(),
        };

        assert_eq!(
            restore_tar_member(tmp.path(), &member, SafeExtractionOptions::default()).unwrap_err(),
            FormatError::UnsafeArchivePath
        );
        assert!(!tmp.path().join("link").exists());
    }

    #[test]
    fn skipped_entries_do_not_create_destination_parents() {
        let tmp = tempdir().unwrap();
        for (path, kind, target) in [
            (
                b"symlink-parent/link".as_slice(),
                TarEntryKind::Symlink,
                Some(b"target".to_vec()),
            ),
            (b"special-parent/fifo".as_slice(), TarEntryKind::Fifo, None),
        ] {
            let member = OwnedTarMember {
                path: path.to_vec(),
                kind,
                data: Vec::new(),
                link_target: target,
                mode: 0o644,
                mtime: ArchiveTimestamp::UNIX_EPOCH,
                logical_size: 0,
                reparse_placeholder: false,
                v45_metadata: None,
                diagnostics: Vec::new(),
            };
            restore_tar_member(
                tmp.path(),
                &member,
                SafeExtractionOptions {
                    restore_policy: RestorePolicy::Content,
                    ..SafeExtractionOptions::default()
                },
            )
            .unwrap();
        }

        assert!(!tmp.path().join("symlink-parent").exists());
        assert!(!tmp.path().join("special-parent").exists());
    }

    #[test]
    fn safe_restore_rejects_directory_over_existing_file_even_with_overwrite() {
        let tmp = tempdir().unwrap();
        let conflict = tmp.path().join("conflict");
        fs::write(&conflict, b"not a directory").unwrap();
        let member = OwnedTarMember {
            path: b"conflict".to_vec(),
            kind: TarEntryKind::Directory,
            data: Vec::new(),
            link_target: None,
            mode: 0o644,
            mtime: ArchiveTimestamp::UNIX_EPOCH,
            logical_size: 0,
            reparse_placeholder: false,
            v45_metadata: None,
            diagnostics: Vec::new(),
        };

        assert_eq!(
            restore_tar_member(
                tmp.path(),
                &member,
                SafeExtractionOptions {
                    overwrite_existing: true,
                    ..SafeExtractionOptions::default()
                }
            )
            .unwrap_err(),
            FormatError::UnsafeOverwrite
        );
        assert!(conflict.is_file());
    }

    #[test]
    fn hardlink_target_checks_use_component_position_not_value() {
        let tmp = tempdir().unwrap();
        fs::create_dir(tmp.path().join("a")).unwrap();
        fs::write(tmp.path().join("a").join("a"), b"target").unwrap();
        let member = OwnedTarMember {
            path: b"linked.txt".to_vec(),
            kind: TarEntryKind::Hardlink,
            data: Vec::new(),
            link_target: Some(b"a/a".to_vec()),
            mode: 0o644,
            mtime: ArchiveTimestamp::UNIX_EPOCH,
            logical_size: 0,
            reparse_placeholder: false,
            v45_metadata: None,
            diagnostics: Vec::new(),
        };

        restore_tar_member(tmp.path(), &member, SafeExtractionOptions::default()).unwrap();
        assert_eq!(fs::read(tmp.path().join("linked.txt")).unwrap(), b"target");
    }

    #[test]
    fn hardlink_targets_obey_max_path_length() {
        let bytes = member(b"link", b'1', b"", b"long/name");

        assert_eq!(
            parse_tar_member_group(&bytes, 4).unwrap_err(),
            FormatError::UnsafeArchivePath
        );
    }

    fn member_summary(bytes: &[u8], group_start: u64) -> TarStreamMemberSummary {
        let parsed = parse_tar_member_group(bytes, 4096).unwrap();
        TarStreamMemberSummary {
            path: parsed.path,
            kind: parsed.kind,
            link_target: parsed.link_target,
            mode: parsed.mode,
            mtime: parsed.mtime,
            logical_size: parsed.logical_size,
            file_entry_flags: parsed.v45_metadata.file_entry_flags,
            reparse_placeholder: parsed.reparse_placeholder,
            v45_metadata: parsed.v45_metadata,
            diagnostics: parsed.diagnostics,
            group_start,
            group_size: bytes.len() as u64,
        }
    }

    #[test]
    fn member_graph_accepts_hardlink_target_after_alias_and_rejects_mirror_mismatch() {
        let alias_bytes = member(b"alias.txt", b'1', b"", b"target.txt");
        let target_bytes = member(b"target.txt", b'0', b"payload", b"");
        let alias = member_summary(&alias_bytes, 0);
        let target = member_summary(&target_bytes, alias_bytes.len() as u64);
        assert!(validate_v45_member_graph(&[alias.clone(), target.clone()]).is_ok());

        let mut mismatched_alias = alias;
        mismatched_alias.v45_metadata.portable_mirror.mode = 0o600;
        assert_eq!(
            validate_v45_member_graph(&[mismatched_alias, target]).unwrap_err(),
            FormatError::InvalidArchive(
                "hardlink portable metadata mirror differs from canonical target"
            )
        );
    }

    #[test]
    fn member_graph_rejects_writes_below_selected_symlink() {
        let link_bytes = member(b"dir", b'2', b"", b"target");
        let child_bytes = member(b"dir/file.txt", b'0', b"payload", b"");
        let link = member_summary(&link_bytes, 0);
        let child = member_summary(&child_bytes, link_bytes.len() as u64);

        assert_eq!(
            validate_v45_member_graph(&[link, child]).unwrap_err(),
            FormatError::InvalidArchive(
                "selected path graph traverses a symlink or reparse ancestor"
            )
        );
    }

    #[test]
    fn partial_capture_diagnostics_preserve_authenticated_omission_details() {
        let bytes = member(b"file.txt", b'0', b"payload", b"");
        let parsed = parse_tar_member_group(&bytes, 4096).unwrap();
        let mut metadata = parsed.v45_metadata;
        metadata.declaration.capture_status = CaptureStatus::Partial;
        metadata.capture_report = Some(vec![CaptureReportRow {
            profile: "portable-v1".into(),
            metadata_class: "sparse-layout".into(),
            reason: "changed-during-read".into(),
            encoded_detail: "extent%20map%20changed".into(),
        }]);

        let diagnostics = plan_restore(
            b"file.txt",
            &metadata,
            TarEntryKind::Regular,
            false,
            SafeExtractionOptions {
                allow_degraded: true,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();

        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.profile == "portable-v1"
                && diagnostic.metadata_class == "sparse-layout"
                && diagnostic.operation == MetadataOperation::Capture
                && diagnostic.status == MetadataDiagnosticStatus::Partial
                && diagnostic.message
                    == "capture omission: changed-during-read; detail=extent%20map%20changed"
        }));
    }

    #[test]
    fn content_restore_reports_portable_mode_and_mtime_as_skipped() {
        let bytes = member(b"file.txt", b'0', b"payload", b"");
        let parsed = parse_tar_member_group(&bytes, 4096).unwrap();

        let diagnostics = plan_restore(
            b"file.txt",
            &parsed.v45_metadata,
            TarEntryKind::Regular,
            false,
            SafeExtractionOptions {
                restore_policy: RestorePolicy::Content,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();

        for metadata_class in ["mode", "mtime"] {
            assert!(diagnostics.iter().any(|diagnostic| {
                diagnostic.profile == "portable-v1"
                    && diagnostic.metadata_class == metadata_class
                    && diagnostic.status == MetadataDiagnosticStatus::Skipped
                    && diagnostic.restore_policy == Some(RestorePolicy::Content)
            }));
        }
    }

    #[test]
    fn unsupported_required_profile_needs_explicit_degraded_restore() {
        let bytes = member(b"file.txt", b'0', b"payload", b"");
        let parsed = parse_tar_member_group(&bytes, 4096).unwrap();
        let mut metadata = parsed.v45_metadata;
        metadata
            .declaration
            .required_profiles
            .push("x.com.example.test-v1".into());
        metadata
            .declaration
            .optional_profiles
            .push("x.com.example.optional-v1".into());

        assert_eq!(
            plan_restore(
                b"file.txt",
                &metadata,
                TarEntryKind::Regular,
                false,
                SafeExtractionOptions::default(),
            )
            .unwrap_err(),
            FormatError::ReaderUnsupported(
                "requested restore policy requires an unsupported required profile"
            )
        );
        let diagnostics = plan_restore(
            b"file.txt",
            &metadata,
            TarEntryKind::Regular,
            false,
            SafeExtractionOptions {
                allow_degraded: true,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.profile == "x.com.example.test-v1"
                && diagnostic.metadata_class == "required-profile"
                && diagnostic.status == MetadataDiagnosticStatus::Unsupported
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.profile == "x.com.example.optional-v1"
                && diagnostic.metadata_class == "optional-profile"
                && diagnostic.status == MetadataDiagnosticStatus::Skipped
        }));
    }

    #[test]
    fn portable_directory_metadata_is_supported_without_degradation() {
        let bytes = member(b"dir", b'5', b"", b"");
        let parsed = parse_tar_member_group(&bytes, 4096).unwrap();

        let diagnostics = plan_restore(
            b"dir",
            &parsed.v45_metadata,
            TarEntryKind::Directory,
            false,
            SafeExtractionOptions::default(),
        )
        .unwrap();
        assert!(diagnostics.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exact_linux_restore_rejects_unrecognized_inode_flag_bits() {
        let bytes = member(b"file.txt", b'0', b"payload", b"");
        let parsed = parse_tar_member_group(&bytes, 4096).unwrap();
        let mut metadata = parsed.v45_metadata;
        metadata.declaration.source_os = "linux".into();
        metadata
            .declaration
            .required_profiles
            .push("linux-backup-v1".into());
        metadata.declaration.required_profiles.sort();
        metadata.primary_has_native_scalar = true;
        metadata
            .primary_records
            .insert("TZAP.linux.fsflags".into(), b"0000000080000000".to_vec());

        assert_eq!(
            plan_restore(
                b"file.txt",
                &metadata,
                TarEntryKind::Regular,
                false,
                SafeExtractionOptions {
                    restore_policy: RestorePolicy::System,
                    system_authorized: true,
                    ..SafeExtractionOptions::default()
                },
            )
            .unwrap_err(),
            FormatError::ReaderUnsupported(
                "requested native metadata is not supported by this conformance class"
            )
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_restore_plans_unknown_and_system_flags_without_silently_applying_them() {
        let bytes = member(b"file.txt", b'0', b"payload", b"");
        let parsed = parse_tar_member_group(&bytes, 4096).unwrap();
        let mut metadata = parsed.v45_metadata;
        metadata.declaration.source_os = "macos".into();
        metadata
            .declaration
            .required_profiles
            .extend(["macos-backup-v1".into(), "posix-backup-v1".into()]);
        metadata.declaration.required_profiles.sort();
        metadata.declaration.required_profiles.dedup();
        metadata.primary_has_native_scalar = true;
        // UF_COMPRESSED is retained but deliberately not in the recognized/settable mask;
        // UF_IMMUTABLE is recognized but System-class under the v45 restore policy.
        metadata
            .primary_records
            .insert("TZAP.macos.st-flags".into(), b"0000000000000022".to_vec());

        let diagnostics = plan_restore(
            b"file.txt",
            &metadata,
            TarEntryKind::Regular,
            false,
            SafeExtractionOptions {
                restore_policy: RestorePolicy::SameOs,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.metadata_class == "unrecognized-file-flags"
                && diagnostic.status == MetadataDiagnosticStatus::Skipped
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.metadata_class == "system-file-flags"
                && diagnostic.status == MetadataDiagnosticStatus::Skipped
        }));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_required_unknown_ordinary_flag_needs_explicit_degraded_restore() {
        let bytes = member(b"file.txt", b'0', b"payload", b"");
        let parsed = parse_tar_member_group(&bytes, 4096).unwrap();
        let mut metadata = parsed.v45_metadata;
        metadata.declaration.source_os = "macos".into();
        metadata
            .declaration
            .required_profiles
            .extend(["macos-backup-v1".into(), "posix-backup-v1".into()]);
        metadata.declaration.required_profiles.sort();
        metadata.declaration.required_profiles.dedup();
        metadata.primary_has_native_scalar = true;
        metadata
            .primary_records
            .insert("TZAP.macos.st-flags".into(), b"0000000000000020".to_vec());

        let strict = plan_restore(
            b"file.txt",
            &metadata,
            TarEntryKind::Regular,
            false,
            SafeExtractionOptions {
                restore_policy: RestorePolicy::SameOs,
                ..SafeExtractionOptions::default()
            },
        );
        assert_eq!(
            strict.unwrap_err(),
            FormatError::ReaderUnsupported(
                "requested native metadata is not supported by this conformance class"
            )
        );
        let degraded = plan_restore(
            b"file.txt",
            &metadata,
            TarEntryKind::Regular,
            false,
            SafeExtractionOptions {
                restore_policy: RestorePolicy::SameOs,
                allow_degraded: true,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();
        assert!(degraded.iter().any(|diagnostic| {
            diagnostic.metadata_class == "unrecognized-file-flags"
                && diagnostic.status == MetadataDiagnosticStatus::Skipped
        }));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_unregistered_superuser_flag_stays_system_class() {
        let bytes = member(b"file.txt", b'0', b"payload", b"");
        let parsed = parse_tar_member_group(&bytes, 4096).unwrap();
        let mut metadata = parsed.v45_metadata;
        metadata.declaration.source_os = "macos".into();
        metadata
            .declaration
            .required_profiles
            .extend(["macos-backup-v1".into(), "posix-backup-v1".into()]);
        metadata.declaration.required_profiles.sort();
        metadata.declaration.required_profiles.dedup();
        metadata.primary_has_native_scalar = true;
        // SF_NOUNLINK is Darwin System-class but is not registered for built-in application.
        metadata
            .primary_records
            .insert("TZAP.macos.st-flags".into(), b"0000000000100000".to_vec());

        let same_os = plan_restore(
            b"file.txt",
            &metadata,
            TarEntryKind::Regular,
            false,
            SafeExtractionOptions {
                restore_policy: RestorePolicy::SameOs,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();
        assert!(same_os.iter().any(|diagnostic| {
            diagnostic.metadata_class == "system-file-flags"
                && diagnostic.status == MetadataDiagnosticStatus::Skipped
        }));
        assert_eq!(
            plan_restore(
                b"file.txt",
                &metadata,
                TarEntryKind::Regular,
                false,
                SafeExtractionOptions {
                    restore_policy: RestorePolicy::System,
                    system_authorized: true,
                    ..SafeExtractionOptions::default()
                },
            )
            .unwrap_err(),
            FormatError::ReaderUnsupported(
                "requested native metadata is not supported by this conformance class"
            )
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_system_file_flags_fail_preflight_without_superuser_privilege() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let bytes = member(b"file.txt", b'0', b"payload", b"");
        let parsed = parse_tar_member_group(&bytes, 4096).unwrap();
        let mut metadata = parsed.v45_metadata;
        metadata.declaration.source_os = "macos".into();
        metadata
            .declaration
            .required_profiles
            .extend(["macos-backup-v1".into(), "posix-backup-v1".into()]);
        metadata.declaration.required_profiles.sort();
        metadata.declaration.required_profiles.dedup();
        metadata.primary_has_native_scalar = true;
        metadata
            .primary_records
            .insert("TZAP.macos.st-flags".into(), b"0000000000020000".to_vec());

        assert_eq!(
            plan_restore(
                b"file.txt",
                &metadata,
                TarEntryKind::Regular,
                false,
                SafeExtractionOptions {
                    restore_policy: RestorePolicy::System,
                    system_authorized: true,
                    ..SafeExtractionOptions::default()
                },
            )
            .unwrap_err(),
            FormatError::ReaderUnsupported(
                "requested native metadata is not supported by this conformance class"
            )
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_device_restore_fails_preflight_without_superuser_privilege() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let bytes = member(b"device", b'0', b"", b"");
        let parsed = parse_tar_member_group(&bytes, 4096).unwrap();

        assert_eq!(
            plan_restore(
                b"device",
                &parsed.v45_metadata,
                TarEntryKind::CharacterDevice,
                false,
                SafeExtractionOptions {
                    restore_policy: RestorePolicy::System,
                    system_authorized: true,
                    ..SafeExtractionOptions::default()
                },
            )
            .unwrap_err(),
            FormatError::ReaderUnsupported(
                "requested native metadata is not supported by this conformance class"
            )
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_resource_fork_support_is_primary_kind_aware() {
        let record = AuxiliaryRecord {
            ordinal: 0,
            kind: "macos.resource-fork".into(),
            profile: "macos-backup-v1".into(),
            restore_class: RestoreClass::SameOs,
            native: true,
            name_encoding: "none".into(),
            decoded_name: Vec::new(),
            flags: 0,
            logical_size: u64::from(u32::MAX) + 1,
            stored_size: 0,
            sha256: [0; 32],
            meta: BTreeMap::new(),
            sparse_layout: None,
            capture_report_payload: None,
        };
        assert!(native_auxiliary_restore_supported(
            &record,
            false,
            Some(TarEntryKind::Regular)
        ));
        assert!(!native_auxiliary_restore_supported(
            &record,
            false,
            Some(TarEntryKind::Symlink)
        ));
        assert!(!native_auxiliary_restore_supported(
            &record,
            false,
            Some(TarEntryKind::Fifo)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn generic_xattr_auxiliary_failure_is_bound_to_pinned_special_object() {
        use sha2::{Digest as _, Sha256};
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt as _;

        let temp = tempfile::tempdir().unwrap();
        let fifo = temp.path().join("events.fifo");
        let fifo_c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        let value = b"member-bound auxiliary value";
        let mut staged_file = tempfile::tempfile().unwrap();
        staged_file.write_all(value).unwrap();
        staged_file.seek(SeekFrom::Start(0)).unwrap();
        let mut staged = vec![StagedAuxiliary {
            record: AuxiliaryRecord {
                ordinal: 0,
                kind: "generic.xattr".into(),
                profile: "posix-backup-v1".into(),
                restore_class: RestoreClass::SameOs,
                native: true,
                name_encoding: "bytes".into(),
                decoded_name: b"user.tzap-aux".to_vec(),
                flags: 0,
                logical_size: value.len() as u64,
                stored_size: value.len() as u64,
                sha256: Sha256::digest(value).into(),
                meta: BTreeMap::new(),
                sparse_layout: None,
                capture_report_payload: None,
            },
            file: staged_file,
        }];
        let mut diagnostics = Vec::new();

        apply_generic_xattr_auxiliaries_to_path(
            &fifo,
            true,
            b"events.fifo",
            &mut staged,
            SafeExtractionOptions {
                restore_policy: RestorePolicy::SameOs,
                allow_degraded: true,
                ..SafeExtractionOptions::default()
            },
            &mut diagnostics,
        )
        .unwrap();

        assert!(staged.is_empty());
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.metadata_class == "extended-attribute"
                && diagnostic.status == MetadataDiagnosticStatus::Failed
        }));
        assert_eq!(xattr::get(&fifo, "user.tzap-aux").unwrap(), None);
    }

    #[test]
    fn sparse_layout_materialization_requires_explicit_degraded_portable_restore() {
        let bytes = member(b"sparse.bin", b'0', b"data", b"");
        let mut parsed = parse_tar_member_group(&bytes, 4096).unwrap();
        parsed.v45_metadata.file_entry_flags |= HAS_SPARSE_EXTENTS;

        let strict = plan_restore(
            b"sparse.bin",
            &parsed.v45_metadata,
            TarEntryKind::Regular,
            false,
            SafeExtractionOptions::default(),
        );
        #[cfg(any(windows, target_os = "linux"))]
        assert!(strict.unwrap().is_empty());
        #[cfg(not(any(windows, target_os = "linux")))]
        assert_eq!(
            strict.unwrap_err(),
            FormatError::ReaderUnsupported(
                "sparse layout materialization needs explicit degraded restore"
            )
        );

        let degraded = plan_restore(
            b"sparse.bin",
            &parsed.v45_metadata,
            TarEntryKind::Regular,
            false,
            SafeExtractionOptions {
                allow_degraded: true,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();
        #[cfg(any(windows, target_os = "linux"))]
        assert!(degraded.is_empty());
        #[cfg(not(any(windows, target_os = "linux")))]
        assert!(degraded.iter().any(|diagnostic| {
            diagnostic.metadata_class == "sparse-layout"
                && diagnostic.status == MetadataDiagnosticStatus::Materialized
                && diagnostic.restore_policy == Some(RestorePolicy::Portable)
        }));

        let content = plan_restore(
            b"sparse.bin",
            &parsed.v45_metadata,
            TarEntryKind::Regular,
            false,
            SafeExtractionOptions {
                restore_policy: RestorePolicy::Content,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();
        assert!(content.iter().any(|diagnostic| {
            diagnostic.metadata_class == "sparse-layout"
                && diagnostic.restore_policy == Some(RestorePolicy::Content)
        }));
    }

    #[test]
    fn validate_symlink_target_rules() {
        // Valid absolute symlink target
        assert!(validate_symlink_target(b"sub/link", b"/tmp/abs_target").is_ok());

        // Invalid absolute symlink target with non-NFC characters
        let non_nfc_abs = "/tmp/abs_\u{0065}\u{0301}";
        assert!(validate_symlink_target(b"sub/link", non_nfc_abs.as_bytes()).is_err());

        // Invalid symlink targets containing null, backslash, or colon
        assert!(validate_symlink_target(b"sub/link", b"/tmp/target\0bad").is_err());
        assert!(validate_symlink_target(b"sub/link", b"/tmp/target\\bad").is_err());
        assert!(validate_symlink_target(b"sub/link", b"/tmp/target:bad").is_err());

        // Valid relative target within sub directory
        assert!(validate_symlink_target(b"sub/link", b"../file.txt").is_ok());

        // Invalid relative target escaping root
        assert!(validate_symlink_target(b"sub/link", b"../../file.txt").is_err());
    }
}
