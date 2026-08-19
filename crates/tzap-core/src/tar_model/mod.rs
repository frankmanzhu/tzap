use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt, SystemTimeSpec};
use cap_std::ambient_authority;
use cap_std::fs::{Dir as CapDir, OpenOptions as CapOpenOptions};
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
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;

use crate::entry_metadata::{
    decode_percent_name, parse_canonical_pax, parse_primary_metadata, ArchiveTimestamp, AuxiliaryRecord, AuxiliaryStreamValidator, CaptureStatus,
    MemberMetadata, PaxRecords, PortableMetadataMirror, RestoreClass, RestorePolicy, SparseExtent, SparseStreamValidator, HAS_NATIVE_METADATA,
    HAS_SPARSE_EXTENTS, MAX_AGGREGATE_PAX_PAYLOAD, MAX_LOCAL_PAX_PAYLOAD,
};
use crate::format::{ExtractError, FormatError};
use crate::metadata::validate_file_path_bytes;

pub mod os_restore;
pub mod pax;
pub mod restore;
pub mod sparse;

#[cfg(test)]
mod tests;

pub(crate) use os_restore::*;
pub use pax::*;
pub(crate) use restore::*;

const TAR_BLOCK_LEN: usize = 512;

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
            let logical_len =
                usize::try_from(layout.logical_size).map_err(|_| FormatError::ReaderUnsupported("sparse logical size exceeds platform limits"))?;
            let mut logical = vec![0u8; logical_len];
            let mut stored_cursor = layout.map_and_padding_size;
            for extent in &layout.extents {
                let extent_len = usize::try_from(extent.length).map_err(|_| FormatError::ReaderUnsupported("sparse extent exceeds platform limits"))?;
                let stored_end = stored_cursor.checked_add(extent_len).ok_or(FormatError::InvalidArchive("sparse stored range overflow"))?;
                let logical_start = usize::try_from(extent.offset).map_err(|_| FormatError::ReaderUnsupported("sparse offset exceeds platform limits"))?;
                let logical_end = logical_start.checked_add(extent_len).ok_or(FormatError::InvalidArchive("sparse logical range overflow"))?;
                logical
                    .get_mut(logical_start..logical_end)
                    .ok_or(FormatError::InvalidArchive("sparse logical range is invalid"))?
                    .copy_from_slice(self.data.get(stored_cursor..stored_end).ok_or(FormatError::InvalidArchive("sparse stored range is invalid"))?);
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

pub(super) fn checked_u64_add(lhs: u64, rhs: u64) -> Result<u64, FormatError> {
    lhs.checked_add(rhs).ok_or(FormatError::InvalidArchive("tar member arithmetic overflow"))
}
pub(crate) fn validate_symlink_target(link_path: &[u8], target: &[u8]) -> Result<(), FormatError> {
    if target.is_empty() || target.contains(&0) || target.contains(&b'\\') || target.contains(&b':') {
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
    let mut stack = link_path.split('/').take(link_path.split('/').count().saturating_sub(1)).map(str::to_owned).collect::<Vec<_>>();
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

pub(super) fn path_components(path: &[u8]) -> Result<Vec<String>, FormatError> {
    validate_file_path_bytes(path, u32::MAX)?;
    let path = std::str::from_utf8(path).map_err(|_| FormatError::UnsafeArchivePath)?;
    Ok(path.split('/').map(str::to_owned).collect())
}

pub(super) fn ustar_path(header: &[u8]) -> Vec<u8> {
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

pub(super) fn verify_tar_checksum(header: &[u8]) -> Result<(), FormatError> {
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

pub(super) fn parse_tar_octal(field: &[u8]) -> Result<u64, FormatError> {
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

pub(super) fn nul_trimmed(bytes: &[u8]) -> &[u8] {
    let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
    &bytes[..end]
}

pub(super) fn padding_to_512(len: usize) -> usize {
    let remainder = len % TAR_BLOCK_LEN;
    if remainder == 0 {
        0
    } else {
        TAR_BLOCK_LEN - remainder
    }
}

pub(super) fn padding_to_512_u64(len: u64) -> u64 {
    let remainder = len % TAR_BLOCK_LEN as u64;
    if remainder == 0 {
        0
    } else {
        TAR_BLOCK_LEN as u64 - remainder
    }
}

pub(super) fn slice(bytes: &[u8], offset: usize, len: usize) -> Result<&[u8], FormatError> {
    let end = checked_add(offset, len)?;
    bytes.get(offset..end).ok_or(FormatError::InvalidLength { structure: "tar member", expected: end, actual: bytes.len() })
}

pub(super) fn checked_add(lhs: usize, rhs: usize) -> Result<usize, FormatError> {
    lhs.checked_add(rhs).ok_or(FormatError::InvalidArchive("tar member arithmetic overflow"))
}

pub(super) fn to_usize(value: u64) -> Result<usize, FormatError> {
    usize::try_from(value).map_err(|_| FormatError::InvalidArchive("tar member size overflow"))
}
