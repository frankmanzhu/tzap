//! Revision-45 per-entry metadata, canonical PAX, and auxiliary-stream rules.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::format::FormatError;

pub const EXTENDED_METADATA_V1: u32 = 1 << 0;
pub const HAS_AUXILIARY_STREAMS: u32 = 1 << 1;
pub const HAS_NATIVE_METADATA: u32 = 1 << 2;
pub const HAS_SPARSE_EXTENTS: u32 = 1 << 3;
pub const CAPTURE_PARTIAL: u32 = 1 << 4;
pub const REQUIRES_SYSTEM_RESTORE: u32 = 1 << 5;
pub const FILE_ENTRY_KNOWN_FLAGS: u32 = (1 << 6) - 1;

pub const MAX_PROFILE_COUNT: usize = 64;
pub const MAX_PROFILE_ID_LEN: usize = 64;
pub const MAX_AUXILIARY_COUNT: usize = 65_535;
pub const MAX_AUXILIARY_NAME_LEN: usize = 65_535;
pub const MAX_LOCAL_PAX_PAYLOAD: usize = 64 * 1024 * 1024;
pub const MAX_AGGREGATE_PAX_PAYLOAD: usize = 128 * 1024 * 1024;
pub const MAX_CAPTURE_REPORT_ROWS: usize = 1_048_576;
pub const MAX_SPARSE_EXTENTS: usize = 1_048_576;

pub const PORTABLE_PROFILE: &str = "portable-v1";
pub const POSIX_PROFILE: &str = "posix-backup-v1";
pub const LINUX_PROFILE: &str = "linux-backup-v1";
pub const MACOS_PROFILE: &str = "macos-backup-v1";
pub const WINDOWS_PROFILE: &str = "windows-backup-v1";
pub const CORE_PROFILE: &str = "tzap-core-v1";
pub const CAPTURE_REPORT_KIND: &str = "tzap.capture-report";

pub type PaxRecords = BTreeMap<String, Vec<u8>>;

/// A revision-45 timestamp represented as signed Unix seconds plus nanoseconds.
///
/// `nanoseconds` must be less than one billion. Writers validate this invariant
/// before serializing the value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArchiveTimestamp {
    pub seconds: i64,
    pub nanoseconds: u32,
}

impl ArchiveTimestamp {
    pub const UNIX_EPOCH: Self = Self::from_seconds(0);

    pub const fn from_seconds(seconds: i64) -> Self {
        Self { seconds, nanoseconds: 0 }
    }

    pub const fn new(seconds: i64, nanoseconds: u32) -> Self {
        Self { seconds, nanoseconds }
    }

    pub fn canonical_pax_value(self) -> Result<Vec<u8>, FormatError> {
        if self.nanoseconds >= 1_000_000_000 {
            return Err(FormatError::WriterUnsupported("timestamp nanoseconds must be less than one billion"));
        }
        if self.nanoseconds == 0 {
            return Ok(self.seconds.to_string().into_bytes());
        }
        let mut buffer = Vec::with_capacity(32);
        use std::io::Write;
        write!(&mut buffer, "{}.{:09}", self.seconds, self.nanoseconds).unwrap();
        while buffer.last() == Some(&b'0') {
            buffer.pop();
        }
        Ok(buffer)
    }
}

impl fmt::Display for ArchiveTimestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.nanoseconds == 0 {
            return write!(formatter, "{}", self.seconds);
        }
        let fraction = format!("{:09}", self.nanoseconds);
        write!(formatter, "{}.{fraction}", self.seconds, fraction = fraction.trim_end_matches('0'))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureStatus {
    Complete,
    Partial,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RestorePolicy {
    Content,
    #[default]
    Portable,
    SameOs,
    System,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RestoreClass {
    None,
    Portable,
    SameOs,
    System,
}

impl RestoreClass {
    fn parse(value: &[u8]) -> Result<Self, FormatError> {
        match value {
            b"none" => Ok(Self::None),
            b"portable" => Ok(Self::Portable),
            b"same-os" => Ok(Self::SameOs),
            b"system" => Ok(Self::System),
            _ => invalid("AuxiliaryMetadata", "invalid restore class"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataDeclaration {
    pub required_profiles: Vec<String>,
    pub optional_profiles: Vec<String>,
    pub source_os: String,
    pub source_filesystem: String,
    pub capture_status: CaptureStatus,
    pub owner_kind_posix: bool,
    pub mode_origin_native: bool,
    pub portable_mode: u32,
    pub portable_attributes: Option<u32>,
}

impl MetadataDeclaration {
    pub fn profile_selected(&self, profile: &str) -> bool {
        self.required_profiles.binary_search_by(|candidate| candidate.as_str().cmp(profile)).is_ok()
            || self.optional_profiles.binary_search_by(|candidate| candidate.as_str().cmp(profile)).is_ok()
    }

    pub fn profile_required(&self, profile: &str) -> bool {
        self.required_profiles.binary_search_by(|candidate| candidate.as_str().cmp(profile)).is_ok()
    }

    pub fn has_unknown_required_profile(&self) -> bool {
        self.required_profiles.iter().any(|profile| !is_known_profile(profile))
    }

    pub fn unknown_required_profiles(&self) -> impl Iterator<Item = &str> {
        self.required_profiles.iter().map(String::as_str).filter(|profile| !is_known_profile(profile))
    }

    pub fn unknown_optional_profiles(&self) -> impl Iterator<Item = &str> {
        self.optional_profiles.iter().map(String::as_str).filter(|profile| !is_known_profile(profile))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparseExtent {
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparseLayout {
    pub logical_size: u64,
    pub map_and_padding_size: usize,
    pub extents: Vec<SparseExtent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuxiliaryRecord {
    pub ordinal: u32,
    pub kind: String,
    pub profile: String,
    pub restore_class: RestoreClass,
    pub native: bool,
    pub name_encoding: String,
    pub decoded_name: Vec<u8>,
    pub flags: u64,
    pub logical_size: u64,
    pub stored_size: u64,
    pub sha256: [u8; 32],
    pub meta: BTreeMap<String, Vec<u8>>,
    pub sparse_layout: Option<SparseLayout>,
    pub capture_report_payload: Option<Vec<u8>>,
}

/// Incrementally validates one revision-45 auxiliary payload. Large ordinary
/// and sparse streams are hashed and structurally checked without retaining
/// their data bytes.
pub struct AuxiliaryStreamValidator {
    record: AuxiliaryRecord,
    hasher: Sha256,
    received: u64,
    sparse: Option<SparseStreamValidator>,
    retained: Option<Vec<u8>>,
    retained_cap: usize,
}

impl AuxiliaryStreamValidator {
    pub fn new(records: &PaxRecords, ordinal: u32, stored_size: u64) -> Result<Self, FormatError> {
        let record = parse_auxiliary_declaration(records, ordinal, stored_size)?;
        let sparse = (record.flags & 1 != 0).then(|| SparseStreamValidator::new(record.logical_size));
        let retained_cap = retained_auxiliary_cap(&record.kind);
        let retained = (retained_cap != 0).then(Vec::new);
        Ok(Self { record, hasher: Sha256::new(), received: 0, sparse, retained, retained_cap })
    }

    pub fn observe(&mut self, bytes: &[u8]) -> Result<(), FormatError> {
        self.received = self.received.checked_add(bytes.len() as u64).ok_or(FormatError::InvalidArchive("auxiliary payload size overflow"))?;
        if self.received > self.record.stored_size {
            return invalid("AuxiliaryMetadata", "auxiliary payload exceeds declared size");
        }
        self.hasher.update(bytes);
        if let Some(sparse) = &mut self.sparse {
            sparse.observe(bytes)?;
        }
        if let Some(retained) = &mut self.retained {
            let next = retained.len().checked_add(bytes.len()).ok_or(FormatError::InvalidArchive("auxiliary retention size overflow"))?;
            if next > self.retained_cap {
                return Err(FormatError::ReaderResourceLimitExceeded {
                    field: "structured auxiliary payload bytes",
                    cap: self.retained_cap as u64,
                    actual: next as u64,
                });
            }
            retained.extend_from_slice(bytes);
        }
        Ok(())
    }

    pub(crate) fn declaration(&self) -> &AuxiliaryRecord {
        &self.record
    }

    pub fn finish(mut self) -> Result<AuxiliaryRecord, FormatError> {
        if self.received != self.record.stored_size {
            return invalid("AuxiliaryMetadata", "auxiliary payload length mismatch");
        }
        if self.hasher.finalize().as_slice() != self.record.sha256 {
            return invalid("AuxiliaryMetadata", "auxiliary payload SHA-256 mismatch");
        }
        self.record.sparse_layout = self.sparse.map(SparseStreamValidator::finish).transpose()?;
        // Retain only the bounded structured kinds selected by
        // `retained_auxiliary_cap`. The historical field name predates native
        // reparse restoration; consumers still gate interpretation by kind.
        self.record.capture_report_payload = self.retained.clone();
        validate_builtin_auxiliary_payload(&self.record, self.retained.as_deref())?;
        Ok(self.record)
    }
}

pub(crate) struct SparseStreamValidator {
    logical_size: u64,
    position: u64,
    line: Vec<u8>,
    extent_count: Option<usize>,
    values_remaining: usize,
    pending_offset: Option<u64>,
    previous_end: u64,
    stored_extent_bytes: u64,
    extents: Vec<SparseExtent>,
    map_and_padding_size: Option<u64>,
}

impl SparseStreamValidator {
    pub(crate) fn new(logical_size: u64) -> Self {
        Self {
            logical_size,
            position: 0,
            line: Vec::new(),
            extent_count: None,
            values_remaining: 0,
            pending_offset: None,
            previous_end: 0,
            stored_extent_bytes: 0,
            extents: Vec::new(),
            map_and_padding_size: None,
        }
    }

    pub(crate) fn observe(&mut self, bytes: &[u8]) -> Result<(), FormatError> {
        for byte in bytes {
            if let Some(padded_end) = self.map_and_padding_size {
                if self.position < padded_end && *byte != 0 {
                    return invalid("SparsePayload", "sparse map padding is invalid");
                }
                self.position = self.position.checked_add(1).ok_or(FormatError::InvalidArchive("sparse payload size overflow"))?;
                continue;
            }

            self.position = self.position.checked_add(1).ok_or(FormatError::InvalidArchive("sparse payload size overflow"))?;
            if *byte != b'\n' {
                if self.line.len() == 20 || !byte.is_ascii_digit() {
                    return invalid("SparsePayload", "sparse map value is not canonical decimal");
                }
                self.line.push(*byte);
                continue;
            }
            let value = parse_decimal_u64(&self.line, "sparse map value")?;
            self.line.clear();
            if self.extent_count.is_none() {
                let count = usize::try_from(value)
                    .map_err(|_| FormatError::InvalidMetadata { structure: "sparse extent count", reason: "decimal value exceeds usize" })?;
                if count > MAX_SPARSE_EXTENTS {
                    return Err(FormatError::ReaderResourceLimitExceeded {
                        field: "sparse extent count",
                        cap: MAX_SPARSE_EXTENTS as u64,
                        actual: count as u64,
                    });
                }
                self.extent_count = Some(count);
                self.values_remaining = count.checked_mul(2).ok_or(FormatError::InvalidArchive("sparse extent count overflow"))?;
                self.extents.reserve(count);
            } else if self.values_remaining != 0 {
                if self.pending_offset.is_none() {
                    self.pending_offset = Some(value);
                } else {
                    let offset = self.pending_offset.take().unwrap();
                    let length = value;
                    if length == 0 || offset < self.previous_end {
                        return invalid("SparsePayload", "extents overlap or have zero length");
                    }
                    if !self.extents.is_empty() && offset == self.previous_end {
                        return invalid("SparsePayload", "adjacent extents are not merged");
                    }
                    let end = offset.checked_add(length).ok_or(FormatError::InvalidArchive("sparse extent overflow"))?;
                    if end > self.logical_size {
                        return invalid("SparsePayload", "extent exceeds logical size");
                    }
                    self.stored_extent_bytes =
                        self.stored_extent_bytes.checked_add(length).ok_or(FormatError::InvalidArchive("sparse stored size overflow"))?;
                    self.previous_end = end;
                    self.extents.push(SparseExtent { offset, length });
                }
                self.values_remaining -= 1;
            } else {
                return invalid("SparsePayload", "sparse map has trailing lines");
            }

            if self.extent_count.is_some() && self.values_remaining == 0 {
                self.map_and_padding_size = Some(self.position.checked_add(511).ok_or(FormatError::InvalidArchive("sparse map padding overflow"))? / 512 * 512);
            }
        }
        Ok(())
    }

    pub(crate) fn layout_if_map_complete(&self) -> Option<SparseLayout> {
        self.map_and_padding_size.map(|padded| SparseLayout {
            logical_size: self.logical_size,
            map_and_padding_size: padded as usize,
            extents: self.extents.clone(),
        })
    }

    pub(crate) fn position(&self) -> u64 {
        self.position
    }

    pub(crate) fn finish(self) -> Result<SparseLayout, FormatError> {
        if !self.line.is_empty() || self.extent_count.is_none() || self.values_remaining != 0 {
            return invalid("SparsePayload", "sparse map is truncated");
        }
        let padded = self.map_and_padding_size.ok_or(FormatError::InvalidArchive("sparse map is missing"))?;
        if self.position < padded || self.position - padded != self.stored_extent_bytes {
            return invalid("SparsePayload", "sparse extent bytes do not match map");
        }
        Ok(SparseLayout {
            logical_size: self.logical_size,
            map_and_padding_size: usize::try_from(padded).map_err(|_| FormatError::InvalidArchive("sparse map size exceeds platform limits"))?,
            extents: self.extents,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureReportRow {
    pub profile: String,
    pub metadata_class: String,
    pub reason: String,
    pub encoded_detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrimaryMetadata {
    pub declaration: MetadataDeclaration,
    pub path: Option<Vec<u8>>,
    pub linkpath: Option<Vec<u8>>,
    pub stored_size: Option<u64>,
    pub mtime: Option<(i64, u32)>,
    pub sparse_logical_size: Option<u64>,
    pub has_native_scalar: bool,
    pub requires_system_restore: bool,
    pub xattr_names: Vec<Vec<u8>>,
}

/// Decoded portable fields that hardlink aliases must mirror exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortableMetadataMirror {
    pub owner_kind_posix: bool,
    pub mode_origin_native: bool,
    pub mode: u32,
    pub attributes: Option<u32>,
    pub uid: Option<u64>,
    pub gid: Option<u64>,
    pub uname: Option<Vec<u8>>,
    pub gname: Option<Vec<u8>>,
    pub mtime: (i64, u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberMetadata {
    pub declaration: MetadataDeclaration,
    /// Authenticated canonical primary PAX records retained for native restore.
    pub primary_records: PaxRecords,
    pub auxiliary: Vec<AuxiliaryRecord>,
    pub file_entry_flags: u32,
    pub sparse_layout: Option<SparseLayout>,
    pub capture_report: Option<Vec<CaptureReportRow>>,
    pub primary_has_native_scalar: bool,
    pub primary_requires_system_restore: bool,
    pub portable_mirror: PortableMetadataMirror,
}

pub fn parse_canonical_pax(payload: &[u8]) -> Result<PaxRecords, FormatError> {
    if payload.is_empty() {
        return invalid("PAX", "payload is empty");
    }
    if payload.len() > MAX_LOCAL_PAX_PAYLOAD {
        return Err(FormatError::ReaderResourceLimitExceeded {
            field: "local PAX payload bytes",
            cap: MAX_LOCAL_PAX_PAYLOAD as u64,
            actual: payload.len() as u64,
        });
    }

    let mut records = BTreeMap::new();
    let mut previous_key: Option<String> = None;
    let mut cursor = 0usize;
    while cursor < payload.len() {
        let relative_space = payload[cursor..].iter().position(|byte| *byte == b' ').ok_or(FormatError::InvalidArchive("PAX record length is missing"))?;
        let space = cursor.checked_add(relative_space).ok_or(FormatError::InvalidArchive("PAX arithmetic overflow"))?;
        let digits = &payload[cursor..space];
        if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) || (digits.len() > 1 && digits[0] == b'0') {
            return invalid("PAX", "record length is not minimal decimal");
        }
        let declared = parse_decimal_usize(digits, "PAX record length")?;
        if declared.to_string().as_bytes() != digits {
            return invalid("PAX", "record length is not canonical");
        }
        let end = cursor.checked_add(declared).ok_or(FormatError::InvalidArchive("PAX arithmetic overflow"))?;
        if end > payload.len() || end <= space + 2 || payload[end - 1] != b'\n' {
            return invalid("PAX", "record length does not frame one record");
        }
        let body = &payload[space + 1..end - 1];
        let equals = body.iter().position(|byte| *byte == b'=').ok_or(FormatError::InvalidArchive("PAX record equals sign is missing"))?;
        let key_bytes = &body[..equals];
        let value = &body[equals + 1..];
        if key_bytes.is_empty() || !key_bytes.iter().all(|byte| (0x21..=0x7e).contains(byte) && *byte != b'=') {
            return invalid("PAX", "key is not canonical ASCII");
        }
        if value.contains(&0) {
            return invalid("PAX", "value contains NUL");
        }
        let key = std::str::from_utf8(key_bytes).map_err(|_| FormatError::InvalidArchive("PAX key is not ASCII"))?.to_owned();
        if previous_key.as_ref().is_some_and(|previous| previous >= &key) {
            return invalid("PAX", "keys are not strictly sorted and unique");
        }
        previous_key = Some(key.clone());
        records.insert(key, value.to_vec());
        cursor = end;
    }
    Ok(records)
}

pub fn encode_canonical_pax(records: &PaxRecords) -> Result<Vec<u8>, FormatError> {
    if records.is_empty() {
        return Err(FormatError::WriterInvariant("PAX payload cannot be empty"));
    }
    let mut out = Vec::new();
    for (key, value) in records {
        if key.is_empty() || !key.as_bytes().iter().all(|byte| (0x21..=0x7e).contains(byte) && *byte != b'=') || value.contains(&0) {
            return Err(FormatError::WriterInvariant("invalid canonical PAX record"));
        }
        let body_len =
            key.len().checked_add(value.len()).and_then(|value| value.checked_add(3)).ok_or(FormatError::WriterInvariant("PAX record length overflow"))?;
        let mut digits = 1usize;
        let record_len = loop {
            let length = digits.checked_add(body_len).ok_or(FormatError::WriterInvariant("PAX record length overflow"))?;
            let next_digits = length.to_string().len();
            if next_digits == digits {
                break length;
            }
            digits = next_digits;
        };
        out.extend_from_slice(record_len.to_string().as_bytes());
        out.push(b' ');
        out.extend_from_slice(key.as_bytes());
        out.push(b'=');
        out.extend_from_slice(value);
        out.push(b'\n');
    }
    if out.len() > MAX_LOCAL_PAX_PAYLOAD {
        return Err(FormatError::WriterUnsupported("local PAX payload exceeds revision-45 limit"));
    }
    Ok(out)
}

pub fn portable_primary_pax(path: &[u8], mode: u32, source_os: &str, path_requires_override: bool) -> Result<PaxRecords, FormatError> {
    if mode & !0x0fff != 0 {
        return Err(FormatError::WriterUnsupported("portable mode contains bits outside revision-45 mode mask"));
    }
    if !is_source_os(source_os) {
        return Err(FormatError::WriterUnsupported("invalid metadata source OS"));
    }
    let mut records = PaxRecords::new();
    records.insert("TZAP.metadata.capture-status".into(), b"complete".to_vec());
    records.insert("TZAP.metadata.optional-profiles".into(), Vec::new());
    records.insert("TZAP.metadata.required-profiles".into(), PORTABLE_PROFILE.as_bytes().to_vec());
    records.insert("TZAP.metadata.source-filesystem".into(), b"unknown".to_vec());
    records.insert("TZAP.metadata.source-os".into(), source_os.as_bytes().to_vec());
    records.insert("TZAP.metadata.version".into(), b"1".to_vec());
    records.insert("TZAP.portable.mode".into(), hex::encode(mode.to_be_bytes()).into_bytes());
    records.insert("TZAP.portable.mode-origin".into(), b"projected".to_vec());
    records.insert("TZAP.portable.owner-kind".into(), b"none".to_vec());
    if path_requires_override {
        records.insert("path".into(), path.to_vec());
    }
    Ok(records)
}

pub fn parse_primary_metadata(records: &PaxRecords) -> Result<PrimaryMetadata, FormatError> {
    validate_primary_key_registry(records)?;
    expect_value(records, "TZAP.metadata.version", b"1", "PrimaryMetadata")?;
    let required_profiles = parse_profile_list(required(records, "TZAP.metadata.required-profiles")?)?;
    let optional_profiles = parse_profile_list(required(records, "TZAP.metadata.optional-profiles")?)?;
    validate_profile_sets(&required_profiles, &optional_profiles)?;

    let source_os = ascii_string(required(records, "TZAP.metadata.source-os")?, "source OS")?;
    if !is_source_os(&source_os) {
        return invalid("PrimaryMetadata", "unknown source OS");
    }
    let source_filesystem = ascii_string(required(records, "TZAP.metadata.source-filesystem")?, "source filesystem")?;
    if !valid_filesystem_token(&source_filesystem) {
        return invalid("PrimaryMetadata", "invalid source filesystem token");
    }
    validate_profile_dependencies(&required_profiles, &optional_profiles, &source_os)?;

    let capture_status = match required(records, "TZAP.metadata.capture-status")? {
        b"complete" => CaptureStatus::Complete,
        b"partial" => CaptureStatus::Partial,
        _ => return invalid("PrimaryMetadata", "invalid capture status"),
    };
    let owner_kind_posix = match required(records, "TZAP.portable.owner-kind")? {
        b"none" => false,
        b"posix" => true,
        _ => return invalid("PrimaryMetadata", "invalid portable owner kind"),
    };
    let mode_origin_native = match required(records, "TZAP.portable.mode-origin")? {
        b"projected" => false,
        b"native" => true,
        _ => return invalid("PrimaryMetadata", "invalid portable mode origin"),
    };
    let portable_mode = parse_fixed_hex_u32(required(records, "TZAP.portable.mode")?, 8, "portable mode")?;
    if portable_mode & !0x0fff != 0 {
        return invalid("PrimaryMetadata", "portable mode has reserved bits");
    }
    let portable_attributes = records.get("TZAP.portable.attributes").map(|value| parse_fixed_hex_u32(value, 8, "portable attributes")).transpose()?;
    if portable_attributes.is_some_and(|value| value & !0x0f != 0) {
        return invalid("PrimaryMetadata", "portable attributes have reserved bits");
    }

    validate_owner_fields(records, owner_kind_posix)?;
    let xattr_names = validate_scalar_encodings(records)?;
    validate_acl_fields(records)?;
    validate_profile_owned_primary_fields(records, &required_profiles, &optional_profiles, &source_os)?;

    let path = records.get("path").cloned();
    let linkpath = records.get("linkpath").cloned();
    let stored_size = records.get("size").map(|value| parse_decimal_u64(value, "PAX size")).transpose()?;
    let mtime = records.get("mtime").map(|value| parse_timestamp(value)).transpose()?;

    let sparse_keys = ["GNU.sparse.major", "GNU.sparse.minor", "GNU.sparse.name", "GNU.sparse.realsize"];
    let sparse_count = sparse_keys.iter().filter(|key| records.contains_key(**key)).count();
    let sparse_logical_size = if sparse_count == 0 {
        None
    } else {
        if sparse_count != sparse_keys.len() {
            return invalid("PrimaryMetadata", "incomplete GNU sparse 1.0 declaration");
        }
        expect_value(records, "GNU.sparse.major", b"1", "PrimaryMetadata")?;
        expect_value(records, "GNU.sparse.minor", b"0", "PrimaryMetadata")?;
        Some(parse_decimal_u64(required(records, "GNU.sparse.realsize")?, "GNU sparse logical size")?)
    };

    let declaration = MetadataDeclaration {
        required_profiles,
        optional_profiles,
        source_os,
        source_filesystem,
        capture_status,
        owner_kind_posix,
        mode_origin_native,
        portable_mode,
        portable_attributes,
    };
    let has_native_scalar = records.keys().any(is_native_primary_key);
    let windows_stream_security = records
        .get("TZAP.windows.data-stream-attributes")
        .map(|value| parse_fixed_hex_u32(value, 8, "Windows stream attributes"))
        .transpose()?
        .is_some_and(|value| value & 0x0000_0002 != 0);
    let requires_system_restore = owner_kind_posix
        || portable_mode & 0o6000 != 0
        || windows_stream_security
        || xattr_names.iter().any(|name| system_xattr_namespace(name, &declaration.source_os))
        || has_no_change_flags(records)?
        || records.keys().any(is_system_primary_key);
    Ok(PrimaryMetadata { declaration, path, linkpath, stored_size, mtime, sparse_logical_size, has_native_scalar, requires_system_restore, xattr_names })
}

pub fn parse_auxiliary_record(records: &PaxRecords, ordinal: u32, stored_size: u64, payload: &[u8]) -> Result<AuxiliaryRecord, FormatError> {
    let mut validator = AuxiliaryStreamValidator::new(records, ordinal, stored_size)?;
    validator.observe(payload)?;
    validator.finish()
}

fn parse_auxiliary_declaration(records: &PaxRecords, ordinal: u32, stored_size: u64) -> Result<AuxiliaryRecord, FormatError> {
    let structure = "AuxiliaryMetadata";
    expect_value(records, "TZAP.aux.version", b"1", structure)?;
    for key in records.keys() {
        if !matches!(
            key.as_str(),
            "TZAP.aux.version"
                | "TZAP.aux.kind"
                | "TZAP.aux.profile"
                | "TZAP.aux.restore-class"
                | "TZAP.aux.native"
                | "TZAP.aux.name-encoding"
                | "TZAP.aux.name"
                | "TZAP.aux.flags"
                | "TZAP.aux.logical-size"
                | "TZAP.aux.sha256"
                | "size"
        ) && !key.starts_with("TZAP.aux.meta.")
        {
            return invalid(structure, "unregistered auxiliary PAX key");
        }
    }
    let kind = ascii_string(required(records, "TZAP.aux.kind")?, "auxiliary kind")?;
    if !valid_profile_token(&kind) || !(is_builtin_aux_kind(&kind) || kind.starts_with("x.") && kind.len() > 2) {
        return invalid(structure, "invalid auxiliary kind");
    }
    let profile = ascii_string(required(records, "TZAP.aux.profile")?, "auxiliary profile")?;
    if profile != CORE_PROFILE && !is_valid_profile_id(&profile) {
        return invalid(structure, "invalid auxiliary owner profile");
    }
    let restore_class = RestoreClass::parse(required(records, "TZAP.aux.restore-class")?)?;
    let native = match required(records, "TZAP.aux.native")? {
        b"0" => false,
        b"1" => true,
        _ => return invalid(structure, "invalid auxiliary native flag"),
    };
    let name_encoding = ascii_string(required(records, "TZAP.aux.name-encoding")?, "auxiliary name encoding")?;
    let decoded_name = decode_auxiliary_name(&name_encoding, required(records, "TZAP.aux.name")?)?;
    if decoded_name.len() > MAX_AUXILIARY_NAME_LEN {
        return Err(FormatError::ReaderResourceLimitExceeded {
            field: "decoded auxiliary name bytes",
            cap: MAX_AUXILIARY_NAME_LEN as u64,
            actual: decoded_name.len() as u64,
        });
    }
    let flags = parse_fixed_hex_u64(required(records, "TZAP.aux.flags")?, 16, "auxiliary flags")?;
    if !kind.starts_with("x.") && flags & !1 != 0 {
        return invalid(structure, "built-in auxiliary flags have reserved bits");
    }
    let logical_size = parse_decimal_u64(required(records, "TZAP.aux.logical-size")?, "auxiliary logical size")?;
    if let Some(size) = records.get("size") {
        if parse_decimal_u64(size, "auxiliary PAX size")? != stored_size {
            return invalid(structure, "PAX size does not match auxiliary stored size");
        }
    }
    let sha256 = parse_fixed_hex_32(required(records, "TZAP.aux.sha256")?)?;
    if flags & 1 == 0 && logical_size != stored_size {
        return invalid(structure, "non-sparse logical and stored sizes differ");
    }
    let mut meta = BTreeMap::new();
    for (key, value) in records.iter().filter(|(key, _)| key.starts_with("TZAP.aux.meta.")) {
        let suffix = &key["TZAP.aux.meta.".len()..];
        if !valid_profile_token(suffix) {
            return invalid(structure, "invalid auxiliary metadata field name");
        }
        meta.insert(key.clone(), value.clone());
    }
    let record = AuxiliaryRecord {
        ordinal,
        kind,
        profile,
        restore_class,
        native,
        name_encoding,
        decoded_name,
        flags,
        logical_size,
        stored_size,
        sha256,
        meta,
        sparse_layout: None,
        capture_report_payload: None,
    };
    validate_builtin_auxiliary(&record)?;
    Ok(record)
}

pub(crate) fn parse_auxiliary_declaration_for_writer(records: &PaxRecords, ordinal: u32, stored_size: u64) -> Result<AuxiliaryRecord, FormatError> {
    parse_auxiliary_declaration(records, ordinal, stored_size)
}

pub fn validate_group_metadata(primary: &PrimaryMetadata, auxiliary: &[AuxiliaryRecord]) -> Result<(u32, Option<Vec<CaptureReportRow>>), FormatError> {
    if auxiliary.len() > MAX_AUXILIARY_COUNT {
        return Err(FormatError::ReaderResourceLimitExceeded {
            field: "auxiliary record count",
            cap: MAX_AUXILIARY_COUNT as u64,
            actual: auxiliary.len() as u64,
        });
    }
    let mut identities = BTreeSet::new();
    let mut capture_report = None;
    for record in auxiliary {
        if record.kind == CAPTURE_REPORT_KIND {
            if capture_report.is_some() {
                return invalid("MemberGroup", "duplicate capture report");
            }
            if record.profile != CORE_PROFILE {
                return invalid("MemberGroup", "capture report owner is not tzap-core-v1");
            }
        } else if !primary.declaration.profile_selected(&record.profile) {
            return invalid("MemberGroup", "auxiliary owner profile is not selected");
        }
        if record.kind == "generic.xattr" {
            validate_generic_xattr_declaration(record, &primary.declaration.source_os)?;
        }
        let identity = if record.kind.starts_with("x.") {
            format!("{}\0{}\0", record.profile, record.kind).into_bytes()
        } else {
            let mut value = record.kind.as_bytes().to_vec();
            value.push(0);
            value
        };
        let mut identity = identity;
        identity.extend_from_slice(&record.decoded_name);
        if !identities.insert(identity) {
            return invalid("MemberGroup", "duplicate auxiliary identity");
        }
    }

    let report_records: Vec<_> = auxiliary.iter().filter(|record| record.kind == CAPTURE_REPORT_KIND).collect();
    match primary.declaration.capture_status {
        CaptureStatus::Complete if !report_records.is_empty() => return invalid("MemberGroup", "complete capture has a capture report"),
        CaptureStatus::Partial if report_records.len() != 1 => return invalid("MemberGroup", "partial capture requires one capture report"),
        _ => {}
    }

    if let Some(record) = report_records.first() {
        // The payload has already been hashed by the caller. Capture report parsing is
        // exposed separately for streaming readers that retain its bounded payload.
        capture_report = Some(parse_capture_report(
            record.capture_report_payload.as_deref().ok_or(FormatError::InvalidArchive("capture report payload is missing"))?,
            &primary.declaration,
        )?);
        if record.flags != 0
            || record.profile != CORE_PROFILE
            || record.restore_class != RestoreClass::None
            || record.native
            || record.name_encoding != "none"
            || !record.decoded_name.is_empty()
        {
            return invalid("MemberGroup", "capture report declaration is not canonical");
        }
    }

    let mut flags = EXTENDED_METADATA_V1;
    if !auxiliary.is_empty() {
        flags |= HAS_AUXILIARY_STREAMS;
    }
    if primary.declaration.required_profiles != [PORTABLE_PROFILE]
        || !primary.declaration.optional_profiles.is_empty()
        || primary.has_native_scalar
        || auxiliary.iter().any(|record| record.native)
    {
        flags |= HAS_NATIVE_METADATA;
    }
    if primary.sparse_logical_size.is_some() || auxiliary.iter().any(|record| record.flags & 1 != 0) {
        flags |= HAS_SPARSE_EXTENTS;
    }
    if primary.declaration.capture_status == CaptureStatus::Partial {
        flags |= CAPTURE_PARTIAL;
    }
    if primary.requires_system_restore || auxiliary.iter().any(|record| record.restore_class == RestoreClass::System) {
        flags |= REQUIRES_SYSTEM_RESTORE;
    }
    Ok((flags, capture_report))
}

pub fn parse_capture_report(payload: &[u8], declaration: &MetadataDeclaration) -> Result<Vec<CaptureReportRow>, FormatError> {
    if payload.len() > MAX_LOCAL_PAX_PAYLOAD {
        return Err(FormatError::ReaderResourceLimitExceeded {
            field: "capture report payload bytes",
            cap: MAX_LOCAL_PAX_PAYLOAD as u64,
            actual: payload.len() as u64,
        });
    }
    let text = std::str::from_utf8(payload).map_err(|_| FormatError::InvalidArchive("capture report is not UTF-8"))?;
    if !text.starts_with("tzap-capture-report-v1\n") || !text.ends_with('\n') {
        return invalid("CaptureReport", "invalid framing");
    }
    let mut rows = Vec::new();
    let mut previous: Option<&str> = None;
    for line in text["tzap-capture-report-v1\n".len()..].split_terminator('\n') {
        if line.is_empty() {
            return invalid("CaptureReport", "empty row");
        }
        if rows.len() >= MAX_CAPTURE_REPORT_ROWS {
            return Err(FormatError::ReaderResourceLimitExceeded {
                field: "capture report rows",
                cap: MAX_CAPTURE_REPORT_ROWS as u64,
                actual: rows.len() as u64 + 1,
            });
        }
        if previous.is_some_and(|value| value >= line) {
            return invalid("CaptureReport", "rows are not strictly sorted and unique");
        }
        previous = Some(line);
        let mut fields = line.split('\t');
        let profile = fields.next().unwrap_or_default();
        let metadata_class = fields.next().unwrap_or_default();
        let reason = fields.next().unwrap_or_default();
        let encoded_detail = fields.next().unwrap_or_default();
        if fields.next().is_some()
            || !declaration.profile_selected(profile)
            || !valid_profile_token(metadata_class)
            || !matches!(
                reason,
                "excluded-policy"
                    | "unsupported-host"
                    | "unsupported-filesystem"
                    | "permission-denied"
                    | "changed-during-read"
                    | "limit-exceeded"
                    | "io-error"
                    | "invalid-source-metadata"
            )
            || !valid_percent_encoded_detail(encoded_detail.as_bytes())
        {
            return invalid("CaptureReport", "invalid row");
        }
        rows.push(CaptureReportRow {
            profile: profile.to_owned(),
            metadata_class: metadata_class.to_owned(),
            reason: reason.to_owned(),
            encoded_detail: encoded_detail.to_owned(),
        });
    }
    if rows.is_empty() {
        return invalid("CaptureReport", "report has no rows");
    }
    Ok(rows)
}

pub fn parse_sparse_payload(payload: &[u8], logical_size: u64) -> Result<SparseLayout, FormatError> {
    let first_newline = payload.iter().position(|byte| *byte == b'\n').ok_or(FormatError::InvalidArchive("sparse extent count is missing"))?;
    let count = parse_decimal_usize(&payload[..first_newline], "sparse extent count")?;
    if count > MAX_SPARSE_EXTENTS {
        return Err(FormatError::ReaderResourceLimitExceeded { field: "sparse extent count", cap: MAX_SPARSE_EXTENTS as u64, actual: count as u64 });
    }
    let mut cursor = first_newline + 1;
    let mut extents = Vec::with_capacity(count);
    let mut previous_end = 0u64;
    let mut stored_extent_bytes = 0u64;
    for _ in 0..count {
        let offset = parse_sparse_line(payload, &mut cursor)?;
        let length = parse_sparse_line(payload, &mut cursor)?;
        if length == 0 || offset < previous_end {
            return invalid("SparsePayload", "extents overlap or have zero length");
        }
        if !extents.is_empty() && offset == previous_end {
            return invalid("SparsePayload", "adjacent extents are not merged");
        }
        let end = offset.checked_add(length).ok_or(FormatError::InvalidArchive("sparse extent overflow"))?;
        if end > logical_size {
            return invalid("SparsePayload", "extent exceeds logical size");
        }
        stored_extent_bytes = stored_extent_bytes.checked_add(length).ok_or(FormatError::InvalidArchive("sparse stored size overflow"))?;
        extents.push(SparseExtent { offset, length });
        previous_end = end;
    }
    let map_and_padding_size = cursor.checked_add(511).ok_or(FormatError::InvalidArchive("sparse map padding overflow"))? / 512 * 512;
    if map_and_padding_size > payload.len() || payload[cursor..map_and_padding_size].iter().any(|byte| *byte != 0) {
        return invalid("SparsePayload", "sparse map padding is invalid");
    }
    if payload.len() as u64 - map_and_padding_size as u64 != stored_extent_bytes {
        return invalid("SparsePayload", "sparse extent bytes do not match map");
    }
    Ok(SparseLayout { logical_size, map_and_padding_size, extents })
}

fn validate_primary_key_registry(records: &PaxRecords) -> Result<(), FormatError> {
    for key in records.keys() {
        let allowed = matches!(
            key.as_str(),
            "TZAP.metadata.version"
                | "TZAP.metadata.required-profiles"
                | "TZAP.metadata.optional-profiles"
                | "TZAP.metadata.source-os"
                | "TZAP.metadata.source-filesystem"
                | "TZAP.metadata.capture-status"
                | "TZAP.portable.owner-kind"
                | "TZAP.portable.mode-origin"
                | "TZAP.portable.mode"
                | "TZAP.portable.attributes"
                | "path"
                | "linkpath"
                | "size"
                | "uid"
                | "gid"
                | "uname"
                | "gname"
                | "mtime"
                | "atime"
                | "LIBARCHIVE.creationtime"
                | "SCHILY.acl.access"
                | "SCHILY.acl.default"
                | "SCHILY.acl.ace"
                | "SCHILY.fflags"
                | "GNU.sparse.major"
                | "GNU.sparse.minor"
                | "GNU.sparse.name"
                | "GNU.sparse.realsize"
                | "TZAP.unix.ctime-observed"
                | "TZAP.windows.change-time"
                | "TZAP.posix.device-major"
                | "TZAP.posix.device-minor"
                | "TZAP.acl.projection"
                | "TZAP.acl.syntax"
                | "TZAP.linux.fsflags"
                | "TZAP.bsd.st-flags"
                | "TZAP.macos.st-flags"
                | "TZAP.linux.project-id"
                | "TZAP.linux.whiteout"
                | "TZAP.macos.clone-group"
                | "TZAP.windows.file-attributes"
                | "TZAP.windows.data-stream-attributes"
                | "TZAP.windows.directory-case-sensitive"
                | "TZAP.windows.reparse-placeholder"
        ) || key.starts_with("LIBARCHIVE.xattr.");
        if !allowed {
            return invalid("PrimaryMetadata", "unregistered primary PAX key");
        }
    }
    Ok(())
}

fn parse_profile_list(value: &[u8]) -> Result<Vec<String>, FormatError> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let text = ascii_string(value, "profile list")?;
    let profiles: Vec<_> = text.split(',').map(str::to_owned).collect();
    if profiles.len() > MAX_PROFILE_COUNT {
        return Err(FormatError::ReaderResourceLimitExceeded {
            field: "metadata profiles per list",
            cap: MAX_PROFILE_COUNT as u64,
            actual: profiles.len() as u64,
        });
    }
    if profiles.iter().any(|profile| !is_valid_profile_id(profile)) || profiles.windows(2).any(|pair| pair[0] >= pair[1]) {
        return invalid("PrimaryMetadata", "profile list is not canonical");
    }
    Ok(profiles)
}

fn validate_profile_sets(required: &[String], optional: &[String]) -> Result<(), FormatError> {
    if required.binary_search_by(|value| value.as_str().cmp(PORTABLE_PROFILE)).is_err() {
        return invalid("PrimaryMetadata", "portable-v1 is not required");
    }
    if required.iter().any(|profile| profile == CORE_PROFILE)
        || optional.iter().any(|profile| profile == CORE_PROFILE)
        || required.iter().any(|profile| optional.binary_search(profile).is_ok())
    {
        return invalid("PrimaryMetadata", "profile lists overlap or contain reserved profile");
    }
    Ok(())
}

fn validate_profile_dependencies(required: &[String], optional: &[String], source_os: &str) -> Result<(), FormatError> {
    let req = |profile: &str| required.binary_search_by(|value| value.as_str().cmp(profile)).is_ok();
    let opt = |profile: &str| optional.binary_search_by(|value| value.as_str().cmp(profile)).is_ok();
    if (req(LINUX_PROFILE) || req(MACOS_PROFILE)) && !req(POSIX_PROFILE) {
        return invalid("PrimaryMetadata", "required native profile dependency is missing");
    }
    if (opt(LINUX_PROFILE) || opt(MACOS_PROFILE)) && !(req(POSIX_PROFILE) || opt(POSIX_PROFILE)) {
        return invalid("PrimaryMetadata", "optional native profile dependency is missing");
    }
    if (req(LINUX_PROFILE) || opt(LINUX_PROFILE)) && source_os != "linux"
        || (req(MACOS_PROFILE) || opt(MACOS_PROFILE)) && source_os != "macos"
        || (req(WINDOWS_PROFILE) || opt(WINDOWS_PROFILE)) && source_os != "windows"
    {
        return invalid("PrimaryMetadata", "native profile does not match source OS");
    }
    Ok(())
}

fn validate_owner_fields(records: &PaxRecords, posix: bool) -> Result<(), FormatError> {
    let ownership = ["uid", "gid", "uname", "gname"];
    if !posix && ownership.iter().any(|key| records.contains_key(*key)) {
        return invalid("PrimaryMetadata", "owner-kind none has POSIX ownership fields");
    }
    if posix {
        if let Some(value) = records.get("uid") {
            parse_decimal_u64(value, "uid")?;
        }
        if let Some(value) = records.get("gid") {
            parse_decimal_u64(value, "gid")?;
        }
        for key in ["uname", "gname"] {
            if let Some(value) = records.get(key) {
                let text = std::str::from_utf8(value).map_err(|_| FormatError::InvalidArchive("owner name is not UTF-8"))?;
                if text.nfc().collect::<String>() != text {
                    return invalid("PrimaryMetadata", "owner name is not NFC");
                }
            }
        }
    }
    Ok(())
}

fn validate_scalar_encodings(records: &PaxRecords) -> Result<Vec<Vec<u8>>, FormatError> {
    for key in ["mtime", "atime", "LIBARCHIVE.creationtime", "TZAP.unix.ctime-observed", "TZAP.windows.change-time"] {
        if let Some(value) = records.get(key) {
            parse_timestamp(value)?;
        }
    }
    for key in ["TZAP.posix.device-major", "TZAP.posix.device-minor"] {
        if let Some(value) = records.get(key) {
            parse_decimal_u64(value, "primary decimal scalar")?;
        }
    }
    if let Some(value) = records.get("TZAP.linux.project-id") {
        let parsed = parse_decimal_u64(value, "Linux project ID")?;
        if parsed > u32::MAX as u64 {
            return invalid("PrimaryMetadata", "Linux project ID exceeds u32");
        }
    }
    for key in ["TZAP.linux.fsflags", "TZAP.bsd.st-flags", "TZAP.macos.st-flags"] {
        if let Some(value) = records.get(key) {
            parse_fixed_hex_u64(value, 16, "native flags")?;
        }
    }
    if let Some(value) = records.get("SCHILY.fflags") {
        let text = ascii_string(value, "SCHILY file flags")?;
        if text.is_empty()
            || text.split(',').any(|token| !valid_profile_token(token) || token.bytes().any(|byte| byte == b'.'))
            || text.split(',').collect::<Vec<_>>().windows(2).any(|pair| pair[0] >= pair[1])
        {
            return invalid("PrimaryMetadata", "SCHILY file flags are not canonical");
        }
    }
    for key in ["TZAP.windows.file-attributes", "TZAP.windows.data-stream-attributes"] {
        if let Some(value) = records.get(key) {
            parse_fixed_hex_u32(value, 8, "Windows attributes")?;
        }
    }
    if let Some(value) = records.get("TZAP.macos.clone-group") {
        if value.len() != 32 || !value.iter().all(is_lower_hex) {
            return invalid("PrimaryMetadata", "invalid macOS clone group");
        }
    }
    for key in ["TZAP.linux.whiteout", "TZAP.windows.reparse-placeholder"] {
        if let Some(value) = records.get(key) {
            if value != b"1" {
                return invalid("PrimaryMetadata", "invalid boolean scalar");
            }
        }
    }
    if let Some(value) = records.get("TZAP.windows.directory-case-sensitive") {
        if value != b"0" && value != b"1" {
            return invalid("PrimaryMetadata", "invalid Windows case-sensitive scalar");
        }
    }
    let mut decoded_xattrs = BTreeSet::new();
    for (key, value) in records.iter().filter(|(key, _)| key.starts_with("LIBARCHIVE.xattr.")) {
        let name = decode_percent_name(&key.as_bytes()["LIBARCHIVE.xattr.".len()..])?;
        if name.len() > MAX_AUXILIARY_NAME_LEN {
            return Err(FormatError::ReaderResourceLimitExceeded {
                field: "decoded xattr name bytes",
                cap: MAX_AUXILIARY_NAME_LEN as u64,
                actual: name.len() as u64,
            });
        }
        if name.is_empty() || !decoded_xattrs.insert(name) {
            return invalid("PrimaryMetadata", "duplicate or empty decoded xattr name");
        }
        let decoded = canonical_base64_decode(value)?;
        if decoded.len() > MAX_LOCAL_PAX_PAYLOAD {
            return Err(FormatError::ReaderResourceLimitExceeded {
                field: "decoded xattr value bytes",
                cap: MAX_LOCAL_PAX_PAYLOAD as u64,
                actual: decoded.len() as u64,
            });
        }
    }
    for reserved in [b"com.apple.ResourceFork".as_slice(), b"com.apple.FinderInfo".as_slice()] {
        if decoded_xattrs.contains(reserved) {
            return invalid("PrimaryMetadata", "macOS resource fork or FinderInfo is encoded as a generic xattr");
        }
    }
    Ok(decoded_xattrs.into_iter().collect())
}

fn validate_acl_fields(records: &PaxRecords) -> Result<(), FormatError> {
    let posix = records.contains_key("SCHILY.acl.access") || records.contains_key("SCHILY.acl.default");
    let nfs4 = records.contains_key("SCHILY.acl.ace");
    if posix && nfs4 {
        return invalid("PrimaryMetadata", "multiple textual ACL models are present");
    }
    let projection = records.get("TZAP.acl.projection");
    let syntax = records.get("TZAP.acl.syntax");
    if posix || nfs4 {
        if !matches!(projection.map(Vec::as_slice), Some(b"exact" | b"lossy")) {
            return invalid("PrimaryMetadata", "textual ACL projection is missing");
        }
        let expected = if posix { b"schily-posix1e-extra-id-v1".as_slice() } else { b"schily-nfs4-full-extra-id-v1".as_slice() };
        if syntax.map(Vec::as_slice) != Some(expected) {
            return invalid("PrimaryMetadata", "textual ACL syntax does not match model");
        }
    } else if (projection.is_some() || syntax.is_some()) && (projection.map(Vec::as_slice) != Some(b"none") || syntax.is_some()) {
        return invalid("PrimaryMetadata", "ACL declaration has no matching ACL data");
    }
    for key in ["SCHILY.acl.access", "SCHILY.acl.default"] {
        if let Some(value) = records.get(key) {
            validate_posix_acl_text(value)?;
        }
    }
    if let Some(value) = records.get("SCHILY.acl.ace") {
        validate_nfs4_acl_text(value)?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PosixAclSortKey {
    category: u8,
    numeric_qualifier: u64,
    name: String,
}

fn validate_posix_acl_text(value: &[u8]) -> Result<(), FormatError> {
    let text = canonical_acl_text(value)?;
    let mut previous: Option<PosixAclSortKey> = None;
    let mut principals = BTreeSet::new();
    let mut base = [false; 3];
    let mut mask_count = 0usize;
    let mut named_count = 0usize;
    for serialized in text.split(',') {
        let fields: Vec<_> = serialized.split(':').collect();
        if !(fields.len() == 3 || fields.len() == 4) {
            return invalid("PrimaryMetadata", "POSIX ACL tuple has invalid field count");
        }
        let tag = fields[0];
        let name = fields[1];
        validate_posix_permissions(fields[2])?;
        let id = if fields.len() == 4 { Some(parse_acl_id(fields[3])?) } else { None };
        let (category, numeric_qualifier) = match (tag, name.is_empty()) {
            ("user", true) => {
                if id.is_some() || std::mem::replace(&mut base[0], true) {
                    return invalid("PrimaryMetadata", "duplicate or invalid POSIX owner-user ACL entry");
                }
                (0, 0)
            }
            ("group", true) => {
                if id.is_some() || std::mem::replace(&mut base[1], true) {
                    return invalid("PrimaryMetadata", "duplicate or invalid POSIX owner-group ACL entry");
                }
                (1, 0)
            }
            ("other", true) => {
                if id.is_some() || std::mem::replace(&mut base[2], true) {
                    return invalid("PrimaryMetadata", "duplicate or invalid POSIX other ACL entry");
                }
                (2, 0)
            }
            ("user", false) => {
                named_count += 1;
                (3, validate_acl_name_and_id(name, id)?)
            }
            ("group", false) => {
                named_count += 1;
                (4, validate_acl_name_and_id(name, id)?)
            }
            ("mask", true) => {
                if id.is_some() || mask_count != 0 {
                    return invalid("PrimaryMetadata", "duplicate or invalid POSIX ACL mask");
                }
                mask_count += 1;
                (5, 0)
            }
            _ => return invalid("PrimaryMetadata", "invalid POSIX ACL tag or qualifier"),
        };
        let key = PosixAclSortKey { category, numeric_qualifier, name: name.to_owned() };
        if previous.as_ref().is_some_and(|prior| prior >= &key) {
            return invalid("PrimaryMetadata", "POSIX ACL entries are not canonically ordered");
        }
        previous = Some(key);
        if !principals.insert((tag.to_owned(), name.to_owned(), id)) {
            return invalid("PrimaryMetadata", "duplicate POSIX ACL principal");
        }
    }
    if !base.into_iter().all(|present| present) || (named_count != 0 && mask_count != 1) {
        return invalid("PrimaryMetadata", "POSIX ACL required entries are missing");
    }
    Ok(())
}

fn validate_nfs4_acl_text(value: &[u8]) -> Result<(), FormatError> {
    let text = canonical_acl_text(value)?;
    let mut tuples = BTreeSet::new();
    for serialized in text.split(',') {
        if !tuples.insert(serialized) {
            return invalid("PrimaryMetadata", "duplicate NFSv4 ACL tuple");
        }
        let fields: Vec<_> = serialized.split(':').collect();
        let named = matches!(fields.first().copied(), Some("user" | "group"));
        let expected_fields = if named { 5..=6 } else { 4..=4 };
        if !expected_fields.contains(&fields.len()) {
            return invalid("PrimaryMetadata", "NFSv4 ACL tuple has invalid field count");
        }
        let offset = if named {
            let id = if fields.len() == 6 { Some(parse_acl_id(fields[5])?) } else { None };
            validate_acl_name_and_id(fields[1], id)?;
            1
        } else {
            if !matches!(fields[0], "owner@" | "group@" | "everyone@") {
                return invalid("PrimaryMetadata", "invalid NFSv4 ACL principal");
            }
            0
        };
        validate_fixed_acl_bits(fields[1 + offset], b"rwxpDdaARWcCos", "NFSv4 permissions")?;
        validate_fixed_acl_bits(fields[2 + offset], b"fdinSFI", "NFSv4 inheritance flags")?;
        if !matches!(fields[3 + offset], "allow" | "deny" | "audit" | "alarm") {
            return invalid("PrimaryMetadata", "invalid NFSv4 ACL entry type");
        }
    }
    Ok(())
}

fn canonical_acl_text(value: &[u8]) -> Result<&str, FormatError> {
    let text = std::str::from_utf8(value).map_err(|_| FormatError::InvalidArchive("ACL text is not UTF-8"))?;
    if text.is_empty()
        || text.starts_with(',')
        || text.ends_with(',')
        || text.contains("default:")
        || text.bytes().any(|byte| byte.is_ascii_whitespace() || byte == b'#' || byte == 0)
    {
        return invalid("PrimaryMetadata", "ACL text is not canonical");
    }
    Ok(text)
}

fn validate_posix_permissions(value: &str) -> Result<(), FormatError> {
    if value.len() != 3 || !value.bytes().zip(*b"rwx").all(|(actual, expected)| actual == expected || actual == b'-') {
        return invalid("PrimaryMetadata", "POSIX ACL permissions are not canonical");
    }
    Ok(())
}

fn validate_fixed_acl_bits(value: &str, positions: &[u8], label: &'static str) -> Result<(), FormatError> {
    if value.len() != positions.len() || !value.bytes().zip(positions.iter().copied()).all(|(actual, expected)| actual == expected || actual == b'-') {
        return invalid("PrimaryMetadata", label);
    }
    Ok(())
}

fn parse_acl_id(value: &str) -> Result<u64, FormatError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) || value.len() > 1 && value.starts_with('0') {
        return invalid("PrimaryMetadata", "ACL numeric ID is not minimal decimal");
    }
    value.parse().map_err(|_| FormatError::InvalidArchive("ACL numeric ID exceeds u64"))
}

fn validate_acl_name_and_id(name: &str, id: Option<u64>) -> Result<u64, FormatError> {
    if name.is_empty() || name.nfc().collect::<String>() != name || name.bytes().any(|byte| matches!(byte, b',' | b':' | b'\r' | b'\n' | 0)) {
        return invalid("PrimaryMetadata", "ACL name is not canonical NFC UTF-8");
    }
    if name.bytes().all(|byte| byte.is_ascii_digit()) {
        let numeric_name = parse_acl_id(name)?;
        if id.is_some() {
            return invalid("PrimaryMetadata", "numeric ACL name has a redundant extra ID");
        }
        Ok(numeric_name)
    } else {
        Ok(id.unwrap_or(u64::MAX))
    }
}

fn validate_profile_owned_primary_fields(records: &PaxRecords, required: &[String], optional: &[String], source_os: &str) -> Result<(), FormatError> {
    let selected = |profile: &str| {
        required.binary_search_by(|value| value.as_str().cmp(profile)).is_ok() || optional.binary_search_by(|value| value.as_str().cmp(profile)).is_ok()
    };
    let source_profile = match source_os {
        "linux" => LINUX_PROFILE,
        "macos" => MACOS_PROFILE,
        "windows" => WINDOWS_PROFILE,
        "freebsd" | "netbsd" | "openbsd" | "solaris" | "other-unix" => POSIX_PROFILE,
        _ => "",
    };
    for key in records.keys() {
        let owner = if key.starts_with("TZAP.linux.") {
            LINUX_PROFILE
        } else if key.starts_with("TZAP.macos.") {
            MACOS_PROFILE
        } else if key.starts_with("TZAP.windows.") {
            WINDOWS_PROFILE
        } else if key.starts_with("TZAP.posix.") {
            POSIX_PROFILE
        } else if key.starts_with("LIBARCHIVE.xattr.") {
            let name = decode_percent_name(&key.as_bytes()["LIBARCHIVE.xattr.".len()..])?;
            xattr_owner_profile(&name, source_os)
        } else if key.starts_with("SCHILY.acl.") || key.starts_with("TZAP.acl.") {
            POSIX_PROFILE
        } else if key.starts_with("SCHILY.") || key == "LIBARCHIVE.creationtime" || key == "TZAP.unix.ctime-observed" {
            source_profile
        } else {
            ""
        };
        if !owner.is_empty() && !selected(owner) {
            return invalid("PrimaryMetadata", "primary key owner profile is not selected");
        }
    }
    Ok(())
}

fn system_xattr_namespace(name: &[u8], source_os: &str) -> bool {
    name.starts_with(b"security.")
        || name.starts_with(b"trusted.")
        || name.starts_with(b"system.")
        || (source_os == "linux" && !name.starts_with(b"user.") && !name.starts_with(b"com.apple."))
}

fn xattr_owner_profile(name: &[u8], source_os: &str) -> &'static str {
    if name.starts_with(b"com.apple.") {
        MACOS_PROFILE
    } else if source_os == "linux" && system_xattr_namespace(name, source_os) {
        LINUX_PROFILE
    } else {
        POSIX_PROFILE
    }
}

fn validate_builtin_auxiliary(record: &AuxiliaryRecord) -> Result<(), FormatError> {
    let structure = "AuxiliaryMetadata";
    let fixed = match record.kind.as_str() {
        CAPTURE_REPORT_KIND => Some((CORE_PROFILE, RestoreClass::None, false, "none")),
        "windows.security-descriptor" => Some((WINDOWS_PROFILE, RestoreClass::System, true, "none")),
        "windows.reparse-data" => Some((WINDOWS_PROFILE, RestoreClass::System, true, "none")),
        "windows.object-id" => Some((WINDOWS_PROFILE, RestoreClass::System, true, "none")),
        "windows.efs-raw" => Some((WINDOWS_PROFILE, RestoreClass::System, true, "none")),
        "macos.resource-fork" => Some((MACOS_PROFILE, RestoreClass::SameOs, true, "none")),
        "macos.acl-native" => Some((MACOS_PROFILE, RestoreClass::SameOs, true, "none")),
        "macos.finder-info" => Some((MACOS_PROFILE, RestoreClass::SameOs, true, "none")),
        "windows.alternate-data" => Some((WINDOWS_PROFILE, record.restore_class, true, "utf16le-base64")),
        "windows.ea-data" | "windows.property-data" => Some((WINDOWS_PROFILE, record.restore_class, true, "none")),
        "generic.xattr" => Some((record.profile.as_str(), record.restore_class, true, "bytes-base64")),
        "generic.named-fork" => Some((record.profile.as_str(), RestoreClass::SameOs, true, "bytes-base64")),
        _ if record.kind.starts_with("x.") => None,
        _ => return invalid(structure, "unknown built-in auxiliary kind"),
    };
    if let Some((profile, class, native, encoding)) = fixed {
        if record.profile != profile || record.restore_class != class || record.native != native || record.name_encoding != encoding {
            return invalid(structure, "built-in auxiliary declaration mismatch");
        }
    }
    let required_meta: &[(&str, Option<&[u8]>)] = match record.kind.as_str() {
        "windows.security-descriptor" => &[("TZAP.aux.meta.security-information", None)],
        "windows.reparse-data" => &[("TZAP.aux.meta.reparse-tag", None)],
        "windows.alternate-data" => &[("TZAP.aux.meta.stream-type", Some(b"00000004")), ("TZAP.aux.meta.stream-attributes", None)],
        "windows.ea-data" => &[("TZAP.aux.meta.stream-type", Some(b"00000002")), ("TZAP.aux.meta.stream-attributes", None)],
        "windows.property-data" => &[("TZAP.aux.meta.stream-type", Some(b"00000006")), ("TZAP.aux.meta.stream-attributes", None)],
        "windows.object-id" => &[("TZAP.aux.meta.stream-type", Some(b"00000007")), ("TZAP.aux.meta.stream-attributes", None)],
        "windows.efs-raw" => &[("TZAP.aux.meta.efs-version", Some(b"1"))],
        "macos.acl-native" => &[("TZAP.aux.meta.acl-format", Some(b"darwin-acl-external-v1"))],
        _ => &[],
    };
    if !record.kind.starts_with("x.") && !matches!(record.kind.as_str(), "generic.xattr" | "generic.named-fork") && record.meta.len() != required_meta.len() {
        return invalid(structure, "unexpected built-in auxiliary metadata field");
    }
    for (key, expected) in required_meta {
        let value = record.meta.get(*key).ok_or(FormatError::InvalidArchive("required auxiliary metadata is missing"))?;
        if let Some(expected) = expected {
            if value != expected {
                return invalid(structure, "auxiliary metadata value mismatch");
            }
        } else if key.ends_with("information") || key.ends_with("tag") || key.ends_with("attributes") {
            parse_fixed_hex_u32(value, 8, "auxiliary metadata hexadecimal")?;
        }
    }
    if matches!(record.kind.as_str(), "windows.alternate-data" | "windows.ea-data" | "windows.property-data" | "windows.object-id") {
        let attributes = parse_fixed_hex_u32(
            record.meta.get("TZAP.aux.meta.stream-attributes").ok_or(FormatError::InvalidArchive("Windows stream attributes are missing"))?,
            8,
            "Windows stream attributes",
        )?;
        let expected_class = if record.kind == "windows.object-id" || attributes & 0x0000_0002 != 0 { RestoreClass::System } else { RestoreClass::SameOs };
        if record.restore_class != expected_class {
            return invalid(structure, "Windows stream restore class disagrees with stream attributes");
        }
        if (attributes & 0x0000_0008 != 0) != (record.flags & 1 != 0) {
            return invalid(structure, "Windows sparse stream attribute disagrees with sparse framing");
        }
    }
    if record.kind == "windows.alternate-data" {
        validate_windows_stream_name(&record.decoded_name)?;
    }
    if record.kind == "generic.xattr" {
        validate_generic_xattr_name(record)?;
    }
    if record.flags & 1 != 0
        && matches!(
            record.kind.as_str(),
            CAPTURE_REPORT_KIND
                | "windows.security-descriptor"
                | "windows.ea-data"
                | "windows.reparse-data"
                | "windows.object-id"
                | "windows.property-data"
                | "windows.efs-raw"
                | "macos.acl-native"
                | "macos.finder-info"
        )
    {
        return invalid(structure, "auxiliary kind cannot use sparse framing");
    }
    Ok(())
}

fn retained_auxiliary_cap(kind: &str) -> usize {
    match kind {
        CAPTURE_REPORT_KIND | "windows.ea-data" => MAX_LOCAL_PAX_PAYLOAD,
        "windows.security-descriptor" => 256 * 1024,
        "windows.reparse-data" => 16 * 1024,
        "windows.object-id" | "macos.finder-info" => 64,
        "macos.acl-native" => 40 + 128 * 28,
        _ => 0,
    }
}

fn validate_darwin_acl_external(value: &[u8]) -> Result<(), FormatError> {
    const HEADER: usize = 40;
    const ACE_SIZE: usize = 28;
    const MAX_ENTRIES: usize = 128;
    const MAGIC: [u8; 4] = [0x01, 0x2c, 0xc1, 0x6d];
    if value.get(..4) != Some(MAGIC.as_slice()) {
        return invalid("AuxiliaryMetadata", "invalid macOS ACL external magic");
    }
    let count = value
        .get(36..40)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or(FormatError::InvalidArchive("macOS ACL external form is truncated"))? as usize;
    let expected = HEADER
        .checked_add(count.checked_mul(ACE_SIZE).ok_or(FormatError::InvalidArchive("macOS ACL entry count overflows"))?)
        .ok_or(FormatError::InvalidArchive("macOS ACL size overflows"))?;
    if count > MAX_ENTRIES || expected != value.len() {
        return invalid("AuxiliaryMetadata", "invalid macOS ACL external size");
    }
    #[cfg(target_os = "macos")]
    {
        extern "C" {
            fn acl_copy_int(buffer: *const libc::c_void) -> *mut libc::c_void;
            fn acl_free(object: *mut libc::c_void) -> libc::c_int;
        }
        let acl = unsafe { acl_copy_int(value.as_ptr().cast()) };
        if acl.is_null() {
            return invalid("AuxiliaryMetadata", "invalid macOS ACL external payload");
        }
        unsafe { acl_free(acl) };
    }
    Ok(())
}

fn validate_generic_xattr_name(record: &AuxiliaryRecord) -> Result<(), FormatError> {
    let name = record.decoded_name.as_slice();
    if matches!(name, b"com.apple.ResourceFork" | b"com.apple.FinderInfo") {
        return invalid("AuxiliaryMetadata", "macOS resource fork or FinderInfo is encoded as a generic xattr");
    }
    Ok(())
}

fn validate_generic_xattr_declaration(record: &AuxiliaryRecord, source_os: &str) -> Result<(), FormatError> {
    validate_generic_xattr_name(record)?;
    let name = record.decoded_name.as_slice();
    let profile = xattr_owner_profile(name, source_os);
    let class = if system_xattr_namespace(name, source_os) { RestoreClass::System } else { RestoreClass::SameOs };
    if record.profile != profile || record.restore_class != class {
        return invalid("AuxiliaryMetadata", "generic xattr owner or restore class disagrees with its namespace");
    }
    Ok(())
}

fn validate_builtin_auxiliary_payload(record: &AuxiliaryRecord, retained: Option<&[u8]>) -> Result<(), FormatError> {
    match record.kind.as_str() {
        CAPTURE_REPORT_KIND if record.stored_size > MAX_LOCAL_PAX_PAYLOAD as u64 => {
            return Err(FormatError::ReaderResourceLimitExceeded {
                field: "capture report payload bytes",
                cap: MAX_LOCAL_PAX_PAYLOAD as u64,
                actual: record.stored_size,
            });
        }
        "windows.security-descriptor" => {
            let security_information = parse_fixed_hex_u32(
                record.meta.get("TZAP.aux.meta.security-information").ok_or(FormatError::InvalidArchive("security-information mask is missing"))?,
                8,
                "security-information mask",
            )?;
            validate_self_relative_security_descriptor(
                retained.ok_or(FormatError::InvalidArchive("security descriptor payload was not retained"))?,
                security_information,
            )?;
        }
        "windows.reparse-data" => {
            let expected_tag = parse_fixed_hex_u32(
                record.meta.get("TZAP.aux.meta.reparse-tag").ok_or(FormatError::InvalidArchive("reparse tag is missing"))?,
                8,
                "reparse tag",
            )?;
            validate_reparse_buffer(retained.ok_or(FormatError::InvalidArchive("reparse payload was not retained"))?, expected_tag)?;
        }
        "windows.ea-data" => validate_windows_ea_stream(retained.ok_or(FormatError::InvalidArchive("EA payload was not retained"))?)?,
        "windows.object-id" if retained.map_or(0, <[u8]>::len) != 64 => {
            return invalid("AuxiliaryMetadata", "Windows object ID payload is not 64 bytes");
        }
        "macos.finder-info" if retained.map_or(0, <[u8]>::len) != 32 => {
            return invalid("AuxiliaryMetadata", "FinderInfo payload is not 32 bytes");
        }
        "macos.acl-native" => validate_darwin_acl_external(retained.ok_or(FormatError::InvalidArchive("macOS ACL payload was not retained"))?)?,
        _ => {}
    }
    Ok(())
}

fn validate_windows_stream_name(name: &[u8]) -> Result<(), FormatError> {
    if name.len() % 2 != 0 {
        return invalid("AuxiliaryMetadata", "Windows alternate-data name is not UTF-16LE");
    }
    let units = name.chunks_exact(2).map(|unit| u16::from_le_bytes([unit[0], unit[1]])).collect::<Vec<_>>();
    const SUFFIX: &[u16] = &[b':' as u16, b'$' as u16, b'D' as u16, b'A' as u16, b'T' as u16, b'A' as u16];
    if units.len() <= SUFFIX.len() + 1
        || units.first() != Some(&(b':' as u16))
        || !units.ends_with(SUFFIX)
        || units[1..units.len() - SUFFIX.len()].iter().any(|unit| matches!(*unit, 0 | 0x2f | 0x3a | 0x5c))
    {
        return invalid("AuxiliaryMetadata", "Windows alternate-data name is not canonical :name:$DATA");
    }
    Ok(())
}

fn validate_self_relative_security_descriptor(payload: &[u8], security_information: u32) -> Result<(), FormatError> {
    if payload.len() < 20 || payload[0] != 1 {
        return invalid("SecurityDescriptor", "invalid self-relative descriptor header");
    }
    let control = u16::from_le_bytes([payload[2], payload[3]]);
    if control & 0x8000 == 0 {
        return invalid("SecurityDescriptor", "descriptor is not self-relative");
    }
    let owner = read_le_u32(payload, 4)?;
    let group = read_le_u32(payload, 8)?;
    let sacl = read_le_u32(payload, 12)?;
    let dacl = read_le_u32(payload, 16)?;
    const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
    const GROUP_SECURITY_INFORMATION: u32 = 0x0000_0002;
    const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
    const SACL_SECURITY_INFORMATION: u32 = 0x0000_0008;
    const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;
    const PROTECTED_SACL_SECURITY_INFORMATION: u32 = 0x4000_0000;
    const UNPROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x2000_0000;
    const UNPROTECTED_SACL_SECURITY_INFORMATION: u32 = 0x1000_0000;
    const ALLOWED_SECURITY_INFORMATION: u32 = OWNER_SECURITY_INFORMATION
        | GROUP_SECURITY_INFORMATION
        | DACL_SECURITY_INFORMATION
        | SACL_SECURITY_INFORMATION
        | PROTECTED_DACL_SECURITY_INFORMATION
        | PROTECTED_SACL_SECURITY_INFORMATION
        | UNPROTECTED_DACL_SECURITY_INFORMATION
        | UNPROTECTED_SACL_SECURITY_INFORMATION;
    let dacl_protection = security_information & (PROTECTED_DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION);
    let expected_dacl_protection = if control & 0x0004 == 0 {
        0
    } else if control & 0x1000 != 0 {
        PROTECTED_DACL_SECURITY_INFORMATION
    } else {
        UNPROTECTED_DACL_SECURITY_INFORMATION
    };
    let sacl_protection = security_information & (PROTECTED_SACL_SECURITY_INFORMATION | UNPROTECTED_SACL_SECURITY_INFORMATION);
    let expected_sacl_protection = if control & 0x0010 == 0 {
        0
    } else if control & 0x2000 != 0 {
        PROTECTED_SACL_SECURITY_INFORMATION
    } else {
        UNPROTECTED_SACL_SECURITY_INFORMATION
    };
    if security_information == 0
        || security_information & !ALLOWED_SECURITY_INFORMATION != 0
        || (security_information & OWNER_SECURITY_INFORMATION != 0) != (owner != 0)
        || (security_information & GROUP_SECURITY_INFORMATION != 0) != (group != 0)
        || (security_information & DACL_SECURITY_INFORMATION != 0) != (control & 0x0004 != 0)
        || (security_information & SACL_SECURITY_INFORMATION != 0) != (control & 0x0010 != 0)
        || (dacl_protection != 0 && dacl_protection != expected_dacl_protection)
        || (sacl_protection != 0 && sacl_protection != expected_sacl_protection)
    {
        return invalid("SecurityDescriptor", "security-information mask disagrees with captured descriptor components");
    }
    for offset in [owner, group, sacl, dacl] {
        if offset != 0 && (offset < 20 || offset % 4 != 0 || offset as usize >= payload.len()) {
            return invalid("SecurityDescriptor", "descriptor component offset is out of bounds");
        }
    }
    for offset in [owner, group] {
        if offset != 0 {
            validate_sid(payload, offset as usize)?;
        }
    }
    if sacl != 0 {
        if control & 0x0010 == 0 {
            return invalid("SecurityDescriptor", "SACL offset is present without SACL control bit");
        }
        validate_acl(payload, sacl as usize)?;
    }
    if dacl != 0 {
        if control & 0x0004 == 0 {
            return invalid("SecurityDescriptor", "DACL offset is present without DACL control bit");
        }
        validate_acl(payload, dacl as usize)?;
    }
    Ok(())
}

fn validate_sid(payload: &[u8], offset: usize) -> Result<(), FormatError> {
    let header = payload.get(offset..offset + 8).ok_or(FormatError::InvalidArchive("SID header is out of bounds"))?;
    if header[0] != 1 || header[1] > 15 {
        return invalid("SecurityDescriptor", "SID header is invalid");
    }
    let len = 8usize.checked_add(header[1] as usize * 4).ok_or(FormatError::InvalidArchive("SID size overflow"))?;
    if offset.checked_add(len).is_none_or(|end| end > payload.len()) {
        return invalid("SecurityDescriptor", "SID is out of bounds");
    }
    Ok(())
}

fn validate_acl(payload: &[u8], offset: usize) -> Result<(), FormatError> {
    let header = payload.get(offset..offset + 8).ok_or(FormatError::InvalidArchive("ACL header is out of bounds"))?;
    if !matches!(header[0], 2 | 4) {
        return invalid("SecurityDescriptor", "ACL revision is unsupported");
    }
    let size = u16::from_le_bytes([header[2], header[3]]) as usize;
    let count = u16::from_le_bytes([header[4], header[5]]) as usize;
    let end = offset.checked_add(size).ok_or(FormatError::InvalidArchive("ACL size overflow"))?;
    if size < 8 || end > payload.len() {
        return invalid("SecurityDescriptor", "ACL size is out of bounds");
    }
    let mut cursor = offset + 8;
    for _ in 0..count {
        let ace = payload.get(cursor..cursor + 4).ok_or(FormatError::InvalidArchive("ACE header is out of bounds"))?;
        let ace_size = u16::from_le_bytes([ace[2], ace[3]]) as usize;
        if ace_size < 4 || ace_size % 4 != 0 {
            return invalid("SecurityDescriptor", "ACE size is invalid");
        }
        cursor = cursor.checked_add(ace_size).ok_or(FormatError::InvalidArchive("ACE size overflow"))?;
        if cursor > end {
            return invalid("SecurityDescriptor", "ACE exceeds ACL bounds");
        }
    }
    Ok(())
}

fn validate_reparse_buffer(payload: &[u8], expected_tag: u32) -> Result<(), FormatError> {
    if payload.len() < 8 {
        return invalid("ReparseBuffer", "reparse buffer header is truncated");
    }
    let tag = read_le_u32(payload, 0)?;
    let data_len = u16::from_le_bytes([payload[4], payload[5]]) as usize;
    let header_len: usize = if tag & 0x8000_0000 == 0 { 24 } else { 8 };
    if tag != expected_tag || payload.len() != header_len.checked_add(data_len).ok_or(FormatError::InvalidArchive("reparse buffer size overflow"))? {
        return invalid("ReparseBuffer", "reparse tag or length is inconsistent");
    }
    let data = &payload[header_len..];
    match tag {
        0xa000_000c => validate_reparse_name_offsets(data, 12)?,
        0xa000_0003 => validate_reparse_name_offsets(data, 8)?,
        _ => {}
    }
    Ok(())
}

fn validate_reparse_name_offsets(data: &[u8], path_buffer_offset: usize) -> Result<(), FormatError> {
    if data.len() < path_buffer_offset {
        return invalid("ReparseBuffer", "reparse name header is truncated");
    }
    for field in [0usize, 4] {
        let offset = u16::from_le_bytes([data[field], data[field + 1]]) as usize;
        let len = u16::from_le_bytes([data[field + 2], data[field + 3]]) as usize;
        if offset % 2 != 0 || len % 2 != 0 || path_buffer_offset.checked_add(offset).and_then(|start| start.checked_add(len)).is_none_or(|end| end > data.len())
        {
            return invalid("ReparseBuffer", "reparse name offset is out of bounds");
        }
    }
    Ok(())
}

fn validate_windows_ea_stream(payload: &[u8]) -> Result<(), FormatError> {
    let mut cursor = 0usize;
    while cursor < payload.len() {
        let header_end = cursor.checked_add(8).ok_or(FormatError::InvalidArchive("EA record offset overflow"))?;
        let header = payload.get(cursor..header_end).ok_or(FormatError::InvalidArchive("EA record header is truncated"))?;
        let next = u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let name_len = header[5] as usize;
        let value_len = u16::from_le_bytes([header[6], header[7]]) as usize;
        let record_len = 8usize
            .checked_add(name_len)
            .and_then(|value| value.checked_add(1))
            .and_then(|value| value.checked_add(value_len))
            .ok_or(FormatError::InvalidArchive("EA record size overflow"))?;
        let record_end = cursor.checked_add(record_len).ok_or(FormatError::InvalidArchive("EA record end overflow"))?;
        let name_end = header_end.checked_add(name_len).ok_or(FormatError::InvalidArchive("EA name end overflow"))?;
        if name_len == 0
            || record_end > payload.len()
            || payload.get(name_end) != Some(&0)
            || payload.get(header_end..name_end).is_none_or(|name| name.contains(&0))
        {
            return invalid("WindowsEaStream", "EA record is malformed");
        }
        if next == 0 {
            if record_end != payload.len() {
                return invalid("WindowsEaStream", "EA stream has trailing bytes");
            }
            return Ok(());
        }
        let next_cursor = cursor.checked_add(next).ok_or(FormatError::InvalidArchive("EA next-entry offset overflow"))?;
        if next < record_len || next % 4 != 0 || next_cursor > payload.len() {
            return invalid("WindowsEaStream", "EA next-entry offset is invalid");
        }
        if payload[record_end..next_cursor].iter().any(|byte| *byte != 0) {
            return invalid("WindowsEaStream", "EA alignment padding is non-zero");
        }
        cursor = next_cursor;
    }
    if payload.is_empty() {
        return invalid("WindowsEaStream", "EA stream is empty");
    }
    Ok(())
}

fn read_le_u32(payload: &[u8], offset: usize) -> Result<u32, FormatError> {
    let bytes: [u8; 4] = payload.get(offset..offset + 4).ok_or(FormatError::InvalidArchive("little-endian u32 is out of bounds"))?.try_into().unwrap();
    Ok(u32::from_le_bytes(bytes))
}

fn decode_auxiliary_name(encoding: &str, value: &[u8]) -> Result<Vec<u8>, FormatError> {
    match encoding {
        "none" if value.is_empty() => Ok(Vec::new()),
        "none" => invalid("AuxiliaryMetadata", "name is non-empty for none encoding"),
        "utf8" => {
            let text = std::str::from_utf8(value).map_err(|_| FormatError::InvalidArchive("auxiliary UTF-8 name is invalid"))?;
            if text.is_empty() || text.nfc().collect::<String>() != text {
                return invalid("AuxiliaryMetadata", "auxiliary UTF-8 name is empty or non-NFC");
            }
            Ok(value.to_vec())
        }
        "bytes-base64" => {
            let decoded = canonical_base64_decode(value)?;
            if decoded.is_empty() {
                return invalid("AuxiliaryMetadata", "decoded auxiliary name is empty");
            }
            Ok(decoded)
        }
        "utf16le-base64" => {
            let decoded = canonical_base64_decode(value)?;
            if decoded.is_empty() || decoded.len() % 2 != 0 || decoded.chunks_exact(2).any(|unit| unit == [0, 0]) {
                return invalid("AuxiliaryMetadata", "decoded UTF-16LE name is invalid");
            }
            Ok(decoded)
        }
        _ => invalid("AuxiliaryMetadata", "unknown auxiliary name encoding"),
    }
}

pub fn canonical_base64_decode(value: &[u8]) -> Result<Vec<u8>, FormatError> {
    if value.contains(&b'=') || value.iter().any(|byte| base64_value(*byte).is_none()) {
        return invalid("Base64", "encoding is not unpadded RFC 4648 base64");
    }
    if value.len() % 4 == 1 {
        return invalid("Base64", "invalid encoded length");
    }
    let mut out = Vec::with_capacity(value.len() / 4 * 3 + 2);
    let mut cursor = 0usize;
    while cursor + 4 <= value.len() {
        let a = base64_value(value[cursor]).unwrap();
        let b = base64_value(value[cursor + 1]).unwrap();
        let c = base64_value(value[cursor + 2]).unwrap();
        let d = base64_value(value[cursor + 3]).unwrap();
        out.push((a << 2) | (b >> 4));
        out.push((b << 4) | (c >> 2));
        out.push((c << 6) | d);
        cursor += 4;
    }
    match value.len() - cursor {
        0 => {}
        2 => {
            let a = base64_value(value[cursor]).unwrap();
            let b = base64_value(value[cursor + 1]).unwrap();
            if b & 0x0f != 0 {
                return invalid("Base64", "non-zero unused bits");
            }
            out.push((a << 2) | (b >> 4));
        }
        3 => {
            let a = base64_value(value[cursor]).unwrap();
            let b = base64_value(value[cursor + 1]).unwrap();
            let c = base64_value(value[cursor + 2]).unwrap();
            if c & 0x03 != 0 {
                return invalid("Base64", "non-zero unused bits");
            }
            out.push((a << 2) | (b >> 4));
            out.push((b << 4) | (c >> 2));
        }
        _ => unreachable!(),
    }
    Ok(out)
}

pub fn canonical_base64_encode(value: &[u8]) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(value.len().div_ceil(3) * 4);
    let mut chunks = value.chunks_exact(3);
    for chunk in &mut chunks {
        out.push(ALPHABET[(chunk[0] >> 2) as usize]);
        out.push(ALPHABET[(((chunk[0] & 3) << 4) | (chunk[1] >> 4)) as usize]);
        out.push(ALPHABET[(((chunk[1] & 15) << 2) | (chunk[2] >> 6)) as usize]);
        out.push(ALPHABET[(chunk[2] & 63) as usize]);
    }
    let remainder = chunks.remainder();
    if let Some(&a) = remainder.first() {
        out.push(ALPHABET[(a >> 2) as usize]);
        if let Some(&b) = remainder.get(1) {
            out.push(ALPHABET[(((a & 3) << 4) | (b >> 4)) as usize]);
            out.push(ALPHABET[((b & 15) << 2) as usize]);
        } else {
            out.push(ALPHABET[((a & 3) << 4) as usize]);
        }
    }
    out
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

pub fn decode_percent_name(value: &[u8]) -> Result<Vec<u8>, FormatError> {
    let mut out = Vec::with_capacity(value.len());
    let mut cursor = 0usize;
    while cursor < value.len() {
        if value[cursor] == b'%' {
            if cursor + 2 >= value.len() || !is_upper_hex(&value[cursor + 1]) || !is_upper_hex(&value[cursor + 2]) {
                return invalid("XattrName", "invalid percent encoding");
            }
            let decoded = hex_nibble(value[cursor + 1]) * 16 + hex_nibble(value[cursor + 2]);
            if decoded == 0 || ((0x21..=0x7e).contains(&decoded) && decoded != b'%' && decoded != b'=') {
                return invalid("XattrName", "percent encoding is non-canonical");
            }
            out.push(decoded);
            cursor += 3;
        } else {
            let byte = value[cursor];
            if !(0x21..=0x7e).contains(&byte) || byte == b'%' || byte == b'=' {
                return invalid("XattrName", "xattr name byte must be percent encoded");
            }
            out.push(byte);
            cursor += 1;
        }
    }
    Ok(out)
}

pub fn encode_percent_name(value: &[u8]) -> Result<String, FormatError> {
    if value.is_empty() || value.contains(&0) {
        return invalid("XattrName", "xattr name is empty or contains NUL");
    }
    let mut out = String::with_capacity(value.len());
    for &byte in value {
        if (0x21..=0x7e).contains(&byte) && byte != b'%' && byte != b'=' {
            out.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut out, "%{byte:02X}").expect("writing to String cannot fail");
        }
    }
    Ok(out)
}

/// Convert Linux's version-2 POSIX ACL xattr ABI into v45 canonical SCHILY
/// POSIX.1e text. Numeric qualifiers are retained without name-service lookup.
pub fn linux_posix_acl_xattr_to_schily(value: &[u8]) -> Result<Vec<u8>, FormatError> {
    if value.len() < 4 || (value.len() - 4) % 8 != 0 || value[..4] != 2u32.to_le_bytes() {
        return invalid("LinuxAcl", "invalid POSIX ACL xattr framing");
    }
    let mut entries = Vec::new();
    for entry in value[4..].chunks_exact(8) {
        let tag = u16::from_le_bytes([entry[0], entry[1]]);
        let permissions = u16::from_le_bytes([entry[2], entry[3]]);
        let id = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
        if permissions & !7 != 0 {
            return invalid("LinuxAcl", "invalid POSIX ACL permissions");
        }
        let perms = format!(
            "{}{}{}",
            if permissions & 4 != 0 { 'r' } else { '-' },
            if permissions & 2 != 0 { 'w' } else { '-' },
            if permissions & 1 != 0 { 'x' } else { '-' },
        );
        let (category, text) = match tag {
            0x01 if id == u32::MAX => (0, format!("user::{perms}")),
            0x04 if id == u32::MAX => (1, format!("group::{perms}")),
            0x20 if id == u32::MAX => (2, format!("other::{perms}")),
            0x02 if id != u32::MAX => (3, format!("user:{id}:{perms}")),
            0x08 if id != u32::MAX => (4, format!("group:{id}:{perms}")),
            0x10 if id == u32::MAX => (5, format!("mask::{perms}")),
            _ => return invalid("LinuxAcl", "invalid POSIX ACL tag or qualifier"),
        };
        let qualifier = if matches!(category, 3 | 4) { id } else { 0 };
        entries.push((category, qualifier, text));
    }
    entries.sort_by_key(|(category, qualifier, _)| (*category, *qualifier));
    let text = entries.into_iter().map(|(_, _, text)| text).collect::<Vec<_>>().join(",").into_bytes();
    validate_posix_acl_text(&text)?;
    Ok(text)
}

/// Convert canonical v45 SCHILY POSIX.1e text to Linux's version-2 POSIX ACL
/// xattr ABI without consulting host user/group databases.
pub fn schily_posix_acl_to_linux_xattr(value: &[u8]) -> Result<Vec<u8>, FormatError> {
    validate_posix_acl_text(value)?;
    let text = std::str::from_utf8(value).map_err(|_| FormatError::InvalidArchive("ACL text is not UTF-8"))?;
    let mut entries = Vec::new();
    for tuple in text.split(',') {
        let fields = tuple.split(':').collect::<Vec<_>>();
        let permissions = fields[2].bytes().enumerate().fold(0u16, |bits, (index, byte)| bits | if byte != b'-' { 4 >> index } else { 0 });
        let numeric_id = |name: &str| name.parse::<u32>().or_else(|_| fields.get(3).ok_or(()).and_then(|id| id.parse::<u32>().map_err(|_| ())));
        let (rank, tag, id) = match (fields[0], fields[1]) {
            ("user", "") => (0, 0x01u16, u32::MAX),
            ("user", id) => (1, 0x02, numeric_id(id).map_err(|_| FormatError::ReaderUnsupported("named ACL principals require numeric qualifiers"))?),
            ("group", "") => (2, 0x04, u32::MAX),
            ("group", id) => (3, 0x08, numeric_id(id).map_err(|_| FormatError::ReaderUnsupported("named ACL principals require numeric qualifiers"))?),
            ("mask", "") => (4, 0x10, u32::MAX),
            ("other", "") => (5, 0x20, u32::MAX),
            _ => return invalid("LinuxAcl", "unsupported POSIX ACL tuple"),
        };
        entries.push((rank, id, tag, permissions));
    }
    entries.sort_by_key(|(rank, id, _, _)| (*rank, *id));
    let mut out = 2u32.to_le_bytes().to_vec();
    for (_, id, tag, permissions) in entries {
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&permissions.to_le_bytes());
        out.extend_from_slice(&id.to_le_bytes());
    }
    Ok(out)
}

pub(crate) fn parse_timestamp(value: &[u8]) -> Result<(i64, u32), FormatError> {
    let text = std::str::from_utf8(value).map_err(|_| FormatError::InvalidArchive("timestamp is not ASCII"))?;
    if text.is_empty() || text.starts_with('+') {
        return invalid("Timestamp", "timestamp is not canonical");
    }
    let (integer, fraction) = text.split_once('.').map_or((text, None), |(a, b)| (a, Some(b)));
    if integer == "-0" {
        return invalid("Timestamp", "timestamp is not canonical");
    }
    let unsigned = integer.strip_prefix('-').unwrap_or(integer);
    if unsigned.is_empty() || !unsigned.bytes().all(|byte| byte.is_ascii_digit()) || (unsigned.len() > 1 && unsigned.starts_with('0')) {
        return invalid("Timestamp", "timestamp integer is not canonical");
    }
    let seconds = integer.parse::<i64>().map_err(|_| FormatError::InvalidArchive("timestamp seconds exceed i64"))?;
    let nanos = if let Some(fraction) = fraction {
        if fraction.is_empty() || fraction.len() > 9 || !fraction.bytes().all(|byte| byte.is_ascii_digit()) || fraction.ends_with('0') {
            return invalid("Timestamp", "timestamp fraction is not canonical");
        }
        let mut padded = fraction.to_owned();
        padded.extend(std::iter::repeat_n('0', 9 - fraction.len()));
        padded.parse::<u32>().unwrap()
    } else {
        0
    };
    Ok((seconds, nanos))
}

fn parse_sparse_line(payload: &[u8], cursor: &mut usize) -> Result<u64, FormatError> {
    let relative = payload[*cursor..].iter().position(|byte| *byte == b'\n').ok_or(FormatError::InvalidArchive("sparse map line is truncated"))?;
    let end = cursor.checked_add(relative).ok_or(FormatError::InvalidArchive("sparse map overflow"))?;
    let value = parse_decimal_u64(&payload[*cursor..end], "sparse map value")?;
    *cursor = end + 1;
    Ok(value)
}

fn required<'a>(records: &'a PaxRecords, key: &'static str) -> Result<&'a [u8], FormatError> {
    records.get(key).map(Vec::as_slice).ok_or(FormatError::InvalidArchive("required revision-45 PAX key is missing"))
}

fn expect_value(records: &PaxRecords, key: &'static str, expected: &[u8], structure: &'static str) -> Result<(), FormatError> {
    if required(records, key)? != expected {
        return invalid(structure, "required PAX value mismatch");
    }
    Ok(())
}

fn parse_decimal_u64(value: &[u8], field: &'static str) -> Result<u64, FormatError> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) || (value.len() > 1 && value[0] == b'0') {
        return Err(FormatError::InvalidMetadata { structure: field, reason: "value is not minimal unsigned decimal" });
    }
    std::str::from_utf8(value)
        .ok()
        .and_then(|text| text.parse().ok())
        .ok_or(FormatError::InvalidMetadata { structure: field, reason: "decimal value exceeds u64" })
}

fn parse_decimal_usize(value: &[u8], field: &'static str) -> Result<usize, FormatError> {
    let parsed = parse_decimal_u64(value, field)?;
    usize::try_from(parsed).map_err(|_| FormatError::InvalidMetadata { structure: field, reason: "decimal value exceeds usize" })
}

fn parse_fixed_hex_u32(value: &[u8], width: usize, field: &'static str) -> Result<u32, FormatError> {
    if value.len() != width || !value.iter().all(is_lower_hex) {
        return Err(FormatError::InvalidMetadata { structure: field, reason: "value is not fixed-width lowercase hexadecimal" });
    }
    u32::from_str_radix(std::str::from_utf8(value).unwrap(), 16)
        .map_err(|_| FormatError::InvalidMetadata { structure: field, reason: "hexadecimal value exceeds u32" })
}

fn parse_fixed_hex_u64(value: &[u8], width: usize, field: &'static str) -> Result<u64, FormatError> {
    if value.len() != width || !value.iter().all(is_lower_hex) {
        return Err(FormatError::InvalidMetadata { structure: field, reason: "value is not fixed-width lowercase hexadecimal" });
    }
    u64::from_str_radix(std::str::from_utf8(value).unwrap(), 16)
        .map_err(|_| FormatError::InvalidMetadata { structure: field, reason: "hexadecimal value exceeds u64" })
}

fn parse_fixed_hex_32(value: &[u8]) -> Result<[u8; 32], FormatError> {
    if value.len() != 64 || !value.iter().all(is_lower_hex) {
        return invalid("AuxiliaryMetadata", "SHA-256 is not lowercase hexadecimal");
    }
    let mut out = [0u8; 32];
    for (index, pair) in value.chunks_exact(2).enumerate() {
        out[index] = hex_nibble(pair[0]) * 16 + hex_nibble(pair[1]);
    }
    Ok(out)
}

fn is_lower_hex(byte: &u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)
}

fn is_upper_hex(byte: &u8) -> bool {
    byte.is_ascii_digit() || (b'A'..=b'F').contains(byte)
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}

fn ascii_string(value: &[u8], field: &'static str) -> Result<String, FormatError> {
    if !value.is_ascii() {
        return Err(FormatError::InvalidMetadata { structure: field, reason: "value is not ASCII" });
    }
    Ok(std::str::from_utf8(value).unwrap().to_owned())
}

pub(crate) fn is_source_os(value: &str) -> bool {
    matches!(value, "linux" | "freebsd" | "netbsd" | "openbsd" | "solaris" | "macos" | "windows" | "other-unix" | "other")
}

pub(crate) fn valid_filesystem_token(value: &str) -> bool {
    value == "unknown"
        || (1..=32).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.' | b'_'))
}

fn valid_profile_token(value: &str) -> bool {
    (1..=MAX_PROFILE_ID_LEN).contains(&value.len())
        && value.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.' | b'_'))
}

fn is_valid_profile_id(value: &str) -> bool {
    if is_known_profile(value) {
        return true;
    }
    if !valid_profile_token(value) || !value.starts_with("x.") {
        return false;
    }
    let components: Vec<_> = value.split('.').collect();
    components.len() >= 4
        && components[0] == "x"
        && components[1..].iter().all(|component| {
            !component.is_empty()
                && component.as_bytes()[0].is_ascii_alphanumeric()
                && component.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_'))
        })
}

fn is_known_profile(value: &str) -> bool {
    matches!(value, PORTABLE_PROFILE | POSIX_PROFILE | LINUX_PROFILE | MACOS_PROFILE | WINDOWS_PROFILE)
}

fn is_builtin_aux_kind(value: &str) -> bool {
    matches!(
        value,
        CAPTURE_REPORT_KIND
            | "windows.security-descriptor"
            | "windows.alternate-data"
            | "windows.ea-data"
            | "windows.reparse-data"
            | "windows.object-id"
            | "windows.property-data"
            | "windows.efs-raw"
            | "macos.resource-fork"
            | "macos.acl-native"
            | "macos.finder-info"
            | "generic.xattr"
            | "generic.named-fork"
    )
}

fn is_native_primary_key(key: &String) -> bool {
    key.starts_with("TZAP.linux.")
        || key.starts_with("TZAP.macos.")
        || key.starts_with("TZAP.windows.")
        || key.starts_with("TZAP.posix.")
        || key.starts_with("LIBARCHIVE.")
        || key.starts_with("SCHILY.")
        || key == "TZAP.unix.ctime-observed"
}

fn is_system_primary_key(key: &String) -> bool {
    key.starts_with("TZAP.posix.device-")
        || key == "TZAP.linux.whiteout"
        || key == "TZAP.linux.project-id"
        || key == "TZAP.windows.reparse-placeholder"
        || key == "TZAP.windows.directory-case-sensitive"
        || key.starts_with("LIBARCHIVE.xattr.security")
        || key.starts_with("LIBARCHIVE.xattr.trusted")
        || key.starts_with("LIBARCHIVE.xattr.system")
}

fn has_no_change_flags(records: &PaxRecords) -> Result<bool, FormatError> {
    let linux =
        records.get("TZAP.linux.fsflags").map(|value| parse_fixed_hex_u64(value, 16, "Linux file flags")).transpose()?.is_some_and(|value| value & 0x30 != 0);
    let bsd = records
        .get("TZAP.bsd.st-flags")
        .map(|value| parse_fixed_hex_u64(value, 16, "BSD file flags"))
        .transpose()?
        .is_some_and(|value| value & 0x0006_0006 != 0);
    let macos = records
        .get("TZAP.macos.st-flags")
        .map(|value| parse_fixed_hex_u64(value, 16, "macOS file flags"))
        .transpose()?
        .is_some_and(|value| value & 0x009f_0086 != 0);
    let projected = records.get("SCHILY.fflags").is_some_and(|value| {
        value.split(|byte| *byte == b',').any(|token| matches!(token, b"append" | b"immutable" | b"sappnd" | b"schg" | b"uappnd" | b"uchg"))
    });
    Ok(linux || bsd || macos || projected)
}

fn valid_percent_encoded_detail(value: &[u8]) -> bool {
    let mut cursor = 0usize;
    let mut decoded = Vec::with_capacity(value.len());
    while cursor < value.len() {
        if value[cursor].is_ascii_alphanumeric() || matches!(value[cursor], b'.' | b'_' | b'~' | b'-') {
            decoded.push(value[cursor]);
            cursor += 1;
        } else if value[cursor] == b'%' && cursor + 2 < value.len() && is_upper_hex(&value[cursor + 1]) && is_upper_hex(&value[cursor + 2]) {
            let byte = hex_nibble(value[cursor + 1]) * 16 + hex_nibble(value[cursor + 2]);
            if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-') {
                return false;
            }
            decoded.push(byte);
            cursor += 3;
        } else {
            return false;
        }
    }
    std::str::from_utf8(&decoded).is_ok()
}

fn invalid<T>(structure: &'static str, reason: &'static str) -> Result<T, FormatError> {
    Err(FormatError::InvalidMetadata { structure, reason })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_pax_round_trip_and_order_rejection() {
        let records = portable_primary_pax(b"file.txt", 0o644, "other", false).unwrap();
        let encoded = encode_canonical_pax(&records).unwrap();
        assert_eq!(parse_canonical_pax(&encoded).unwrap(), records);

        let mut reversed = encoded.split_inclusive(|byte| *byte == b'\n').map(<[u8]>::to_vec).collect::<Vec<_>>();
        reversed.swap(0, 1);
        assert!(parse_canonical_pax(&reversed.concat()).is_err());
    }

    #[test]
    fn timestamp_rejects_negative_zero_integer_component() {
        assert!(parse_timestamp(b"-0").is_err());
        assert!(parse_timestamp(b"-0.5").is_err());
        assert_eq!(parse_timestamp(b"-1.5").unwrap(), (-1, 500_000_000));
    }

    #[test]
    fn sparse_map_requires_merged_bounded_extents() {
        let mut payload = b"2\n0\n2\n4\n2\n".to_vec();
        payload.resize(512, 0);
        payload.extend_from_slice(b"abcd");
        let sparse = parse_sparse_payload(&payload, 6).unwrap();
        assert_eq!(sparse.extents.len(), 2);

        let mut adjacent = b"2\n0\n2\n2\n2\n".to_vec();
        adjacent.resize(512, 0);
        adjacent.extend_from_slice(b"abcd");
        assert!(parse_sparse_payload(&adjacent, 4).is_err());
    }

    #[test]
    fn linux_posix_acl_binary_and_canonical_text_round_trip() {
        let text = b"user::rw-,group::r--,other::---,user:123:r--,mask::r--";
        let binary = schily_posix_acl_to_linux_xattr(text).unwrap();
        assert_eq!(&binary[..4], &2u32.to_le_bytes());
        assert_eq!(linux_posix_acl_xattr_to_schily(&binary).unwrap(), text);
    }

    #[test]
    fn profile_dependencies_and_extension_namespace_are_enforced() {
        let mut records = portable_primary_pax(b"file.txt", 0o644, "linux", false).unwrap();
        records.insert("TZAP.metadata.required-profiles".into(), b"linux-backup-v1,portable-v1".to_vec());
        assert!(parse_primary_metadata(&records).is_err());

        records.insert("TZAP.metadata.required-profiles".into(), b"linux-backup-v1,portable-v1,posix-backup-v1".to_vec());
        assert!(parse_primary_metadata(&records).is_ok());
    }

    #[test]
    fn canonical_base64_and_percent_name_codecs_round_trip_binary_values() {
        for len in 0..=512usize {
            let value = (0..len).map(|index| (index.wrapping_mul(73).wrapping_add(19) & 0xff) as u8).collect::<Vec<_>>();
            let encoded = canonical_base64_encode(&value);
            assert_eq!(canonical_base64_decode(&encoded).unwrap(), value);
            assert!(!encoded.contains(&b'='));
        }
        assert!(canonical_base64_decode(b"AB").is_err());
        assert!(canonical_base64_decode(b"ABC").is_err());

        let name = (1u8..=u8::MAX).collect::<Vec<_>>();
        let encoded = encode_percent_name(&name).unwrap();
        assert_eq!(decode_percent_name(encoded.as_bytes()).unwrap(), name);
        assert!(encode_percent_name(b"").is_err());
        assert!(encode_percent_name(b"nul\0name").is_err());
    }

    #[test]
    fn xattr_profile_ownership_depends_on_declared_source_os() {
        let mut macos = portable_primary_pax(b"file.txt", 0o644, "macos", false).unwrap();
        macos.insert("TZAP.metadata.required-profiles".into(), b"macos-backup-v1,portable-v1,posix-backup-v1".to_vec());
        macos.insert("LIBARCHIVE.xattr.security.example".into(), canonical_base64_encode(b"value"));
        let parsed = parse_primary_metadata(&macos).unwrap();
        assert!(parsed.requires_system_restore);

        let mut linux = portable_primary_pax(b"file.txt", 0o644, "linux", false).unwrap();
        linux.insert("TZAP.metadata.required-profiles".into(), b"portable-v1,posix-backup-v1".to_vec());
        linux.insert("LIBARCHIVE.xattr.unknown.example".into(), canonical_base64_encode(b"value"));
        assert!(parse_primary_metadata(&linux).is_err());
        linux.insert("TZAP.metadata.required-profiles".into(), b"linux-backup-v1,portable-v1,posix-backup-v1".to_vec());
        let parsed = parse_primary_metadata(&linux).unwrap();
        assert!(parsed.requires_system_restore);
    }

    #[test]
    fn macos_entitlement_and_superuser_flags_are_system_class() {
        for flags in [0x0000_0080u64, 0x0008_0000, 0x0010_0000, 0x0080_0000] {
            let mut records = PaxRecords::new();
            records.insert("TZAP.macos.st-flags".into(), format!("{flags:016x}").into_bytes());
            assert!(has_no_change_flags(&records).unwrap());
        }
    }

    #[test]
    fn generic_xattr_auxiliary_uses_the_declared_source_os_namespace_rules() {
        let mut records = portable_primary_pax(b"file.txt", 0o644, "macos", false).unwrap();
        records.insert("TZAP.metadata.required-profiles".into(), b"macos-backup-v1,portable-v1,posix-backup-v1".to_vec());
        let primary = parse_primary_metadata(&records).unwrap();
        let mut auxiliary = AuxiliaryRecord {
            ordinal: 0,
            kind: "generic.xattr".into(),
            profile: "posix-backup-v1".into(),
            restore_class: RestoreClass::System,
            native: true,
            name_encoding: "bytes-base64".into(),
            decoded_name: b"security.example".to_vec(),
            flags: 0,
            logical_size: 0,
            stored_size: 0,
            sha256: [0; 32],
            meta: BTreeMap::new(),
            sparse_layout: None,
            capture_report_payload: None,
        };
        assert!(validate_group_metadata(&primary, &[auxiliary.clone()]).is_ok());

        auxiliary.profile = "linux-backup-v1".into();
        assert!(validate_group_metadata(&primary, &[auxiliary]).is_err());
    }

    #[test]
    fn capture_report_detail_must_decode_to_canonical_utf8() {
        let records = portable_primary_pax(b"file.txt", 0o644, "other", false).unwrap();
        let declaration = parse_primary_metadata(&records).unwrap().declaration;
        let invalid = b"tzap-capture-report-v1\nportable-v1\tdata\tio-error\t%C3%28\n";
        assert!(parse_capture_report(invalid, &declaration).is_err());

        let valid = b"tzap-capture-report-v1\nportable-v1\tdata\tio-error\t%C3%A9\n";
        assert!(parse_capture_report(valid, &declaration).is_ok());
    }

    #[test]
    fn textual_acl_requires_canonical_tuple_order_and_fixed_fields() {
        let mut records = portable_primary_pax(b"file.txt", 0o640, "linux", false).unwrap();
        records.insert("TZAP.metadata.required-profiles".into(), b"portable-v1,posix-backup-v1".to_vec());
        records.insert("TZAP.acl.projection".into(), b"exact".to_vec());
        records.insert("TZAP.acl.syntax".into(), b"schily-posix1e-extra-id-v1".to_vec());
        records.insert("SCHILY.acl.access".into(), b"user::rw-,group::r--,other::---,user:1000:r--,mask::r--".to_vec());
        assert!(parse_primary_metadata(&records).is_ok());

        records.insert("SCHILY.acl.access".into(), b"user::rw-,user:1000:r--,group::r--,other::---,mask::r--".to_vec());
        assert!(parse_primary_metadata(&records).is_err());
    }

    #[test]
    fn nfs4_acl_rejects_compact_permission_and_flag_fields() {
        let mut records = portable_primary_pax(b"file.txt", 0o640, "macos", false).unwrap();
        records.insert("TZAP.metadata.required-profiles".into(), b"macos-backup-v1,portable-v1,posix-backup-v1".to_vec());
        records.insert("TZAP.acl.projection".into(), b"exact".to_vec());
        records.insert("TZAP.acl.syntax".into(), b"schily-nfs4-full-extra-id-v1".to_vec());
        records.insert("SCHILY.acl.ace".into(), b"owner@:rwx-----------:-------:allow".to_vec());
        assert!(parse_primary_metadata(&records).is_ok());

        records.insert("SCHILY.acl.ace".into(), b"owner@:rwx:fd:allow".to_vec());
        assert!(parse_primary_metadata(&records).is_err());
    }

    #[test]
    fn darwin_acl_external_form_rejects_malformed_or_unbounded_payloads() {
        let mut empty = vec![0u8; 40];
        empty[..4].copy_from_slice(&[0x01, 0x2c, 0xc1, 0x6d]);

        let mut bad_magic = empty.clone();
        bad_magic[0] = 0;
        assert!(validate_darwin_acl_external(&bad_magic).is_err());
        assert!(validate_darwin_acl_external(&empty[..39]).is_err());

        let mut oversized_count = empty;
        oversized_count[36..40].copy_from_slice(&129u32.to_be_bytes());
        assert!(validate_darwin_acl_external(&oversized_count).is_err());
    }

    #[test]
    fn pax_parsing_negative_and_fuzz_vectors() {
        // Empty payload
        assert!(parse_canonical_pax(b"").is_err());
        assert!(parse_canonical_pax(b"10").is_err());

        // Non-minimal decimal: leading zero, negative, invalid digit
        assert!(parse_canonical_pax(b"05 a=b\n").is_err());
        assert!(parse_canonical_pax(b"010 key=val\n").is_err());
        assert!(parse_canonical_pax(b"-5 a=b\n").is_err());
        assert!(parse_canonical_pax(b"+5 a=b\n").is_err());
        assert!(parse_canonical_pax(b"x5 a=b\n").is_err());
        assert!(parse_canonical_pax(b" a=b\n").is_err());
        assert!(parse_canonical_pax(b"abc key=val\n").is_err());

        // Missing space delimiter
        assert!(parse_canonical_pax(b"6a=b\n").is_err());

        // Missing trailing newline
        assert!(parse_canonical_pax(b"6 a=b ").is_err());
        assert!(parse_canonical_pax(b"6 a=bX").is_err());
        assert!(parse_canonical_pax(b"11 key=valX").is_err());

        // Missing equals sign in body
        assert!(parse_canonical_pax(b"6 abcd\n").is_err());
        assert!(parse_canonical_pax(b"11 key val\n").is_err());

        // Non-canonical ASCII keys (spaces, control chars, equals in key, empty key)
        assert!(parse_canonical_pax(b"8 a b=c\n").is_err());
        assert!(parse_canonical_pax(b"8 a\x00b=c\n").is_err());
        assert!(parse_canonical_pax(b"8 =val\n").is_err());
        assert!(parse_canonical_pax(b"11 =val\n").is_err());
        assert!(parse_canonical_pax(b"12 key\x01=val\n").is_err());
        assert!(parse_canonical_pax(b"12 key=va\0l\n").is_err());

        // Declared length does not frame record / out of bounds
        assert!(parse_canonical_pax(b"50 a=b\n").is_err());
        assert!(parse_canonical_pax(b"3 a=b\n").is_err());
        assert!(parse_canonical_pax(b"12 key=val\n").is_err());

        // Valid canonical record (11 bytes total: "11 foo=bar\n")
        let records = parse_canonical_pax(b"11 foo=bar\n").unwrap();
        assert_eq!(records.get("foo").unwrap(), b"bar");

        // Non-canonical key order or duplicate keys
        assert!(parse_canonical_pax(b"10 zed=1\n10 aaa=2\n").is_err());
        assert!(parse_canonical_pax(b"11 bbb=val\n11 aaa=val\n").is_err());
        assert!(parse_canonical_pax(b"11 key=val\n11 key=val\n").is_err());
    }

    #[test]
    fn streaming_auxiliary_validator_error_cases() {
        let expected_sha256_hex = format!("{:x}", sha2::Sha256::digest(b"correct payload"));
        let mut records = PaxRecords::new();
        records.insert("TZAP.aux.version".into(), b"1".to_vec());
        records.insert("TZAP.aux.kind".into(), b"generic.xattr".to_vec());
        records.insert("TZAP.aux.profile".into(), b"posix-backup-v1".to_vec());
        records.insert("TZAP.aux.restore-class".into(), b"same-os".to_vec());
        records.insert("TZAP.aux.native".into(), b"1".to_vec());
        records.insert("TZAP.aux.name-encoding".into(), b"bytes-base64".to_vec());
        records.insert("TZAP.aux.name".into(), b"dXNlci5jb21tZW50".to_vec());
        records.insert("TZAP.aux.flags".into(), b"0000000000000000".to_vec());
        records.insert("TZAP.aux.logical-size".into(), b"15".to_vec());
        records.insert("TZAP.aux.sha256".into(), expected_sha256_hex.into_bytes());

        // Case 1: Payload exceeds declared size
        let mut validator = AuxiliaryStreamValidator::new(&records, 0, 15).unwrap();
        validator.observe(b"012345678901234").unwrap();
        assert!(validator.observe(b"extra").is_err());

        // Case 2: Incomplete payload on finish
        let mut validator = AuxiliaryStreamValidator::new(&records, 0, 15).unwrap();
        validator.observe(b"short").unwrap();
        assert!(validator.finish().is_err());

        // Case 3: Checksum mismatch on finish
        let mut validator = AuxiliaryStreamValidator::new(&records, 0, 15).unwrap();
        validator.observe(b"wrong payload!!").unwrap();
        assert!(validator.finish().is_err());

        // Case 4: Valid payload succeeds
        let mut validator = AuxiliaryStreamValidator::new(&records, 0, 15).unwrap();
        validator.observe(b"correct payload").unwrap();
        let finished = validator.finish().unwrap();
        assert_eq!(finished.decoded_name, b"user.comment");
    }

    #[test]
    fn decoder_and_hex_utility_validations() {
        // canonical_base64_decode
        assert!(canonical_base64_decode(b"").unwrap().is_empty());
        assert_eq!(canonical_base64_decode(b"aGVsbG8").unwrap(), b"hello");
        assert!(canonical_base64_decode(b"aGVsbG8=").is_err()); // padding rejected
        assert!(canonical_base64_decode(b"aGVsbG8\n").is_err()); // newline rejected
        assert!(canonical_base64_decode(b"aGVsbG8?").is_err()); // invalid char

        // parse_fixed_hex_u32
        assert_eq!(parse_fixed_hex_u32(b"0000002a", 8, "test").unwrap(), 42);
        assert!(parse_fixed_hex_u32(b"0000002A", 8, "test").is_err()); // uppercase
        assert!(parse_fixed_hex_u32(b"2a", 8, "test").is_err()); // not 8 chars
        assert!(parse_fixed_hex_u32(b"0000002g", 8, "test").is_err()); // invalid hex

        // parse_fixed_hex_u64
        assert_eq!(parse_fixed_hex_u64(b"000000000000002a", 16, "test").unwrap(), 42);
        assert!(parse_fixed_hex_u64(b"000000000000002A", 16, "test").is_err());
        assert!(parse_fixed_hex_u64(b"2a", 16, "test").is_err());

        // parse_fixed_hex_32
        assert!(parse_fixed_hex_32(b"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").is_ok());
        assert!(parse_fixed_hex_32(b"short").is_err());
        assert!(parse_fixed_hex_32(b"00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF").is_err());

        // parse_decimal_usize and parse_decimal_u64
        assert_eq!(parse_decimal_usize(b"123", "test").unwrap(), 123);
        assert_eq!(parse_decimal_usize(b"42", "test").unwrap(), 42);
        assert!(parse_decimal_usize(b"0123", "test").is_err());
        assert!(parse_decimal_usize(b"", "test").is_err());
        assert!(parse_decimal_usize(b"123a", "test").is_err());

        assert_eq!(parse_decimal_u64(b"0", "test").unwrap(), 0);
        assert_eq!(parse_decimal_u64(b"456", "test").unwrap(), 456);
        assert_eq!(parse_decimal_u64(b"789", "test").unwrap(), 789);
        assert!(parse_decimal_u64(b"01", "test").is_err());
        assert!(parse_decimal_u64(b"18446744073709551616", "test").is_err()); // overflow
        assert!(parse_decimal_u64(b"9999999999999999999999999999", "test").is_err());
    }

    #[test]
    fn sparse_layout_parsing_and_profile_methods() {
        // Odd count of fields in sparse layout payload
        assert!(parse_sparse_payload(b"20\n30\n", 100).is_err());

        // Valid layout using encode_v45_sparse_map + payload
        let mut map = crate::encode_v45_sparse_map(&[SparseExtent { offset: 20, length: 30 }], 100).unwrap();
        map.extend_from_slice(&[0x11u8; 30]);
        let layout = parse_sparse_payload(&map, 100).unwrap();
        assert_eq!(layout.logical_size, 100);
        assert_eq!(layout.extents.len(), 1);
        assert_eq!(layout.extents[0].offset, 20);
        assert_eq!(layout.extents[0].length, 30);

        // Extent out of bounds (offset 80 + length 30 > 100)
        let bad_map = crate::encode_v45_sparse_map(&[SparseExtent { offset: 80, length: 30 }], 100);
        assert!(bad_map.is_err());

        // Profiles and unknown required profiles
        assert!(is_known_profile("portable-v1"));
        assert!(is_known_profile("posix-backup-v1"));
        assert!(is_known_profile("macos-backup-v1"));
        assert!(is_known_profile("linux-backup-v1"));
        assert!(is_known_profile("windows-backup-v1"));
        assert!(!is_known_profile("x.org.tzap.custom"));

        let mut records = portable_primary_pax(b"file.txt", 0o644, "linux", false).unwrap();
        records.insert("TZAP.metadata.required-profiles".into(), b"linux-backup-v1,portable-v1,posix-backup-v1,x.org.tzap.custom".to_vec());
        let primary = parse_primary_metadata(&records).unwrap();
        assert!(primary.declaration.has_unknown_required_profile());
        assert!(primary.declaration.profile_required("x.org.tzap.custom"));
        assert!(primary.declaration.profile_required("portable-v1"));
    }

    #[test]
    fn archive_timestamp_methods_and_formatting() {
        let ts_zero = ArchiveTimestamp::from_seconds(123);
        assert_eq!(ts_zero.seconds, 123);
        assert_eq!(ts_zero.nanoseconds, 0);
        assert_eq!(ts_zero.canonical_pax_value().unwrap(), b"123");
        assert_eq!(format!("{ts_zero}"), "123");

        let ts_frac = ArchiveTimestamp::new(123, 450_000_000);
        assert_eq!(ts_frac.canonical_pax_value().unwrap(), b"123.45");
        assert_eq!(format!("{ts_frac}"), "123.45");

        let ts_full = ArchiveTimestamp::new(123, 123_456_789);
        assert_eq!(ts_full.canonical_pax_value().unwrap(), b"123.123456789");
        assert_eq!(format!("{ts_full}"), "123.123456789");

        let ts_invalid = ArchiveTimestamp::new(123, 1_000_000_000);
        assert!(ts_invalid.canonical_pax_value().is_err());
    }

    #[test]
    fn metadata_declaration_query_methods() {
        let decl = MetadataDeclaration {
            required_profiles: vec!["portable-v1".into(), "x.custom.vendor.profile-v1".into()],
            optional_profiles: vec!["posix-backup-v1".into(), "x.opt.vendor.profile-v1".into()],
            source_os: "linux".into(),
            source_filesystem: "ext4".into(),
            capture_status: CaptureStatus::Complete,
            owner_kind_posix: true,
            mode_origin_native: true,
            portable_mode: 0o755,
            portable_attributes: Some(0),
        };

        assert!(decl.profile_selected("portable-v1"));
        assert!(decl.profile_selected("posix-backup-v1"));
        assert!(decl.profile_selected("x.custom.vendor.profile-v1"));
        assert!(!decl.profile_selected("unknown-v1"));

        assert!(decl.profile_required("portable-v1"));
        assert!(decl.profile_required("x.custom.vendor.profile-v1"));
        assert!(!decl.profile_required("posix-backup-v1"));

        assert!(decl.has_unknown_required_profile());
        let unk_req: Vec<_> = decl.unknown_required_profiles().collect();
        assert_eq!(unk_req, vec!["x.custom.vendor.profile-v1"]);

        let unk_opt: Vec<_> = decl.unknown_optional_profiles().collect();
        assert_eq!(unk_opt, vec!["x.opt.vendor.profile-v1"]);
    }

    #[test]
    fn canonical_pax_encode_error_cases() {
        let empty = PaxRecords::new();
        assert!(encode_canonical_pax(&empty).is_err());

        let mut invalid_key = PaxRecords::new();
        invalid_key.insert("invalid=key".into(), b"val".to_vec());
        assert!(encode_canonical_pax(&invalid_key).is_err());

        let mut nul_val = PaxRecords::new();
        nul_val.insert("valid_key".into(), b"val\0with_nul".to_vec());
        assert!(encode_canonical_pax(&nul_val).is_err());
    }

    #[test]
    fn parse_timestamp_comprehensive() {
        assert_eq!(parse_timestamp(b"0").unwrap(), (0, 0));
        assert_eq!(parse_timestamp(b"123456").unwrap(), (123456, 0));
        assert_eq!(parse_timestamp(b"-123456").unwrap(), (-123456, 0));
        assert_eq!(parse_timestamp(b"123.456").unwrap(), (123, 456_000_000));
        assert_eq!(parse_timestamp(b"123.1").unwrap(), (123, 100_000_000));
        assert_eq!(parse_timestamp(b"123.000000001").unwrap(), (123, 1));
        assert_eq!(parse_timestamp(b"-123.001").unwrap(), (-123, 1_000_000));

        assert!(parse_timestamp(b"").is_err());
        assert!(parse_timestamp(b"+123").is_err());
        assert!(parse_timestamp(b"0123").is_err());
        assert!(parse_timestamp(b"-0123").is_err());
        assert!(parse_timestamp(b"123.").is_err());
        assert!(parse_timestamp(b"123.0").is_err()); // trailing zero in fraction
        assert!(parse_timestamp(b"123.10").is_err());
        assert!(parse_timestamp(b"123.1234567890").is_err()); // > 9 digits
        assert!(parse_timestamp(b"123.abc").is_err());
        assert!(parse_timestamp(b"abc").is_err());
    }

    #[test]
    fn auxiliary_name_decoding_comprehensive() {
        assert_eq!(decode_auxiliary_name("none", b"").unwrap(), Vec::<u8>::new());
        assert!(decode_auxiliary_name("none", b"not-empty").is_err());

        assert_eq!(decode_auxiliary_name("utf8", b"valid-name").unwrap(), b"valid-name");
        assert!(decode_auxiliary_name("utf8", b"").is_err());
        assert!(decode_auxiliary_name("utf8", b"\xff\xff").is_err());

        assert_eq!(decode_auxiliary_name("bytes-base64", b"aGVsbG8").unwrap(), b"hello");
        assert!(decode_auxiliary_name("bytes-base64", b"").is_err());

        // UTF-16LE base64
        let utf16le = "test".encode_utf16().flat_map(|u| u.to_le_bytes()).collect::<Vec<_>>();
        let encoded_utf16 = canonical_base64_encode(&utf16le);
        assert_eq!(decode_auxiliary_name("utf16le-base64", &encoded_utf16).unwrap(), utf16le);
        assert!(decode_auxiliary_name("utf16le-base64", b"aA").is_err()); // odd byte length
        assert!(decode_auxiliary_name("unknown-encoding", b"abc").is_err());
    }

    #[test]
    fn windows_security_descriptor_validation_comprehensive() {
        // Minimum valid self-relative SD with Owner and Group SIDs, no DACL/SACL
        // Owner SID: S-1-5-18 (8 bytes: [1, 1, 0,0,0,0,0,5, 18,0,0,0] = 12 bytes)
        // Header: [1, 0, control(2), owner_off(4), group_off(4), sacl_off(4), dacl_off(4)]
        let mut sd = vec![0u8; 20];
        sd[0] = 1; // Revision 1
        let control = 0x8000u16; // Self-relative
        sd[2..4].copy_from_slice(&control.to_le_bytes());
        sd[4..8].copy_from_slice(&20u32.to_le_bytes()); // Owner offset at 20
        sd[8..12].copy_from_slice(&32u32.to_le_bytes()); // Group offset at 32
        let sid1 = [1u8, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]; // 12 bytes
        let sid2 = [1u8, 1, 0, 0, 0, 0, 0, 5, 19, 0, 0, 0]; // 12 bytes
        sd.extend_from_slice(&sid1);
        sd.extend_from_slice(&sid2);

        let sec_info = 0x0000_0001 | 0x0000_0002; // OWNER | GROUP
        assert!(validate_self_relative_security_descriptor(&sd, sec_info).is_ok());

        // Error: security_information = 0
        assert!(validate_self_relative_security_descriptor(&sd, 0).is_err());
        // Error: truncated header < 20
        assert!(validate_self_relative_security_descriptor(&sd[..16], sec_info).is_err());
        // Error: not self-relative (control missing 0x8000)
        let mut not_sr = sd.clone();
        not_sr[2..4].copy_from_slice(&0u16.to_le_bytes());
        assert!(validate_self_relative_security_descriptor(&not_sr, sec_info).is_err());
        // Error: unaligned offset
        let mut unaligned = sd.clone();
        unaligned[4..8].copy_from_slice(&21u32.to_le_bytes());
        assert!(validate_self_relative_security_descriptor(&unaligned, sec_info).is_err());

        // Test with DACL
        let mut sd_dacl = vec![0u8; 20];
        sd_dacl[0] = 1;
        let control = 0x8000u16 | 0x0004 | 0x2000; // Self-relative | DACL Present | Unprotected DACL
        sd_dacl[2..4].copy_from_slice(&control.to_le_bytes());
        // Valid empty DACL header: revision=2, sbz1=0, acl_size=8, ace_count=0, sbz2=0.
        sd_dacl[16..20].copy_from_slice(&20u32.to_le_bytes()); // DACL offset at 20
        let mut dacl = vec![0u8; 8];
        dacl[0] = 2; // ACL revision 2
        dacl[2..4].copy_from_slice(&8u16.to_le_bytes());
        sd_dacl.extend_from_slice(&dacl);

        let dacl_info = 0x0000_0004 | 0x2000_0000; // DACL | UNPROTECTED_DACL
        assert!(validate_self_relative_security_descriptor(&sd_dacl, dacl_info).is_ok());

        // Error: DACL with invalid revision
        let mut bad_acl = sd_dacl.clone();
        bad_acl[20] = 99;
        assert!(validate_self_relative_security_descriptor(&bad_acl, dacl_info).is_err());
    }

    #[test]
    fn windows_reparse_buffer_and_ea_stream_validation() {
        // Reparse buffer: 0xA000000C (symlink)
        let mut symlink_reparse = vec![0u8; 8 + 12 + 8];
        symlink_reparse[0..4].copy_from_slice(&0xA000_000Cu32.to_le_bytes());
        let data_len = 12 + 8;
        symlink_reparse[4..6].copy_from_slice(&(data_len as u16).to_le_bytes());
        // SubstituteNameOffset=0, SubstituteNameLength=4, PrintNameOffset=4, PrintNameLength=4
        symlink_reparse[8..10].copy_from_slice(&0u16.to_le_bytes());
        symlink_reparse[10..12].copy_from_slice(&4u16.to_le_bytes());
        symlink_reparse[12..14].copy_from_slice(&4u16.to_le_bytes());
        symlink_reparse[14..16].copy_from_slice(&4u16.to_le_bytes());
        assert!(validate_reparse_buffer(&symlink_reparse, 0xA000_000C).is_ok());

        // Error: truncated reparse buffer
        assert!(validate_reparse_buffer(&symlink_reparse[..6], 0xA000_000C).is_err());
        // Error: wrong tag
        assert!(validate_reparse_buffer(&symlink_reparse, 0xA000_0003).is_err());

        // Windows EA stream validation
        // EA Header: next_offset (4), flags (1), name_len (1), val_len (2), name (name_len+1), val (val_len)
        let mut ea = Vec::new();
        let name = b"MY_EA\0";
        let val = b"val123";
        let _rec_len = 8 + name.len() + val.len(); // 8 + 6 + 6 = 20
        ea.extend_from_slice(&0u32.to_le_bytes()); // next = 0 (last entry)
        ea.push(0); // flags
        ea.push(5); // name_len = 5 (excluding NUL)
        ea.extend_from_slice(&(val.len() as u16).to_le_bytes());
        ea.extend_from_slice(name);
        ea.extend_from_slice(val);
        assert!(validate_windows_ea_stream(&ea).is_ok());

        // Error: empty EA stream
        assert!(validate_windows_ea_stream(&[]).is_err());
        // Error: EA stream with name missing NUL
        let mut bad_ea = ea.clone();
        bad_ea[8 + 5] = b'X';
        assert!(validate_windows_ea_stream(&bad_ea).is_err());
    }

    #[test]
    fn capture_report_validation_comprehensive() {
        let records = portable_primary_pax(b"file.txt", 0o644, "linux", false).unwrap();
        let decl = parse_primary_metadata(&records).unwrap().declaration;

        // Valid capture report
        let valid_report = b"tzap-capture-report-v1\nportable-v1\tsparse-layout\tchanged-during-read\textent%20map\n";
        let rows = parse_capture_report(valid_report, &decl).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].profile, "portable-v1");
        assert_eq!(rows[0].metadata_class, "sparse-layout");
        assert_eq!(rows[0].reason, "changed-during-read");
        assert_eq!(rows[0].encoded_detail, "extent%20map");

        // Error: wrong header
        assert!(parse_capture_report(b"bad-header\n", &decl).is_err());
        // Error: not ending in newline
        assert!(parse_capture_report(b"tzap-capture-report-v1\nportable-v1\tsparse-layout\tchanged-during-read\textent%20map", &decl).is_err());
        // Error: duplicate/unsorted rows
        let dup = b"tzap-capture-report-v1\nportable-v1\ta\tio-error\tdetail\nportable-v1\ta\tio-error\tdetail\n";
        assert!(parse_capture_report(dup, &decl).is_err());
        // Error: unselected profile
        let unselected = b"tzap-capture-report-v1\nunknown-v1\ta\tio-error\tdetail\n";
        assert!(parse_capture_report(unselected, &decl).is_err());
        // Error: invalid reason
        let bad_reason = b"tzap-capture-report-v1\nportable-v1\ta\tunknown-reason\tdetail\n";
        assert!(parse_capture_report(bad_reason, &decl).is_err());
    }

    #[test]
    fn helper_predicates_and_tokens() {
        assert!(is_source_os("linux"));
        assert!(is_source_os("macos"));
        assert!(is_source_os("windows"));
        assert!(is_source_os("freebsd"));
        assert!(is_source_os("other"));
        assert!(!is_source_os("plan9"));

        assert!(valid_filesystem_token("unknown"));
        assert!(valid_filesystem_token("ext4"));
        assert!(valid_filesystem_token("apfs"));
        assert!(valid_filesystem_token("ntfs"));
        assert!(!valid_filesystem_token(""));
        assert!(!valid_filesystem_token("INVALID_UPPERCASE"));

        assert!(is_valid_profile_id("portable-v1"));
        assert!(is_valid_profile_id("x.custom.vendor.profile-v1"));
        assert!(!is_valid_profile_id("x.short"));
        assert!(!is_valid_profile_id("custom-without-x"));
    }

    #[test]
    fn parse_primary_metadata_negatives() {
        let path = b"test.txt";
        let valid_records = portable_primary_pax(path, 0o644, "linux", false).unwrap();

        // 1. Unknown source OS
        let mut rec = valid_records.clone();
        rec.insert("TZAP.source.os".into(), b"plan9".to_vec());
        assert!(parse_primary_metadata(&rec).is_err());

        // 2. Invalid filesystem token
        let mut rec = valid_records.clone();
        rec.insert("TZAP.source.fs".into(), b"EXT4_CAPS".to_vec());
        assert!(parse_primary_metadata(&rec).is_err());

        // 3. Invalid capture status
        let mut rec = valid_records.clone();
        rec.insert("TZAP.capture.status".into(), b"corrupted".to_vec());
        assert!(parse_primary_metadata(&rec).is_err());

        // 4. Invalid portable owner kind
        let mut rec = valid_records.clone();
        rec.insert("TZAP.portable.owner.kind".into(), b"root".to_vec());
        assert!(parse_primary_metadata(&rec).is_err());

        // 5. Invalid portable mode origin
        let mut rec = valid_records.clone();
        rec.insert("TZAP.portable.mode.origin".into(), b"invalid".to_vec());
        assert!(parse_primary_metadata(&rec).is_err());

        // 6. Incomplete GNU sparse declaration
        let mut rec = valid_records;
        rec.insert("GNU.sparse.major".into(), b"1".to_vec());
        rec.insert("GNU.sparse.minor".into(), b"0".to_vec());
        rec.insert("GNU.sparse.name".into(), b"test.txt".to_vec());
        // missing GNU.sparse.numblocks
        assert!(parse_primary_metadata(&rec).is_err());
    }

    #[test]
    fn generated_canonical_pax_records_round_trip_with_unicode_and_non_ascii_values() {
        let keys = ["TZAP.path", "TZAP.owner.name", "TZAP.description", "TZAP.payload-hint"];
        let values = ["資料/проекты/مرحبا-日本語.txt".as_bytes(), "München — café\n".as_bytes(), &[0x01, 0x7f, 0x80, 0xff][..], "こんにちは世界".as_bytes()];

        let mut state = 0x1234_5678_9abc_def0u64;
        for _case in 0..256 {
            let mut records = PaxRecords::new();
            let count = (next_u64(&mut state) % keys.len() as u64 + 1) as usize;
            for _ in 0..count {
                let key = keys[(next_u64(&mut state) as usize) % keys.len()];
                let value = values[(next_u64(&mut state) as usize) % values.len()];
                records.insert(key.to_owned(), value.to_vec());
            }
            let encoded = encode_canonical_pax(&records).unwrap();
            assert_eq!(parse_canonical_pax(&encoded).unwrap(), records);
        }
    }

    fn next_u64(state: &mut u64) -> u64 {
        *state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        *state
    }
}
