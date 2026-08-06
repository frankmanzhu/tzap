use std::collections::BTreeMap;

#[cfg(target_os = "linux")]
use crate::entry_metadata::schily_posix_acl_to_linux_xattr;
#[cfg(windows)]
use cap_std::fs::OpenOptionsExt as _;
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
    parse_auxiliary_record, parse_canonical_pax, parse_primary_metadata, parse_sparse_payload,
    validate_group_metadata, ArchiveTimestamp, AuxiliaryRecord, AuxiliaryStreamValidator,
    CaptureReportRow, CaptureStatus, MemberMetadata, PaxRecords, PortableMetadataMirror,
    PrimaryMetadata, SparseStreamValidator, CAPTURE_REPORT_KIND, MAX_AGGREGATE_PAX_PAYLOAD,
    MAX_LOCAL_PAX_PAYLOAD, REQUIRES_SYSTEM_RESTORE,
};
use crate::format::FormatError;
use crate::metadata::validate_file_path_bytes;

use super::restore::{
    tar_member_group_end, try_tar_member_group_end, StreamedTarMemberMetadata,
    TarStreamMemberSummary, TarStreamSummary,
};
use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum V45PaxKind {
    Primary,
    Auxiliary(u32),
}

#[derive(Default)]
pub(crate) struct V45StreamingGroup {
    pending: Option<(V45PaxKind, PaxRecords)>,
    auxiliary: Vec<AuxiliaryRecord>,
    aggregate_pax_bytes: usize,
}

pub(crate) struct StreamingSparsePrimary {
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

pub(super) fn validate_v45_metadata_header(header: &[u8]) -> Result<(), FormatError> {
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

pub(super) fn parse_auxiliary_pax_label(label: &[u8]) -> Option<u32> {
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

pub(super) fn validate_v45_auxiliary_header(
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

pub(super) fn validate_v45_primary_header(
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

pub(super) fn decoded_mtime(
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

pub(super) fn portable_metadata_mirror(
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

pub(super) fn v45_primary_path(
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

pub(super) fn v45_primary_link_target(
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
pub(super) struct V45PrimaryLink<'a> {
    pub(super) path: &'a [u8],
    pub(super) target: Option<&'a [u8]>,
}

pub(super) fn validate_v45_primary_cross_fields(
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
pub(super) const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x0000_0100;
const FILE_ATTRIBUTE_SPARSE_FILE: u32 = 0x0000_0200;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const FILE_ATTRIBUTE_COMPRESSED: u32 = 0x0000_0800;
const FILE_ATTRIBUTE_NOT_CONTENT_INDEXED: u32 = 0x0000_2000;
const FILE_ATTRIBUTE_ENCRYPTED: u32 = 0x0000_4000;
pub(super) const WINDOWS_ESSENTIAL_SETTABLE_ATTRIBUTES: u32 = FILE_ATTRIBUTE_READONLY
    | FILE_ATTRIBUTE_HIDDEN
    | FILE_ATTRIBUTE_SYSTEM
    | FILE_ATTRIBUTE_ARCHIVE
    | FILE_ATTRIBUTE_TEMPORARY
    | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
pub(super) const WINDOWS_ESSENTIAL_INTRINSIC_ATTRIBUTES: u32 = FILE_ATTRIBUTE_DIRECTORY
    | FILE_ATTRIBUTE_SPARSE_FILE
    | FILE_ATTRIBUTE_REPARSE_POINT
    | FILE_ATTRIBUTE_COMPRESSED
    | FILE_ATTRIBUTE_ENCRYPTED;
pub(super) const STREAM_MODIFIED_WHEN_READ: u32 = 0x0000_0001;
pub(super) const STREAM_CONTAINS_SECURITY: u32 = 0x0000_0002;
const STREAM_SPARSE_ATTRIBUTE: u32 = 0x0000_0008;

pub(super) fn validate_windows_essential_reparse_data(data: &[u8]) -> Result<u32, FormatError> {
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

pub(super) fn parse_lower_hex_u32(
    value: &[u8],
    structure: &'static str,
) -> Result<u32, FormatError> {
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

pub(super) fn v45_group_flags(
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

pub(super) fn parse_minimal_decimal_u64(
    value: &[u8],
    structure: &'static str,
) -> Result<u64, FormatError> {
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

pub(super) fn restore_phase_for_kind(kind: TarEntryKind, reparse_placeholder: bool) -> u8 {
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
