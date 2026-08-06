#[cfg(test)]
use super::os_restore::apply_restored_regular_file_metadata;
#[cfg(unix)]
use super::os_restore::numeric_ownership_supported;
#[cfg(target_os = "macos")]
use super::os_restore::validate_darwin_acl_external;
#[cfg(target_os = "macos")]
use super::os_restore::MACOS_KNOWN_SETTABLE_FLAGS;
#[cfg(windows)]
use super::os_restore::{
    apply_generic_xattr_auxiliaries, apply_windows_basic_metadata,
    apply_windows_security_descriptor, restore_windows_efs_temp,
};
#[cfg(target_os = "linux")]
use super::os_restore::{
    apply_generic_xattr_auxiliaries_to_path, apply_linux_inode_flags, apply_linux_project_id,
};
use super::os_restore::{
    apply_restored_regular_file_metadata_parts, apply_windows_alternate_streams,
    macos_flags_require_system, macos_flags_supported, native_auxiliary_restore_supported,
    native_primary_restore_unsupported, parse_macos_flags, record_metadata_application_failure,
    source_os_matches_current_host, special_object_restore_supported, system_xattr_name,
    windows_reparse_metadata_supported, RestoredRegularMetadata,
};
#[cfg(target_os = "linux")]
use super::sparse::punch_linux_sparse_holes;
use super::sparse::{
    create_temp_regular_file, publish_regular_file, stream_sparse_primary_payload,
};
#[cfg(windows)]
use super::sparse::{prepare_windows_sparse_file, verify_windows_sparse_file};
use super::*;

#[cfg(windows)]
use cap_std::fs::OpenOptionsExt as _;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    FileBasicInfo, GetFileInformationByHandleEx, DELETE, FILE_BASIC_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_WRITE_ATTRIBUTES,
};

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

pub(crate) trait TarMemberStreamHandler {
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

pub(super) enum StreamingTarState {
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
    pub(crate) fn new_member(group_start: u64) -> Self {
        Self::Header {
            metadata: V45StreamingGroup::default(),
            group_start,
            group_size: 0,
            header: Vec::new(),
        }
    }
}

pub(super) enum PendingTarEntry {
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

pub(super) fn plan_restore(
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

pub(crate) struct StagedAuxiliary {
    pub(crate) record: AuxiliaryRecord,
    pub(crate) file: fs::File,
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

fn format_error_from_extract_error(error: ExtractError) -> FormatError {
    match error {
        ExtractError::Format(error) => error,
        ExtractError::Output(_) => {
            FormatError::FilesystemExtractionFailed("failed to write regular file")
        }
    }
}

pub(crate) fn read_member_bytes<R: TarMemberGroupReader>(
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

pub(super) fn tar_member_group_end(stream: &[u8], start: usize) -> Result<usize, FormatError> {
    try_tar_member_group_end(stream, start)?.ok_or(FormatError::InvalidArchive(
        "tar member payload exceeds stream",
    ))
}

#[cfg(test)]
pub(crate) fn restore_tar_member(
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

pub(crate) struct PreparedDestination {
    pub(crate) parent: CapDir,
    pub(crate) leaf: PathBuf,
}

pub(crate) fn prepare_destination(
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

pub(crate) fn create_new_file_options() -> CapOpenOptions {
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
pub(crate) fn remove_existing_leaf_if_needed(
    destination: &PreparedDestination,
) -> Result<(), FormatError> {
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

pub(crate) fn create_directory(destination: &PreparedDestination) -> Result<(), FormatError> {
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
