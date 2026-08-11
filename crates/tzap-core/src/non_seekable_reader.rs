use std::collections::BTreeMap;
use std::fs;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::compression::validate_exact_zstd_frame;
use crate::crypto::{decrypt_padded_aead_object, verify_integrity_tag, AeadObjectContext, HmacDomain, MasterKey, Subkeys};
use crate::entry_metadata::ArchiveTimestamp;
use crate::fec::recover_data_bytes_gf16;
use crate::format::{BlockKind, ExtractError, FormatError, BLOCK_RECORD_FRAMING_LEN, VOLUME_HEADER_LEN};
use crate::raw_stream_profile::reject_unsupported_raw_stream_profile;
use crate::reader::{
    block_record_error_is_recoverable_erasure, expected_stream_block_index, manifest_bootstrap_fields_match, observed_archive_size,
    parse_non_seekable_bootstrap_material, parse_terminal_material_read_at, recipient_wrap_subkeys_from_table, required_object_parity, startup_key_wrap_table,
    total_extraction_size_cap, v45_terminal_tail_cap, validate_crypto_class_parity_exactness, validate_reader_options, ArchiveEntry, ArchiveIndexEntry,
    ArchiveReadAt, KeyHoldingTerminalContext, NonSeekableBootstrapMaterial, OpenedArchive, ReaderOptions, RecipientWrapCandidateMasterKey,
    RecipientWrapRecordContext, StreamedArchiveOpenParts,
};
use crate::tar_model::{
    finalize_committed_directory_metadata, metadata_verification_report, MetadataVerificationReport, NoopTarStreamObserver, SafeExtractionOptions,
    TarEntryKind, TarStreamFilesystemRestoreObserver, TarStreamMemberSummary, TarStreamObserver, TarStreamSummary, TarStreamSummaryValidator,
};
use crate::wire::{BlockRecord, CryptoHeader, CryptoHeaderFixed, ExtensionTlv, RootAuthFooterV1, VolumeHeader};

const DEFAULT_MAX_RETAINED_METADATA_BYTES: usize = 128 * 1024 * 1024;
const DEFAULT_MAX_INCOMPLETE_TAR_GROUP_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_STREAMED_MEMBER_COUNT: u64 = 1_000_000;

fn parse_volume_format_dispatch(volume_header: &VolumeHeader) -> Result<(), FormatError> {
    let revision = volume_header.parse_volume_format_revision()?;
    match revision {
        crate::format::VolumeFormatRevision::V45 => Ok(()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequentialRootAuthStatus {
    Absent,
    WireValidOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequentialVerifyReport {
    pub archive_uuid: [u8; 16],
    pub session_id: [u8; 16],
    pub volume_format_rev: u16,
    pub volume_index: u32,
    pub total_volumes: u32,
    pub file_count: u64,
    pub payload_block_count: u64,
    pub tar_total_size: u64,
    pub content_sha256: [u8; 32],
    pub root_auth: SequentialRootAuthStatus,
    pub metadata: MetadataVerificationReport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequentialExtractReport {
    pub verification: SequentialVerifyReport,
    pub extracted_member_count: u64,
    pub degraded_metadata_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequentialListReport {
    pub verification: SequentialVerifyReport,
    pub entries: Vec<ArchiveEntry>,
    pub index_entries: Vec<ArchiveIndexEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonSeekableReaderOptions {
    pub reader: ReaderOptions,
    pub max_terminal_tail_size: usize,
    pub max_retained_metadata_bytes: usize,
    pub max_incomplete_tar_group_bytes: usize,
    pub max_streamed_member_count: u64,
}

impl Default for NonSeekableReaderOptions {
    fn default() -> Self {
        Self {
            reader: ReaderOptions::default(),
            max_terminal_tail_size: v45_terminal_tail_cap().expect("v45 terminal tail cap must fit usize"),
            max_retained_metadata_bytes: DEFAULT_MAX_RETAINED_METADATA_BYTES,
            max_incomplete_tar_group_bytes: DEFAULT_MAX_INCOMPLETE_TAR_GROUP_BYTES,
            max_streamed_member_count: DEFAULT_MAX_STREAMED_MEMBER_COUNT,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StreamedEnvelopeSummary {
    pub(crate) envelope_index: u64,
    pub(crate) first_block_index: u64,
    pub(crate) data_block_count: u32,
    pub(crate) parity_block_count: u32,
    pub(crate) encrypted_size: u32,
    pub(crate) plaintext_size: u32,
    pub(crate) first_frame_index: u64,
    pub(crate) frame_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StreamedFrameSummary {
    pub(crate) frame_index: u64,
    pub(crate) envelope_index: u64,
    pub(crate) offset_in_envelope: u32,
    pub(crate) compressed_size: u32,
    pub(crate) decompressed_size: u32,
    pub(crate) tar_stream_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StreamedPayloadSummary {
    pub(crate) tar: TarStreamSummary,
    pub(crate) content_sha256: [u8; 32],
    pub(crate) envelopes: Vec<StreamedEnvelopeSummary>,
    pub(crate) frames: Vec<StreamedFrameSummary>,
}

impl StreamedPayloadSummary {
    pub(crate) fn envelope_map(&self) -> Result<BTreeMap<u64, &StreamedEnvelopeSummary>, FormatError> {
        let mut map = BTreeMap::new();
        for envelope in &self.envelopes {
            if map.insert(envelope.envelope_index, envelope).is_some() {
                return Err(FormatError::InvalidArchive("duplicate streamed payload envelope"));
            }
        }
        Ok(map)
    }

    pub(crate) fn frame_map(&self) -> Result<BTreeMap<u64, &StreamedFrameSummary>, FormatError> {
        let mut map = BTreeMap::new();
        for frame in &self.frames {
            if map.insert(frame.frame_index, frame).is_some() {
                return Err(FormatError::InvalidArchive("duplicate streamed payload frame"));
            }
        }
        Ok(map)
    }

    pub(crate) fn member_start_map(&self) -> Result<BTreeMap<u64, &TarStreamMemberSummary>, FormatError> {
        let mut map = BTreeMap::new();
        for member in &self.tar.members {
            if map.insert(member.group_start, member).is_some() {
                return Err(FormatError::InvalidArchive("duplicate streamed tar member start"));
            }
        }
        Ok(map)
    }

    pub(crate) fn frame_flags(&self, frame: &StreamedFrameSummary) -> Result<u32, FormatError> {
        let frame_end = frame
            .tar_stream_offset
            .checked_add(frame.decompressed_size as u64)
            .ok_or(FormatError::InvalidArchive("streamed frame range overflow"))?;
        let mut flags = 0u32;
        if self
            .tar
            .members
            .binary_search_by_key(&frame.tar_stream_offset, |member| member.group_start)
            .is_ok()
        {
            flags |= 0x0000_0001;
        }
        let end_candidate = self
            .tar
            .members
            .partition_point(|member| member.group_start < frame_end)
            .checked_sub(1)
            .and_then(|index| self.tar.members.get(index));
        if let Some(member) = end_candidate {
            let member_end = member
                .group_start
                .checked_add(member.group_size)
                .ok_or(FormatError::InvalidArchive("streamed tar member range overflow"))?;
            if member_end == frame_end {
                flags |= 0x0000_0002;
            }
        }
        Ok(flags)
    }
}

pub fn verify_non_seekable_stream<R: Read>(reader: R, master_key: &MasterKey) -> Result<SequentialVerifyReport, FormatError> {
    verify_non_seekable_stream_with_options(reader, master_key, NonSeekableReaderOptions::default())
}

pub fn verify_non_seekable_stream_with_options<R: Read>(
    reader: R,
    master_key: &MasterKey,
    options: NonSeekableReaderOptions,
) -> Result<SequentialVerifyReport, FormatError> {
    Ok(run_non_seekable_stream(reader, NonSeekableKeySource::MasterKey(Some(master_key)), options, NoopTarStreamObserver, None)?.verification)
}

pub fn verify_non_seekable_stream_with_recipient_wrap_resolver_options<R, F>(
    reader: R,
    mut resolver: F,
    options: NonSeekableReaderOptions,
) -> Result<SequentialVerifyReport, FormatError>
where
    R: Read,
    F: FnMut(RecipientWrapRecordContext<'_>) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
{
    Ok(run_non_seekable_stream(reader, NonSeekableKeySource::RecipientWrap(&mut resolver), options, NoopTarStreamObserver, None)?.verification)
}

pub fn verify_unencrypted_non_seekable_stream_with_options<R: Read>(
    reader: R,
    options: NonSeekableReaderOptions,
) -> Result<SequentialVerifyReport, FormatError> {
    Ok(run_non_seekable_stream(reader, NonSeekableKeySource::MasterKey(None), options, NoopTarStreamObserver, None)?.verification)
}

pub fn verify_non_seekable_stream_with_bootstrap_sidecar<R: Read>(
    reader: R,
    bootstrap_sidecar: &[u8],
    master_key: &MasterKey,
    options: NonSeekableReaderOptions,
) -> Result<SequentialVerifyReport, FormatError> {
    Ok(run_non_seekable_stream(
        reader,
        NonSeekableKeySource::MasterKey(Some(master_key)),
        options,
        NoopTarStreamObserver,
        Some(bootstrap_sidecar),
    )?
    .verification)
}

pub fn verify_non_seekable_stream_with_recipient_wrap_resolver_and_bootstrap_sidecar<R, F>(
    reader: R,
    bootstrap_sidecar: &[u8],
    mut resolver: F,
    options: NonSeekableReaderOptions,
) -> Result<SequentialVerifyReport, FormatError>
where
    R: Read,
    F: FnMut(RecipientWrapRecordContext<'_>) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
{
    Ok(run_non_seekable_stream(
        reader,
        NonSeekableKeySource::RecipientWrap(&mut resolver),
        options,
        NoopTarStreamObserver,
        Some(bootstrap_sidecar),
    )?
    .verification)
}

pub fn verify_unencrypted_non_seekable_stream_with_bootstrap_sidecar<R: Read>(
    reader: R,
    bootstrap_sidecar: &[u8],
    options: NonSeekableReaderOptions,
) -> Result<SequentialVerifyReport, FormatError> {
    Ok(run_non_seekable_stream(
        reader,
        NonSeekableKeySource::MasterKey(None),
        options,
        NoopTarStreamObserver,
        Some(bootstrap_sidecar),
    )?
    .verification)
}

pub fn extract_non_seekable_stream_to_dir<R: Read>(
    reader: R,
    master_key: &MasterKey,
    output_dir: &Path,
    options: NonSeekableReaderOptions,
    extraction: SafeExtractionOptions,
) -> Result<SequentialExtractReport, ExtractError> {
    let staging = StagedExtraction::new(output_dir)?;
    let observer = TarStreamFilesystemRestoreObserver::new(
        staging.root(),
        SafeExtractionOptions {
            overwrite_existing: true,
            ..extraction
        },
    );
    let mut outcome = run_non_seekable_stream(reader, NonSeekableKeySource::MasterKey(Some(master_key)), options, observer, None)?;
    let merged_directories = existing_output_directory_paths(output_dir, &outcome.streamed_payload.tar.members);
    staging.commit(extraction)?;
    finalize_committed_directory_metadata(output_dir, &mut outcome.streamed_payload.tar.members, &merged_directories, extraction)?;
    Ok(SequentialExtractReport {
        verification: outcome.verification,
        extracted_member_count: outcome
            .streamed_payload
            .tar
            .members
            .len()
            .try_into()
            .map_err(|_| FormatError::InvalidArchive("extracted member count overflow"))?,
        degraded_metadata_count: degraded_metadata_count(&outcome.streamed_payload)?,
    })
}

fn existing_output_directory_paths(output_dir: &Path, members: &[TarStreamMemberSummary]) -> Vec<Vec<u8>> {
    members
        .iter()
        .filter(|member| member.kind == TarEntryKind::Directory)
        .filter_map(|member| {
            let path = std::str::from_utf8(&member.path).ok()?;
            let metadata = fs::symlink_metadata(output_dir.join(path)).ok()?;
            (metadata.is_dir() && !metadata.file_type().is_symlink()).then(|| member.path.clone())
        })
        .collect()
}

pub fn extract_non_seekable_stream_to_dir_with_recipient_wrap_resolver<R, F>(
    reader: R,
    mut resolver: F,
    output_dir: &Path,
    options: NonSeekableReaderOptions,
    extraction: SafeExtractionOptions,
) -> Result<SequentialExtractReport, ExtractError>
where
    R: Read,
    F: FnMut(RecipientWrapRecordContext<'_>) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
{
    let staging = StagedExtraction::new(output_dir)?;
    let observer = TarStreamFilesystemRestoreObserver::new(
        staging.root(),
        SafeExtractionOptions {
            overwrite_existing: true,
            ..extraction
        },
    );
    let mut outcome = run_non_seekable_stream(reader, NonSeekableKeySource::RecipientWrap(&mut resolver), options, observer, None)?;
    let merged_directories = existing_output_directory_paths(output_dir, &outcome.streamed_payload.tar.members);
    staging.commit(extraction)?;
    finalize_committed_directory_metadata(output_dir, &mut outcome.streamed_payload.tar.members, &merged_directories, extraction)?;
    Ok(SequentialExtractReport {
        verification: outcome.verification,
        extracted_member_count: outcome
            .streamed_payload
            .tar
            .members
            .len()
            .try_into()
            .map_err(|_| FormatError::InvalidArchive("extracted member count overflow"))?,
        degraded_metadata_count: degraded_metadata_count(&outcome.streamed_payload)?,
    })
}

pub fn extract_unencrypted_non_seekable_stream_to_dir<R: Read>(
    reader: R,
    output_dir: &Path,
    options: NonSeekableReaderOptions,
    extraction: SafeExtractionOptions,
) -> Result<SequentialExtractReport, ExtractError> {
    let staging = StagedExtraction::new(output_dir)?;
    let observer = TarStreamFilesystemRestoreObserver::new(
        staging.root(),
        SafeExtractionOptions {
            overwrite_existing: true,
            ..extraction
        },
    );
    let mut outcome = run_non_seekable_stream(reader, NonSeekableKeySource::MasterKey(None), options, observer, None)?;
    let merged_directories = existing_output_directory_paths(output_dir, &outcome.streamed_payload.tar.members);
    staging.commit(extraction)?;
    finalize_committed_directory_metadata(output_dir, &mut outcome.streamed_payload.tar.members, &merged_directories, extraction)?;
    Ok(SequentialExtractReport {
        verification: outcome.verification,
        extracted_member_count: outcome
            .streamed_payload
            .tar
            .members
            .len()
            .try_into()
            .map_err(|_| FormatError::InvalidArchive("extracted member count overflow"))?,
        degraded_metadata_count: degraded_metadata_count(&outcome.streamed_payload)?,
    })
}

pub fn extract_non_seekable_stream_to_dir_with_bootstrap_sidecar<R: Read>(
    reader: R,
    bootstrap_sidecar: &[u8],
    master_key: &MasterKey,
    output_dir: &Path,
    options: NonSeekableReaderOptions,
    extraction: SafeExtractionOptions,
) -> Result<SequentialExtractReport, ExtractError> {
    let staging = StagedExtraction::new(output_dir)?;
    let observer = TarStreamFilesystemRestoreObserver::new(
        staging.root(),
        SafeExtractionOptions {
            overwrite_existing: true,
            ..extraction
        },
    );
    let mut outcome = run_non_seekable_stream(
        reader,
        NonSeekableKeySource::MasterKey(Some(master_key)),
        options,
        observer,
        Some(bootstrap_sidecar),
    )?;
    let merged_directories = existing_output_directory_paths(output_dir, &outcome.streamed_payload.tar.members);
    staging.commit(extraction)?;
    finalize_committed_directory_metadata(output_dir, &mut outcome.streamed_payload.tar.members, &merged_directories, extraction)?;
    Ok(SequentialExtractReport {
        verification: outcome.verification,
        extracted_member_count: outcome
            .streamed_payload
            .tar
            .members
            .len()
            .try_into()
            .map_err(|_| FormatError::InvalidArchive("extracted member count overflow"))?,
        degraded_metadata_count: degraded_metadata_count(&outcome.streamed_payload)?,
    })
}

pub fn extract_non_seekable_stream_to_dir_with_recipient_wrap_resolver_and_bootstrap_sidecar<R, F>(
    reader: R,
    bootstrap_sidecar: &[u8],
    mut resolver: F,
    output_dir: &Path,
    options: NonSeekableReaderOptions,
    extraction: SafeExtractionOptions,
) -> Result<SequentialExtractReport, ExtractError>
where
    R: Read,
    F: FnMut(RecipientWrapRecordContext<'_>) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
{
    let staging = StagedExtraction::new(output_dir)?;
    let observer = TarStreamFilesystemRestoreObserver::new(
        staging.root(),
        SafeExtractionOptions {
            overwrite_existing: true,
            ..extraction
        },
    );
    let mut outcome = run_non_seekable_stream(
        reader,
        NonSeekableKeySource::RecipientWrap(&mut resolver),
        options,
        observer,
        Some(bootstrap_sidecar),
    )?;
    let merged_directories = existing_output_directory_paths(output_dir, &outcome.streamed_payload.tar.members);
    staging.commit(extraction)?;
    finalize_committed_directory_metadata(output_dir, &mut outcome.streamed_payload.tar.members, &merged_directories, extraction)?;
    Ok(SequentialExtractReport {
        verification: outcome.verification,
        extracted_member_count: outcome
            .streamed_payload
            .tar
            .members
            .len()
            .try_into()
            .map_err(|_| FormatError::InvalidArchive("extracted member count overflow"))?,
        degraded_metadata_count: degraded_metadata_count(&outcome.streamed_payload)?,
    })
}

pub fn extract_unencrypted_non_seekable_stream_to_dir_with_bootstrap_sidecar<R: Read>(
    reader: R,
    bootstrap_sidecar: &[u8],
    output_dir: &Path,
    options: NonSeekableReaderOptions,
    extraction: SafeExtractionOptions,
) -> Result<SequentialExtractReport, ExtractError> {
    let staging = StagedExtraction::new(output_dir)?;
    let observer = TarStreamFilesystemRestoreObserver::new(
        staging.root(),
        SafeExtractionOptions {
            overwrite_existing: true,
            ..extraction
        },
    );
    let mut outcome = run_non_seekable_stream(reader, NonSeekableKeySource::MasterKey(None), options, observer, Some(bootstrap_sidecar))?;
    let merged_directories = existing_output_directory_paths(output_dir, &outcome.streamed_payload.tar.members);
    staging.commit(extraction)?;
    finalize_committed_directory_metadata(output_dir, &mut outcome.streamed_payload.tar.members, &merged_directories, extraction)?;
    Ok(SequentialExtractReport {
        verification: outcome.verification,
        extracted_member_count: outcome
            .streamed_payload
            .tar
            .members
            .len()
            .try_into()
            .map_err(|_| FormatError::InvalidArchive("extracted member count overflow"))?,
        degraded_metadata_count: degraded_metadata_count(&outcome.streamed_payload)?,
    })
}

pub fn list_non_seekable_stream<R: Read>(reader: R, master_key: &MasterKey, options: NonSeekableReaderOptions) -> Result<SequentialListReport, FormatError> {
    let outcome = run_non_seekable_stream(reader, NonSeekableKeySource::MasterKey(Some(master_key)), options, NoopTarStreamObserver, None)?;
    sequential_list_report(outcome)
}

pub fn list_non_seekable_stream_with_recipient_wrap_resolver<R, F>(
    reader: R,
    mut resolver: F,
    options: NonSeekableReaderOptions,
) -> Result<SequentialListReport, FormatError>
where
    R: Read,
    F: FnMut(RecipientWrapRecordContext<'_>) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
{
    let outcome = run_non_seekable_stream(reader, NonSeekableKeySource::RecipientWrap(&mut resolver), options, NoopTarStreamObserver, None)?;
    sequential_list_report(outcome)
}

pub fn list_unencrypted_non_seekable_stream<R: Read>(reader: R, options: NonSeekableReaderOptions) -> Result<SequentialListReport, FormatError> {
    let outcome = run_non_seekable_stream(reader, NonSeekableKeySource::MasterKey(None), options, NoopTarStreamObserver, None)?;
    sequential_list_report(outcome)
}

pub fn list_non_seekable_stream_with_bootstrap_sidecar<R: Read>(
    reader: R,
    bootstrap_sidecar: &[u8],
    master_key: &MasterKey,
    options: NonSeekableReaderOptions,
) -> Result<SequentialListReport, FormatError> {
    let outcome = run_non_seekable_stream(
        reader,
        NonSeekableKeySource::MasterKey(Some(master_key)),
        options,
        NoopTarStreamObserver,
        Some(bootstrap_sidecar),
    )?;
    sequential_list_report(outcome)
}

pub fn list_non_seekable_stream_with_recipient_wrap_resolver_and_bootstrap_sidecar<R, F>(
    reader: R,
    bootstrap_sidecar: &[u8],
    mut resolver: F,
    options: NonSeekableReaderOptions,
) -> Result<SequentialListReport, FormatError>
where
    R: Read,
    F: FnMut(RecipientWrapRecordContext<'_>) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
{
    let outcome = run_non_seekable_stream(
        reader,
        NonSeekableKeySource::RecipientWrap(&mut resolver),
        options,
        NoopTarStreamObserver,
        Some(bootstrap_sidecar),
    )?;
    sequential_list_report(outcome)
}

pub fn list_unencrypted_non_seekable_stream_with_bootstrap_sidecar<R: Read>(
    reader: R,
    bootstrap_sidecar: &[u8],
    options: NonSeekableReaderOptions,
) -> Result<SequentialListReport, FormatError> {
    let outcome = run_non_seekable_stream(
        reader,
        NonSeekableKeySource::MasterKey(None),
        options,
        NoopTarStreamObserver,
        Some(bootstrap_sidecar),
    )?;
    sequential_list_report(outcome)
}

struct SequentialStreamOutcome {
    opened: OpenedArchive,
    streamed_payload: StreamedPayloadSummary,
    verification: SequentialVerifyReport,
}

fn sequential_list_report(outcome: SequentialStreamOutcome) -> Result<SequentialListReport, FormatError> {
    let index_entries = outcome.opened.list_index_entries()?;
    let entries = streamed_list_entries(&index_entries, &outcome.streamed_payload)?;
    Ok(SequentialListReport {
        verification: outcome.verification,
        entries,
        index_entries,
    })
}

type RecipientWrapResolver<'a> = dyn FnMut(RecipientWrapRecordContext<'_>) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError> + 'a;

enum NonSeekableKeySource<'a> {
    MasterKey(Option<&'a MasterKey>),
    RecipientWrap(&'a mut RecipientWrapResolver<'a>),
}

fn run_non_seekable_stream<R, O>(
    mut reader: R,
    key_source: NonSeekableKeySource<'_>,
    options: NonSeekableReaderOptions,
    observer: O,
    bootstrap_sidecar: Option<&[u8]>,
) -> Result<SequentialStreamOutcome, FormatError>
where
    R: Read,
    O: TarStreamObserver,
{
    validate_reader_options(options.reader)?;
    let mut volume_header_bytes = [0u8; VOLUME_HEADER_LEN];
    read_exact_stream(&mut reader, &mut volume_header_bytes, "VolumeHeader")?;
    let volume_header = VolumeHeader::parse(&volume_header_bytes)?;
    parse_volume_format_dispatch(&volume_header)?;

    let crypto_len = usize::try_from(volume_header.crypto_header_length).map_err(|_| FormatError::InvalidArchive("CryptoHeader length overflow"))?;
    let mut crypto_header_bytes = vec![0u8; crypto_len];
    read_exact_stream(&mut reader, &mut crypto_header_bytes, "CryptoHeader")?;
    let parsed_crypto = CryptoHeader::parse(&crypto_header_bytes, volume_header.crypto_header_length)?;
    let crypto_header = parsed_crypto.fixed.clone();
    let mut stream_cursor = checked_u64_add(VOLUME_HEADER_LEN as u64, volume_header.crypto_header_length as u64)?;
    let startup_key_wrap_table = startup_key_wrap_table(&volume_header, &parsed_crypto.kdf_params, |start, length| {
        if stream_cursor != start {
            return Err(FormatError::InvalidArchive("KeyWrapTableV1 does not start at stream cursor"));
        }
        let mut key_wrap_table_bytes = vec![0u8; length];
        read_exact_stream(&mut reader, &mut key_wrap_table_bytes, "KeyWrapTableV1")?;
        stream_cursor = checked_u64_add(stream_cursor, length as u64)?;
        Ok(key_wrap_table_bytes)
    })?;
    let subkeys = match (crypto_header.aead_algo.is_encrypted(), &parsed_crypto.kdf_params, key_source) {
        (false, _, NonSeekableKeySource::RecipientWrap(_)) => {
            return Err(FormatError::KeyMaterialMismatch);
        }
        (false, _, NonSeekableKeySource::MasterKey(_)) => Subkeys::unencrypted_placeholder(),
        (true, crate::crypto::KdfParams::RecipientWrap { .. }, NonSeekableKeySource::RecipientWrap(resolver)) => {
            let table = startup_key_wrap_table.as_ref().ok_or(FormatError::KeyMaterialMismatch)?;
            recipient_wrap_subkeys_from_table(&volume_header, &parsed_crypto, &table.table, resolver)?
        }
        (true, crate::crypto::KdfParams::RecipientWrap { .. }, NonSeekableKeySource::MasterKey(_)) => {
            return Err(FormatError::KeyMaterialMismatch);
        }
        (true, _, NonSeekableKeySource::MasterKey(master_key)) => Subkeys::derive(
            master_key.ok_or(FormatError::KeyMaterialMismatch)?,
            &volume_header.archive_uuid,
            &volume_header.session_id,
        )?,
        (true, _, NonSeekableKeySource::RecipientWrap(_)) => {
            return Err(FormatError::KeyMaterialMismatch);
        }
    };
    verify_integrity_tag(
        HmacDomain::CryptoHeader,
        crypto_header.aead_algo,
        volume_header.volume_format_rev,
        Some(&subkeys.mac_key),
        &volume_header.archive_uuid,
        &volume_header.session_id,
        parsed_crypto.hmac_covered_bytes,
        &parsed_crypto.header_hmac,
    )?;
    parsed_crypto.validate_extension_semantics()?;
    reject_unsupported_raw_stream_profile(&parsed_crypto.extensions)?;
    validate_crypto_class_parity_exactness(&crypto_header)?;
    let block_records_start = startup_key_wrap_table.as_ref().map(|table| table.block_records_start).unwrap_or(stream_cursor);
    let bootstrap = bootstrap_sidecar
        .map(|sidecar| parse_non_seekable_bootstrap_material(sidecar, &volume_header, &crypto_header, &subkeys))
        .transpose()?;
    validate_sequential_verify_supported_volume(&volume_header, &crypto_header, &parsed_crypto.extensions, bootstrap.as_ref())?;

    let block_size = crypto_header.block_size as usize;
    let record_len = block_size
        .checked_add(BLOCK_RECORD_FRAMING_LEN)
        .ok_or(FormatError::InvalidArchive("BlockRecord length overflow"))?;
    let mut stream_offset = block_records_start;
    let mut observed_block_count = 0u64;
    let mut metadata_seen = false;
    let mut pending = PendingLiveEnvelope::default();
    let mut next_envelope_index = 0u64;
    let mut retained_metadata_bytes = 0usize;
    let mut metadata_blocks = BTreeMap::new();
    let mut payload = StreamedPayloadCollector::with_observer(
        &crypto_header,
        options,
        observer,
        bootstrap.as_ref().and_then(|material| material.payload_dictionary.clone()),
    )?;

    let terminal_tail = loop {
        let mut magic = [0u8; 4];
        read_exact_stream(&mut reader, &mut magic, "BlockRecord or terminal tail")?;
        if magic != *b"TZBK" {
            let tail_start = stream_offset;
            stream_offset = checked_u64_add(stream_offset, magic.len() as u64)?;
            let mut tail = TerminalTailBuffer::new(tail_start, options.max_terminal_tail_size);
            tail.append(&magic)?;
            let mut buf = [0u8; 64 * 1024];
            loop {
                let read = read_stream_chunk(&mut reader, &mut buf)?;
                if read == 0 {
                    break;
                }
                tail.append(&buf[..read])?;
                stream_offset = checked_u64_add(stream_offset, read as u64)?;
            }
            break tail.finish(stream_offset);
        }

        let expected_block_index = expected_stream_block_index(&volume_header, observed_block_count)?;
        let mut raw = vec![0u8; record_len];
        raw[..4].copy_from_slice(&magic);
        read_exact_stream(&mut reader, &mut raw[4..], "BlockRecord")?;
        observed_block_count = checked_u64_add(observed_block_count, 1)?;
        stream_offset = checked_u64_add(stream_offset, record_len as u64)?;

        match BlockRecord::parse(&raw, block_size) {
            Ok(record) => {
                if record.block_index != expected_block_index {
                    return Err(FormatError::InvalidArchive("BlockRecord index does not match stream position"));
                }
                handle_live_record(
                    record,
                    &mut pending,
                    LiveStreamContext {
                        payload: &mut payload,
                        subkeys: &subkeys,
                        volume_header: &volume_header,
                        crypto_header: &crypto_header,
                        next_envelope_index: &mut next_envelope_index,
                        metadata_seen: &mut metadata_seen,
                        metadata_blocks: &mut metadata_blocks,
                        retained_metadata_bytes: &mut retained_metadata_bytes,
                        max_retained_metadata_bytes: options.max_retained_metadata_bytes,
                    },
                )?;
            }
            Err(err) if block_record_error_is_recoverable_erasure(&err) => {
                handle_live_erasure(
                    &mut pending,
                    LiveStreamContext {
                        payload: &mut payload,
                        subkeys: &subkeys,
                        volume_header: &volume_header,
                        crypto_header: &crypto_header,
                        next_envelope_index: &mut next_envelope_index,
                        metadata_seen: &mut metadata_seen,
                        metadata_blocks: &mut metadata_blocks,
                        retained_metadata_bytes: &mut retained_metadata_bytes,
                        max_retained_metadata_bytes: options.max_retained_metadata_bytes,
                    },
                    expected_block_index,
                )?;
            }
            Err(err) => return Err(err),
        }
    };

    if !pending.is_empty() {
        finalize_live_envelope(&mut pending, &mut payload, &subkeys, &volume_header, &crypto_header, &mut next_envelope_index)?;
    }

    let terminal = parse_terminal_material_read_at(
        &terminal_tail,
        terminal_tail.stream_len,
        terminal_tail.start_offset,
        observed_block_count,
        KeyHoldingTerminalContext {
            subkeys: &subkeys,
            volume_header: &volume_header,
            crypto_header: &crypto_header,
            crypto_header_bytes: &crypto_header_bytes,
        },
    )?;
    if let Some(bootstrap) = &bootstrap {
        if !manifest_bootstrap_fields_match(&terminal.manifest_footer, &bootstrap.manifest_footer) {
            return Err(FormatError::InvalidArchive("bootstrap sidecar conflicts with terminal ManifestFooter"));
        }
    }
    let observed_archive_bytes = observed_archive_size([terminal_tail.stream_len])?;
    let streamed_payload = payload.finish()?;
    if streamed_payload.tar.total_extraction_size > total_extraction_size_cap(options.reader, observed_archive_bytes) {
        return Err(FormatError::ReaderUnsupported("total extraction size exceeds configured cap"));
    }

    let root_auth = root_auth_status(terminal.root_auth_footer.as_ref());
    let opened = OpenedArchive::from_streamed_parts(StreamedArchiveOpenParts {
        options: options.reader,
        observed_archive_bytes,
        subkeys,
        blocks: metadata_blocks,
        crypto_header_bytes,
        volume_header,
        crypto_header,
        manifest_footer: terminal.manifest_footer,
        volume_trailer: terminal.volume_trailer,
        root_auth_footer: terminal.root_auth_footer,
    })?;
    opened.verify_streamed_payload_summary(&streamed_payload)?;

    let verification = SequentialVerifyReport {
        archive_uuid: opened.volume_header.archive_uuid,
        session_id: opened.volume_header.session_id,
        volume_format_rev: opened.volume_header.volume_format_rev,
        volume_index: opened.volume_header.volume_index,
        total_volumes: opened.manifest_footer.total_volumes,
        file_count: opened.index_root.header.file_count,
        payload_block_count: opened.index_root.header.payload_block_count,
        tar_total_size: opened.index_root.header.tar_total_size,
        content_sha256: opened.index_root.header.content_sha256,
        root_auth,
        metadata: metadata_verification_report(&streamed_payload.tar.members)?,
    };

    Ok(SequentialStreamOutcome {
        opened,
        streamed_payload,
        verification,
    })
}

fn degraded_metadata_count(payload: &StreamedPayloadSummary) -> Result<u64, FormatError> {
    payload.tar.members.iter().try_fold(0u64, |count, member| {
        count
            .checked_add(member.diagnostics.len() as u64)
            .ok_or(FormatError::InvalidArchive("degraded metadata count overflow"))
    })
}

fn streamed_list_entries(index_entries: &[ArchiveIndexEntry], payload: &StreamedPayloadSummary) -> Result<Vec<ArchiveEntry>, FormatError> {
    let mut latest_by_path = BTreeMap::<Vec<u8>, &TarStreamMemberSummary>::new();
    for member in &payload.tar.members {
        let replace = latest_by_path
            .get(&member.path)
            .map(|existing| member.group_start > existing.group_start)
            .unwrap_or(true);
        if replace {
            latest_by_path.insert(member.path.clone(), member);
        }
    }

    index_entries
        .iter()
        .map(|entry| {
            let member = latest_by_path
                .get(entry.path.as_bytes())
                .ok_or(FormatError::InvalidArchive("streamed tar member missing from final index"))?;
            let v45 = &member.v45_metadata;
            let mtime = v45.portable_mirror.mtime;
            Ok(ArchiveEntry {
                path: entry.path.clone(),
                file_data_size: entry.file_data_size,
                kind: member.kind,
                mode: member.mode,
                mtime: ArchiveTimestamp::new(mtime.0, mtime.1),
                diagnostics: member.diagnostics.clone(),
                link_target: member.link_target.as_ref().map(|target| String::from_utf8_lossy(target).into_owned()),
                created: parse_timestamp_opt(&v45.primary_records, "LIBARCHIVE.creationtime"),
                accessed: parse_timestamp_opt(&v45.primary_records, "atime"),
                attributes: v45.portable_mirror.attributes,
                uid: v45.portable_mirror.uid,
                gid: v45.portable_mirror.gid,
                uname: v45.portable_mirror.uname.as_ref().map(|bytes| String::from_utf8_lossy(bytes).into_owned()),
                gname: v45.portable_mirror.gname.as_ref().map(|bytes| String::from_utf8_lossy(bytes).into_owned()),
            })
        })
        .collect()
}

fn parse_timestamp_opt(records: &crate::entry_metadata::PaxRecords, key: &str) -> Option<ArchiveTimestamp> {
    let bytes = records.get(key)?;
    let (sec, nsec) = crate::entry_metadata::parse_timestamp(bytes).ok()?;
    Some(ArchiveTimestamp::new(sec, nsec))
}

struct StagedExtraction {
    tempdir: tempfile::TempDir,
    root: PathBuf,
    output_dir: PathBuf,
}

impl StagedExtraction {
    fn new(output_dir: &Path) -> Result<Self, ExtractError> {
        let parent = output_dir
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let tempdir = tempfile::Builder::new()
            .prefix(".tzap-nonseekable-")
            .tempdir_in(parent)
            .map_err(ExtractError::Output)?;
        let root = tempdir.path().join("root");
        fs::create_dir(&root).map_err(ExtractError::Output)?;
        Ok(Self {
            tempdir,
            root,
            output_dir: output_dir.to_path_buf(),
        })
    }

    fn root(&self) -> &Path {
        &self.root
    }

    fn commit(self, options: SafeExtractionOptions) -> Result<(), ExtractError> {
        match fs::symlink_metadata(&self.output_dir) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                    return Err(FormatError::UnsafeArchivePath.into());
                }
                preflight_staged_merge(&self.root, &self.output_dir, options)?;
                merge_staged_dir(&self.root, &self.output_dir, options)?;
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                if let Some(parent) = self.output_dir.parent().filter(|path| !path.as_os_str().is_empty()) {
                    fs::create_dir_all(parent).map_err(ExtractError::Output)?;
                }
                fs::rename(&self.root, &self.output_dir).map_err(ExtractError::Output)?;
            }
            Err(_) => {
                return Err(FormatError::FilesystemExtractionFailed("failed to inspect extraction directory").into());
            }
        }
        drop(self.tempdir);
        Ok(())
    }
}

fn preflight_staged_merge(staged_root: &Path, output_root: &Path, options: SafeExtractionOptions) -> Result<(), FormatError> {
    for entry in read_dir_sorted(staged_root)? {
        let staged_path = entry.path();
        let relative = staged_path.strip_prefix(staged_root).map_err(|_| FormatError::UnsafeArchivePath)?;
        preflight_staged_entry(&staged_path, output_root, relative, options)?;
    }
    Ok(())
}

fn preflight_staged_entry(staged_path: &Path, output_root: &Path, relative: &Path, options: SafeExtractionOptions) -> Result<(), FormatError> {
    let final_path = output_root.join(relative);
    let staged_metadata =
        fs::symlink_metadata(staged_path).map_err(|_| FormatError::FilesystemExtractionFailed("failed to inspect staged extraction output"))?;
    if let Some(parent) = relative.parent().filter(|path| !path.as_os_str().is_empty()) {
        preflight_relative_parent_chain(output_root, parent)?;
    }
    match fs::symlink_metadata(&final_path) {
        Ok(final_metadata) => {
            let final_type = final_metadata.file_type();
            if final_type.is_symlink() {
                return Err(FormatError::UnsafeArchivePath);
            }
            if staged_metadata.file_type().is_dir() {
                if !final_type.is_dir() {
                    return Err(FormatError::UnsafeOverwrite);
                }
            } else if final_type.is_dir() || !options.overwrite_existing {
                return Err(FormatError::UnsafeOverwrite);
            }
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(_) => {
            return Err(FormatError::FilesystemExtractionFailed("failed to inspect extraction destination"));
        }
    }
    if staged_metadata.file_type().is_dir() {
        for entry in read_dir_sorted(staged_path)? {
            let child_relative = relative.join(entry.file_name());
            preflight_staged_entry(&entry.path(), output_root, &child_relative, options)?;
        }
    }
    Ok(())
}

fn preflight_relative_parent_chain(root: &Path, parent: &Path) -> Result<(), FormatError> {
    let mut current = root.to_path_buf();
    for component in parent.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                let file_type = metadata.file_type();
                if file_type.is_symlink() || !file_type.is_dir() {
                    return Err(FormatError::UnsafeArchivePath);
                }
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(_) => {
                return Err(FormatError::FilesystemExtractionFailed("failed to inspect extraction destination"));
            }
        }
    }
    Ok(())
}

fn merge_staged_dir(staged_dir: &Path, final_dir: &Path, options: SafeExtractionOptions) -> Result<(), ExtractError> {
    fs::create_dir_all(final_dir).map_err(ExtractError::Output)?;
    for entry in read_dir_sorted(staged_dir)? {
        let staged_path = entry.path();
        let final_path = final_dir.join(entry.file_name());
        let metadata = fs::symlink_metadata(&staged_path).map_err(|_| FormatError::FilesystemExtractionFailed("failed to inspect staged extraction output"))?;
        if metadata.file_type().is_dir() {
            match fs::symlink_metadata(&final_path) {
                Ok(final_metadata) if !final_metadata.file_type().is_symlink() && final_metadata.file_type().is_dir() => {}
                Ok(_) => return Err(FormatError::UnsafeOverwrite.into()),
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    fs::rename(&staged_path, &final_path).map_err(ExtractError::Output)?;
                    continue;
                }
                Err(_) => return Err(FormatError::FilesystemExtractionFailed("failed to inspect extraction destination").into()),
            }
            merge_staged_dir(&staged_path, &final_path, options)?;
            continue;
        }
        if options.overwrite_existing && fs::symlink_metadata(&final_path).is_ok() {
            fs::remove_file(&final_path).map_err(ExtractError::Output)?;
        }
        fs::rename(&staged_path, &final_path).map_err(ExtractError::Output)?;
    }
    Ok(())
}

fn read_dir_sorted(path: &Path) -> Result<Vec<fs::DirEntry>, FormatError> {
    let mut entries = fs::read_dir(path)
        .map_err(|_| FormatError::FilesystemExtractionFailed("failed to read directory"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| FormatError::FilesystemExtractionFailed("failed to read directory"))?;
    entries.sort_by_key(|entry| entry.file_name());
    Ok(entries)
}

fn validate_sequential_verify_supported_volume(
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
    extensions: &[ExtensionTlv<'_>],
    bootstrap: Option<&NonSeekableBootstrapMaterial>,
) -> Result<(), FormatError> {
    reject_unsupported_raw_stream_profile(extensions)?;
    if volume_header.stripe_width != 1 || volume_header.volume_index != 0 {
        return Err(FormatError::ReaderUnsupported("sequential reader supports only single-volume archive input"));
    }
    if crypto_header.stripe_width != volume_header.stripe_width {
        return Err(FormatError::InvalidArchive("VolumeHeader and CryptoHeader stripe_width differ"));
    }
    if crypto_header.has_dictionary != 0 && bootstrap.and_then(|material| material.payload_dictionary.as_ref()).is_none() {
        return Err(FormatError::ReaderUnsupported(
            "dictionary bootstrap required for non-seekable sequential verification",
        ));
    }
    Ok(())
}

struct LiveStreamContext<'a, O: TarStreamObserver> {
    payload: &'a mut StreamedPayloadCollector<O>,
    subkeys: &'a Subkeys,
    volume_header: &'a VolumeHeader,
    crypto_header: &'a CryptoHeaderFixed,
    next_envelope_index: &'a mut u64,
    metadata_seen: &'a mut bool,
    metadata_blocks: &'a mut BTreeMap<u64, BlockRecord>,
    retained_metadata_bytes: &'a mut usize,
    max_retained_metadata_bytes: usize,
}

fn handle_live_record<O: TarStreamObserver>(
    record: BlockRecord,
    pending: &mut PendingLiveEnvelope,
    context: LiveStreamContext<'_, O>,
) -> Result<(), FormatError> {
    match record.kind {
        BlockKind::PayloadData => {
            if *context.metadata_seen {
                return Err(FormatError::InvalidArchive("payload BlockRecord appears after metadata"));
            }
            if pending.awaiting_tentative_parity {
                return Err(FormatError::InvalidArchive(
                    "sequential payload envelope boundary is ambiguous after CRC erasure",
                ));
            }
            if pending.saw_last_data {
                finalize_live_envelope(
                    pending,
                    &mut *context.payload,
                    context.subkeys,
                    context.volume_header,
                    context.crypto_header,
                    &mut *context.next_envelope_index,
                )?;
            }
            pending.note_block(record.block_index);
            let is_last_data = record.is_last_data();
            pending.data_shards.push(Some(record.payload));
            if is_last_data {
                pending.saw_last_data = true;
            }
            if pending.data_shards.len() > context.crypto_header.fec_data_shards as usize {
                return Err(FormatError::InvalidArchive("sequential payload envelope exceeds data-shard cap"));
            }
        }
        BlockKind::PayloadParity => {
            if *context.metadata_seen {
                return Err(FormatError::InvalidArchive("payload parity BlockRecord appears after metadata"));
            }
            if pending.awaiting_tentative_parity {
                pending.awaiting_tentative_parity = false;
                pending.saw_last_data = true;
            } else if pending.data_shards.is_empty() || !pending.saw_last_data {
                return Err(FormatError::InvalidArchive("payload parity appears before envelope data is complete"));
            }
            pending.note_block(record.block_index);
            pending.parity_shards.push(Some(record.payload));
            if pending.parity_shards.len() > context.crypto_header.fec_parity_shards as usize {
                return Err(FormatError::InvalidArchive("sequential payload envelope exceeds parity-shard cap"));
            }
        }
        _ => {
            if !pending.is_empty() {
                finalize_live_envelope(
                    pending,
                    &mut *context.payload,
                    context.subkeys,
                    context.volume_header,
                    context.crypto_header,
                    &mut *context.next_envelope_index,
                )?;
            }
            *context.metadata_seen = true;
            retain_metadata_record(
                &mut *context.metadata_blocks,
                record,
                &mut *context.retained_metadata_bytes,
                context.max_retained_metadata_bytes,
            )?;
        }
    }
    Ok(())
}

fn retain_metadata_record(
    metadata_blocks: &mut BTreeMap<u64, BlockRecord>,
    record: BlockRecord,
    retained_metadata_bytes: &mut usize,
    max_retained_metadata_bytes: usize,
) -> Result<(), FormatError> {
    let retained = record
        .payload
        .len()
        .checked_add(BLOCK_RECORD_FRAMING_LEN)
        .ok_or(FormatError::InvalidArchive("metadata retention overflow"))?;
    *retained_metadata_bytes = retained_metadata_bytes
        .checked_add(retained)
        .ok_or(FormatError::InvalidArchive("metadata retention overflow"))?;
    if *retained_metadata_bytes > max_retained_metadata_bytes {
        return Err(FormatError::ReaderUnsupported("retained metadata exceeds configured streaming cap"));
    }
    if metadata_blocks.insert(record.block_index, record).is_some() {
        return Err(FormatError::InvalidArchive("duplicate BlockRecord index"));
    }
    Ok(())
}

fn handle_live_erasure<O: TarStreamObserver>(
    pending: &mut PendingLiveEnvelope,
    context: LiveStreamContext<'_, O>,
    expected_block_index: u64,
) -> Result<(), FormatError> {
    if *context.metadata_seen {
        return Ok(());
    }
    if pending.saw_last_data && pending.parity_shards.len() >= required_object_parity(pending.data_shards.len() as u64, context.crypto_header)? as usize {
        finalize_live_envelope(
            pending,
            &mut *context.payload,
            context.subkeys,
            context.volume_header,
            context.crypto_header,
            &mut *context.next_envelope_index,
        )?;
        *context.metadata_seen = true;
        return Ok(());
    }
    if pending.saw_last_data {
        return Err(FormatError::BadCrc { structure: "BlockRecord" });
    }
    if !sequential_payload_parity_is_guaranteed(context.crypto_header) {
        return Err(FormatError::BadCrc { structure: "BlockRecord" });
    }
    pending.note_block(expected_block_index);
    pending.data_shards.push(None);
    pending.awaiting_tentative_parity = true;
    if pending.data_shards.len() > context.crypto_header.fec_data_shards as usize {
        return Err(FormatError::InvalidArchive("sequential payload envelope exceeds data-shard cap"));
    }
    Ok(())
}

fn sequential_payload_parity_is_guaranteed(crypto_header: &CryptoHeaderFixed) -> bool {
    crypto_header.fec_parity_shards > 0 && (crypto_header.volume_loss_tolerance > 0 || crypto_header.bit_rot_buffer_pct > 0)
}

fn finalize_live_envelope<O: TarStreamObserver>(
    pending: &mut PendingLiveEnvelope,
    payload: &mut StreamedPayloadCollector<O>,
    subkeys: &Subkeys,
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
    next_envelope_index: &mut u64,
) -> Result<(), FormatError> {
    if !pending.saw_last_data {
        return Err(FormatError::InvalidArchive("sequential payload envelope is missing last-data flag"));
    }
    if pending.data_shards.len() > crypto_header.fec_data_shards as usize {
        return Err(FormatError::InvalidArchive("sequential payload envelope exceeds data-shard cap"));
    }
    if pending.parity_shards.len() > crypto_header.fec_parity_shards as usize {
        return Err(FormatError::InvalidArchive("sequential payload envelope exceeds parity-shard cap"));
    }
    let required_parity = required_object_parity(pending.data_shards.len() as u64, crypto_header)?;
    if pending.parity_shards.len() < required_parity as usize {
        return Err(FormatError::InvalidArchive(
            "sequential payload envelope has insufficient parity for recovery settings",
        ));
    }
    let first_block_index = pending
        .first_block_index
        .ok_or(FormatError::InvalidArchive("sequential payload envelope is missing first block"))?;

    let block_size = crypto_header.block_size as usize;
    let encrypted = recover_data_bytes_gf16(&pending.data_shards, &pending.parity_shards, block_size)?;
    let plaintext = decrypt_padded_aead_object(
        AeadObjectContext {
            algo: crypto_header.aead_algo,
            key: &subkeys.enc_key,
            nonce_seed: &subkeys.nonce_seed,
            domain: b"envelope",
            archive_uuid: &volume_header.archive_uuid,
            session_id: &volume_header.session_id,
            counter: *next_envelope_index,
        },
        &encrypted,
    )?;
    payload.decode_envelope(
        *next_envelope_index,
        first_block_index,
        pending.data_shards.len(),
        pending.parity_shards.len(),
        crypto_header.block_size as usize,
        &plaintext,
    )?;
    *next_envelope_index = checked_u64_add(*next_envelope_index, 1)?;
    *pending = PendingLiveEnvelope::default();
    Ok(())
}

#[derive(Debug, Default)]
struct PendingLiveEnvelope {
    first_block_index: Option<u64>,
    data_shards: Vec<Option<Vec<u8>>>,
    parity_shards: Vec<Option<Vec<u8>>>,
    saw_last_data: bool,
    awaiting_tentative_parity: bool,
}

impl PendingLiveEnvelope {
    fn is_empty(&self) -> bool {
        self.data_shards.is_empty() && self.parity_shards.is_empty()
    }

    fn note_block(&mut self, block_index: u64) {
        if self.first_block_index.is_none() {
            self.first_block_index = Some(block_index);
        }
    }
}

struct StreamedPayloadCollector<O = NoopTarStreamObserver> {
    tar: TarStreamSummaryValidator<O>,
    hasher: Sha256,
    max_tar_stream_size: usize,
    payload_dictionary: Option<Vec<u8>>,
    envelopes: Vec<StreamedEnvelopeSummary>,
    frames: Vec<StreamedFrameSummary>,
}

impl<O: TarStreamObserver> StreamedPayloadCollector<O> {
    fn with_observer(
        crypto_header: &CryptoHeaderFixed,
        options: NonSeekableReaderOptions,
        observer: O,
        payload_dictionary: Option<Vec<u8>>,
    ) -> Result<Self, FormatError> {
        Ok(Self {
            tar: TarStreamSummaryValidator::with_observer(
                crypto_header.max_path_length,
                options.reader.max_total_extraction_size,
                options.max_incomplete_tar_group_bytes,
                options.max_streamed_member_count,
                observer,
            ),
            hasher: Sha256::new(),
            max_tar_stream_size: options.reader.max_verify_tar_size,
            payload_dictionary,
            envelopes: Vec::new(),
            frames: Vec::new(),
        })
    }

    fn decode_envelope(
        &mut self,
        envelope_index: u64,
        first_block_index: u64,
        data_block_count: usize,
        parity_block_count: usize,
        block_size: usize,
        plaintext: &[u8],
    ) -> Result<(), FormatError> {
        if plaintext.is_empty() {
            return Err(FormatError::InvalidArchive("payload envelope plaintext has no frames"));
        }
        let first_frame_index = u64::try_from(self.frames.len()).map_err(|_| FormatError::InvalidArchive("FrameEntry count overflow"))?;
        let mut cursor = 0usize;
        while cursor < plaintext.len() {
            let frame_len = zstd::zstd_safe::find_frame_compressed_size(&plaintext[cursor..]).map_err(|_| FormatError::InvalidZstdFrame)?;
            if frame_len == 0 {
                return Err(FormatError::InvalidZstdFrame);
            }
            let end = checked_usize_add(cursor, frame_len)?;
            validate_exact_zstd_frame(&plaintext[cursor..end])?;
            self.decode_frame(envelope_index, u32_len(cursor, "FrameEntry.offset_in_envelope")?, &plaintext[cursor..end])?;
            cursor = end;
        }
        let frame_count = u32_len(self.frames.len() - first_frame_index as usize, "EnvelopeEntry.frame_count")?;
        if frame_count == 0 {
            return Err(FormatError::InvalidArchive("payload envelope plaintext has no frames"));
        }
        let encrypted_size = data_block_count
            .checked_mul(block_size)
            .ok_or(FormatError::InvalidArchive("EnvelopeEntry encrypted size overflow"))?;
        self.envelopes.push(StreamedEnvelopeSummary {
            envelope_index,
            first_block_index,
            data_block_count: u32_len(data_block_count, "EnvelopeEntry.data_block_count")?,
            parity_block_count: u32_len(parity_block_count, "EnvelopeEntry.parity_block_count")?,
            encrypted_size: u32_len(encrypted_size, "EnvelopeEntry.encrypted_size")?,
            plaintext_size: u32_len(plaintext.len(), "EnvelopeEntry.plaintext_size")?,
            first_frame_index,
            frame_count,
        });
        Ok(())
    }

    fn decode_frame(&mut self, envelope_index: u64, offset_in_envelope: u32, compressed: &[u8]) -> Result<(), FormatError> {
        let frame_index = u64::try_from(self.frames.len()).map_err(|_| FormatError::InvalidArchive("FrameEntry count overflow"))?;
        let tar_stream_offset = self.tar.tar_total_size();
        let decompressed_size = if let Some(dictionary) = &self.payload_dictionary {
            let mut decoder = zstd::stream::Decoder::with_dictionary(compressed, dictionary).map_err(|_| FormatError::ZstdDecompressionFailure)?;
            self.decode_zstd_frame_body(&mut decoder)?
        } else {
            let mut decoder = zstd::stream::Decoder::new(compressed).map_err(|_| FormatError::ZstdDecompressionFailure)?;
            self.decode_zstd_frame_body(&mut decoder)?
        };
        if decompressed_size == 0 {
            return Err(FormatError::InvalidArchive("zstd payload frame decompressed to zero bytes"));
        }
        self.frames.push(StreamedFrameSummary {
            frame_index,
            envelope_index,
            offset_in_envelope,
            compressed_size: u32_len(compressed.len(), "FrameEntry.compressed_size")?,
            decompressed_size: u32_len(
                usize::try_from(decompressed_size).map_err(|_| FormatError::InvalidArchive("FrameEntry size overflow"))?,
                "FrameEntry.decompressed_size",
            )?,
            tar_stream_offset,
        });
        Ok(())
    }

    fn decode_zstd_frame_body<D: Read>(&mut self, decoder: &mut D) -> Result<u64, FormatError> {
        let mut decompressed_size = 0u64;
        let mut buf = [0u8; 64 * 1024];
        loop {
            let read = decoder.read(&mut buf).map_err(|_| FormatError::ZstdDecompressionFailure)?;
            if read == 0 {
                break;
            }
            let next_tar_size = self
                .tar
                .tar_total_size()
                .checked_add(read as u64)
                .ok_or(FormatError::ReaderUnsupported("sequential tar stream exceeds configured verification cap"))?;
            if next_tar_size > self.max_tar_stream_size as u64 {
                return Err(FormatError::ReaderUnsupported("sequential tar stream exceeds configured verification cap"));
            }
            self.hasher.update(&buf[..read]);
            self.tar.observe(&buf[..read])?;
            decompressed_size = checked_u64_add(decompressed_size, read as u64)?;
        }
        Ok(decompressed_size)
    }

    fn finish(self) -> Result<StreamedPayloadSummary, FormatError> {
        let content_sha256 = self.hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&content_sha256);
        Ok(StreamedPayloadSummary {
            tar: self.tar.finish()?,
            content_sha256: digest,
            envelopes: self.envelopes,
            frames: self.frames,
        })
    }
}

struct TerminalTailBuffer {
    start_offset: u64,
    cap: usize,
    bytes: Vec<u8>,
}

impl TerminalTailBuffer {
    fn new(start_offset: u64, cap: usize) -> Self {
        Self {
            start_offset,
            cap,
            bytes: Vec::new(),
        }
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), FormatError> {
        let next_len = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or(FormatError::InvalidArchive("terminal tail size overflow"))?;
        if next_len > self.cap {
            return Err(FormatError::ReaderUnsupported("terminal tail exceeds configured cap"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn finish(self, stream_len: u64) -> TerminalTailReadAt {
        TerminalTailReadAt {
            start_offset: self.start_offset,
            stream_len,
            bytes: self.bytes,
        }
    }
}

struct TerminalTailReadAt {
    start_offset: u64,
    stream_len: u64,
    bytes: Vec<u8>,
}

impl ArchiveReadAt for TerminalTailReadAt {
    fn len(&self) -> Result<u64, FormatError> {
        Ok(self.stream_len)
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), FormatError> {
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(FormatError::InvalidArchive("terminal tail range overflow"))?;
        let tail_end = self
            .start_offset
            .checked_add(self.bytes.len() as u64)
            .ok_or(FormatError::InvalidArchive("terminal tail range overflow"))?;
        if offset < self.start_offset || end > tail_end {
            return Err(FormatError::InvalidLength {
                structure: "terminal tail",
                expected: usize::try_from(end.saturating_sub(self.start_offset)).unwrap_or(usize::MAX),
                actual: self.bytes.len(),
            });
        }
        let start = usize::try_from(offset - self.start_offset).map_err(|_| FormatError::InvalidArchive("terminal tail range overflow"))?;
        let end = start
            .checked_add(buf.len())
            .ok_or(FormatError::InvalidArchive("terminal tail range overflow"))?;
        buf.copy_from_slice(&self.bytes[start..end]);
        Ok(())
    }
}

fn root_auth_status(footer: Option<&RootAuthFooterV1>) -> SequentialRootAuthStatus {
    if footer.is_some() {
        SequentialRootAuthStatus::WireValidOnly
    } else {
        SequentialRootAuthStatus::Absent
    }
}

fn read_exact_stream<R: Read>(reader: &mut R, mut buf: &mut [u8], structure: &'static str) -> Result<(), FormatError> {
    let expected = buf.len();
    let mut actual = 0usize;
    while !buf.is_empty() {
        match reader.read(buf) {
            Ok(0) => return Err(FormatError::InvalidLength { structure, expected, actual }),
            Ok(read) => {
                actual = checked_usize_add(actual, read)?;
                let (_, rest) = buf.split_at_mut(read);
                buf = rest;
            }
            Err(err) if err.kind() == ErrorKind::Interrupted => {}
            Err(_) => return Err(FormatError::InvalidArchive("archive read failed")),
        }
    }
    Ok(())
}

fn read_stream_chunk<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize, FormatError> {
    loop {
        match reader.read(buf) {
            Ok(read) => return Ok(read),
            Err(err) if err.kind() == ErrorKind::Interrupted => {}
            Err(_) => return Err(FormatError::InvalidArchive("archive read failed")),
        }
    }
}

fn checked_u64_add(lhs: u64, rhs: u64) -> Result<u64, FormatError> {
    lhs.checked_add(rhs).ok_or(FormatError::InvalidArchive("stream arithmetic overflow"))
}

fn checked_usize_add(lhs: usize, rhs: usize) -> Result<usize, FormatError> {
    lhs.checked_add(rhs).ok_or(FormatError::InvalidArchive("stream arithmetic overflow"))
}

fn u32_len(value: usize, structure: &'static str) -> Result<u32, FormatError> {
    u32::try_from(value).map_err(|_| FormatError::InvalidArchive(structure))
}
