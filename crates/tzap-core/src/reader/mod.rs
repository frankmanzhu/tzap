use std::collections::{hash_map::Entry, BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::io::Write;
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::compression::validate_exact_zstd_frame;
use crate::crypto::{verify_integrity_tag, HmacDomain, MasterKey, Subkeys};
use crate::entry_metadata::ArchiveTimestamp;
use crate::fec::{encode_parity_gf16, repair_data_gf16};
use crate::format::{
    AeadAlgo, BlockKind, ExtractError, FormatError, KdfAlgo, VolumeFormatRevision,
    CRYPTO_HEADER_HMAC_LEN, MASTER_KEY_LEN, VOLUME_HEADER_LEN,
};
use crate::metadata::{
    normalize_lookup_file_path, DirectoryHintShardEntry, DirectoryHintTable, EnvelopeEntry,
    FileEntry, FrameEntry, IndexRoot, IndexShard, MetadataLimits, ShardEntry,
};
use crate::non_seekable_reader::{
    StreamedEnvelopeSummary, StreamedFrameSummary, StreamedPayloadSummary,
};
use crate::raw_stream_profile::reject_unsupported_raw_stream_profile;
use crate::root_auth::{
    archive_root_for_revision, critical_metadata_digest, data_block_merkle_root_for_revision,
    fec_layout_digest_for_revision, index_digest_for_revision,
    root_auth_descriptor_digest_for_revision, signer_identity_digest, ArchiveRootInputs,
    CriticalMetadataDigestInputs, DataBlockMerkleLeaf, FecLayoutObjectRow,
};
#[cfg(windows)]
use crate::tar_model::replay_windows_descendant_metadata;
use crate::tar_model::{
    metadata_verification_report, parse_tar_member_group, plan_owned_member_restore, restore_phase,
    restore_regular_file_metadata_to_open_file, restore_streaming_tar_member_group,
    stream_regular_tar_member_group_to_writer, validate_owned_restore_plan, MetadataDiagnostic,
    MetadataVerificationReport, NoopTarStreamObserver, OwnedTarMember, SafeExtractionOptions,
    StreamingMemberExpectation, TarEntryKind, TarMemberGroupReader,
    TarStreamFilesystemRestoreObserver, TarStreamObserver, TarStreamSummaryValidator,
};
use crate::wire::{
    BlockRecord, CryptoHeader, CryptoHeaderFixed, ManifestFooter, RootAuthFooterV1, VolumeHeader,
    VolumeTrailer,
};

pub mod cmra;
pub mod sidecar;
pub mod validation;
pub mod volume;

#[cfg(test)]
mod tests;

pub(crate) use cmra::*;
pub(crate) use sidecar::*;
pub(crate) use validation::*;
pub use volume::public_no_key_verify_volumes_with_options;
pub(crate) use volume::*;
pub(crate) const TRAILER_HMAC_COVERED_LEN: usize = 96;
pub(crate) const MANIFEST_HMAC_COVERED_LEN: usize = 104;
pub(crate) const SIDECAR_HMAC_COVERED_LEN: usize = 92;
pub(crate) const DEFAULT_MAX_VERIFY_TAR_SIZE: usize = 128 * 1024 * 1024;
pub(crate) const DEFAULT_MAX_TRAILING_GARBAGE_SCAN: usize = 1024 * 1024;
pub(crate) const DEFAULT_MAX_TOTAL_EXTRACTION_SIZE: u64 = 100 * 1024 * 1024 * 1024;
pub(crate) const DIRECTORY_HINT_REQUIRED_FILE_COUNT: u64 = 100_000;

pub(crate) fn default_jobs() -> usize {
    std::thread::available_parallelism()
        .map(|jobs| jobs.get())
        .unwrap_or(1)
}

pub trait ArchiveReadAt: Send + Sync + 'static {
    fn len(&self) -> Result<u64, FormatError>;
    fn is_empty(&self) -> Result<bool, FormatError> {
        Ok(self.len()? == 0)
    }
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), FormatError>;
}

pub type RecipientWrapCandidateMasterKey = [u8; MASTER_KEY_LEN];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecipientWrapArchiveIdentity {
    pub archive_uuid: [u8; 16],
    pub session_id: [u8; 16],
    pub format_version: u16,
    pub volume_format_rev: u16,
}

#[derive(Debug, Clone, Copy)]
pub struct RecipientWrapRecordContext<'a> {
    pub archive_identity: RecipientWrapArchiveIdentity,
    pub record: &'a crate::wire::RecipientRecordV1,
}

impl ArchiveReadAt for File {
    fn len(&self) -> Result<u64, FormatError> {
        self.metadata()
            .map(|metadata| metadata.len())
            .map_err(|_| FormatError::InvalidArchive("archive read metadata failed"))
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), FormatError> {
        file_read_exact_at(self, offset, buf)
    }
}

#[cfg(unix)]
pub(crate) fn file_read_exact_at(
    file: &File,
    offset: u64,
    buf: &mut [u8],
) -> Result<(), FormatError> {
    use std::os::unix::fs::FileExt;

    file_read_exact_at_with(offset, buf, |chunk, offset| file.read_at(chunk, offset))
}

#[cfg(windows)]
pub(crate) fn file_read_exact_at(
    file: &File,
    offset: u64,
    buf: &mut [u8],
) -> Result<(), FormatError> {
    use std::os::windows::fs::FileExt;

    file_read_exact_at_with(offset, buf, |chunk, offset| file.seek_read(chunk, offset))
}

#[cfg(any(unix, windows))]
pub(crate) fn file_read_exact_at_with<F>(
    mut offset: u64,
    mut buf: &mut [u8],
    mut read_at: F,
) -> Result<(), FormatError>
where
    F: FnMut(&mut [u8], u64) -> std::io::Result<usize>,
{
    while !buf.is_empty() {
        let read =
            read_at(buf, offset).map_err(|_| FormatError::InvalidArchive("archive read failed"))?;
        if read == 0 {
            return Err(FormatError::InvalidArchive("archive read failed"));
        }
        offset = checked_u64_add(offset, read as u64, "archive read offset overflow")?;
        let rest = std::mem::take(&mut buf).split_at_mut(read).1;
        buf = rest;
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn file_read_exact_at(
    file: &File,
    offset: u64,
    buf: &mut [u8],
) -> Result<(), FormatError> {
    let mut file = file
        .try_clone()
        .map_err(|_| FormatError::InvalidArchive("archive read clone failed"))?;
    std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(offset))
        .map_err(|_| FormatError::InvalidArchive("archive read seek failed"))?;
    file.read_exact(buf)
        .map_err(|_| FormatError::InvalidArchive("archive read failed"))
}

impl ArchiveReadAt for Vec<u8> {
    fn len(&self) -> Result<u64, FormatError> {
        u64::try_from(self.len())
            .map_err(|_| FormatError::InvalidArchive("archive length overflow"))
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), FormatError> {
        let offset = to_usize(offset, "archive")?;
        let end = checked_add(offset, buf.len(), "archive")?;
        let source = self.get(offset..end).ok_or(FormatError::InvalidLength {
            structure: "archive",
            expected: end,
            actual: self.len(),
        })?;
        buf.copy_from_slice(source);
        Ok(())
    }
}

impl<T: ArchiveReadAt + ?Sized> ArchiveReadAt for Arc<T> {
    fn len(&self) -> Result<u64, FormatError> {
        (**self).len()
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), FormatError> {
        (**self).read_exact_at(offset, buf)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReaderOptions {
    pub max_trailing_garbage_scan: usize,
    pub max_verify_tar_size: usize,
    pub max_total_extraction_size: u64,
    pub jobs: usize,
}

impl Default for ReaderOptions {
    fn default() -> Self {
        Self {
            max_trailing_garbage_scan: DEFAULT_MAX_TRAILING_GARBAGE_SCAN,
            max_verify_tar_size: DEFAULT_MAX_VERIFY_TAR_SIZE,
            max_total_extraction_size: DEFAULT_MAX_TOTAL_EXTRACTION_SIZE,
            jobs: default_jobs(),
        }
    }
}

pub(crate) fn validate_reader_options(options: ReaderOptions) -> Result<(), FormatError> {
    if options.jobs == 0 {
        return Err(FormatError::ReaderUnsupported("jobs must be at least 1"));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveEntry {
    pub path: String,
    pub file_data_size: u64,
    pub kind: TarEntryKind,
    pub mode: u32,
    pub mtime: ArchiveTimestamp,
    pub diagnostics: Vec<MetadataDiagnostic>,
    pub link_target: Option<String>,
    pub created: Option<ArchiveTimestamp>,
    pub accessed: Option<ArchiveTimestamp>,
    pub attributes: Option<u32>,
    pub uid: Option<u64>,
    pub gid: Option<u64>,
    pub uname: Option<String>,
    pub gname: Option<String>,
}

pub(crate) fn pax_timestamp(
    records: &crate::entry_metadata::PaxRecords,
    key: &str,
) -> Option<ArchiveTimestamp> {
    let bytes = records.get(key)?;
    let (sec, nsec) = crate::entry_metadata::parse_timestamp(bytes).ok()?;
    Some(ArchiveTimestamp::new(sec, nsec))
}

pub(crate) fn exposed_file_attributes(
    records: &crate::entry_metadata::PaxRecords,
    portable_attributes: Option<u32>,
) -> Option<u32> {
    for key in ["TZAP.macos.st-flags", "TZAP.windows.file-attributes"] {
        let Some(value) = records.get(key) else {
            continue;
        };
        let Ok(value) = std::str::from_utf8(value) else {
            continue;
        };
        if let Ok(attributes) = u32::from_str_radix(value, 16) {
            return Some(attributes);
        }
    }
    portable_attributes
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveIndexEntry {
    pub path: String,
    pub name: String,
    pub file_data_size: u64,
    pub flags: u32,
    pub path_hash: [u8; 8],
    pub tar_member_group_size: u64,
    pub first_frame_index: u64,
    pub frame_count: u32,
    pub offset_in_first_frame_plaintext: u32,
    pub layout: ArchiveIndexEntryLayout,
    pub kind: TarEntryKind,
    pub mtime: ArchiveTimestamp,
    pub created: Option<ArchiveTimestamp>,
    pub accessed: Option<ArchiveTimestamp>,
    pub mode: u32,
    pub attributes: Option<u32>,
    pub uid: Option<u64>,
    pub gid: Option<u64>,
    pub uname: Option<String>,
    pub gname: Option<String>,
    pub link_target: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveIndexEntryLayout {
    pub compressed_size: u64,
    pub decompressed_frame_size: u64,
    pub envelope_count: u32,
    pub first_envelope_index: Option<u64>,
    pub last_envelope_index: Option<u64>,
    pub first_payload_block_index: Option<u64>,
    pub payload_data_block_count: u64,
    pub payload_parity_block_count: u64,
    pub payload_encrypted_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedArchiveMember {
    pub path: String,
    pub kind: TarEntryKind,
    pub data: Vec<u8>,
    pub link_target: Option<String>,
    pub reparse_placeholder: bool,
    pub diagnostics: Vec<MetadataDiagnostic>,
}

/// Receives logical regular-file bytes while the archive reader extracts data.
///
/// Callbacks report uncompressed member payload bytes after they are accepted by
/// the destination writer. Each selected file is capped by its authenticated
/// `file_data_size`.
pub trait ArchiveExtractProgressSink {
    /// Reports newly extracted payload bytes for one archive member.
    fn file_bytes_extracted(&mut self, archive_path: &str, bytes: u64);
}

impl<F> ArchiveExtractProgressSink for F
where
    F: FnMut(&str, u64),
{
    fn file_bytes_extracted(&mut self, archive_path: &str, bytes: u64) {
        self(archive_path, bytes);
    }
}

#[derive(Debug, Clone)]
pub struct OpenedArchive {
    options: ReaderOptions,
    observed_archive_bytes: u64,
    observed_volume_count: u32,
    subkeys: Subkeys,
    blocks: BTreeMap<u64, BlockRecord>,
    lazy_blocks: Option<Arc<SeekableBlockSource>>,
    crypto_header_bytes: Vec<u8>,
    pub volume_header: VolumeHeader,
    pub crypto_header: CryptoHeaderFixed,
    pub manifest_footer: ManifestFooter,
    pub volume_trailer: Option<VolumeTrailer>,
    pub root_auth_footer: Option<RootAuthFooterV1>,
    pub index_root: IndexRoot,
    payload_dictionary: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct ArchiveContentVerification<'a> {
    archive: &'a OpenedArchive,
    mode: ContentVerificationMode,
    metadata_report: Option<MetadataVerificationReport>,
}

impl ArchiveContentVerification<'_> {
    /// Per-entry revision-45 capture, profile, restore-capability, and fidelity
    /// results. Fast verification returns `None` when payload semantics were
    /// deliberately deferred.
    pub fn metadata_report(&self) -> Option<&MetadataVerificationReport> {
        self.metadata_report.as_ref()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContentVerificationMode {
    Full,
    Fast,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveRepairPatch {
    pub volume_index: u32,
    pub block_index: u64,
    pub record_offset: u64,
    pub record_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootAuthDiagnostic {
    RootAuthContentVerified,
    RootAuthDeferredFullArchiveScanRequired,
    AuthenticatedMetadataNotRootSigned,
    RecoveryMarginNotRootAuthenticated,
    ReplicatedGlobalCopyUncheckedDueToVolumeLoss,
    RecoveryMarginChecked,
    RecoveryMarginFailed,
    RecoveryMarginUnchecked,
}

impl RootAuthDiagnostic {
    pub const fn label(self) -> &'static str {
        match self {
            Self::RootAuthContentVerified => "root_auth_content_verified",
            Self::RootAuthDeferredFullArchiveScanRequired => {
                "root_auth_deferred_full_archive_scan_required"
            }
            Self::AuthenticatedMetadataNotRootSigned => "authenticated_metadata_not_root_signed",
            Self::RecoveryMarginNotRootAuthenticated => "recovery_margin_not_root_authenticated",
            Self::ReplicatedGlobalCopyUncheckedDueToVolumeLoss => {
                "replicated_global_copy_unchecked_due_to_volume_loss"
            }
            Self::RecoveryMarginChecked => "recovery_margin_checked",
            Self::RecoveryMarginFailed => "recovery_margin_failed",
            Self::RecoveryMarginUnchecked => "recovery_margin_unchecked",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicNoKeyDiagnostic {
    PublicDataBlockCommitmentVerified,
    PublicPhysicalCompletenessUnverified,
    PublicRecoveryMarginUnchecked,
}

impl PublicNoKeyDiagnostic {
    pub const fn label(self) -> &'static str {
        match self {
            Self::PublicDataBlockCommitmentVerified => "public_data_block_commitment_verified",
            Self::PublicPhysicalCompletenessUnverified => "public_physical_completeness_unverified",
            Self::PublicRecoveryMarginUnchecked => "public_recovery_margin_unchecked",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootAuthVerification {
    pub format_version: u16,
    pub volume_format_rev: u16,
    pub archive_root: [u8; 32],
    pub authenticator_id: u16,
    pub signer_identity_type: u16,
    pub signer_identity_bytes: Vec<u8>,
    pub total_data_block_count: u64,
    pub diagnostics: Vec<RootAuthDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicNoKeyVerification {
    pub format_version: u16,
    pub volume_format_rev: u16,
    pub archive_root: [u8; 32],
    pub authenticator_id: u16,
    pub signer_identity_type: u16,
    pub signer_identity_bytes: Vec<u8>,
    pub total_data_block_count: u64,
    pub diagnostics: Vec<PublicNoKeyDiagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RootAuthMaterial {
    critical_metadata_digest: [u8; 32],
    index_digest: [u8; 32],
    fec_layout_digest: [u8; 32],
    data_block_merkle_root: [u8; 32],
    signer_identity_digest: [u8; 32],
    archive_root: [u8; 32],
    total_data_block_count: u64,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ObjectExtent {
    first_block_index: u64,
    data_block_count: u32,
    parity_block_count: u32,
    encrypted_size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParityReadPolicy {
    Always,
    RepairOnly,
}

pub(crate) struct StreamedArchiveOpenParts {
    pub(crate) options: ReaderOptions,
    pub(crate) observed_archive_bytes: u64,
    pub(crate) subkeys: Subkeys,
    pub(crate) blocks: BTreeMap<u64, BlockRecord>,
    pub(crate) crypto_header_bytes: Vec<u8>,
    pub(crate) volume_header: VolumeHeader,
    pub(crate) crypto_header: CryptoHeaderFixed,
    pub(crate) manifest_footer: ManifestFooter,
    pub(crate) volume_trailer: VolumeTrailer,
    pub(crate) root_auth_footer: Option<RootAuthFooterV1>,
}

#[derive(Clone, Copy)]
pub(crate) struct WinningIndexEntry {
    start: u64,
    file_data_size: u64,
    shard_index: usize,
    file_index: usize,
}

pub(crate) struct LocatedIndexFile {
    shard: IndexShard,
    file_index: usize,
    start: u64,
}

pub(crate) struct ExtractProgressWriter<'a, W> {
    inner: &'a mut W,
    archive_path: &'a str,
    file_data_size: u64,
    reported_bytes: u64,
    progress: &'a mut dyn ArchiveExtractProgressSink,
}

impl<'a, W> ExtractProgressWriter<'a, W> {
    fn new(
        inner: &'a mut W,
        archive_path: &'a str,
        file_data_size: u64,
        progress: &'a mut dyn ArchiveExtractProgressSink,
    ) -> Self {
        Self {
            inner,
            archive_path,
            file_data_size,
            reported_bytes: 0,
            progress,
        }
    }

    fn report(&mut self, bytes: u64) {
        if bytes == 0 || self.file_data_size == 0 {
            return;
        }
        let capped_next = self
            .reported_bytes
            .saturating_add(bytes)
            .min(self.file_data_size);
        let delta = capped_next.saturating_sub(self.reported_bytes);
        if delta == 0 {
            return;
        }
        self.reported_bytes = capped_next;
        self.progress.file_bytes_extracted(self.archive_path, delta);
    }
}

impl<W: Write> Write for ExtractProgressWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.report(written as u64);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

pub(crate) struct DecodedTarMemberGroupReader<'a> {
    archive: &'a OpenedArchive,
    shard: &'a IndexShard,
    file: &'a FileEntry,
    decompressor: zstd::bulk::Decompressor<'static>,
    next_frame_offset: u64,
    cached_envelope_index: Option<u64>,
    cached_envelope_plaintext: Vec<u8>,
    current_frame: Vec<u8>,
    current_frame_offset: usize,
    remaining_group_bytes: u64,
}

pub(crate) struct SeekableVolumeSource {
    reader: Arc<dyn ArchiveReadAt>,
    volume_index: u32,
    block_records_start: u64,
    block_count: u64,
    record_len: u64,
    block_size: usize,
}

impl std::fmt::Debug for SeekableVolumeSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SeekableVolumeSource")
            .field("volume_index", &self.volume_index)
            .field("block_records_start", &self.block_records_start)
            .field("block_count", &self.block_count)
            .field("record_len", &self.record_len)
            .field("block_size", &self.block_size)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub(crate) struct SeekableBlockSource {
    stripe_width: u32,
    volumes: Vec<Option<SeekableVolumeSource>>,
}

pub(crate) trait BlockProvider {
    fn block(&self, block_index: u64) -> Result<Option<BlockRecord>, FormatError>;
}

pub(crate) struct OpenedBlockProvider<'a> {
    memory_blocks: &'a BTreeMap<u64, BlockRecord>,
    lazy_blocks: Option<&'a SeekableBlockSource>,
}

impl SeekableBlockSource {
    fn record_location(&self, block_index: u64) -> Result<(u32, u64), FormatError> {
        if self.stripe_width == 0 {
            return Err(FormatError::ZeroStripeWidth);
        }
        let volume_index = u32::try_from(block_index % self.stripe_width as u64)
            .map_err(|_| FormatError::InvalidArchive("BlockRecord volume index overflow"))?;
        let Some(volume) = self
            .volumes
            .get(volume_index as usize)
            .and_then(Option::as_ref)
        else {
            return Err(FormatError::InvalidArchive(
                "repair output requires all archive volumes",
            ));
        };
        let slot = block_index / self.stripe_width as u64;
        if slot >= volume.block_count {
            return Err(FormatError::InvalidArchive(
                "BlockRecord global coverage has a gap",
            ));
        }
        Ok((volume_index, volume.record_offset(slot)?))
    }

    fn block(&self, block_index: u64) -> Result<Option<BlockRecord>, FormatError> {
        if self.stripe_width == 0 {
            return Err(FormatError::ZeroStripeWidth);
        }
        let volume_index = u32::try_from(block_index % self.stripe_width as u64)
            .map_err(|_| FormatError::InvalidArchive("BlockRecord volume index overflow"))?;
        let Some(volume) = self
            .volumes
            .get(volume_index as usize)
            .and_then(Option::as_ref)
        else {
            return Ok(None);
        };
        let slot = block_index / self.stripe_width as u64;
        if slot >= volume.block_count {
            return Ok(None);
        }
        match volume.read_slot(slot, block_index) {
            Ok(record) => Ok(Some(record)),
            Err(err) if block_record_error_is_recoverable_erasure(&err) => Ok(None),
            Err(err) => Err(err),
        }
    }

    fn is_complete_volume_set(&self) -> bool {
        self.volumes.iter().all(Option::is_some)
    }

    fn total_block_count(&self) -> Result<u64, FormatError> {
        self.volumes
            .iter()
            .map(|volume| {
                volume
                    .as_ref()
                    .map(|volume| volume.block_count)
                    .ok_or(FormatError::InvalidArchive(
                        "missing volume in complete set",
                    ))
            })
            .try_fold(0u64, |sum, count| {
                checked_u64_add(sum, count?, "BlockRecord count overflow")
            })
    }
}

impl SeekableVolumeSource {
    fn record_offset(&self, slot: u64) -> Result<u64, FormatError> {
        self.block_records_start
            .checked_add(checked_u64_mul(
                slot,
                self.record_len,
                "BlockRecord offset overflow",
            )?)
            .ok_or(FormatError::InvalidArchive("BlockRecord offset overflow"))
    }

    fn read_slot(&self, slot: u64, expected_block_index: u64) -> Result<BlockRecord, FormatError> {
        let record_offset = self.record_offset(slot)?;
        let raw = read_at_vec_unchecked(
            self.reader.as_ref(),
            record_offset,
            usize::try_from(self.record_len)
                .map_err(|_| FormatError::InvalidArchive("BlockRecord length overflow"))?,
        )?;
        let record = BlockRecord::parse(&raw, self.block_size)?;
        if record.block_index != expected_block_index {
            return Err(FormatError::InvalidArchive(
                "BlockRecord index does not match volume position",
            ));
        }
        Ok(record)
    }
}

impl BlockProvider for BTreeMap<u64, BlockRecord> {
    fn block(&self, block_index: u64) -> Result<Option<BlockRecord>, FormatError> {
        Ok(self.get(&block_index).cloned())
    }
}

impl BlockProvider for OpenedBlockProvider<'_> {
    fn block(&self, block_index: u64) -> Result<Option<BlockRecord>, FormatError> {
        if let Some(record) = self.memory_blocks.get(&block_index) {
            return Ok(Some(record.clone()));
        }
        match self.lazy_blocks {
            Some(source) => source.block(block_index),
            None => Ok(None),
        }
    }
}

pub(crate) fn subkeys_for_open(
    master_key: Option<&MasterKey>,
    aead_algo: AeadAlgo,
    archive_uuid: &[u8; 16],
    session_id: &[u8; 16],
) -> Result<Subkeys, FormatError> {
    if aead_algo.is_encrypted() {
        Subkeys::derive(
            master_key.ok_or(FormatError::KeyMaterialMismatch)?,
            archive_uuid,
            session_id,
        )
    } else {
        Ok(Subkeys::unencrypted_placeholder())
    }
}

type DirectoryHintMap = BTreeMap<Vec<u8>, BTreeSet<u32>>;
pub type ExtractedRegularFile = (Vec<u8>, Vec<MetadataDiagnostic>);
pub(crate) const FAST_FULL_EXTRACT_UNIQUE_PATHS_UNSUPPORTED: &str =
    "fast full extract requires unique archive paths";

pub(crate) fn parse_volume_format_dispatch(
    volume_header: &VolumeHeader,
) -> Result<VolumeFormatRevision, FormatError> {
    let revision = volume_header.parse_volume_format_revision()?;
    match revision {
        VolumeFormatRevision::V45 => Ok(revision),
    }
}

#[derive(Debug)]
pub(crate) struct PayloadIndexTables {
    shards: Vec<IndexShard>,
    file_count: u64,
    frames: BTreeMap<u64, FrameEntry>,
    envelopes: BTreeMap<u64, EnvelopeEntry>,
}

pub fn open_archive(bytes: &[u8], master_key: &MasterKey) -> Result<OpenedArchive, FormatError> {
    OpenedArchive::open_with_options(bytes, master_key, ReaderOptions::default())
}

pub fn open_archive_with_recipient_wrap_resolver<F>(
    bytes: &[u8],
    resolver: F,
) -> Result<OpenedArchive, FormatError>
where
    F: FnMut(
        RecipientWrapRecordContext<'_>,
    ) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
{
    OpenedArchive::open_with_recipient_wrap_resolver_options(
        bytes,
        resolver,
        ReaderOptions::default(),
    )
}

pub fn open_archive_unencrypted(bytes: &[u8]) -> Result<OpenedArchive, FormatError> {
    require_unencrypted_volume_profile(bytes)?;
    let placeholder = MasterKey::from_raw_key(&[0; 32])?;
    OpenedArchive::open_with_options(bytes, &placeholder, ReaderOptions::default())
}

pub fn open_archive_volumes(
    volumes: &[&[u8]],
    master_key: &MasterKey,
) -> Result<OpenedArchive, FormatError> {
    OpenedArchive::open_volumes_with_options(volumes, master_key, ReaderOptions::default())
}

pub fn open_archive_volumes_unencrypted(volumes: &[&[u8]]) -> Result<OpenedArchive, FormatError> {
    for volume in volumes {
        require_unencrypted_volume_profile(volume)?;
    }
    let placeholder = MasterKey::from_raw_key(&[0; 32])?;
    OpenedArchive::open_volumes_with_options(volumes, &placeholder, ReaderOptions::default())
}

pub fn open_archive_with_bootstrap_sidecar(
    bytes: &[u8],
    bootstrap_sidecar: &[u8],
    master_key: &MasterKey,
) -> Result<OpenedArchive, FormatError> {
    OpenedArchive::open_with_bootstrap_sidecar_options(
        bytes,
        bootstrap_sidecar,
        master_key,
        ReaderOptions::default(),
    )
}

pub(crate) fn require_unencrypted_volume_profile(bytes: &[u8]) -> Result<(), FormatError> {
    if bytes.len() < VOLUME_HEADER_LEN {
        return Err(FormatError::InvalidLength {
            structure: "archive",
            expected: VOLUME_HEADER_LEN,
            actual: bytes.len(),
        });
    }
    let volume_header = VolumeHeader::parse(slice(bytes, 0, VOLUME_HEADER_LEN, "archive")?)?;
    parse_volume_format_dispatch(&volume_header)?;
    let crypto_start = volume_header.crypto_header_offset as usize;
    let crypto_len = volume_header.crypto_header_length as usize;
    let crypto_bytes = slice(bytes, crypto_start, crypto_len, "CryptoHeader")?;
    let crypto_header = CryptoHeader::parse(crypto_bytes, volume_header.crypto_header_length)?;
    if crypto_header.fixed.aead_algo == AeadAlgo::None
        && crypto_header.fixed.kdf_algo == KdfAlgo::None
    {
        Ok(())
    } else {
        Err(FormatError::KeyMaterialMismatch)
    }
}

pub fn open_seekable_archive<R: ArchiveReadAt>(
    reader: R,
    master_key: &MasterKey,
) -> Result<OpenedArchive, FormatError> {
    OpenedArchive::open_seekable_volumes_with_options(
        vec![reader],
        master_key,
        ReaderOptions::default(),
    )
}

pub fn open_seekable_archive_volumes<R: ArchiveReadAt>(
    readers: Vec<R>,
    master_key: &MasterKey,
) -> Result<OpenedArchive, FormatError> {
    OpenedArchive::open_seekable_volumes_with_options(readers, master_key, ReaderOptions::default())
}

pub fn open_seekable_archive_with_bootstrap_sidecar<R: ArchiveReadAt>(
    reader: R,
    bootstrap_sidecar: &[u8],
    master_key: &MasterKey,
) -> Result<OpenedArchive, FormatError> {
    open_seekable_archive_with_bootstrap_sidecar_options(
        reader,
        bootstrap_sidecar,
        master_key,
        ReaderOptions::default(),
    )
}

pub fn open_seekable_archive_with_bootstrap_sidecar_options<R: ArchiveReadAt>(
    reader: R,
    bootstrap_sidecar: &[u8],
    master_key: &MasterKey,
    options: ReaderOptions,
) -> Result<OpenedArchive, FormatError> {
    OpenedArchive::open_seekable_volumes_with_options_for_mode(
        vec![Arc::new(reader) as Arc<dyn ArchiveReadAt>],
        master_key,
        options,
        Some(bootstrap_sidecar),
    )
}

pub fn open_seekable_archive_with_recipient_wrap_resolver_options<R, F>(
    reader: R,
    resolver: F,
    options: ReaderOptions,
) -> Result<OpenedArchive, FormatError>
where
    R: ArchiveReadAt,
    F: FnMut(
        RecipientWrapRecordContext<'_>,
    ) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
{
    OpenedArchive::open_seekable_with_recipient_wrap_resolver_options(reader, resolver, options)
}

pub fn open_seekable_archive_volumes_with_recipient_wrap_resolver_options<R, F>(
    readers: Vec<R>,
    resolver: F,
    options: ReaderOptions,
) -> Result<OpenedArchive, FormatError>
where
    R: ArchiveReadAt,
    F: FnMut(
        RecipientWrapRecordContext<'_>,
    ) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
{
    OpenedArchive::open_seekable_volumes_with_recipient_wrap_resolver_options(
        readers, resolver, options,
    )
}

pub fn open_non_seekable_archive(
    bytes: &[u8],
    master_key: &MasterKey,
    bootstrap_sidecar: Option<&[u8]>,
) -> Result<OpenedArchive, FormatError> {
    match bootstrap_sidecar {
        Some(sidecar) => OpenedArchive::open_with_bootstrap_sidecar_options_for_mode(
            bytes,
            sidecar,
            master_key,
            ReaderOptions::default(),
            BootstrapSidecarUse::NonSeekableRandomAccess,
        ),
        None => Err(FormatError::ReaderUnsupported(
            "non-seekable random access requires a bootstrap sidecar",
        )),
    }
}

pub fn public_no_key_verify_archive_with<F>(
    bytes: &[u8],
    verifier: F,
) -> Result<PublicNoKeyVerification, FormatError>
where
    F: FnMut(&RootAuthFooterV1, &[u8; 32]) -> Result<bool, FormatError>,
{
    public_no_key_verify_volumes_with_options(&[bytes], verifier, ReaderOptions::default())
}

pub fn public_no_key_verify_volumes_with<F>(
    volumes: &[&[u8]],
    verifier: F,
) -> Result<PublicNoKeyVerification, FormatError>
where
    F: FnMut(&RootAuthFooterV1, &[u8; 32]) -> Result<bool, FormatError>,
{
    public_no_key_verify_volumes_with_options(volumes, verifier, ReaderOptions::default())
}

/// Decode a single-volume, dictionary-free non-seekable archive image into tar
/// bytes after authenticating its terminal ManifestFooter and VolumeTrailer.
///
/// This is a whole-buffer helper, not a live provisional-output API.
/// Callers receive no decoded bytes if terminal authentication fails.
pub fn sequential_extract_tar_stream(
    bytes: &[u8],
    master_key: &MasterKey,
) -> Result<Vec<u8>, FormatError> {
    sequential_extract_tar_stream_with_options(bytes, master_key, ReaderOptions::default())
}

impl OpenedArchive {
    fn block_provider(&self) -> OpenedBlockProvider<'_> {
        OpenedBlockProvider {
            memory_blocks: &self.blocks,
            lazy_blocks: self.lazy_blocks.as_deref(),
        }
    }

    pub fn observed_archive_bytes(&self) -> u64 {
        self.observed_archive_bytes
    }

    fn missing_volume_count(&self) -> u32 {
        self.crypto_header
            .stripe_width
            .saturating_sub(self.observed_volume_count)
    }

    fn root_auth_success_diagnostics(&self) -> Vec<RootAuthDiagnostic> {
        let mut diagnostics = vec![
            RootAuthDiagnostic::RootAuthContentVerified,
            RootAuthDiagnostic::AuthenticatedMetadataNotRootSigned,
            RootAuthDiagnostic::RecoveryMarginNotRootAuthenticated,
        ];
        if self.missing_volume_count() > 0 {
            diagnostics.push(RootAuthDiagnostic::ReplicatedGlobalCopyUncheckedDueToVolumeLoss);
        }
        diagnostics.push(RootAuthDiagnostic::RecoveryMarginUnchecked);
        diagnostics
    }

    pub fn open_with_options(
        bytes: &[u8],
        master_key: &MasterKey,
        options: ReaderOptions,
    ) -> Result<Self, FormatError> {
        Self::open_volumes_with_options(&[bytes], master_key, options)
    }

    pub fn open_with_recipient_wrap_resolver_options<F>(
        bytes: &[u8],
        mut resolver: F,
        options: ReaderOptions,
    ) -> Result<Self, FormatError>
    where
        F: FnMut(
            RecipientWrapRecordContext<'_>,
        ) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
    {
        validate_reader_options(options)?;
        let observed_archive_bytes = observed_archive_size(std::iter::once(bytes.len() as u64))?;
        let parsed =
            parse_seekable_volume_with_recipient_wrap_resolver(bytes, &mut resolver, options)?;
        let ParsedSeekableVolume {
            volume_header,
            crypto_header,
            crypto_header_bytes,
            key_wrap_table_bytes: _,
            subkeys,
            manifest_footer,
            manifest_footer_error,
            root_auth_footer,
            root_auth_footer_bytes: _,
            volume_trailer,
            blocks,
            erased_block_indices,
        } = parsed;
        let manifest_footer = match manifest_footer {
            Some(footer) => footer,
            None => {
                return Err(manifest_footer_error.unwrap_or(FormatError::InvalidArchive(
                    "no verified ManifestFooter found",
                )));
            }
        };
        let observed_volume_count = 1;
        let missing_volume_count = crypto_header
            .stripe_width
            .checked_sub(observed_volume_count)
            .ok_or(FormatError::InvalidArchive("volume count overflow"))?;
        if missing_volume_count > crypto_header.volume_loss_tolerance as u32 {
            return Err(FormatError::InvalidArchive(
                "missing volume count exceeds volume_loss_tolerance",
            ));
        }
        if missing_volume_count == 0 {
            validate_complete_global_block_coverage(&blocks, &erased_block_indices)?;
        }

        let limits = metadata_limits(&crypto_header);
        let index_root_plaintext = load_metadata_object_from_parts(
            &blocks,
            ObjectLoadContext::index_root(
                &volume_header,
                &crypto_header,
                &subkeys,
                ObjectExtent {
                    first_block_index: manifest_footer.index_root_first_block,
                    data_block_count: manifest_footer.index_root_data_block_count,
                    parity_block_count: manifest_footer.index_root_parity_block_count,
                    encrypted_size: manifest_footer.index_root_encrypted_size,
                },
            ),
            manifest_footer.index_root_decompressed_size,
        )?;
        let index_root = IndexRoot::parse(
            &index_root_plaintext,
            crypto_header.has_dictionary != 0,
            limits,
        )?;
        let payload_dictionary = load_archive_dictionary(
            &blocks,
            &subkeys,
            &volume_header,
            &crypto_header,
            &index_root,
        )?;

        Ok(Self {
            options,
            observed_archive_bytes,
            observed_volume_count,
            subkeys,
            blocks,
            lazy_blocks: None,
            crypto_header_bytes,
            volume_header,
            crypto_header,
            manifest_footer,
            volume_trailer: Some(volume_trailer),
            root_auth_footer,
            index_root,
            payload_dictionary,
        })
    }

    pub fn open_seekable_with_recipient_wrap_resolver_options<R, F>(
        reader: R,
        mut resolver: F,
        options: ReaderOptions,
    ) -> Result<Self, FormatError>
    where
        R: ArchiveReadAt,
        F: FnMut(
            RecipientWrapRecordContext<'_>,
        ) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
    {
        validate_reader_options(options)?;
        let reader = Arc::new(reader) as Arc<dyn ArchiveReadAt>;
        let observed_len = reader.len()?;
        let observed_archive_bytes = observed_archive_size([observed_len])?;
        let mut parsed = parse_seekable_read_at_volume_with_recipient_wrap_resolver(
            reader.clone(),
            &mut resolver,
            options,
        )?;
        let manifest_footer = match parsed.manifest_footer.take() {
            Some(footer) => footer,
            None => {
                return Err(parsed.manifest_footer_error.take().unwrap_or(
                    FormatError::InvalidArchive("no verified ManifestFooter found"),
                ));
            }
        };
        let observed_volume_count = 1;
        let missing_volume_count = parsed
            .crypto_header
            .stripe_width
            .checked_sub(observed_volume_count)
            .ok_or(FormatError::InvalidArchive("volume count overflow"))?;
        if missing_volume_count > parsed.crypto_header.volume_loss_tolerance as u32 {
            return Err(FormatError::InvalidArchive(
                "missing volume count exceeds volume_loss_tolerance",
            ));
        }

        let record_len = block_record_len(parsed.crypto_header.block_size as usize)?;
        let mut lazy_volume_slots = Vec::new();
        lazy_volume_slots.resize_with(parsed.crypto_header.stripe_width as usize, || None);
        let slot = parsed.volume_header.volume_index as usize;
        if slot >= lazy_volume_slots.len() {
            return Err(FormatError::InvalidArchive(
                "authenticated volume index exceeds stripe_width",
            ));
        }
        lazy_volume_slots[slot] = Some(SeekableVolumeSource {
            reader: parsed.reader.clone(),
            volume_index: parsed.volume_header.volume_index,
            block_records_start: parsed.block_records_start,
            block_count: parsed.volume_trailer.block_count,
            record_len,
            block_size: parsed.crypto_header.block_size as usize,
        });
        let lazy_source = Arc::new(SeekableBlockSource {
            stripe_width: parsed.crypto_header.stripe_width,
            volumes: lazy_volume_slots,
        });
        let blocks = BTreeMap::new();
        let block_provider = OpenedBlockProvider {
            memory_blocks: &blocks,
            lazy_blocks: Some(lazy_source.as_ref()),
        };
        let limits = metadata_limits(&parsed.crypto_header);
        let index_root_plaintext = load_metadata_object_from_parts(
            &block_provider,
            ObjectLoadContext::index_root(
                &parsed.volume_header,
                &parsed.crypto_header,
                &parsed.subkeys,
                index_root_extent_from_manifest(&manifest_footer),
            ),
            manifest_footer.index_root_decompressed_size,
        )?;
        let index_root = IndexRoot::parse(
            &index_root_plaintext,
            parsed.crypto_header.has_dictionary != 0,
            limits,
        )?;
        let block_provider = OpenedBlockProvider {
            memory_blocks: &blocks,
            lazy_blocks: Some(lazy_source.as_ref()),
        };
        let payload_dictionary = load_archive_dictionary(
            &block_provider,
            &parsed.subkeys,
            &parsed.volume_header,
            &parsed.crypto_header,
            &index_root,
        )?;

        Ok(Self {
            options,
            observed_archive_bytes,
            observed_volume_count,
            subkeys: parsed.subkeys,
            blocks,
            lazy_blocks: Some(lazy_source),
            crypto_header_bytes: parsed.crypto_header_bytes,
            volume_header: parsed.volume_header,
            crypto_header: parsed.crypto_header,
            manifest_footer,
            volume_trailer: Some(parsed.volume_trailer),
            root_auth_footer: parsed.root_auth_footer,
            index_root,
            payload_dictionary,
        })
    }

    pub fn open_seekable_volumes_with_recipient_wrap_resolver_options<R, F>(
        readers: Vec<R>,
        mut resolver: F,
        options: ReaderOptions,
    ) -> Result<Self, FormatError>
    where
        R: ArchiveReadAt,
        F: FnMut(
            RecipientWrapRecordContext<'_>,
        ) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
    {
        validate_reader_options(options)?;
        if readers.is_empty() {
            return Err(FormatError::InvalidArchive("no volumes supplied"));
        }
        let readers = readers
            .into_iter()
            .map(|reader| Arc::new(reader) as Arc<dyn ArchiveReadAt>)
            .collect::<Vec<_>>();
        let observed_archive_bytes = observed_archive_size(
            readers
                .iter()
                .map(|reader| reader.len())
                .collect::<Result<Vec<_>, _>>()?,
        )?;
        let mut first: Option<ParsedSeekableReadAtVolume> = None;
        let mut manifest_authority: Option<ManifestFooter> = None;
        let mut manifest_authority_volume_header: Option<VolumeHeader> = None;
        let mut manifest_authority_volume_trailer: Option<VolumeTrailer> = None;
        let mut root_auth_authority: Option<RootAuthFooterV1> = None;
        let mut root_auth_authority_bytes: Option<Vec<u8>> = None;
        let mut saw_root_auth_absent = false;
        let mut first_manifest_footer_error: Option<FormatError> = None;
        let mut seen_volume_indexes = BTreeSet::new();
        let mut lazy_volume_slots: Vec<Option<SeekableVolumeSource>> = Vec::new();

        for reader in readers {
            let mut parsed = parse_seekable_read_at_volume_with_recipient_wrap_resolver(
                reader,
                &mut resolver,
                options,
            )?;
            if !seen_volume_indexes.insert(parsed.volume_header.volume_index) {
                return Err(FormatError::InvalidArchive(
                    "duplicate authenticated volume index",
                ));
            }

            if let Some(first) = &first {
                validate_volume_set_member_metadata(
                    &first.volume_header,
                    &first.crypto_header,
                    &first.crypto_header_bytes,
                    &parsed.volume_header,
                    &parsed.crypto_header,
                    &parsed.crypto_header_bytes,
                )?;
                validate_key_wrap_table_bytes_match(
                    &first.key_wrap_table_bytes,
                    &parsed.key_wrap_table_bytes,
                )?;
            } else {
                lazy_volume_slots.resize_with(parsed.crypto_header.stripe_width as usize, || None);
            }

            if let Some(footer) = &parsed.manifest_footer {
                if let Some(authority) = &manifest_authority {
                    if !manifest_bootstrap_fields_match(authority, footer) {
                        return Err(FormatError::InvalidArchive(
                            "ManifestFooter bootstrap fields differ",
                        ));
                    }
                } else {
                    manifest_authority = Some(footer.clone());
                    manifest_authority_volume_header = Some(parsed.volume_header.clone());
                    manifest_authority_volume_trailer = Some(parsed.volume_trailer.clone());
                }
            } else if first_manifest_footer_error.is_none() {
                first_manifest_footer_error = parsed.manifest_footer_error.take();
            }

            match (&parsed.root_auth_footer, &parsed.root_auth_footer_bytes) {
                (Some(footer), Some(bytes)) => {
                    if saw_root_auth_absent {
                        return Err(FormatError::InvalidArchive(
                            "root-auth footer presence differs across volumes",
                        ));
                    }
                    if let Some(authority_bytes) = &root_auth_authority_bytes {
                        if authority_bytes != bytes {
                            return Err(FormatError::InvalidArchive(
                                "RootAuthFooter copies differ",
                            ));
                        }
                    } else {
                        root_auth_authority = Some(footer.clone());
                        root_auth_authority_bytes = Some(bytes.clone());
                    }
                }
                (None, None) => {
                    if root_auth_authority_bytes.is_some() {
                        return Err(FormatError::InvalidArchive(
                            "root-auth footer presence differs across volumes",
                        ));
                    }
                    saw_root_auth_absent = true;
                }
                _ => {
                    return Err(FormatError::InvalidArchive(
                        "root-auth footer terminal state is inconsistent",
                    ));
                }
            }

            let record_len = block_record_len(parsed.crypto_header.block_size as usize)?;
            let source = SeekableVolumeSource {
                reader: parsed.reader.clone(),
                volume_index: parsed.volume_header.volume_index,
                block_records_start: parsed.block_records_start,
                block_count: parsed.volume_trailer.block_count,
                record_len,
                block_size: parsed.crypto_header.block_size as usize,
            };
            let slot = parsed.volume_header.volume_index as usize;
            if slot >= lazy_volume_slots.len() || lazy_volume_slots[slot].replace(source).is_some()
            {
                return Err(FormatError::InvalidArchive(
                    "duplicate authenticated volume index",
                ));
            }

            if first.is_none() {
                first = Some(parsed);
            }
        }

        let first = first.ok_or(FormatError::InvalidArchive("no volumes supplied"))?;
        let manifest_footer = manifest_authority.ok_or(match first_manifest_footer_error {
            Some(err) => err,
            None => FormatError::InvalidArchive("no verified ManifestFooter found"),
        })?;
        let authority_volume_header = manifest_authority_volume_header.ok_or(
            FormatError::InvalidArchive("no verified ManifestFooter found"),
        )?;
        let authority_volume_trailer = manifest_authority_volume_trailer.ok_or(
            FormatError::InvalidArchive("no verified ManifestFooter found"),
        )?;
        let observed_volume_count = u32::try_from(seen_volume_indexes.len())
            .map_err(|_| FormatError::InvalidArchive("volume count overflow"))?;
        let missing_volume_count = first
            .crypto_header
            .stripe_width
            .checked_sub(observed_volume_count)
            .ok_or(FormatError::InvalidArchive("volume count overflow"))?;
        if missing_volume_count > first.crypto_header.volume_loss_tolerance as u32 {
            return Err(FormatError::InvalidArchive(
                "missing volume count exceeds volume_loss_tolerance",
            ));
        }

        let blocks = BTreeMap::new();
        let lazy_source = Arc::new(SeekableBlockSource {
            stripe_width: first.crypto_header.stripe_width,
            volumes: lazy_volume_slots,
        });
        let block_provider = OpenedBlockProvider {
            memory_blocks: &blocks,
            lazy_blocks: Some(lazy_source.as_ref()),
        };
        let limits = metadata_limits(&first.crypto_header);
        let index_root_plaintext = load_metadata_object_from_parts(
            &block_provider,
            ObjectLoadContext::index_root(
                &first.volume_header,
                &first.crypto_header,
                &first.subkeys,
                index_root_extent_from_manifest(&manifest_footer),
            ),
            manifest_footer.index_root_decompressed_size,
        )?;
        let index_root = IndexRoot::parse(
            &index_root_plaintext,
            first.crypto_header.has_dictionary != 0,
            limits,
        )?;
        let block_provider = OpenedBlockProvider {
            memory_blocks: &blocks,
            lazy_blocks: Some(lazy_source.as_ref()),
        };
        let payload_dictionary = load_archive_dictionary(
            &block_provider,
            &first.subkeys,
            &first.volume_header,
            &first.crypto_header,
            &index_root,
        )?;

        Ok(Self {
            options,
            observed_archive_bytes,
            observed_volume_count,
            subkeys: first.subkeys,
            blocks,
            lazy_blocks: Some(lazy_source),
            crypto_header_bytes: first.crypto_header_bytes,
            volume_header: authority_volume_header,
            crypto_header: first.crypto_header,
            manifest_footer,
            volume_trailer: Some(authority_volume_trailer),
            root_auth_footer: root_auth_authority,
            index_root,
            payload_dictionary,
        })
    }

    pub fn open_volumes_with_options(
        volumes: &[&[u8]],
        master_key: &MasterKey,
        options: ReaderOptions,
    ) -> Result<Self, FormatError> {
        validate_reader_options(options)?;
        if volumes.is_empty() {
            return Err(FormatError::InvalidArchive("no volumes supplied"));
        }

        let observed_archive_bytes =
            observed_archive_size(volumes.iter().map(|volume| volume.len() as u64))?;
        let mut first: Option<ParsedSeekableVolume> = None;
        let mut manifest_authority: Option<ManifestFooter> = None;
        let mut manifest_authority_volume_header: Option<VolumeHeader> = None;
        let mut manifest_authority_volume_trailer: Option<VolumeTrailer> = None;
        let mut root_auth_authority: Option<RootAuthFooterV1> = None;
        let mut root_auth_authority_bytes: Option<Vec<u8>> = None;
        let mut saw_root_auth_absent = false;
        let mut first_manifest_footer_error: Option<FormatError> = None;
        let mut seen_volume_indexes = BTreeSet::new();
        let mut blocks = BTreeMap::new();
        let mut erased_block_indices = BTreeSet::new();

        for volume_bytes in volumes {
            let mut parsed = parse_seekable_volume(volume_bytes, master_key, options)?;
            if !seen_volume_indexes.insert(parsed.volume_header.volume_index) {
                return Err(FormatError::InvalidArchive(
                    "duplicate authenticated volume index",
                ));
            }

            if let Some(first) = &first {
                validate_volume_set_member(first, &parsed)?;
            }

            if let Some(footer) = &parsed.manifest_footer {
                if let Some(authority) = &manifest_authority {
                    if !manifest_bootstrap_fields_match(authority, footer) {
                        return Err(FormatError::InvalidArchive(
                            "ManifestFooter bootstrap fields differ",
                        ));
                    }
                } else {
                    manifest_authority = Some(footer.clone());
                    manifest_authority_volume_header = Some(parsed.volume_header.clone());
                    manifest_authority_volume_trailer = Some(parsed.volume_trailer.clone());
                }
            } else if first_manifest_footer_error.is_none() {
                first_manifest_footer_error = parsed.manifest_footer_error.take();
            }

            match (&parsed.root_auth_footer, &parsed.root_auth_footer_bytes) {
                (Some(footer), Some(bytes)) => {
                    if saw_root_auth_absent {
                        return Err(FormatError::InvalidArchive(
                            "root-auth footer presence differs across volumes",
                        ));
                    }
                    if let Some(authority_bytes) = &root_auth_authority_bytes {
                        if authority_bytes != bytes {
                            return Err(FormatError::InvalidArchive(
                                "RootAuthFooter copies differ",
                            ));
                        }
                    } else {
                        root_auth_authority = Some(footer.clone());
                        root_auth_authority_bytes = Some(bytes.clone());
                    }
                }
                (None, None) => {
                    if root_auth_authority_bytes.is_some() {
                        return Err(FormatError::InvalidArchive(
                            "root-auth footer presence differs across volumes",
                        ));
                    }
                    saw_root_auth_absent = true;
                }
                _ => {
                    return Err(FormatError::InvalidArchive(
                        "root-auth footer terminal state is inconsistent",
                    ));
                }
            }

            for (block_index, record) in &parsed.blocks {
                if blocks.insert(*block_index, record.clone()).is_some() {
                    return Err(FormatError::InvalidArchive("duplicate BlockRecord index"));
                }
            }
            for block_index in &parsed.erased_block_indices {
                erased_block_indices.insert(*block_index);
            }

            if first.is_none() {
                first = Some(parsed);
            }
        }

        let first = first.ok_or(FormatError::InvalidArchive("no volumes supplied"))?;
        let manifest_footer = manifest_authority.ok_or(match first_manifest_footer_error {
            Some(err) => err,
            None => FormatError::InvalidArchive("no verified ManifestFooter found"),
        })?;
        let authority_volume_header = manifest_authority_volume_header.ok_or(
            FormatError::InvalidArchive("no verified ManifestFooter found"),
        )?;
        let authority_volume_trailer = manifest_authority_volume_trailer.ok_or(
            FormatError::InvalidArchive("no verified ManifestFooter found"),
        )?;
        let observed_volume_count = u32::try_from(seen_volume_indexes.len())
            .map_err(|_| FormatError::InvalidArchive("volume count overflow"))?;
        let missing_volume_count = first
            .crypto_header
            .stripe_width
            .checked_sub(observed_volume_count)
            .ok_or(FormatError::InvalidArchive("volume count overflow"))?;
        if missing_volume_count > first.crypto_header.volume_loss_tolerance as u32 {
            return Err(FormatError::InvalidArchive(
                "missing volume count exceeds volume_loss_tolerance",
            ));
        }
        if seen_volume_indexes.len() == first.crypto_header.stripe_width as usize {
            validate_complete_global_block_coverage(&blocks, &erased_block_indices)?;
        }

        let limits = metadata_limits(&first.crypto_header);
        let index_root_plaintext = load_metadata_object_from_parts(
            &blocks,
            ObjectLoadContext::index_root(
                &first.volume_header,
                &first.crypto_header,
                &first.subkeys,
                ObjectExtent {
                    first_block_index: manifest_footer.index_root_first_block,
                    data_block_count: manifest_footer.index_root_data_block_count,
                    parity_block_count: manifest_footer.index_root_parity_block_count,
                    encrypted_size: manifest_footer.index_root_encrypted_size,
                },
            ),
            manifest_footer.index_root_decompressed_size,
        )?;
        let index_root = IndexRoot::parse(
            &index_root_plaintext,
            first.crypto_header.has_dictionary != 0,
            limits,
        )?;
        let payload_dictionary = load_archive_dictionary(
            &blocks,
            &first.subkeys,
            &first.volume_header,
            &first.crypto_header,
            &index_root,
        )?;

        Ok(Self {
            options,
            observed_archive_bytes,
            observed_volume_count,
            subkeys: first.subkeys,
            blocks,
            lazy_blocks: None,
            crypto_header_bytes: first.crypto_header_bytes,
            volume_header: authority_volume_header,
            crypto_header: first.crypto_header,
            manifest_footer,
            volume_trailer: Some(authority_volume_trailer),
            root_auth_footer: root_auth_authority,
            index_root,
            payload_dictionary,
        })
    }

    pub fn open_seekable_volumes_with_options<R: ArchiveReadAt>(
        readers: Vec<R>,
        master_key: &MasterKey,
        options: ReaderOptions,
    ) -> Result<Self, FormatError> {
        let readers = readers
            .into_iter()
            .map(|reader| Arc::new(reader) as Arc<dyn ArchiveReadAt>)
            .collect::<Vec<_>>();
        Self::open_seekable_volumes_with_options_for_mode(readers, master_key, options, None)
    }

    fn open_seekable_volumes_with_options_for_mode(
        readers: Vec<Arc<dyn ArchiveReadAt>>,
        master_key: &MasterKey,
        options: ReaderOptions,
        bootstrap_sidecar: Option<&[u8]>,
    ) -> Result<Self, FormatError> {
        validate_reader_options(options)?;
        if readers.is_empty() {
            return Err(FormatError::InvalidArchive("no volumes supplied"));
        }
        if bootstrap_sidecar.is_some() && readers.len() > 1 {
            return Err(FormatError::ReaderUnsupported(
                "multi-volume inputs with bootstrap sidecar are not supported",
            ));
        }

        let observed_archive_bytes = observed_archive_size(
            readers
                .iter()
                .map(|reader| reader.len())
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .chain(bootstrap_sidecar.map(|sidecar| sidecar.len() as u64)),
        )?;
        let mut first: Option<ParsedSeekableReadAtVolume> = None;
        let mut manifest_authority: Option<ManifestFooter> = None;
        let mut manifest_authority_volume_header: Option<VolumeHeader> = None;
        let mut manifest_authority_volume_trailer: Option<VolumeTrailer> = None;
        let mut root_auth_authority: Option<RootAuthFooterV1> = None;
        let mut root_auth_authority_bytes: Option<Vec<u8>> = None;
        let mut saw_root_auth_absent = false;
        let mut first_manifest_footer_error: Option<FormatError> = None;
        let mut seen_volume_indexes = BTreeSet::new();
        let mut lazy_volume_slots: Vec<Option<SeekableVolumeSource>> = Vec::new();

        for reader in readers {
            let mut parsed = parse_seekable_read_at_volume(reader, master_key, options)?;
            if bootstrap_sidecar.is_some() {
                validate_bootstrap_single_volume_input(
                    &parsed.volume_header,
                    &parsed.crypto_header,
                )?;
            }
            if !seen_volume_indexes.insert(parsed.volume_header.volume_index) {
                return Err(FormatError::InvalidArchive(
                    "duplicate authenticated volume index",
                ));
            }

            if let Some(first) = &first {
                validate_volume_set_member_metadata(
                    &first.volume_header,
                    &first.crypto_header,
                    &first.crypto_header_bytes,
                    &parsed.volume_header,
                    &parsed.crypto_header,
                    &parsed.crypto_header_bytes,
                )?;
                validate_key_wrap_table_bytes_match(
                    &first.key_wrap_table_bytes,
                    &parsed.key_wrap_table_bytes,
                )?;
            } else {
                lazy_volume_slots.resize_with(parsed.crypto_header.stripe_width as usize, || None);
            }

            if let Some(footer) = &parsed.manifest_footer {
                if let Some(authority) = &manifest_authority {
                    if !manifest_bootstrap_fields_match(authority, footer) {
                        return Err(FormatError::InvalidArchive(
                            "ManifestFooter bootstrap fields differ",
                        ));
                    }
                } else {
                    manifest_authority = Some(footer.clone());
                    manifest_authority_volume_header = Some(parsed.volume_header.clone());
                    manifest_authority_volume_trailer = Some(parsed.volume_trailer.clone());
                }
            } else if first_manifest_footer_error.is_none() {
                first_manifest_footer_error = parsed.manifest_footer_error.take();
            }

            match (&parsed.root_auth_footer, &parsed.root_auth_footer_bytes) {
                (Some(footer), Some(bytes)) => {
                    if saw_root_auth_absent {
                        return Err(FormatError::InvalidArchive(
                            "root-auth footer presence differs across volumes",
                        ));
                    }
                    if let Some(authority_bytes) = &root_auth_authority_bytes {
                        if authority_bytes != bytes {
                            return Err(FormatError::InvalidArchive(
                                "RootAuthFooter copies differ",
                            ));
                        }
                    } else {
                        root_auth_authority = Some(footer.clone());
                        root_auth_authority_bytes = Some(bytes.clone());
                    }
                }
                (None, None) => {
                    if root_auth_authority_bytes.is_some() {
                        return Err(FormatError::InvalidArchive(
                            "root-auth footer presence differs across volumes",
                        ));
                    }
                    saw_root_auth_absent = true;
                }
                _ => {
                    return Err(FormatError::InvalidArchive(
                        "root-auth footer terminal state is inconsistent",
                    ));
                }
            }

            let record_len = block_record_len(parsed.crypto_header.block_size as usize)?;
            let source = SeekableVolumeSource {
                reader: parsed.reader.clone(),
                volume_index: parsed.volume_header.volume_index,
                block_records_start: parsed.block_records_start,
                block_count: parsed.volume_trailer.block_count,
                record_len,
                block_size: parsed.crypto_header.block_size as usize,
            };
            let slot = parsed.volume_header.volume_index as usize;
            if slot >= lazy_volume_slots.len() || lazy_volume_slots[slot].replace(source).is_some()
            {
                return Err(FormatError::InvalidArchive(
                    "duplicate authenticated volume index",
                ));
            }

            if first.is_none() {
                first = Some(parsed);
            }
        }

        let first = first.ok_or(FormatError::InvalidArchive("no volumes supplied"))?;
        let manifest_footer = manifest_authority.ok_or(match first_manifest_footer_error {
            Some(err) => err,
            None => FormatError::InvalidArchive("no verified ManifestFooter found"),
        })?;
        let authority_volume_header = manifest_authority_volume_header.ok_or(
            FormatError::InvalidArchive("no verified ManifestFooter found"),
        )?;
        let authority_volume_trailer = manifest_authority_volume_trailer.ok_or(
            FormatError::InvalidArchive("no verified ManifestFooter found"),
        )?;
        let observed_volume_count = u32::try_from(seen_volume_indexes.len())
            .map_err(|_| FormatError::InvalidArchive("volume count overflow"))?;
        let missing_volume_count = first
            .crypto_header
            .stripe_width
            .checked_sub(observed_volume_count)
            .ok_or(FormatError::InvalidArchive("volume count overflow"))?;
        if missing_volume_count > first.crypto_header.volume_loss_tolerance as u32 {
            return Err(FormatError::InvalidArchive(
                "missing volume count exceeds volume_loss_tolerance",
            ));
        }

        let mut blocks = BTreeMap::new();
        let sidecar = if let Some(bytes) = bootstrap_sidecar {
            let sidecar = parse_bootstrap_sidecar(
                bytes,
                &first.volume_header,
                &first.crypto_header,
                &first.subkeys,
            )?;
            sidecar
                .require_sections_for(BootstrapSidecarUse::SeekableAssist, &first.crypto_header)?;
            if let Some(sidecar_manifest) = &sidecar.manifest_footer {
                if !manifest_bootstrap_fields_match(&manifest_footer, sidecar_manifest) {
                    return Err(FormatError::InvalidArchive(
                        "bootstrap sidecar conflicts with terminal ManifestFooter",
                    ));
                }
            }
            Some((bytes, sidecar))
        } else {
            None
        };

        if let Some((sidecar_bytes, sidecar)) = &sidecar {
            if let Some((offset, length)) = sidecar.index_root_records_section {
                let index_root_records = parse_sidecar_block_records(
                    sidecar_bytes,
                    first.crypto_header.block_size as usize,
                    SidecarBlockRecordsSection {
                        offset,
                        length,
                        extent: index_root_extent_from_manifest(&manifest_footer),
                        data_kind: BlockKind::IndexRootData,
                        parity_kind: BlockKind::IndexRootParity,
                        structure: "IndexRoot",
                    },
                )?;
                insert_sidecar_records(&mut blocks, index_root_records)?;
            }
        }

        let lazy_source = Arc::new(SeekableBlockSource {
            stripe_width: first.crypto_header.stripe_width,
            volumes: lazy_volume_slots,
        });
        let block_provider = OpenedBlockProvider {
            memory_blocks: &blocks,
            lazy_blocks: Some(lazy_source.as_ref()),
        };
        let limits = metadata_limits(&first.crypto_header);
        let index_root_plaintext = load_metadata_object_from_parts(
            &block_provider,
            ObjectLoadContext::index_root(
                &first.volume_header,
                &first.crypto_header,
                &first.subkeys,
                index_root_extent_from_manifest(&manifest_footer),
            ),
            manifest_footer.index_root_decompressed_size,
        )?;
        let index_root = IndexRoot::parse(
            &index_root_plaintext,
            first.crypto_header.has_dictionary != 0,
            limits,
        )?;
        if first.crypto_header.has_dictionary != 0 {
            if let Some((sidecar_bytes, sidecar)) = &sidecar {
                if let Some((offset, length)) = sidecar.dictionary_records_section {
                    let dictionary_records = parse_sidecar_block_records(
                        sidecar_bytes,
                        first.crypto_header.block_size as usize,
                        SidecarBlockRecordsSection {
                            offset,
                            length,
                            extent: dictionary_extent_from_index_root(&index_root)?,
                            data_kind: BlockKind::DictionaryData,
                            parity_kind: BlockKind::DictionaryParity,
                            structure: "Dictionary",
                        },
                    )?;
                    insert_sidecar_records(&mut blocks, dictionary_records)?;
                }
            }
        }
        let block_provider = OpenedBlockProvider {
            memory_blocks: &blocks,
            lazy_blocks: Some(lazy_source.as_ref()),
        };
        let payload_dictionary = load_archive_dictionary(
            &block_provider,
            &first.subkeys,
            &first.volume_header,
            &first.crypto_header,
            &index_root,
        )?;

        Ok(Self {
            options,
            observed_archive_bytes,
            observed_volume_count,
            subkeys: first.subkeys,
            blocks,
            lazy_blocks: Some(lazy_source),
            crypto_header_bytes: first.crypto_header_bytes,
            volume_header: authority_volume_header,
            crypto_header: first.crypto_header,
            manifest_footer,
            volume_trailer: Some(authority_volume_trailer),
            root_auth_footer: root_auth_authority,
            index_root,
            payload_dictionary,
        })
    }

    pub fn open_with_bootstrap_sidecar_options(
        bytes: &[u8],
        bootstrap_sidecar: &[u8],
        master_key: &MasterKey,
        options: ReaderOptions,
    ) -> Result<Self, FormatError> {
        Self::open_with_bootstrap_sidecar_options_for_mode(
            bytes,
            bootstrap_sidecar,
            master_key,
            options,
            BootstrapSidecarUse::SeekableAssist,
        )
    }

    fn open_with_bootstrap_sidecar_options_for_mode(
        bytes: &[u8],
        bootstrap_sidecar: &[u8],
        master_key: &MasterKey,
        options: ReaderOptions,
        sidecar_use: BootstrapSidecarUse,
    ) -> Result<Self, FormatError> {
        let observed_archive_bytes =
            observed_archive_size([bytes.len() as u64, bootstrap_sidecar.len() as u64])?;
        if bytes.len() < VOLUME_HEADER_LEN {
            return Err(FormatError::InvalidLength {
                structure: "archive",
                expected: VOLUME_HEADER_LEN,
                actual: bytes.len(),
            });
        }

        let volume_header = VolumeHeader::parse(slice(bytes, 0, VOLUME_HEADER_LEN, "archive")?)?;
        parse_volume_format_dispatch(&volume_header)?;
        let crypto_start = volume_header.crypto_header_offset as usize;
        let crypto_len = volume_header.crypto_header_length as usize;
        let crypto_bytes = slice(bytes, crypto_start, crypto_len, "CryptoHeader")?;
        let parsed_crypto = CryptoHeader::parse(crypto_bytes, volume_header.crypto_header_length)?;
        let subkeys = subkeys_for_open(
            Some(master_key),
            parsed_crypto.fixed.aead_algo,
            &volume_header.archive_uuid,
            &volume_header.session_id,
        )?;
        verify_integrity_tag(
            HmacDomain::CryptoHeader,
            parsed_crypto.fixed.aead_algo,
            volume_header.volume_format_rev,
            Some(&subkeys.mac_key),
            &volume_header.archive_uuid,
            &volume_header.session_id,
            parsed_crypto.hmac_covered_bytes,
            &parsed_crypto.header_hmac,
        )?;
        parsed_crypto.validate_extension_semantics()?;
        reject_unsupported_raw_stream_profile(&parsed_crypto.extensions)?;
        validate_bootstrap_single_volume_input(&volume_header, &parsed_crypto.fixed)?;
        validate_crypto_class_parity_exactness(&parsed_crypto.fixed)?;

        let sidecar = parse_bootstrap_sidecar(
            bootstrap_sidecar,
            &volume_header,
            &parsed_crypto.fixed,
            &subkeys,
        )?;
        sidecar.require_sections_for(sidecar_use, &parsed_crypto.fixed)?;
        let block_records_start = startup_block_records_start(
            &volume_header,
            &parsed_crypto.kdf_params,
            |start, length| {
                let start = to_usize(start, "KeyWrapTableV1")?;
                Ok(slice(bytes, start, length, "KeyWrapTableV1")?.to_vec())
            },
        )?;

        let (mut blocks, terminal_offset, observed_block_count) = parse_stream_block_prefix(
            bytes,
            to_usize(block_records_start, "BlockRecord")?,
            parsed_crypto.fixed.block_size as usize,
            &volume_header,
        )?;
        let terminal_material = match sidecar_use {
            BootstrapSidecarUse::SeekableAssist => Some(parse_terminal_material(
                bytes,
                terminal_offset,
                observed_block_count,
                KeyHoldingTerminalContext {
                    subkeys: &subkeys,
                    volume_header: &volume_header,
                    crypto_header: &parsed_crypto.fixed,
                    crypto_header_bytes: crypto_bytes,
                },
                options,
            )?),
            BootstrapSidecarUse::NonSeekableRandomAccess => parse_terminal_material(
                bytes,
                terminal_offset,
                observed_block_count,
                KeyHoldingTerminalContext {
                    subkeys: &subkeys,
                    volume_header: &volume_header,
                    crypto_header: &parsed_crypto.fixed,
                    crypto_header_bytes: crypto_bytes,
                },
                options,
            )
            .ok(),
        };
        let terminal_manifest = terminal_material.as_ref().map(|(manifest, _, _)| manifest);
        let manifest_authority = match sidecar_use {
            BootstrapSidecarUse::SeekableAssist => {
                let terminal_manifest = terminal_manifest.ok_or(FormatError::InvalidArchive(
                    "terminal ManifestFooter/VolumeTrailer is required",
                ))?;
                if let Some(sidecar_manifest) = &sidecar.manifest_footer {
                    if !manifest_bootstrap_fields_match(terminal_manifest, sidecar_manifest) {
                        return Err(FormatError::InvalidArchive(
                            "bootstrap sidecar conflicts with terminal ManifestFooter",
                        ));
                    }
                }
                terminal_manifest.clone()
            }
            BootstrapSidecarUse::NonSeekableRandomAccess => {
                let sidecar_manifest = sidecar
                    .manifest_footer
                    .as_ref()
                    .ok_or(FormatError::ReaderUnsupported(
                    "non-seekable bootstrap sidecar requires ManifestFooter and IndexRoot sections",
                ))?;
                if let Some(terminal_manifest) = terminal_manifest {
                    if !manifest_bootstrap_fields_match(terminal_manifest, sidecar_manifest) {
                        return Err(FormatError::InvalidArchive(
                            "bootstrap sidecar conflicts with terminal ManifestFooter",
                        ));
                    }
                }
                sidecar_manifest.clone()
            }
        };
        manifest_authority.validate_index_root_extent(parsed_crypto.fixed.block_size)?;

        if let Some((offset, length)) = sidecar.index_root_records_section {
            let index_root_records = parse_sidecar_block_records(
                bootstrap_sidecar,
                parsed_crypto.fixed.block_size as usize,
                SidecarBlockRecordsSection {
                    offset,
                    length,
                    extent: index_root_extent_from_manifest(&manifest_authority),
                    data_kind: BlockKind::IndexRootData,
                    parity_kind: BlockKind::IndexRootParity,
                    structure: "IndexRoot",
                },
            )?;
            insert_sidecar_records(&mut blocks, index_root_records)?;
        }

        let limits = metadata_limits(&parsed_crypto.fixed);
        let index_root_plaintext = load_metadata_object_from_parts(
            &blocks,
            ObjectLoadContext::index_root(
                &volume_header,
                &parsed_crypto.fixed,
                &subkeys,
                index_root_extent_from_manifest(&manifest_authority),
            ),
            manifest_authority.index_root_decompressed_size,
        )?;
        let index_root = IndexRoot::parse(
            &index_root_plaintext,
            parsed_crypto.fixed.has_dictionary != 0,
            limits,
        )?;
        if parsed_crypto.fixed.has_dictionary != 0 {
            if let Some((offset, length)) = sidecar.dictionary_records_section {
                let dictionary_records = parse_sidecar_block_records(
                    bootstrap_sidecar,
                    parsed_crypto.fixed.block_size as usize,
                    SidecarBlockRecordsSection {
                        offset,
                        length,
                        extent: dictionary_extent_from_index_root(&index_root)?,
                        data_kind: BlockKind::DictionaryData,
                        parity_kind: BlockKind::DictionaryParity,
                        structure: "dictionary",
                    },
                )?;
                insert_sidecar_records(&mut blocks, dictionary_records)?;
            }
        }
        let payload_dictionary = load_archive_dictionary(
            &blocks,
            &subkeys,
            &volume_header,
            &parsed_crypto.fixed,
            &index_root,
        )?;

        Ok(Self {
            options,
            observed_archive_bytes,
            observed_volume_count: 1,
            subkeys,
            blocks,
            lazy_blocks: None,
            crypto_header_bytes: crypto_bytes.to_vec(),
            volume_header,
            crypto_header: parsed_crypto.fixed,
            manifest_footer: manifest_authority,
            volume_trailer: terminal_material
                .as_ref()
                .map(|(_, trailer, _)| trailer.clone()),
            root_auth_footer: terminal_material.and_then(|(_, _, root_auth)| root_auth),
            index_root,
            payload_dictionary,
        })
    }

    /// Return path and payload-size entries from encrypted index metadata only.
    ///
    /// Unlike [`Self::list_files`], this does not decode tar member groups, so
    /// it does not read or decrypt payload envelopes after the index shards are
    /// available.
    pub fn list_index_entries(&self) -> Result<Vec<ArchiveIndexEntry>, FormatError> {
        let shards = self.load_all_index_shards()?;
        final_index_entry_winners(&shards)?
            .into_iter()
            .map(|(path, winner)| {
                archive_index_entry_from_loaded_file_with_path(
                    path,
                    &shards[winner.shard_index],
                    winner.file_index,
                )
            })
            .collect()
    }

    pub fn list_directory_contents(
        &self,
        path: &str,
    ) -> Result<Vec<ArchiveIndexEntry>, FormatError> {
        let normalized = crate::metadata::normalize_lookup_directory_path(
            path,
            self.crypto_header.max_path_length,
        )?;
        let target_hash = crate::metadata::hash_prefix(&normalized);

        let mut locating_hint_shard = None;
        for shard_entry in &self.index_root.directory_hint_shards {
            if target_hash >= shard_entry.first_dir_hash && target_hash <= shard_entry.last_dir_hash
            {
                locating_hint_shard = Some(shard_entry);
                break;
            }
        }

        let mut shard_rows = Vec::new();
        if let Some(hint_shard) = locating_hint_shard {
            let table = self.load_directory_hint_table(hint_shard)?;
            if let Some(entry_index) = table.lookup_directory_index(&normalized) {
                if let Some(rows) = table.shard_rows_for_entry(entry_index) {
                    shard_rows.extend_from_slice(rows);
                }
            } else {
                return Ok(Vec::new());
            }
        } else if self.index_root.directory_hint_shards.is_empty() {
            shard_rows = (0..self.index_root.shards.len() as u32).collect();
        } else {
            return Ok(Vec::new());
        }

        let mut loaded_shards = Vec::new();
        for &row_index in &shard_rows {
            if let Some(shard_entry) = self.index_root.shards.get(row_index as usize) {
                let shard = self.load_index_shard(shard_entry)?;
                loaded_shards.push(shard);
            }
        }

        let winners = final_index_entry_winners(&loaded_shards)?;

        let mut results = Vec::new();
        let mut child_indices: HashMap<String, usize> = HashMap::new();

        let prefix_len = if normalized.is_empty() {
            0
        } else {
            normalized.len() + 1
        };

        for (entry_path, winner) in winners {
            if crate::metadata::is_directory_ancestor(&normalized, entry_path.as_bytes()) {
                let suffix = &entry_path.as_bytes()[prefix_len..];

                let (child_path, is_implicit_dir) =
                    if let Some(slash_idx) = suffix.iter().position(|&c| c == b'/') {
                        let mut child = if normalized.is_empty() {
                            Vec::new()
                        } else {
                            let mut p = normalized.clone();
                            p.push(b'/');
                            p
                        };
                        child.extend_from_slice(&suffix[..slash_idx]);
                        (String::from_utf8_lossy(&child).into_owned(), true)
                    } else {
                        (entry_path.clone(), false)
                    };

                match child_indices.entry(child_path.clone()) {
                    std::collections::hash_map::Entry::Vacant(vacant) => {
                        let idx = results.len();
                        vacant.insert(idx);
                        if is_implicit_dir {
                            let name = child_path.split('/').next_back().unwrap_or("").to_string();
                            results.push(ArchiveIndexEntry {
                                path: child_path,
                                name,
                                file_data_size: 0,
                                flags: 0,
                                path_hash: [0; 8],
                                tar_member_group_size: 0,
                                first_frame_index: 0,
                                frame_count: 0,
                                offset_in_first_frame_plaintext: 0,
                                layout: ArchiveIndexEntryLayout {
                                    compressed_size: 0,
                                    decompressed_frame_size: 0,
                                    envelope_count: 0,
                                    first_envelope_index: None,
                                    last_envelope_index: None,
                                    first_payload_block_index: None,
                                    payload_data_block_count: 0,
                                    payload_parity_block_count: 0,
                                    payload_encrypted_size: 0,
                                },
                                kind: crate::tar_model::TarEntryKind::Directory,
                                mtime: crate::entry_metadata::ArchiveTimestamp {
                                    seconds: 0,
                                    nanoseconds: 0,
                                },
                                created: None,
                                accessed: None,
                                mode: 0o755,
                                attributes: None,
                                uid: None,
                                gid: None,
                                uname: None,
                                gname: None,
                                link_target: None,
                            });
                        } else {
                            let entry = archive_index_entry_from_loaded_file_with_path(
                                entry_path,
                                &loaded_shards[winner.shard_index],
                                winner.file_index,
                            )?;
                            results.push(entry);
                        }
                    }
                    std::collections::hash_map::Entry::Occupied(occupied) => {
                        if !is_implicit_dir {
                            let idx = *occupied.get();
                            let entry = archive_index_entry_from_loaded_file_with_path(
                                entry_path,
                                &loaded_shards[winner.shard_index],
                                winner.file_index,
                            )?;
                            results[idx] = entry;
                        }
                    }
                }
            }
        }

        Ok(results)
    }

    /// Look up one archive path using encrypted index metadata only.
    pub fn lookup_index_entry(&self, path: &str) -> Result<Option<ArchiveIndexEntry>, FormatError> {
        let normalized = normalize_lookup_file_path(path, self.crypto_header.max_path_length)?;
        self.locate_index_file(&normalized)?
            .map(|located| archive_index_entry_from_loaded_file(&located.shard, located.file_index))
            .transpose()
    }

    pub fn list_files(&self) -> Result<Vec<ArchiveEntry>, FormatError> {
        let shards = self.load_all_index_shards()?;
        final_index_entry_winners(&shards)?
            .into_iter()
            .map(|(path, winner)| {
                let shard = &shards[winner.shard_index];
                let member =
                    self.decode_loaded_owned_tar_member(shard, winner.file_index, false)?;
                let v45 = member
                    .v45_metadata
                    .as_ref()
                    .ok_or(FormatError::InvalidArchive(
                        "revision-45 member metadata is missing",
                    ))?;
                let mtime = v45.portable_mirror.mtime;
                Ok(ArchiveEntry {
                    path,
                    file_data_size: winner.file_data_size,
                    kind: member.kind,
                    mode: member.mode,
                    mtime: ArchiveTimestamp::new(mtime.0, mtime.1),
                    diagnostics: member.diagnostics,
                    link_target: member
                        .link_target
                        .as_ref()
                        .map(|target| String::from_utf8_lossy(target).into_owned()),
                    created: pax_timestamp(&v45.primary_records, "LIBARCHIVE.creationtime"),
                    accessed: pax_timestamp(&v45.primary_records, "atime"),
                    attributes: exposed_file_attributes(
                        &v45.primary_records,
                        v45.portable_mirror.attributes,
                    ),
                    uid: v45.portable_mirror.uid,
                    gid: v45.portable_mirror.gid,
                    uname: v45
                        .portable_mirror
                        .uname
                        .as_ref()
                        .map(|bytes| String::from_utf8_lossy(bytes).into_owned()),
                    gname: v45
                        .portable_mirror
                        .gname
                        .as_ref()
                        .map(|bytes| String::from_utf8_lossy(bytes).into_owned()),
                })
            })
            .collect()
    }

    /// Validate metadata restoration for the final archive entries without
    /// creating destination paths.
    pub fn plan_metadata_restore(
        &self,
        options: SafeExtractionOptions,
    ) -> Result<Vec<(String, Vec<MetadataDiagnostic>)>, FormatError> {
        let shards = self.load_all_index_shards()?;
        let mut planned = Vec::new();
        for (path, winner) in final_index_entry_winners(&shards)? {
            let member = self.decode_loaded_owned_tar_member(
                &shards[winner.shard_index],
                winner.file_index,
                false,
            )?;
            planned.push((path, member));
        }
        let members: Vec<_> = planned.iter().map(|(_, member)| member).collect();
        validate_owned_restore_plan(&members, options)?;
        planned
            .into_iter()
            .map(|(path, member)| Ok((path, plan_owned_member_restore(&member, options)?)))
            .collect()
    }

    /// Return only the regular-file payload bytes for `path`.
    ///
    /// This is a payload-only convenience for callers that do not need tar
    /// metadata fidelity diagnostics. Use [`Self::extract_file_with_diagnostics`]
    /// or [`Self::extract_member`] when revision-45 metadata fidelity
    /// diagnostics must be reported to users.
    pub fn extract_file(&self, path: &str) -> Result<Option<Vec<u8>>, FormatError> {
        self.extract_member(path)?
            .map(|member| {
                if member.kind != TarEntryKind::Regular || member.reparse_placeholder {
                    return Err(FormatError::ReaderUnsupported(
                        "extract_file returns only regular file payloads",
                    ));
                }
                Ok(member.data)
            })
            .transpose()
    }

    /// Return regular-file payload bytes together with parsed tar metadata
    /// diagnostics for `path`.
    pub fn extract_file_with_diagnostics(
        &self,
        path: &str,
    ) -> Result<Option<ExtractedRegularFile>, FormatError> {
        self.extract_member(path)?
            .map(|member| {
                if member.kind != TarEntryKind::Regular || member.reparse_placeholder {
                    return Err(FormatError::ReaderUnsupported(
                        "extract_file_with_diagnostics returns only regular file payloads",
                    ));
                }
                Ok((member.data, member.diagnostics))
            })
            .transpose()
    }

    /// Stream regular-file payload bytes for `path` into `writer`.
    ///
    /// This keeps extraction memory bounded by the selected payload envelope,
    /// one decompressed frame, and small tar metadata buffers. It returns the
    /// same metadata diagnostics as [`Self::extract_file_with_diagnostics`].
    pub fn extract_file_to_writer<W: Write>(
        &self,
        path: &str,
        writer: &mut W,
    ) -> Result<Option<Vec<MetadataDiagnostic>>, ExtractError> {
        let normalized = normalize_lookup_file_path(path, self.crypto_header.max_path_length)?;
        self.locate_index_file(&normalized)?
            .map(|located| {
                self.stream_loaded_file_to_writer(&located.shard, located.file_index, writer)
            })
            .transpose()
    }

    /// Stream regular-file payload bytes for `path` into `writer` while
    /// reporting extracted logical payload bytes.
    pub fn extract_file_to_writer_with_progress<W: Write>(
        &self,
        path: &str,
        writer: &mut W,
        progress: &mut dyn ArchiveExtractProgressSink,
    ) -> Result<Option<Vec<MetadataDiagnostic>>, ExtractError> {
        let normalized = normalize_lookup_file_path(path, self.crypto_header.max_path_length)?;
        self.locate_index_file(&normalized)?
            .map(|located| {
                self.stream_loaded_file_to_writer_with_progress(
                    &located.shard,
                    located.file_index,
                    writer,
                    progress,
                )
            })
            .transpose()
    }

    /// Apply the selected restore policy's regular-file metadata to an already
    /// materialized output file without rewriting its payload.
    pub fn restore_file_metadata_to_open_file(
        &self,
        path: &str,
        file: &File,
        options: SafeExtractionOptions,
    ) -> Result<Option<Vec<MetadataDiagnostic>>, FormatError> {
        let normalized = normalize_lookup_file_path(path, self.crypto_header.max_path_length)?;
        let normalized_path = std::str::from_utf8(&normalized)
            .map_err(|_| FormatError::UnsafeArchivePath)?
            .to_owned();
        let shards = self.load_all_index_shards()?;
        let winners = final_index_entry_winners(&shards)?;
        let Some(requested) = winners.get(&normalized_path).copied() else {
            return Ok(None);
        };
        let member = self.decode_loaded_owned_tar_member(
            &shards[requested.shard_index],
            requested.file_index,
            false,
        )?;
        restore_regular_file_metadata_to_open_file(file, &member, options).map(Some)
    }

    pub fn extract_member(
        &self,
        path: &str,
    ) -> Result<Option<ExtractedArchiveMember>, FormatError> {
        let normalized = normalize_lookup_file_path(path, self.crypto_header.max_path_length)?;
        self.locate_index_file(&normalized)?
            .map(|located| self.extract_loaded_member(&located.shard, located.file_index))
            .transpose()
    }

    pub fn extract_file_to(
        &self,
        path: &str,
        root: &std::path::Path,
        options: SafeExtractionOptions,
    ) -> Result<Option<Vec<MetadataDiagnostic>>, FormatError> {
        let normalized = normalize_lookup_file_path(path, self.crypto_header.max_path_length)?;
        let normalized_path = std::str::from_utf8(&normalized)
            .map_err(|_| FormatError::UnsafeArchivePath)?
            .to_owned();
        let shards = self.load_all_index_shards()?;
        let winners = final_index_entry_winners(&shards)?;
        let Some(requested) = winners.get(&normalized_path).copied() else {
            return Ok(None);
        };
        let requested_member = self.decode_loaded_owned_tar_member(
            &shards[requested.shard_index],
            requested.file_index,
            false,
        )?;
        let mut entries = Vec::with_capacity(2);
        if requested_member.kind == TarEntryKind::Hardlink {
            let target = requested_member
                .link_target
                .as_deref()
                .ok_or(FormatError::InvalidArchive("hardlink target is missing"))?;
            let target = std::str::from_utf8(target)
                .map_err(|_| FormatError::UnsafeArchivePath)?
                .to_owned();
            let target_entry = winners
                .get(&target)
                .copied()
                .ok_or(FormatError::InvalidArchive(
                    "hardlink target is absent from the final index",
                ))?;
            entries.push((target, target_entry));
        }
        entries.push((normalized_path.clone(), requested));
        let restored = self.extract_winning_index_entries_to(&shards, entries, root, options, 1)?;
        restored
            .into_iter()
            .find_map(|(entry_path, diagnostics)| {
                (entry_path == normalized_path).then_some(diagnostics)
            })
            .map(Some)
            .ok_or(FormatError::InvalidArchive(
                "selected restore result is missing",
            ))
    }

    pub fn extract_indexed_files_to(
        &self,
        root: &std::path::Path,
        options: SafeExtractionOptions,
        jobs: usize,
    ) -> Result<Vec<(String, Vec<MetadataDiagnostic>)>, FormatError> {
        if jobs == 0 {
            return Err(FormatError::ReaderUnsupported("jobs must be at least 1"));
        }

        let shards = self.load_all_index_shards()?;
        let mut entries = final_index_entry_winners(&shards)?
            .into_iter()
            .collect::<Vec<_>>();
        entries.sort_by_key(|(_, entry)| entry.start);
        self.extract_winning_index_entries_to(&shards, entries, root, options, jobs)
    }

    /// Restore a selected final-view path set after preflighting it as one graph.
    ///
    /// Canonical hardlink targets are included as restore dependencies. No
    /// selected destination is written until every selected member and added
    /// dependency passes metadata-policy and path-graph validation.
    pub fn extract_selected_files_to(
        &self,
        paths: &[String],
        root: &std::path::Path,
        options: SafeExtractionOptions,
        jobs: usize,
    ) -> Result<Vec<(String, Vec<MetadataDiagnostic>)>, FormatError> {
        if jobs == 0 {
            return Err(FormatError::ReaderUnsupported("jobs must be at least 1"));
        }

        let shards = self.load_all_index_shards()?;
        let winners = final_index_entry_winners(&shards)?;
        let mut selected = BTreeMap::new();
        for path in paths {
            let normalized = normalize_lookup_file_path(path, self.crypto_header.max_path_length)?;
            let normalized = std::str::from_utf8(&normalized)
                .map_err(|_| FormatError::UnsafeArchivePath)?
                .to_owned();
            let entry = winners
                .get(&normalized)
                .copied()
                .ok_or(FormatError::ReaderUnsupported(
                    "selected archive path is absent from the final index",
                ))?;
            selected.insert(normalized, entry);
        }

        let requested = selected
            .iter()
            .map(|(path, entry)| (path.clone(), *entry))
            .collect::<Vec<_>>();
        for (_, entry) in requested {
            let member = self.decode_loaded_owned_tar_member(
                &shards[entry.shard_index],
                entry.file_index,
                false,
            )?;
            if member.kind != TarEntryKind::Hardlink {
                continue;
            }
            let target = member
                .link_target
                .as_deref()
                .ok_or(FormatError::InvalidArchive("hardlink target is missing"))?;
            let target = std::str::from_utf8(target)
                .map_err(|_| FormatError::UnsafeArchivePath)?
                .to_owned();
            let target_entry = winners
                .get(&target)
                .copied()
                .ok_or(FormatError::InvalidArchive(
                    "hardlink target is absent from the final index",
                ))?;
            selected.entry(target).or_insert(target_entry);
        }

        let mut entries = selected.into_iter().collect::<Vec<_>>();
        entries.sort_by_key(|(_, entry)| entry.start);
        self.extract_winning_index_entries_to(&shards, entries, root, options, jobs)
    }

    pub fn verify(&self) -> Result<(), FormatError> {
        self.verify_content().map(|_| ())
    }

    pub fn verify_content(&self) -> Result<ArchiveContentVerification<'_>, FormatError> {
        self.verify_content_with_parity_policy(
            ParityReadPolicy::Always,
            ContentVerificationMode::Full,
        )
    }

    pub fn verify_content_fast(&self) -> Result<ArchiveContentVerification<'_>, FormatError> {
        if self.fast_verify_defers_payload_semantics() {
            self.verify_payload_record_integrity_only()?;
            return Ok(ArchiveContentVerification {
                archive: self,
                mode: ContentVerificationMode::Fast,
                metadata_report: None,
            });
        }
        self.verify_content_with_parity_policy(
            ParityReadPolicy::RepairOnly,
            ContentVerificationMode::Fast,
        )
    }

    pub fn fast_verify_defers_payload_semantics(&self) -> bool {
        self.root_auth_footer.is_none()
            && self.crypto_header.has_dictionary == 0
            && !self.crypto_header.aead_algo.is_encrypted()
            && self.crypto_header.fec_parity_shards == 0
            && self.crypto_header.index_fec_parity_shards == 0
            && self.crypto_header.index_root_fec_parity_shards == 0
            && self.manifest_footer.index_root_parity_block_count == 0
    }

    fn verify_payload_record_integrity_only(&self) -> Result<(), FormatError> {
        let tables = self.load_payload_index_tables()?;
        let block_provider = self.block_provider();
        let block_size = self.crypto_header.block_size as u64;
        for envelope in tables.envelopes.values() {
            if envelope.parity_block_count != 0 {
                return Err(FormatError::InvalidArchive(
                    "fast payload record scan requires zero parity",
                ));
            }
            let expected_encrypted_size = checked_u64_mul(
                envelope.data_block_count as u64,
                block_size,
                "payload envelope encrypted size",
            )?;
            if envelope.encrypted_size as u64 != expected_encrypted_size {
                return Err(FormatError::InvalidArchive(
                    "payload envelope encrypted_size mismatch",
                ));
            }
            for offset in 0..envelope.data_block_count {
                let block_index =
                    checked_u64_add(envelope.first_block_index, offset as u64, "payload")?;
                let record = block_provider
                    .block(block_index)?
                    .ok_or(FormatError::InvalidArchive("payload data block is missing"))?;
                if record.kind != BlockKind::PayloadData {
                    return Err(FormatError::InvalidArchive(
                        "payload data block has unexpected kind",
                    ));
                }
                let should_be_last = offset + 1 == envelope.data_block_count;
                if record.is_last_data() != should_be_last {
                    return Err(FormatError::InvalidArchive(
                        "payload last-data flag is not on the final data block",
                    ));
                }
            }
        }
        Ok(())
    }

    fn verify_content_with_parity_policy(
        &self,
        parity_policy: ParityReadPolicy,
        mode: ContentVerificationMode,
    ) -> Result<ArchiveContentVerification<'_>, FormatError> {
        let tables = self.load_payload_index_tables()?;
        let streamed = self.scan_seekable_payload(
            &tables,
            u64::MAX,
            NoopTarStreamObserver,
            true,
            parity_policy,
        )?;
        self.validate_streamed_payload_summary(&tables, &streamed, false, true)?;
        let metadata_report = metadata_verification_report(&streamed.tar.members)?;
        Ok(ArchiveContentVerification {
            archive: self,
            mode,
            metadata_report: Some(metadata_report),
        })
    }

    pub fn repair_patches(&self) -> Result<Vec<ArchiveRepairPatch>, FormatError> {
        let lazy_source = self
            .lazy_blocks
            .as_ref()
            .ok_or(FormatError::ReaderUnsupported(
                "repair output requires seekable archive input",
            ))?;
        if !lazy_source.is_complete_volume_set() {
            return Err(FormatError::ReaderUnsupported(
                "repair output requires all archive volumes",
            ));
        }

        let shards = self.load_all_index_shards()?;
        let rows = self.root_auth_fec_layout_rows(&shards)?;
        let block_provider = self.block_provider();
        let mut patches = BTreeMap::<u64, ArchiveRepairPatch>::new();
        for row in rows.into_iter().filter(|row| row.present) {
            self.collect_repair_patches_for_object(
                &block_provider,
                lazy_source,
                row,
                &mut patches,
            )?;
        }
        Ok(patches.into_values().collect())
    }

    pub fn extract_all_to(
        &self,
        root: &std::path::Path,
        options: SafeExtractionOptions,
    ) -> Result<Vec<(String, Vec<MetadataDiagnostic>)>, FormatError> {
        let tables = self.load_payload_index_tables()?;
        if final_index_entry_winners(&tables.shards)?.len() as u64 != tables.file_count {
            return Err(FormatError::ReaderUnsupported(
                FAST_FULL_EXTRACT_UNIQUE_PATHS_UNSUPPORTED,
            ));
        }

        let dry_run = self.scan_seekable_payload(
            &tables,
            total_extraction_size_cap(self.options, self.observed_archive_bytes),
            NoopTarStreamObserver,
            false,
            ParityReadPolicy::RepairOnly,
        )?;
        self.validate_streamed_payload_summary(&tables, &dry_run, true, false)?;

        let observer = TarStreamFilesystemRestoreObserver::new(root, options);
        let streamed = self.scan_seekable_payload(
            &tables,
            total_extraction_size_cap(self.options, self.observed_archive_bytes),
            observer,
            false,
            ParityReadPolicy::RepairOnly,
        )?;
        streamed
            .tar
            .members
            .into_iter()
            .map(|member| Ok((utf8_path(&member.path)?, member.diagnostics)))
            .collect()
    }

    fn collect_repair_patches_for_object(
        &self,
        blocks: &impl BlockProvider,
        source: &SeekableBlockSource,
        row: FecLayoutObjectRow,
        patches: &mut BTreeMap<u64, ArchiveRepairPatch>,
    ) -> Result<(), FormatError> {
        let (data_kind, parity_kind, data_max, parity_max) =
            self.fec_object_class_shape(row.object_class)?;
        let extent = ObjectExtent {
            first_block_index: row.first_block_index,
            data_block_count: row.data_block_count,
            parity_block_count: row.parity_block_count,
            encrypted_size: row.encrypted_size,
        };
        validate_object_extent(extent, &self.crypto_header, data_max, parity_max)?;

        let block_size = self.crypto_header.block_size as usize;
        let data_count = extent.data_block_count as usize;
        let parity_count = extent.parity_block_count as usize;
        let mut data_shards = Vec::with_capacity(data_count);
        let mut parity_shards = Vec::with_capacity(parity_count);

        for offset in 0..data_count {
            let block_index = checked_u64_add(extent.first_block_index, offset as u64, "object")?;
            match blocks.block(block_index)? {
                Some(record) => {
                    if record.kind != data_kind {
                        return Err(FormatError::InvalidArchive(
                            "object data block has unexpected kind",
                        ));
                    }
                    let should_be_last = offset + 1 == data_count;
                    if record.is_last_data() != should_be_last {
                        return Err(FormatError::InvalidArchive(
                            "object last-data flag is not on the final data block",
                        ));
                    }
                    data_shards.push(Some(record.payload.clone()));
                }
                None => data_shards.push(None),
            }
        }

        for offset in 0..parity_count {
            let block_index = checked_u64_add(
                extent.first_block_index,
                data_count as u64 + offset as u64,
                "object",
            )?;
            match blocks.block(block_index)? {
                Some(record) => {
                    if record.kind != parity_kind {
                        return Err(FormatError::InvalidArchive(
                            "object parity block has unexpected kind",
                        ));
                    }
                    if record.is_last_data() {
                        return Err(FormatError::InvalidArchive(
                            "object parity block has last-data flag",
                        ));
                    }
                    parity_shards.push(Some(record.payload.clone()));
                }
                None => parity_shards.push(None),
            }
        }

        let repaired_data = repair_data_gf16(&data_shards, &parity_shards, block_size)?;
        for (offset, payload) in repaired_data.iter().enumerate() {
            if data_shards[offset].is_none() {
                let block_index =
                    checked_u64_add(extent.first_block_index, offset as u64, "object")?;
                let flags = if offset + 1 == data_count { 0x01 } else { 0 };
                self.insert_repair_patch(
                    patches,
                    source,
                    block_index,
                    data_kind,
                    flags,
                    payload.clone(),
                )?;
            }
        }

        if parity_count > 0 {
            let repaired_parity = encode_parity_gf16(&repaired_data, parity_count)?;
            for (offset, payload) in repaired_parity.into_iter().enumerate() {
                if parity_shards[offset].as_ref() != Some(&payload) {
                    let block_index = checked_u64_add(
                        extent.first_block_index,
                        data_count as u64 + offset as u64,
                        "object",
                    )?;
                    self.insert_repair_patch(
                        patches,
                        source,
                        block_index,
                        parity_kind,
                        0,
                        payload,
                    )?;
                }
            }
        }

        Ok(())
    }

    fn insert_repair_patch(
        &self,
        patches: &mut BTreeMap<u64, ArchiveRepairPatch>,
        source: &SeekableBlockSource,
        block_index: u64,
        kind: BlockKind,
        flags: u8,
        payload: Vec<u8>,
    ) -> Result<(), FormatError> {
        let (volume_index, record_offset) = source.record_location(block_index)?;
        let record = BlockRecord {
            block_index,
            kind,
            flags,
            payload,
            record_crc32c: 0,
        };
        let patch = ArchiveRepairPatch {
            volume_index,
            block_index,
            record_offset,
            record_bytes: record.to_bytes(),
        };
        if let Some(existing) = patches.insert(block_index, patch.clone()) {
            if existing != patch {
                return Err(FormatError::InvalidArchive(
                    "conflicting repair patch for BlockRecord",
                ));
            }
        }
        Ok(())
    }

    fn load_payload_index_tables(&self) -> Result<PayloadIndexTables, FormatError> {
        if self.index_root.header.file_count > DIRECTORY_HINT_REQUIRED_FILE_COUNT
            && self.index_root.directory_hint_shards.is_empty()
        {
            return Err(FormatError::InvalidArchive(
                "IndexRoot file_count requires directory hints",
            ));
        }

        let shards = self.load_all_index_shards()?;
        let mut file_count = 0u64;
        let mut frames = BTreeMap::<u64, FrameEntry>::new();
        let mut envelopes = BTreeMap::<u64, EnvelopeEntry>::new();

        for shard in &shards {
            file_count = file_count
                .checked_add(shard.files.len() as u64)
                .ok_or(FormatError::InvalidArchive("file count overflow"))?;
            for frame in &shard.frames {
                if let Some(existing) = frames.insert(frame.frame_index, frame.clone()) {
                    if existing != *frame {
                        return Err(FormatError::InvalidArchive(
                            "duplicate FrameEntry rows do not match",
                        ));
                    }
                }
            }
            for envelope in &shard.envelopes {
                if let Some(existing) = envelopes.insert(envelope.envelope_index, envelope.clone())
                {
                    if existing != *envelope {
                        return Err(FormatError::InvalidArchive(
                            "duplicate EnvelopeEntry rows do not match",
                        ));
                    }
                }
            }
        }
        validate_global_file_table_order(&shards)?;

        if file_count != self.index_root.header.file_count {
            return Err(FormatError::InvalidArchive(
                "IndexRoot file_count does not match decoded shards",
            ));
        }
        verify_dense_keys(&frames, self.index_root.header.frame_count, "FrameEntry")?;
        verify_dense_keys(
            &envelopes,
            self.index_root.header.envelope_count,
            "EnvelopeEntry",
        )?;
        validate_envelope_frame_coverage(&frames, &envelopes)?;
        self.validate_encrypted_object_block_ranges(&envelopes)?;

        let payload_block_count = envelopes.values().try_fold(0u64, |sum, envelope| {
            sum.checked_add(envelope.data_block_count as u64)
                .ok_or(FormatError::InvalidArchive("payload block count overflow"))
        })?;
        if payload_block_count != self.index_root.header.payload_block_count {
            return Err(FormatError::InvalidArchive(
                "IndexRoot payload_block_count does not match envelopes",
            ));
        }

        Ok(PayloadIndexTables {
            shards,
            file_count,
            frames,
            envelopes,
        })
    }

    fn scan_seekable_payload<O: TarStreamObserver>(
        &self,
        tables: &PayloadIndexTables,
        extraction_cap: u64,
        observer: O,
        hash_content: bool,
        parity_policy: ParityReadPolicy,
    ) -> Result<StreamedPayloadSummary, FormatError> {
        let mut tar = TarStreamSummaryValidator::with_observer(
            self.crypto_header.max_path_length,
            extraction_cap,
            usize::MAX,
            self.index_root.header.file_count,
            observer,
        );
        let mut content_hasher = hash_content.then(Sha256::new);
        let mut streamed_frames = Vec::with_capacity(tables.frames.len());
        let streamed_envelopes = tables
            .envelopes
            .values()
            .map(|envelope| StreamedEnvelopeSummary {
                envelope_index: envelope.envelope_index,
                first_block_index: envelope.first_block_index,
                data_block_count: envelope.data_block_count,
                parity_block_count: envelope.parity_block_count,
                encrypted_size: envelope.encrypted_size,
                plaintext_size: envelope.plaintext_size,
                first_frame_index: envelope.first_frame_index,
                frame_count: envelope.frame_count,
            })
            .collect::<Vec<_>>();
        let mut cached_envelope_index = None;
        let mut cached_envelope_plaintext = Vec::new();
        let mut decompressor = self.new_payload_decompressor()?;

        for frame in tables.frames.values() {
            let envelope =
                tables
                    .envelopes
                    .get(&frame.envelope_index)
                    .ok_or(FormatError::InvalidArchive(
                        "FrameEntry references missing EnvelopeEntry",
                    ))?;
            if cached_envelope_index != Some(envelope.envelope_index) {
                cached_envelope_plaintext = self.load_payload_envelope(envelope, parity_policy)?;
                cached_envelope_index = Some(envelope.envelope_index);
            }
            let compressed = slice(
                &cached_envelope_plaintext,
                frame.offset_in_envelope as usize,
                frame.compressed_size as usize,
                "FrameEntry",
            )?;
            let tar_stream_offset = tar.tar_total_size();
            let decoded = self.decompress_payload_frame_with(
                &mut decompressor,
                compressed,
                frame.decompressed_size,
            )?;
            if decoded.is_empty() {
                return Err(FormatError::InvalidArchive(
                    "zstd payload frame decompressed to zero bytes",
                ));
            }
            if let Some(hasher) = &mut content_hasher {
                hasher.update(&decoded);
            }
            tar.observe(&decoded)?;
            streamed_frames.push(StreamedFrameSummary {
                frame_index: frame.frame_index,
                envelope_index: frame.envelope_index,
                offset_in_envelope: frame.offset_in_envelope,
                compressed_size: u32::try_from(compressed.len()).map_err(|_| {
                    FormatError::InvalidArchive("FrameEntry.compressed_size overflow")
                })?,
                decompressed_size: u32::try_from(decoded.len()).map_err(|_| {
                    FormatError::InvalidArchive("FrameEntry.decompressed_size overflow")
                })?,
                tar_stream_offset,
            });
        }

        let mut content_sha256 = [0u8; 32];
        if let Some(hasher) = content_hasher {
            let digest = hasher.finalize();
            content_sha256.copy_from_slice(&digest);
        }
        Ok(StreamedPayloadSummary {
            tar: tar.finish()?,
            content_sha256,
            envelopes: streamed_envelopes,
            frames: streamed_frames,
        })
    }

    fn validate_streamed_payload_summary(
        &self,
        tables: &PayloadIndexTables,
        streamed: &StreamedPayloadSummary,
        enforce_total_extraction_cap: bool,
        enforce_content_sha256: bool,
    ) -> Result<(), FormatError> {
        if enforce_total_extraction_cap
            && streamed.tar.total_extraction_size
                > total_extraction_size_cap(self.options, self.observed_archive_bytes)
        {
            return Err(FormatError::ReaderUnsupported(
                "total extraction size exceeds configured cap",
            ));
        }

        let streamed_payload_block_count =
            streamed.envelopes.iter().try_fold(0u64, |sum, envelope| {
                sum.checked_add(envelope.data_block_count as u64)
                    .ok_or(FormatError::InvalidArchive("payload block count overflow"))
            })?;
        if streamed_payload_block_count != self.index_root.header.payload_block_count {
            return Err(FormatError::InvalidArchive(
                "streamed payload block count does not match IndexRoot",
            ));
        }

        if streamed.tar.tar_total_size != self.index_root.header.tar_total_size {
            return Err(FormatError::InvalidArchive(
                "IndexRoot tar_total_size does not match streamed tar stream",
            ));
        }
        if enforce_content_sha256
            && streamed.content_sha256 != self.index_root.header.content_sha256
        {
            return Err(FormatError::InvalidArchive(
                "IndexRoot content_sha256 does not match decoded tar stream",
            ));
        }

        let streamed_envelopes = streamed.envelope_map()?;
        for envelope in tables.envelopes.values() {
            let actual = streamed_envelopes.get(&envelope.envelope_index).ok_or(
                FormatError::InvalidArchive(
                    "metadata references missing streamed payload envelope",
                ),
            )?;
            if actual.first_block_index != envelope.first_block_index
                || actual.data_block_count != envelope.data_block_count
                || actual.parity_block_count != envelope.parity_block_count
                || actual.encrypted_size != envelope.encrypted_size
                || actual.plaintext_size != envelope.plaintext_size
                || actual.first_frame_index != envelope.first_frame_index
                || actual.frame_count != envelope.frame_count
            {
                return Err(FormatError::InvalidArchive(
                    "EnvelopeEntry does not match streamed payload envelope",
                ));
            }
        }

        let streamed_frames = streamed.frame_map()?;
        for frame in tables.frames.values() {
            let actual =
                streamed_frames
                    .get(&frame.frame_index)
                    .ok_or(FormatError::InvalidArchive(
                        "metadata references missing streamed payload frame",
                    ))?;
            if actual.envelope_index != frame.envelope_index
                || actual.offset_in_envelope != frame.offset_in_envelope
                || actual.compressed_size != frame.compressed_size
                || actual.decompressed_size != frame.decompressed_size
                || actual.tar_stream_offset != frame.tar_stream_offset
                || streamed.frame_flags(actual)? != frame.flags
            {
                return Err(FormatError::InvalidArchive(
                    "FrameEntry does not match streamed payload frame",
                ));
            }
        }

        let streamed_members = streamed.member_start_map()?;
        if streamed.tar.members.len() as u64 != tables.file_count {
            return Err(FormatError::InvalidArchive(
                "streamed tar member count does not match decoded shards",
            ));
        }
        let mut file_extents = Vec::new();
        let mut directory_hint_map = DirectoryHintMap::new();
        for (shard_row_index, shard) in tables.shards.iter().enumerate() {
            let shard_row_index = u32::try_from(shard_row_index)
                .map_err(|_| FormatError::InvalidArchive("shard row index overflow"))?;
            for idx in 0..shard.files.len() {
                let file = &shard.files[idx];
                let start =
                    shard
                        .tar_member_group_start(idx)
                        .ok_or(FormatError::InvalidArchive(
                            "FileEntry tar member start is missing",
                        ))?;
                file_extents.push((start, file.tar_member_group_size));
                let path = shard
                    .file_path(idx)
                    .ok_or(FormatError::InvalidArchive("FileEntry path is missing"))?;
                let member = streamed_members
                    .get(&start)
                    .ok_or(FormatError::InvalidArchive(
                        "FileEntry tar member start is missing from streamed tar",
                    ))?;
                if member.path != path {
                    return Err(FormatError::InvalidArchive(
                        "tar member path does not match FileEntry path",
                    ));
                }
                if member.logical_size != file.file_data_size {
                    return Err(FormatError::InvalidArchive(
                        "tar member size does not match FileEntry file_data_size",
                    ));
                }
                if member.file_entry_flags != file.flags {
                    return Err(FormatError::InvalidArchive(
                        "streamed tar member metadata flags do not match FileEntry flags",
                    ));
                }
                if member.group_size != file.tar_member_group_size {
                    return Err(FormatError::InvalidArchive(
                        "FileEntry does not match streamed tar member",
                    ));
                }
                add_expected_directory_hint_rows(
                    &mut directory_hint_map,
                    shard_row_index,
                    path,
                    member.kind,
                );
            }
        }
        validate_file_extent_coverage_ranges(&file_extents, self.index_root.header.tar_total_size)?;
        if !self.index_root.directory_hint_shards.is_empty() {
            let hint_tables = self.load_all_directory_hint_tables()?;
            validate_directory_hint_tables_against_expected(&hint_tables, &directory_hint_map)?;
        }

        Ok(())
    }

    pub(crate) fn from_streamed_parts(
        parts: StreamedArchiveOpenParts,
    ) -> Result<Self, FormatError> {
        let limits = metadata_limits(&parts.crypto_header);
        let index_root_plaintext = load_metadata_object_from_parts(
            &parts.blocks,
            ObjectLoadContext::index_root(
                &parts.volume_header,
                &parts.crypto_header,
                &parts.subkeys,
                ObjectExtent {
                    first_block_index: parts.manifest_footer.index_root_first_block,
                    data_block_count: parts.manifest_footer.index_root_data_block_count,
                    parity_block_count: parts.manifest_footer.index_root_parity_block_count,
                    encrypted_size: parts.manifest_footer.index_root_encrypted_size,
                },
            ),
            parts.manifest_footer.index_root_decompressed_size,
        )?;
        let index_root = IndexRoot::parse(
            &index_root_plaintext,
            parts.crypto_header.has_dictionary != 0,
            limits,
        )?;
        let payload_dictionary = load_archive_dictionary(
            &parts.blocks,
            &parts.subkeys,
            &parts.volume_header,
            &parts.crypto_header,
            &index_root,
        )?;

        Ok(Self {
            options: parts.options,
            observed_archive_bytes: parts.observed_archive_bytes,
            observed_volume_count: 1,
            subkeys: parts.subkeys,
            blocks: parts.blocks,
            lazy_blocks: None,
            crypto_header_bytes: parts.crypto_header_bytes,
            volume_header: parts.volume_header,
            crypto_header: parts.crypto_header,
            manifest_footer: parts.manifest_footer,
            volume_trailer: Some(parts.volume_trailer),
            root_auth_footer: parts.root_auth_footer,
            index_root,
            payload_dictionary,
        })
    }

    pub(crate) fn verify_streamed_payload_summary(
        &self,
        streamed: &StreamedPayloadSummary,
    ) -> Result<(), FormatError> {
        let tables = self.load_payload_index_tables()?;
        self.validate_streamed_payload_summary(&tables, streamed, true, true)
    }

    pub fn verify_root_auth_with<F>(&self, verifier: F) -> Result<RootAuthVerification, FormatError>
    where
        F: FnMut(&RootAuthFooterV1, &[u8; 32]) -> Result<bool, FormatError>,
    {
        let content_verification = self.verify_content()?;
        self.verify_root_auth_with_verified_content(&content_verification, verifier)
    }

    pub fn verify_root_auth_with_verified_content<F>(
        &self,
        content_verification: &ArchiveContentVerification<'_>,
        mut verifier: F,
    ) -> Result<RootAuthVerification, FormatError>
    where
        F: FnMut(&RootAuthFooterV1, &[u8; 32]) -> Result<bool, FormatError>,
    {
        if !std::ptr::eq(content_verification.archive, self) {
            return Err(FormatError::InvalidArchive(
                "content verification does not match archive",
            ));
        }
        if content_verification.mode != ContentVerificationMode::Full {
            return Err(FormatError::ReaderUnsupported(
                "RootAuth verification requires full archive content verification",
            ));
        }
        let footer = self
            .root_auth_footer
            .as_ref()
            .ok_or(FormatError::ReaderUnsupported("root-auth footer is absent"))?;
        let material = self.recompute_root_auth_material(footer)?;
        if material.critical_metadata_digest != footer.critical_metadata_digest
            || material.index_digest != footer.index_digest
            || material.fec_layout_digest != footer.fec_layout_digest
            || material.data_block_merkle_root != footer.data_block_merkle_root
            || material.signer_identity_digest != footer.signer_identity_digest
            || material.archive_root != footer.archive_root
            || material.total_data_block_count != footer.total_data_block_count
        {
            return Err(FormatError::InvalidArchive(
                "RootAuthFooter commitments do not match recomputed archive root",
            ));
        }
        if !verifier(footer, &material.archive_root)? {
            return Err(FormatError::InvalidArchive(
                "root-auth authenticator verification failed",
            ));
        }
        Ok(RootAuthVerification {
            format_version: footer.format_version,
            volume_format_rev: footer.volume_format_rev,
            archive_root: material.archive_root,
            authenticator_id: footer.authenticator_id,
            signer_identity_type: footer.signer_identity_type,
            signer_identity_bytes: footer.signer_identity_bytes.clone(),
            total_data_block_count: footer.total_data_block_count,
            diagnostics: self.root_auth_success_diagnostics(),
        })
    }

    fn load_all_index_shards(&self) -> Result<Vec<IndexShard>, FormatError> {
        parallel_map_ref(&self.index_root.shards, self.options.jobs, |entry| {
            self.load_index_shard(entry)
        })
    }

    fn load_index_shard(&self, entry: &ShardEntry) -> Result<IndexShard, FormatError> {
        let block_provider = self.block_provider();
        let plaintext = load_metadata_object_from_parts(
            &block_provider,
            ObjectLoadContext::index_shard(
                &self.volume_header,
                &self.crypto_header,
                &self.subkeys,
                entry,
            ),
            entry.decompressed_size,
        )?;
        IndexShard::parse(&plaintext, entry, self.metadata_limits())
    }

    fn load_all_directory_hint_tables(&self) -> Result<Vec<DirectoryHintTable>, FormatError> {
        parallel_map_ref(
            &self.index_root.directory_hint_shards,
            self.options.jobs,
            |entry| self.load_directory_hint_table(entry),
        )
    }

    fn load_directory_hint_table(
        &self,
        entry: &DirectoryHintShardEntry,
    ) -> Result<DirectoryHintTable, FormatError> {
        let block_provider = self.block_provider();
        let plaintext = load_metadata_object_from_parts(
            &block_provider,
            ObjectLoadContext::directory_hint(
                &self.volume_header,
                &self.crypto_header,
                &self.subkeys,
                entry,
            ),
            entry.decompressed_size,
        )?;
        DirectoryHintTable::parse(
            &plaintext,
            entry,
            self.index_root.header.shard_count,
            self.metadata_limits(),
        )
    }

    fn load_payload_envelope(
        &self,
        envelope: &EnvelopeEntry,
        parity_policy: ParityReadPolicy,
    ) -> Result<Vec<u8>, FormatError> {
        let block_provider = self.block_provider();
        let plaintext = load_decrypted_object_from_parts_with_parity_policy(
            &block_provider,
            ObjectLoadContext::payload(
                &self.volume_header,
                &self.crypto_header,
                &self.subkeys,
                envelope,
            ),
            parity_policy,
        )?;
        if plaintext.len() != envelope.plaintext_size as usize {
            return Err(FormatError::InvalidArchive(
                "payload envelope plaintext_size mismatch",
            ));
        }
        Ok(plaintext)
    }

    fn locate_index_file(
        &self,
        normalized: &[u8],
    ) -> Result<Option<LocatedIndexFile>, FormatError> {
        let candidate_indexes = self
            .index_root
            .candidate_shards_for_path(normalized, self.metadata_limits())?;
        let mut winner: Option<LocatedIndexFile> = None;

        for row_index in candidate_indexes {
            let locating =
                self.index_root
                    .shards
                    .get(row_index)
                    .ok_or(FormatError::InvalidArchive(
                        "candidate shard row is out of bounds",
                    ))?;
            let shard = self.load_index_shard(locating)?;
            if let Some(file_index) = shard.lookup_file_index(normalized) {
                let start =
                    shard
                        .tar_member_group_start(file_index)
                        .ok_or(FormatError::InvalidArchive(
                            "FileEntry tar member start is missing",
                        ))?;
                if winner
                    .as_ref()
                    .map(|existing| start > existing.start)
                    .unwrap_or(true)
                {
                    winner = Some(LocatedIndexFile {
                        shard,
                        file_index,
                        start,
                    });
                }
            }
        }

        Ok(winner)
    }

    fn extract_loaded_member(
        &self,
        shard: &IndexShard,
        file_index: usize,
    ) -> Result<ExtractedArchiveMember, FormatError> {
        let member = self.extract_loaded_owned_tar_member(shard, file_index)?;
        Ok(ExtractedArchiveMember {
            path: utf8_path(&member.path)?,
            kind: member.kind,
            data: member.data,
            link_target: member
                .link_target
                .map(|target| utf8_path(&target))
                .transpose()?,
            reparse_placeholder: member.reparse_placeholder,
            diagnostics: member.diagnostics,
        })
    }

    fn extract_loaded_owned_tar_member(
        &self,
        shard: &IndexShard,
        file_index: usize,
    ) -> Result<OwnedTarMember, FormatError> {
        self.decode_loaded_owned_tar_member(shard, file_index, true)
    }

    fn stream_loaded_file_to_writer<W: Write>(
        &self,
        shard: &IndexShard,
        file_index: usize,
        writer: &mut W,
    ) -> Result<Vec<MetadataDiagnostic>, ExtractError> {
        let file = shard
            .files
            .get(file_index)
            .ok_or(FormatError::InvalidArchive("FileEntry index out of bounds"))?;
        self.validate_total_extraction_size(file.file_data_size)?;
        let expected_path = shard
            .file_path(file_index)
            .ok_or(FormatError::InvalidArchive("FileEntry path is missing"))?;
        let mut reader = DecodedTarMemberGroupReader::new(self, shard, file)?;
        stream_regular_tar_member_group_to_writer(
            &mut reader,
            expected_path,
            file.file_data_size,
            file.flags,
            file.tar_member_group_size,
            self.crypto_header.max_path_length,
            writer,
        )
    }

    fn stream_loaded_file_to_writer_with_progress<W: Write>(
        &self,
        shard: &IndexShard,
        file_index: usize,
        writer: &mut W,
        progress: &mut dyn ArchiveExtractProgressSink,
    ) -> Result<Vec<MetadataDiagnostic>, ExtractError> {
        let file = shard
            .files
            .get(file_index)
            .ok_or(FormatError::InvalidArchive("FileEntry index out of bounds"))?;
        self.validate_total_extraction_size(file.file_data_size)?;
        let expected_path = shard
            .file_path(file_index)
            .ok_or(FormatError::InvalidArchive("FileEntry path is missing"))?;
        let archive_path = utf8_path(expected_path)?;
        let mut progress_writer =
            ExtractProgressWriter::new(writer, &archive_path, file.file_data_size, progress);
        let mut reader = DecodedTarMemberGroupReader::new(self, shard, file)?;
        stream_regular_tar_member_group_to_writer(
            &mut reader,
            expected_path,
            file.file_data_size,
            file.flags,
            file.tar_member_group_size,
            self.crypto_header.max_path_length,
            &mut progress_writer,
        )
    }

    fn stream_loaded_file_to_path(
        &self,
        shard: &IndexShard,
        file_index: usize,
        root: &std::path::Path,
        options: SafeExtractionOptions,
    ) -> Result<Vec<MetadataDiagnostic>, FormatError> {
        let file = shard
            .files
            .get(file_index)
            .ok_or(FormatError::InvalidArchive("FileEntry index out of bounds"))?;
        self.validate_total_extraction_size(file.file_data_size)?;
        let expected_path = shard
            .file_path(file_index)
            .ok_or(FormatError::InvalidArchive("FileEntry path is missing"))?;
        let mut reader = DecodedTarMemberGroupReader::new(self, shard, file)?;
        restore_streaming_tar_member_group(
            root,
            StreamingMemberExpectation {
                path: expected_path,
                file_data_size: file.file_data_size,
                file_flags: file.flags,
                group_len: file.tar_member_group_size,
                max_path_length: self.crypto_header.max_path_length,
            },
            options,
            &mut reader,
        )
        .map_err(format_error_from_extract_error)
    }

    fn extract_winning_index_entries_to(
        &self,
        shards: &[IndexShard],
        entries: Vec<(String, WinningIndexEntry)>,
        root: &std::path::Path,
        options: SafeExtractionOptions,
        jobs: usize,
    ) -> Result<Vec<(String, Vec<MetadataDiagnostic>)>, FormatError> {
        if entries.is_empty() {
            return Ok(Vec::new());
        }
        let metadata = parallel_map_ref(&entries, jobs, |(_, entry)| {
            let shard = shards
                .get(entry.shard_index)
                .ok_or(FormatError::InvalidArchive(
                    "winning FileEntry shard is out of bounds",
                ))?;
            self.decode_loaded_owned_tar_member(shard, entry.file_index, false)
        })?;
        validate_owned_restore_plan(&metadata.iter().collect::<Vec<_>>(), options)?;
        let mut planned = entries
            .into_iter()
            .zip(metadata)
            .map(|((path, entry), member)| (path, entry, member))
            .collect::<Vec<_>>();
        planned.sort_by(|left, right| {
            restore_phase(&left.2)
                .cmp(&restore_phase(&right.2))
                .then_with(|| left.2.path.cmp(&right.2.path))
        });
        let restored = planned
            .iter()
            .map(|(path, entry, _)| {
                let shard = &shards[entry.shard_index];
                let diagnostics =
                    self.stream_loaded_file_to_path(shard, entry.file_index, root, options)?;
                Ok((path.clone(), diagnostics))
            })
            .collect::<Result<Vec<_>, FormatError>>()?;
        #[cfg(windows)]
        let mut restored = restored;
        #[cfg(windows)]
        if options.restore_policy == crate::entry_metadata::RestorePolicy::System
            && options.system_authorized
        {
            // Directory security is restored last so children can be created
            // safely. Applying an inherited DACL can update descendant
            // security and ChangeTime, so replay exact descendant metadata
            // only after every selected directory has reached its final state.
            for ((_, _, member), (_, diagnostics)) in planned.iter().zip(restored.iter_mut()) {
                if !matches!(member.kind, TarEntryKind::Regular | TarEntryKind::Symlink) {
                    continue;
                }
                let metadata = member
                    .v45_metadata
                    .as_ref()
                    .ok_or(FormatError::InvalidArchive(
                        "revision-45 member metadata is missing",
                    ))?;
                replay_windows_descendant_metadata(
                    root,
                    &member.path,
                    member.kind,
                    metadata,
                    options,
                    diagnostics,
                )?;
            }
        }
        Ok(restored)
    }

    fn decode_loaded_owned_tar_member(
        &self,
        shard: &IndexShard,
        file_index: usize,
        enforce_extraction_cap: bool,
    ) -> Result<OwnedTarMember, FormatError> {
        let file = shard
            .files
            .get(file_index)
            .ok_or(FormatError::InvalidArchive("FileEntry index out of bounds"))?;
        if enforce_extraction_cap {
            self.validate_total_extraction_size(file.file_data_size)?;
        }
        let expected_path = shard
            .file_path(file_index)
            .ok_or(FormatError::InvalidArchive("FileEntry path is missing"))?;
        let frames = frame_range_for_file(shard, file)?;
        let mut envelope_cache = HashMap::<u64, Vec<u8>>::new();
        let mut decoded = Vec::new();

        for frame in frames {
            let envelope = envelope_by_index(shard, frame.envelope_index)?;
            if let Entry::Vacant(entry) = envelope_cache.entry(envelope.envelope_index) {
                entry.insert(self.load_payload_envelope(envelope, ParityReadPolicy::RepairOnly)?);
            }
            let envelope_plaintext = envelope_cache
                .get(&envelope.envelope_index)
                .expect("inserted above");
            let compressed = slice(
                envelope_plaintext,
                frame.offset_in_envelope as usize,
                frame.compressed_size as usize,
                "FrameEntry",
            )?;
            decoded.extend_from_slice(
                &self.decompress_payload_frame(compressed, frame.decompressed_size)?,
            );
        }

        let offset = file.offset_in_first_frame_plaintext as usize;
        let group_len = to_usize(file.tar_member_group_size, "FileEntry")?;
        let group = slice(&decoded, offset, group_len, "FileEntry")?;
        let member = parse_tar_member_group(group, self.crypto_header.max_path_length)?;
        if member.path != expected_path {
            return Err(FormatError::InvalidArchive(
                "tar member path does not match FileEntry path",
            ));
        }
        if member.logical_size != file.file_data_size {
            return Err(FormatError::InvalidArchive(
                "tar member size does not match FileEntry file_data_size",
            ));
        }
        if member.v45_metadata.file_entry_flags != file.flags {
            return Err(FormatError::InvalidArchive(
                "FileEntry flags do not match decoded member-group metadata",
            ));
        }
        if enforce_extraction_cap {
            member.to_owned_member()
        } else {
            Ok(member.to_owned_metadata())
        }
    }

    fn metadata_limits(&self) -> MetadataLimits {
        metadata_limits(&self.crypto_header)
    }

    fn recompute_root_auth_material(
        &self,
        footer: &RootAuthFooterV1,
    ) -> Result<RootAuthMaterial, FormatError> {
        if footer.format_version != self.volume_header.format_version {
            return Err(FormatError::InvalidArchive(
                "RootAuthFooter format_version differs from authenticated VolumeHeader",
            ));
        }
        if footer.volume_format_rev != self.volume_header.volume_format_rev {
            return Err(FormatError::InvalidArchive(
                "RootAuthFooter volume_format_rev differs from authenticated VolumeHeader",
            ));
        }
        let format_version = self.volume_header.format_version;
        let volume_format_rev = self.volume_header.volume_format_rev;
        let footer_length = footer.footer_length()?;
        let root_auth_descriptor_digest = root_auth_descriptor_digest_for_revision(
            format_version,
            volume_format_rev,
            footer.authenticator_id,
            footer.signer_identity_type,
            &footer.signer_identity_bytes,
            u32::try_from(footer.authenticator_value.len()).map_err(|_| {
                FormatError::InvalidArchive("RootAuthFooter authenticator length overflow")
            })?,
            footer_length,
        )?;
        let signer_identity_digest =
            signer_identity_digest(footer.signer_identity_type, &footer.signer_identity_bytes)?;
        let manifest_pre_hmac = manifest_footer_global_pre_hmac_bytes(&self.manifest_footer);
        let crypto_pre_hmac_len = self
            .crypto_header_bytes
            .len()
            .checked_sub(CRYPTO_HEADER_HMAC_LEN)
            .ok_or(FormatError::InvalidArchive("CryptoHeader is too short"))?;
        let critical_metadata_digest = critical_metadata_digest(CriticalMetadataDigestInputs {
            archive_uuid: self.volume_header.archive_uuid,
            session_id: self.volume_header.session_id,
            format_version,
            volume_format_rev,
            stripe_width: self.crypto_header.stripe_width,
            total_volumes: self.manifest_footer.total_volumes,
            compression_algo: self.crypto_header.compression_algo,
            aead_algo: self.crypto_header.aead_algo,
            fec_algo: self.crypto_header.fec_algo,
            kdf_algo: self.crypto_header.kdf_algo,
            crypto_header_pre_hmac_bytes: &self.crypto_header_bytes[..crypto_pre_hmac_len],
            chunk_size: self.crypto_header.chunk_size,
            envelope_target_size: self.crypto_header.envelope_target_size,
            block_size: self.crypto_header.block_size,
            fec_data_shards: self.crypto_header.fec_data_shards,
            fec_parity_shards: self.crypto_header.fec_parity_shards,
            index_fec_data_shards: self.crypto_header.index_fec_data_shards,
            index_fec_parity_shards: self.crypto_header.index_fec_parity_shards,
            index_root_fec_data_shards: self.crypto_header.index_root_fec_data_shards,
            index_root_fec_parity_shards: self.crypto_header.index_root_fec_parity_shards,
            volume_loss_tolerance: self.crypto_header.volume_loss_tolerance,
            bit_rot_buffer_pct: self.crypto_header.bit_rot_buffer_pct,
            has_dictionary: self.crypto_header.has_dictionary,
            manifest_footer_global_pre_hmac_bytes: &manifest_pre_hmac,
            index_root_first_block: self.manifest_footer.index_root_first_block,
            index_root_data_block_count: self.manifest_footer.index_root_data_block_count,
            index_root_parity_block_count: self.manifest_footer.index_root_parity_block_count,
            index_root_encrypted_size: self.manifest_footer.index_root_encrypted_size,
            index_root_decompressed_size: self.manifest_footer.index_root_decompressed_size,
            root_auth_descriptor_digest,
        })?;
        let index_root_plaintext = self.index_root.to_bytes();
        let index_digest =
            index_digest_for_revision(format_version, volume_format_rev, &index_root_plaintext)?;
        let shards = self.load_all_index_shards()?;
        let fec_layout_rows = self.root_auth_fec_layout_rows(&shards)?;
        let fec_layout_digest =
            fec_layout_digest_for_revision(format_version, volume_format_rev, &fec_layout_rows)?;
        let data_leaves = self.root_auth_data_block_leaves(&fec_layout_rows)?;
        let total_data_block_count = u64::try_from(data_leaves.len())
            .map_err(|_| FormatError::InvalidArchive("root-auth data block count overflow"))?;
        let data_block_merkle_root =
            data_block_merkle_root_for_revision(format_version, volume_format_rev, &data_leaves)?;
        let archive_root = archive_root_for_revision(ArchiveRootInputs {
            archive_uuid: self.volume_header.archive_uuid,
            session_id: self.volume_header.session_id,
            format_version,
            volume_format_rev,
            compression_algo: self.crypto_header.compression_algo,
            aead_algo: self.crypto_header.aead_algo,
            fec_algo: self.crypto_header.fec_algo,
            kdf_algo: self.crypto_header.kdf_algo,
            critical_metadata_digest,
            index_digest,
            fec_layout_digest,
            total_data_block_count,
            data_block_merkle_root,
            root_auth_descriptor_digest,
            signer_identity_digest,
        })?;
        Ok(RootAuthMaterial {
            critical_metadata_digest,
            index_digest,
            fec_layout_digest,
            data_block_merkle_root,
            signer_identity_digest,
            archive_root,
            total_data_block_count,
        })
    }

    fn root_auth_fec_layout_rows(
        &self,
        shards: &[IndexShard],
    ) -> Result<Vec<FecLayoutObjectRow>, FormatError> {
        let mut rows = Vec::new();
        rows.push(FecLayoutObjectRow {
            object_class: 1,
            present: true,
            object_id: 0,
            first_block_index: self.manifest_footer.index_root_first_block,
            data_block_count: self.manifest_footer.index_root_data_block_count,
            parity_block_count: self.manifest_footer.index_root_parity_block_count,
            encrypted_size: self.manifest_footer.index_root_encrypted_size,
            plain_size: self.manifest_footer.index_root_decompressed_size,
        });
        if self.crypto_header.has_dictionary != 0 {
            rows.push(FecLayoutObjectRow {
                object_class: 2,
                present: true,
                object_id: 0,
                first_block_index: self.index_root.header.dictionary_first_block,
                data_block_count: self.index_root.header.dictionary_data_block_count,
                parity_block_count: self.index_root.header.dictionary_parity_block_count,
                encrypted_size: self.index_root.header.dictionary_encrypted_size,
                plain_size: self.index_root.header.dictionary_decompressed_size,
            });
        } else {
            rows.push(FecLayoutObjectRow {
                object_class: 2,
                present: false,
                object_id: 0,
                first_block_index: 0,
                data_block_count: 0,
                parity_block_count: 0,
                encrypted_size: 0,
                plain_size: 0,
            });
        }
        for entry in &self.index_root.shards {
            rows.push(FecLayoutObjectRow {
                object_class: 3,
                present: true,
                object_id: entry.shard_index,
                first_block_index: entry.first_block_index,
                data_block_count: entry.data_block_count,
                parity_block_count: entry.parity_block_count,
                encrypted_size: entry.encrypted_size,
                plain_size: entry.decompressed_size,
            });
        }
        let mut envelopes = BTreeMap::<u64, EnvelopeEntry>::new();
        for shard in shards {
            for envelope in &shard.envelopes {
                if let Some(existing) = envelopes.insert(envelope.envelope_index, envelope.clone())
                {
                    if existing != *envelope {
                        return Err(FormatError::InvalidArchive(
                            "duplicate EnvelopeEntry rows do not match",
                        ));
                    }
                }
            }
        }
        for envelope in envelopes.values() {
            rows.push(FecLayoutObjectRow {
                object_class: 4,
                present: true,
                object_id: envelope.envelope_index,
                first_block_index: envelope.first_block_index,
                data_block_count: envelope.data_block_count,
                parity_block_count: envelope.parity_block_count,
                encrypted_size: envelope.encrypted_size,
                plain_size: envelope.plaintext_size,
            });
        }
        for entry in &self.index_root.directory_hint_shards {
            rows.push(FecLayoutObjectRow {
                object_class: 5,
                present: true,
                object_id: entry.hint_shard_index,
                first_block_index: entry.first_block_index,
                data_block_count: entry.data_block_count,
                parity_block_count: entry.parity_block_count,
                encrypted_size: entry.encrypted_size,
                plain_size: entry.decompressed_size,
            });
        }
        Ok(rows)
    }

    fn fec_object_class_shape(
        &self,
        object_class: u8,
    ) -> Result<(BlockKind, BlockKind, u16, u16), FormatError> {
        match object_class {
            1 => Ok((
                BlockKind::IndexRootData,
                BlockKind::IndexRootParity,
                self.crypto_header.index_root_fec_data_shards,
                self.crypto_header.index_root_fec_parity_shards,
            )),
            2 => Ok((
                BlockKind::DictionaryData,
                BlockKind::DictionaryParity,
                self.crypto_header.index_root_fec_data_shards,
                self.crypto_header.index_root_fec_parity_shards,
            )),
            3 => Ok((
                BlockKind::IndexShardData,
                BlockKind::IndexShardParity,
                self.crypto_header.index_fec_data_shards,
                self.crypto_header.index_fec_parity_shards,
            )),
            4 => Ok((
                BlockKind::PayloadData,
                BlockKind::PayloadParity,
                self.crypto_header.fec_data_shards,
                self.crypto_header.fec_parity_shards,
            )),
            5 => Ok((
                BlockKind::DirectoryHintData,
                BlockKind::DirectoryHintParity,
                self.crypto_header.index_fec_data_shards,
                self.crypto_header.index_fec_parity_shards,
            )),
            _ => Err(FormatError::InvalidArchive(
                "unknown root-auth FEC row class",
            )),
        }
    }

    fn root_auth_data_block_leaves(
        &self,
        rows: &[FecLayoutObjectRow],
    ) -> Result<Vec<DataBlockMerkleLeaf>, FormatError> {
        let block_provider = self.block_provider();
        let present_rows = rows.iter().filter(|row| row.present).collect::<Vec<_>>();
        let chunks = parallel_map_ref(&present_rows, self.options.jobs, |row| {
            let row = **row;
            let (data_kind, parity_kind, data_max, parity_max) =
                self.fec_object_class_shape(row.object_class)?;
            let extent = ObjectExtent {
                first_block_index: row.first_block_index,
                data_block_count: row.data_block_count,
                parity_block_count: row.parity_block_count,
                encrypted_size: row.encrypted_size,
            };
            let repaired = load_repaired_object_data_shards_from_parts(
                &block_provider,
                &self.crypto_header,
                extent,
                data_kind,
                parity_kind,
                data_max,
                parity_max,
            )?;
            let mut leaves = Vec::new();
            for (offset, payload) in repaired.into_iter().enumerate() {
                leaves.push(DataBlockMerkleLeaf {
                    block_index: checked_u64_add(
                        row.first_block_index,
                        offset as u64,
                        "root-auth data block",
                    )?,
                    kind: data_kind,
                    flags: if offset + 1 == row.data_block_count as usize {
                        0x01
                    } else {
                        0
                    },
                    payload,
                });
            }
            Ok(leaves)
        })?;
        let mut leaves = Vec::new();
        for mut chunk in chunks {
            leaves.append(&mut chunk);
        }
        leaves.sort_by_key(|leaf| leaf.block_index);
        Ok(leaves)
    }

    fn validate_total_extraction_size(&self, logical_size: u64) -> Result<(), FormatError> {
        let cap = total_extraction_size_cap(self.options, self.observed_archive_bytes);
        if logical_size > cap {
            return Err(FormatError::ReaderUnsupported(
                "total extraction size exceeds configured cap",
            ));
        }
        Ok(())
    }

    fn decompress_payload_frame(
        &self,
        compressed: &[u8],
        decompressed_size: u32,
    ) -> Result<Vec<u8>, FormatError> {
        let mut decompressor = self.new_payload_decompressor()?;
        self.decompress_payload_frame_with(&mut decompressor, compressed, decompressed_size)
    }

    fn new_payload_decompressor(&self) -> Result<zstd::bulk::Decompressor<'static>, FormatError> {
        match &self.payload_dictionary {
            Some(dictionary) => zstd::bulk::Decompressor::with_dictionary(dictionary),
            None => zstd::bulk::Decompressor::new(),
        }
        .map_err(|_| FormatError::ZstdDecompressionFailure)
    }

    fn decompress_payload_frame_with(
        &self,
        decompressor: &mut zstd::bulk::Decompressor<'static>,
        compressed: &[u8],
        decompressed_size: u32,
    ) -> Result<Vec<u8>, FormatError> {
        validate_exact_zstd_frame(compressed)?;
        let expected = decompressed_size as usize;
        let decoded = decompressor
            .decompress(compressed, expected)
            .map_err(|_| FormatError::ZstdDecompressionFailure)?;
        if decoded.len() != expected {
            return Err(FormatError::ZstdDecompressedSizeMismatch {
                expected,
                actual: decoded.len(),
            });
        }
        Ok(decoded)
    }

    fn validate_encrypted_object_block_ranges(
        &self,
        envelopes: &BTreeMap<u64, EnvelopeEntry>,
    ) -> Result<(), FormatError> {
        let mut ranges = Vec::new();
        ranges.push(object_block_range(
            self.manifest_footer.index_root_first_block,
            self.manifest_footer.index_root_data_block_count,
            self.manifest_footer.index_root_parity_block_count,
            "IndexRoot",
        )?);
        for shard in &self.index_root.shards {
            ranges.push(object_block_range(
                shard.first_block_index,
                shard.data_block_count,
                shard.parity_block_count,
                "IndexShard",
            )?);
        }
        for hint in &self.index_root.directory_hint_shards {
            ranges.push(object_block_range(
                hint.first_block_index,
                hint.data_block_count,
                hint.parity_block_count,
                "DirectoryHintShardEntry",
            )?);
        }
        if self.crypto_header.has_dictionary != 0 {
            ranges.push(object_block_range(
                self.index_root.header.dictionary_first_block,
                self.index_root.header.dictionary_data_block_count,
                self.index_root.header.dictionary_parity_block_count,
                "dictionary",
            )?);
        }
        for envelope in envelopes.values() {
            ranges.push(object_block_range(
                envelope.first_block_index,
                envelope.data_block_count,
                envelope.parity_block_count,
                "EnvelopeEntry",
            )?);
        }
        validate_non_overlapping_object_ranges(&mut ranges)?;
        if let Some(source) = &self.lazy_blocks {
            if source.is_complete_volume_set() {
                validate_exact_coverage_ranges_u64(
                    &mut ranges,
                    source.total_block_count()?,
                    "encrypted object block ranges do not cover complete archive exactly",
                )?;
            }
        }
        Ok(())
    }
}

impl<'a> DecodedTarMemberGroupReader<'a> {
    fn new(
        archive: &'a OpenedArchive,
        shard: &'a IndexShard,
        file: &'a FileEntry,
    ) -> Result<Self, FormatError> {
        Ok(Self {
            archive,
            shard,
            file,
            decompressor: archive.new_payload_decompressor()?,
            next_frame_offset: 0,
            cached_envelope_index: None,
            cached_envelope_plaintext: Vec::new(),
            current_frame: Vec::new(),
            current_frame_offset: 0,
            remaining_group_bytes: file.tar_member_group_size,
        })
    }

    fn ensure_frame_available(&mut self) -> Result<(), ExtractError> {
        while self.current_frame_offset >= self.current_frame.len() {
            if self.next_frame_offset >= self.file.frame_count as u64 {
                return Err(
                    FormatError::InvalidArchive("tar member group exceeds frame range").into(),
                );
            }
            let frame_index = self
                .file
                .first_frame_index
                .checked_add(self.next_frame_offset)
                .ok_or(FormatError::InvalidArchive(
                    "FileEntry frame range overflow",
                ))?;
            let frame = frame_by_index(self.shard, frame_index)?;
            let envelope = envelope_by_index(self.shard, frame.envelope_index)?;
            if self.cached_envelope_index != Some(envelope.envelope_index) {
                self.cached_envelope_plaintext = self
                    .archive
                    .load_payload_envelope(envelope, ParityReadPolicy::RepairOnly)?;
                self.cached_envelope_index = Some(envelope.envelope_index);
            }
            let compressed = slice(
                &self.cached_envelope_plaintext,
                frame.offset_in_envelope as usize,
                frame.compressed_size as usize,
                "FrameEntry",
            )?;
            let decoded = self.archive.decompress_payload_frame_with(
                &mut self.decompressor,
                compressed,
                frame.decompressed_size,
            )?;
            let offset = if self.next_frame_offset == 0 {
                self.file.offset_in_first_frame_plaintext as usize
            } else {
                0
            };
            if offset > decoded.len() {
                return Err(FormatError::InvalidArchive(
                    "offset in first frame is outside the first referenced frame",
                )
                .into());
            }
            self.next_frame_offset += 1;
            self.current_frame = decoded;
            self.current_frame_offset = offset;
        }
        Ok(())
    }
}

impl TarMemberGroupReader for DecodedTarMemberGroupReader<'_> {
    fn read_some_member_bytes(&mut self, buf: &mut [u8]) -> Result<usize, ExtractError> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.remaining_group_bytes == 0 {
            return Ok(0);
        }
        self.ensure_frame_available()?;
        let available = self.current_frame.len() - self.current_frame_offset;
        let len = available
            .min(buf.len())
            .min(to_usize(self.remaining_group_bytes, "FileEntry")?);
        if len == 0 {
            return Err(FormatError::InvalidArchive("tar member group exceeds frame range").into());
        }
        buf[..len].copy_from_slice(
            &self.current_frame[self.current_frame_offset..self.current_frame_offset + len],
        );
        self.current_frame_offset += len;
        self.remaining_group_bytes -= len as u64;
        Ok(len)
    }
}

pub(crate) fn frame_by_index(
    shard: &IndexShard,
    frame_index: u64,
) -> Result<&FrameEntry, FormatError> {
    shard
        .frames
        .binary_search_by_key(&frame_index, |entry| entry.frame_index)
        .map(|idx| &shard.frames[idx])
        .map_err(|_| FormatError::InvalidArchive("FileEntry references missing FrameEntry"))
}

pub(crate) fn envelope_by_index(
    shard: &IndexShard,
    envelope_index: u64,
) -> Result<&EnvelopeEntry, FormatError> {
    shard
        .envelopes
        .binary_search_by_key(&envelope_index, |entry| entry.envelope_index)
        .map(|idx| &shard.envelopes[idx])
        .map_err(|_| FormatError::InvalidArchive("FrameEntry references missing EnvelopeEntry"))
}

pub(crate) fn format_error_from_extract_error(err: ExtractError) -> FormatError {
    match err {
        ExtractError::Format(err) => err,
        ExtractError::Output(_) => {
            FormatError::FilesystemExtractionFailed("failed to write regular file")
        }
    }
}

pub(crate) fn final_index_entry_winners(
    shards: &[IndexShard],
) -> Result<BTreeMap<String, WinningIndexEntry>, FormatError> {
    let mut final_entries = BTreeMap::<String, WinningIndexEntry>::new();
    for (shard_index, shard) in shards.iter().enumerate() {
        for (idx, file) in shard.files.iter().enumerate() {
            let path = utf8_path(
                shard
                    .file_path(idx)
                    .ok_or(FormatError::InvalidArchive("FileEntry path is missing"))?,
            )?;
            let start = shard
                .tar_member_group_start(idx)
                .ok_or(FormatError::InvalidArchive(
                    "FileEntry tar member start is missing",
                ))?;
            if let Some(winner) = final_entries.get_mut(&path) {
                if start >= winner.start {
                    winner.start = start;
                    winner.file_data_size = file.file_data_size;
                    winner.shard_index = shard_index;
                    winner.file_index = idx;
                }
            } else {
                final_entries.insert(
                    path,
                    WinningIndexEntry {
                        start,
                        file_data_size: file.file_data_size,
                        shard_index,
                        file_index: idx,
                    },
                );
            }
        }
    }
    Ok(final_entries)
}

pub(crate) fn archive_index_entry_from_loaded_file(
    shard: &IndexShard,
    file_index: usize,
) -> Result<ArchiveIndexEntry, FormatError> {
    let path = utf8_path(
        shard
            .file_path(file_index)
            .ok_or(FormatError::InvalidArchive("FileEntry path is missing"))?,
    )?;
    archive_index_entry_from_loaded_file_with_path(path, shard, file_index)
}

pub(crate) fn archive_index_entry_from_loaded_file_with_path(
    path: String,
    shard: &IndexShard,
    file_index: usize,
) -> Result<ArchiveIndexEntry, FormatError> {
    let file = shard
        .files
        .get(file_index)
        .ok_or(FormatError::InvalidArchive("FileEntry index out of bounds"))?;
    let layout = archive_index_entry_layout(shard, file)?;

    let resolve_string = |offset: u32, len: u32| -> Result<Option<String>, FormatError> {
        if len == 0 {
            return Ok(None);
        }
        let end = offset
            .checked_add(len)
            .ok_or(FormatError::InvalidArchive("String pool offset overflow"))?;
        let bytes = shard
            .string_pool
            .get(offset as usize..end as usize)
            .ok_or(FormatError::InvalidArchive("String pool out of bounds"))?;
        Ok(Some(String::from_utf8(bytes.to_vec()).map_err(|_| {
            FormatError::InvalidArchive("Invalid UTF-8 in string pool")
        })?))
    };

    Ok(ArchiveIndexEntry {
        name: archive_entry_name(&path),
        path,
        file_data_size: file.file_data_size,
        flags: file.flags,
        path_hash: file.path_hash,
        tar_member_group_size: file.tar_member_group_size,
        first_frame_index: file.first_frame_index,
        frame_count: file.frame_count,
        offset_in_first_frame_plaintext: file.offset_in_first_frame_plaintext,
        layout,
        kind: TarEntryKind::from_u8(file.kind),
        mtime: ArchiveTimestamp::new(file.mtime_sec, file.mtime_nsec),
        created: if (file.metadata_flags & 1) != 0 {
            Some(ArchiveTimestamp::new(file.created_sec, file.created_nsec))
        } else {
            None
        },
        accessed: if (file.metadata_flags & 2) != 0 {
            Some(ArchiveTimestamp::new(file.accessed_sec, file.accessed_nsec))
        } else {
            None
        },
        mode: file.mode,
        attributes: if (file.metadata_flags & 4) != 0 {
            Some(file.attributes)
        } else {
            None
        },
        uid: if file.uid == u64::MAX {
            None
        } else {
            Some(file.uid)
        },
        gid: if file.gid == u64::MAX {
            None
        } else {
            Some(file.gid)
        },
        uname: resolve_string(file.uname_offset, file.uname_length)?,
        gname: resolve_string(file.gname_offset, file.gname_length)?,
        link_target: resolve_string(file.link_target_offset, file.link_target_length)?,
    })
}

pub(crate) fn archive_index_entry_layout(
    shard: &IndexShard,
    file: &FileEntry,
) -> Result<ArchiveIndexEntryLayout, FormatError> {
    let frames = frame_range_for_file(shard, file)?;
    if let [frame] = frames {
        let envelope = envelope_by_index(shard, frame.envelope_index)?;
        return Ok(ArchiveIndexEntryLayout {
            compressed_size: frame.compressed_size as u64,
            decompressed_frame_size: frame.decompressed_size as u64,
            envelope_count: 1,
            first_envelope_index: Some(envelope.envelope_index),
            last_envelope_index: Some(envelope.envelope_index),
            first_payload_block_index: Some(envelope.first_block_index),
            payload_data_block_count: envelope.data_block_count as u64,
            payload_parity_block_count: envelope.parity_block_count as u64,
            payload_encrypted_size: envelope.encrypted_size as u64,
        });
    }

    let mut compressed_size = 0u64;
    let mut decompressed_frame_size = 0u64;
    let mut envelope_indexes = BTreeSet::new();

    for frame in frames {
        compressed_size = checked_u64_add(
            compressed_size,
            frame.compressed_size as u64,
            "ArchiveIndexEntry.compressed_size",
        )?;
        decompressed_frame_size = checked_u64_add(
            decompressed_frame_size,
            frame.decompressed_size as u64,
            "ArchiveIndexEntry.decompressed_frame_size",
        )?;
        envelope_indexes.insert(frame.envelope_index);
    }

    let mut first_payload_block_index = None::<u64>;
    let mut payload_data_block_count = 0u64;
    let mut payload_parity_block_count = 0u64;
    let mut payload_encrypted_size = 0u64;

    for envelope_index in &envelope_indexes {
        let envelope = envelope_by_index(shard, *envelope_index)?;
        first_payload_block_index = Some(
            first_payload_block_index
                .map(|existing| existing.min(envelope.first_block_index))
                .unwrap_or(envelope.first_block_index),
        );
        payload_data_block_count = checked_u64_add(
            payload_data_block_count,
            envelope.data_block_count as u64,
            "ArchiveIndexEntry.payload_data_block_count",
        )?;
        payload_parity_block_count = checked_u64_add(
            payload_parity_block_count,
            envelope.parity_block_count as u64,
            "ArchiveIndexEntry.payload_parity_block_count",
        )?;
        payload_encrypted_size = checked_u64_add(
            payload_encrypted_size,
            envelope.encrypted_size as u64,
            "ArchiveIndexEntry.payload_encrypted_size",
        )?;
    }

    Ok(ArchiveIndexEntryLayout {
        compressed_size,
        decompressed_frame_size,
        envelope_count: u32::try_from(envelope_indexes.len()).map_err(|_| {
            FormatError::InvalidArchive("ArchiveIndexEntry envelope count overflow")
        })?,
        first_envelope_index: envelope_indexes.iter().next().copied(),
        last_envelope_index: envelope_indexes.iter().next_back().copied(),
        first_payload_block_index,
        payload_data_block_count,
        payload_parity_block_count,
        payload_encrypted_size,
    })
}

pub(crate) fn archive_entry_name(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_owned()
}
