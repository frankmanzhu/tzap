use std::collections::{hash_map::Entry, BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::io::{Read, Write};
use std::sync::Arc;
use std::thread;

use sha2::{Digest, Sha256};

use crate::compression::{decompress_exact_zstd_frame, validate_exact_zstd_frame};
use crate::crypto::{
    decrypt_padded_aead_object, verify_integrity_tag, AeadObjectContext, HmacDomain, KdfParams,
    MasterKey, Subkeys,
};
use crate::entry_metadata::ArchiveTimestamp;
use crate::fec::{encode_parity_gf16, repair_data_gf16};
use crate::format::{
    AeadAlgo, BlockKind, ExtractError, FormatError, KdfAlgo, VolumeFormatRevision,
    BLOCK_RECORD_FRAMING_LEN, BOOTSTRAP_SIDECAR_HEADER_LEN, CRITICAL_METADATA_IMAGE_FIXED_LEN,
    CRITICAL_METADATA_RECOVERY_HEADER_LEN, CRITICAL_METADATA_RECOVERY_SHARD_HEADER_LEN,
    CRITICAL_RECOVERY_LOCATOR_LEN, CRYPTO_HEADER_HMAC_LEN, IMAGE_CRC_LEN, LOCATOR_PAIR_LEN,
    MANIFEST_FOOTER_LEN, MASTER_KEY_LEN, READER_MAX_CMRA_PARITY_PCT, READER_MAX_CRYPTO_HEADER_LEN,
    READER_MAX_KEY_WRAP_TABLE_LEN, READER_MAX_ROOT_AUTH_FOOTER_LEN, SERIALIZED_REGION_HEADER_LEN,
    VOLUME_FORMAT_REV_45, VOLUME_HEADER_LEN, VOLUME_TRAILER_LEN,
};
use crate::metadata::{
    hash_prefix, normalize_lookup_file_path, DirectoryHintShardEntry, DirectoryHintTable,
    EnvelopeEntry, FileEntry, FrameEntry, IndexRoot, IndexShard, MetadataLimits, ShardEntry,
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
    stream_regular_tar_member_group_to_writer, validate_owned_restore_plan,
    validate_tar_stream_total_extraction_size, MetadataDiagnostic, MetadataVerificationReport,
    NoopTarStreamObserver, OwnedTarMember, SafeExtractionOptions, StreamingMemberExpectation,
    TarEntryKind, TarMemberGroupReader, TarStreamFilesystemRestoreObserver, TarStreamObserver,
    TarStreamSummaryValidator, TarStreamTotalExtractionSizeValidator,
};
use crate::wire::{
    compute_key_wrap_table_digest, BlockRecord, BootstrapSidecarHeader, CriticalMetadataImage,
    CriticalMetadataRecoveryHeader, CriticalMetadataRecoveryShard, CriticalRecoveryLocator,
    CryptoHeader, CryptoHeaderFixed, ExtensionTlv, KeyWrapTableV1, ManifestFooter,
    RootAuthFooterV1, VolumeHeader, VolumeTrailer,
};

const TRAILER_HMAC_COVERED_LEN: usize = 96;
const MANIFEST_HMAC_COVERED_LEN: usize = 104;
const SIDECAR_HMAC_COVERED_LEN: usize = 92;
const DEFAULT_MAX_VERIFY_TAR_SIZE: usize = 128 * 1024 * 1024;
const DEFAULT_MAX_TRAILING_GARBAGE_SCAN: usize = 1024 * 1024;
const DEFAULT_MAX_TOTAL_EXTRACTION_SIZE: u64 = 100 * 1024 * 1024 * 1024;
const DIRECTORY_HINT_REQUIRED_FILE_COUNT: u64 = 100_000;

fn default_jobs() -> usize {
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
fn file_read_exact_at(file: &File, offset: u64, buf: &mut [u8]) -> Result<(), FormatError> {
    use std::os::unix::fs::FileExt;

    file_read_exact_at_with(offset, buf, |chunk, offset| file.read_at(chunk, offset))
}

#[cfg(windows)]
fn file_read_exact_at(file: &File, offset: u64, buf: &mut [u8]) -> Result<(), FormatError> {
    use std::os::windows::fs::FileExt;

    file_read_exact_at_with(offset, buf, |chunk, offset| file.seek_read(chunk, offset))
}

#[cfg(any(unix, windows))]
fn file_read_exact_at_with<F>(
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
fn file_read_exact_at(file: &File, offset: u64, buf: &mut [u8]) -> Result<(), FormatError> {
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

fn pax_timestamp(
    records: &crate::entry_metadata::PaxRecords,
    key: &str,
) -> Option<ArchiveTimestamp> {
    let bytes = records.get(key)?;
    let (sec, nsec) = crate::entry_metadata::parse_timestamp(bytes).ok()?;
    Some(ArchiveTimestamp::new(sec, nsec))
}

fn exposed_file_attributes(
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
enum ContentVerificationMode {
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
struct RootAuthMaterial {
    critical_metadata_digest: [u8; 32],
    index_digest: [u8; 32],
    fec_layout_digest: [u8; 32],
    data_block_merkle_root: [u8; 32],
    signer_identity_digest: [u8; 32],
    archive_root: [u8; 32],
    total_data_block_count: u64,
}

#[derive(Debug, Clone, Copy)]
struct ObjectExtent {
    first_block_index: u64,
    data_block_count: u32,
    parity_block_count: u32,
    encrypted_size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParityReadPolicy {
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
struct WinningIndexEntry {
    start: u64,
    file_data_size: u64,
    shard_index: usize,
    file_index: usize,
}

struct LocatedIndexFile {
    shard: IndexShard,
    file_index: usize,
    start: u64,
}

struct ExtractProgressWriter<'a, W> {
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

struct DecodedTarMemberGroupReader<'a> {
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

struct SeekableVolumeSource {
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
struct SeekableBlockSource {
    stripe_width: u32,
    volumes: Vec<Option<SeekableVolumeSource>>,
}

trait BlockProvider {
    fn block(&self, block_index: u64) -> Result<Option<BlockRecord>, FormatError>;
}

struct OpenedBlockProvider<'a> {
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

fn subkeys_for_open(
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
const FAST_FULL_EXTRACT_UNIQUE_PATHS_UNSUPPORTED: &str =
    "fast full extract requires unique archive paths";

fn parse_volume_format_dispatch(
    volume_header: &VolumeHeader,
) -> Result<VolumeFormatRevision, FormatError> {
    let revision = volume_header.parse_volume_format_revision()?;
    match revision {
        VolumeFormatRevision::V45 => Ok(revision),
    }
}

#[derive(Debug)]
struct PayloadIndexTables {
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

fn require_unencrypted_volume_profile(bytes: &[u8]) -> Result<(), FormatError> {
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
                    "no authenticated ManifestFooter found",
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
                    FormatError::InvalidArchive("no authenticated ManifestFooter found"),
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
            None => FormatError::InvalidArchive("no authenticated ManifestFooter found"),
        })?;
        let authority_volume_header = manifest_authority_volume_header.ok_or(
            FormatError::InvalidArchive("no authenticated ManifestFooter found"),
        )?;
        let authority_volume_trailer = manifest_authority_volume_trailer.ok_or(
            FormatError::InvalidArchive("no authenticated ManifestFooter found"),
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
            None => FormatError::InvalidArchive("no authenticated ManifestFooter found"),
        })?;
        let authority_volume_header = manifest_authority_volume_header.ok_or(
            FormatError::InvalidArchive("no authenticated ManifestFooter found"),
        )?;
        let authority_volume_trailer = manifest_authority_volume_trailer.ok_or(
            FormatError::InvalidArchive("no authenticated ManifestFooter found"),
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
            None => FormatError::InvalidArchive("no authenticated ManifestFooter found"),
        })?;
        let authority_volume_header = manifest_authority_volume_header.ok_or(
            FormatError::InvalidArchive("no authenticated ManifestFooter found"),
        )?;
        let authority_volume_trailer = manifest_authority_volume_trailer.ok_or(
            FormatError::InvalidArchive("no authenticated ManifestFooter found"),
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

fn frame_by_index(shard: &IndexShard, frame_index: u64) -> Result<&FrameEntry, FormatError> {
    shard
        .frames
        .binary_search_by_key(&frame_index, |entry| entry.frame_index)
        .map(|idx| &shard.frames[idx])
        .map_err(|_| FormatError::InvalidArchive("FileEntry references missing FrameEntry"))
}

fn envelope_by_index(
    shard: &IndexShard,
    envelope_index: u64,
) -> Result<&EnvelopeEntry, FormatError> {
    shard
        .envelopes
        .binary_search_by_key(&envelope_index, |entry| entry.envelope_index)
        .map(|idx| &shard.envelopes[idx])
        .map_err(|_| FormatError::InvalidArchive("FrameEntry references missing EnvelopeEntry"))
}

fn format_error_from_extract_error(err: ExtractError) -> FormatError {
    match err {
        ExtractError::Format(err) => err,
        ExtractError::Output(_) => {
            FormatError::FilesystemExtractionFailed("failed to write regular file")
        }
    }
}

fn final_index_entry_winners(
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

fn archive_index_entry_from_loaded_file(
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

fn archive_index_entry_from_loaded_file_with_path(
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

fn archive_index_entry_layout(
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

fn archive_entry_name(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_owned()
}

#[derive(Debug)]
struct ParsedSeekableVolume {
    volume_header: VolumeHeader,
    crypto_header: CryptoHeaderFixed,
    crypto_header_bytes: Vec<u8>,
    key_wrap_table_bytes: Option<Vec<u8>>,
    subkeys: Subkeys,
    manifest_footer: Option<ManifestFooter>,
    manifest_footer_error: Option<FormatError>,
    root_auth_footer: Option<RootAuthFooterV1>,
    root_auth_footer_bytes: Option<Vec<u8>>,
    volume_trailer: VolumeTrailer,
    blocks: BTreeMap<u64, BlockRecord>,
    erased_block_indices: BTreeSet<u64>,
}

struct ParsedSeekableReadAtVolume {
    reader: Arc<dyn ArchiveReadAt>,
    volume_header: VolumeHeader,
    crypto_header: CryptoHeaderFixed,
    crypto_header_bytes: Vec<u8>,
    key_wrap_table_bytes: Option<Vec<u8>>,
    subkeys: Subkeys,
    manifest_footer: Option<ManifestFooter>,
    manifest_footer_error: Option<FormatError>,
    root_auth_footer: Option<RootAuthFooterV1>,
    root_auth_footer_bytes: Option<Vec<u8>>,
    volume_trailer: VolumeTrailer,
    block_records_start: u64,
}

struct ParsedOpenPrefix {
    volume_header: VolumeHeader,
    crypto_header: CryptoHeaderFixed,
    crypto_header_bytes: Vec<u8>,
    key_wrap_table_bytes: Option<Vec<u8>>,
    block_records_start: u64,
    subkeys: Subkeys,
}

struct ParsedReadAtOpenPrefix {
    volume_header: VolumeHeader,
    crypto_header: CryptoHeaderFixed,
    crypto_header_bytes: Vec<u8>,
    key_wrap_table_bytes: Option<Vec<u8>>,
    block_records_start: u64,
    subkeys: Subkeys,
}

pub(crate) struct StartupKeyWrapTable {
    pub(crate) table: KeyWrapTableV1,
    pub(crate) bytes: Vec<u8>,
    pub(crate) block_records_start: u64,
}

pub(crate) fn startup_block_records_start(
    volume_header: &VolumeHeader,
    kdf_params: &KdfParams,
    read_key_wrap_table: impl FnMut(u64, usize) -> Result<Vec<u8>, FormatError>,
) -> Result<u64, FormatError> {
    Ok(
        startup_key_wrap_table(volume_header, kdf_params, read_key_wrap_table)?
            .map(|startup| startup.block_records_start)
            .unwrap_or_else(|| {
                volume_header.crypto_header_offset as u64
                    + volume_header.crypto_header_length as u64
            }),
    )
}

pub(crate) fn startup_key_wrap_table(
    volume_header: &VolumeHeader,
    kdf_params: &KdfParams,
    mut read_key_wrap_table: impl FnMut(u64, usize) -> Result<Vec<u8>, FormatError>,
) -> Result<Option<StartupKeyWrapTable>, FormatError> {
    let crypto_end = checked_u64_add(
        volume_header.crypto_header_offset as u64,
        volume_header.crypto_header_length as u64,
        "CryptoHeader",
    )?;
    let &KdfParams::RecipientWrap {
        key_wrap_table_length,
        ..
    } = kdf_params
    else {
        return Ok(None);
    };
    if volume_header.volume_format_rev != VOLUME_FORMAT_REV_45 {
        return Err(FormatError::InvalidArchive(
            "RecipientWrap KdfParams require volume_format_rev 45",
        ));
    }
    let key_wrap_table_length_usize =
        to_usize(u64::from(key_wrap_table_length), "KeyWrapTableV1 length")?;
    let key_wrap_table_bytes = read_key_wrap_table(crypto_end, key_wrap_table_length_usize)?;
    Ok(Some(parse_startup_key_wrap_table_bytes(
        volume_header,
        kdf_params,
        key_wrap_table_bytes,
    )?))
}

pub(crate) fn parse_startup_key_wrap_table_bytes(
    volume_header: &VolumeHeader,
    kdf_params: &KdfParams,
    key_wrap_table_bytes: Vec<u8>,
) -> Result<StartupKeyWrapTable, FormatError> {
    let crypto_end = checked_u64_add(
        volume_header.crypto_header_offset as u64,
        volume_header.crypto_header_length as u64,
        "CryptoHeader",
    )?;
    let KdfParams::RecipientWrap {
        key_wrap_table_length,
        key_wrap_table_record_count,
        key_wrap_table_digest,
        ..
    } = kdf_params
    else {
        return Err(FormatError::KeyMaterialMismatch);
    };
    let key_wrap_table = KeyWrapTableV1::parse(
        &key_wrap_table_bytes,
        &volume_header.archive_uuid,
        &volume_header.session_id,
        *key_wrap_table_length,
        *key_wrap_table_record_count,
    )?;
    if compute_key_wrap_table_digest(*key_wrap_table_length, &key_wrap_table_bytes)
        != *key_wrap_table_digest
    {
        return Err(FormatError::IntegrityDigestMismatch {
            structure: "KeyWrapTableV1",
        });
    }
    let block_records_start = checked_u64_add(
        crypto_end,
        key_wrap_table.table_length as u64,
        "KeyWrapTableV1",
    )?;
    Ok(StartupKeyWrapTable {
        table: key_wrap_table,
        bytes: key_wrap_table_bytes,
        block_records_start,
    })
}

fn parse_seekable_volume(
    bytes: &[u8],
    master_key: &MasterKey,
    options: ReaderOptions,
) -> Result<ParsedSeekableVolume, FormatError> {
    if bytes.len() < VOLUME_HEADER_LEN + VOLUME_TRAILER_LEN {
        return Err(FormatError::InvalidLength {
            structure: "archive",
            expected: VOLUME_HEADER_LEN + VOLUME_TRAILER_LEN,
            actual: bytes.len(),
        });
    }

    let prefix = match parse_open_prefix(bytes, master_key) {
        Ok(prefix) => prefix,
        Err(prefix_err) => {
            if matches!(
                prefix_err,
                FormatError::UnsupportedVolumeFormatRevision { .. }
            ) {
                return Err(prefix_err);
            }
            if matches!(prefix_err, FormatError::KeyMaterialMismatch)
                && prefix_uses_recipient_wrap(bytes)
            {
                return Err(prefix_err);
            }
            return parse_seekable_volume_from_recovered_terminal(bytes, master_key, options)
                .or(Err(prefix_err));
        }
    };
    let physical_crypto_header_bytes = prefix.crypto_header_bytes.clone();
    match parse_seekable_volume_with_prefix(bytes, prefix, options) {
        Ok(parsed) => Ok(parsed),
        Err(prefix_err) => {
            match parse_seekable_volume_from_recovered_terminal(bytes, master_key, options) {
                Ok(recovered) if recovered.crypto_header_bytes == physical_crypto_header_bytes => {
                    Ok(recovered)
                }
                Ok(_) | Err(_) => Err(prefix_err),
            }
        }
    }
}

fn parse_seekable_volume_with_recipient_wrap_resolver<F>(
    bytes: &[u8],
    resolver: &mut F,
    options: ReaderOptions,
) -> Result<ParsedSeekableVolume, FormatError>
where
    F: FnMut(
        RecipientWrapRecordContext<'_>,
    ) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
{
    let prefix = match parse_open_prefix_with_recipient_wrap_resolver(bytes, resolver) {
        Ok(prefix) => prefix,
        Err(prefix_err) => {
            if recipient_wrap_prefix_error_precludes_recovery(&prefix_err) {
                return Err(prefix_err);
            }
            return parse_seekable_volume_with_recipient_wrap_resolver_from_recovered_terminal(
                bytes, resolver, options,
            )
            .or(Err(prefix_err));
        }
    };
    let physical_crypto_header_bytes = prefix.crypto_header_bytes.clone();
    match parse_seekable_volume_with_prefix(bytes, prefix, options) {
        Ok(parsed) => Ok(parsed),
        Err(prefix_err) => {
            match parse_seekable_volume_with_recipient_wrap_resolver_from_recovered_terminal(
                bytes, resolver, options,
            ) {
                Ok(recovered) if recovered.crypto_header_bytes == physical_crypto_header_bytes => {
                    Ok(recovered)
                }
                Ok(_) | Err(_) => Err(prefix_err),
            }
        }
    }
}

fn parse_seekable_volume_with_prefix(
    bytes: &[u8],
    prefix: ParsedOpenPrefix,
    options: ReaderOptions,
) -> Result<ParsedSeekableVolume, FormatError> {
    let ParsedOpenPrefix {
        volume_header,
        crypto_header,
        crypto_header_bytes,
        key_wrap_table_bytes,
        block_records_start,
        subkeys,
    } = prefix;
    let crypto_bytes = crypto_header_bytes.as_slice();

    let terminal = locate_v41_terminal(
        bytes,
        KeyHoldingTerminalContext {
            subkeys: &subkeys,
            volume_header: &volume_header,
            crypto_header: &crypto_header,
            crypto_header_bytes: crypto_bytes,
        },
        options,
    )?;
    finish_parse_seekable_volume(
        bytes,
        volume_header,
        crypto_header,
        crypto_header_bytes,
        key_wrap_table_bytes,
        block_records_start,
        subkeys,
        terminal,
    )
}

fn parse_seekable_volume_from_recovered_terminal(
    bytes: &[u8],
    master_key: &MasterKey,
    options: ReaderOptions,
) -> Result<ParsedSeekableVolume, FormatError> {
    let authority = locate_v41_terminal_authority(bytes, master_key, options)?;
    parse_volume_format_dispatch(&authority.volume_header)?;
    let startup_key_wrap_table = startup_key_wrap_table(
        &authority.volume_header,
        &authority.kdf_params,
        |start, length| {
            let start = to_usize(start, "KeyWrapTableV1")?;
            Ok(slice(bytes, start, length, "KeyWrapTableV1")?.to_vec())
        },
    )?;
    let crypto_end = checked_u64_add(
        authority.volume_header.crypto_header_offset as u64,
        authority.volume_header.crypto_header_length as u64,
        "CryptoHeader",
    )?;
    let (key_wrap_table_bytes, block_records_start) = startup_key_wrap_table
        .map(|startup| (Some(startup.bytes), startup.block_records_start))
        .unwrap_or((None, crypto_end));
    finish_parse_seekable_volume(
        bytes,
        authority.volume_header,
        authority.crypto_header,
        authority.crypto_header_bytes,
        key_wrap_table_bytes,
        block_records_start,
        authority.subkeys,
        authority.terminal,
    )
}

fn parse_seekable_volume_with_recipient_wrap_resolver_from_recovered_terminal<F>(
    bytes: &[u8],
    resolver: &mut F,
    options: ReaderOptions,
) -> Result<ParsedSeekableVolume, FormatError>
where
    F: FnMut(
        RecipientWrapRecordContext<'_>,
    ) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
{
    let authority = locate_v41_recipient_wrap_terminal_authority(bytes, resolver, options)?;
    finish_parse_seekable_volume(
        bytes,
        authority.volume_header,
        authority.crypto_header,
        authority.crypto_header_bytes,
        Some(authority.key_wrap_table_bytes),
        authority.block_records_start,
        authority.subkeys,
        authority.terminal,
    )
}

fn recipient_wrap_prefix_error_precludes_recovery(error: &FormatError) -> bool {
    matches!(
        error,
        FormatError::UnsupportedVolumeFormatRevision { .. }
            | FormatError::ReaderUnsupported(_)
            | FormatError::InvalidArchive(
                "VolumeHeader and CryptoHeader stripe_width differ"
                    | "fec_parity_shards does not match v41 compute_parity"
                    | "index_fec_parity_shards does not match v41 compute_parity"
                    | "index_root_fec_parity_shards does not match v41 compute_parity"
            )
    )
}

fn parse_open_prefix(
    bytes: &[u8],
    master_key: &MasterKey,
) -> Result<ParsedOpenPrefix, FormatError> {
    let volume_header = VolumeHeader::parse(slice(bytes, 0, VOLUME_HEADER_LEN, "archive")?)?;
    parse_volume_format_dispatch(&volume_header)?;
    let crypto_start = volume_header.crypto_header_offset as usize;
    let crypto_len = volume_header.crypto_header_length as usize;
    let crypto_bytes = slice(bytes, crypto_start, crypto_len, "CryptoHeader")?;
    let parsed_crypto = CryptoHeader::parse(crypto_bytes, volume_header.crypto_header_length)?;
    if matches!(parsed_crypto.kdf_params, KdfParams::RecipientWrap { .. }) {
        return Err(FormatError::KeyMaterialMismatch);
    }
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
    validate_seekable_supported_volume(
        &volume_header,
        &parsed_crypto.fixed,
        &parsed_crypto.extensions,
    )?;
    validate_crypto_class_parity_exactness(&parsed_crypto.fixed)?;
    let block_records_start = startup_block_records_start(
        &volume_header,
        &parsed_crypto.kdf_params,
        |start, length| {
            let start = to_usize(start, "KeyWrapTableV1")?;
            Ok(slice(bytes, start, length, "KeyWrapTableV1")?.to_vec())
        },
    )?;
    let crypto_header = parsed_crypto.fixed.clone();
    Ok(ParsedOpenPrefix {
        volume_header,
        crypto_header,
        crypto_header_bytes: crypto_bytes.to_vec(),
        key_wrap_table_bytes: None,
        block_records_start,
        subkeys,
    })
}

fn prefix_uses_recipient_wrap(bytes: &[u8]) -> bool {
    let Ok(volume_header_bytes) = slice(bytes, 0, VOLUME_HEADER_LEN, "archive") else {
        return false;
    };
    let Ok(volume_header) = VolumeHeader::parse(volume_header_bytes) else {
        return false;
    };
    let crypto_start = volume_header.crypto_header_offset as usize;
    let crypto_len = volume_header.crypto_header_length as usize;
    let Ok(crypto_bytes) = slice(bytes, crypto_start, crypto_len, "CryptoHeader") else {
        return false;
    };
    let Ok(parsed_crypto) = CryptoHeader::parse(crypto_bytes, volume_header.crypto_header_length)
    else {
        return false;
    };
    matches!(parsed_crypto.kdf_params, KdfParams::RecipientWrap { .. })
}

fn parse_open_prefix_with_recipient_wrap_resolver<F>(
    bytes: &[u8],
    resolver: &mut F,
) -> Result<ParsedOpenPrefix, FormatError>
where
    F: FnMut(
        RecipientWrapRecordContext<'_>,
    ) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
{
    let volume_header = VolumeHeader::parse(slice(bytes, 0, VOLUME_HEADER_LEN, "archive")?)?;
    parse_volume_format_dispatch(&volume_header)?;
    let crypto_start = volume_header.crypto_header_offset as usize;
    let crypto_len = volume_header.crypto_header_length as usize;
    let crypto_bytes = slice(bytes, crypto_start, crypto_len, "CryptoHeader")?;
    let parsed_crypto = CryptoHeader::parse(crypto_bytes, volume_header.crypto_header_length)?;
    if !matches!(parsed_crypto.kdf_params, KdfParams::RecipientWrap { .. })
        || !parsed_crypto.fixed.aead_algo.is_encrypted()
    {
        return Err(FormatError::KeyMaterialMismatch);
    }

    validate_seekable_supported_volume(&volume_header, &parsed_crypto.fixed, &[])?;
    validate_crypto_class_parity_exactness(&parsed_crypto.fixed)?;

    let startup_key_wrap_table = startup_key_wrap_table(
        &volume_header,
        &parsed_crypto.kdf_params,
        |start, length| {
            let start = to_usize(start, "KeyWrapTableV1")?;
            Ok(slice(bytes, start, length, "KeyWrapTableV1")?.to_vec())
        },
    )?
    .ok_or(FormatError::KeyMaterialMismatch)?;
    let key_wrap_table = startup_key_wrap_table.table;
    let key_wrap_table_bytes = Some(startup_key_wrap_table.bytes);
    let block_records_start = startup_key_wrap_table.block_records_start;

    let subkeys = recipient_wrap_subkeys_from_table(
        &volume_header,
        &parsed_crypto,
        &key_wrap_table,
        resolver,
    )?;
    parsed_crypto.validate_extension_semantics()?;
    reject_unsupported_raw_stream_profile(&parsed_crypto.extensions)?;

    let crypto_header = parsed_crypto.fixed.clone();
    Ok(ParsedOpenPrefix {
        volume_header,
        crypto_header,
        crypto_header_bytes: crypto_bytes.to_vec(),
        key_wrap_table_bytes,
        block_records_start,
        subkeys,
    })
}

pub(crate) fn recipient_wrap_subkeys_from_table<F>(
    volume_header: &VolumeHeader,
    parsed_crypto: &CryptoHeader<'_>,
    key_wrap_table: &KeyWrapTableV1,
    resolver: &mut F,
) -> Result<Subkeys, FormatError>
where
    F: FnMut(
            RecipientWrapRecordContext<'_>,
        ) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>
        + ?Sized,
{
    let archive_identity = RecipientWrapArchiveIdentity {
        archive_uuid: volume_header.archive_uuid,
        session_id: volume_header.session_id,
        format_version: volume_header.format_version,
        volume_format_rev: volume_header.volume_format_rev,
    };

    for record in &key_wrap_table.recipient_records {
        let candidates = resolver(RecipientWrapRecordContext {
            archive_identity,
            record,
        })?;
        for candidate in candidates {
            let master_key = MasterKey::from_raw_key(&candidate)?;
            let subkeys = subkeys_for_open(
                Some(&master_key),
                parsed_crypto.fixed.aead_algo,
                &volume_header.archive_uuid,
                &volume_header.session_id,
            )?;
            if verify_integrity_tag(
                HmacDomain::CryptoHeader,
                parsed_crypto.fixed.aead_algo,
                volume_header.volume_format_rev,
                Some(&subkeys.mac_key),
                &volume_header.archive_uuid,
                &volume_header.session_id,
                parsed_crypto.hmac_covered_bytes,
                &parsed_crypto.header_hmac,
            )
            .is_ok()
            {
                return Ok(subkeys);
            }
        }
    }
    Err(FormatError::KeyMaterialMismatch)
}

#[allow(clippy::too_many_arguments)]
fn finish_parse_seekable_volume(
    bytes: &[u8],
    volume_header: VolumeHeader,
    crypto_header: CryptoHeaderFixed,
    crypto_header_bytes: Vec<u8>,
    key_wrap_table_bytes: Option<Vec<u8>>,
    block_records_start: u64,
    subkeys: Subkeys,
    terminal: V41Terminal,
) -> Result<ParsedSeekableVolume, FormatError> {
    let trailer_offset = to_usize(terminal.image.volume_trailer_offset, "VolumeTrailer")?;
    let volume_trailer = terminal.volume_trailer.clone();
    validate_trailer_identity(&volume_header, &volume_trailer)?;

    let manifest_offset = to_usize(volume_trailer.manifest_footer_offset, "ManifestFooter")?;
    let manifest_end = checked_add(manifest_offset, MANIFEST_FOOTER_LEN, "ManifestFooter")?;
    if volume_trailer.root_auth_flags & 0x0000_0001 != 0 {
        if to_usize(volume_trailer.root_auth_footer_offset, "RootAuthFooter")? != manifest_end
            || volume_trailer
                .root_auth_footer_offset
                .checked_add(volume_trailer.root_auth_footer_length as u64)
                .ok_or(FormatError::InvalidArchive(
                    "RootAuthFooter terminal boundary overflow",
                ))?
                != trailer_offset as u64
        {
            return Err(FormatError::InvalidArchive(
                "RootAuthFooter does not sit before selected trailer",
            ));
        }
    } else if manifest_end != trailer_offset {
        return Err(FormatError::InvalidArchive(
            "ManifestFooter does not end at selected trailer",
        ));
    }
    let manifest_bytes = &terminal.manifest_footer_bytes;
    let (manifest_footer, manifest_footer_error) =
        match parse_valid_manifest_footer(&volume_header, &crypto_header, &subkeys, manifest_bytes)
        {
            Ok(footer) => (Some(footer), None),
            Err(err) if manifest_footer_copy_error_is_recoverable(&err) => (None, Some(err)),
            Err(err) => return Err(err),
        };

    let block_region = parse_block_region(
        bytes,
        to_usize(block_records_start, "BlockRecord")?,
        manifest_offset,
        crypto_header.block_size as usize,
        &volume_header,
        &volume_trailer,
    )?;

    Ok(ParsedSeekableVolume {
        volume_header,
        crypto_header,
        crypto_header_bytes,
        key_wrap_table_bytes,
        subkeys,
        manifest_footer,
        manifest_footer_error,
        root_auth_footer: terminal.root_auth_footer,
        root_auth_footer_bytes: terminal.root_auth_footer_bytes,
        volume_trailer,
        blocks: block_region.blocks,
        erased_block_indices: block_region.erased_block_indices,
    })
}

fn parse_seekable_read_at_volume(
    reader: Arc<dyn ArchiveReadAt>,
    master_key: &MasterKey,
    options: ReaderOptions,
) -> Result<ParsedSeekableReadAtVolume, FormatError> {
    let observed_len = reader.len()?;
    if observed_len < (VOLUME_HEADER_LEN + VOLUME_TRAILER_LEN) as u64 {
        return Err(FormatError::InvalidLength {
            structure: "archive",
            expected: VOLUME_HEADER_LEN + VOLUME_TRAILER_LEN,
            actual: to_usize(observed_len, "archive")?,
        });
    }

    let prefix = match parse_read_at_open_prefix(reader.as_ref(), master_key) {
        Ok(prefix) => prefix,
        Err(prefix_err) => {
            if matches!(
                prefix_err,
                FormatError::UnsupportedVolumeFormatRevision { .. }
            ) {
                return Err(prefix_err);
            }
            return parse_seekable_read_at_volume_from_recovered_terminal(
                reader,
                observed_len,
                master_key,
                options,
            )
            .or(Err(prefix_err));
        }
    };
    let physical_crypto_header_bytes = prefix.crypto_header_bytes.clone();
    match parse_seekable_read_at_volume_with_prefix(reader.clone(), observed_len, prefix, options) {
        Ok(parsed) => Ok(parsed),
        Err(prefix_err) => match parse_seekable_read_at_volume_from_recovered_terminal(
            reader,
            observed_len,
            master_key,
            options,
        ) {
            Ok(recovered) if recovered.crypto_header_bytes == physical_crypto_header_bytes => {
                Ok(recovered)
            }
            Ok(_) | Err(_) => Err(prefix_err),
        },
    }
}

fn parse_seekable_read_at_volume_with_recipient_wrap_resolver<F>(
    reader: Arc<dyn ArchiveReadAt>,
    resolver: &mut F,
    options: ReaderOptions,
) -> Result<ParsedSeekableReadAtVolume, FormatError>
where
    F: FnMut(
        RecipientWrapRecordContext<'_>,
    ) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
{
    let observed_len = reader.len()?;
    if observed_len < (VOLUME_HEADER_LEN + VOLUME_TRAILER_LEN) as u64 {
        return Err(FormatError::InvalidLength {
            structure: "archive",
            expected: VOLUME_HEADER_LEN + VOLUME_TRAILER_LEN,
            actual: to_usize(observed_len, "archive")?,
        });
    }

    let prefix = match parse_read_at_open_prefix_with_recipient_wrap_resolver(
        reader.as_ref(),
        resolver,
    ) {
        Ok(prefix) => prefix,
        Err(prefix_err) => {
            if recipient_wrap_prefix_error_precludes_recovery(&prefix_err) {
                return Err(prefix_err);
            }
            return parse_seekable_read_at_volume_with_recipient_wrap_resolver_from_recovered_terminal(
                reader,
                observed_len,
                resolver,
                options,
            )
            .or(Err(prefix_err));
        }
    };
    let physical_crypto_header_bytes = prefix.crypto_header_bytes.clone();
    match parse_seekable_read_at_volume_with_prefix(reader.clone(), observed_len, prefix, options) {
        Ok(parsed) => Ok(parsed),
        Err(prefix_err) => {
            match parse_seekable_read_at_volume_with_recipient_wrap_resolver_from_recovered_terminal(
                reader,
                observed_len,
                resolver,
                options,
            ) {
                Ok(recovered) if recovered.crypto_header_bytes == physical_crypto_header_bytes => {
                    Ok(recovered)
                }
                Ok(_) | Err(_) => Err(prefix_err),
            }
        }
    }
}

fn parse_seekable_read_at_volume_with_prefix(
    reader: Arc<dyn ArchiveReadAt>,
    observed_len: u64,
    prefix: ParsedReadAtOpenPrefix,
    options: ReaderOptions,
) -> Result<ParsedSeekableReadAtVolume, FormatError> {
    let ParsedReadAtOpenPrefix {
        volume_header,
        crypto_header,
        crypto_header_bytes,
        key_wrap_table_bytes,
        block_records_start,
        subkeys,
    } = prefix;

    let terminal = locate_v41_terminal_read_at(
        reader.as_ref(),
        observed_len,
        KeyHoldingTerminalContext {
            subkeys: &subkeys,
            volume_header: &volume_header,
            crypto_header: &crypto_header,
            crypto_header_bytes: &crypto_header_bytes,
        },
        options,
    )?;
    finish_parse_seekable_read_at_volume(
        reader,
        volume_header,
        crypto_header,
        crypto_header_bytes,
        key_wrap_table_bytes,
        block_records_start,
        subkeys,
        terminal,
    )
}

fn parse_seekable_read_at_volume_from_recovered_terminal(
    reader: Arc<dyn ArchiveReadAt>,
    observed_len: u64,
    master_key: &MasterKey,
    options: ReaderOptions,
) -> Result<ParsedSeekableReadAtVolume, FormatError> {
    let authority =
        locate_v41_terminal_authority_read_at(reader.as_ref(), observed_len, master_key, options)?;
    parse_volume_format_dispatch(&authority.volume_header)?;
    if matches!(authority.kdf_params, KdfParams::RecipientWrap { .. }) {
        return Err(FormatError::KeyMaterialMismatch);
    }
    let block_records_start = startup_block_records_start(
        &authority.volume_header,
        &authority.kdf_params,
        |start, length| read_at_vec(reader.as_ref(), start, length, "KeyWrapTableV1"),
    )?;
    finish_parse_seekable_read_at_volume(
        reader,
        authority.volume_header,
        authority.crypto_header,
        authority.crypto_header_bytes,
        None,
        block_records_start,
        authority.subkeys,
        authority.terminal,
    )
}

fn parse_seekable_read_at_volume_with_recipient_wrap_resolver_from_recovered_terminal<F>(
    reader: Arc<dyn ArchiveReadAt>,
    observed_len: u64,
    resolver: &mut F,
    options: ReaderOptions,
) -> Result<ParsedSeekableReadAtVolume, FormatError>
where
    F: FnMut(
        RecipientWrapRecordContext<'_>,
    ) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
{
    let authority = locate_v41_recipient_wrap_terminal_authority_read_at(
        reader.as_ref(),
        observed_len,
        resolver,
        options,
    )?;
    finish_parse_seekable_read_at_volume(
        reader,
        authority.volume_header,
        authority.crypto_header,
        authority.crypto_header_bytes,
        Some(authority.key_wrap_table_bytes),
        authority.block_records_start,
        authority.subkeys,
        authority.terminal,
    )
}

fn parse_read_at_open_prefix(
    reader: &dyn ArchiveReadAt,
    master_key: &MasterKey,
) -> Result<ParsedReadAtOpenPrefix, FormatError> {
    let volume_header_bytes = read_at_vec(reader, 0, VOLUME_HEADER_LEN, "archive")?;
    let volume_header = VolumeHeader::parse(&volume_header_bytes)?;
    parse_volume_format_dispatch(&volume_header)?;
    let crypto_start = volume_header.crypto_header_offset as u64;
    let crypto_len = volume_header.crypto_header_length as u64;
    let crypto_bytes = read_at_vec(
        reader,
        crypto_start,
        to_usize(crypto_len, "CryptoHeader")?,
        "CryptoHeader",
    )?;
    let parsed_crypto = CryptoHeader::parse(&crypto_bytes, volume_header.crypto_header_length)?;
    if matches!(parsed_crypto.kdf_params, KdfParams::RecipientWrap { .. }) {
        return Err(FormatError::KeyMaterialMismatch);
    }
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
    validate_seekable_supported_volume(
        &volume_header,
        &parsed_crypto.fixed,
        &parsed_crypto.extensions,
    )?;
    validate_crypto_class_parity_exactness(&parsed_crypto.fixed)?;
    let block_records_start = startup_block_records_start(
        &volume_header,
        &parsed_crypto.kdf_params,
        |start, length| read_at_vec(reader, start, length, "KeyWrapTableV1"),
    )?;
    let crypto_header = parsed_crypto.fixed.clone();
    drop(parsed_crypto);
    Ok(ParsedReadAtOpenPrefix {
        volume_header,
        crypto_header,
        crypto_header_bytes: crypto_bytes,
        key_wrap_table_bytes: None,
        block_records_start,
        subkeys,
    })
}

fn parse_read_at_open_prefix_with_recipient_wrap_resolver<F>(
    reader: &dyn ArchiveReadAt,
    resolver: &mut F,
) -> Result<ParsedReadAtOpenPrefix, FormatError>
where
    F: FnMut(
        RecipientWrapRecordContext<'_>,
    ) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
{
    let volume_header_bytes = read_at_vec(reader, 0, VOLUME_HEADER_LEN, "archive")?;
    let volume_header = VolumeHeader::parse(&volume_header_bytes)?;
    parse_volume_format_dispatch(&volume_header)?;
    let crypto_start = volume_header.crypto_header_offset as u64;
    let crypto_len = volume_header.crypto_header_length as u64;
    let crypto_bytes = read_at_vec(
        reader,
        crypto_start,
        to_usize(crypto_len, "CryptoHeader")?,
        "CryptoHeader",
    )?;
    let parsed_crypto = CryptoHeader::parse(&crypto_bytes, volume_header.crypto_header_length)?;
    if !matches!(parsed_crypto.kdf_params, KdfParams::RecipientWrap { .. })
        || !parsed_crypto.fixed.aead_algo.is_encrypted()
    {
        return Err(FormatError::KeyMaterialMismatch);
    }

    validate_seekable_supported_volume(&volume_header, &parsed_crypto.fixed, &[])?;
    validate_crypto_class_parity_exactness(&parsed_crypto.fixed)?;

    let startup_key_wrap_table = startup_key_wrap_table(
        &volume_header,
        &parsed_crypto.kdf_params,
        |start, length| read_at_vec(reader, start, length, "KeyWrapTableV1"),
    )?
    .ok_or(FormatError::KeyMaterialMismatch)?;
    let key_wrap_table = startup_key_wrap_table.table;
    let key_wrap_table_bytes = Some(startup_key_wrap_table.bytes);
    let block_records_start = startup_key_wrap_table.block_records_start;

    let subkeys = recipient_wrap_subkeys_from_table(
        &volume_header,
        &parsed_crypto,
        &key_wrap_table,
        resolver,
    )?;
    parsed_crypto.validate_extension_semantics()?;
    reject_unsupported_raw_stream_profile(&parsed_crypto.extensions)?;

    let crypto_header = parsed_crypto.fixed.clone();
    Ok(ParsedReadAtOpenPrefix {
        volume_header,
        crypto_header,
        crypto_header_bytes: crypto_bytes,
        key_wrap_table_bytes,
        block_records_start,
        subkeys,
    })
}

#[allow(clippy::too_many_arguments)]
fn finish_parse_seekable_read_at_volume(
    reader: Arc<dyn ArchiveReadAt>,
    volume_header: VolumeHeader,
    crypto_header: CryptoHeaderFixed,
    crypto_header_bytes: Vec<u8>,
    key_wrap_table_bytes: Option<Vec<u8>>,
    block_records_start: u64,
    subkeys: Subkeys,
    terminal: V41Terminal,
) -> Result<ParsedSeekableReadAtVolume, FormatError> {
    let volume_trailer = terminal.volume_trailer.clone();
    validate_trailer_identity(&volume_header, &volume_trailer)?;

    let manifest_offset = volume_trailer.manifest_footer_offset;
    let manifest_end = checked_u64_add(
        manifest_offset,
        MANIFEST_FOOTER_LEN as u64,
        "ManifestFooter",
    )?;
    if volume_trailer.root_auth_flags & 0x0000_0001 != 0 {
        if volume_trailer.root_auth_footer_offset != manifest_end
            || volume_trailer
                .root_auth_footer_offset
                .checked_add(volume_trailer.root_auth_footer_length as u64)
                .ok_or(FormatError::InvalidArchive(
                    "RootAuthFooter terminal boundary overflow",
                ))?
                != terminal.image.volume_trailer_offset
        {
            return Err(FormatError::InvalidArchive(
                "RootAuthFooter does not sit before selected trailer",
            ));
        }
    } else if manifest_end != terminal.image.volume_trailer_offset {
        return Err(FormatError::InvalidArchive(
            "ManifestFooter does not end at selected trailer",
        ));
    }
    validate_seekable_block_region_layout(
        block_records_start,
        manifest_offset,
        crypto_header.block_size as usize,
        &volume_trailer,
    )?;

    let manifest_bytes = &terminal.manifest_footer_bytes;
    let (manifest_footer, manifest_footer_error) =
        match parse_valid_manifest_footer(&volume_header, &crypto_header, &subkeys, manifest_bytes)
        {
            Ok(footer) => (Some(footer), None),
            Err(err) if manifest_footer_copy_error_is_recoverable(&err) => (None, Some(err)),
            Err(err) => return Err(err),
        };

    Ok(ParsedSeekableReadAtVolume {
        reader,
        volume_header,
        crypto_header,
        crypto_header_bytes,
        key_wrap_table_bytes,
        subkeys,
        manifest_footer,
        manifest_footer_error,
        root_auth_footer: terminal.root_auth_footer,
        root_auth_footer_bytes: terminal.root_auth_footer_bytes,
        volume_trailer,
        block_records_start,
    })
}

#[derive(Debug)]
struct ParsedPublicNoKeyVolume {
    volume_header: VolumeHeader,
    crypto_header: CryptoHeaderFixed,
    kdf_params: KdfParams,
    root_auth_footer: RootAuthFooterV1,
    root_auth_footer_bytes: Vec<u8>,
    blocks: BTreeMap<u64, BlockRecord>,
}

pub fn public_no_key_verify_volumes_with_options<F>(
    volumes: &[&[u8]],
    mut verifier: F,
    options: ReaderOptions,
) -> Result<PublicNoKeyVerification, FormatError>
where
    F: FnMut(&RootAuthFooterV1, &[u8; 32]) -> Result<bool, FormatError>,
{
    validate_reader_options(options)?;
    if volumes.is_empty() {
        return Err(FormatError::InvalidArchive("no volumes supplied"));
    }
    let mut parsed = Vec::with_capacity(volumes.len());
    for volume in volumes {
        parsed.push(parse_public_no_key_volume(volume, options)?);
    }
    let first = parsed
        .first()
        .ok_or(FormatError::InvalidArchive("no volumes supplied"))?;
    if parsed.len() != first.crypto_header.stripe_width as usize {
        return Err(FormatError::ReaderUnsupported(
            "public no-key verification requires a complete volume set",
        ));
    }

    let mut seen_volume_indexes = BTreeSet::new();
    let mut blocks = BTreeMap::new();
    for volume in &parsed {
        if volume.volume_header.archive_uuid != first.volume_header.archive_uuid
            || volume.volume_header.session_id != first.volume_header.session_id
            || !public_crypto_headers_agree(&volume.crypto_header, &first.crypto_header)
            || !public_kdf_profiles_agree(&volume.kdf_params, &first.kdf_params)
        {
            return Err(FormatError::InvalidArchive(
                "public no-key volume global metadata differs",
            ));
        }
        if volume.root_auth_footer_bytes != first.root_auth_footer_bytes {
            return Err(FormatError::InvalidArchive(
                "public no-key RootAuthFooter copies differ",
            ));
        }
        if !seen_volume_indexes.insert(volume.volume_header.volume_index) {
            return Err(FormatError::InvalidArchive(
                "duplicate public no-key volume index",
            ));
        }
        for (block_index, record) in &volume.blocks {
            if blocks.insert(*block_index, record.clone()).is_some() {
                return Err(FormatError::InvalidArchive("duplicate BlockRecord index"));
            }
        }
    }
    validate_complete_global_block_coverage(&blocks, &BTreeSet::new())?;

    let footer = &first.root_auth_footer;
    let mut data_leaves = blocks
        .values()
        .filter(|record| record.kind.is_data())
        .map(|record| DataBlockMerkleLeaf {
            block_index: record.block_index,
            kind: record.kind,
            flags: record.flags,
            payload: record.payload.clone(),
        })
        .collect::<Vec<_>>();
    data_leaves.sort_by_key(|leaf| leaf.block_index);
    let total_data_block_count = u64::try_from(data_leaves.len())
        .map_err(|_| FormatError::InvalidArchive("public no-key data block count overflow"))?;
    let observed_data_root = data_block_merkle_root_for_revision(
        footer.format_version,
        footer.volume_format_rev,
        &data_leaves,
    )?;
    if total_data_block_count != footer.total_data_block_count
        || observed_data_root != footer.data_block_merkle_root
    {
        return Err(FormatError::InvalidArchive(
            "public no-key data-block commitment mismatch",
        ));
    }
    let archive_root = recompute_public_archive_root(footer, &first.crypto_header)?;
    if archive_root != footer.archive_root {
        return Err(FormatError::InvalidArchive(
            "public no-key archive_root mismatch",
        ));
    }
    if !verifier(footer, &archive_root)? {
        return Err(FormatError::InvalidArchive(
            "public no-key authenticator verification failed",
        ));
    }
    Ok(PublicNoKeyVerification {
        format_version: footer.format_version,
        volume_format_rev: footer.volume_format_rev,
        archive_root,
        authenticator_id: footer.authenticator_id,
        signer_identity_type: footer.signer_identity_type,
        signer_identity_bytes: footer.signer_identity_bytes.clone(),
        total_data_block_count,
        diagnostics: vec![
            PublicNoKeyDiagnostic::PublicDataBlockCommitmentVerified,
            PublicNoKeyDiagnostic::PublicPhysicalCompletenessUnverified,
            PublicNoKeyDiagnostic::PublicRecoveryMarginUnchecked,
        ],
    })
}

fn parse_public_no_key_volume(
    bytes: &[u8],
    options: ReaderOptions,
) -> Result<ParsedPublicNoKeyVolume, FormatError> {
    if bytes.len() < VOLUME_HEADER_LEN + VOLUME_TRAILER_LEN {
        return Err(FormatError::InvalidLength {
            structure: "archive",
            expected: VOLUME_HEADER_LEN + VOLUME_TRAILER_LEN,
            actual: bytes.len(),
        });
    }
    let volume_header = VolumeHeader::parse(slice(bytes, 0, VOLUME_HEADER_LEN, "archive")?)?;
    parse_volume_format_dispatch(&volume_header)?;
    let crypto_start = volume_header.crypto_header_offset as usize;
    let crypto_len = volume_header.crypto_header_length as usize;
    let crypto_end = checked_add(crypto_start, crypto_len, "CryptoHeader")?;
    let crypto_bytes = slice(bytes, crypto_start, crypto_len, "CryptoHeader")?;
    let parsed_crypto = CryptoHeader::parse(crypto_bytes, volume_header.crypto_header_length)?;
    parsed_crypto.validate_extension_semantics()?;
    validate_seekable_supported_volume(
        &volume_header,
        &parsed_crypto.fixed,
        &parsed_crypto.extensions,
    )?;
    validate_crypto_class_parity_exactness(&parsed_crypto.fixed)?;

    let terminal = locate_v41_public_terminal(bytes, &volume_header, &parsed_crypto, options)?;
    let block_records_start = match &parsed_crypto.kdf_params {
        KdfParams::RecipientWrap {
            key_wrap_table_length,
            ..
        } => checked_add(
            crypto_end,
            *key_wrap_table_length as usize,
            "KeyWrapTableV1",
        )?,
        _ => crypto_end,
    };
    let block_region = parse_public_block_observation(
        bytes,
        block_records_start,
        &terminal.image,
        parsed_crypto.fixed.block_size as usize,
        &volume_header,
    )?;
    Ok(ParsedPublicNoKeyVolume {
        volume_header,
        crypto_header: parsed_crypto.fixed,
        kdf_params: parsed_crypto.kdf_params,
        root_auth_footer: terminal.root_auth_footer,
        root_auth_footer_bytes: terminal.root_auth_footer_bytes,
        blocks: block_region,
    })
}

fn public_crypto_headers_agree(left: &CryptoHeaderFixed, right: &CryptoHeaderFixed) -> bool {
    left.length == right.length
        && left.stripe_width == right.stripe_width
        && left.block_size == right.block_size
        && left.compression_algo == right.compression_algo
        && left.aead_algo == right.aead_algo
        && left.fec_algo == right.fec_algo
        && left.kdf_algo == right.kdf_algo
}

fn public_kdf_profiles_agree(left: &KdfParams, right: &KdfParams) -> bool {
    match (left, right) {
        (
            KdfParams::RecipientWrap {
                key_wrap_table_length: left_length,
                key_wrap_table_record_count: left_count,
                key_wrap_table_version: left_version,
                key_wrap_table_digest: left_digest,
            },
            KdfParams::RecipientWrap {
                key_wrap_table_length: right_length,
                key_wrap_table_record_count: right_count,
                key_wrap_table_version: right_version,
                key_wrap_table_digest: right_digest,
            },
        ) => {
            left_length == right_length
                && left_count == right_count
                && left_version == right_version
                && left_digest == right_digest
        }
        (KdfParams::RecipientWrap { .. }, _) | (_, KdfParams::RecipientWrap { .. }) => false,
        _ => true,
    }
}

fn recompute_public_archive_root(
    footer: &RootAuthFooterV1,
    crypto_header: &CryptoHeaderFixed,
) -> Result<[u8; 32], FormatError> {
    let descriptor_digest = root_auth_descriptor_digest_for_revision(
        footer.format_version,
        footer.volume_format_rev,
        footer.authenticator_id,
        footer.signer_identity_type,
        &footer.signer_identity_bytes,
        u32::try_from(footer.authenticator_value.len()).map_err(|_| {
            FormatError::InvalidArchive("RootAuthFooter authenticator length overflow")
        })?,
        footer.footer_length()?,
    )?;
    let signer_digest =
        signer_identity_digest(footer.signer_identity_type, &footer.signer_identity_bytes)?;
    if signer_digest != footer.signer_identity_digest {
        return Err(FormatError::InvalidArchive(
            "public no-key signer identity digest mismatch",
        ));
    }
    archive_root_for_revision(ArchiveRootInputs {
        archive_uuid: footer.archive_uuid,
        session_id: footer.session_id,
        format_version: footer.format_version,
        volume_format_rev: footer.volume_format_rev,
        compression_algo: crypto_header.compression_algo,
        aead_algo: crypto_header.aead_algo,
        fec_algo: crypto_header.fec_algo,
        kdf_algo: crypto_header.kdf_algo,
        critical_metadata_digest: footer.critical_metadata_digest,
        index_digest: footer.index_digest,
        fec_layout_digest: footer.fec_layout_digest,
        total_data_block_count: footer.total_data_block_count,
        data_block_merkle_root: footer.data_block_merkle_root,
        root_auth_descriptor_digest: descriptor_digest,
        signer_identity_digest: signer_digest,
    })
}

fn parse_valid_manifest_footer(
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
    subkeys: &Subkeys,
    manifest_bytes: &[u8],
) -> Result<ManifestFooter, FormatError> {
    let manifest_footer = ManifestFooter::parse(manifest_bytes)?;
    validate_manifest_footer(
        volume_header,
        crypto_header,
        &manifest_footer,
        subkeys,
        volume_header.volume_format_rev,
        manifest_bytes,
    )?;
    manifest_footer.validate_index_root_extent(crypto_header.block_size)?;
    Ok(manifest_footer)
}

fn manifest_footer_copy_error_is_recoverable(error: &FormatError) -> bool {
    matches!(
        error,
        FormatError::BadMagic {
            structure: "ManifestFooter",
        } | FormatError::NonZeroReserved {
            structure: "ManifestFooter",
        } | FormatError::InvalidAuthoritativeFlag(_)
            | FormatError::HmacMismatch {
                structure: "ManifestFooter",
            }
            | FormatError::IntegrityDigestMismatch {
                structure: "ManifestFooter",
            }
    )
}

fn validate_seekable_supported_volume(
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
    extensions: &[ExtensionTlv<'_>],
) -> Result<(), FormatError> {
    reject_unsupported_raw_stream_profile(extensions)?;
    if crypto_header.stripe_width != volume_header.stripe_width {
        return Err(FormatError::InvalidArchive(
            "VolumeHeader and CryptoHeader stripe_width differ",
        ));
    }
    Ok(())
}

pub(crate) fn validate_crypto_class_parity_exactness(
    crypto_header: &CryptoHeaderFixed,
) -> Result<(), FormatError> {
    let fec = required_object_parity(crypto_header.fec_data_shards as u64, crypto_header)?;
    if crypto_header.fec_parity_shards as u32 != fec {
        return Err(FormatError::InvalidArchive(
            "fec_parity_shards does not match v41 compute_parity",
        ));
    }
    let index = required_object_parity(crypto_header.index_fec_data_shards as u64, crypto_header)?;
    if crypto_header.index_fec_parity_shards as u32 != index {
        return Err(FormatError::InvalidArchive(
            "index_fec_parity_shards does not match v41 compute_parity",
        ));
    }
    let index_root = required_object_parity(
        crypto_header.index_root_fec_data_shards as u64,
        crypto_header,
    )?;
    if crypto_header.index_root_fec_parity_shards as u32 != index_root {
        return Err(FormatError::InvalidArchive(
            "index_root_fec_parity_shards does not match v41 compute_parity",
        ));
    }
    Ok(())
}

fn validate_volume_set_member(
    first: &ParsedSeekableVolume,
    candidate: &ParsedSeekableVolume,
) -> Result<(), FormatError> {
    validate_volume_set_member_metadata(
        &first.volume_header,
        &first.crypto_header,
        &first.crypto_header_bytes,
        &candidate.volume_header,
        &candidate.crypto_header,
        &candidate.crypto_header_bytes,
    )?;
    validate_key_wrap_table_bytes_match(
        &first.key_wrap_table_bytes,
        &candidate.key_wrap_table_bytes,
    )
}

fn validate_key_wrap_table_bytes_match(
    first_key_wrap_table_bytes: &Option<Vec<u8>>,
    candidate_key_wrap_table_bytes: &Option<Vec<u8>>,
) -> Result<(), FormatError> {
    if candidate_key_wrap_table_bytes != first_key_wrap_table_bytes {
        return Err(FormatError::InvalidArchive("KeyWrapTableV1 copies differ"));
    }
    Ok(())
}

fn validate_volume_set_member_metadata(
    first_volume_header: &VolumeHeader,
    first_crypto_header: &CryptoHeaderFixed,
    first_crypto_header_bytes: &[u8],
    candidate_volume_header: &VolumeHeader,
    candidate_crypto_header: &CryptoHeaderFixed,
    candidate_crypto_header_bytes: &[u8],
) -> Result<(), FormatError> {
    if candidate_volume_header.archive_uuid != first_volume_header.archive_uuid
        || candidate_volume_header.session_id != first_volume_header.session_id
    {
        return Err(FormatError::InvalidArchive(
            "mixed archive or session IDs in volume set",
        ));
    }
    if candidate_crypto_header_bytes != first_crypto_header_bytes
        || candidate_crypto_header != first_crypto_header
    {
        return Err(FormatError::InvalidArchive("CryptoHeader copies differ"));
    }
    Ok(())
}

pub(crate) fn manifest_bootstrap_fields_match(
    left: &ManifestFooter,
    right: &ManifestFooter,
) -> bool {
    left.archive_uuid == right.archive_uuid
        && left.session_id == right.session_id
        && left.is_authoritative == right.is_authoritative
        && left.total_volumes == right.total_volumes
        && left.index_root_first_block == right.index_root_first_block
        && left.index_root_data_block_count == right.index_root_data_block_count
        && left.index_root_parity_block_count == right.index_root_parity_block_count
        && left.index_root_encrypted_size == right.index_root_encrypted_size
        && left.index_root_decompressed_size == right.index_root_decompressed_size
}

fn validate_complete_global_block_coverage(
    blocks: &BTreeMap<u64, BlockRecord>,
    erased_block_indices: &BTreeSet<u64>,
) -> Result<(), FormatError> {
    let mut expected = 0u64;
    let mut block_iter = blocks.keys().copied().peekable();
    let mut erasure_iter = erased_block_indices.iter().copied().peekable();

    loop {
        let next_block = block_iter.peek().copied();
        let next_erasure = erasure_iter.peek().copied();
        let next = match (next_block, next_erasure) {
            (Some(block), Some(erasure)) if block == erasure => {
                return Err(FormatError::InvalidArchive(
                    "BlockRecord index is both present and erased",
                ));
            }
            (Some(block), Some(erasure)) => block.min(erasure),
            (Some(block), None) => block,
            (None, Some(erasure)) => erasure,
            (None, None) => return Ok(()),
        };

        if next != expected {
            return Err(FormatError::InvalidArchive(
                "complete volume set has missing global blocks",
            ));
        }
        if next_block == Some(next) {
            block_iter.next();
        }
        if next_erasure == Some(next) {
            erasure_iter.next();
        }
        expected = expected
            .checked_add(1)
            .ok_or(FormatError::InvalidArchive("global block index overflow"))?;
    }
}

#[derive(Debug)]
struct V41Terminal {
    image: CriticalMetadataImage,
    manifest_footer_bytes: Vec<u8>,
    root_auth_footer_bytes: Option<Vec<u8>>,
    root_auth_footer: Option<RootAuthFooterV1>,
    volume_trailer: VolumeTrailer,
}

pub(crate) struct SequentialTerminalMaterial {
    pub(crate) manifest_footer: ManifestFooter,
    pub(crate) volume_trailer: VolumeTrailer,
    pub(crate) root_auth_footer: Option<RootAuthFooterV1>,
}

#[derive(Debug)]
struct V41PublicTerminal {
    image: CriticalMetadataImage,
    root_auth_footer_bytes: Vec<u8>,
    root_auth_footer: RootAuthFooterV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CmraDecoderTuple {
    shard_size: u32,
    data_shard_count: u16,
    parity_shard_count: u16,
    image_length: u32,
    image_sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CmraIdentityHints {
    archive_uuid: [u8; 16],
    session_id: [u8; 16],
    volume_index: u32,
}

impl From<CriticalMetadataRecoveryHeader> for CmraDecoderTuple {
    fn from(header: CriticalMetadataRecoveryHeader) -> Self {
        Self {
            shard_size: header.shard_size,
            data_shard_count: header.data_shard_count,
            parity_shard_count: header.parity_shard_count,
            image_length: header.image_length,
            image_sha256: header.image_sha256,
        }
    }
}

impl From<CriticalMetadataRecoveryHeader> for CmraIdentityHints {
    fn from(header: CriticalMetadataRecoveryHeader) -> Self {
        Self {
            archive_uuid: header.archive_uuid_hint,
            session_id: header.session_id_hint,
            volume_index: header.volume_index_hint,
        }
    }
}

impl From<CriticalRecoveryLocator> for CmraDecoderTuple {
    fn from(locator: CriticalRecoveryLocator) -> Self {
        Self {
            shard_size: locator.cmra_shard_size,
            data_shard_count: locator.cmra_data_shard_count,
            parity_shard_count: locator.cmra_parity_shard_count,
            image_length: locator.cmra_image_length,
            image_sha256: locator.cmra_image_sha256,
        }
    }
}

impl From<CriticalRecoveryLocator> for CmraIdentityHints {
    fn from(locator: CriticalRecoveryLocator) -> Self {
        Self {
            archive_uuid: locator.archive_uuid_hint,
            session_id: locator.session_id_hint,
            volume_index: locator.volume_index_hint,
        }
    }
}

#[derive(Debug)]
struct RecoveredCmra {
    image: CriticalMetadataImage,
    tuple: CmraDecoderTuple,
    header_hints: Option<CmraIdentityHints>,
    cmra_length: u64,
}

#[derive(Debug)]
struct TerminalCandidate {
    terminal: V41Terminal,
    anchor: usize,
    locator_sequence: Option<u32>,
    cmra_offset: u64,
    cmra_length: u64,
}

#[derive(Debug)]
struct PublicTerminalCandidate {
    terminal: V41PublicTerminal,
    anchor: usize,
    cmra_offset: u64,
    cmra_length: u64,
}

#[derive(Debug)]
struct RecoveredTerminalAuthority {
    terminal: V41Terminal,
    volume_header: VolumeHeader,
    crypto_header: CryptoHeaderFixed,
    crypto_header_bytes: Vec<u8>,
    subkeys: Subkeys,
    kdf_params: KdfParams,
}

#[derive(Debug)]
struct RecoveredRecipientWrapTerminalAuthority {
    terminal: V41Terminal,
    volume_header: VolumeHeader,
    crypto_header: CryptoHeaderFixed,
    crypto_header_bytes: Vec<u8>,
    key_wrap_table_bytes: Vec<u8>,
    block_records_start: u64,
    subkeys: Subkeys,
}

#[derive(Debug)]
struct TerminalAuthorityCandidate {
    authority: RecoveredTerminalAuthority,
    anchor: usize,
    cmra_offset: u64,
    cmra_length: u64,
}

#[derive(Debug)]
struct RecipientWrapTerminalAuthorityCandidate {
    authority: RecoveredRecipientWrapTerminalAuthority,
    anchor: usize,
    cmra_offset: u64,
    cmra_length: u64,
}

#[derive(Debug, Clone, Copy)]
enum CmraRecoveryMode {
    KeyHolding,
    PublicNoKey,
}

#[derive(Clone, Copy)]
pub(crate) struct KeyHoldingTerminalContext<'a> {
    pub(crate) subkeys: &'a Subkeys,
    pub(crate) volume_header: &'a VolumeHeader,
    pub(crate) crypto_header: &'a CryptoHeaderFixed,
    pub(crate) crypto_header_bytes: &'a [u8],
}

fn locate_v41_terminal(
    bytes: &[u8],
    context: KeyHoldingTerminalContext<'_>,
    options: ReaderOptions,
) -> Result<V41Terminal, FormatError> {
    locate_v41_terminal_candidate(bytes, context, options).map(|candidate| candidate.terminal)
}

fn locate_v41_terminal_read_at(
    reader: &dyn ArchiveReadAt,
    len: u64,
    context: KeyHoldingTerminalContext<'_>,
    options: ReaderOptions,
) -> Result<V41Terminal, FormatError> {
    let mut candidates = Vec::new();
    if len >= CRITICAL_RECOVERY_LOCATOR_LEN as u64 {
        let final_offset = len - CRITICAL_RECOVERY_LOCATOR_LEN as u64;
        collect_v41_locator_candidate_read_at(reader, final_offset, 0, context, &mut candidates);
    }
    if len >= LOCATOR_PAIR_LEN as u64 {
        let mirror_offset = len - LOCATOR_PAIR_LEN as u64;
        collect_v41_locator_candidate_read_at(reader, mirror_offset, 1, context, &mut candidates);
    }

    if candidates.is_empty() {
        let scan = max_critical_recovery_scan(options)? as u64;
        let scan_start = len.saturating_sub(scan);
        let scan_len = to_usize(len.saturating_sub(scan_start), "CMRA scan")?;
        let tail = read_at_vec(reader, scan_start, scan_len, "CMRA scan")?;
        let mut offset = tail.len().saturating_sub(4);
        while offset < tail.len() {
            let absolute_offset = checked_u64_add(scan_start, offset as u64, "CMRA scan")?;
            if tail.get(offset..offset + 4) == Some(b"TZCL") {
                collect_v41_locator_candidate_read_at(
                    reader,
                    absolute_offset,
                    2,
                    context,
                    &mut candidates,
                );
            } else if tail.get(offset..offset + 4) == Some(b"TZCR") {
                if let Ok(candidate) =
                    parse_locatorless_cmra_candidate_read_at(reader, absolute_offset, context)
                {
                    candidates.push(candidate);
                }
            }
            if offset == 0 {
                break;
            }
            offset -= 1;
        }
    }

    choose_v41_terminal_candidate(candidates).map(|candidate| candidate.terminal)
}

fn locate_v41_terminal_authority(
    bytes: &[u8],
    master_key: &MasterKey,
    options: ReaderOptions,
) -> Result<RecoveredTerminalAuthority, FormatError> {
    let mut candidates = Vec::new();
    if bytes.len() >= CRITICAL_RECOVERY_LOCATOR_LEN {
        let final_offset = bytes.len() - CRITICAL_RECOVERY_LOCATOR_LEN;
        collect_v41_locator_authority_candidate(
            bytes,
            final_offset,
            0,
            master_key,
            &mut candidates,
        );
    }
    if bytes.len() >= LOCATOR_PAIR_LEN {
        let mirror_offset = bytes.len() - LOCATOR_PAIR_LEN;
        collect_v41_locator_authority_candidate(
            bytes,
            mirror_offset,
            1,
            master_key,
            &mut candidates,
        );
    }

    if candidates.is_empty() {
        let scan = max_critical_recovery_scan(options)?;
        let scan_start = bytes.len().saturating_sub(scan);
        let mut offset = bytes.len().saturating_sub(4);
        while offset >= scan_start {
            if bytes.get(offset..offset + 4) == Some(b"TZCL") {
                collect_v41_locator_authority_candidate(
                    bytes,
                    offset,
                    2,
                    master_key,
                    &mut candidates,
                );
            } else if bytes.get(offset..offset + 4) == Some(b"TZCR") {
                if let Ok(candidate) =
                    parse_locatorless_cmra_authority_candidate(bytes, offset, master_key)
                {
                    candidates.push(candidate);
                }
            }
            if offset == 0 {
                break;
            }
            offset -= 1;
        }
    }

    choose_v41_terminal_authority_candidate(candidates).map(|candidate| candidate.authority)
}

fn locate_v41_recipient_wrap_terminal_authority<F>(
    bytes: &[u8],
    resolver: &mut F,
    options: ReaderOptions,
) -> Result<RecoveredRecipientWrapTerminalAuthority, FormatError>
where
    F: FnMut(
        RecipientWrapRecordContext<'_>,
    ) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
{
    let mut candidates = Vec::new();
    if bytes.len() >= CRITICAL_RECOVERY_LOCATOR_LEN {
        let final_offset = bytes.len() - CRITICAL_RECOVERY_LOCATOR_LEN;
        collect_v41_recipient_wrap_locator_authority_candidate(
            bytes,
            final_offset,
            0,
            resolver,
            &mut candidates,
        );
    }
    if bytes.len() >= LOCATOR_PAIR_LEN {
        let mirror_offset = bytes.len() - LOCATOR_PAIR_LEN;
        collect_v41_recipient_wrap_locator_authority_candidate(
            bytes,
            mirror_offset,
            1,
            resolver,
            &mut candidates,
        );
    }

    if candidates.is_empty() {
        let scan = max_critical_recovery_scan(options)?;
        let scan_start = bytes.len().saturating_sub(scan);
        let mut offset = bytes.len().saturating_sub(4);
        while offset >= scan_start {
            if bytes.get(offset..offset + 4) == Some(b"TZCL") {
                collect_v41_recipient_wrap_locator_authority_candidate(
                    bytes,
                    offset,
                    2,
                    resolver,
                    &mut candidates,
                );
            } else if bytes.get(offset..offset + 4) == Some(b"TZCR") {
                if let Ok(candidate) = parse_locatorless_cmra_recipient_wrap_authority_candidate(
                    bytes, offset, resolver,
                ) {
                    candidates.push(candidate);
                }
            }
            if offset == 0 {
                break;
            }
            offset -= 1;
        }
    }

    choose_v41_recipient_wrap_terminal_authority_candidate(candidates)
        .map(|candidate| candidate.authority)
}

fn locate_v41_recipient_wrap_terminal_authority_read_at<F>(
    reader: &dyn ArchiveReadAt,
    len: u64,
    resolver: &mut F,
    options: ReaderOptions,
) -> Result<RecoveredRecipientWrapTerminalAuthority, FormatError>
where
    F: FnMut(
        RecipientWrapRecordContext<'_>,
    ) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
{
    let mut candidates = Vec::new();
    if len >= CRITICAL_RECOVERY_LOCATOR_LEN as u64 {
        let final_offset = len - CRITICAL_RECOVERY_LOCATOR_LEN as u64;
        collect_v41_recipient_wrap_locator_authority_candidate_read_at(
            reader,
            final_offset,
            0,
            resolver,
            &mut candidates,
        );
    }
    if len >= LOCATOR_PAIR_LEN as u64 {
        let mirror_offset = len - LOCATOR_PAIR_LEN as u64;
        collect_v41_recipient_wrap_locator_authority_candidate_read_at(
            reader,
            mirror_offset,
            1,
            resolver,
            &mut candidates,
        );
    }

    if candidates.is_empty() {
        let scan = max_critical_recovery_scan(options)? as u64;
        let scan_start = len.saturating_sub(scan);
        let scan_len = to_usize(len.saturating_sub(scan_start), "CMRA scan")?;
        let tail = read_at_vec(reader, scan_start, scan_len, "CMRA scan")?;
        let mut offset = tail.len().saturating_sub(4);
        while offset < tail.len() {
            let absolute_offset = checked_u64_add(scan_start, offset as u64, "CMRA scan")?;
            if tail.get(offset..offset + 4) == Some(b"TZCL") {
                collect_v41_recipient_wrap_locator_authority_candidate_read_at(
                    reader,
                    absolute_offset,
                    2,
                    resolver,
                    &mut candidates,
                );
            } else if tail.get(offset..offset + 4) == Some(b"TZCR") {
                if let Ok(candidate) =
                    parse_locatorless_cmra_recipient_wrap_authority_candidate_read_at(
                        reader,
                        absolute_offset,
                        resolver,
                    )
                {
                    candidates.push(candidate);
                }
            }
            if offset == 0 {
                break;
            }
            offset -= 1;
        }
    }

    choose_v41_recipient_wrap_terminal_authority_candidate(candidates)
        .map(|candidate| candidate.authority)
}

fn locate_v41_terminal_authority_read_at(
    reader: &dyn ArchiveReadAt,
    len: u64,
    master_key: &MasterKey,
    options: ReaderOptions,
) -> Result<RecoveredTerminalAuthority, FormatError> {
    let mut candidates = Vec::new();
    if len >= CRITICAL_RECOVERY_LOCATOR_LEN as u64 {
        let final_offset = len - CRITICAL_RECOVERY_LOCATOR_LEN as u64;
        collect_v41_locator_authority_candidate_read_at(
            reader,
            final_offset,
            0,
            master_key,
            &mut candidates,
        );
    }
    if len >= LOCATOR_PAIR_LEN as u64 {
        let mirror_offset = len - LOCATOR_PAIR_LEN as u64;
        collect_v41_locator_authority_candidate_read_at(
            reader,
            mirror_offset,
            1,
            master_key,
            &mut candidates,
        );
    }

    if candidates.is_empty() {
        let scan = max_critical_recovery_scan(options)? as u64;
        let scan_start = len.saturating_sub(scan);
        let scan_len = to_usize(len.saturating_sub(scan_start), "CMRA scan")?;
        let tail = read_at_vec(reader, scan_start, scan_len, "CMRA scan")?;
        let mut offset = tail.len().saturating_sub(4);
        while offset < tail.len() {
            let absolute_offset = checked_u64_add(scan_start, offset as u64, "CMRA scan")?;
            if tail.get(offset..offset + 4) == Some(b"TZCL") {
                collect_v41_locator_authority_candidate_read_at(
                    reader,
                    absolute_offset,
                    2,
                    master_key,
                    &mut candidates,
                );
            } else if tail.get(offset..offset + 4) == Some(b"TZCR") {
                if let Ok(candidate) = parse_locatorless_cmra_authority_candidate_read_at(
                    reader,
                    absolute_offset,
                    master_key,
                ) {
                    candidates.push(candidate);
                }
            }
            if offset == 0 {
                break;
            }
            offset -= 1;
        }
    }

    choose_v41_terminal_authority_candidate(candidates).map(|candidate| candidate.authority)
}

fn locate_v41_terminal_candidate(
    bytes: &[u8],
    context: KeyHoldingTerminalContext<'_>,
    options: ReaderOptions,
) -> Result<TerminalCandidate, FormatError> {
    let mut candidates = Vec::new();
    if bytes.len() >= CRITICAL_RECOVERY_LOCATOR_LEN {
        let final_offset = bytes.len() - CRITICAL_RECOVERY_LOCATOR_LEN;
        collect_v41_locator_candidate(bytes, final_offset, 0, context, &mut candidates);
    }
    if bytes.len() >= LOCATOR_PAIR_LEN {
        let mirror_offset = bytes.len() - LOCATOR_PAIR_LEN;
        collect_v41_locator_candidate(bytes, mirror_offset, 1, context, &mut candidates);
    }

    if candidates.is_empty() {
        let scan = max_critical_recovery_scan(options)?;
        let scan_start = bytes.len().saturating_sub(scan);
        let mut offset = bytes.len().saturating_sub(4);
        while offset >= scan_start {
            if bytes.get(offset..offset + 4) == Some(b"TZCL") {
                collect_v41_locator_candidate(bytes, offset, 2, context, &mut candidates);
            } else if bytes.get(offset..offset + 4) == Some(b"TZCR") {
                if let Ok(candidate) = parse_locatorless_cmra_candidate(bytes, offset, context) {
                    candidates.push(candidate);
                }
            }
            if offset == 0 {
                break;
            }
            offset -= 1;
        }
    }

    choose_v41_terminal_candidate(candidates)
}

fn locate_v41_public_terminal(
    bytes: &[u8],
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeader<'_>,
    options: ReaderOptions,
) -> Result<V41PublicTerminal, FormatError> {
    let mut candidates = Vec::new();
    if bytes.len() >= CRITICAL_RECOVERY_LOCATOR_LEN {
        let final_offset = bytes.len() - CRITICAL_RECOVERY_LOCATOR_LEN;
        collect_v41_public_locator_candidate(
            bytes,
            final_offset,
            0,
            volume_header,
            crypto_header,
            &mut candidates,
        );
    }
    if bytes.len() >= LOCATOR_PAIR_LEN {
        let mirror_offset = bytes.len() - LOCATOR_PAIR_LEN;
        collect_v41_public_locator_candidate(
            bytes,
            mirror_offset,
            1,
            volume_header,
            crypto_header,
            &mut candidates,
        );
    }

    if candidates.is_empty() {
        let scan = max_critical_recovery_scan(options)?;
        let scan_start = bytes.len().saturating_sub(scan);
        let mut offset = bytes.len().saturating_sub(4);
        while offset >= scan_start {
            if bytes.get(offset..offset + 4) == Some(b"TZCL") {
                collect_v41_public_locator_candidate(
                    bytes,
                    offset,
                    2,
                    volume_header,
                    crypto_header,
                    &mut candidates,
                );
            } else if bytes.get(offset..offset + 4) == Some(b"TZCR") {
                if let Ok(candidate) = parse_public_locatorless_cmra_candidate(
                    bytes,
                    offset,
                    volume_header,
                    crypto_header,
                ) {
                    candidates.push(candidate);
                }
            }
            if offset == 0 {
                break;
            }
            offset -= 1;
        }
    }

    choose_v41_public_terminal_candidate(candidates).map(|candidate| candidate.terminal)
}

fn collect_v41_locator_candidate(
    bytes: &[u8],
    offset: usize,
    expected_sequence: u32,
    context: KeyHoldingTerminalContext<'_>,
    candidates: &mut Vec<TerminalCandidate>,
) {
    let Some(raw) = bytes.get(offset..offset + CRITICAL_RECOVERY_LOCATOR_LEN) else {
        return;
    };
    let Ok(locator) = CriticalRecoveryLocator::parse(raw) else {
        return;
    };
    if expected_sequence <= 1 && locator.locator_sequence != expected_sequence {
        return;
    }
    if let Ok(candidate) = parse_locator_cmra_candidate(bytes, offset, locator, context) {
        candidates.push(candidate);
    }
}

fn collect_v41_locator_candidate_read_at(
    reader: &dyn ArchiveReadAt,
    offset: u64,
    expected_sequence: u32,
    context: KeyHoldingTerminalContext<'_>,
    candidates: &mut Vec<TerminalCandidate>,
) {
    let Ok(raw) = read_at_vec(
        reader,
        offset,
        CRITICAL_RECOVERY_LOCATOR_LEN,
        "CriticalRecoveryLocator",
    ) else {
        return;
    };
    let Ok(locator) = CriticalRecoveryLocator::parse(&raw) else {
        return;
    };
    if expected_sequence <= 1 && locator.locator_sequence != expected_sequence {
        return;
    }
    if let Ok(candidate) = parse_locator_cmra_candidate_read_at(reader, offset, locator, context) {
        candidates.push(candidate);
    }
}

fn collect_v41_locator_authority_candidate(
    bytes: &[u8],
    offset: usize,
    expected_sequence: u32,
    master_key: &MasterKey,
    candidates: &mut Vec<TerminalAuthorityCandidate>,
) {
    let Some(raw) = bytes.get(offset..offset + CRITICAL_RECOVERY_LOCATOR_LEN) else {
        return;
    };
    let Ok(locator) = CriticalRecoveryLocator::parse(raw) else {
        return;
    };
    if expected_sequence <= 1 && locator.locator_sequence != expected_sequence {
        return;
    }
    if let Ok(candidate) =
        parse_locator_cmra_authority_candidate(bytes, offset, locator, master_key)
    {
        candidates.push(candidate);
    }
}

fn collect_v41_recipient_wrap_locator_authority_candidate<F>(
    bytes: &[u8],
    offset: usize,
    expected_sequence: u32,
    resolver: &mut F,
    candidates: &mut Vec<RecipientWrapTerminalAuthorityCandidate>,
) where
    F: FnMut(
        RecipientWrapRecordContext<'_>,
    ) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
{
    let Some(raw) = bytes.get(offset..offset + CRITICAL_RECOVERY_LOCATOR_LEN) else {
        return;
    };
    let Ok(locator) = CriticalRecoveryLocator::parse(raw) else {
        return;
    };
    if expected_sequence <= 1 && locator.locator_sequence != expected_sequence {
        return;
    }
    if let Ok(candidate) =
        parse_locator_cmra_recipient_wrap_authority_candidate(bytes, offset, locator, resolver)
    {
        candidates.push(candidate);
    }
}

fn collect_v41_recipient_wrap_locator_authority_candidate_read_at<F>(
    reader: &dyn ArchiveReadAt,
    offset: u64,
    expected_sequence: u32,
    resolver: &mut F,
    candidates: &mut Vec<RecipientWrapTerminalAuthorityCandidate>,
) where
    F: FnMut(
        RecipientWrapRecordContext<'_>,
    ) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
{
    let Ok(raw) = read_at_vec(
        reader,
        offset,
        CRITICAL_RECOVERY_LOCATOR_LEN,
        "CriticalRecoveryLocator",
    ) else {
        return;
    };
    let Ok(locator) = CriticalRecoveryLocator::parse(&raw) else {
        return;
    };
    if expected_sequence <= 1 && locator.locator_sequence != expected_sequence {
        return;
    }
    if let Ok(candidate) = parse_locator_cmra_recipient_wrap_authority_candidate_read_at(
        reader, offset, locator, resolver,
    ) {
        candidates.push(candidate);
    }
}

fn collect_v41_locator_authority_candidate_read_at(
    reader: &dyn ArchiveReadAt,
    offset: u64,
    expected_sequence: u32,
    master_key: &MasterKey,
    candidates: &mut Vec<TerminalAuthorityCandidate>,
) {
    let Ok(raw) = read_at_vec(
        reader,
        offset,
        CRITICAL_RECOVERY_LOCATOR_LEN,
        "CriticalRecoveryLocator",
    ) else {
        return;
    };
    let Ok(locator) = CriticalRecoveryLocator::parse(&raw) else {
        return;
    };
    if expected_sequence <= 1 && locator.locator_sequence != expected_sequence {
        return;
    }
    if let Ok(candidate) =
        parse_locator_cmra_authority_candidate_read_at(reader, offset, locator, master_key)
    {
        candidates.push(candidate);
    }
}

fn collect_v41_public_locator_candidate(
    bytes: &[u8],
    offset: usize,
    expected_sequence: u32,
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeader<'_>,
    candidates: &mut Vec<PublicTerminalCandidate>,
) {
    let Some(raw) = bytes.get(offset..offset + CRITICAL_RECOVERY_LOCATOR_LEN) else {
        return;
    };
    let Ok(locator) = CriticalRecoveryLocator::parse(raw) else {
        return;
    };
    if expected_sequence <= 1 && locator.locator_sequence != expected_sequence {
        return;
    }
    if let Ok(candidate) =
        parse_public_locator_cmra_candidate(bytes, offset, locator, volume_header, crypto_header)
    {
        candidates.push(candidate);
    }
}

fn choose_v41_terminal_candidate(
    mut candidates: Vec<TerminalCandidate>,
) -> Result<TerminalCandidate, FormatError> {
    candidates.sort_by_key(|candidate| candidate.anchor);
    let winner = candidates.pop().ok_or(FormatError::InvalidArchive(
        "no valid v41 CMRA candidate found",
    ))?;
    if let Some(previous) = candidates.last() {
        if previous.anchor == winner.anchor
            && (previous.cmra_offset != winner.cmra_offset
                || previous.cmra_length != winner.cmra_length)
        {
            return Err(FormatError::InvalidArchive("ambiguous v41 CMRA candidates"));
        }
    }
    Ok(winner)
}

fn choose_v41_terminal_authority_candidate(
    mut candidates: Vec<TerminalAuthorityCandidate>,
) -> Result<TerminalAuthorityCandidate, FormatError> {
    candidates.sort_by_key(|candidate| candidate.anchor);
    let winner = candidates.pop().ok_or(FormatError::InvalidArchive(
        "no valid v41 CMRA candidate found",
    ))?;
    if let Some(previous) = candidates.last() {
        if previous.anchor == winner.anchor
            && (previous.cmra_offset != winner.cmra_offset
                || previous.cmra_length != winner.cmra_length)
        {
            return Err(FormatError::InvalidArchive("ambiguous v41 CMRA candidates"));
        }
    }
    Ok(winner)
}

fn choose_v41_recipient_wrap_terminal_authority_candidate(
    mut candidates: Vec<RecipientWrapTerminalAuthorityCandidate>,
) -> Result<RecipientWrapTerminalAuthorityCandidate, FormatError> {
    candidates.sort_by_key(|candidate| candidate.anchor);
    let winner = candidates.pop().ok_or(FormatError::InvalidArchive(
        "no valid v41 CMRA candidate found",
    ))?;
    if let Some(previous) = candidates.last() {
        if previous.anchor == winner.anchor
            && (previous.cmra_offset != winner.cmra_offset
                || previous.cmra_length != winner.cmra_length)
        {
            return Err(FormatError::InvalidArchive("ambiguous v41 CMRA candidates"));
        }
    }
    Ok(winner)
}

fn choose_v41_public_terminal_candidate(
    mut candidates: Vec<PublicTerminalCandidate>,
) -> Result<PublicTerminalCandidate, FormatError> {
    candidates.sort_by_key(|candidate| candidate.anchor);
    let winner = candidates.pop().ok_or(FormatError::InvalidArchive(
        "no valid v41 public CMRA candidate found",
    ))?;
    if let Some(previous) = candidates.last() {
        if previous.anchor == winner.anchor
            && (previous.cmra_offset != winner.cmra_offset
                || previous.cmra_length != winner.cmra_length)
        {
            return Err(FormatError::InvalidArchive(
                "ambiguous v41 public CMRA candidates",
            ));
        }
    }
    Ok(winner)
}

fn parse_locator_cmra_candidate(
    bytes: &[u8],
    locator_offset: usize,
    locator: CriticalRecoveryLocator,
    context: KeyHoldingTerminalContext<'_>,
) -> Result<TerminalCandidate, FormatError> {
    let tuple = CmraDecoderTuple::from(locator);
    validate_cmra_decoder_tuple(tuple)?;
    let expected_cmra_length = cmra_serialized_length(tuple)?;
    if locator.cmra_length as u64 != expected_cmra_length {
        return Err(FormatError::InvalidArchive("locator CMRA length mismatch"));
    }
    validate_locator_position(locator_offset, locator)?;
    let recovered = recover_cmra(
        bytes,
        locator.cmra_offset,
        Some(tuple),
        CmraRecoveryMode::KeyHolding,
    )?;
    if recovered.tuple != tuple {
        return Err(FormatError::InvalidArchive("CMRA decoder tuple mismatch"));
    }
    if expected_cmra_length != recovered.cmra_length {
        return Err(FormatError::InvalidArchive("locator CMRA length mismatch"));
    }
    validate_locator_image_boundary(locator, &recovered.image)?;
    validate_cmra_identity_hints(
        recovered.header_hints,
        Some(CmraIdentityHints::from(locator)),
        &recovered.image,
    )?;
    let terminal =
        validate_recovered_terminal(recovered.image, recovered.tuple, bytes, context, false)?;
    Ok(TerminalCandidate {
        terminal,
        anchor: locator_offset
            .checked_add(CRITICAL_RECOVERY_LOCATOR_LEN)
            .ok_or(FormatError::InvalidArchive("locator anchor overflow"))?,
        locator_sequence: Some(locator.locator_sequence),
        cmra_offset: locator.cmra_offset,
        cmra_length: recovered.cmra_length,
    })
}

fn parse_locator_cmra_candidate_read_at(
    reader: &dyn ArchiveReadAt,
    locator_offset: u64,
    locator: CriticalRecoveryLocator,
    context: KeyHoldingTerminalContext<'_>,
) -> Result<TerminalCandidate, FormatError> {
    let tuple = CmraDecoderTuple::from(locator);
    validate_cmra_decoder_tuple(tuple)?;
    let expected_cmra_length = cmra_serialized_length(tuple)?;
    if locator.cmra_length as u64 != expected_cmra_length {
        return Err(FormatError::InvalidArchive("locator CMRA length mismatch"));
    }
    validate_locator_position(
        to_usize(locator_offset, "CriticalRecoveryLocator")?,
        locator,
    )?;
    let recovered = recover_cmra_read_at(
        reader,
        locator.cmra_offset,
        Some(tuple),
        CmraRecoveryMode::KeyHolding,
    )?;
    if recovered.tuple != tuple {
        return Err(FormatError::InvalidArchive("CMRA decoder tuple mismatch"));
    }
    if expected_cmra_length != recovered.cmra_length {
        return Err(FormatError::InvalidArchive("locator CMRA length mismatch"));
    }
    validate_locator_image_boundary(locator, &recovered.image)?;
    validate_cmra_identity_hints(
        recovered.header_hints,
        Some(CmraIdentityHints::from(locator)),
        &recovered.image,
    )?;
    let terminal = validate_recovered_terminal_read_at(
        recovered.image,
        recovered.tuple,
        reader,
        context,
        false,
    )?;
    Ok(TerminalCandidate {
        terminal,
        anchor: to_usize(
            checked_u64_add(
                locator_offset,
                CRITICAL_RECOVERY_LOCATOR_LEN as u64,
                "locator anchor overflow",
            )?,
            "locator anchor overflow",
        )?,
        locator_sequence: Some(locator.locator_sequence),
        cmra_offset: locator.cmra_offset,
        cmra_length: recovered.cmra_length,
    })
}

fn parse_locator_cmra_authority_candidate(
    bytes: &[u8],
    locator_offset: usize,
    locator: CriticalRecoveryLocator,
    master_key: &MasterKey,
) -> Result<TerminalAuthorityCandidate, FormatError> {
    let tuple = CmraDecoderTuple::from(locator);
    validate_cmra_decoder_tuple(tuple)?;
    let expected_cmra_length = cmra_serialized_length(tuple)?;
    if locator.cmra_length as u64 != expected_cmra_length {
        return Err(FormatError::InvalidArchive("locator CMRA length mismatch"));
    }
    validate_locator_position(locator_offset, locator)?;
    let recovered = recover_cmra(
        bytes,
        locator.cmra_offset,
        Some(tuple),
        CmraRecoveryMode::KeyHolding,
    )?;
    if recovered.tuple != tuple {
        return Err(FormatError::InvalidArchive("CMRA decoder tuple mismatch"));
    }
    if expected_cmra_length != recovered.cmra_length {
        return Err(FormatError::InvalidArchive("locator CMRA length mismatch"));
    }
    validate_locator_image_boundary(locator, &recovered.image)?;
    validate_cmra_identity_hints(
        recovered.header_hints,
        Some(CmraIdentityHints::from(locator)),
        &recovered.image,
    )?;
    let cmra_length = recovered.cmra_length;
    let authority =
        validate_recovered_terminal_authority(recovered.image, recovered.tuple, master_key, false)?;
    Ok(TerminalAuthorityCandidate {
        authority,
        anchor: locator_offset
            .checked_add(CRITICAL_RECOVERY_LOCATOR_LEN)
            .ok_or(FormatError::InvalidArchive("locator anchor overflow"))?,
        cmra_offset: locator.cmra_offset,
        cmra_length,
    })
}

fn parse_locator_cmra_recipient_wrap_authority_candidate<F>(
    bytes: &[u8],
    locator_offset: usize,
    locator: CriticalRecoveryLocator,
    resolver: &mut F,
) -> Result<RecipientWrapTerminalAuthorityCandidate, FormatError>
where
    F: FnMut(
        RecipientWrapRecordContext<'_>,
    ) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
{
    let tuple = CmraDecoderTuple::from(locator);
    validate_cmra_decoder_tuple(tuple)?;
    let expected_cmra_length = cmra_serialized_length(tuple)?;
    if locator.cmra_length as u64 != expected_cmra_length {
        return Err(FormatError::InvalidArchive("locator CMRA length mismatch"));
    }
    validate_locator_position(locator_offset, locator)?;
    let recovered = recover_cmra(
        bytes,
        locator.cmra_offset,
        Some(tuple),
        CmraRecoveryMode::KeyHolding,
    )?;
    if recovered.tuple != tuple {
        return Err(FormatError::InvalidArchive("CMRA decoder tuple mismatch"));
    }
    if expected_cmra_length != recovered.cmra_length {
        return Err(FormatError::InvalidArchive("locator CMRA length mismatch"));
    }
    validate_locator_image_boundary(locator, &recovered.image)?;
    validate_cmra_identity_hints(
        recovered.header_hints,
        Some(CmraIdentityHints::from(locator)),
        &recovered.image,
    )?;
    let cmra_length = recovered.cmra_length;
    let authority = validate_recovered_recipient_wrap_terminal_authority(
        recovered.image,
        recovered.tuple,
        resolver,
        false,
    )?;
    Ok(RecipientWrapTerminalAuthorityCandidate {
        authority,
        anchor: locator_offset
            .checked_add(CRITICAL_RECOVERY_LOCATOR_LEN)
            .ok_or(FormatError::InvalidArchive("locator anchor overflow"))?,
        cmra_offset: locator.cmra_offset,
        cmra_length,
    })
}

fn parse_locator_cmra_recipient_wrap_authority_candidate_read_at<F>(
    reader: &dyn ArchiveReadAt,
    locator_offset: u64,
    locator: CriticalRecoveryLocator,
    resolver: &mut F,
) -> Result<RecipientWrapTerminalAuthorityCandidate, FormatError>
where
    F: FnMut(
        RecipientWrapRecordContext<'_>,
    ) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
{
    let tuple = CmraDecoderTuple::from(locator);
    validate_cmra_decoder_tuple(tuple)?;
    let expected_cmra_length = cmra_serialized_length(tuple)?;
    if locator.cmra_length as u64 != expected_cmra_length {
        return Err(FormatError::InvalidArchive("locator CMRA length mismatch"));
    }
    validate_locator_position(
        to_usize(locator_offset, "CriticalRecoveryLocator")?,
        locator,
    )?;
    let recovered = recover_cmra_read_at(
        reader,
        locator.cmra_offset,
        Some(tuple),
        CmraRecoveryMode::KeyHolding,
    )?;
    if recovered.tuple != tuple {
        return Err(FormatError::InvalidArchive("CMRA decoder tuple mismatch"));
    }
    if expected_cmra_length != recovered.cmra_length {
        return Err(FormatError::InvalidArchive("locator CMRA length mismatch"));
    }
    validate_locator_image_boundary(locator, &recovered.image)?;
    validate_cmra_identity_hints(
        recovered.header_hints,
        Some(CmraIdentityHints::from(locator)),
        &recovered.image,
    )?;
    let cmra_length = recovered.cmra_length;
    let authority = validate_recovered_recipient_wrap_terminal_authority(
        recovered.image,
        recovered.tuple,
        resolver,
        false,
    )?;
    Ok(RecipientWrapTerminalAuthorityCandidate {
        authority,
        anchor: to_usize(
            checked_u64_add(
                locator_offset,
                CRITICAL_RECOVERY_LOCATOR_LEN as u64,
                "locator anchor overflow",
            )?,
            "locator anchor overflow",
        )?,
        cmra_offset: locator.cmra_offset,
        cmra_length,
    })
}

fn parse_locator_cmra_authority_candidate_read_at(
    reader: &dyn ArchiveReadAt,
    locator_offset: u64,
    locator: CriticalRecoveryLocator,
    master_key: &MasterKey,
) -> Result<TerminalAuthorityCandidate, FormatError> {
    let tuple = CmraDecoderTuple::from(locator);
    validate_cmra_decoder_tuple(tuple)?;
    let expected_cmra_length = cmra_serialized_length(tuple)?;
    if locator.cmra_length as u64 != expected_cmra_length {
        return Err(FormatError::InvalidArchive("locator CMRA length mismatch"));
    }
    validate_locator_position(
        to_usize(locator_offset, "CriticalRecoveryLocator")?,
        locator,
    )?;
    let recovered = recover_cmra_read_at(
        reader,
        locator.cmra_offset,
        Some(tuple),
        CmraRecoveryMode::KeyHolding,
    )?;
    if recovered.tuple != tuple {
        return Err(FormatError::InvalidArchive("CMRA decoder tuple mismatch"));
    }
    if expected_cmra_length != recovered.cmra_length {
        return Err(FormatError::InvalidArchive("locator CMRA length mismatch"));
    }
    validate_locator_image_boundary(locator, &recovered.image)?;
    validate_cmra_identity_hints(
        recovered.header_hints,
        Some(CmraIdentityHints::from(locator)),
        &recovered.image,
    )?;
    let cmra_length = recovered.cmra_length;
    let authority =
        validate_recovered_terminal_authority(recovered.image, recovered.tuple, master_key, false)?;
    Ok(TerminalAuthorityCandidate {
        authority,
        anchor: to_usize(
            checked_u64_add(
                locator_offset,
                CRITICAL_RECOVERY_LOCATOR_LEN as u64,
                "locator anchor overflow",
            )?,
            "locator anchor overflow",
        )?,
        cmra_offset: locator.cmra_offset,
        cmra_length,
    })
}

fn parse_public_locator_cmra_candidate(
    bytes: &[u8],
    locator_offset: usize,
    locator: CriticalRecoveryLocator,
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeader<'_>,
) -> Result<PublicTerminalCandidate, FormatError> {
    let tuple = CmraDecoderTuple::from(locator);
    validate_cmra_decoder_tuple(tuple)?;
    let expected_cmra_length = cmra_serialized_length(tuple)?;
    if locator.cmra_length as u64 != expected_cmra_length {
        return Err(FormatError::InvalidArchive("locator CMRA length mismatch"));
    }
    validate_locator_position(locator_offset, locator)?;
    let recovered = recover_cmra(
        bytes,
        locator.cmra_offset,
        Some(tuple),
        CmraRecoveryMode::PublicNoKey,
    )?;
    if recovered.tuple != tuple {
        return Err(FormatError::InvalidArchive("CMRA decoder tuple mismatch"));
    }
    if expected_cmra_length != recovered.cmra_length {
        return Err(FormatError::InvalidArchive("locator CMRA length mismatch"));
    }
    validate_locator_image_boundary(locator, &recovered.image)?;
    validate_cmra_identity_hints(
        recovered.header_hints,
        Some(CmraIdentityHints::from(locator)),
        &recovered.image,
    )?;
    let terminal = validate_recovered_public_terminal(
        recovered.image,
        bytes,
        volume_header,
        crypto_header,
        false,
    )?;
    Ok(PublicTerminalCandidate {
        terminal,
        anchor: locator_offset
            .checked_add(CRITICAL_RECOVERY_LOCATOR_LEN)
            .ok_or(FormatError::InvalidArchive("locator anchor overflow"))?,
        cmra_offset: locator.cmra_offset,
        cmra_length: recovered.cmra_length,
    })
}

fn parse_locatorless_cmra_candidate(
    bytes: &[u8],
    cmra_offset: usize,
    context: KeyHoldingTerminalContext<'_>,
) -> Result<TerminalCandidate, FormatError> {
    let recovered = recover_cmra(
        bytes,
        cmra_offset as u64,
        None,
        CmraRecoveryMode::KeyHolding,
    )?;
    if recovered.image.body_bytes_before_cmra != cmra_offset as u64 {
        return Err(FormatError::InvalidArchive(
            "locatorless CMRA boundary mismatch",
        ));
    }
    if recovered
        .image
        .volume_trailer_offset
        .checked_add(VOLUME_TRAILER_LEN as u64)
        .ok_or(FormatError::InvalidArchive("CMRA boundary overflow"))?
        != cmra_offset as u64
    {
        return Err(FormatError::InvalidArchive(
            "locatorless trailer boundary mismatch",
        ));
    }
    validate_cmra_identity_hints(recovered.header_hints, None, &recovered.image)?;
    let terminal =
        validate_recovered_terminal(recovered.image, recovered.tuple, bytes, context, true)?;
    Ok(TerminalCandidate {
        terminal,
        anchor: cmra_offset
            .checked_add(to_usize(recovered.cmra_length, "CMRA")?)
            .ok_or(FormatError::InvalidArchive("CMRA anchor overflow"))?,
        locator_sequence: None,
        cmra_offset: cmra_offset as u64,
        cmra_length: recovered.cmra_length,
    })
}

fn parse_locatorless_cmra_candidate_read_at(
    reader: &dyn ArchiveReadAt,
    cmra_offset: u64,
    context: KeyHoldingTerminalContext<'_>,
) -> Result<TerminalCandidate, FormatError> {
    let recovered = recover_cmra_read_at(reader, cmra_offset, None, CmraRecoveryMode::KeyHolding)?;
    if recovered.image.body_bytes_before_cmra != cmra_offset {
        return Err(FormatError::InvalidArchive(
            "locatorless CMRA boundary mismatch",
        ));
    }
    if recovered
        .image
        .volume_trailer_offset
        .checked_add(VOLUME_TRAILER_LEN as u64)
        .ok_or(FormatError::InvalidArchive("CMRA boundary overflow"))?
        != cmra_offset
    {
        return Err(FormatError::InvalidArchive(
            "locatorless trailer boundary mismatch",
        ));
    }
    validate_cmra_identity_hints(recovered.header_hints, None, &recovered.image)?;
    let terminal = validate_recovered_terminal_read_at(
        recovered.image,
        recovered.tuple,
        reader,
        context,
        true,
    )?;
    Ok(TerminalCandidate {
        terminal,
        anchor: to_usize(
            checked_u64_add(cmra_offset, recovered.cmra_length, "CMRA anchor overflow")?,
            "CMRA anchor overflow",
        )?,
        locator_sequence: None,
        cmra_offset,
        cmra_length: recovered.cmra_length,
    })
}

fn parse_locatorless_cmra_authority_candidate(
    bytes: &[u8],
    cmra_offset: usize,
    master_key: &MasterKey,
) -> Result<TerminalAuthorityCandidate, FormatError> {
    let recovered = recover_cmra(
        bytes,
        cmra_offset as u64,
        None,
        CmraRecoveryMode::KeyHolding,
    )?;
    if recovered.image.body_bytes_before_cmra != cmra_offset as u64 {
        return Err(FormatError::InvalidArchive(
            "locatorless CMRA boundary mismatch",
        ));
    }
    if recovered
        .image
        .volume_trailer_offset
        .checked_add(VOLUME_TRAILER_LEN as u64)
        .ok_or(FormatError::InvalidArchive("CMRA boundary overflow"))?
        != cmra_offset as u64
    {
        return Err(FormatError::InvalidArchive(
            "locatorless trailer boundary mismatch",
        ));
    }
    validate_cmra_identity_hints(recovered.header_hints, None, &recovered.image)?;
    let cmra_length = recovered.cmra_length;
    let authority =
        validate_recovered_terminal_authority(recovered.image, recovered.tuple, master_key, true)?;
    Ok(TerminalAuthorityCandidate {
        authority,
        anchor: cmra_offset
            .checked_add(to_usize(cmra_length, "CMRA")?)
            .ok_or(FormatError::InvalidArchive("CMRA anchor overflow"))?,
        cmra_offset: cmra_offset as u64,
        cmra_length,
    })
}

fn parse_locatorless_cmra_recipient_wrap_authority_candidate<F>(
    bytes: &[u8],
    cmra_offset: usize,
    resolver: &mut F,
) -> Result<RecipientWrapTerminalAuthorityCandidate, FormatError>
where
    F: FnMut(
        RecipientWrapRecordContext<'_>,
    ) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
{
    let recovered = recover_cmra(
        bytes,
        cmra_offset as u64,
        None,
        CmraRecoveryMode::KeyHolding,
    )?;
    if recovered.image.body_bytes_before_cmra != cmra_offset as u64 {
        return Err(FormatError::InvalidArchive(
            "locatorless CMRA boundary mismatch",
        ));
    }
    if recovered
        .image
        .volume_trailer_offset
        .checked_add(VOLUME_TRAILER_LEN as u64)
        .ok_or(FormatError::InvalidArchive("CMRA boundary overflow"))?
        != cmra_offset as u64
    {
        return Err(FormatError::InvalidArchive(
            "locatorless trailer boundary mismatch",
        ));
    }
    validate_cmra_identity_hints(recovered.header_hints, None, &recovered.image)?;
    let cmra_length = recovered.cmra_length;
    let authority = validate_recovered_recipient_wrap_terminal_authority(
        recovered.image,
        recovered.tuple,
        resolver,
        true,
    )?;
    Ok(RecipientWrapTerminalAuthorityCandidate {
        authority,
        anchor: cmra_offset
            .checked_add(to_usize(cmra_length, "CMRA")?)
            .ok_or(FormatError::InvalidArchive("CMRA anchor overflow"))?,
        cmra_offset: cmra_offset as u64,
        cmra_length,
    })
}

fn parse_locatorless_cmra_recipient_wrap_authority_candidate_read_at<F>(
    reader: &dyn ArchiveReadAt,
    cmra_offset: u64,
    resolver: &mut F,
) -> Result<RecipientWrapTerminalAuthorityCandidate, FormatError>
where
    F: FnMut(
        RecipientWrapRecordContext<'_>,
    ) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
{
    let recovered = recover_cmra_read_at(reader, cmra_offset, None, CmraRecoveryMode::KeyHolding)?;
    if recovered.image.body_bytes_before_cmra != cmra_offset {
        return Err(FormatError::InvalidArchive(
            "locatorless CMRA boundary mismatch",
        ));
    }
    if recovered
        .image
        .volume_trailer_offset
        .checked_add(VOLUME_TRAILER_LEN as u64)
        .ok_or(FormatError::InvalidArchive("CMRA boundary overflow"))?
        != cmra_offset
    {
        return Err(FormatError::InvalidArchive(
            "locatorless trailer boundary mismatch",
        ));
    }
    validate_cmra_identity_hints(recovered.header_hints, None, &recovered.image)?;
    let cmra_length = recovered.cmra_length;
    let authority = validate_recovered_recipient_wrap_terminal_authority(
        recovered.image,
        recovered.tuple,
        resolver,
        true,
    )?;
    Ok(RecipientWrapTerminalAuthorityCandidate {
        authority,
        anchor: to_usize(
            checked_u64_add(cmra_offset, cmra_length, "CMRA anchor overflow")?,
            "CMRA anchor overflow",
        )?,
        cmra_offset,
        cmra_length,
    })
}

fn parse_locatorless_cmra_authority_candidate_read_at(
    reader: &dyn ArchiveReadAt,
    cmra_offset: u64,
    master_key: &MasterKey,
) -> Result<TerminalAuthorityCandidate, FormatError> {
    let recovered = recover_cmra_read_at(reader, cmra_offset, None, CmraRecoveryMode::KeyHolding)?;
    if recovered.image.body_bytes_before_cmra != cmra_offset {
        return Err(FormatError::InvalidArchive(
            "locatorless CMRA boundary mismatch",
        ));
    }
    if recovered
        .image
        .volume_trailer_offset
        .checked_add(VOLUME_TRAILER_LEN as u64)
        .ok_or(FormatError::InvalidArchive("CMRA boundary overflow"))?
        != cmra_offset
    {
        return Err(FormatError::InvalidArchive(
            "locatorless trailer boundary mismatch",
        ));
    }
    validate_cmra_identity_hints(recovered.header_hints, None, &recovered.image)?;
    let cmra_length = recovered.cmra_length;
    let authority =
        validate_recovered_terminal_authority(recovered.image, recovered.tuple, master_key, true)?;
    Ok(TerminalAuthorityCandidate {
        authority,
        anchor: to_usize(
            checked_u64_add(cmra_offset, cmra_length, "CMRA anchor overflow")?,
            "CMRA anchor overflow",
        )?,
        cmra_offset,
        cmra_length,
    })
}

fn parse_public_locatorless_cmra_candidate(
    bytes: &[u8],
    cmra_offset: usize,
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeader<'_>,
) -> Result<PublicTerminalCandidate, FormatError> {
    let recovered = recover_cmra(
        bytes,
        cmra_offset as u64,
        None,
        CmraRecoveryMode::PublicNoKey,
    )?;
    if recovered.image.body_bytes_before_cmra != cmra_offset as u64 {
        return Err(FormatError::InvalidArchive(
            "locatorless CMRA boundary mismatch",
        ));
    }
    if recovered
        .image
        .volume_trailer_offset
        .checked_add(VOLUME_TRAILER_LEN as u64)
        .ok_or(FormatError::InvalidArchive("CMRA boundary overflow"))?
        != cmra_offset as u64
    {
        return Err(FormatError::InvalidArchive(
            "locatorless trailer boundary mismatch",
        ));
    }
    validate_cmra_identity_hints(recovered.header_hints, None, &recovered.image)?;
    let terminal = validate_recovered_public_terminal(
        recovered.image,
        bytes,
        volume_header,
        crypto_header,
        true,
    )?;
    Ok(PublicTerminalCandidate {
        terminal,
        anchor: cmra_offset
            .checked_add(to_usize(recovered.cmra_length, "CMRA")?)
            .ok_or(FormatError::InvalidArchive("CMRA anchor overflow"))?,
        cmra_offset: cmra_offset as u64,
        cmra_length: recovered.cmra_length,
    })
}

fn validate_locator_position(
    locator_offset: usize,
    locator: CriticalRecoveryLocator,
) -> Result<(), FormatError> {
    if locator.cmra_offset != locator.body_bytes_before_cmra {
        return Err(FormatError::InvalidArchive(
            "locator CMRA boundary mismatch",
        ));
    }
    if locator
        .volume_trailer_offset
        .checked_add(VOLUME_TRAILER_LEN as u64)
        .ok_or(FormatError::InvalidArchive("locator trailer overflow"))?
        != locator.cmra_offset
    {
        return Err(FormatError::InvalidArchive(
            "locator trailer boundary mismatch",
        ));
    }
    let expected_offset = match locator.locator_sequence {
        1 => locator.cmra_offset.checked_add(locator.cmra_length as u64),
        0 => locator
            .cmra_offset
            .checked_add(locator.cmra_length as u64)
            .and_then(|value| value.checked_add(CRITICAL_RECOVERY_LOCATOR_LEN as u64)),
        _ => None,
    }
    .ok_or(FormatError::InvalidArchive("locator position overflow"))?;
    if expected_offset != locator_offset as u64 {
        return Err(FormatError::InvalidArchive(
            "locator position does not match sequence",
        ));
    }
    Ok(())
}

fn validate_locator_image_boundary(
    locator: CriticalRecoveryLocator,
    image: &CriticalMetadataImage,
) -> Result<(), FormatError> {
    if locator.volume_format_rev != image.volume_format_rev
        || locator.volume_trailer_offset != image.volume_trailer_offset
        || locator.body_bytes_before_cmra != image.body_bytes_before_cmra
        || image
            .volume_trailer_offset
            .checked_add(VOLUME_TRAILER_LEN as u64)
            .ok_or(FormatError::InvalidArchive("CMRA image boundary overflow"))?
            != locator.cmra_offset
    {
        return Err(FormatError::InvalidArchive(
            "locator and CMRA image boundaries differ",
        ));
    }
    Ok(())
}

fn validate_cmra_identity_hints(
    header_hints: Option<CmraIdentityHints>,
    locator_hints: Option<CmraIdentityHints>,
    image: &CriticalMetadataImage,
) -> Result<(), FormatError> {
    if let (Some(header), Some(locator)) = (header_hints, locator_hints) {
        if header != locator {
            return Err(FormatError::InvalidArchive(
                "CMRA header and locator identity hints differ",
            ));
        }
    }
    for hints in [header_hints, locator_hints].into_iter().flatten() {
        if hints.archive_uuid != image.archive_uuid
            || hints.session_id != image.session_id
            || hints.volume_index != image.volume_index
        {
            return Err(FormatError::InvalidArchive(
                "CMRA identity hints do not match recovered image",
            ));
        }
    }
    Ok(())
}

fn recover_cmra(
    bytes: &[u8],
    cmra_offset: u64,
    locator_tuple: Option<CmraDecoderTuple>,
    mode: CmraRecoveryMode,
) -> Result<RecoveredCmra, FormatError> {
    let offset = to_usize(cmra_offset, "CMRA")?;
    let header_bytes = slice(
        bytes,
        offset,
        CRITICAL_METADATA_RECOVERY_HEADER_LEN,
        "CriticalMetadataRecoveryHeader",
    )?;
    let (tuple, header_hints) = recover_cmra_header_tuple(header_bytes, locator_tuple)?;
    validate_cmra_decoder_tuple(tuple)?;
    let cmra_length = cmra_serialized_length(tuple)?;
    let cmra_len = to_usize(cmra_length, "CMRA")?;
    let cmra_bytes = slice(bytes, offset, cmra_len, "CMRA")?;
    recover_cmra_from_bytes(cmra_bytes, tuple, header_hints, cmra_length, mode)
}

fn recover_cmra_read_at(
    reader: &dyn ArchiveReadAt,
    cmra_offset: u64,
    locator_tuple: Option<CmraDecoderTuple>,
    mode: CmraRecoveryMode,
) -> Result<RecoveredCmra, FormatError> {
    let header_bytes = read_at_vec(
        reader,
        cmra_offset,
        CRITICAL_METADATA_RECOVERY_HEADER_LEN,
        "CriticalMetadataRecoveryHeader",
    )?;
    let (tuple, header_hints) = recover_cmra_header_tuple(&header_bytes, locator_tuple)?;
    validate_cmra_decoder_tuple(tuple)?;
    let cmra_length = cmra_serialized_length(tuple)?;
    let cmra_bytes = read_at_vec(reader, cmra_offset, to_usize(cmra_length, "CMRA")?, "CMRA")?;
    recover_cmra_from_bytes(&cmra_bytes, tuple, header_hints, cmra_length, mode)
}

fn recover_cmra_header_tuple(
    header_bytes: &[u8],
    locator_tuple: Option<CmraDecoderTuple>,
) -> Result<(CmraDecoderTuple, Option<CmraIdentityHints>), FormatError> {
    let parsed_header = CriticalMetadataRecoveryHeader::parse(header_bytes);
    Ok(match (parsed_header, locator_tuple) {
        (Ok(header), Some(locator_tuple)) => {
            let header_tuple = CmraDecoderTuple::from(header);
            if header_tuple != locator_tuple {
                return Err(FormatError::InvalidArchive("CMRA decoder tuple mismatch"));
            }
            (locator_tuple, Some(CmraIdentityHints::from(header)))
        }
        (Ok(header), None) => (
            CmraDecoderTuple::from(header),
            Some(CmraIdentityHints::from(header)),
        ),
        (Err(_), Some(tuple)) => (tuple, None),
        (Err(err), _) => return Err(err),
    })
}

fn recover_cmra_from_bytes(
    cmra_bytes: &[u8],
    tuple: CmraDecoderTuple,
    header_hints: Option<CmraIdentityHints>,
    cmra_length: u64,
    mode: CmraRecoveryMode,
) -> Result<RecoveredCmra, FormatError> {
    let shard_size = tuple.shard_size as usize;
    let mut data_shards = vec![None; tuple.data_shard_count as usize];
    let mut parity_shards = vec![None; tuple.parity_shard_count as usize];
    let mut cursor = CRITICAL_METADATA_RECOVERY_HEADER_LEN;
    for idx in 0..(tuple.data_shard_count as usize + tuple.parity_shard_count as usize) {
        let raw = slice(
            cmra_bytes,
            cursor,
            CRITICAL_METADATA_RECOVERY_SHARD_HEADER_LEN + shard_size,
            "CriticalMetadataRecoveryShard",
        )?;
        let shard = CriticalMetadataRecoveryShard::parse(raw, shard_size).ok();
        if let Some(shard) = shard {
            validate_cmra_shard(&shard, idx, tuple)?;
            if shard.shard_role == 0 {
                let data_slot = data_shards
                    .get_mut(idx)
                    .ok_or(FormatError::InvalidArchive("CMRA data shard out of range"))?;
                *data_slot = Some(shard.payload);
            } else {
                let parity_idx = idx - tuple.data_shard_count as usize;
                let parity_slot =
                    parity_shards
                        .get_mut(parity_idx)
                        .ok_or(FormatError::InvalidArchive(
                            "CMRA parity shard out of range",
                        ))?;
                *parity_slot = Some(shard.payload);
            }
        }
        cursor = checked_add(
            cursor,
            CRITICAL_METADATA_RECOVERY_SHARD_HEADER_LEN + shard_size,
            "CriticalMetadataRecoveryShard",
        )?;
    }
    let repaired = repair_data_gf16(&data_shards, &parity_shards, shard_size)?;
    let mut image_bytes = Vec::with_capacity(tuple.image_length as usize);
    for shard in repaired {
        image_bytes.extend_from_slice(&shard);
    }
    image_bytes.truncate(tuple.image_length as usize);
    if sha256_bytes(&image_bytes) != tuple.image_sha256 {
        return Err(FormatError::InvalidArchive("CMRA image SHA-256 mismatch"));
    }
    let image = CriticalMetadataImage::parse(&image_bytes)?;
    validate_critical_metadata_image(&image, mode)?;
    Ok(RecoveredCmra {
        image,
        tuple,
        header_hints,
        cmra_length,
    })
}

fn validate_cmra_decoder_tuple(tuple: CmraDecoderTuple) -> Result<(), FormatError> {
    let shard_size = tuple.shard_size as u64;
    if !(512..=4096).contains(&shard_size) || shard_size % 2 != 0 {
        return Err(FormatError::InvalidArchive("CMRA shard_size is invalid"));
    }
    let image_length = tuple.image_length as u64;
    let min = critical_image_min();
    let cap = critical_image_cap()?;
    if image_length < min || image_length > cap {
        return Err(FormatError::InvalidArchive(
            "CMRA image_length is outside bounds",
        ));
    }
    let expected_data_shards = ceil_div_u64(image_length, shard_size)?;
    if expected_data_shards == 0 || expected_data_shards != tuple.data_shard_count as u64 {
        return Err(FormatError::InvalidArchive(
            "CMRA data_shard_count does not match image length",
        ));
    }
    let max_parity = 2u64.max(ceil_div_u64(
        checked_u64_mul(
            expected_data_shards,
            READER_MAX_CMRA_PARITY_PCT as u64,
            "CMRA parity overflow",
        )?,
        100,
    )?);
    if tuple.parity_shard_count as u64 > max_parity {
        return Err(FormatError::ReaderResourceLimitExceeded {
            field: "CMRA parity shard count",
            cap: max_parity,
            actual: tuple.parity_shard_count as u64,
        });
    }
    let total = expected_data_shards
        .checked_add(tuple.parity_shard_count as u64)
        .ok_or(FormatError::InvalidArchive("CMRA shard count overflow"))?;
    if total > 65_535 {
        return Err(FormatError::FecTooManyShards(total as usize));
    }
    Ok(())
}

fn validate_cmra_writer_parity_lower_bound(
    tuple: CmraDecoderTuple,
    bit_rot_buffer_pct: u8,
) -> Result<(), FormatError> {
    let min_parity = 2u64.max(ceil_div_u64(
        checked_u64_mul(
            tuple.data_shard_count as u64,
            bit_rot_buffer_pct as u64,
            "CMRA parity lower-bound overflow",
        )?,
        100,
    )?);
    if (tuple.parity_shard_count as u64) < min_parity {
        return Err(FormatError::InvalidArchive(
            "CMRA parity shard count is below authenticated bit-rot lower bound",
        ));
    }
    Ok(())
}

fn validate_cmra_shard(
    shard: &CriticalMetadataRecoveryShard,
    serialized_idx: usize,
    tuple: CmraDecoderTuple,
) -> Result<(), FormatError> {
    if shard.shard_index as usize != serialized_idx {
        return Err(FormatError::InvalidArchive(
            "CMRA shards are not in canonical order",
        ));
    }
    let data_count = tuple.data_shard_count as usize;
    let shard_size = tuple.shard_size as usize;
    if serialized_idx < data_count {
        if shard.shard_role != 0 {
            return Err(FormatError::InvalidArchive(
                "CMRA data shard has wrong role",
            ));
        }
        let expected_len = if serialized_idx + 1 == data_count {
            let used = tuple.image_length as usize - serialized_idx * shard_size;
            if used == 0 {
                shard_size
            } else {
                used
            }
        } else {
            shard_size
        };
        if shard.shard_payload_length as usize != expected_len {
            return Err(FormatError::InvalidArchive(
                "CMRA data shard payload length is non-canonical",
            ));
        }
        if serialized_idx + 1 == data_count
            && shard.payload[expected_len..].iter().any(|byte| *byte != 0)
        {
            return Err(FormatError::InvalidArchive(
                "CMRA final data shard padding is non-zero",
            ));
        }
    } else {
        if shard.shard_role != 1 {
            return Err(FormatError::InvalidArchive(
                "CMRA parity shard has wrong role",
            ));
        }
        if shard.shard_payload_length as usize != shard_size {
            return Err(FormatError::InvalidArchive(
                "CMRA parity shard payload length is non-canonical",
            ));
        }
    }
    Ok(())
}

fn validate_critical_metadata_image(
    image: &CriticalMetadataImage,
    mode: CmraRecoveryMode,
) -> Result<(), FormatError> {
    let root_auth_present = image.layout_flags & 0x0000_0001 != 0;
    let key_wrap_layout_present = image.layout_flags & 0x0000_0002 != 0;
    let key_wrap_region = image.region(6);
    if key_wrap_layout_present != key_wrap_region.is_some() {
        return Err(FormatError::InvalidArchive(
            "CriticalMetadataImage key-wrap layout flag mismatch",
        ));
    }
    let key_wrap_present = key_wrap_layout_present;
    if image.volume_header_offset != 0
        || image.volume_header_length != VOLUME_HEADER_LEN as u32
        || image.crypto_header_offset != VOLUME_HEADER_LEN as u64
        || image.manifest_footer_length != MANIFEST_FOOTER_LEN as u32
        || image.volume_trailer_length != VOLUME_TRAILER_LEN as u32
        || image.body_bytes_before_cmra
            != image
                .volume_trailer_offset
                .checked_add(VOLUME_TRAILER_LEN as u64)
                .ok_or(FormatError::InvalidArchive("CMRA image boundary overflow"))?
    {
        return Err(FormatError::InvalidArchive(
            "CriticalMetadataImage fixed layout is invalid",
        ));
    }
    if root_auth_present {
        if image.root_auth_footer_offset == 0
            || image.root_auth_footer_length == 0
            || image.root_auth_footer_length > READER_MAX_ROOT_AUTH_FOOTER_LEN
        {
            return Err(FormatError::InvalidArchive(
                "CriticalMetadataImage root-auth range is invalid",
            ));
        }
    } else if image.root_auth_footer_offset != 0
        || image.root_auth_footer_length != 0
        || image.root_auth_footer_sha256 != [0u8; 32]
    {
        return Err(FormatError::InvalidArchive(
            "CriticalMetadataImage root-auth fields must be zero when absent",
        ));
    }
    let block_record_len = image_block_record_len_from_region(image)?;
    let block_record_len_u64 = u64::try_from(block_record_len)
        .map_err(|_| FormatError::InvalidArchive("BlockRecord length overflow"))?;
    match mode {
        CmraRecoveryMode::KeyHolding => {
            let expected_len = image.block_count.checked_mul(block_record_len_u64).ok_or(
                FormatError::InvalidArchive("BlockRecord region length overflow"),
            )?;
            if image.block_records_length != expected_len {
                return Err(FormatError::InvalidArchive(
                    "CriticalMetadataImage terminal equations are invalid",
                ));
            }
        }
        CmraRecoveryMode::PublicNoKey => {
            if image.block_records_length % block_record_len_u64 != 0 {
                return Err(FormatError::InvalidArchive(
                    "CriticalMetadataImage BlockRecord region is not aligned",
                ));
            }
        }
    }
    let crypto_header_end = image
        .crypto_header_offset
        .checked_add(image.crypto_header_length as u64)
        .ok_or(FormatError::InvalidArchive(
            "CryptoHeader boundary overflow",
        ))?;
    let expected_block_records_offset = if key_wrap_present {
        let key_wrap_region = key_wrap_region.ok_or(FormatError::InvalidArchive(
            "missing CriticalMetadataImage key-wrap region",
        ))?;
        if image.key_wrap_table_offset != crypto_header_end
            || image.key_wrap_table_length == 0
            || key_wrap_region.offset != image.key_wrap_table_offset
            || key_wrap_region.bytes.len() != image.key_wrap_table_length as usize
        {
            return Err(FormatError::InvalidArchive(
                "CriticalMetadataImage key-wrap region is malformed",
            ));
        }
        image
            .key_wrap_table_offset
            .checked_add(image.key_wrap_table_length as u64)
            .ok_or(FormatError::InvalidArchive(
                "KeyWrapTableV1 boundary overflow",
            ))?
    } else {
        if image.key_wrap_table_offset != 0
            || image.key_wrap_table_length != 0
            || image.key_wrap_table_sha256 != [0u8; 32]
        {
            return Err(FormatError::InvalidArchive(
                "CriticalMetadataImage key-wrap fields must be zero when absent",
            ));
        }
        crypto_header_end
    };
    if image.block_records_offset != expected_block_records_offset
        || image.manifest_footer_offset
            != image
                .block_records_offset
                .checked_add(image.block_records_length)
                .ok_or(FormatError::InvalidArchive(
                    "ManifestFooter boundary overflow",
                ))?
    {
        return Err(FormatError::InvalidArchive(
            "CriticalMetadataImage terminal equations are invalid",
        ));
    }
    let manifest_end = image
        .manifest_footer_offset
        .checked_add(MANIFEST_FOOTER_LEN as u64)
        .ok_or(FormatError::InvalidArchive(
            "RootAuthFooter boundary overflow",
        ))?;
    if root_auth_present {
        if image.root_auth_footer_offset != manifest_end
            || image
                .root_auth_footer_offset
                .checked_add(image.root_auth_footer_length as u64)
                .ok_or(FormatError::InvalidArchive(
                    "VolumeTrailer boundary overflow",
                ))?
                != image.volume_trailer_offset
        {
            return Err(FormatError::InvalidArchive(
                "CriticalMetadataImage root-auth terminal equations are invalid",
            ));
        }
    } else if image.volume_trailer_offset != manifest_end {
        return Err(FormatError::InvalidArchive(
            "CriticalMetadataImage unsigned terminal equations are invalid",
        ));
    }
    let expected_types: &[u16] = match (key_wrap_present, root_auth_present) {
        (false, false) => &[1, 2, 3, 5],
        (false, true) => &[1, 2, 3, 4, 5],
        (true, false) => &[1, 2, 6, 3, 5],
        (true, true) => &[1, 2, 6, 3, 4, 5],
    };
    if image.regions.len() != expected_types.len()
        || image
            .regions
            .iter()
            .map(|region| region.region_type)
            .ne(expected_types.iter().copied())
    {
        return Err(FormatError::InvalidArchive(
            "CriticalMetadataImage regions are not canonical",
        ));
    }
    validate_image_region(
        image,
        1,
        image.volume_header_offset,
        image.volume_header_length,
    )?;
    validate_image_region(
        image,
        2,
        image.crypto_header_offset,
        image.crypto_header_length,
    )?;
    validate_image_region(
        image,
        3,
        image.manifest_footer_offset,
        image.manifest_footer_length,
    )?;
    if key_wrap_present {
        validate_image_region(
            image,
            6,
            image.key_wrap_table_offset,
            image.key_wrap_table_length,
        )?;
    }
    if root_auth_present {
        validate_image_region(
            image,
            4,
            image.root_auth_footer_offset,
            image.root_auth_footer_length,
        )?;
    }
    validate_image_region(
        image,
        5,
        image.volume_trailer_offset,
        image.volume_trailer_length,
    )?;
    if sha256_region(image, 1)? != image.volume_header_sha256
        || sha256_region(image, 2)? != image.crypto_header_sha256
        || (key_wrap_present && sha256_region(image, 6)? != image.key_wrap_table_sha256)
        || (!key_wrap_present && image.key_wrap_table_sha256 != [0u8; 32])
        || sha256_region(image, 3)? != image.manifest_footer_sha256
        || (root_auth_present && sha256_region(image, 4)? != image.root_auth_footer_sha256)
        || (!root_auth_present && image.root_auth_footer_sha256 != [0u8; 32])
        || sha256_region(image, 5)? != image.volume_trailer_sha256
    {
        return Err(FormatError::InvalidArchive(
            "CriticalMetadataImage region digest mismatch",
        ));
    }
    Ok(())
}

fn image_block_record_len_from_region(image: &CriticalMetadataImage) -> Result<usize, FormatError> {
    let crypto_region = image
        .region(2)
        .ok_or(FormatError::InvalidArchive("missing CryptoHeader region"))?;
    let crypto = CryptoHeader::parse(&crypto_region.bytes, image.crypto_header_length)?;
    crypto.fixed.validate_supported_profile()?;
    Ok(crypto.fixed.block_size as usize + BLOCK_RECORD_FRAMING_LEN)
}

fn validate_image_region(
    image: &CriticalMetadataImage,
    region_type: u16,
    offset: u64,
    length: u32,
) -> Result<(), FormatError> {
    let region = image
        .region(region_type)
        .ok_or(FormatError::InvalidArchive(
            "missing CriticalMetadataImage region",
        ))?;
    if region.offset != offset || region.bytes.len() != length as usize {
        return Err(FormatError::InvalidArchive(
            "CriticalMetadataImage region range mismatch",
        ));
    }
    Ok(())
}

fn validate_image_identity(
    image: &CriticalMetadataImage,
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
) -> Result<(), FormatError> {
    if image.volume_format_rev != volume_header.volume_format_rev
        || image.archive_uuid != volume_header.archive_uuid
        || image.session_id != volume_header.session_id
        || image.volume_index != volume_header.volume_index
        || image.stripe_width != volume_header.stripe_width
        || image.stripe_width != crypto_header.stripe_width
    {
        return Err(FormatError::InvalidArchive(
            "CriticalMetadataImage identity does not match selected volume",
        ));
    }
    Ok(())
}

fn validate_image_key_wrap_table(
    image: &CriticalMetadataImage,
    volume_header: &VolumeHeader,
    kdf_params: &KdfParams,
) -> Result<(), FormatError> {
    match kdf_params {
        KdfParams::RecipientWrap {
            key_wrap_table_length,
            key_wrap_table_record_count,
            key_wrap_table_digest,
            ..
        } => {
            if image.layout_flags & 0x0000_0002 == 0
                || image.key_wrap_table_length != *key_wrap_table_length
            {
                return Err(FormatError::InvalidArchive(
                    "CriticalMetadataImage key-wrap fields do not match KdfParams",
                ));
            }
            let region = image.region(6).ok_or(FormatError::InvalidArchive(
                "missing CriticalMetadataImage key-wrap region",
            ))?;
            if region.offset != image.key_wrap_table_offset
                || region.bytes.len() != *key_wrap_table_length as usize
            {
                return Err(FormatError::InvalidArchive(
                    "CriticalMetadataImage key-wrap region is malformed",
                ));
            }
            if compute_key_wrap_table_digest(*key_wrap_table_length, &region.bytes)
                != *key_wrap_table_digest
            {
                return Err(FormatError::IntegrityDigestMismatch {
                    structure: "KeyWrapTableV1",
                });
            }
            KeyWrapTableV1::parse(
                &region.bytes,
                &volume_header.archive_uuid,
                &volume_header.session_id,
                *key_wrap_table_length,
                *key_wrap_table_record_count,
            )?;
            Ok(())
        }
        _ => {
            if image.layout_flags & 0x0000_0002 != 0
                || image.region(6).is_some()
                || image.key_wrap_table_offset != 0
                || image.key_wrap_table_length != 0
                || image.key_wrap_table_sha256 != [0u8; 32]
            {
                return Err(FormatError::InvalidArchive(
                    "CriticalMetadataImage key-wrap fields must be zero when absent",
                ));
            }
            Ok(())
        }
    }
}

fn sha256_region(image: &CriticalMetadataImage, region_type: u16) -> Result<[u8; 32], FormatError> {
    Ok(sha256_bytes(
        &image
            .region(region_type)
            .ok_or(FormatError::InvalidArchive(
                "missing CriticalMetadataImage region",
            ))?
            .bytes,
    ))
}

fn validate_recovered_terminal_authority(
    image: CriticalMetadataImage,
    tuple: CmraDecoderTuple,
    master_key: &MasterKey,
    require_cmra_boundary_magic: bool,
) -> Result<RecoveredTerminalAuthority, FormatError> {
    let volume_header_region = image
        .region(1)
        .ok_or(FormatError::InvalidArchive("missing VolumeHeader region"))?;
    let volume_header = VolumeHeader::parse(&volume_header_region.bytes)?;
    let crypto_region = image
        .region(2)
        .ok_or(FormatError::InvalidArchive("missing CryptoHeader region"))?;
    let crypto_header_bytes = crypto_region.bytes.clone();
    let parsed_crypto = CryptoHeader::parse(&crypto_header_bytes, image.crypto_header_length)?;
    let kdf_params = parsed_crypto.kdf_params.clone();
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
    validate_seekable_supported_volume(
        &volume_header,
        &parsed_crypto.fixed,
        &parsed_crypto.extensions,
    )?;
    validate_crypto_class_parity_exactness(&parsed_crypto.fixed)?;
    let crypto_header = parsed_crypto.fixed.clone();
    if crypto_header.bit_rot_buffer_pct == 0 {
        return Err(FormatError::InvalidArchive(
            "CMRA startup recovery requires a nonzero bit-rot budget",
        ));
    }
    drop(parsed_crypto);

    let terminal = validate_recovered_terminal_inner(
        image,
        tuple,
        require_cmra_boundary_magic,
        true,
        KeyHoldingTerminalContext {
            subkeys: &subkeys,
            volume_header: &volume_header,
            crypto_header: &crypto_header,
            crypto_header_bytes: &crypto_header_bytes,
        },
    )?;
    Ok(RecoveredTerminalAuthority {
        terminal,
        volume_header,
        crypto_header,
        crypto_header_bytes,
        subkeys,
        kdf_params,
    })
}

fn validate_recovered_recipient_wrap_terminal_authority<F>(
    image: CriticalMetadataImage,
    tuple: CmraDecoderTuple,
    resolver: &mut F,
    require_cmra_boundary_magic: bool,
) -> Result<RecoveredRecipientWrapTerminalAuthority, FormatError>
where
    F: FnMut(
        RecipientWrapRecordContext<'_>,
    ) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
{
    let volume_header_region = image
        .region(1)
        .ok_or(FormatError::InvalidArchive("missing VolumeHeader region"))?;
    let volume_header = VolumeHeader::parse(&volume_header_region.bytes)?;
    let crypto_region = image
        .region(2)
        .ok_or(FormatError::InvalidArchive("missing CryptoHeader region"))?;
    let crypto_header_bytes = crypto_region.bytes.clone();
    let parsed_crypto = CryptoHeader::parse(&crypto_header_bytes, image.crypto_header_length)?;
    if !matches!(parsed_crypto.kdf_params, KdfParams::RecipientWrap { .. })
        || !parsed_crypto.fixed.aead_algo.is_encrypted()
    {
        return Err(FormatError::KeyMaterialMismatch);
    }
    validate_seekable_supported_volume(&volume_header, &parsed_crypto.fixed, &[])?;
    validate_crypto_class_parity_exactness(&parsed_crypto.fixed)?;
    if parsed_crypto.fixed.bit_rot_buffer_pct == 0 {
        return Err(FormatError::InvalidArchive(
            "CMRA startup recovery requires a nonzero bit-rot budget",
        ));
    }
    validate_cmra_writer_parity_lower_bound(tuple, parsed_crypto.fixed.bit_rot_buffer_pct)?;
    validate_image_key_wrap_table(&image, &volume_header, &parsed_crypto.kdf_params)?;
    let key_wrap_region = image.region(6).ok_or(FormatError::InvalidArchive(
        "missing CriticalMetadataImage key-wrap region",
    ))?;
    let startup_key_wrap_table = parse_startup_key_wrap_table_bytes(
        &volume_header,
        &parsed_crypto.kdf_params,
        key_wrap_region.bytes.clone(),
    )?;
    let subkeys = recipient_wrap_subkeys_from_table(
        &volume_header,
        &parsed_crypto,
        &startup_key_wrap_table.table,
        resolver,
    )?;
    parsed_crypto.validate_extension_semantics()?;
    reject_unsupported_raw_stream_profile(&parsed_crypto.extensions)?;
    let crypto_header = parsed_crypto.fixed.clone();

    let terminal = validate_recovered_terminal_inner(
        image,
        tuple,
        require_cmra_boundary_magic,
        true,
        KeyHoldingTerminalContext {
            subkeys: &subkeys,
            volume_header: &volume_header,
            crypto_header: &crypto_header,
            crypto_header_bytes: &crypto_header_bytes,
        },
    )?;
    Ok(RecoveredRecipientWrapTerminalAuthority {
        terminal,
        volume_header,
        crypto_header,
        crypto_header_bytes,
        key_wrap_table_bytes: startup_key_wrap_table.bytes,
        block_records_start: startup_key_wrap_table.block_records_start,
        subkeys,
    })
}

fn validate_recovered_terminal(
    image: CriticalMetadataImage,
    tuple: CmraDecoderTuple,
    bytes: &[u8],
    context: KeyHoldingTerminalContext<'_>,
    require_cmra_boundary_magic: bool,
) -> Result<V41Terminal, FormatError> {
    let cmra_offset = to_usize(image.body_bytes_before_cmra, "CMRA")?;
    let cmra_boundary_magic_ok = bytes.get(cmra_offset..cmra_offset + 4) == Some(b"TZCR");
    validate_recovered_terminal_inner(
        image,
        tuple,
        require_cmra_boundary_magic,
        cmra_boundary_magic_ok,
        context,
    )
}

fn validate_recovered_terminal_read_at(
    image: CriticalMetadataImage,
    tuple: CmraDecoderTuple,
    reader: &dyn ArchiveReadAt,
    context: KeyHoldingTerminalContext<'_>,
    require_cmra_boundary_magic: bool,
) -> Result<V41Terminal, FormatError> {
    let mut magic = [0u8; 4];
    reader.read_exact_at(image.body_bytes_before_cmra, &mut magic)?;
    validate_recovered_terminal_inner(
        image,
        tuple,
        require_cmra_boundary_magic,
        magic == *b"TZCR",
        context,
    )
}

fn validate_recovered_terminal_inner(
    image: CriticalMetadataImage,
    tuple: CmraDecoderTuple,
    require_cmra_boundary_magic: bool,
    cmra_boundary_magic_ok: bool,
    context: KeyHoldingTerminalContext<'_>,
) -> Result<V41Terminal, FormatError> {
    let subkeys = context.subkeys;
    let volume_header = context.volume_header;
    let crypto_header = context.crypto_header;
    let volume_header_region = image
        .region(1)
        .ok_or(FormatError::InvalidArchive("missing VolumeHeader region"))?;
    let recovered_volume_header = VolumeHeader::parse(&volume_header_region.bytes)?;
    if &recovered_volume_header != volume_header {
        return Err(FormatError::InvalidArchive(
            "CMRA VolumeHeader differs from parsed VolumeHeader",
        ));
    }
    validate_image_identity(&image, volume_header, crypto_header)?;
    let crypto_region = image
        .region(2)
        .ok_or(FormatError::InvalidArchive("missing CryptoHeader region"))?;
    let recovered_crypto = CryptoHeader::parse(&crypto_region.bytes, image.crypto_header_length)?;
    if recovered_crypto.fixed != *crypto_header {
        return Err(FormatError::InvalidArchive(
            "CMRA CryptoHeader differs from parsed CryptoHeader",
        ));
    }
    let recovered_pre_hmac_len = crypto_region
        .bytes
        .len()
        .checked_sub(CRYPTO_HEADER_HMAC_LEN)
        .ok_or(FormatError::InvalidArchive(
            "CMRA CryptoHeader is too short",
        ))?;
    let parsed_pre_hmac_len = context
        .crypto_header_bytes
        .len()
        .checked_sub(CRYPTO_HEADER_HMAC_LEN)
        .ok_or(FormatError::InvalidArchive("CryptoHeader is too short"))?;
    if recovered_pre_hmac_len != parsed_pre_hmac_len
        || crypto_region.bytes[..recovered_pre_hmac_len]
            != context.crypto_header_bytes[..parsed_pre_hmac_len]
    {
        return Err(FormatError::InvalidArchive(
            "CMRA CryptoHeader differs from parsed CryptoHeader",
        ));
    }
    verify_integrity_tag(
        HmacDomain::CryptoHeader,
        recovered_crypto.fixed.aead_algo,
        volume_header.volume_format_rev,
        Some(&subkeys.mac_key),
        &volume_header.archive_uuid,
        &volume_header.session_id,
        recovered_crypto.hmac_covered_bytes,
        &recovered_crypto.header_hmac,
    )?;
    validate_cmra_writer_parity_lower_bound(tuple, recovered_crypto.fixed.bit_rot_buffer_pct)?;
    recovered_crypto.validate_extension_semantics()?;
    validate_image_key_wrap_table(&image, volume_header, &recovered_crypto.kdf_params)?;

    let manifest_region = image
        .region(3)
        .ok_or(FormatError::InvalidArchive("missing ManifestFooter region"))?;
    let manifest_footer = ManifestFooter::parse(&manifest_region.bytes)?;
    validate_manifest_footer(
        volume_header,
        crypto_header,
        &manifest_footer,
        subkeys,
        volume_header.volume_format_rev,
        &manifest_region.bytes,
    )?;
    manifest_footer.validate_index_root_extent(crypto_header.block_size)?;

    let root_auth_footer = if image.layout_flags & 0x0000_0001 != 0 {
        let root_auth_region = image
            .region(4)
            .ok_or(FormatError::InvalidArchive("missing RootAuthFooter region"))?;
        let footer = RootAuthFooterV1::parse(&root_auth_region.bytes)?;
        if footer.format_version != volume_header.format_version
            || footer.volume_format_rev != volume_header.volume_format_rev
        {
            return Err(FormatError::InvalidArchive(
                "RootAuthFooter format/revision does not match VolumeHeader",
            ));
        }
        if footer.archive_uuid != volume_header.archive_uuid
            || footer.session_id != volume_header.session_id
            || footer.footer_length()? != image.root_auth_footer_length
        {
            return Err(FormatError::InvalidArchive(
                "RootAuthFooter identity or length does not match terminal image",
            ));
        }
        Some(footer)
    } else {
        None
    };

    let trailer_region = image
        .region(5)
        .ok_or(FormatError::InvalidArchive("missing VolumeTrailer region"))?;
    let trailer = VolumeTrailer::parse(&trailer_region.bytes)?;
    verify_integrity_tag(
        HmacDomain::VolumeTrailer,
        crypto_header.aead_algo,
        volume_header.volume_format_rev,
        Some(&subkeys.mac_key),
        &volume_header.archive_uuid,
        &volume_header.session_id,
        &trailer_region.bytes[..TRAILER_HMAC_COVERED_LEN],
        &trailer.trailer_hmac,
    )?;
    validate_trailer_identity(volume_header, &trailer)?;
    validate_v41_trailer_equations(&image, &trailer)?;

    if require_cmra_boundary_magic && !cmra_boundary_magic_ok {
        return Err(FormatError::InvalidArchive("CMRA is not at image boundary"));
    }

    let manifest_footer_bytes = manifest_region.bytes.clone();
    let root_auth_footer_bytes = image.region(4).map(|region| region.bytes.clone());
    Ok(V41Terminal {
        image,
        manifest_footer_bytes,
        root_auth_footer_bytes,
        root_auth_footer,
        volume_trailer: trailer,
    })
}

fn validate_recovered_public_terminal(
    image: CriticalMetadataImage,
    bytes: &[u8],
    volume_header: &VolumeHeader,
    public_crypto_header: &CryptoHeader<'_>,
    require_cmra_boundary_magic: bool,
) -> Result<V41PublicTerminal, FormatError> {
    if image.layout_flags & 0x0000_0001 == 0 {
        return Err(FormatError::ReaderUnsupported(
            "public no-key verification requires root-auth",
        ));
    }
    let volume_header_region = image
        .region(1)
        .ok_or(FormatError::InvalidArchive("missing VolumeHeader region"))?;
    let recovered_volume_header = VolumeHeader::parse(&volume_header_region.bytes)?;
    if &recovered_volume_header != volume_header {
        return Err(FormatError::InvalidArchive(
            "CMRA VolumeHeader differs from parsed VolumeHeader",
        ));
    }
    validate_image_identity(&image, volume_header, &public_crypto_header.fixed)?;
    let crypto_region = image
        .region(2)
        .ok_or(FormatError::InvalidArchive("missing CryptoHeader region"))?;
    let recovered_crypto = CryptoHeader::parse(&crypto_region.bytes, image.crypto_header_length)?;
    if !public_crypto_headers_agree(&recovered_crypto.fixed, &public_crypto_header.fixed)
        || !public_kdf_profiles_agree(
            &recovered_crypto.kdf_params,
            &public_crypto_header.kdf_params,
        )
    {
        return Err(FormatError::InvalidArchive(
            "CMRA CryptoHeader differs from parsed CryptoHeader",
        ));
    }
    recovered_crypto.validate_extension_semantics()?;
    validate_image_key_wrap_table(&image, volume_header, &recovered_crypto.kdf_params)?;

    image
        .region(3)
        .ok_or(FormatError::InvalidArchive("missing ManifestFooter region"))?;

    let root_auth_region = image
        .region(4)
        .ok_or(FormatError::InvalidArchive("missing RootAuthFooter region"))?;
    let root_auth_footer = RootAuthFooterV1::parse(&root_auth_region.bytes)?;
    if root_auth_footer.format_version != volume_header.format_version
        || root_auth_footer.volume_format_rev != volume_header.volume_format_rev
    {
        return Err(FormatError::InvalidArchive(
            "public RootAuthFooter format/revision does not match VolumeHeader",
        ));
    }
    if root_auth_footer.archive_uuid != volume_header.archive_uuid
        || root_auth_footer.session_id != volume_header.session_id
        || root_auth_footer.footer_length()? != image.root_auth_footer_length
    {
        return Err(FormatError::InvalidArchive(
            "public RootAuthFooter identity or length does not match terminal image",
        ));
    }

    let trailer_region = image
        .region(5)
        .ok_or(FormatError::InvalidArchive("missing VolumeTrailer region"))?;
    let trailer = VolumeTrailer::parse(&trailer_region.bytes)?;
    validate_trailer_identity(volume_header, &trailer)?;
    validate_v41_public_trailer_profile(&image, &trailer)?;

    let cmra_offset = to_usize(image.body_bytes_before_cmra, "CMRA")?;
    if require_cmra_boundary_magic && bytes.get(cmra_offset..cmra_offset + 4) != Some(b"TZCR") {
        return Err(FormatError::InvalidArchive("CMRA is not at image boundary"));
    }

    let root_auth_footer_bytes = root_auth_region.bytes.clone();
    Ok(V41PublicTerminal {
        image,
        root_auth_footer_bytes,
        root_auth_footer,
    })
}

fn validate_v41_trailer_equations(
    image: &CriticalMetadataImage,
    trailer: &VolumeTrailer,
) -> Result<(), FormatError> {
    let root_auth_present = image.layout_flags & 0x0000_0001 != 0;
    if trailer.bytes_written != image.volume_trailer_offset
        || trailer.manifest_footer_offset != image.manifest_footer_offset
        || trailer.manifest_footer_length != MANIFEST_FOOTER_LEN as u32
        || trailer.block_count != image.block_count
    {
        return Err(FormatError::InvalidArchive(
            "VolumeTrailer does not match v41 terminal layout",
        ));
    }
    if root_auth_present {
        if trailer.root_auth_flags != 0x0000_0001
            || trailer.root_auth_footer_offset != image.root_auth_footer_offset
            || trailer.root_auth_footer_length != image.root_auth_footer_length
            || image.root_auth_footer_offset
                != image
                    .manifest_footer_offset
                    .checked_add(MANIFEST_FOOTER_LEN as u64)
                    .ok_or(FormatError::InvalidArchive(
                        "RootAuthFooter trailer boundary overflow",
                    ))?
            || image
                .root_auth_footer_offset
                .checked_add(image.root_auth_footer_length as u64)
                .ok_or(FormatError::InvalidArchive(
                    "RootAuthFooter trailer boundary overflow",
                ))?
                != image.volume_trailer_offset
        {
            return Err(FormatError::InvalidArchive(
                "VolumeTrailer root-auth fields do not match v41 terminal layout",
            ));
        }
    } else if trailer.root_auth_footer_offset != 0
        || trailer.root_auth_footer_length != 0
        || trailer.root_auth_flags != 0
    {
        return Err(FormatError::InvalidArchive(
            "VolumeTrailer root-auth fields must be zero when absent",
        ));
    }
    Ok(())
}

fn validate_v41_public_trailer_profile(
    image: &CriticalMetadataImage,
    trailer: &VolumeTrailer,
) -> Result<(), FormatError> {
    if trailer.bytes_written != image.volume_trailer_offset
        || trailer.manifest_footer_offset != image.manifest_footer_offset
        || trailer.manifest_footer_length != MANIFEST_FOOTER_LEN as u32
    {
        return Err(FormatError::InvalidArchive(
            "VolumeTrailer does not match v41 public terminal layout",
        ));
    }
    if trailer.root_auth_flags != 0x0000_0001
        || trailer.root_auth_footer_offset == 0
        || trailer.root_auth_footer_length == 0
        || trailer.root_auth_footer_length > READER_MAX_ROOT_AUTH_FOOTER_LEN
        || trailer.root_auth_footer_offset != image.root_auth_footer_offset
        || trailer.root_auth_footer_length != image.root_auth_footer_length
        || image.root_auth_footer_offset
            != image
                .manifest_footer_offset
                .checked_add(MANIFEST_FOOTER_LEN as u64)
                .ok_or(FormatError::InvalidArchive(
                    "RootAuthFooter trailer boundary overflow",
                ))?
        || image
            .root_auth_footer_offset
            .checked_add(image.root_auth_footer_length as u64)
            .ok_or(FormatError::InvalidArchive(
                "RootAuthFooter trailer boundary overflow",
            ))?
            != image.volume_trailer_offset
    {
        return Err(FormatError::InvalidArchive(
            "VolumeTrailer root-auth fields do not match v41 public terminal layout",
        ));
    }
    Ok(())
}

fn critical_image_min() -> u64 {
    const MIN_CRYPTO_HEADER_LEN: u64 = 116;
    CRITICAL_METADATA_IMAGE_FIXED_LEN as u64
        + 4 * SERIALIZED_REGION_HEADER_LEN as u64
        + VOLUME_HEADER_LEN as u64
        + MIN_CRYPTO_HEADER_LEN
        + MANIFEST_FOOTER_LEN as u64
        + VOLUME_TRAILER_LEN as u64
        + IMAGE_CRC_LEN as u64
}

fn critical_image_cap() -> Result<u64, FormatError> {
    [
        CRITICAL_METADATA_IMAGE_FIXED_LEN as u64,
        6 * SERIALIZED_REGION_HEADER_LEN as u64,
        VOLUME_HEADER_LEN as u64,
        READER_MAX_CRYPTO_HEADER_LEN as u64,
        READER_MAX_KEY_WRAP_TABLE_LEN as u64,
        MANIFEST_FOOTER_LEN as u64,
        READER_MAX_ROOT_AUTH_FOOTER_LEN as u64,
        VOLUME_TRAILER_LEN as u64,
        IMAGE_CRC_LEN as u64,
    ]
    .into_iter()
    .try_fold(0u64, |total, value| {
        total
            .checked_add(value)
            .ok_or(FormatError::InvalidArchive("critical image cap overflow"))
    })
}

fn cmra_serialized_length(tuple: CmraDecoderTuple) -> Result<u64, FormatError> {
    let shard_total = (tuple.data_shard_count as u64)
        .checked_add(tuple.parity_shard_count as u64)
        .ok_or(FormatError::InvalidArchive("CMRA shard count overflow"))?;
    let row_len = (CRITICAL_METADATA_RECOVERY_SHARD_HEADER_LEN as u64)
        .checked_add(tuple.shard_size as u64)
        .ok_or(FormatError::InvalidArchive("CMRA row length overflow"))?;
    checked_u64_mul(shard_total, row_len, "CMRA length overflow")?
        .checked_add(CRITICAL_METADATA_RECOVERY_HEADER_LEN as u64)
        .ok_or(FormatError::InvalidArchive("CMRA length overflow"))
}

fn cmra_worst_case_cap() -> Result<u64, FormatError> {
    let cap = critical_image_cap()?;
    let mut worst = 0u64;
    let mut shard_size = 512u64;
    while shard_size <= 4096 {
        let data = ceil_div_u64(cap, shard_size)?;
        let parity = 2u64.max(ceil_div_u64(
            checked_u64_mul(data, READER_MAX_CMRA_PARITY_PCT as u64, "CMRA cap overflow")?,
            100,
        )?);
        let tuple = CmraDecoderTuple {
            shard_size: shard_size as u32,
            data_shard_count: u16::try_from(data)
                .map_err(|_| FormatError::InvalidArchive("CMRA cap data shard overflow"))?,
            parity_shard_count: u16::try_from(parity)
                .map_err(|_| FormatError::InvalidArchive("CMRA cap parity shard overflow"))?,
            image_length: u32::try_from(cap)
                .map_err(|_| FormatError::InvalidArchive("CMRA cap image overflow"))?,
            image_sha256: [0u8; 32],
        };
        worst = worst.max(cmra_serialized_length(tuple)?);
        shard_size += 2;
    }
    Ok(worst)
}

pub(crate) fn v41_terminal_tail_cap() -> Result<usize, FormatError> {
    let total = [
        MANIFEST_FOOTER_LEN as u64,
        READER_MAX_ROOT_AUTH_FOOTER_LEN as u64,
        VOLUME_TRAILER_LEN as u64,
        cmra_worst_case_cap()?,
        LOCATOR_PAIR_LEN as u64,
    ]
    .into_iter()
    .try_fold(0u64, |sum, value| {
        sum.checked_add(value)
            .ok_or(FormatError::InvalidArchive("terminal tail cap overflow"))
    })?;
    usize::try_from(total).map_err(|_| FormatError::InvalidArchive("terminal tail cap overflow"))
}

fn max_critical_recovery_scan(options: ReaderOptions) -> Result<usize, FormatError> {
    let worst = cmra_worst_case_cap()?;
    let total = options
        .max_trailing_garbage_scan
        .try_into()
        .map_err(|_| FormatError::InvalidArchive("scan cap overflow"))
        .and_then(|scan: u64| {
            scan.checked_add(worst)
                .and_then(|value| value.checked_add(LOCATOR_PAIR_LEN as u64))
                .ok_or(FormatError::InvalidArchive("scan cap overflow"))
        })?;
    usize::try_from(total).map_err(|_| FormatError::InvalidArchive("scan cap overflow"))
}

fn validate_bootstrap_single_volume_input(
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
) -> Result<(), FormatError> {
    if volume_header.stripe_width != 1 || volume_header.volume_index != 0 {
        return Err(FormatError::ReaderUnsupported(
            "bootstrap sidecar reader supports only single-volume archive input",
        ));
    }
    if crypto_header.stripe_width != volume_header.stripe_width {
        return Err(FormatError::InvalidArchive(
            "VolumeHeader and CryptoHeader stripe_width differ",
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct ParsedBootstrapSidecar {
    manifest_footer: Option<ManifestFooter>,
    index_root_records_section: Option<(u64, u64)>,
    dictionary_records_section: Option<(u64, u64)>,
}

pub(crate) struct NonSeekableBootstrapMaterial {
    pub(crate) manifest_footer: ManifestFooter,
    pub(crate) payload_dictionary: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BootstrapSidecarUse {
    SeekableAssist,
    NonSeekableRandomAccess,
}

impl ParsedBootstrapSidecar {
    fn require_sections_for(
        &self,
        sidecar_use: BootstrapSidecarUse,
        crypto_header: &CryptoHeaderFixed,
    ) -> Result<(), FormatError> {
        if sidecar_use == BootstrapSidecarUse::NonSeekableRandomAccess {
            if self.manifest_footer.is_none() || self.index_root_records_section.is_none() {
                return Err(FormatError::ReaderUnsupported(
                    "non-seekable bootstrap sidecar requires ManifestFooter and IndexRoot sections",
                ));
            }
            if crypto_header.has_dictionary != 0 && self.dictionary_records_section.is_none() {
                return Err(FormatError::ReaderUnsupported(
                    "dictionary bootstrap required",
                ));
            }
        }
        Ok(())
    }
}

pub(crate) fn parse_non_seekable_bootstrap_material(
    bootstrap_sidecar: &[u8],
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
    subkeys: &Subkeys,
) -> Result<NonSeekableBootstrapMaterial, FormatError> {
    validate_bootstrap_single_volume_input(volume_header, crypto_header)?;
    let sidecar =
        parse_bootstrap_sidecar(bootstrap_sidecar, volume_header, crypto_header, subkeys)?;
    sidecar.require_sections_for(BootstrapSidecarUse::NonSeekableRandomAccess, crypto_header)?;
    let manifest_footer = sidecar
        .manifest_footer
        .clone()
        .ok_or(FormatError::ReaderUnsupported(
            "non-seekable bootstrap sidecar requires ManifestFooter and IndexRoot sections",
        ))?;

    let mut blocks = BTreeMap::new();
    let (offset, length) =
        sidecar
            .index_root_records_section
            .ok_or(FormatError::ReaderUnsupported(
                "non-seekable bootstrap sidecar requires ManifestFooter and IndexRoot sections",
            ))?;
    let index_root_records = parse_sidecar_block_records(
        bootstrap_sidecar,
        crypto_header.block_size as usize,
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

    let limits = metadata_limits(crypto_header);
    let index_root_plaintext = load_metadata_object_from_parts(
        &blocks,
        ObjectLoadContext::index_root(
            volume_header,
            crypto_header,
            subkeys,
            index_root_extent_from_manifest(&manifest_footer),
        ),
        manifest_footer.index_root_decompressed_size,
    )?;
    let index_root = IndexRoot::parse(
        &index_root_plaintext,
        crypto_header.has_dictionary != 0,
        limits,
    )?;

    if crypto_header.has_dictionary != 0 {
        let (offset, length) =
            sidecar
                .dictionary_records_section
                .ok_or(FormatError::ReaderUnsupported(
                    "dictionary bootstrap required",
                ))?;
        let dictionary_records = parse_sidecar_block_records(
            bootstrap_sidecar,
            crypto_header.block_size as usize,
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
    let payload_dictionary =
        load_archive_dictionary(&blocks, subkeys, volume_header, crypto_header, &index_root)?;

    Ok(NonSeekableBootstrapMaterial {
        manifest_footer,
        payload_dictionary,
    })
}

fn parse_bootstrap_sidecar(
    bytes: &[u8],
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
    subkeys: &Subkeys,
) -> Result<ParsedBootstrapSidecar, FormatError> {
    let header_bytes = slice(
        bytes,
        0,
        BOOTSTRAP_SIDECAR_HEADER_LEN,
        "BootstrapSidecarHeader",
    )?;
    let header = BootstrapSidecarHeader::parse(header_bytes)?;
    if header.archive_uuid != volume_header.archive_uuid
        || header.session_id != volume_header.session_id
    {
        return Err(FormatError::InvalidArchive(
            "bootstrap sidecar identity does not match VolumeHeader",
        ));
    }
    verify_integrity_tag(
        HmacDomain::BootstrapSidecar,
        crypto_header.aead_algo,
        volume_header.volume_format_rev,
        Some(&subkeys.mac_key),
        &volume_header.archive_uuid,
        &volume_header.session_id,
        &header_bytes[..SIDECAR_HMAC_COVERED_LEN],
        &header.sidecar_hmac,
    )?;
    header.validate_packed_layout(bytes.len() as u64)?;
    validate_sidecar_size_cap(&header, crypto_header, bytes.len() as u64)?;

    if header.has_dictionary_records() && crypto_header.has_dictionary == 0 {
        return Err(FormatError::InvalidArchive(
            "bootstrap sidecar has dictionary records while has_dictionary is false",
        ));
    }

    let manifest_footer = if header.has_manifest_footer() {
        let manifest_offset = to_usize(header.manifest_footer_offset, "BootstrapSidecarHeader")?;
        let manifest_bytes = slice(
            bytes,
            manifest_offset,
            MANIFEST_FOOTER_LEN,
            "ManifestFooter",
        )?;
        let manifest_footer = ManifestFooter::parse(manifest_bytes)?;
        validate_sidecar_manifest_footer(
            volume_header,
            crypto_header,
            &manifest_footer,
            subkeys,
            volume_header.volume_format_rev,
            manifest_bytes,
        )?;
        manifest_footer.validate_index_root_extent(crypto_header.block_size)?;
        Some(manifest_footer)
    } else {
        None
    };

    Ok(ParsedBootstrapSidecar {
        manifest_footer,
        index_root_records_section: header.has_index_root_records().then_some((
            header.index_root_records_offset,
            header.index_root_records_length,
        )),
        dictionary_records_section: header.has_dictionary_records().then_some((
            header.dictionary_records_offset,
            header.dictionary_records_length,
        )),
    })
}

fn index_root_extent_from_manifest(manifest_footer: &ManifestFooter) -> ObjectExtent {
    ObjectExtent {
        first_block_index: manifest_footer.index_root_first_block,
        data_block_count: manifest_footer.index_root_data_block_count,
        parity_block_count: manifest_footer.index_root_parity_block_count,
        encrypted_size: manifest_footer.index_root_encrypted_size,
    }
}

fn insert_sidecar_records(
    blocks: &mut BTreeMap<u64, BlockRecord>,
    records: Vec<BlockRecord>,
) -> Result<(), FormatError> {
    for record in records {
        if let Some(existing) = blocks.insert(record.block_index, record.clone()) {
            if existing != record {
                return Err(FormatError::InvalidArchive(
                    "bootstrap sidecar conflicts with volume BlockRecord",
                ));
            }
        }
    }
    Ok(())
}

fn validate_sidecar_manifest_footer(
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
    footer: &ManifestFooter,
    subkeys: &Subkeys,
    volume_format_rev: u16,
    raw: &[u8],
) -> Result<(), FormatError> {
    if footer.archive_uuid != volume_header.archive_uuid
        || footer.session_id != volume_header.session_id
    {
        return Err(FormatError::InvalidArchive(
            "sidecar ManifestFooter identity does not match VolumeHeader",
        ));
    }
    if footer.volume_index != 0 {
        return Err(FormatError::InvalidArchive(
            "sidecar ManifestFooter volume_index must be zero",
        ));
    }
    if footer.total_volumes != crypto_header.stripe_width {
        return Err(FormatError::InvalidArchive(
            "sidecar ManifestFooter total_volumes does not match stripe_width",
        ));
    }
    if footer.is_authoritative != 1 {
        return Err(FormatError::InvalidArchive(
            "sidecar ManifestFooter is not authoritative",
        ));
    }
    verify_integrity_tag(
        HmacDomain::ManifestFooter,
        crypto_header.aead_algo,
        volume_format_rev,
        Some(&subkeys.mac_key),
        &volume_header.archive_uuid,
        &volume_header.session_id,
        &raw[..MANIFEST_HMAC_COVERED_LEN],
        &footer.manifest_hmac,
    )
}

fn validate_sidecar_size_cap(
    header: &BootstrapSidecarHeader,
    crypto_header: &CryptoHeaderFixed,
    file_size: u64,
) -> Result<(), FormatError> {
    let record_len = checked_u64_add(
        crypto_header.block_size as u64,
        BLOCK_RECORD_FRAMING_LEN as u64,
        "bootstrap sidecar cap overflow",
    )?;
    let max_index_records = crypto_header.index_root_fec_data_shards as u64
        + crypto_header.index_root_fec_parity_shards as u64;
    let max_record_section_bytes = checked_u64_mul(
        max_index_records,
        record_len,
        "bootstrap sidecar cap overflow",
    )?;
    if header.index_root_records_length % record_len != 0 {
        return Err(FormatError::InvalidArchive(
            "bootstrap sidecar IndexRoot records length is not aligned",
        ));
    }
    if header.index_root_records_length / record_len > max_index_records {
        return Err(FormatError::InvalidArchive(
            "bootstrap sidecar IndexRoot records exceed resource cap",
        ));
    }
    if header.dictionary_records_length % record_len != 0 {
        return Err(FormatError::InvalidArchive(
            "bootstrap sidecar dictionary records length is not aligned",
        ));
    }
    if header.dictionary_records_length / record_len > max_index_records {
        return Err(FormatError::InvalidArchive(
            "bootstrap sidecar dictionary records exceed resource cap",
        ));
    }

    let mut cap = BOOTSTRAP_SIDECAR_HEADER_LEN as u64;
    if header.has_manifest_footer() {
        cap = cap
            .checked_add(MANIFEST_FOOTER_LEN as u64)
            .ok_or(FormatError::InvalidArchive(
                "bootstrap sidecar cap overflow",
            ))?;
    }
    if header.has_index_root_records() {
        cap = checked_u64_add(
            cap,
            max_record_section_bytes,
            "bootstrap sidecar cap overflow",
        )?;
    }
    if header.has_dictionary_records() {
        cap = checked_u64_add(
            cap,
            max_record_section_bytes,
            "bootstrap sidecar cap overflow",
        )?;
    }
    if file_size > cap {
        return Err(FormatError::InvalidArchive(
            "bootstrap sidecar exceeds resource cap",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct SidecarBlockRecordsSection {
    offset: u64,
    length: u64,
    extent: ObjectExtent,
    data_kind: BlockKind,
    parity_kind: BlockKind,
    structure: &'static str,
}

fn parse_sidecar_block_records(
    sidecar_bytes: &[u8],
    block_size: usize,
    section: SidecarBlockRecordsSection,
) -> Result<Vec<BlockRecord>, FormatError> {
    let record_len = block_size
        .checked_add(BLOCK_RECORD_FRAMING_LEN)
        .ok_or(FormatError::InvalidArchive("BlockRecord length overflow"))?;
    if section.length % record_len as u64 != 0 {
        return Err(FormatError::InvalidArchive(
            "sidecar BlockRecord section is not aligned",
        ));
    }
    let expected_count =
        section.extent.data_block_count as usize + section.extent.parity_block_count as usize;
    let actual_count = usize::try_from(section.length / record_len as u64)
        .map_err(|_| FormatError::InvalidArchive("sidecar BlockRecord count overflow"))?;
    if actual_count != expected_count {
        return Err(FormatError::InvalidArchive(
            "sidecar BlockRecord section does not match declared extent",
        ));
    }
    let start = to_usize(section.offset, "BootstrapSidecarHeader")?;
    let raw = slice(
        sidecar_bytes,
        start,
        to_usize(section.length, "BootstrapSidecarHeader")?,
        "BootstrapSidecarHeader",
    )?;
    let mut records = Vec::with_capacity(expected_count);

    for idx in 0..expected_count {
        let record = BlockRecord::parse(
            slice(raw, idx * record_len, record_len, "BlockRecord")?,
            block_size,
        )?;
        let expected_block_index = checked_u64_add(
            section.extent.first_block_index,
            idx as u64,
            section.structure,
        )?;
        if record.block_index != expected_block_index {
            return Err(FormatError::InvalidArchive(
                "sidecar BlockRecord section has missing or duplicate blocks",
            ));
        }
        let expected_kind = if idx < section.extent.data_block_count as usize {
            section.data_kind
        } else {
            section.parity_kind
        };
        if record.kind != expected_kind {
            return Err(FormatError::InvalidArchive(
                "sidecar BlockRecord section has wrong kind",
            ));
        }
        let should_be_last = idx + 1 == section.extent.data_block_count as usize;
        if idx < section.extent.data_block_count as usize && record.is_last_data() != should_be_last
        {
            return Err(FormatError::InvalidArchive(
                "sidecar BlockRecord section has wrong last-data flag",
            ));
        }
        records.push(record);
    }

    Ok(records)
}

fn validate_trailer_identity(
    volume_header: &VolumeHeader,
    trailer: &VolumeTrailer,
) -> Result<(), FormatError> {
    if trailer.archive_uuid != volume_header.archive_uuid
        || trailer.session_id != volume_header.session_id
        || trailer.volume_index != volume_header.volume_index
    {
        return Err(FormatError::InvalidArchive(
            "VolumeTrailer identity does not match VolumeHeader",
        ));
    }
    Ok(())
}

fn validate_manifest_footer(
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
    footer: &ManifestFooter,
    subkeys: &Subkeys,
    volume_format_rev: u16,
    raw: &[u8],
) -> Result<(), FormatError> {
    if footer.archive_uuid != volume_header.archive_uuid
        || footer.session_id != volume_header.session_id
        || footer.volume_index != volume_header.volume_index
    {
        return Err(FormatError::InvalidArchive(
            "ManifestFooter identity does not match VolumeHeader",
        ));
    }
    if footer.total_volumes != volume_header.stripe_width {
        return Err(FormatError::InvalidArchive(
            "ManifestFooter total_volumes does not match stripe_width",
        ));
    }
    if footer.is_authoritative != 1 {
        return Err(FormatError::InvalidArchive(
            "ManifestFooter is not authoritative",
        ));
    }
    verify_integrity_tag(
        HmacDomain::ManifestFooter,
        crypto_header.aead_algo,
        volume_format_rev,
        Some(&subkeys.mac_key),
        &volume_header.archive_uuid,
        &volume_header.session_id,
        &raw[..MANIFEST_HMAC_COVERED_LEN],
        &footer.manifest_hmac,
    )
}

#[derive(Debug)]
struct ParsedBlockRegion {
    blocks: BTreeMap<u64, BlockRecord>,
    erased_block_indices: BTreeSet<u64>,
}

fn parse_block_region(
    bytes: &[u8],
    start: usize,
    end: usize,
    block_size: usize,
    volume_header: &VolumeHeader,
    trailer: &VolumeTrailer,
) -> Result<ParsedBlockRegion, FormatError> {
    if end < start {
        return Err(FormatError::InvalidArchive(
            "ManifestFooter starts before BlockRecord region",
        ));
    }
    let record_len = block_size
        .checked_add(BLOCK_RECORD_FRAMING_LEN)
        .ok_or(FormatError::InvalidArchive("BlockRecord length overflow"))?;
    let region_len = end - start;
    if region_len % record_len != 0 {
        return Err(FormatError::InvalidArchive(
            "BlockRecord region length is not aligned",
        ));
    }
    let observed_count = region_len / record_len;
    if observed_count as u64 != trailer.block_count {
        return Err(FormatError::InvalidArchive(
            "VolumeTrailer block_count does not match BlockRecord region",
        ));
    }

    let mut blocks = BTreeMap::new();
    let mut erased_block_indices = BTreeSet::new();
    for idx in 0..observed_count {
        let offset = start + idx * record_len;
        let expected_block_index = checked_u64_add(
            volume_header.volume_index as u64,
            checked_u64_mul(
                idx as u64,
                volume_header.stripe_width as u64,
                "BlockRecord index overflow",
            )?,
            "BlockRecord index overflow",
        )?;
        let raw = slice(bytes, offset, record_len, "BlockRecord")?;
        match BlockRecord::parse(raw, block_size) {
            Ok(record) => {
                if record.block_index != expected_block_index {
                    return Err(FormatError::InvalidArchive(
                        "BlockRecord index does not match volume position",
                    ));
                }
                if blocks.insert(record.block_index, record).is_some() {
                    return Err(FormatError::InvalidArchive("duplicate BlockRecord index"));
                }
            }
            Err(err) if block_record_error_is_recoverable_erasure(&err) => {
                if !erased_block_indices.insert(expected_block_index) {
                    return Err(FormatError::InvalidArchive(
                        "duplicate erased BlockRecord index",
                    ));
                }
            }
            Err(err) => return Err(err),
        }
    }

    Ok(ParsedBlockRegion {
        blocks,
        erased_block_indices,
    })
}

fn validate_seekable_block_region_layout(
    start: u64,
    end: u64,
    block_size: usize,
    trailer: &VolumeTrailer,
) -> Result<(), FormatError> {
    if end < start {
        return Err(FormatError::InvalidArchive(
            "ManifestFooter starts before BlockRecord region",
        ));
    }
    let record_len = block_record_len(block_size)?;
    let region_len = end - start;
    if region_len % record_len != 0 {
        return Err(FormatError::InvalidArchive(
            "BlockRecord region length is not aligned",
        ));
    }
    let observed_count = region_len / record_len;
    if observed_count != trailer.block_count {
        return Err(FormatError::InvalidArchive(
            "VolumeTrailer block_count does not match BlockRecord region",
        ));
    }
    Ok(())
}

fn parse_public_block_observation(
    bytes: &[u8],
    start: usize,
    image: &CriticalMetadataImage,
    block_size: usize,
    volume_header: &VolumeHeader,
) -> Result<BTreeMap<u64, BlockRecord>, FormatError> {
    let image_start = to_usize(image.block_records_offset, "BlockRecord")?;
    if start != image_start {
        return Err(FormatError::InvalidArchive(
            "public BlockRecord observation start mismatch",
        ));
    }
    let scan_limit_u64 = image
        .block_records_offset
        .checked_add(image.block_records_length)
        .ok_or(FormatError::InvalidArchive(
            "public BlockRecord observation limit overflow",
        ))?;
    if scan_limit_u64 != image.manifest_footer_offset {
        return Err(FormatError::InvalidArchive(
            "public BlockRecord observation limit mismatch",
        ));
    }
    let scan_limit = to_usize(scan_limit_u64, "BlockRecord")?;
    if scan_limit < start {
        return Err(FormatError::InvalidArchive(
            "public BlockRecord observation limit before start",
        ));
    }
    let record_len = block_size
        .checked_add(BLOCK_RECORD_FRAMING_LEN)
        .ok_or(FormatError::InvalidArchive("BlockRecord length overflow"))?;
    let region_len = scan_limit - start;
    if region_len % record_len != 0 {
        return Err(FormatError::InvalidArchive(
            "public BlockRecord observation window is not aligned",
        ));
    }

    let mut blocks = BTreeMap::new();
    let mut offset = start;
    let mut observed_slot = 0u64;
    while offset < scan_limit {
        let magic_end = checked_add(offset, 4, "BlockRecord")?;
        if magic_end > scan_limit || bytes.get(offset..magic_end) != Some(b"TZBK") {
            break;
        }
        let record_end = checked_add(offset, record_len, "BlockRecord")?;
        if record_end > scan_limit {
            return Err(FormatError::InvalidArchive(
                "public BlockRecord observation slot is incomplete",
            ));
        }
        let raw = slice(bytes, offset, record_len, "BlockRecord")?;
        let record = BlockRecord::parse(raw, block_size)?;
        let expected_block_index = checked_u64_add(
            volume_header.volume_index as u64,
            checked_u64_mul(
                observed_slot,
                volume_header.stripe_width as u64,
                "BlockRecord index overflow",
            )?,
            "BlockRecord index overflow",
        )?;
        if record.block_index != expected_block_index {
            return Err(FormatError::InvalidArchive(
                "public BlockRecord index does not match volume position",
            ));
        }
        if blocks.insert(record.block_index, record).is_some() {
            return Err(FormatError::InvalidArchive("duplicate BlockRecord index"));
        }
        offset = record_end;
        observed_slot = observed_slot
            .checked_add(1)
            .ok_or(FormatError::InvalidArchive("BlockRecord count overflow"))?;
    }

    let mut scan = if offset < scan_limit {
        checked_add(offset, record_len, "BlockRecord")?
    } else {
        scan_limit
    };
    while scan < scan_limit {
        let magic_end = checked_add(scan, 4, "BlockRecord")?;
        let record_end = checked_add(scan, record_len, "BlockRecord")?;
        if record_end <= scan_limit && bytes.get(scan..magic_end) == Some(b"TZBK") {
            let raw = slice(bytes, scan, record_len, "BlockRecord")?;
            if BlockRecord::parse(raw, block_size).is_ok() {
                return Err(FormatError::InvalidArchive(
                    "public observation has ambiguous extra BlockRecord",
                ));
            }
        }
        scan = record_end;
    }

    Ok(blocks)
}

pub(crate) fn block_record_error_is_recoverable_erasure(error: &FormatError) -> bool {
    matches!(
        error,
        FormatError::BadCrc {
            structure: "BlockRecord",
        } | FormatError::BadMagic {
            structure: "BlockRecord",
        } | FormatError::NonZeroReserved {
            structure: "BlockRecord",
        }
    )
}

fn block_record_len(block_size: usize) -> Result<u64, FormatError> {
    let len = block_size
        .checked_add(BLOCK_RECORD_FRAMING_LEN)
        .ok_or(FormatError::InvalidArchive("BlockRecord length overflow"))?;
    u64::try_from(len).map_err(|_| FormatError::InvalidArchive("BlockRecord length overflow"))
}

fn checked_u64_mul(lhs: u64, rhs: u64, reason: &'static str) -> Result<u64, FormatError> {
    lhs.checked_mul(rhs)
        .ok_or(FormatError::InvalidArchive(reason))
}

fn parse_stream_block_prefix(
    bytes: &[u8],
    start: usize,
    block_size: usize,
    volume_header: &VolumeHeader,
) -> Result<(BTreeMap<u64, BlockRecord>, usize, u64), FormatError> {
    let record_len = block_size
        .checked_add(BLOCK_RECORD_FRAMING_LEN)
        .ok_or(FormatError::InvalidArchive("BlockRecord length overflow"))?;
    let mut blocks = BTreeMap::new();
    let mut offset = start;
    let mut observed_block_count = 0u64;

    while bytes.get(offset..offset + 4) == Some(b"TZBK") {
        let expected_block_index =
            expected_stream_block_index(volume_header, observed_block_count)?;
        let raw = slice(bytes, offset, record_len, "BlockRecord")?;
        match BlockRecord::parse(raw, block_size) {
            Ok(record) => {
                if record.block_index != expected_block_index {
                    return Err(FormatError::InvalidArchive(
                        "BlockRecord index does not match stream position",
                    ));
                }
                if blocks.insert(record.block_index, record).is_some() {
                    return Err(FormatError::InvalidArchive("duplicate BlockRecord index"));
                }
            }
            Err(err) if block_record_error_is_recoverable_erasure(&err) => {}
            Err(err) => return Err(err),
        }
        offset = checked_add(offset, record_len, "BlockRecord")?;
        observed_block_count = observed_block_count
            .checked_add(1)
            .ok_or(FormatError::InvalidArchive("BlockRecord count overflow"))?;
    }

    Ok((blocks, offset, observed_block_count))
}

pub(crate) fn expected_stream_block_index(
    volume_header: &VolumeHeader,
    observed_block_count: u64,
) -> Result<u64, FormatError> {
    checked_u64_add(
        volume_header.volume_index as u64,
        checked_u64_mul(
            observed_block_count,
            volume_header.stripe_width as u64,
            "BlockRecord index overflow",
        )?,
        "BlockRecord index overflow",
    )
}

fn parse_sequential_block_or_erasure(
    bytes: &[u8],
    offset: usize,
    record_len: usize,
    block_size: usize,
    volume_header: &VolumeHeader,
    observed_block_count: u64,
) -> Result<Option<BlockRecord>, FormatError> {
    let expected_block_index = expected_stream_block_index(volume_header, observed_block_count)?;
    let raw = slice(bytes, offset, record_len, "BlockRecord")?;
    match BlockRecord::parse(raw, block_size) {
        Ok(record) => {
            if record.block_index != expected_block_index {
                return Err(FormatError::InvalidArchive(
                    "BlockRecord index does not match stream position",
                ));
            }
            Ok(Some(record))
        }
        Err(err) if block_record_error_is_recoverable_erasure(&err) => Ok(None),
        Err(err) => Err(err),
    }
}

fn parse_terminal_material(
    bytes: &[u8],
    manifest_offset: usize,
    observed_block_count: u64,
    context: KeyHoldingTerminalContext<'_>,
    options: ReaderOptions,
) -> Result<(ManifestFooter, VolumeTrailer, Option<RootAuthFooterV1>), FormatError> {
    let candidate = locate_v41_terminal_candidate(bytes, context, options)?;
    if !terminal_candidate_reaches_eof(&candidate, bytes.len())? {
        return Err(FormatError::InvalidArchive(
            "sequential terminal does not end at EOF",
        ));
    }
    let terminal = candidate.terminal;
    if terminal.image.manifest_footer_offset != manifest_offset as u64 {
        return Err(FormatError::InvalidArchive(
            "VolumeTrailer ManifestFooter offset does not match observed stream offset",
        ));
    }
    if terminal.volume_trailer.block_count != observed_block_count {
        return Err(FormatError::InvalidArchive(
            "VolumeTrailer block_count does not match observed stream",
        ));
    }
    let manifest_footer = ManifestFooter::parse(&terminal.manifest_footer_bytes)?;
    Ok((
        manifest_footer,
        terminal.volume_trailer,
        terminal.root_auth_footer,
    ))
}

pub(crate) fn parse_terminal_material_read_at(
    reader: &dyn ArchiveReadAt,
    input_len: u64,
    manifest_offset: u64,
    observed_block_count: u64,
    context: KeyHoldingTerminalContext<'_>,
) -> Result<SequentialTerminalMaterial, FormatError> {
    let mut candidates = Vec::new();
    if input_len >= CRITICAL_RECOVERY_LOCATOR_LEN as u64 {
        collect_v41_locator_candidate_read_at(
            reader,
            input_len - CRITICAL_RECOVERY_LOCATOR_LEN as u64,
            0,
            context,
            &mut candidates,
        );
    }
    if input_len >= LOCATOR_PAIR_LEN as u64 {
        collect_v41_locator_candidate_read_at(
            reader,
            input_len - LOCATOR_PAIR_LEN as u64,
            1,
            context,
            &mut candidates,
        );
    }

    let candidate = choose_v41_terminal_candidate(candidates)?;
    if !terminal_candidate_reaches_eof(&candidate, to_usize(input_len, "terminal EOF")?)? {
        return Err(FormatError::InvalidArchive(
            "sequential terminal does not end at EOF",
        ));
    }
    let terminal = candidate.terminal;
    if terminal.image.manifest_footer_offset != manifest_offset {
        return Err(FormatError::InvalidArchive(
            "VolumeTrailer ManifestFooter offset does not match observed stream offset",
        ));
    }
    if terminal.volume_trailer.block_count != observed_block_count {
        return Err(FormatError::InvalidArchive(
            "VolumeTrailer block_count does not match observed stream",
        ));
    }
    let manifest_footer = ManifestFooter::parse(&terminal.manifest_footer_bytes)?;
    Ok(SequentialTerminalMaterial {
        manifest_footer,
        volume_trailer: terminal.volume_trailer,
        root_auth_footer: terminal.root_auth_footer,
    })
}

fn terminal_candidate_reaches_eof(
    candidate: &TerminalCandidate,
    input_len: usize,
) -> Result<bool, FormatError> {
    let expected_end =
        match candidate.locator_sequence {
            Some(0) => candidate.anchor,
            Some(1) => candidate
                .anchor
                .checked_add(CRITICAL_RECOVERY_LOCATOR_LEN)
                .ok_or(FormatError::InvalidArchive(
                    "terminal EOF boundary overflow",
                ))?,
            None => candidate.anchor.checked_add(LOCATOR_PAIR_LEN).ok_or(
                FormatError::InvalidArchive("terminal EOF boundary overflow"),
            )?,
            Some(_) => {
                return Err(FormatError::InvalidArchive(
                    "invalid terminal locator sequence",
                ))
            }
        };
    Ok(expected_end == input_len)
}

#[derive(Debug, Default)]
struct PendingSequentialEnvelope {
    data_shards: Vec<Option<Vec<u8>>>,
    parity_shards: Vec<Option<Vec<u8>>>,
    saw_last_data: bool,
    awaiting_tentative_parity: bool,
}

impl PendingSequentialEnvelope {
    fn is_empty(&self) -> bool {
        self.data_shards.is_empty() && self.parity_shards.is_empty()
    }
}

fn handle_sequential_payload_erasure(
    pending: &mut PendingSequentialEnvelope,
    crypto_header: &CryptoHeaderFixed,
    metadata_seen: bool,
) -> Result<(), FormatError> {
    if metadata_seen || pending.saw_last_data {
        return Err(FormatError::BadCrc {
            structure: "BlockRecord",
        });
    }
    if !sequential_payload_parity_is_guaranteed(crypto_header) {
        return Err(FormatError::BadCrc {
            structure: "BlockRecord",
        });
    }
    pending.data_shards.push(None);
    pending.awaiting_tentative_parity = true;
    if pending.data_shards.len() > crypto_header.fec_data_shards as usize {
        return Err(FormatError::InvalidArchive(
            "sequential payload envelope exceeds data-shard cap",
        ));
    }
    Ok(())
}

fn sequential_payload_parity_is_guaranteed(crypto_header: &CryptoHeaderFixed) -> bool {
    crypto_header.fec_parity_shards > 0
        && (crypto_header.volume_loss_tolerance > 0 || crypto_header.bit_rot_buffer_pct > 0)
}

fn sequential_extract_tar_stream_with_options(
    bytes: &[u8],
    master_key: &MasterKey,
    options: ReaderOptions,
) -> Result<Vec<u8>, FormatError> {
    validate_reader_options(options)?;
    if bytes.len() < VOLUME_HEADER_LEN {
        return Err(FormatError::InvalidLength {
            structure: "archive",
            expected: VOLUME_HEADER_LEN,
            actual: bytes.len(),
        });
    }

    let volume_header = VolumeHeader::parse(slice(bytes, 0, VOLUME_HEADER_LEN, "archive")?)?;
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
    validate_sequential_supported_volume(
        &volume_header,
        &parsed_crypto.fixed,
        &parsed_crypto.extensions,
    )?;
    validate_crypto_class_parity_exactness(&parsed_crypto.fixed)?;
    let block_records_start = startup_block_records_start(
        &volume_header,
        &parsed_crypto.kdf_params,
        |start, length| {
            let start = to_usize(start, "KeyWrapTableV1")?;
            Ok(slice(bytes, start, length, "KeyWrapTableV1")?.to_vec())
        },
    )?;

    let block_size = parsed_crypto.fixed.block_size as usize;
    let record_len = block_size
        .checked_add(BLOCK_RECORD_FRAMING_LEN)
        .ok_or(FormatError::InvalidArchive("BlockRecord length overflow"))?;
    let mut offset = to_usize(block_records_start, "BlockRecord")?;
    let mut observed_block_count = 0u64;
    let mut metadata_seen = false;
    let mut pending = PendingSequentialEnvelope::default();
    let mut next_envelope_index = 0u64;
    let mut tar_stream = Vec::new();
    let max_tar_stream_size = options.max_verify_tar_size;
    let observed_archive_bytes = observed_archive_size([bytes.len() as u64])?;
    let total_extraction_cap = total_extraction_size_cap(options, observed_archive_bytes);
    let mut tar_stream_total_validator = TarStreamTotalExtractionSizeValidator::new(
        parsed_crypto.fixed.max_path_length,
        total_extraction_cap,
    );

    while bytes.get(offset..offset + 4) == Some(b"TZBK") {
        let record = parse_sequential_block_or_erasure(
            bytes,
            offset,
            record_len,
            block_size,
            &volume_header,
            observed_block_count,
        )?;
        observed_block_count = observed_block_count
            .checked_add(1)
            .ok_or(FormatError::InvalidArchive("BlockRecord count overflow"))?;
        let Some(record) = record else {
            handle_sequential_payload_erasure(&mut pending, &parsed_crypto.fixed, metadata_seen)?;
            offset = checked_add(offset, record_len, "BlockRecord")?;
            continue;
        };

        match record.kind {
            BlockKind::PayloadData => {
                if metadata_seen {
                    return Err(FormatError::InvalidArchive(
                        "payload BlockRecord appears after metadata",
                    ));
                }
                if pending.awaiting_tentative_parity {
                    return Err(FormatError::InvalidArchive(
                        "sequential payload envelope boundary is ambiguous after CRC erasure",
                    ));
                }
                if pending.saw_last_data {
                    finalize_sequential_envelope(
                        &mut pending,
                        SequentialEnvelopeDecodeContext {
                            crypto_header: &parsed_crypto.fixed,
                            subkeys: &subkeys,
                            volume_header: &volume_header,
                            next_envelope_index: &mut next_envelope_index,
                            tar_stream: &mut tar_stream,
                            max_tar_stream_size,
                            tar_stream_total_validator: &mut tar_stream_total_validator,
                        },
                    )?;
                }
                let is_last_data = record.is_last_data();
                pending.data_shards.push(Some(record.payload));
                if is_last_data {
                    pending.saw_last_data = true;
                }
                if pending.data_shards.len() > parsed_crypto.fixed.fec_data_shards as usize {
                    return Err(FormatError::InvalidArchive(
                        "sequential payload envelope exceeds data-shard cap",
                    ));
                }
            }
            BlockKind::PayloadParity => {
                if metadata_seen {
                    return Err(FormatError::InvalidArchive(
                        "payload parity BlockRecord appears after metadata",
                    ));
                }
                if pending.awaiting_tentative_parity {
                    pending.awaiting_tentative_parity = false;
                    pending.saw_last_data = true;
                } else if pending.data_shards.is_empty() || !pending.saw_last_data {
                    return Err(FormatError::InvalidArchive(
                        "payload parity appears before envelope data is complete",
                    ));
                }
                pending.parity_shards.push(Some(record.payload));
                if pending.parity_shards.len() > parsed_crypto.fixed.fec_parity_shards as usize {
                    return Err(FormatError::InvalidArchive(
                        "sequential payload envelope exceeds parity-shard cap",
                    ));
                }
            }
            _ => {
                if !pending.is_empty() {
                    finalize_sequential_envelope(
                        &mut pending,
                        SequentialEnvelopeDecodeContext {
                            crypto_header: &parsed_crypto.fixed,
                            subkeys: &subkeys,
                            volume_header: &volume_header,
                            next_envelope_index: &mut next_envelope_index,
                            tar_stream: &mut tar_stream,
                            max_tar_stream_size,
                            tar_stream_total_validator: &mut tar_stream_total_validator,
                        },
                    )?;
                }
                metadata_seen = true;
            }
        }

        offset = checked_add(offset, record_len, "BlockRecord")?;
    }

    if !pending.is_empty() {
        finalize_sequential_envelope(
            &mut pending,
            SequentialEnvelopeDecodeContext {
                crypto_header: &parsed_crypto.fixed,
                subkeys: &subkeys,
                volume_header: &volume_header,
                next_envelope_index: &mut next_envelope_index,
                tar_stream: &mut tar_stream,
                max_tar_stream_size,
                tar_stream_total_validator: &mut tar_stream_total_validator,
            },
        )?;
    }

    parse_terminal_material(
        bytes,
        offset,
        observed_block_count,
        KeyHoldingTerminalContext {
            subkeys: &subkeys,
            volume_header: &volume_header,
            crypto_header: &parsed_crypto.fixed,
            crypto_header_bytes: crypto_bytes,
        },
        options,
    )?;
    // This public helper is intentionally whole-buffer: decoded payload bytes
    // stay internal until terminal ManifestFooter and VolumeTrailer HMACs pass.
    validate_tar_stream_total_extraction_size(
        &tar_stream,
        parsed_crypto.fixed.max_path_length,
        total_extraction_cap,
    )?;
    Ok(tar_stream)
}

fn validate_sequential_supported_volume(
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
    extensions: &[ExtensionTlv<'_>],
) -> Result<(), FormatError> {
    reject_unsupported_raw_stream_profile(extensions)?;
    if volume_header.stripe_width != 1 || volume_header.volume_index != 0 {
        return Err(FormatError::ReaderUnsupported(
            "sequential reader supports only single-volume archive input",
        ));
    }
    if crypto_header.stripe_width != volume_header.stripe_width {
        return Err(FormatError::InvalidArchive(
            "VolumeHeader and CryptoHeader stripe_width differ",
        ));
    }
    if crypto_header.has_dictionary != 0 {
        return Err(FormatError::ReaderUnsupported(
            "dictionary bootstrap required for non-seekable sequential extraction",
        ));
    }
    Ok(())
}

struct SequentialEnvelopeDecodeContext<'a> {
    crypto_header: &'a CryptoHeaderFixed,
    subkeys: &'a Subkeys,
    volume_header: &'a VolumeHeader,
    next_envelope_index: &'a mut u64,
    tar_stream: &'a mut Vec<u8>,
    max_tar_stream_size: usize,
    tar_stream_total_validator: &'a mut TarStreamTotalExtractionSizeValidator,
}

fn finalize_sequential_envelope(
    pending: &mut PendingSequentialEnvelope,
    context: SequentialEnvelopeDecodeContext<'_>,
) -> Result<(), FormatError> {
    if !pending.saw_last_data {
        return Err(FormatError::InvalidArchive(
            "sequential payload envelope is missing last-data flag",
        ));
    }
    if pending.data_shards.len() > context.crypto_header.fec_data_shards as usize {
        return Err(FormatError::InvalidArchive(
            "sequential payload envelope exceeds data-shard cap",
        ));
    }
    if pending.parity_shards.len() > context.crypto_header.fec_parity_shards as usize {
        return Err(FormatError::InvalidArchive(
            "sequential payload envelope exceeds parity-shard cap",
        ));
    }
    let required_parity =
        required_object_parity(pending.data_shards.len() as u64, context.crypto_header)?;
    if pending.parity_shards.len() < required_parity as usize {
        return Err(FormatError::InvalidArchive(
            "sequential payload envelope has insufficient parity for recovery settings",
        ));
    }

    let repaired = repair_data_gf16(
        &pending.data_shards,
        &pending.parity_shards,
        context.crypto_header.block_size as usize,
    )?;
    let mut encrypted =
        Vec::with_capacity(repaired.len() * context.crypto_header.block_size as usize);
    for shard in repaired {
        encrypted.extend_from_slice(&shard);
    }
    let plaintext = decrypt_padded_aead_object(
        AeadObjectContext {
            algo: context.crypto_header.aead_algo,
            key: &context.subkeys.enc_key,
            nonce_seed: &context.subkeys.nonce_seed,
            domain: b"envelope",
            archive_uuid: &context.volume_header.archive_uuid,
            session_id: &context.volume_header.session_id,
            counter: *context.next_envelope_index,
        },
        &encrypted,
    )?;
    decode_concatenated_zstd_frames_with_cap(
        &plaintext,
        None,
        context.tar_stream,
        context.max_tar_stream_size,
        Some(context.tar_stream_total_validator),
    )?;
    *context.next_envelope_index = (*context.next_envelope_index)
        .checked_add(1)
        .ok_or(FormatError::InvalidArchive("envelope counter overflow"))?;
    *pending = PendingSequentialEnvelope::default();
    Ok(())
}

fn decode_concatenated_zstd_frames_with_cap(
    plaintext: &[u8],
    dictionary: Option<&[u8]>,
    output: &mut Vec<u8>,
    max_output_len: usize,
    mut tar_stream_total_validator: Option<&mut TarStreamTotalExtractionSizeValidator>,
) -> Result<(), FormatError> {
    let mut cursor = 0usize;
    while cursor < plaintext.len() {
        let frame_len = zstd_safe::find_frame_compressed_size(&plaintext[cursor..])
            .map_err(|_| FormatError::InvalidZstdFrame)?;
        if frame_len == 0 {
            return Err(FormatError::InvalidZstdFrame);
        }
        let end = checked_add(cursor, frame_len, "zstd frame")?;
        validate_exact_zstd_frame(&plaintext[cursor..end])?;
        if let Some(dictionary) = dictionary {
            let mut decoder =
                zstd::stream::Decoder::with_dictionary(&plaintext[cursor..end], dictionary)
                    .map_err(|_| FormatError::ZstdDecompressionFailure)?;
            read_zstd_frame_to_capped_output(
                &mut decoder,
                output,
                max_output_len,
                tar_stream_total_validator.as_deref_mut(),
            )?;
        } else {
            let mut decoder = zstd::stream::Decoder::new(&plaintext[cursor..end])
                .map_err(|_| FormatError::ZstdDecompressionFailure)?;
            read_zstd_frame_to_capped_output(
                &mut decoder,
                output,
                max_output_len,
                tar_stream_total_validator.as_deref_mut(),
            )?;
        }
        cursor = end;
    }
    Ok(())
}

fn read_zstd_frame_to_capped_output<R: Read>(
    decoder: &mut R,
    output: &mut Vec<u8>,
    max_output_len: usize,
    mut tar_stream_total_validator: Option<&mut TarStreamTotalExtractionSizeValidator>,
) -> Result<(), FormatError> {
    let mut buf = [0u8; 64 * 1024];
    loop {
        let read = decoder
            .read(&mut buf)
            .map_err(|_| FormatError::ZstdDecompressionFailure)?;
        if read == 0 {
            return Ok(());
        }
        let next_len = output
            .len()
            .checked_add(read)
            .ok_or(FormatError::ReaderUnsupported(
                "sequential tar stream exceeds configured verification cap",
            ))?;
        if next_len > max_output_len {
            return Err(FormatError::ReaderUnsupported(
                "sequential tar stream exceeds configured verification cap",
            ));
        }
        output.extend_from_slice(&buf[..read]);
        if let Some(validator) = tar_stream_total_validator.as_mut() {
            validator.observe(output)?;
        }
    }
}

fn load_archive_dictionary(
    blocks: &impl BlockProvider,
    subkeys: &Subkeys,
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
    index_root: &IndexRoot,
) -> Result<Option<Vec<u8>>, FormatError> {
    if crypto_header.has_dictionary == 0 {
        return Ok(None);
    }
    let plaintext = load_metadata_object_from_parts(
        blocks,
        ObjectLoadContext::dictionary(volume_header, crypto_header, subkeys, index_root)?,
        index_root.header.dictionary_decompressed_size,
    )?;
    Ok(Some(plaintext))
}

#[derive(Clone, Copy)]
struct ObjectLoadContext<'a> {
    volume_header: &'a VolumeHeader,
    crypto_header: &'a CryptoHeaderFixed,
    extent: ObjectExtent,
    data_kind: BlockKind,
    parity_kind: BlockKind,
    key: &'a [u8; 32],
    nonce_seed: &'a [u8; 32],
    domain: &'a [u8],
    counter: u64,
    class_data_shard_max: u16,
    class_parity_shard_max: u16,
}

impl<'a> ObjectLoadContext<'a> {
    fn index_root(
        volume_header: &'a VolumeHeader,
        crypto_header: &'a CryptoHeaderFixed,
        subkeys: &'a Subkeys,
        extent: ObjectExtent,
    ) -> Self {
        Self {
            volume_header,
            crypto_header,
            extent,
            data_kind: BlockKind::IndexRootData,
            parity_kind: BlockKind::IndexRootParity,
            key: &subkeys.index_root_key,
            nonce_seed: &subkeys.index_nonce_seed,
            domain: b"idxroot",
            counter: 0,
            class_data_shard_max: crypto_header.index_root_fec_data_shards,
            class_parity_shard_max: crypto_header.index_root_fec_parity_shards,
        }
    }

    fn index_shard(
        volume_header: &'a VolumeHeader,
        crypto_header: &'a CryptoHeaderFixed,
        subkeys: &'a Subkeys,
        entry: &ShardEntry,
    ) -> Self {
        Self {
            volume_header,
            crypto_header,
            extent: ObjectExtent {
                first_block_index: entry.first_block_index,
                data_block_count: entry.data_block_count,
                parity_block_count: entry.parity_block_count,
                encrypted_size: entry.encrypted_size,
            },
            data_kind: BlockKind::IndexShardData,
            parity_kind: BlockKind::IndexShardParity,
            key: &subkeys.index_shard_key,
            nonce_seed: &subkeys.index_nonce_seed,
            domain: b"idxshard",
            counter: entry.shard_index,
            class_data_shard_max: crypto_header.index_fec_data_shards,
            class_parity_shard_max: crypto_header.index_fec_parity_shards,
        }
    }

    fn directory_hint(
        volume_header: &'a VolumeHeader,
        crypto_header: &'a CryptoHeaderFixed,
        subkeys: &'a Subkeys,
        entry: &DirectoryHintShardEntry,
    ) -> Self {
        Self {
            volume_header,
            crypto_header,
            extent: ObjectExtent {
                first_block_index: entry.first_block_index,
                data_block_count: entry.data_block_count,
                parity_block_count: entry.parity_block_count,
                encrypted_size: entry.encrypted_size,
            },
            data_kind: BlockKind::DirectoryHintData,
            parity_kind: BlockKind::DirectoryHintParity,
            key: &subkeys.dir_hint_key,
            nonce_seed: &subkeys.index_nonce_seed,
            domain: b"dirhint",
            counter: entry.hint_shard_index,
            class_data_shard_max: crypto_header.index_fec_data_shards,
            class_parity_shard_max: crypto_header.index_fec_parity_shards,
        }
    }

    fn dictionary(
        volume_header: &'a VolumeHeader,
        crypto_header: &'a CryptoHeaderFixed,
        subkeys: &'a Subkeys,
        index_root: &IndexRoot,
    ) -> Result<Self, FormatError> {
        Ok(Self {
            volume_header,
            crypto_header,
            extent: dictionary_extent_from_index_root(index_root)?,
            data_kind: BlockKind::DictionaryData,
            parity_kind: BlockKind::DictionaryParity,
            key: &subkeys.dictionary_key,
            nonce_seed: &subkeys.index_nonce_seed,
            domain: b"dict",
            counter: 0,
            class_data_shard_max: crypto_header.index_root_fec_data_shards,
            class_parity_shard_max: crypto_header.index_root_fec_parity_shards,
        })
    }

    fn payload(
        volume_header: &'a VolumeHeader,
        crypto_header: &'a CryptoHeaderFixed,
        subkeys: &'a Subkeys,
        envelope: &EnvelopeEntry,
    ) -> Self {
        Self {
            volume_header,
            crypto_header,
            extent: ObjectExtent {
                first_block_index: envelope.first_block_index,
                data_block_count: envelope.data_block_count,
                parity_block_count: envelope.parity_block_count,
                encrypted_size: envelope.encrypted_size,
            },
            data_kind: BlockKind::PayloadData,
            parity_kind: BlockKind::PayloadParity,
            key: &subkeys.enc_key,
            nonce_seed: &subkeys.nonce_seed,
            domain: b"envelope",
            counter: envelope.envelope_index,
            class_data_shard_max: crypto_header.fec_data_shards,
            class_parity_shard_max: crypto_header.fec_parity_shards,
        }
    }
}

fn dictionary_extent_from_index_root(index_root: &IndexRoot) -> Result<ObjectExtent, FormatError> {
    if index_root.header.dictionary_data_block_count == 0
        || index_root.header.dictionary_encrypted_size == 0
        || index_root.header.dictionary_decompressed_size == 0
    {
        return Err(FormatError::InvalidArchive("dictionary bootstrap required"));
    }
    Ok(ObjectExtent {
        first_block_index: index_root.header.dictionary_first_block,
        data_block_count: index_root.header.dictionary_data_block_count,
        parity_block_count: index_root.header.dictionary_parity_block_count,
        encrypted_size: index_root.header.dictionary_encrypted_size,
    })
}

fn load_metadata_object_from_parts(
    blocks: &impl BlockProvider,
    context: ObjectLoadContext<'_>,
    decompressed_size: u32,
) -> Result<Vec<u8>, FormatError> {
    let compressed = load_decrypted_object_from_parts(blocks, context)?;
    decompress_exact_zstd_frame(&compressed, decompressed_size as usize)
}

fn load_decrypted_object_from_parts(
    blocks: &impl BlockProvider,
    context: ObjectLoadContext<'_>,
) -> Result<Vec<u8>, FormatError> {
    load_decrypted_object_from_parts_with_parity_policy(blocks, context, ParityReadPolicy::Always)
}

fn load_decrypted_object_from_parts_with_parity_policy(
    blocks: &impl BlockProvider,
    context: ObjectLoadContext<'_>,
    parity_policy: ParityReadPolicy,
) -> Result<Vec<u8>, FormatError> {
    let repaired = load_repaired_object_data_shards_from_parts_with_parity_policy(
        blocks,
        context.crypto_header,
        context.extent,
        context.data_kind,
        context.parity_kind,
        context.class_data_shard_max,
        context.class_parity_shard_max,
        parity_policy,
    )?;
    let mut encrypted = Vec::with_capacity(context.extent.encrypted_size as usize);
    for shard in repaired {
        encrypted.extend_from_slice(&shard);
    }
    if encrypted.len() != context.extent.encrypted_size as usize {
        return Err(FormatError::InvalidArchive(
            "object encrypted size does not match repaired shards",
        ));
    }

    decrypt_padded_aead_object(
        AeadObjectContext {
            algo: context.crypto_header.aead_algo,
            key: context.key,
            nonce_seed: context.nonce_seed,
            domain: context.domain,
            archive_uuid: &context.volume_header.archive_uuid,
            session_id: &context.volume_header.session_id,
            counter: context.counter,
        },
        &encrypted,
    )
}

fn load_repaired_object_data_shards_from_parts(
    blocks: &impl BlockProvider,
    crypto_header: &CryptoHeaderFixed,
    extent: ObjectExtent,
    data_kind: BlockKind,
    parity_kind: BlockKind,
    class_data_shard_max: u16,
    class_parity_shard_max: u16,
) -> Result<Vec<Vec<u8>>, FormatError> {
    load_repaired_object_data_shards_from_parts_with_parity_policy(
        blocks,
        crypto_header,
        extent,
        data_kind,
        parity_kind,
        class_data_shard_max,
        class_parity_shard_max,
        ParityReadPolicy::Always,
    )
}

#[allow(clippy::too_many_arguments)]
fn load_repaired_object_data_shards_from_parts_with_parity_policy(
    blocks: &impl BlockProvider,
    crypto_header: &CryptoHeaderFixed,
    extent: ObjectExtent,
    data_kind: BlockKind,
    parity_kind: BlockKind,
    class_data_shard_max: u16,
    class_parity_shard_max: u16,
    parity_policy: ParityReadPolicy,
) -> Result<Vec<Vec<u8>>, FormatError> {
    validate_object_extent(
        extent,
        crypto_header,
        class_data_shard_max,
        class_parity_shard_max,
    )?;
    let block_size = crypto_header.block_size as usize;
    let data_count = extent.data_block_count as usize;
    let parity_count = extent.parity_block_count as usize;
    let mut data_shards = Vec::with_capacity(data_count);
    let mut parity_shards = Vec::with_capacity(parity_count);

    for offset in 0..data_count {
        let block_index = checked_u64_add(extent.first_block_index, offset as u64, "object")?;
        if let Some(record) = blocks.block(block_index)? {
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
        } else {
            data_shards.push(None);
        }
    }

    if parity_policy == ParityReadPolicy::RepairOnly && data_shards.iter().all(Option::is_some) {
        return repair_data_gf16(&data_shards, &[], block_size);
    }

    for offset in 0..parity_count {
        let block_index = checked_u64_add(
            extent.first_block_index,
            data_count as u64 + offset as u64,
            "object",
        )?;
        if let Some(record) = blocks.block(block_index)? {
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
        } else {
            parity_shards.push(None);
        }
    }

    repair_data_gf16(&data_shards, &parity_shards, block_size)
}

fn validate_object_extent(
    extent: ObjectExtent,
    crypto_header: &CryptoHeaderFixed,
    class_data_shard_max: u16,
    class_parity_shard_max: u16,
) -> Result<(), FormatError> {
    if extent.data_block_count == 0 || extent.encrypted_size == 0 {
        return Err(FormatError::InvalidArchive(
            "encrypted object has zero data blocks or size",
        ));
    }
    if extent.data_block_count > class_data_shard_max as u32 {
        return Err(FormatError::InvalidArchive(
            "encrypted object exceeds its class data-shard maximum",
        ));
    }
    if extent.parity_block_count > class_parity_shard_max as u32 {
        return Err(FormatError::InvalidArchive(
            "encrypted object exceeds its class parity-shard maximum",
        ));
    }
    let required_parity = required_object_parity(extent.data_block_count as u64, crypto_header)?;
    if extent.parity_block_count != required_parity {
        return Err(FormatError::InvalidArchive(
            "encrypted object parity does not match v41 compute_parity",
        ));
    }
    let total = checked_u64_add(
        extent.data_block_count as u64,
        extent.parity_block_count as u64,
        "encrypted object shard count overflow",
    )?;
    if total > 65_535 {
        return Err(FormatError::FecTooManyShards(total as usize));
    }
    let expected = checked_u64_mul(
        extent.data_block_count as u64,
        crypto_header.block_size as u64,
        "encrypted object size overflow",
    )?;
    if expected != extent.encrypted_size as u64 {
        return Err(FormatError::InvalidArchive(
            "encrypted object size is not data_block_count * block_size",
        ));
    }
    if extent.encrypted_size as usize <= crypto_header.aead_algo.tag_len() {
        return Err(FormatError::InvalidArchive(
            "encrypted object is too small for AEAD tag",
        ));
    }
    Ok(())
}

pub(crate) fn required_object_parity(
    data_block_count: u64,
    crypto_header: &CryptoHeaderFixed,
) -> Result<u32, FormatError> {
    let min_parity =
        if crypto_header.volume_loss_tolerance > 0 || crypto_header.bit_rot_buffer_pct > 0 {
            1
        } else {
            0
        };
    let mut parity = 0u64;
    for _ in 0..100 {
        let total = data_block_count
            .checked_add(parity)
            .ok_or(FormatError::InvalidArchive("parity total overflow"))?;
        let by_volume = checked_u64_mul(
            crypto_header.volume_loss_tolerance as u64,
            ceil_div_u64(total, crypto_header.stripe_width as u64)?,
            "volume-loss parity overflow",
        )?;
        let by_bitrot = ceil_div_u64(
            checked_u64_mul(
                total,
                crypto_header.bit_rot_buffer_pct as u64,
                "bit-rot parity overflow",
            )?,
            100,
        )?;
        let next = by_volume
            .checked_add(by_bitrot)
            .ok_or(FormatError::InvalidArchive("parity overflow"))?
            .max(min_parity);
        if next == parity {
            return u32::try_from(next)
                .map_err(|_| FormatError::InvalidArchive("parity count overflow"));
        }
        parity = next;
    }
    Err(FormatError::InvalidArchive(
        "parity calculation did not converge",
    ))
}

fn ceil_div_u64(numerator: u64, denominator: u64) -> Result<u64, FormatError> {
    if denominator == 0 {
        return Err(FormatError::InvalidArchive("division by zero"));
    }
    numerator
        .checked_add(denominator - 1)
        .ok_or(FormatError::InvalidArchive("ceiling division overflow"))
        .map(|value| value / denominator)
}

fn frame_range_for_file<'b>(
    shard: &'b IndexShard,
    file: &FileEntry,
) -> Result<&'b [FrameEntry], FormatError> {
    let start = shard
        .frames
        .binary_search_by_key(&file.first_frame_index, |entry| entry.frame_index)
        .map_err(|_| FormatError::InvalidArchive("FileEntry references missing FrameEntry"))?;
    let count = usize::try_from(file.frame_count)
        .map_err(|_| FormatError::InvalidArchive("FileEntry frame count overflow"))?;
    let end = start.checked_add(count).ok_or(FormatError::InvalidArchive(
        "FileEntry frame range overflow",
    ))?;
    let frames = shard
        .frames
        .get(start..end)
        .ok_or(FormatError::InvalidArchive(
            "FileEntry references missing FrameEntry",
        ))?;
    for (offset, frame) in frames.iter().enumerate() {
        let expected = file.first_frame_index.checked_add(offset as u64).ok_or(
            FormatError::InvalidArchive("FileEntry frame range overflow"),
        )?;
        if frame.frame_index != expected {
            return Err(FormatError::InvalidArchive(
                "FileEntry references missing FrameEntry",
            ));
        }
    }
    Ok(frames)
}

fn metadata_limits(crypto_header: &CryptoHeaderFixed) -> MetadataLimits {
    MetadataLimits {
        block_size: crypto_header.block_size,
        max_path_length: crypto_header.max_path_length,
        max_payload_data_shards: crypto_header.fec_data_shards,
        max_payload_parity_shards: crypto_header.fec_parity_shards,
        max_index_data_shards: crypto_header.index_fec_data_shards,
        max_index_parity_shards: crypto_header.index_fec_parity_shards,
        max_index_root_data_shards: crypto_header.index_root_fec_data_shards,
        max_index_root_parity_shards: crypto_header.index_root_fec_parity_shards,
        ..MetadataLimits::default()
    }
}

fn verify_dense_keys<T>(
    entries: &BTreeMap<u64, T>,
    expected_count: u64,
    structure: &'static str,
) -> Result<(), FormatError> {
    if entries.len() as u64 != expected_count {
        return Err(FormatError::InvalidArchive(
            "decoded table count does not match IndexRoot",
        ));
    }
    for expected in 0..expected_count {
        if !entries.contains_key(&expected) {
            return Err(FormatError::InvalidMetadata {
                structure,
                reason: "global index coverage has a gap",
            });
        }
    }
    Ok(())
}

fn validate_envelope_frame_coverage(
    frames: &BTreeMap<u64, FrameEntry>,
    envelopes: &BTreeMap<u64, EnvelopeEntry>,
) -> Result<(), FormatError> {
    let mut accounted_frames = BTreeSet::new();
    for envelope in envelopes.values() {
        let first = envelope.first_frame_index;
        let end =
            first
                .checked_add(envelope.frame_count as u64)
                .ok_or(FormatError::InvalidArchive(
                    "EnvelopeEntry frame range overflow",
                ))?;
        let mut ranges = Vec::with_capacity(envelope.frame_count as usize);
        for frame_index in first..end {
            let frame = frames.get(&frame_index).ok_or(FormatError::InvalidArchive(
                "EnvelopeEntry references missing FrameEntry",
            ))?;
            if frame.envelope_index != envelope.envelope_index {
                return Err(FormatError::InvalidArchive(
                    "FrameEntry envelope_index does not match containing EnvelopeEntry",
                ));
            }
            if !accounted_frames.insert(frame_index) {
                return Err(FormatError::InvalidArchive(
                    "FrameEntry is covered by multiple EnvelopeEntries",
                ));
            }
            let start = frame.offset_in_envelope as usize;
            let end = checked_add(start, frame.compressed_size as usize, "FrameEntry")?;
            if end > envelope.plaintext_size as usize {
                return Err(FormatError::InvalidArchive(
                    "FrameEntry exceeds EnvelopeEntry plaintext_size",
                ));
            }
            ranges.push((start, end));
        }
        validate_exact_coverage_ranges(
            &mut ranges,
            envelope.plaintext_size as usize,
            "EnvelopeEntry frame coverage has a gap or overlap",
        )?;
    }

    for frame_index in frames.keys() {
        if !accounted_frames.contains(frame_index) {
            return Err(FormatError::InvalidArchive(
                "FrameEntry is not covered by any EnvelopeEntry",
            ));
        }
    }
    Ok(())
}

fn validate_global_file_table_order(shards: &[IndexShard]) -> Result<(), FormatError> {
    let mut previous = None::<([u8; 8], Vec<u8>, u64)>;
    for shard in shards {
        for (idx, file) in shard.files.iter().enumerate() {
            let path = shard
                .file_path(idx)
                .ok_or(FormatError::InvalidArchive("FileEntry path is missing"))?
                .to_vec();
            let start = shard
                .tar_member_group_start(idx)
                .ok_or(FormatError::InvalidArchive(
                    "FileEntry tar member start is missing",
                ))?;
            let key = (file.path_hash, path, start);
            validate_global_file_table_key_step(previous.as_ref(), &key)?;
            previous = Some(key);
        }
    }
    Ok(())
}

fn validate_global_file_table_key_step(
    previous: Option<&([u8; 8], Vec<u8>, u64)>,
    current: &([u8; 8], Vec<u8>, u64),
) -> Result<(), FormatError> {
    if let Some(previous) = previous {
        if previous >= current {
            return Err(FormatError::InvalidArchive(
                "global FileEntry rows are not sorted and unique",
            ));
        }
    }
    Ok(())
}

fn validate_file_extent_coverage_ranges(
    extents: &[(u64, u64)],
    tar_len: u64,
) -> Result<(), FormatError> {
    let mut ranges = Vec::with_capacity(extents.len());
    for (start, len) in extents {
        let end = checked_u64_add(*start, *len, "FileEntry")?;
        if end > tar_len {
            return Err(FormatError::InvalidArchive(
                "FileEntry extent exceeds IndexRoot tar_total_size",
            ));
        }
        ranges.push((*start, end));
    }
    validate_exact_coverage_ranges_u64(
        &mut ranges,
        tar_len,
        "FileEntry extents do not cover tar stream exactly",
    )
}

fn add_expected_directory_hint_rows(
    map: &mut DirectoryHintMap,
    shard_row_index: u32,
    path: &[u8],
    kind: TarEntryKind,
) {
    map.entry(Vec::new()).or_default().insert(shard_row_index);
    for (idx, byte) in path.iter().enumerate() {
        if *byte == b'/' {
            map.entry(path[..idx].to_vec())
                .or_default()
                .insert(shard_row_index);
        }
    }
    if kind == TarEntryKind::Directory {
        map.entry(path.to_vec())
            .or_default()
            .insert(shard_row_index);
    }
}

fn validate_directory_hint_tables_against_expected(
    tables: &[DirectoryHintTable],
    expected: &DirectoryHintMap,
) -> Result<(), FormatError> {
    let mut actual = Vec::new();
    let mut previous_key: Option<([u8; 8], Vec<u8>)> = None;

    for table in tables {
        for entry_index in 0..table.entries.len() {
            let path = table
                .entry_path(entry_index)
                .ok_or(FormatError::InvalidArchive(
                    "DirectoryHintEntry path is missing",
                ))?;
            let key = (hash_prefix(path), path.to_vec());
            if let Some(previous) = &previous_key {
                if previous >= &key {
                    return Err(FormatError::InvalidArchive(
                        "DirectoryHintEntry rows are not globally sorted",
                    ));
                }
            }
            previous_key = Some(key);

            let rows =
                table
                    .shard_rows_for_entry(entry_index)
                    .ok_or(FormatError::InvalidArchive(
                        "DirectoryHintEntry shard rows are missing",
                    ))?;
            actual.push((path.to_vec(), rows.to_vec()));
        }
    }

    if actual != sorted_directory_hint_rows(expected) {
        return Err(FormatError::InvalidArchive(
            "directory hint map does not match decoded files",
        ));
    }
    Ok(())
}

fn sorted_directory_hint_rows(map: &DirectoryHintMap) -> Vec<(Vec<u8>, Vec<u32>)> {
    let mut rows = map
        .iter()
        .map(|(path, shard_rows)| {
            (
                path.clone(),
                shard_rows.iter().copied().collect::<Vec<u32>>(),
            )
        })
        .collect::<Vec<_>>();
    rows.sort_by(|(left_path, _), (right_path, _)| {
        hash_prefix(left_path)
            .cmp(&hash_prefix(right_path))
            .then_with(|| left_path.cmp(right_path))
    });
    rows
}

fn validate_exact_coverage_ranges(
    ranges: &mut [(usize, usize)],
    expected_end: usize,
    reason: &'static str,
) -> Result<(), FormatError> {
    ranges.sort_unstable();
    let mut cursor = 0usize;
    for (start, end) in ranges.iter().copied() {
        if start != cursor || end < start {
            return Err(FormatError::InvalidArchive(reason));
        }
        cursor = end;
    }
    if cursor != expected_end {
        return Err(FormatError::InvalidArchive(reason));
    }
    Ok(())
}

fn validate_exact_coverage_ranges_u64(
    ranges: &mut [(u64, u64)],
    expected_end: u64,
    reason: &'static str,
) -> Result<(), FormatError> {
    ranges.sort_unstable();
    let mut cursor = 0u64;
    for (start, end) in ranges.iter().copied() {
        if start != cursor || end < start {
            return Err(FormatError::InvalidArchive(reason));
        }
        cursor = end;
    }
    if cursor != expected_end {
        return Err(FormatError::InvalidArchive(reason));
    }
    Ok(())
}

fn object_block_range(
    first_block_index: u64,
    data_block_count: u32,
    parity_block_count: u32,
    structure: &'static str,
) -> Result<(u64, u64), FormatError> {
    let total = data_block_count as u64 + parity_block_count as u64;
    if total == 0 {
        return Err(FormatError::InvalidArchive(structure));
    }
    let end = checked_u64_add(first_block_index, total, structure)?;
    Ok((first_block_index, end))
}

fn validate_non_overlapping_object_ranges(ranges: &mut [(u64, u64)]) -> Result<(), FormatError> {
    ranges.sort_unstable();
    for pair in ranges.windows(2) {
        if pair[0].1 > pair[1].0 {
            return Err(FormatError::InvalidArchive(
                "encrypted object block ranges overlap",
            ));
        }
    }
    Ok(())
}

pub(crate) fn observed_archive_size(
    sizes: impl IntoIterator<Item = u64>,
) -> Result<u64, FormatError> {
    sizes.into_iter().try_fold(0u64, |sum, size| {
        sum.checked_add(size).ok_or(FormatError::InvalidArchive(
            "observed archive size overflow",
        ))
    })
}

pub(crate) fn total_extraction_size_cap(
    options: ReaderOptions,
    observed_archive_bytes: u64,
) -> u64 {
    options
        .max_total_extraction_size
        .min(observed_archive_bytes.saturating_mul(10))
}

fn utf8_path(bytes: &[u8]) -> Result<String, FormatError> {
    std::str::from_utf8(bytes)
        .map(|path| path.to_owned())
        .map_err(|_| FormatError::UnsafeArchivePath)
}

fn manifest_footer_global_pre_hmac_bytes(manifest_footer: &ManifestFooter) -> [u8; 104] {
    let mut bytes = [0u8; 104];
    bytes.copy_from_slice(&manifest_footer.to_bytes()[..104]);
    bytes[36..40].fill(0);
    bytes
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn slice<'b>(
    bytes: &'b [u8],
    offset: usize,
    len: usize,
    structure: &'static str,
) -> Result<&'b [u8], FormatError> {
    let end = checked_add(offset, len, structure)?;
    bytes.get(offset..end).ok_or(FormatError::InvalidLength {
        structure,
        expected: end,
        actual: bytes.len(),
    })
}

fn read_at_vec(
    reader: &dyn ArchiveReadAt,
    offset: u64,
    len: usize,
    structure: &'static str,
) -> Result<Vec<u8>, FormatError> {
    let expected_end = offset
        .checked_add(len as u64)
        .ok_or(FormatError::InvalidArchive("archive read range overflow"))?;
    let observed_len = reader.len()?;
    if expected_end > observed_len {
        return Err(FormatError::InvalidLength {
            structure,
            expected: to_usize(expected_end, structure)?,
            actual: to_usize(observed_len, structure)?,
        });
    }
    let mut out = vec![0u8; len];
    reader.read_exact_at(offset, &mut out)?;
    Ok(out)
}

fn read_at_vec_unchecked(
    reader: &dyn ArchiveReadAt,
    offset: u64,
    len: usize,
) -> Result<Vec<u8>, FormatError> {
    let mut out = vec![0u8; len];
    reader.read_exact_at(offset, &mut out)?;
    Ok(out)
}

fn parallel_map_ref<T, U, F>(items: &[T], jobs: usize, f: F) -> Result<Vec<U>, FormatError>
where
    T: Sync,
    U: Send,
    F: Fn(&T) -> Result<U, FormatError> + Sync,
{
    if jobs <= 1 || items.len() <= 1 {
        return items.iter().map(f).collect();
    }
    let worker_count = jobs.min(items.len());
    let chunk_size = items.len().div_ceil(worker_count);
    let mut out = Vec::with_capacity(items.len());
    thread::scope(|scope| {
        let handles = items
            .chunks(chunk_size)
            .map(|chunk| scope.spawn(|| chunk.iter().map(&f).collect::<Result<Vec<_>, _>>()))
            .collect::<Vec<_>>();
        for handle in handles {
            let mut chunk = handle
                .join()
                .map_err(|_| FormatError::InvalidArchive("reader worker panicked"))??;
            out.append(&mut chunk);
        }
        Ok(out)
    })
}

fn checked_add(lhs: usize, rhs: usize, structure: &'static str) -> Result<usize, FormatError> {
    lhs.checked_add(rhs)
        .ok_or(FormatError::InvalidArchive(structure))
}

fn checked_u64_add(lhs: u64, rhs: u64, structure: &'static str) -> Result<u64, FormatError> {
    lhs.checked_add(rhs)
        .ok_or(FormatError::InvalidArchive(structure))
}

fn to_usize(value: u64, structure: &'static str) -> Result<usize, FormatError> {
    usize::try_from(value).map_err(|_| FormatError::InvalidArchive(structure))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::compression::compress_zstd_frame;
    use crate::crypto::{compute_hmac, encrypt_padded_aead_object};
    use crate::entry_metadata::RestorePolicy;
    use crate::fec::encode_parity_gf16;
    use crate::format::{
        AeadAlgo, CompressionAlgo, FecAlgo, KdfAlgo, CRYPTO_EXTENSION_HEADER_LEN,
        CRYPTO_HEADER_FIXED_LEN, FORMAT_VERSION, READER_MAX_SUPPORTED_VOLUME_FORMAT_REV,
        VOLUME_FORMAT_REV, VOLUME_FORMAT_REV_45,
    };
    use crate::metadata::{
        DirectoryHintEntry, DirectoryHintTableHeader, IndexRootHeader, IndexShardHeader,
        ENVELOPE_ENTRY_LEN, FILE_ENTRY_LEN, FRAME_ENTRY_LEN, INDEX_SHARD_HEADER_LEN,
    };
    use crate::non_seekable_reader::{
        extract_non_seekable_stream_to_dir, list_non_seekable_stream, verify_non_seekable_stream,
        verify_non_seekable_stream_with_bootstrap_sidecar, verify_non_seekable_stream_with_options,
        verify_non_seekable_stream_with_recipient_wrap_resolver_options, NonSeekableReaderOptions,
        SequentialRootAuthStatus,
    };
    use crate::raw_stream_profile::{
        serialize_raw_stream_content_model_extension, RAW_STREAM_UNSUPPORTED_MESSAGE,
    };
    use crate::wire::RecipientRecordV1;
    use crate::writer::NativeFileMetadata;
    use crate::writer::{
        write_archive, write_archive_sources_to_sink_single_pass, write_archive_unencrypted,
        write_archive_with_dictionary, write_archive_with_kdf,
        write_archive_with_recipient_wrap_records, write_archive_with_root_auth,
        write_archive_with_root_auth_and_recipient_wrap_records, MemoryArchiveSink,
        PortableFileMetadata, PortableModeOrigin, PortablePosixOwner, RegularFile,
        RegularFileSource, RootAuthSigningRequest, RootAuthWriterConfig, SourceEntryKind,
        WriterOptions,
    };
    #[cfg(target_os = "linux")]
    use crate::writer::{NativeAuxiliaryMetadata, NativeAuxiliaryNameEncoding};

    #[test]
    fn exposed_attributes_prefer_exact_native_platform_flags() {
        let mut records = crate::entry_metadata::PaxRecords::new();
        records.insert("TZAP.macos.st-flags".into(), b"0000000000008000".to_vec());
        assert_eq!(exposed_file_attributes(&records, Some(2)), Some(0x8000));

        records.remove("TZAP.macos.st-flags");
        records.insert("TZAP.windows.file-attributes".into(), b"00000022".to_vec());
        assert_eq!(exposed_file_attributes(&records, Some(2)), Some(0x22));

        records.clear();
        assert_eq!(exposed_file_attributes(&records, Some(2)), Some(2));
    }

    fn master_key() -> MasterKey {
        MasterKey::from_raw_key(&[0x42; 32]).unwrap()
    }

    fn recipient_wrap_test_record() -> RecipientRecordV1 {
        RecipientRecordV1 {
            record_length: 0,
            profile_id: 1,
            recipient_identity_type: 2,
            flags: 0,
            recipient_identity_length: 0,
            profile_payload_length: 0,
            recipient_identity_digest: [0u8; 32],
            recipient_identity_bytes: b"recipient-a".to_vec(),
            profile_payload_bytes: b"profile-payload".to_vec(),
        }
    }

    fn recipient_wrap_layout(volume: &[u8]) -> (usize, usize, usize, usize, u32) {
        let header = VolumeHeader::parse(&volume[..VOLUME_HEADER_LEN]).unwrap();
        let crypto_start = header.crypto_header_offset as usize;
        let crypto_len = header.crypto_header_length as usize;
        let crypto_end = crypto_start + crypto_len;
        let crypto = CryptoHeader::parse(
            &volume[crypto_start..crypto_end],
            header.crypto_header_length,
        )
        .unwrap();
        let KdfParams::RecipientWrap {
            key_wrap_table_length,
            ..
        } = crypto.kdf_params
        else {
            panic!("expected RecipientWrap KdfParams");
        };
        (
            crypto_start,
            crypto_len,
            crypto_end,
            key_wrap_table_length as usize,
            key_wrap_table_length,
        )
    }

    fn rewrite_recipient_wrap_kdf_digest(crypto_bytes: &mut [u8], digest: [u8; 32]) {
        let digest_start = CRYPTO_HEADER_FIXED_LEN + 14;
        crypto_bytes[digest_start..digest_start + 32].copy_from_slice(&digest);
    }

    fn mutate_top_level_recipient_wrap_public_profile(volume: &mut [u8]) {
        let (crypto_start, crypto_len, table_start, table_len, table_len_u32) =
            recipient_wrap_layout(volume);
        let table_end = table_start + table_len;
        volume[table_end - 1] ^= 0x5a;
        let digest = compute_key_wrap_table_digest(table_len_u32, &volume[table_start..table_end]);
        rewrite_recipient_wrap_kdf_digest(
            &mut volume[crypto_start..crypto_start + crypto_len],
            digest,
        );
    }

    fn mutate_cmra_recipient_wrap_public_profile(volume: &mut [u8]) {
        rewrite_public_cmra_image(volume, |image| {
            let table_region = image
                .regions
                .iter_mut()
                .find(|region| region.region_type == 6)
                .unwrap();
            *table_region.bytes.last_mut().unwrap() ^= 0x5a;
            let digest =
                compute_key_wrap_table_digest(table_region.bytes.len() as u32, &table_region.bytes);
            let crypto_region = image
                .regions
                .iter_mut()
                .find(|region| region.region_type == 2)
                .unwrap();
            rewrite_recipient_wrap_kdf_digest(&mut crypto_region.bytes, digest);
        });
    }

    fn add_raw_stream_profile_to_physical_crypto_header(volume: &mut Vec<u8>) {
        let mut header = VolumeHeader::parse(&volume[..VOLUME_HEADER_LEN]).unwrap();
        let crypto_start = header.crypto_header_offset as usize;
        let crypto_len = header.crypto_header_length as usize;
        let hmac_start = crypto_start + crypto_len - CRYPTO_HEADER_HMAC_LEN;
        let terminator_start = hmac_start - CRYPTO_EXTENSION_HEADER_LEN;
        let extension = serialize_raw_stream_content_model_extension();
        let new_crypto_len = header.crypto_header_length + extension.len() as u32;

        volume.splice(terminator_start..terminator_start, extension);
        header.crypto_header_length = new_crypto_len;
        volume[..VOLUME_HEADER_LEN].copy_from_slice(&header.to_bytes());
        volume[crypto_start + 4..crypto_start + 8].copy_from_slice(&new_crypto_len.to_le_bytes());
    }

    fn recompute_physical_crypto_header_hmac(volume: &mut [u8], master_key: &MasterKey) {
        let header = VolumeHeader::parse(&volume[..VOLUME_HEADER_LEN]).unwrap();
        let crypto_start = header.crypto_header_offset as usize;
        let crypto_end = crypto_start + header.crypto_header_length as usize;
        let hmac_start = crypto_end - CRYPTO_HEADER_HMAC_LEN;
        let subkeys =
            Subkeys::derive(master_key, &header.archive_uuid, &header.session_id).unwrap();
        let hmac = compute_hmac(
            HmacDomain::CryptoHeader,
            &subkeys.mac_key,
            &header.archive_uuid,
            &header.session_id,
            &volume[crypto_start..hmac_start],
        );
        volume[hmac_start..crypto_end].copy_from_slice(&hmac);
    }

    #[test]
    fn reader_defaults_use_available_parallelism_jobs() {
        let options = ReaderOptions::default();

        assert_eq!(options.jobs, default_jobs());
        assert!(options.jobs >= 1);
    }

    #[test]
    fn reader_options_reject_zero_jobs() {
        let err = OpenedArchive::open_with_options(
            &[],
            &master_key(),
            ReaderOptions {
                jobs: 0,
                ..ReaderOptions::default()
            },
        )
        .unwrap_err();

        assert_eq!(
            err,
            FormatError::ReaderUnsupported("jobs must be at least 1")
        );
    }

    const TEST_ROOT_AUTH_ID: u16 = 0xe001;
    const TEST_ROOT_AUTH_VALUE_LEN: u32 = 32;

    fn test_root_auth_config() -> RootAuthWriterConfig<'static> {
        RootAuthWriterConfig {
            authenticator_id: TEST_ROOT_AUTH_ID,
            signer_identity_type: 0,
            signer_identity: &[],
            authenticator_value_length: TEST_ROOT_AUTH_VALUE_LEN,
        }
    }

    fn test_root_auth_value(request: &RootAuthSigningRequest) -> Vec<u8> {
        request.archive_root.to_vec()
    }

    fn test_root_auth_verifies(footer: &RootAuthFooterV1, archive_root: &[u8; 32]) -> bool {
        footer.authenticator_id == TEST_ROOT_AUTH_ID
            && footer.signer_identity_type == 0
            && footer.signer_identity_bytes.is_empty()
            && footer.authenticator_value.as_slice() == archive_root
    }

    fn dictionary() -> &'static [u8] {
        b"dir/dict.txt common words common words common words dictionary payload"
    }

    #[derive(Clone)]
    struct CountingReadAt {
        bytes: std::sync::Arc<Vec<u8>>,
        reads: std::sync::Arc<std::sync::Mutex<Vec<(u64, u64)>>>,
        denied_ranges: std::sync::Arc<Vec<(u64, u64)>>,
    }

    impl CountingReadAt {
        fn new(bytes: Vec<u8>, denied_ranges: Vec<(u64, u64)>) -> Self {
            Self {
                bytes: std::sync::Arc::new(bytes),
                reads: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
                denied_ranges: std::sync::Arc::new(denied_ranges),
            }
        }

        fn reads(&self) -> Vec<(u64, u64)> {
            self.reads.lock().unwrap().clone()
        }
    }

    impl ArchiveReadAt for CountingReadAt {
        fn len(&self) -> Result<u64, FormatError> {
            u64::try_from(self.bytes.as_ref().len())
                .map_err(|_| FormatError::InvalidArchive("archive length overflow"))
        }

        fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), FormatError> {
            let end = checked_u64_add(offset, buf.len() as u64, "archive read range overflow")?;
            self.reads.lock().unwrap().push((offset, end));
            if self
                .denied_ranges
                .iter()
                .any(|(start, limit)| ranges_overlap(offset, end, *start, *limit))
            {
                return Err(FormatError::InvalidArchive("denied test read"));
            }
            let start = to_usize(offset, "archive")?;
            let end_usize = checked_add(start, buf.len(), "archive")?;
            let source = self
                .bytes
                .get(start..end_usize)
                .ok_or(FormatError::InvalidLength {
                    structure: "archive",
                    expected: end_usize,
                    actual: self.bytes.as_ref().len(),
                })?;
            buf.copy_from_slice(source);
            Ok(())
        }
    }

    fn ranges_overlap(left_start: u64, left_end: u64, right_start: u64, right_end: u64) -> bool {
        left_start < right_end && right_start < left_end
    }

    fn single_stream_options() -> WriterOptions {
        WriterOptions {
            stripe_width: 1,
            volume_loss_tolerance: 0,
            ..WriterOptions::default()
        }
    }

    struct ChunkedReader {
        bytes: Vec<u8>,
        cursor: usize,
        max_chunk: usize,
    }

    impl ChunkedReader {
        fn new(bytes: Vec<u8>, max_chunk: usize) -> Self {
            Self {
                bytes,
                cursor: 0,
                max_chunk,
            }
        }
    }

    impl std::io::Read for ChunkedReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.cursor >= self.bytes.len() {
                return Ok(0);
            }
            let available = self.bytes.len() - self.cursor;
            let len = available.min(buf.len()).min(self.max_chunk);
            buf[..len].copy_from_slice(&self.bytes[self.cursor..self.cursor + len]);
            self.cursor += len;
            Ok(len)
        }
    }

    #[test]
    fn global_file_table_key_step_rejects_distinct_path_regression() {
        let previous = ([1u8; 8], b"b.txt".to_vec(), 0);
        let current = ([1u8; 8], b"a.txt".to_vec(), 0);

        assert_eq!(
            validate_global_file_table_key_step(Some(&previous), &current).unwrap_err(),
            FormatError::InvalidArchive("global FileEntry rows are not sorted and unique")
        );
    }

    #[test]
    fn global_file_table_key_step_rejects_duplicate_full_key() {
        let previous = ([1u8; 8], b"a.txt".to_vec(), 7);
        let current = ([1u8; 8], b"a.txt".to_vec(), 7);

        assert_eq!(
            validate_global_file_table_key_step(Some(&previous), &current).unwrap_err(),
            FormatError::InvalidArchive("global FileEntry rows are not sorted and unique")
        );
    }

    fn small_block_recovery_options() -> WriterOptions {
        WriterOptions {
            block_size: 4096,
            chunk_size: 32 * 1024,
            envelope_target_size: 32 * 1024,
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 1,
            fec_data_shards: 16,
            fec_parity_shards: 1,
            index_fec_data_shards: 4,
            index_fec_parity_shards: 1,
            index_root_fec_data_shards: 16,
            index_root_fec_parity_shards: 1,
            ..WriterOptions::default()
        }
    }

    fn parity_rich_recovery_options() -> WriterOptions {
        WriterOptions {
            block_size: 4096,
            chunk_size: 32 * 1024,
            envelope_target_size: 32 * 1024,
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 40,
            fec_data_shards: 16,
            fec_parity_shards: 16,
            index_fec_data_shards: 4,
            index_fec_parity_shards: 4,
            index_root_fec_data_shards: 16,
            index_root_fec_parity_shards: 16,
            ..WriterOptions::default()
        }
    }

    fn pseudo_random_bytes(len: usize) -> Vec<u8> {
        let mut state = 0x1234_5678u32;
        (0..len)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (state >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn opens_lists_verifies_and_extracts_one_file_archive() {
        let archive = write_archive(
            &[RegularFile::new("dir/hello.txt", b"hello m7")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();

        assert_eq!(
            opened.list_files().unwrap(),
            vec![ArchiveEntry {
                path: "dir/hello.txt".to_string(),
                file_data_size: 8,
                kind: TarEntryKind::Regular,
                mode: 0o644,
                mtime: ArchiveTimestamp::UNIX_EPOCH,
                diagnostics: Vec::new(),
                link_target: None,
                created: None,
                accessed: None,
                attributes: None,
                uid: None,
                gid: None,
                uname: None,
                gname: None,
            }]
        );
        opened.verify().unwrap();
        assert_eq!(
            opened.extract_file("dir/hello.txt").unwrap(),
            Some(b"hello m7".to_vec())
        );
        assert_eq!(opened.extract_file("missing.txt").unwrap(), None);
    }

    #[test]
    fn root_auth_archive_round_trips_and_verifies_with_callback() {
        let archive = write_archive_with_root_auth(
            &[RegularFile::new("signed.txt", b"root-auth payload")],
            &master_key(),
            single_stream_options(),
            RootAuthWriterConfig {
                authenticator_id: 0x7777,
                signer_identity_type: 1,
                signer_identity: b"test signer",
                authenticator_value_length: 32,
            },
            |request| Ok(request.archive_root.to_vec()),
        )
        .unwrap();

        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        opened.verify().unwrap();
        let verified = opened
            .verify_root_auth_with(|footer, archive_root| {
                Ok(footer.authenticator_value == archive_root.as_slice())
            })
            .unwrap();

        assert_eq!(verified.authenticator_id, 0x7777);
        assert_eq!(verified.signer_identity_type, 1);
        assert_eq!(verified.signer_identity_bytes, b"test signer");
        assert_eq!(
            verified.archive_root,
            opened.root_auth_footer.as_ref().unwrap().archive_root
        );
        assert_eq!(
            verified.diagnostics,
            vec![
                RootAuthDiagnostic::RootAuthContentVerified,
                RootAuthDiagnostic::AuthenticatedMetadataNotRootSigned,
                RootAuthDiagnostic::RecoveryMarginNotRootAuthenticated,
                RootAuthDiagnostic::RecoveryMarginUnchecked,
            ]
        );
    }

    #[test]
    fn root_auth_rejects_fast_content_verification_token() {
        let archive = write_archive_with_root_auth(
            &[RegularFile::new("signed.txt", b"root-auth payload")],
            &master_key(),
            single_stream_options(),
            RootAuthWriterConfig {
                authenticator_id: 0x7777,
                signer_identity_type: 1,
                signer_identity: b"test signer",
                authenticator_value_length: 32,
            },
            |request| Ok(request.archive_root.to_vec()),
        )
        .unwrap();

        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        let content_verification = opened.verify_content_fast().unwrap();
        assert_eq!(
            opened
                .verify_root_auth_with_verified_content(&content_verification, |_, _| Ok(true))
                .unwrap_err(),
            FormatError::ReaderUnsupported(
                "RootAuth verification requires full archive content verification"
            )
        );
    }

    #[test]
    fn root_auth_verification_requires_authenticator_success() {
        let archive = write_archive_with_root_auth(
            &[RegularFile::new("signed.txt", b"root-auth payload")],
            &master_key(),
            single_stream_options(),
            RootAuthWriterConfig {
                authenticator_id: 9,
                signer_identity_type: 1,
                signer_identity: b"test signer",
                authenticator_value_length: 32,
            },
            |request| Ok(request.archive_root.to_vec()),
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();

        assert_eq!(
            opened.verify_root_auth_with(|_, _| Ok(false)).unwrap_err(),
            FormatError::InvalidArchive("root-auth authenticator verification failed")
        );
    }

    #[test]
    fn public_no_key_verifies_encrypted_data_block_commitment_with_callback() {
        let archive = write_archive_with_root_auth(
            &[RegularFile::new("public.txt", b"public commitment")],
            &master_key(),
            single_stream_options(),
            RootAuthWriterConfig {
                authenticator_id: 0x2222,
                signer_identity_type: 1,
                signer_identity: b"public verifier",
                authenticator_value_length: 32,
            },
            |request| Ok(request.archive_root.to_vec()),
        )
        .unwrap();

        let verified = public_no_key_verify_archive_with(&archive.bytes, |footer, archive_root| {
            Ok(footer.authenticator_value == archive_root.as_slice())
        })
        .unwrap();

        assert_eq!(verified.authenticator_id, 0x2222);
        assert_eq!(verified.signer_identity_bytes, b"public verifier");
        assert!(verified.total_data_block_count > 0);
    }

    #[test]
    fn public_no_key_verifier_not_invoked_for_future_revision() {
        let archive = write_archive_with_root_auth(
            &[RegularFile::new("public.txt", b"public callback")],
            &master_key(),
            single_stream_options(),
            RootAuthWriterConfig {
                authenticator_id: 0x2222,
                signer_identity_type: 1,
                signer_identity: b"public verifier",
                authenticator_value_length: 32,
            },
            |request| Ok(request.archive_root.to_vec()),
        )
        .unwrap();
        let mut bytes = archive.bytes;
        let mut header = VolumeHeader::parse(&bytes[..VOLUME_HEADER_LEN]).unwrap();
        header.volume_format_rev = VOLUME_FORMAT_REV_45 + 1;
        bytes[..VOLUME_HEADER_LEN].copy_from_slice(&header.to_bytes());

        let mut called = false;
        let err = public_no_key_verify_archive_with(&bytes, |_, _| {
            called = true;
            Ok(true)
        })
        .unwrap_err();

        assert!(!called);
        assert_eq!(
            err,
            FormatError::UnsupportedVolumeFormatRevision {
                format_version: FORMAT_VERSION,
                volume_format_rev: VOLUME_FORMAT_REV_45 + 1,
                reader_max_supported_revision: READER_MAX_SUPPORTED_VOLUME_FORMAT_REV,
            }
        );
    }

    #[test]
    fn public_no_key_rejects_public_header_revision_mismatch() {
        let archive = write_archive_with_root_auth(
            &[RegularFile::new("public.txt", b"public v45 only")],
            &master_key(),
            single_stream_options(),
            RootAuthWriterConfig {
                authenticator_id: 0x2222,
                signer_identity_type: 1,
                signer_identity: b"public verifier",
                authenticator_value_length: 32,
            },
            |request| Ok(request.archive_root.to_vec()),
        )
        .unwrap();
        let mut bytes = archive.bytes;
        let mut header = VolumeHeader::parse(&bytes[..VOLUME_HEADER_LEN]).unwrap();
        header.volume_format_rev = 43;
        bytes[..VOLUME_HEADER_LEN].copy_from_slice(&header.to_bytes());

        let mut called = false;
        let err = public_no_key_verify_archive_with(&bytes, |_, _| {
            called = true;
            Ok(true)
        })
        .unwrap_err();

        assert!(!called);
        assert_eq!(
            err,
            FormatError::UnsupportedVolumeFormatRevision {
                format_version: FORMAT_VERSION,
                volume_format_rev: 43,
                reader_max_supported_revision: READER_MAX_SUPPORTED_VOLUME_FORMAT_REV,
            }
        );
    }

    #[test]
    fn public_no_key_rejects_recovered_footer_revision_mismatch() {
        let archive = write_archive_with_root_auth(
            &[RegularFile::new("public.txt", b"public footer mismatch")],
            &master_key(),
            single_stream_options(),
            RootAuthWriterConfig {
                authenticator_id: 0x2222,
                signer_identity_type: 1,
                signer_identity: b"public verifier",
                authenticator_value_length: 32,
            },
            |request| Ok(request.archive_root.to_vec()),
        )
        .unwrap();
        let mut bytes = archive.bytes;
        rewrite_public_cmra_image(&mut bytes, |image| {
            let root_auth_region = image
                .regions
                .iter_mut()
                .find(|region| region.region_type == 4)
                .unwrap();
            rewrite_root_auth_footer_revision_bytes(&mut root_auth_region.bytes, 43);
        });

        let mut called = false;
        let err = public_no_key_verify_archive_with(&bytes, |_, _| {
            called = true;
            Ok(true)
        })
        .unwrap_err();

        assert!(!called);
        assert_eq!(
            err,
            FormatError::InvalidArchive("no valid v41 public CMRA candidate found")
        );
    }

    #[test]
    fn public_no_key_rejects_recovered_image_with_unknown_layout_flags() {
        let archive = write_archive_with_root_auth(
            &[RegularFile::new("public.txt", b"public image mismatch")],
            &master_key(),
            single_stream_options(),
            RootAuthWriterConfig {
                authenticator_id: 0x2222,
                signer_identity_type: 1,
                signer_identity: b"public verifier",
                authenticator_value_length: 32,
            },
            |request| Ok(request.archive_root.to_vec()),
        )
        .unwrap();
        let bytes = rewrite_cmra_image_variable_len(
            &archive.bytes,
            CmraRecoveryMode::PublicNoKey,
            |image| {
                image.layout_flags |= 0x8000_0000;
            },
        );

        let mut called = false;
        let err = public_no_key_verify_archive_with(&bytes, |_, _| {
            called = true;
            Ok(true)
        })
        .unwrap_err();

        assert!(!called);
        assert_eq!(
            err,
            FormatError::InvalidArchive("no valid v41 public CMRA candidate found")
        );
    }

    #[test]
    fn public_no_key_ignores_untrusted_manifest_and_trailer_block_count_fields() {
        let archive = write_archive_with_root_auth(
            &[RegularFile::new(
                "public-fields.txt",
                b"public source authority",
            )],
            &master_key(),
            single_stream_options(),
            RootAuthWriterConfig {
                authenticator_id: 0x2222,
                signer_identity_type: 1,
                signer_identity: b"public verifier",
                authenticator_value_length: 32,
            },
            |request| Ok(request.archive_root.to_vec()),
        )
        .unwrap();
        let mut bytes = archive.bytes.clone();

        rewrite_public_cmra_image(&mut bytes, |image| {
            let manifest_region = image
                .regions
                .iter_mut()
                .find(|region| region.region_type == 3)
                .unwrap();
            manifest_region.bytes[44..48].copy_from_slice(&99u32.to_le_bytes());

            let trailer_region = image
                .regions
                .iter_mut()
                .find(|region| region.region_type == 5)
                .unwrap();
            let mut trailer = VolumeTrailer::parse(&trailer_region.bytes).unwrap();
            trailer.block_count += 7;
            trailer_region.bytes = trailer.to_bytes().to_vec();
        });

        public_no_key_verify_archive_with(&bytes, |footer, archive_root| {
            Ok(footer.authenticator_value == archive_root.as_slice())
        })
        .unwrap();
    }

    #[test]
    fn public_no_key_compares_only_public_crypto_profile_across_volumes() {
        let archive = write_archive_with_root_auth(
            &[RegularFile::new(
                "public-crypto.txt",
                b"cross-volume public profile",
            )],
            &master_key(),
            WriterOptions {
                stripe_width: 2,
                volume_loss_tolerance: 0,
                ..WriterOptions::default()
            },
            RootAuthWriterConfig {
                authenticator_id: 0x3333,
                signer_identity_type: 1,
                signer_identity: b"public verifier",
                authenticator_value_length: 32,
            },
            |request| Ok(request.archive_root.to_vec()),
        )
        .unwrap();
        let mut volumes = archive.volumes.clone();
        let volume_header = VolumeHeader::parse(&volumes[1][..VOLUME_HEADER_LEN]).unwrap();
        let crypto_offset = volume_header.crypto_header_offset as usize;
        let expected_volume_size = 123_456_789u64;
        volumes[1][crypto_offset + 52..crypto_offset + 60]
            .copy_from_slice(&expected_volume_size.to_le_bytes());
        rewrite_public_cmra_image(&mut volumes[1], |image| {
            let crypto_region = image
                .regions
                .iter_mut()
                .find(|region| region.region_type == 2)
                .unwrap();
            crypto_region.bytes[52..60].copy_from_slice(&expected_volume_size.to_le_bytes());
        });

        let volume_refs = volumes.iter().map(Vec::as_slice).collect::<Vec<_>>();
        public_no_key_verify_volumes_with(&volume_refs, |footer, archive_root| {
            Ok(footer.authenticator_value == archive_root.as_slice())
        })
        .unwrap();
    }

    #[test]
    fn locator_based_cmra_recovery_treats_header_damage_as_recoverable() {
        let archive = write_archive_with_root_auth(
            &[RegularFile::new("cmra-header.txt", b"header fallback")],
            &master_key(),
            single_stream_options(),
            RootAuthWriterConfig {
                authenticator_id: 0x4444,
                signer_identity_type: 1,
                signer_identity: b"public verifier",
                authenticator_value_length: 32,
            },
            |request| Ok(request.archive_root.to_vec()),
        )
        .unwrap();
        let final_locator = final_recovery_locator(&archive.bytes);

        let mut bad_crc = archive.bytes.clone();
        let crc_offset =
            final_locator.cmra_offset as usize + CRITICAL_METADATA_RECOVERY_HEADER_LEN - 1;
        bad_crc[crc_offset] ^= 0x55;
        public_no_key_verify_archive_with(&bad_crc, |footer, archive_root| {
            Ok(footer.authenticator_value == archive_root.as_slice())
        })
        .unwrap();

        let mut bad_magic = archive.bytes.clone();
        bad_magic[final_locator.cmra_offset as usize] ^= 0x55;
        public_no_key_verify_archive_with(&bad_magic, |footer, archive_root| {
            Ok(footer.authenticator_value == archive_root.as_slice())
        })
        .unwrap();

        let mut bad_hint = archive.bytes.clone();
        bad_hint[crc_offset] ^= 0xAA;
        for offset in [
            bad_hint.len() - LOCATOR_PAIR_LEN,
            bad_hint.len() - CRITICAL_RECOVERY_LOCATOR_LEN,
        ] {
            let mut locator = CriticalRecoveryLocator::parse(
                &bad_hint[offset..offset + CRITICAL_RECOVERY_LOCATOR_LEN],
            )
            .unwrap();
            locator.volume_index_hint += 1;
            bad_hint[offset..offset + CRITICAL_RECOVERY_LOCATOR_LEN]
                .copy_from_slice(&locator.to_bytes());
        }
        assert_eq!(
            public_no_key_verify_archive_with(&bad_hint, |_, _| Ok(true)).unwrap_err(),
            FormatError::InvalidArchive("no valid v41 public CMRA candidate found")
        );
    }

    #[test]
    fn recovers_physical_volume_header_magic_from_cmra_authority() {
        let payload = b"front header authority".to_vec();
        let archive = write_archive(
            &[RegularFile::new("volume-header.txt", &payload)],
            &master_key(),
            small_block_recovery_options(),
        )
        .unwrap();

        let mut corrupted = archive.bytes;
        corrupted[0] ^= 0x55;

        let opened = open_archive(&corrupted, &master_key()).unwrap();
        assert_eq!(
            opened.extract_file("volume-header.txt").unwrap(),
            Some(payload)
        );
        opened.verify().unwrap();
    }

    #[test]
    fn recovers_crc_valid_physical_volume_index_from_cmra_authority() {
        let payload = b"crc-valid wrong volume index".to_vec();
        let mut options = small_block_recovery_options();
        options.stripe_width = 2;
        options.volume_loss_tolerance = 0;
        let archive = write_archive(
            &[RegularFile::new("volume-index.txt", &payload)],
            &master_key(),
            options,
        )
        .unwrap();

        let mut corrupted = archive.volumes[0].clone();
        let mut header = VolumeHeader::parse(&corrupted[..VOLUME_HEADER_LEN]).unwrap();
        assert_eq!(header.volume_index, 0);
        header.volume_index = 1;
        corrupted[..VOLUME_HEADER_LEN].copy_from_slice(&header.to_bytes());
        assert_eq!(
            VolumeHeader::parse(&corrupted[..VOLUME_HEADER_LEN])
                .unwrap()
                .volume_index,
            1
        );

        let opened = open_archive_volumes(
            &[corrupted.as_slice(), archive.volumes[1].as_slice()],
            &master_key(),
        )
        .unwrap();
        assert_eq!(opened.volume_header.volume_index, 0);
        assert_eq!(
            opened.extract_file("volume-index.txt").unwrap(),
            Some(payload)
        );
        opened.verify().unwrap();
    }

    #[test]
    fn recovers_physical_crypto_header_magic_from_cmra_authority() {
        let payload = b"crypto header authority".to_vec();
        let archive = write_archive(
            &[RegularFile::new("crypto-header.txt", &payload)],
            &master_key(),
            small_block_recovery_options(),
        )
        .unwrap();
        let crypto_offset = VolumeHeader::parse(&archive.bytes[..VOLUME_HEADER_LEN])
            .unwrap()
            .crypto_header_offset;

        let mut corrupted = archive.bytes;
        corrupted[crypto_offset as usize] ^= 0x55;

        let opened = open_archive(&corrupted, &master_key()).unwrap();
        assert_eq!(
            opened.extract_file("crypto-header.txt").unwrap(),
            Some(payload)
        );
        opened.verify().unwrap();
    }

    #[test]
    fn read_at_api_recovers_physical_header_magic_from_cmra_authority() {
        let payload = b"read-at header authority".to_vec();
        let archive = write_archive(
            &[RegularFile::new("read-at-header.txt", &payload)],
            &master_key(),
            small_block_recovery_options(),
        )
        .unwrap();

        let mut corrupted = archive.bytes;
        corrupted[0] ^= 0x55;

        let opened = open_seekable_archive(corrupted, &master_key()).unwrap();
        assert_eq!(
            opened.extract_file("read-at-header.txt").unwrap(),
            Some(payload)
        );
        opened.verify().unwrap();
    }

    #[test]
    fn read_at_api_recovers_crc_valid_physical_volume_index_from_cmra_authority() {
        let payload = b"read-at crc-valid wrong volume index".to_vec();
        let mut options = small_block_recovery_options();
        options.stripe_width = 2;
        options.volume_loss_tolerance = 0;
        let archive = write_archive(
            &[RegularFile::new("read-at-volume-index.txt", &payload)],
            &master_key(),
            options,
        )
        .unwrap();

        let mut corrupted = archive.volumes[0].clone();
        let mut header = VolumeHeader::parse(&corrupted[..VOLUME_HEADER_LEN]).unwrap();
        assert_eq!(header.volume_index, 0);
        header.volume_index = 1;
        corrupted[..VOLUME_HEADER_LEN].copy_from_slice(&header.to_bytes());

        let opened = open_seekable_archive_volumes(
            vec![corrupted, archive.volumes[1].clone()],
            &master_key(),
        )
        .unwrap();
        assert_eq!(opened.volume_header.volume_index, 0);
        assert_eq!(
            opened.extract_file("read-at-volume-index.txt").unwrap(),
            Some(payload)
        );
        opened.verify().unwrap();
    }

    #[test]
    fn recovers_cmra_header_magic_from_locator_tuple() {
        let payload = b"cmra header authority".to_vec();
        let archive = write_archive(
            &[RegularFile::new("cmra-header-magic.txt", &payload)],
            &master_key(),
            small_block_recovery_options(),
        )
        .unwrap();
        let locator = final_recovery_locator(&archive.bytes);

        let mut corrupted = archive.bytes;
        corrupted[locator.cmra_offset as usize] ^= 0x55;

        let opened = open_archive(&corrupted, &master_key()).unwrap();
        assert_eq!(
            opened.extract_file("cmra-header-magic.txt").unwrap(),
            Some(payload)
        );
        opened.verify().unwrap();
    }

    #[test]
    fn recovers_cmra_shard_magic_as_erasure() {
        let payload = b"cmra shard authority".to_vec();
        let archive = write_archive(
            &[RegularFile::new("cmra-shard-magic.txt", &payload)],
            &master_key(),
            small_block_recovery_options(),
        )
        .unwrap();
        let locator = final_recovery_locator(&archive.bytes);
        let first_shard_offset =
            locator.cmra_offset as usize + CRITICAL_METADATA_RECOVERY_HEADER_LEN;

        let mut corrupted = archive.bytes;
        corrupted[first_shard_offset] ^= 0x55;

        let opened = open_archive(&corrupted, &master_key()).unwrap();
        assert_eq!(
            opened.extract_file("cmra-shard-magic.txt").unwrap(),
            Some(payload)
        );
        opened.verify().unwrap();
    }

    #[test]
    fn key_holding_rejects_recovered_image_with_unknown_layout_flags() {
        let archive = write_archive(
            &[RegularFile::new("cmra-image-revision.txt", b"payload")],
            &master_key(),
            small_block_recovery_options(),
        )
        .unwrap();
        let mut mutated = rewrite_cmra_image_variable_len(
            &archive.bytes,
            CmraRecoveryMode::KeyHolding,
            |image| {
                image.layout_flags |= 0x8000_0000;
            },
        );
        mutated[0] ^= 0x55;

        assert!(open_archive(&mutated, &master_key()).is_err());
    }

    #[test]
    fn key_holding_rejects_recovered_footer_revision_mismatch() {
        let archive = write_archive_with_root_auth(
            &[RegularFile::new("cmra-footer-revision.txt", b"payload")],
            &master_key(),
            single_stream_options(),
            test_root_auth_config(),
            |request| Ok(test_root_auth_value(request)),
        )
        .unwrap();
        let mut mutated = archive.bytes;
        rewrite_cmra_image(&mut mutated, CmraRecoveryMode::KeyHolding, |image| {
            let root_auth_region = image
                .regions
                .iter_mut()
                .find(|region| region.region_type == 4)
                .unwrap();
            rewrite_root_auth_footer_revision_bytes(&mut root_auth_region.bytes, 43);
        });
        mutated[0] ^= 0x55;

        assert!(open_archive(&mutated, &master_key()).is_err());
    }

    #[test]
    fn key_holding_rejects_locator_image_revision_mismatch() {
        let archive = write_archive(
            &[RegularFile::new("cmra-locator-revision.txt", b"payload")],
            &master_key(),
            small_block_recovery_options(),
        )
        .unwrap();
        let mut mutated = archive.bytes;
        let locator = final_recovery_locator(&mutated);
        let mirror_offset = mutated.len() - LOCATOR_PAIR_LEN;
        let final_offset = mutated.len() - CRITICAL_RECOVERY_LOCATOR_LEN;
        for offset in [mirror_offset, final_offset] {
            rewrite_recovery_locator(&mut mutated, offset, |locator| {
                locator.volume_format_rev = 43;
            });
        }
        mutated[0] ^= 0x55;
        mutated[locator.cmra_offset as usize] ^= 0x55;

        assert!(open_archive(&mutated, &master_key()).is_err());
    }

    #[test]
    fn image_identity_allows_matching_current_revision() {
        let archive = write_archive(
            &[RegularFile::new("matching-v45.txt", b"payload")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let locator = final_recovery_locator(&archive.bytes);
        let recovered = recover_cmra(
            &archive.bytes,
            locator.cmra_offset,
            Some(CmraDecoderTuple::from(locator)),
            CmraRecoveryMode::KeyHolding,
        )
        .unwrap();
        let image = recovered.image;
        let header = VolumeHeader::parse(&archive.bytes[..VOLUME_HEADER_LEN]).unwrap();
        let crypto_start = header.crypto_header_offset as usize;
        let crypto_end = crypto_start + header.crypto_header_length as usize;
        let crypto = CryptoHeader::parse(
            &archive.bytes[crypto_start..crypto_end],
            header.crypto_header_length,
        )
        .unwrap();

        validate_image_identity(&image, &header, &crypto.fixed).unwrap();
    }

    #[test]
    fn key_holding_rejects_cmra_below_authenticated_parity_floor() {
        let archive = write_archive(
            &[RegularFile::new(
                "cmra-floor.txt",
                b"authenticated CMRA floor",
            )],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let malformed = rewrite_cmra_parity_count(&archive.bytes, 1);
        let final_offset = malformed.len() - CRITICAL_RECOVERY_LOCATOR_LEN;
        let locator = CriticalRecoveryLocator::parse(
            &malformed[final_offset..final_offset + CRITICAL_RECOVERY_LOCATOR_LEN],
        )
        .unwrap();
        let volume_header = VolumeHeader::parse(&malformed[..VOLUME_HEADER_LEN]).unwrap();
        let crypto_start = volume_header.crypto_header_offset as usize;
        let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
        let crypto_header = CryptoHeader::parse(
            &malformed[crypto_start..crypto_end],
            volume_header.crypto_header_length,
        )
        .unwrap();
        let subkeys = Subkeys::derive(
            &master_key(),
            &volume_header.archive_uuid,
            &volume_header.session_id,
        )
        .unwrap();

        assert_eq!(
            parse_locator_cmra_candidate(
                &malformed,
                final_offset,
                locator,
                KeyHoldingTerminalContext {
                    subkeys: &subkeys,
                    volume_header: &volume_header,
                    crypto_header: &crypto_header.fixed,
                    crypto_header_bytes: &malformed[crypto_start..crypto_end],
                },
            )
            .unwrap_err(),
            FormatError::InvalidArchive(
                "CMRA parity shard count is below authenticated bit-rot lower bound"
            )
        );
        assert!(open_archive(&malformed, &master_key()).is_err());
    }

    #[test]
    fn locator_tuple_bounds_are_checked_before_locator_position_fields() {
        let archive = write_archive(
            &[RegularFile::new(
                "locator-order.txt",
                b"locator tuple first",
            )],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let final_offset = archive.bytes.len() - CRITICAL_RECOVERY_LOCATOR_LEN;
        let mut locator = final_recovery_locator(&archive.bytes);
        locator.cmra_shard_size = 513;
        locator.body_bytes_before_cmra = locator.cmra_offset + 1;
        let volume_header = VolumeHeader::parse(&archive.bytes[..VOLUME_HEADER_LEN]).unwrap();
        let crypto_start = volume_header.crypto_header_offset as usize;
        let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
        let crypto_header = CryptoHeader::parse(
            &archive.bytes[crypto_start..crypto_end],
            volume_header.crypto_header_length,
        )
        .unwrap();
        let subkeys = Subkeys::derive(
            &master_key(),
            &volume_header.archive_uuid,
            &volume_header.session_id,
        )
        .unwrap();

        assert_eq!(
            parse_locator_cmra_candidate(
                &archive.bytes,
                final_offset,
                locator,
                KeyHoldingTerminalContext {
                    subkeys: &subkeys,
                    volume_header: &volume_header,
                    crypto_header: &crypto_header.fixed,
                    crypto_header_bytes: &archive.bytes[crypto_start..crypto_end],
                },
            )
            .unwrap_err(),
            FormatError::InvalidArchive("CMRA shard_size is invalid")
        );
    }

    #[test]
    fn sequential_extract_rejects_bytes_after_terminal_locator() {
        let archive = write_archive(
            &[RegularFile::new("seq.txt", b"sequential EOF")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let mut appended = archive.bytes.clone();
        appended.extend_from_slice(&[0xAA; 32]);

        assert_eq!(
            sequential_extract_tar_stream(&appended, &master_key()).unwrap_err(),
            FormatError::InvalidArchive("sequential terminal does not end at EOF")
        );
    }

    #[test]
    fn global_file_table_order_rejects_cross_shard_duplicate_reversal() {
        let first = (hash_prefix(b"dup.txt"), b"dup.txt".to_vec(), 2048);
        let second = (hash_prefix(b"dup.txt"), b"dup.txt".to_vec(), 1024);

        assert_eq!(
            validate_global_file_table_key_step(Some(&first), &second).unwrap_err(),
            FormatError::InvalidArchive("global FileEntry rows are not sorted and unique")
        );
    }

    #[test]
    fn root_auth_verifies_key_holding_and_public_no_key_modes() {
        let archive = write_archive_with_root_auth(
            &[RegularFile::new("signed.txt", b"ed25519 payload")],
            &master_key(),
            single_stream_options(),
            test_root_auth_config(),
            |request| Ok(test_root_auth_value(request)),
        )
        .unwrap();

        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        let root_auth = opened
            .verify_root_auth_with(|footer, archive_root| {
                Ok(test_root_auth_verifies(footer, archive_root))
            })
            .unwrap();
        assert_eq!(
            root_auth.archive_root,
            opened.root_auth_footer.as_ref().unwrap().archive_root
        );

        let public = public_no_key_verify_archive_with(&archive.bytes, |footer, archive_root| {
            Ok(test_root_auth_verifies(footer, archive_root))
        })
        .unwrap();
        assert_eq!(public.archive_root, root_auth.archive_root);
        assert_eq!(
            public.diagnostics,
            vec![
                PublicNoKeyDiagnostic::PublicDataBlockCommitmentVerified,
                PublicNoKeyDiagnostic::PublicPhysicalCompletenessUnverified,
                PublicNoKeyDiagnostic::PublicRecoveryMarginUnchecked,
            ]
        );
    }

    #[test]
    fn root_auth_verifies_with_tolerated_missing_volume_after_fec_repair() {
        let options = WriterOptions {
            block_size: 4096,
            chunk_size: 16 * 1024,
            envelope_target_size: 16 * 1024,
            stripe_width: 2,
            volume_loss_tolerance: 1,
            bit_rot_buffer_pct: 0,
            fec_data_shards: 16,
            fec_parity_shards: 1,
            index_fec_data_shards: 4,
            index_fec_parity_shards: 1,
            index_root_fec_data_shards: 16,
            index_root_fec_parity_shards: 1,
            ..WriterOptions::default()
        };
        let archive = write_archive_with_root_auth(
            &[RegularFile::new("missing-volume.txt", b"recover me")],
            &master_key(),
            options,
            test_root_auth_config(),
            |request| Ok(test_root_auth_value(request)),
        )
        .unwrap();

        let opened = open_archive_volumes(&[archive.volumes[0].as_slice()], &master_key()).unwrap();
        let root_auth = opened
            .verify_root_auth_with(|footer, archive_root| {
                Ok(test_root_auth_verifies(footer, archive_root))
            })
            .unwrap();
        assert!(root_auth
            .diagnostics
            .contains(&RootAuthDiagnostic::ReplicatedGlobalCopyUncheckedDueToVolumeLoss));
    }

    #[test]
    fn public_no_key_rejects_unsigned_archives() {
        let archive = write_archive(
            &[RegularFile::new("plain.txt", b"unsigned")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();

        assert_eq!(
            public_no_key_verify_archive_with(&archive.bytes, |_, _| Ok(true)).unwrap_err(),
            FormatError::InvalidArchive("no valid v41 public CMRA candidate found")
        );
    }

    #[test]
    fn unsigned_archive_reports_root_auth_absent() {
        let archive = write_archive(
            &[RegularFile::new("plain.txt", b"unsigned")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();

        assert_eq!(
            opened.verify_root_auth_with(|_, _| Ok(true)).unwrap_err(),
            FormatError::ReaderUnsupported("root-auth footer is absent")
        );
    }

    #[test]
    fn safe_extract_writes_regular_file_under_root() {
        let archive = write_archive(
            &[RegularFile::new("dir/hello.txt", b"safe m8")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        let tmp = tempfile::tempdir().unwrap();

        opened
            .extract_file_to(
                "dir/hello.txt",
                tmp.path(),
                SafeExtractionOptions::default(),
            )
            .unwrap()
            .unwrap();

        assert_eq!(
            std::fs::read(tmp.path().join("dir").join("hello.txt")).unwrap(),
            b"safe m8"
        );
    }

    fn decoded_primary_metadata_storage(
        opened: &OpenedArchive,
        path: &str,
    ) -> (crate::entry_metadata::PaxRecords, [u8; 512]) {
        let located = opened.locate_index_file(path.as_bytes()).unwrap().unwrap();
        let file = &located.shard.files[located.file_index];
        let mut reader = DecodedTarMemberGroupReader::new(opened, &located.shard, file).unwrap();
        let mut group = vec![0u8; usize::try_from(file.tar_member_group_size).unwrap()];
        let mut offset = 0usize;
        while offset < group.len() {
            let read = reader.read_some_member_bytes(&mut group[offset..]).unwrap();
            assert_ne!(read, 0, "decoded member group ended early");
            offset += read;
        }

        assert_eq!(group[156], b'x');
        let pax_size = usize::try_from(parse_test_tar_octal(&group[124..136])).unwrap();
        let pax_end = 512 + pax_size;
        let records = crate::entry_metadata::parse_canonical_pax(&group[512..pax_end]).unwrap();
        let primary_offset = pax_end + padding_to_512(pax_size);
        let primary = group[primary_offset..primary_offset + 512]
            .try_into()
            .unwrap();
        (records, primary)
    }

    fn parse_test_tar_octal(field: &[u8]) -> u64 {
        let field = nul_trimmed_test_field(field);
        let text = std::str::from_utf8(field).unwrap().trim();
        u64::from_str_radix(text, 8).unwrap()
    }

    fn nul_trimmed_test_field(field: &[u8]) -> &[u8] {
        let end = field
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(field.len());
        &field[..end]
    }

    #[test]
    fn compressed_archive_round_trips_header_and_pax_portable_metadata_stores() {
        let files = [
            RegularFile {
                mode: 0o640,
                mtime: ArchiveTimestamp::from_seconds(1_700_000_000),
                portable_metadata: PortableFileMetadata {
                    source_os: "other-unix".into(),
                    source_filesystem: "ext4".into(),
                    mode_origin: PortableModeOrigin::Native,
                    posix_owner: Some(PortablePosixOwner {
                        uid: 42,
                        gid: 84,
                        uname: Some("alice".into()),
                        gname: Some("staff".into()),
                    }),
                    attributes: Some(1),
                    created: None,
                    accessed: None,
                    native: Default::default(),
                },
                ..RegularFile::new("header-fields.txt", b"header metadata")
            },
            RegularFile {
                mode: 0o604,
                mtime: ArchiveTimestamp::new(-1, 500_000_000),
                portable_metadata: PortableFileMetadata {
                    source_os: "other-unix".into(),
                    source_filesystem: "zfs".into(),
                    mode_origin: PortableModeOrigin::Native,
                    posix_owner: Some(PortablePosixOwner {
                        uid: 9_000_000,
                        gid: 8_000_000,
                        uname: Some("u".repeat(40)),
                        gname: Some("g".repeat(40)),
                    }),
                    attributes: Some(2),
                    created: None,
                    accessed: None,
                    native: Default::default(),
                },
                ..RegularFile::new("pax-overrides.txt", b"PAX metadata")
            },
        ];
        let archive = write_archive(&files, &master_key(), single_stream_options()).unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();

        assert_eq!(
            opened.crypto_header.compression_algo,
            CompressionAlgo::ZstdFramed
        );

        let (header_records, header_primary) =
            decoded_primary_metadata_storage(&opened, "header-fields.txt");
        for key in ["uid", "gid", "uname", "gname", "mtime"] {
            assert!(!header_records.contains_key(key), "{key} should use ustar");
        }
        assert_eq!(parse_test_tar_octal(&header_primary[108..116]), 42);
        assert_eq!(parse_test_tar_octal(&header_primary[116..124]), 84);
        assert_eq!(nul_trimmed_test_field(&header_primary[265..297]), b"alice");
        assert_eq!(nul_trimmed_test_field(&header_primary[297..329]), b"staff");
        assert_eq!(
            parse_test_tar_octal(&header_primary[136..148]),
            1_700_000_000
        );

        let (pax_records, pax_primary) =
            decoded_primary_metadata_storage(&opened, "pax-overrides.txt");
        let long_uname = "u".repeat(40);
        let long_gname = "g".repeat(40);
        for (key, expected) in [
            ("uid", b"9000000".as_slice()),
            ("gid", b"8000000".as_slice()),
            ("uname", long_uname.as_bytes()),
            ("gname", long_gname.as_bytes()),
            ("mtime", b"-1.5".as_slice()),
        ] {
            assert_eq!(pax_records.get(key).map(Vec::as_slice), Some(expected));
        }
        assert_eq!(parse_test_tar_octal(&pax_primary[108..116]), 0);
        assert_eq!(parse_test_tar_octal(&pax_primary[116..124]), 0);
        assert!(nul_trimmed_test_field(&pax_primary[265..297]).is_empty());
        assert!(nul_trimmed_test_field(&pax_primary[297..329]).is_empty());
        assert_eq!(parse_test_tar_octal(&pax_primary[136..148]), 0);

        for expected in &files {
            let index = opened.lookup_index_entry(expected.path).unwrap().unwrap();
            assert!(index.layout.compressed_size > 0);
            assert_eq!(
                index.flags,
                crate::entry_metadata::EXTENDED_METADATA_V1
                    | crate::entry_metadata::REQUIRES_SYSTEM_RESTORE
            );

            let located = opened
                .locate_index_file(expected.path.as_bytes())
                .unwrap()
                .unwrap();
            let member = opened
                .decode_loaded_owned_tar_member(&located.shard, located.file_index, false)
                .unwrap();
            let metadata = member.v45_metadata.unwrap();
            let owner = expected.portable_metadata.posix_owner.as_ref().unwrap();

            assert_eq!(member.mode, expected.mode);
            assert_eq!(member.mtime, expected.mtime);
            assert_eq!(
                metadata.file_entry_flags,
                crate::entry_metadata::EXTENDED_METADATA_V1
                    | crate::entry_metadata::REQUIRES_SYSTEM_RESTORE
            );
            assert_eq!(
                metadata.declaration.source_os,
                expected.portable_metadata.source_os
            );
            assert_eq!(
                metadata.declaration.source_filesystem,
                expected.portable_metadata.source_filesystem
            );
            assert!(metadata.declaration.mode_origin_native);
            assert_eq!(metadata.portable_mirror.mode, expected.mode);
            assert_eq!(
                metadata.portable_mirror.mtime,
                (expected.mtime.seconds, expected.mtime.nanoseconds)
            );
            assert_eq!(
                metadata.portable_mirror.attributes,
                expected.portable_metadata.attributes
            );
            assert_eq!(metadata.portable_mirror.uid, Some(owner.uid));
            assert_eq!(metadata.portable_mirror.gid, Some(owner.gid));
            assert_eq!(
                metadata.portable_mirror.uname.as_deref(),
                owner.uname.as_deref().map(str::as_bytes)
            );
            assert_eq!(
                metadata.portable_mirror.gname.as_deref(),
                owner.gname.as_deref().map(str::as_bytes)
            );
        }
    }

    #[test]
    fn compressed_archive_extraction_applies_portable_mode_and_pax_mtime() {
        let archived_mtime = ArchiveTimestamp::new(946_684_800, 123_456_700);
        let archive = write_archive(
            &[RegularFile {
                mode: 0o604,
                mtime: archived_mtime,
                ..RegularFile::new("dated.txt", b"dated")
            }],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        assert_eq!(
            opened
                .lookup_index_entry("dated.txt")
                .unwrap()
                .unwrap()
                .flags,
            crate::entry_metadata::EXTENDED_METADATA_V1
        );
        let content_root = tempfile::tempdir().unwrap();

        let content_diagnostics = opened
            .extract_file_to(
                "dated.txt",
                content_root.path(),
                SafeExtractionOptions {
                    restore_policy: crate::entry_metadata::RestorePolicy::Content,
                    ..SafeExtractionOptions::default()
                },
            )
            .unwrap()
            .unwrap();
        for metadata_class in ["mode", "mtime"] {
            assert!(content_diagnostics.iter().any(|diagnostic| {
                diagnostic.metadata_class == metadata_class
                    && diagnostic.status == crate::tar_model::MetadataDiagnosticStatus::Skipped
            }));
        }
        let content_mtime = fs::metadata(content_root.path().join("dated.txt"))
            .unwrap()
            .modified()
            .unwrap();
        assert_ne!(
            content_mtime,
            std::time::UNIX_EPOCH
                + std::time::Duration::new(
                    archived_mtime.seconds as u64,
                    archived_mtime.nanoseconds,
                )
        );

        let portable_root = tempfile::tempdir().unwrap();
        opened
            .extract_file_to(
                "dated.txt",
                portable_root.path(),
                SafeExtractionOptions::default(),
            )
            .unwrap()
            .unwrap();
        let portable_mtime = fs::metadata(portable_root.path().join("dated.txt"))
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(
            portable_mtime,
            std::time::UNIX_EPOCH
                + std::time::Duration::new(
                    archived_mtime.seconds as u64,
                    archived_mtime.nanoseconds,
                )
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(
                fs::metadata(portable_root.path().join("dated.txt"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                0o604
            );
        }
    }

    #[test]
    fn same_os_restore_rejects_required_native_profile_from_another_os() {
        let (source_os, required_profiles) = if cfg!(target_os = "macos") {
            (
                "linux",
                vec!["posix-backup-v1".into(), "linux-backup-v1".into()],
            )
        } else {
            (
                "macos",
                vec!["posix-backup-v1".into(), "macos-backup-v1".into()],
            )
        };
        let archive = write_archive(
            &[RegularFile {
                portable_metadata: PortableFileMetadata {
                    source_os: source_os.into(),
                    native: NativeFileMetadata {
                        required_profiles,
                        ..NativeFileMetadata::default()
                    },
                    ..PortableFileMetadata::default()
                },
                ..RegularFile::new("foreign-native.txt", b"payload")
            }],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();

        assert_eq!(
            opened
                .plan_metadata_restore(SafeExtractionOptions {
                    restore_policy: RestorePolicy::SameOs,
                    ..SafeExtractionOptions::default()
                })
                .unwrap_err(),
            FormatError::ReaderUnsupported(
                "requested native metadata is not supported by this conformance class"
            )
        );
    }

    #[cfg(unix)]
    #[test]
    fn compressed_archive_extraction_restores_setid_bits_only_for_authorized_system_policy() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        // SAFETY: these process identity getters have no preconditions.
        let uid = unsafe { libc::geteuid() } as u64;
        let gid = unsafe { libc::getegid() } as u64;

        let archive = write_archive(
            &[RegularFile {
                mode: 0o7751,
                mtime: ArchiveTimestamp::from_seconds(1_700_000_000),
                portable_metadata: PortableFileMetadata {
                    source_os: "other-unix".into(),
                    source_filesystem: "unknown".into(),
                    mode_origin: PortableModeOrigin::Native,
                    posix_owner: Some(PortablePosixOwner {
                        uid,
                        gid,
                        uname: None,
                        gname: None,
                    }),
                    attributes: None,
                    created: None,
                    accessed: None,
                    native: Default::default(),
                },
                ..RegularFile::new("privileged.sh", b"#!/bin/sh\n")
            }],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        assert_eq!(
            opened
                .lookup_index_entry("privileged.sh")
                .unwrap()
                .unwrap()
                .flags,
            crate::entry_metadata::EXTENDED_METADATA_V1
                | crate::entry_metadata::REQUIRES_SYSTEM_RESTORE
        );

        let portable_root = tempfile::tempdir().unwrap();
        let portable_diagnostics = opened
            .extract_file_to(
                "privileged.sh",
                portable_root.path(),
                SafeExtractionOptions::default(),
            )
            .unwrap()
            .unwrap();
        assert!(portable_diagnostics.iter().any(|diagnostic| {
            diagnostic.metadata_class == "setid-mode"
                && diagnostic.status == crate::tar_model::MetadataDiagnosticStatus::Skipped
        }));
        assert!(portable_diagnostics.iter().any(|diagnostic| {
            diagnostic.metadata_class == "numeric-ownership"
                && diagnostic.status == crate::tar_model::MetadataDiagnosticStatus::Skipped
        }));
        assert_eq!(
            fs::metadata(portable_root.path().join("privileged.sh"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o1751
        );

        let same_os_root = tempfile::tempdir().unwrap();
        opened
            .extract_file_to(
                "privileged.sh",
                same_os_root.path(),
                SafeExtractionOptions {
                    restore_policy: crate::entry_metadata::RestorePolicy::SameOs,
                    ..SafeExtractionOptions::default()
                },
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            fs::metadata(same_os_root.path().join("privileged.sh"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o1751
        );

        let unauthorized_root = tempfile::tempdir().unwrap();
        assert_eq!(
            opened
                .extract_file_to(
                    "privileged.sh",
                    unauthorized_root.path(),
                    SafeExtractionOptions {
                        restore_policy: crate::entry_metadata::RestorePolicy::System,
                        ..SafeExtractionOptions::default()
                    },
                )
                .unwrap_err(),
            FormatError::ReaderUnsupported(
                "system restore policy requires explicit caller authorization"
            )
        );
        assert!(!unauthorized_root.path().join("privileged.sh").exists());

        let system_root = tempfile::tempdir().unwrap();
        opened
            .extract_file_to(
                "privileged.sh",
                system_root.path(),
                SafeExtractionOptions {
                    restore_policy: crate::entry_metadata::RestorePolicy::System,
                    system_authorized: true,
                    ..SafeExtractionOptions::default()
                },
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            fs::metadata(system_root.path().join("privileged.sh"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o7751
        );
        let restored = fs::metadata(system_root.path().join("privileged.sh")).unwrap();
        assert_eq!(restored.uid() as u64, uid);
        assert_eq!(restored.gid() as u64, gid);
    }

    #[cfg(unix)]
    #[test]
    fn compressed_archive_extraction_restores_native_xattrs_only_under_native_policy() {
        let mut native = NativeFileMetadata {
            required_profiles: vec!["posix-backup-v1".into()],
            ..NativeFileMetadata::default()
        };
        native.primary_pax_records.insert(
            "LIBARCHIVE.xattr.user.tzap-test".into(),
            crate::entry_metadata::canonical_base64_encode(b"native value"),
        );
        let archive = write_archive(
            &[RegularFile {
                portable_metadata: PortableFileMetadata {
                    source_os: source_os_for_test().into(),
                    native,
                    ..PortableFileMetadata::default()
                },
                ..RegularFile::new("xattr.txt", b"payload")
            }],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();

        let portable_root = tempfile::tempdir().unwrap();
        opened
            .extract_file_to(
                "xattr.txt",
                portable_root.path(),
                SafeExtractionOptions {
                    restore_policy: RestorePolicy::Portable,
                    ..SafeExtractionOptions::default()
                },
            )
            .unwrap();
        assert_eq!(
            xattr::get(portable_root.path().join("xattr.txt"), "user.tzap-test").unwrap(),
            None
        );

        let native_root = tempfile::tempdir().unwrap();
        opened
            .extract_file_to(
                "xattr.txt",
                native_root.path(),
                SafeExtractionOptions {
                    restore_policy: RestorePolicy::SameOs,
                    ..SafeExtractionOptions::default()
                },
            )
            .unwrap();
        assert_eq!(
            xattr::get(native_root.path().join("xattr.txt"), "user.tzap-test").unwrap(),
            Some(b"native value".to_vec())
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn compressed_archive_extraction_restores_auxiliary_linux_xattr() {
        let mut record = NativeAuxiliaryMetadata::new(
            "generic.xattr",
            "posix-backup-v1",
            crate::entry_metadata::RestoreClass::SameOs,
            b"auxiliary xattr value".to_vec(),
        );
        record.name_encoding = NativeAuxiliaryNameEncoding::Bytes;
        record.name = b"user.tzap-aux".to_vec();
        let native = NativeFileMetadata {
            required_profiles: vec!["posix-backup-v1".into(), "linux-backup-v1".into()],
            auxiliary_records: vec![record],
            ..NativeFileMetadata::default()
        };
        let archive = write_archive(
            &[RegularFile {
                portable_metadata: PortableFileMetadata {
                    source_os: "linux".into(),
                    native,
                    ..PortableFileMetadata::default()
                },
                ..RegularFile::new("aux-xattr.txt", b"payload")
            }],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        let root = tempfile::tempdir().unwrap();
        opened
            .extract_file_to(
                "aux-xattr.txt",
                root.path(),
                SafeExtractionOptions {
                    restore_policy: RestorePolicy::SameOs,
                    ..SafeExtractionOptions::default()
                },
            )
            .unwrap();
        assert_eq!(
            xattr::get(root.path().join("aux-xattr.txt"), "user.tzap-aux").unwrap(),
            Some(b"auxiliary xattr value".to_vec())
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn same_os_restore_reports_system_xattr_as_policy_skipped() {
        let mut native = NativeFileMetadata {
            required_profiles: vec!["posix-backup-v1".into(), "linux-backup-v1".into()],
            ..NativeFileMetadata::default()
        };
        native.primary_pax_records.insert(
            "LIBARCHIVE.xattr.security.selinux".into(),
            crate::entry_metadata::canonical_base64_encode(b"label"),
        );
        let archive = write_archive(
            &[RegularFile {
                portable_metadata: PortableFileMetadata {
                    source_os: "linux".into(),
                    native,
                    ..PortableFileMetadata::default()
                },
                ..RegularFile::new("label.txt", b"payload")
            }],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        let root = tempfile::tempdir().unwrap();
        let diagnostics = opened
            .extract_file_to(
                "label.txt",
                root.path(),
                SafeExtractionOptions {
                    restore_policy: RestorePolicy::SameOs,
                    ..SafeExtractionOptions::default()
                },
            )
            .unwrap()
            .unwrap();
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.metadata_class == "system-extended-attribute"
                && diagnostic.status == crate::tar_model::MetadataDiagnosticStatus::Skipped
        }));
        assert_eq!(
            xattr::get(root.path().join("label.txt"), "security.selinux").unwrap(),
            None
        );
    }

    #[cfg(target_os = "linux")]
    fn source_os_for_test() -> &'static str {
        "linux"
    }

    #[cfg(target_os = "macos")]
    fn source_os_for_test() -> &'static str {
        "macos"
    }

    #[cfg(all(unix, not(target_os = "linux"), not(target_os = "macos")))]
    fn source_os_for_test() -> &'static str {
        "other-unix"
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn compressed_archive_extraction_restores_linux_inode_flags() {
        use std::os::fd::AsRawFd;

        let root = tempfile::tempdir().unwrap();
        let probe_path = root.path().join("flags-probe.txt");
        fs::write(&probe_path, b"probe").unwrap();
        let probe = fs::File::open(&probe_path).unwrap();
        let mut intrinsic_flags: libc::c_long = 0;
        assert_eq!(
            unsafe {
                libc::ioctl(
                    probe.as_raw_fd(),
                    libc::FS_IOC_GETFLAGS,
                    &mut intrinsic_flags,
                )
            },
            0
        );
        drop(probe);
        fs::remove_file(probe_path).unwrap();
        let expected_flags =
            intrinsic_flags as u64 | u64::from(linux_raw_sys::general::FS_NODUMP_FL);
        let mut native = NativeFileMetadata {
            required_profiles: vec!["posix-backup-v1".into(), "linux-backup-v1".into()],
            ..NativeFileMetadata::default()
        };
        native.primary_pax_records.insert(
            "TZAP.linux.fsflags".into(),
            format!("{expected_flags:016x}").into_bytes(),
        );
        let archive = write_archive(
            &[RegularFile {
                portable_metadata: PortableFileMetadata {
                    source_os: "linux".into(),
                    native,
                    ..PortableFileMetadata::default()
                },
                ..RegularFile::new("flags.txt", b"payload")
            }],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        opened
            .extract_file_to(
                "flags.txt",
                root.path(),
                SafeExtractionOptions {
                    restore_policy: RestorePolicy::SameOs,
                    ..SafeExtractionOptions::default()
                },
            )
            .unwrap();
        let file = fs::File::open(root.path().join("flags.txt")).unwrap();
        let mut flags: libc::c_long = 0;
        // SAFETY: GETFLAGS writes one c_long to a valid pointer.
        assert_eq!(
            unsafe { libc::ioctl(file.as_raw_fd(), libc::FS_IOC_GETFLAGS, &mut flags,) },
            0
        );
        assert_eq!(flags as u64, expected_flags);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn compressed_archive_extraction_restores_canonical_posix_acl() {
        let acl = b"user::rw-,group::r--,other::---,user:123:r--,mask::r--";
        let mut native = NativeFileMetadata {
            required_profiles: vec!["posix-backup-v1".into()],
            ..NativeFileMetadata::default()
        };
        native
            .primary_pax_records
            .insert("SCHILY.acl.access".into(), acl.to_vec());
        native
            .primary_pax_records
            .insert("TZAP.acl.projection".into(), b"exact".to_vec());
        native.primary_pax_records.insert(
            "TZAP.acl.syntax".into(),
            b"schily-posix1e-extra-id-v1".to_vec(),
        );
        let archive = write_archive(
            &[RegularFile {
                mode: 0o640,
                portable_metadata: PortableFileMetadata {
                    source_os: "linux".into(),
                    native,
                    ..PortableFileMetadata::default()
                },
                ..RegularFile::new("acl.txt", b"payload")
            }],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        let root = tempfile::tempdir().unwrap();
        opened
            .extract_file_to(
                "acl.txt",
                root.path(),
                SafeExtractionOptions {
                    restore_policy: RestorePolicy::SameOs,
                    ..SafeExtractionOptions::default()
                },
            )
            .unwrap();
        let binary = xattr::get(root.path().join("acl.txt"), "system.posix_acl_access")
            .unwrap()
            .unwrap();
        assert_eq!(
            crate::entry_metadata::linux_posix_acl_xattr_to_schily(&binary).unwrap(),
            acl
        );
    }

    #[cfg(windows)]
    #[test]
    #[allow(clippy::permissions_set_readonly_false)]
    fn compressed_archive_extraction_restores_portable_readonly_attribute() {
        let archive = write_archive(
            &[RegularFile {
                portable_metadata: PortableFileMetadata {
                    source_os: "windows".into(),
                    source_filesystem: "ntfs".into(),
                    mode_origin: PortableModeOrigin::Projected,
                    posix_owner: None,
                    attributes: Some(1),
                    created: None,
                    accessed: None,
                    native: Default::default(),
                },
                ..RegularFile::new("readonly.txt", b"readonly")
            }],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        let root = tempfile::tempdir().unwrap();

        opened
            .extract_file_to(
                "readonly.txt",
                root.path(),
                SafeExtractionOptions::default(),
            )
            .unwrap()
            .unwrap();
        let path = root.path().join("readonly.txt");
        assert!(fs::metadata(&path).unwrap().permissions().readonly());

        // Let TempDir clean up the restored file on Windows.
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(false);
        fs::set_permissions(path, permissions).unwrap();
    }

    #[test]
    fn seekable_extract_all_to_streams_unique_archive() {
        let archive = write_archive(
            &[
                RegularFile::new("alpha.txt", b"alpha"),
                RegularFile::new("dir/beta.txt", b"beta"),
            ],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        let tmp = tempfile::tempdir().unwrap();

        let diagnostics = opened
            .extract_all_to(tmp.path(), SafeExtractionOptions::default())
            .unwrap();

        assert_eq!(diagnostics.len(), 2);
        assert_eq!(fs::read(tmp.path().join("alpha.txt")).unwrap(), b"alpha");
        assert_eq!(
            fs::read(tmp.path().join("dir").join("beta.txt")).unwrap(),
            b"beta"
        );
    }

    #[test]
    fn seekable_extract_all_to_rejects_duplicate_paths_for_cli_fallback() {
        let archive = write_archive(
            &[
                RegularFile::new("same.txt", b"old"),
                RegularFile::new("same.txt", b"new"),
            ],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        let tmp = tempfile::tempdir().unwrap();

        assert_eq!(
            opened
                .extract_all_to(tmp.path(), SafeExtractionOptions::default())
                .unwrap_err(),
            FormatError::ReaderUnsupported("fast full extract requires unique archive paths")
        );
    }

    #[test]
    fn seekable_extract_indexed_files_to_restores_final_duplicate_winner() {
        let archive = write_archive(
            &[
                RegularFile::new("same.txt", b"old"),
                RegularFile::new("same.txt", b"new"),
            ],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        let tmp = tempfile::tempdir().unwrap();

        let diagnostics = opened
            .extract_indexed_files_to(tmp.path(), SafeExtractionOptions::default(), 2)
            .unwrap();

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].0, "same.txt");
        assert_eq!(fs::read(tmp.path().join("same.txt")).unwrap(), b"new");
    }

    #[test]
    fn selected_restore_preflights_every_path_before_writing() {
        let archive = write_archive(
            &[RegularFile::new("alpha.txt", b"alpha")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        let tmp = tempfile::tempdir().unwrap();

        let error = opened
            .extract_selected_files_to(
                &["alpha.txt".into(), "missing.txt".into()],
                tmp.path(),
                SafeExtractionOptions::default(),
                2,
            )
            .unwrap_err();

        assert_eq!(
            error,
            FormatError::ReaderUnsupported("selected archive path is absent from the final index")
        );
        assert!(!tmp.path().join("alpha.txt").exists());
    }

    #[test]
    fn safe_extract_rejects_overwriting_existing_file_by_default() {
        let archive = write_archive(
            &[RegularFile::new("hello.txt", b"new")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("hello.txt"), b"old").unwrap();

        assert_eq!(
            opened
                .extract_file_to("hello.txt", tmp.path(), SafeExtractionOptions::default())
                .unwrap_err(),
            FormatError::UnsafeOverwrite
        );
        assert_eq!(std::fs::read(tmp.path().join("hello.txt")).unwrap(), b"old");
    }

    #[test]
    fn opens_and_verifies_empty_archive() {
        let archive = write_archive(&[], &master_key(), single_stream_options()).unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();

        assert!(opened.list_files().unwrap().is_empty());
        opened.verify().unwrap();
    }

    #[test]
    fn default_reader_options_allow_v36_trailing_garbage_scan() {
        let archive = write_archive(
            &[RegularFile::new("garbage-tolerant.txt", b"still intact")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let mut with_trailing_garbage = archive.bytes.clone();
        with_trailing_garbage.extend_from_slice(b"ignored trailing bytes");

        let opened = open_archive(&with_trailing_garbage, &master_key()).unwrap();
        assert_eq!(
            opened.extract_file("garbage-tolerant.txt").unwrap(),
            Some(b"still intact".to_vec())
        );
    }

    #[test]
    fn seekable_open_rejects_too_small_and_unavailable_header_crypto_bytes() {
        assert_eq!(
            open_archive(
                &[0u8; VOLUME_HEADER_LEN + VOLUME_TRAILER_LEN - 1],
                &master_key()
            )
            .unwrap_err(),
            FormatError::InvalidLength {
                structure: "archive",
                expected: VOLUME_HEADER_LEN + VOLUME_TRAILER_LEN,
                actual: VOLUME_HEADER_LEN + VOLUME_TRAILER_LEN - 1,
            }
        );

        let mut header = test_volume_header();
        header.crypto_header_length = 512;
        let mut unavailable_crypto = header.to_bytes().to_vec();
        unavailable_crypto.resize(VOLUME_HEADER_LEN + VOLUME_TRAILER_LEN, 0);

        assert_eq!(
            open_archive(&unavailable_crypto, &master_key()).unwrap_err(),
            FormatError::InvalidLength {
                structure: "CryptoHeader",
                expected: VOLUME_HEADER_LEN + 512,
                actual: VOLUME_HEADER_LEN + VOLUME_TRAILER_LEN,
            }
        );
    }

    #[test]
    fn seekable_open_recovers_physical_noncanonical_crypto_header_offset() {
        let archive = write_archive(
            &[RegularFile::new("offset.txt", b"offset")],
            &master_key(),
            small_block_recovery_options(),
        )
        .unwrap();
        let mut mutated = archive.bytes;
        let mut header = VolumeHeader::parse(&mutated[..VOLUME_HEADER_LEN]).unwrap();
        header.crypto_header_offset = VOLUME_HEADER_LEN as u32 + 1;
        mutated[..VOLUME_HEADER_LEN].copy_from_slice(&header.to_bytes());

        let opened = open_archive(&mutated, &master_key()).unwrap();
        assert_eq!(
            opened.volume_header.crypto_header_offset,
            VOLUME_HEADER_LEN as u32
        );
        assert_eq!(
            opened.extract_file("offset.txt").unwrap(),
            Some(b"offset".to_vec())
        );
        opened.verify().unwrap();
    }

    #[test]
    fn rejects_wrong_key_before_metadata_release() {
        let archive = write_archive(&[], &master_key(), single_stream_options()).unwrap();
        let wrong = MasterKey::from_raw_key(&[0x43; 32]).unwrap();

        assert_eq!(
            open_archive(&archive.bytes, &wrong).unwrap_err(),
            FormatError::HmacMismatch {
                structure: "CryptoHeader"
            }
        );
    }

    #[test]
    fn ordinary_encrypted_writers_emit_v45_archives() {
        let raw_key_archive = write_archive(
            &[RegularFile::new("raw.txt", b"raw key payload")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let raw_header = VolumeHeader::parse(&raw_key_archive.bytes[..VOLUME_HEADER_LEN]).unwrap();
        assert_eq!(raw_header.volume_format_rev, VOLUME_FORMAT_REV_45);
        let raw_opened = open_archive(&raw_key_archive.bytes, &master_key()).unwrap();
        assert_eq!(
            raw_opened.volume_header.volume_format_rev,
            VOLUME_FORMAT_REV_45
        );
        assert_eq!(
            raw_opened.extract_file("raw.txt").unwrap(),
            Some(b"raw key payload".to_vec())
        );

        let passphrase_kdf = KdfParams::Argon2id {
            t_cost: 1,
            m_cost_kib: 8,
            parallelism: 1,
            salt: b"0123456789abcdef".to_vec(),
        };
        let passphrase_archive = write_archive_with_kdf(
            &[RegularFile::new("pass.txt", b"passphrase payload")],
            &master_key(),
            single_stream_options(),
            &passphrase_kdf,
        )
        .unwrap();
        let passphrase_header =
            VolumeHeader::parse(&passphrase_archive.bytes[..VOLUME_HEADER_LEN]).unwrap();
        assert_eq!(passphrase_header.volume_format_rev, VOLUME_FORMAT_REV_45);
        let passphrase_opened = open_archive(&passphrase_archive.bytes, &master_key()).unwrap();
        assert_eq!(
            passphrase_opened.volume_header.volume_format_rev,
            VOLUME_FORMAT_REV_45
        );
        assert_eq!(
            passphrase_opened.extract_file("pass.txt").unwrap(),
            Some(b"passphrase payload".to_vec())
        );
    }

    #[test]
    fn rejects_future_volume_format_revision_before_key_mismatch() {
        let archive = write_archive(&[], &master_key(), single_stream_options()).unwrap();
        let mut bytes = archive.bytes;
        let mut header = VolumeHeader::parse(&bytes[..VOLUME_HEADER_LEN]).unwrap();
        header.volume_format_rev = VOLUME_FORMAT_REV_45 + 1;
        bytes[..VOLUME_HEADER_LEN].copy_from_slice(&header.to_bytes());
        let wrong = MasterKey::from_raw_key(&[0x43; 32]).unwrap();

        assert_eq!(
            open_archive(&bytes, &wrong).unwrap_err(),
            FormatError::UnsupportedVolumeFormatRevision {
                format_version: FORMAT_VERSION,
                volume_format_rev: VOLUME_FORMAT_REV_45 + 1,
                reader_max_supported_revision: READER_MAX_SUPPORTED_VOLUME_FORMAT_REV,
            }
        );
    }

    #[test]
    fn open_archive_unencrypted_accepts_v45_profile() {
        let archive = write_archive_unencrypted(
            &[RegularFile::new("payload.txt", b"smoke-v45-unencrypted")],
            WriterOptions {
                aead_algo: AeadAlgo::None,
                ..single_stream_options()
            },
        )
        .unwrap();

        let opened = open_archive_unencrypted(&archive.bytes).unwrap();
        let header = VolumeHeader::parse(&archive.bytes[..VOLUME_HEADER_LEN]).unwrap();

        assert_eq!(header.volume_format_rev, VOLUME_FORMAT_REV_45);
        assert_eq!(opened.volume_header.volume_format_rev, VOLUME_FORMAT_REV_45);
        assert_eq!(
            opened.extract_file("payload.txt").unwrap(),
            Some(b"smoke-v45-unencrypted".to_vec())
        );
        opened.verify().unwrap();
    }

    #[test]
    fn full_verification_reports_v45_metadata_capabilities_separately() {
        let archive = write_archive(
            &[RegularFile::new("report.txt", b"report")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        let verification = opened.verify_content().unwrap();
        let report = verification.metadata_report().unwrap();

        assert!(report.all_capture_complete);
        assert!(report.full_fidelity_possible);
        assert_eq!(report.profiles_present, ["portable-v1"]);
        assert!(report.auxiliary_kinds_present.is_empty());
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].path, b"report.txt");
        assert!(report.entries[0]
            .policy_capabilities
            .iter()
            .all(|capability| capability.policy_complete));
        assert!(report.entries[0].diagnostics.is_empty());
    }

    #[test]
    fn root_auth_unencrypted_v45_round_trips_with_recomputed_archive_root() {
        let archive = write_archive_with_root_auth(
            &[RegularFile::new(
                "signed-v45.txt",
                b"root-auth v45 plaintext",
            )],
            &master_key(),
            WriterOptions {
                aead_algo: AeadAlgo::None,
                ..single_stream_options()
            },
            test_root_auth_config(),
            |request| Ok(test_root_auth_value(request)),
        )
        .unwrap();
        let opened = open_archive_unencrypted(&archive.bytes).unwrap();
        let header = VolumeHeader::parse(&archive.bytes[..VOLUME_HEADER_LEN]).unwrap();

        assert_eq!(header.volume_format_rev, VOLUME_FORMAT_REV_45);
        assert_eq!(opened.volume_header.volume_format_rev, VOLUME_FORMAT_REV_45);
        assert_eq!(
            opened.extract_file("signed-v45.txt").unwrap(),
            Some(b"root-auth v45 plaintext".to_vec())
        );

        let verified = opened
            .verify_root_auth_with(|footer, archive_root| {
                Ok(test_root_auth_verifies(footer, archive_root))
            })
            .unwrap();

        assert_eq!(verified.format_version, FORMAT_VERSION);
        assert_eq!(verified.volume_format_rev, VOLUME_FORMAT_REV_45);
        assert_eq!(
            verified.archive_root,
            opened.root_auth_footer.as_ref().unwrap().archive_root
        );
    }

    #[test]
    fn recipientwrap_open_accepts_candidate_after_header_hmac() {
        let master = master_key();
        let archive = write_archive_with_recipient_wrap_records(
            &[RegularFile::new("wrapped.txt", b"recipient payload")],
            &master,
            single_stream_options(),
            vec![recipient_wrap_test_record()],
        )
        .unwrap();

        let opened = open_archive_with_recipient_wrap_resolver(&archive.bytes, |context| {
            assert_eq!(
                context.archive_identity.volume_format_rev,
                VOLUME_FORMAT_REV_45
            );
            assert_eq!(context.record.profile_id, 1);
            Ok(vec![master.0])
        })
        .unwrap();

        assert_eq!(
            opened.extract_file("wrapped.txt").unwrap(),
            Some(b"recipient payload".to_vec())
        );
        opened.verify().unwrap();
    }

    #[test]
    fn recipientwrap_seekable_open_uses_lazy_block_source() {
        let master = master_key();
        let archive = write_archive_with_recipient_wrap_records(
            &[RegularFile::new("wrapped.txt", b"recipient payload")],
            &master,
            single_stream_options(),
            vec![recipient_wrap_test_record()],
        )
        .unwrap();

        let opened = open_seekable_archive_with_recipient_wrap_resolver_options(
            CountingReadAt::new(archive.bytes, vec![]),
            |context| {
                assert_eq!(
                    context.archive_identity.volume_format_rev,
                    VOLUME_FORMAT_REV_45
                );
                assert_eq!(context.record.profile_id, 1);
                Ok(vec![master.0])
            },
            ReaderOptions::default(),
        )
        .unwrap();

        assert!(opened.blocks.is_empty());
        assert!(opened.lazy_blocks.is_some());
        assert_eq!(
            opened.extract_file("wrapped.txt").unwrap(),
            Some(b"recipient payload".to_vec())
        );
        opened.verify().unwrap();
    }

    #[test]
    fn recipientwrap_seekable_volume_set_opens_with_resolver() {
        let master = master_key();
        let archive = write_archive_with_recipient_wrap_records(
            &[RegularFile::new("wrapped.txt", b"recipient payload")],
            &master,
            WriterOptions {
                stripe_width: 2,
                volume_loss_tolerance: 0,
                ..WriterOptions::default()
            },
            vec![recipient_wrap_test_record()],
        )
        .unwrap();
        assert_eq!(archive.volumes.len(), 2);

        let opened = open_seekable_archive_volumes_with_recipient_wrap_resolver_options(
            archive.volumes,
            |context| {
                assert_eq!(
                    context.archive_identity.volume_format_rev,
                    VOLUME_FORMAT_REV_45
                );
                assert_eq!(context.record.profile_id, 1);
                Ok(vec![master.0])
            },
            ReaderOptions::default(),
        )
        .unwrap();

        assert_eq!(opened.observed_volume_count, 2);
        assert!(opened.blocks.is_empty());
        assert!(opened.lazy_blocks.is_some());
        assert_eq!(
            opened.extract_file("wrapped.txt").unwrap(),
            Some(b"recipient payload".to_vec())
        );
        opened.verify().unwrap();
    }

    #[test]
    fn recipientwrap_open_tries_subsequent_records_after_failed_candidate() {
        let master = master_key();
        let mut first_record = recipient_wrap_test_record();
        first_record.recipient_identity_bytes = b"first-candidate".to_vec();
        let mut second_record = recipient_wrap_test_record();
        second_record.recipient_identity_bytes = b"second-candidate".to_vec();

        let archive = write_archive_with_recipient_wrap_records(
            &[RegularFile::new("wrapped.txt", b"recipient payload")],
            &master,
            single_stream_options(),
            vec![first_record, second_record],
        )
        .unwrap();

        let mut attempts = Vec::new();
        let opened = open_archive_with_recipient_wrap_resolver(&archive.bytes, |context| {
            attempts.push(context.record.recipient_identity_bytes.clone());
            if context.record.recipient_identity_bytes.as_slice() == b"second-candidate" {
                Ok(vec![master.0])
            } else {
                Ok(vec![[0x99u8; 32]])
            }
        })
        .unwrap();

        assert_eq!(
            attempts,
            vec![b"first-candidate".to_vec(), b"second-candidate".to_vec(),]
        );
        assert_eq!(
            opened.extract_file("wrapped.txt").unwrap(),
            Some(b"recipient payload".to_vec())
        );
        opened.verify().unwrap();
    }

    #[test]
    fn recipientwrap_startup_rejects_malformed_record_length() {
        let master = master_key();
        let options = WriterOptions {
            bit_rot_buffer_pct: 0,
            ..single_stream_options()
        };
        let archive = write_archive_with_recipient_wrap_records(
            &[RegularFile::new("wrapped.txt", b"recipient payload")],
            &master,
            options,
            vec![recipient_wrap_test_record()],
        )
        .unwrap();
        let mut bytes = archive.bytes;
        let (_, _, table_start, _table_len, _) = recipient_wrap_layout(&bytes);
        bytes[table_start + 96..table_start + 100].copy_from_slice(&1u32.to_le_bytes());

        assert_eq!(
            open_archive_with_recipient_wrap_resolver(&bytes, |_| { Ok(vec![master.0]) })
                .unwrap_err(),
            FormatError::InvalidArchive("RecipientRecordV1 record_length is too small")
        );
    }

    #[test]
    fn recipientwrap_future_revision_rejects_before_resolver_callback() {
        let archive = write_archive_with_recipient_wrap_records(
            &[RegularFile::new("wrapped.txt", b"recipient payload")],
            &master_key(),
            single_stream_options(),
            vec![recipient_wrap_test_record()],
        )
        .unwrap();
        let mut bytes = archive.bytes;
        let mut header = VolumeHeader::parse(&bytes[..VOLUME_HEADER_LEN]).unwrap();
        header.volume_format_rev = VOLUME_FORMAT_REV_45 + 1;
        bytes[..VOLUME_HEADER_LEN].copy_from_slice(&header.to_bytes());

        let mut called = false;
        let err = open_archive_with_recipient_wrap_resolver(&bytes, |_| {
            called = true;
            Ok(vec![master_key().0])
        })
        .unwrap_err();

        assert!(!called);
        assert_eq!(
            err,
            FormatError::UnsupportedVolumeFormatRevision {
                format_version: FORMAT_VERSION,
                volume_format_rev: VOLUME_FORMAT_REV_45 + 1,
                reader_max_supported_revision: READER_MAX_SUPPORTED_VOLUME_FORMAT_REV,
            }
        );
    }

    #[test]
    fn recipientwrap_stripe_width_mismatch_rejects_before_resolver_callback() {
        let archive = write_archive_with_recipient_wrap_records(
            &[RegularFile::new("wrapped.txt", b"recipient payload")],
            &master_key(),
            single_stream_options(),
            vec![recipient_wrap_test_record()],
        )
        .unwrap();
        let mut bytes = archive.bytes;
        let mut header = VolumeHeader::parse(&bytes[..VOLUME_HEADER_LEN]).unwrap();
        header.stripe_width += 1;
        bytes[..VOLUME_HEADER_LEN].copy_from_slice(&header.to_bytes());

        let mut called = false;
        let err = open_archive_with_recipient_wrap_resolver(&bytes, |_| {
            called = true;
            Ok(vec![master_key().0])
        })
        .unwrap_err();

        assert!(!called);
        assert_eq!(
            err,
            FormatError::InvalidArchive("VolumeHeader and CryptoHeader stripe_width differ")
        );
    }

    #[test]
    fn recipientwrap_defers_raw_stream_profile_rejection_until_after_resolver_callback() {
        let master = master_key();
        let archive = write_archive_with_recipient_wrap_records(
            &[RegularFile::new("wrapped.txt", b"recipient payload")],
            &master,
            single_stream_options(),
            vec![recipient_wrap_test_record()],
        )
        .unwrap();
        let mut bytes = archive.bytes;
        add_raw_stream_profile_to_physical_crypto_header(&mut bytes);
        recompute_physical_crypto_header_hmac(&mut bytes, &master);

        let mut called = false;
        let err = open_archive_with_recipient_wrap_resolver(&bytes, |_| {
            called = true;
            Ok(vec![master.0])
        })
        .unwrap_err();

        assert!(called);
        assert_eq!(
            err,
            FormatError::ReaderUnsupported(RAW_STREAM_UNSUPPORTED_MESSAGE)
        );
    }

    #[test]
    fn recipientwrap_recovers_physical_key_wrap_table_from_cmra_authority() {
        let master = master_key();
        let archive = write_archive_with_recipient_wrap_records(
            &[RegularFile::new("wrapped.txt", b"recipient payload")],
            &master,
            single_stream_options(),
            vec![recipient_wrap_test_record()],
        )
        .unwrap();
        let mut bytes = archive.bytes;
        let header = VolumeHeader::parse(&bytes[..VOLUME_HEADER_LEN]).unwrap();
        let crypto_start = header.crypto_header_offset as usize;
        let crypto_end = crypto_start + header.crypto_header_length as usize;
        let crypto_header = CryptoHeader::parse(
            &bytes[crypto_start..crypto_end],
            header.crypto_header_length,
        )
        .unwrap();
        let KdfParams::RecipientWrap {
            key_wrap_table_length,
            ..
        } = crypto_header.kdf_params
        else {
            panic!("expected RecipientWrap KdfParams");
        };
        let table_start = crypto_end;
        let table_end = table_start + key_wrap_table_length as usize;
        bytes[table_end - 1] ^= 0x01;

        let mut called = false;
        let opened = open_archive_with_recipient_wrap_resolver(&bytes, |context| {
            called = true;
            assert_eq!(
                context.archive_identity.volume_format_rev,
                VOLUME_FORMAT_REV_45
            );
            assert_eq!(context.record.profile_id, 1);
            Ok(vec![master.0])
        })
        .unwrap();

        assert!(called);
        assert_eq!(
            opened.extract_file("wrapped.txt").unwrap(),
            Some(b"recipient payload".to_vec())
        );
        opened.verify().unwrap();
    }

    #[test]
    fn recipientwrap_open_rejects_wrong_candidate_header_hmac() {
        let archive = write_archive_with_recipient_wrap_records(
            &[RegularFile::new("wrapped.txt", b"recipient payload")],
            &master_key(),
            single_stream_options(),
            vec![recipient_wrap_test_record()],
        )
        .unwrap();
        let wrong_candidate = [0x99u8; 32];

        assert_eq!(
            open_archive_with_recipient_wrap_resolver(&archive.bytes, |_| {
                Ok(vec![wrong_candidate])
            })
            .unwrap_err(),
            FormatError::KeyMaterialMismatch
        );
    }

    #[test]
    fn recipientwrap_open_recovers_tampered_physical_crypto_header_hmac_from_cmra() {
        let master = master_key();
        let archive = write_archive_with_recipient_wrap_records(
            &[RegularFile::new("wrapped.txt", b"recipient payload")],
            &master,
            single_stream_options(),
            vec![recipient_wrap_test_record()],
        )
        .unwrap();
        let mut bytes = archive.bytes.clone();
        let header = VolumeHeader::parse(&bytes[..VOLUME_HEADER_LEN]).unwrap();
        let hmac_end = header.crypto_header_offset as usize + header.crypto_header_length as usize;
        bytes[hmac_end - 1] ^= 0x55;

        let opened =
            open_archive_with_recipient_wrap_resolver(&bytes, |_| Ok(vec![master.0])).unwrap();

        assert_eq!(
            opened.extract_file("wrapped.txt").unwrap(),
            Some(b"recipient payload".to_vec())
        );
        assert_eq!(
            opened.crypto_header_bytes,
            archive.bytes[header.crypto_header_offset as usize..hmac_end]
        );
        opened.verify().unwrap();
    }

    #[test]
    fn recipientwrap_archive_does_not_fall_back_to_raw_master_key_open() {
        let master = master_key();
        let archive = write_archive_with_recipient_wrap_records(
            &[RegularFile::new("wrapped.txt", b"recipient payload")],
            &master,
            single_stream_options(),
            vec![recipient_wrap_test_record()],
        )
        .unwrap();

        assert_eq!(
            open_archive(&archive.bytes, &master).unwrap_err(),
            FormatError::KeyMaterialMismatch
        );
    }

    #[test]
    fn recipientwrap_seekable_archive_does_not_fall_back_to_raw_master_key_open() {
        let master = master_key();
        let archive = write_archive_with_recipient_wrap_records(
            &[RegularFile::new("wrapped.txt", b"recipient payload")],
            &master,
            single_stream_options(),
            vec![recipient_wrap_test_record()],
        )
        .unwrap();

        assert_eq!(
            open_seekable_archive(archive.bytes, &master).unwrap_err(),
            FormatError::KeyMaterialMismatch
        );
    }

    #[test]
    fn public_no_key_verifies_signed_recipientwrap_block_commitment() {
        let archive = write_archive_with_root_auth_and_recipient_wrap_records(
            &[RegularFile::new("wrapped.txt", b"recipient payload")],
            &master_key(),
            single_stream_options(),
            vec![recipient_wrap_test_record()],
            test_root_auth_config(),
            |request| Ok(test_root_auth_value(request)),
        )
        .unwrap();

        let verified = public_no_key_verify_archive_with(&archive.bytes, |footer, archive_root| {
            Ok(test_root_auth_verifies(footer, archive_root))
        })
        .unwrap();

        assert_eq!(verified.volume_format_rev, VOLUME_FORMAT_REV_45);
        assert_eq!(verified.total_data_block_count, 3);
    }

    #[test]
    fn public_no_key_rejects_recipientwrap_startup_and_cmra_kdf_mismatch() {
        let archive = write_archive_with_root_auth_and_recipient_wrap_records(
            &[RegularFile::new("wrapped.txt", b"recipient payload")],
            &master_key(),
            single_stream_options(),
            vec![recipient_wrap_test_record()],
            test_root_auth_config(),
            |request| Ok(test_root_auth_value(request)),
        )
        .unwrap();
        let mut bytes = archive.bytes;
        mutate_top_level_recipient_wrap_public_profile(&mut bytes);

        let err = public_no_key_verify_archive_with(&bytes, |footer, archive_root| {
            Ok(test_root_auth_verifies(footer, archive_root))
        })
        .unwrap_err();

        assert_eq!(
            err,
            FormatError::InvalidArchive("no valid v41 public CMRA candidate found")
        );
    }

    #[test]
    fn public_no_key_rejects_recipientwrap_kdf_profile_mismatch_across_volumes() {
        let archive = write_archive_with_root_auth_and_recipient_wrap_records(
            &[RegularFile::new("wrapped.txt", b"recipient payload")],
            &master_key(),
            WriterOptions {
                stripe_width: 2,
                volume_loss_tolerance: 0,
                ..WriterOptions::default()
            },
            vec![recipient_wrap_test_record()],
            test_root_auth_config(),
            |request| Ok(test_root_auth_value(request)),
        )
        .unwrap();
        let mut volumes = archive.volumes;
        mutate_top_level_recipient_wrap_public_profile(&mut volumes[1]);
        mutate_cmra_recipient_wrap_public_profile(&mut volumes[1]);

        let volume_refs = volumes.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let err = public_no_key_verify_volumes_with(&volume_refs, |footer, archive_root| {
            Ok(test_root_auth_verifies(footer, archive_root))
        })
        .unwrap_err();

        assert_eq!(
            err,
            FormatError::InvalidArchive("public no-key volume global metadata differs")
        );
    }

    #[test]
    fn write_archive_defaults_to_current_revision() {
        let archive = write_archive(&[], &master_key(), single_stream_options()).unwrap();
        let header = VolumeHeader::parse(&archive.bytes[..VOLUME_HEADER_LEN]).unwrap();

        assert_eq!(header.format_version, FORMAT_VERSION);
        assert_eq!(header.volume_format_rev, VOLUME_FORMAT_REV);
    }

    #[test]
    fn non_seekable_stream_rejects_future_volume_format_revision() {
        let archive = write_archive(&[], &master_key(), single_stream_options()).unwrap();
        let mut bytes = archive.bytes;
        let mut header = VolumeHeader::parse(&bytes[..VOLUME_HEADER_LEN]).unwrap();
        header.volume_format_rev = VOLUME_FORMAT_REV_45 + 1;
        bytes[..VOLUME_HEADER_LEN].copy_from_slice(&header.to_bytes());

        assert_eq!(
            verify_non_seekable_stream(std::io::Cursor::new(bytes), &master_key()).unwrap_err(),
            FormatError::UnsupportedVolumeFormatRevision {
                format_version: FORMAT_VERSION,
                volume_format_rev: VOLUME_FORMAT_REV_45 + 1,
                reader_max_supported_revision: READER_MAX_SUPPORTED_VOLUME_FORMAT_REV,
            }
        );
    }

    #[test]
    fn open_seekable_archive_rejects_future_volume_format_revision() {
        let archive = write_archive(&[], &master_key(), single_stream_options()).unwrap();
        let mut bytes = archive.bytes;
        let mut header = VolumeHeader::parse(&bytes[..VOLUME_HEADER_LEN]).unwrap();
        header.volume_format_rev = VOLUME_FORMAT_REV_45 + 1;
        bytes[..VOLUME_HEADER_LEN].copy_from_slice(&header.to_bytes());

        assert_eq!(
            open_seekable_archive(CountingReadAt::new(bytes, vec![]), &master_key()).unwrap_err(),
            FormatError::UnsupportedVolumeFormatRevision {
                format_version: FORMAT_VERSION,
                volume_format_rev: VOLUME_FORMAT_REV_45 + 1,
                reader_max_supported_revision: READER_MAX_SUPPORTED_VOLUME_FORMAT_REV,
            }
        );
    }

    #[test]
    fn rejects_payload_tamper_even_with_recomputed_block_crc() {
        let mut archive = write_archive(
            &[RegularFile::new("file.txt", b"authenticated")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap()
        .bytes;
        let volume = VolumeHeader::parse(&archive[..VOLUME_HEADER_LEN]).unwrap();
        let crypto_end = VOLUME_HEADER_LEN + usize::try_from(volume.crypto_header_length).unwrap();
        let crypto = CryptoHeader::parse(
            &archive[VOLUME_HEADER_LEN..crypto_end],
            volume.crypto_header_length,
        )
        .unwrap();
        let block_size = crypto.fixed.block_size as usize;
        archive[crypto_end + 16] ^= 1;
        let crc_offset = crypto_end + 16 + block_size;
        let crc = crc32c::crc32c(&archive[crypto_end..crc_offset]);
        archive[crc_offset..crc_offset + 4].copy_from_slice(&crc.to_le_bytes());

        let opened = open_archive(&archive, &master_key()).unwrap();
        assert_eq!(opened.verify().unwrap_err(), FormatError::AeadFailure);
    }

    #[test]
    fn list_and_extract_use_final_view_for_duplicate_paths() {
        let archive = write_archive(
            &[
                RegularFile {
                    mtime: crate::ArchiveTimestamp::from_seconds(1_700_000_000),
                    ..RegularFile::new("same.txt", b"old")
                },
                RegularFile {
                    mtime: crate::ArchiveTimestamp::from_seconds(1_700_000_100),
                    ..RegularFile::new("same.txt", b"newer")
                },
            ],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();

        let listed = opened.list_index_entries().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].path, "same.txt");
        assert_eq!(listed[0].name, "same.txt");
        assert_eq!(listed[0].file_data_size, 5);
        assert_eq!(listed[0].flags, crate::entry_metadata::EXTENDED_METADATA_V1);
        assert_eq!(listed[0].frame_count, 1);
        assert!(listed[0].layout.compressed_size > 0);
        let looked_up = opened.lookup_index_entry("same.txt").unwrap().unwrap();
        assert_eq!(looked_up.path, "same.txt");
        assert_eq!(looked_up.file_data_size, 5);
        assert_eq!(looked_up.flags, crate::entry_metadata::EXTENDED_METADATA_V1);
        assert_eq!(opened.lookup_index_entry("missing.txt").unwrap(), None);
        assert_eq!(
            opened.list_files().unwrap(),
            vec![ArchiveEntry {
                path: "same.txt".to_string(),
                file_data_size: 5,
                kind: TarEntryKind::Regular,
                mode: 0o644,
                mtime: ArchiveTimestamp::from_seconds(1_700_000_100),
                diagnostics: Vec::new(),
                link_target: None,
                created: None,
                accessed: None,
                attributes: None,
                uid: None,
                gid: None,
                uname: None,
                gname: None,
            }]
        );
        assert_eq!(
            opened.extract_file("same.txt").unwrap(),
            Some(b"newer".to_vec())
        );
        opened.verify().unwrap();
    }

    #[test]
    fn index_entries_do_not_decrypt_payload_envelopes() {
        let (mut opened, broken_payload_block) = multi_envelope_reader_fixture();
        corrupt_payload_record(&mut opened.blocks, broken_payload_block);

        let listed = opened.list_index_entries().unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].path, "broken.txt");
        assert_eq!(listed[0].file_data_size, b"broken payload\n".len() as u64);
        assert_eq!(listed[0].flags, crate::entry_metadata::EXTENDED_METADATA_V1);
        assert_eq!(listed[1].path, "healthy.txt");
        assert_eq!(listed[1].file_data_size, b"healthy payload\n".len() as u64);
        assert_eq!(listed[1].flags, crate::entry_metadata::EXTENDED_METADATA_V1);
        let looked_up = opened.lookup_index_entry("broken.txt").unwrap().unwrap();
        assert_eq!(looked_up.path, "broken.txt");
        assert_eq!(looked_up.file_data_size, b"broken payload\n".len() as u64);
        assert_eq!(looked_up.flags, crate::entry_metadata::EXTENDED_METADATA_V1);
        assert_eq!(opened.list_files().unwrap_err(), FormatError::AeadFailure);
    }

    #[test]
    fn index_entry_layout_stats_match_frame_and_envelope_tables() {
        let payload = pseudo_random_bytes(12 * 1024);
        let archive = write_archive(
            &[RegularFile::new("chunked.bin", &payload)],
            &master_key(),
            WriterOptions {
                block_size: 4096,
                chunk_size: 1024,
                envelope_target_size: 2048,
                stripe_width: 1,
                volume_loss_tolerance: 0,
                bit_rot_buffer_pct: 0,
                fec_data_shards: 16,
                fec_parity_shards: 0,
                ..WriterOptions::default()
            },
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        let entry = opened.list_index_entries().unwrap().remove(0);
        let located = opened
            .locate_index_file(b"chunked.bin")
            .unwrap()
            .expect("indexed file exists");
        let file = &located.shard.files[located.file_index];
        let frames = frame_range_for_file(&located.shard, file).unwrap();
        assert!(frames.len() > 1);

        let expected_compressed_size = frames
            .iter()
            .map(|frame| frame.compressed_size as u64)
            .sum::<u64>();
        let expected_decompressed_frame_size = frames
            .iter()
            .map(|frame| frame.decompressed_size as u64)
            .sum::<u64>();
        let envelope_indexes = frames
            .iter()
            .map(|frame| frame.envelope_index)
            .collect::<BTreeSet<_>>();
        assert!(envelope_indexes.len() > 1);

        let envelopes = envelope_indexes
            .iter()
            .map(|index| envelope_by_index(&located.shard, *index).unwrap())
            .collect::<Vec<_>>();
        let expected_first_payload_block_index = envelopes
            .iter()
            .map(|envelope| envelope.first_block_index)
            .min();
        let expected_payload_data_block_count = envelopes
            .iter()
            .map(|envelope| envelope.data_block_count as u64)
            .sum::<u64>();
        let expected_payload_parity_block_count = envelopes
            .iter()
            .map(|envelope| envelope.parity_block_count as u64)
            .sum::<u64>();
        let expected_payload_encrypted_size = envelopes
            .iter()
            .map(|envelope| envelope.encrypted_size as u64)
            .sum::<u64>();

        assert_eq!(entry.path, "chunked.bin");
        assert_eq!(entry.name, "chunked.bin");
        assert_eq!(entry.file_data_size, payload.len() as u64);
        assert_eq!(entry.flags, file.flags);
        assert_eq!(entry.tar_member_group_size, file.tar_member_group_size);
        assert_eq!(entry.first_frame_index, file.first_frame_index);
        assert_eq!(entry.frame_count, file.frame_count);
        assert_eq!(
            entry.offset_in_first_frame_plaintext,
            file.offset_in_first_frame_plaintext
        );
        assert_eq!(entry.layout.compressed_size, expected_compressed_size);
        assert_eq!(
            entry.layout.decompressed_frame_size,
            expected_decompressed_frame_size
        );
        assert_eq!(entry.layout.envelope_count as usize, envelope_indexes.len());
        assert_eq!(
            entry.layout.first_envelope_index,
            envelope_indexes.iter().next().copied()
        );
        assert_eq!(
            entry.layout.last_envelope_index,
            envelope_indexes.iter().next_back().copied()
        );
        assert_eq!(
            entry.layout.first_payload_block_index,
            expected_first_payload_block_index
        );
        assert_eq!(
            entry.layout.payload_data_block_count,
            expected_payload_data_block_count
        );
        assert_eq!(
            entry.layout.payload_parity_block_count,
            expected_payload_parity_block_count
        );
        assert_eq!(
            entry.layout.payload_encrypted_size,
            expected_payload_encrypted_size
        );
    }

    #[test]
    fn extract_file_does_not_decrypt_unselected_payload_envelope() {
        // This fixture corrupts only the unselected envelope, proving selected
        // extraction does not decrypt unrelated payload envelopes.
        let (mut opened, broken_payload_block) = multi_envelope_reader_fixture();
        corrupt_payload_record(&mut opened.blocks, broken_payload_block);

        assert_eq!(
            opened.extract_file("healthy.txt").unwrap(),
            Some(b"healthy payload\n".to_vec())
        );
        assert_eq!(
            opened.extract_file("broken.txt").unwrap_err(),
            FormatError::AeadFailure
        );
        assert_eq!(opened.verify().unwrap_err(), FormatError::AeadFailure);
    }

    #[test]
    fn seekable_extract_does_not_read_unselected_payload_envelope() {
        let healthy = pseudo_random_bytes(64 * 1024);
        let broken = pseudo_random_bytes(64 * 1024);
        let options = WriterOptions {
            block_size: 4096,
            chunk_size: 4096,
            envelope_target_size: 8192,
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            fec_data_shards: 4,
            fec_parity_shards: 0,
            index_fec_data_shards: 4,
            index_fec_parity_shards: 0,
            index_root_fec_data_shards: 4,
            index_root_fec_parity_shards: 0,
            ..WriterOptions::default()
        };
        let archive = write_archive(
            &[
                RegularFile::new("healthy.bin", &healthy),
                RegularFile::new("broken.bin", &broken),
            ],
            &master_key(),
            options,
        )
        .unwrap();
        let eager = open_archive(&archive.bytes, &master_key()).unwrap();
        let healthy_envelopes = envelope_indices_for_path(&eager, "healthy.bin");
        let broken_envelopes = envelope_entries_for_path(&eager, "broken.bin");
        let denied_block_indices = broken_envelopes
            .iter()
            .filter(|envelope| !healthy_envelopes.contains(&envelope.envelope_index))
            .flat_map(|envelope| {
                let block_count =
                    envelope.data_block_count as u64 + envelope.parity_block_count as u64;
                envelope.first_block_index..envelope.first_block_index + block_count
            })
            .collect::<BTreeSet<_>>();
        assert!(
            !denied_block_indices.is_empty(),
            "fixture must place broken.bin in at least one unshared envelope"
        );
        let denied_ranges = block_record_slots(&archive.bytes)
            .into_iter()
            .filter_map(|(offset, len, record)| {
                denied_block_indices
                    .contains(&record.block_index)
                    .then_some((offset as u64, (offset + len) as u64))
            })
            .collect::<Vec<_>>();
        assert!(!denied_ranges.is_empty());

        let reader = CountingReadAt::new(archive.bytes, denied_ranges.clone());
        let opened = open_seekable_archive(reader.clone(), &master_key()).unwrap();

        assert_eq!(opened.extract_file("healthy.bin").unwrap(), Some(healthy));
        for (read_start, read_end) in reader.reads() {
            assert!(
                denied_ranges
                    .iter()
                    .all(|(start, end)| !ranges_overlap(read_start, read_end, *start, *end)),
                "targeted extract read an unrelated payload BlockRecord range"
            );
        }
        assert_eq!(
            opened.extract_file("broken.bin").unwrap_err(),
            FormatError::InvalidArchive("denied test read")
        );
    }

    #[test]
    fn extract_file_to_writer_streams_before_reading_later_envelopes() {
        struct FailOnFirstWrite;

        impl std::io::Write for FailOnFirstWrite {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("sink stopped"))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let payload = pseudo_random_bytes(128 * 1024);
        let options = WriterOptions {
            block_size: 4096,
            chunk_size: 4096,
            envelope_target_size: 8192,
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            fec_data_shards: 4,
            fec_parity_shards: 0,
            index_fec_data_shards: 4,
            index_fec_parity_shards: 0,
            index_root_fec_data_shards: 4,
            index_root_fec_parity_shards: 0,
            ..WriterOptions::default()
        };
        let archive = write_archive(
            &[RegularFile::new("large.bin", &payload)],
            &master_key(),
            options,
        )
        .unwrap();
        let eager = open_archive(&archive.bytes, &master_key()).unwrap();
        let envelopes = envelope_entries_for_path(&eager, "large.bin");
        let first_envelope = envelopes
            .first()
            .expect("large fixture should have at least one envelope")
            .envelope_index;
        let later_envelope_blocks = envelopes
            .iter()
            .filter(|entry| entry.envelope_index != first_envelope)
            .flat_map(|entry| {
                let block_count = entry.data_block_count as u64 + entry.parity_block_count as u64;
                entry.first_block_index..entry.first_block_index + block_count
            })
            .collect::<BTreeSet<_>>();
        assert!(
            !later_envelope_blocks.is_empty(),
            "fixture must span more than one payload envelope"
        );
        let denied_ranges = block_record_slots(&archive.bytes)
            .into_iter()
            .filter_map(|(offset, len, record)| {
                later_envelope_blocks
                    .contains(&record.block_index)
                    .then_some((offset as u64, (offset + len) as u64))
            })
            .collect::<Vec<_>>();
        assert!(!denied_ranges.is_empty());

        let reader = CountingReadAt::new(archive.bytes, denied_ranges.clone());
        let opened = open_seekable_archive(reader.clone(), &master_key()).unwrap();
        let mut writer = FailOnFirstWrite;

        let err = opened
            .extract_file_to_writer("large.bin", &mut writer)
            .unwrap_err();
        assert_eq!(err.to_string(), "extraction output write failed");
        for (read_start, read_end) in reader.reads() {
            assert!(
                denied_ranges
                    .iter()
                    .all(|(start, end)| !ranges_overlap(read_start, read_end, *start, *end)),
                "streaming writer read a later payload envelope before surfacing writer failure"
            );
        }
    }

    #[test]
    fn extract_file_to_writer_writes_bounded_chunks() {
        struct ChunkRecorder {
            total: usize,
            max_write: usize,
            writes: usize,
        }

        impl std::io::Write for ChunkRecorder {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.total += buf.len();
                self.max_write = self.max_write.max(buf.len());
                self.writes += 1;
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let payload = pseudo_random_bytes(128 * 1024);
        let options = WriterOptions {
            block_size: 4096,
            chunk_size: 4096,
            envelope_target_size: 8192,
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            fec_data_shards: 4,
            fec_parity_shards: 0,
            index_fec_data_shards: 4,
            index_fec_parity_shards: 0,
            index_root_fec_data_shards: 4,
            index_root_fec_parity_shards: 0,
            ..WriterOptions::default()
        };
        let archive = write_archive(
            &[RegularFile::new("large.bin", &payload)],
            &master_key(),
            options,
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        let mut writer = ChunkRecorder {
            total: 0,
            max_write: 0,
            writes: 0,
        };

        opened
            .extract_file_to_writer("large.bin", &mut writer)
            .unwrap()
            .unwrap();

        assert_eq!(writer.total, payload.len());
        assert!(writer.writes > 1);
        assert!(
            writer.max_write <= options.chunk_size as usize,
            "writer saw a {} byte chunk, larger than the {} byte frame target",
            writer.max_write,
            options.chunk_size
        );
    }

    #[test]
    fn extract_file_to_writer_with_progress_reports_payload_bytes() {
        struct ChunkRecorder {
            total: usize,
        }

        impl std::io::Write for ChunkRecorder {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.total += buf.len();
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let payload = pseudo_random_bytes(128 * 1024);
        let options = WriterOptions {
            block_size: 4096,
            chunk_size: 4096,
            envelope_target_size: 8192,
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            fec_data_shards: 4,
            fec_parity_shards: 0,
            index_fec_data_shards: 4,
            index_fec_parity_shards: 0,
            index_root_fec_data_shards: 4,
            index_root_fec_parity_shards: 0,
            ..WriterOptions::default()
        };
        let archive = write_archive(
            &[RegularFile::new("large.bin", &payload)],
            &master_key(),
            options,
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        let mut writer = ChunkRecorder { total: 0 };
        let mut progress_events = Vec::new();
        let mut progress = |archive_path: &str, bytes: u64| {
            progress_events.push((archive_path.to_owned(), bytes));
        };

        opened
            .extract_file_to_writer_with_progress("large.bin", &mut writer, &mut progress)
            .unwrap()
            .unwrap();

        let reported_bytes = progress_events.iter().map(|(_, bytes)| *bytes).sum::<u64>();
        assert_eq!(writer.total, payload.len());
        assert_eq!(reported_bytes, payload.len() as u64);
        assert!(progress_events.len() > 1);
        assert!(progress_events.iter().all(|(path, _)| path == "large.bin"));
    }

    #[test]
    fn streaming_filesystem_extract_does_not_publish_partial_file_on_late_payload_error() {
        let payload = pseudo_random_bytes(128 * 1024);
        let options = WriterOptions {
            block_size: 4096,
            chunk_size: 4096,
            envelope_target_size: 8192,
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            fec_data_shards: 4,
            fec_parity_shards: 0,
            index_fec_data_shards: 4,
            index_fec_parity_shards: 0,
            index_root_fec_data_shards: 4,
            index_root_fec_parity_shards: 0,
            ..WriterOptions::default()
        };
        let archive = write_archive(
            &[RegularFile::new("large.bin", &payload)],
            &master_key(),
            options,
        )
        .unwrap();
        let eager = open_archive(&archive.bytes, &master_key()).unwrap();
        let envelopes = envelope_entries_for_path(&eager, "large.bin");
        let last_envelope = envelopes
            .last()
            .expect("large fixture should have at least one envelope");
        assert_ne!(
            envelopes.first().unwrap().envelope_index,
            last_envelope.envelope_index,
            "fixture must span more than one payload envelope"
        );
        let corrupt_slot = block_record_slots(&archive.bytes)
            .into_iter()
            .enumerate()
            .find_map(|(slot, (_, _, record))| {
                (record.block_index == last_envelope.first_block_index).then_some(slot)
            })
            .unwrap();
        let mut corrupted = archive.bytes;
        corrupt_block_record_payload_at_slot(&mut corrupted, corrupt_slot);
        let opened = open_seekable_archive(corrupted, &master_key()).unwrap();
        let tmp = tempfile::tempdir().unwrap();

        assert!(matches!(
            opened
                .extract_file_to("large.bin", tmp.path(), SafeExtractionOptions::default())
                .unwrap_err(),
            FormatError::AeadFailure | FormatError::FecTooFewAvailableShards
        ));
        assert!(!tmp.path().join("large.bin").exists());
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
    }

    #[test]
    fn bootstrap_sidecar_opens_lists_verifies_and_extracts() {
        let archive = write_archive(
            &[RegularFile::new("dir/sidecar.txt", b"hello sidecar")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let opened = open_archive_with_bootstrap_sidecar(
            &archive.bytes,
            &archive.bootstrap_sidecar,
            &master_key(),
        )
        .unwrap();

        assert_eq!(
            opened.list_files().unwrap(),
            vec![ArchiveEntry {
                path: "dir/sidecar.txt".to_string(),
                file_data_size: 13,
                kind: TarEntryKind::Regular,
                mode: 0o644,
                mtime: ArchiveTimestamp::UNIX_EPOCH,
                diagnostics: Vec::new(),
                link_target: None,
                created: None,
                accessed: None,
                attributes: None,
                uid: None,
                gid: None,
                uname: None,
                gname: None,
            }]
        );
        assert_eq!(
            opened.extract_file("dir/sidecar.txt").unwrap(),
            Some(b"hello sidecar".to_vec())
        );
        opened.verify().unwrap();
    }

    #[test]
    fn fast_verify_plaintext_zero_recovery_defers_payload_semantics() {
        let options = WriterOptions {
            aead_algo: AeadAlgo::None,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            ..single_stream_options()
        };
        let archive = write_archive_unencrypted(
            &[RegularFile::new(
                "payload.txt",
                b"payload bytes large enough to produce a zstd frame",
            )],
            options,
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        let tables = opened.load_payload_index_tables().unwrap();
        let first_envelope = tables.envelopes.values().next().unwrap();
        let volume_header = VolumeHeader::parse(&archive.bytes[..VOLUME_HEADER_LEN]).unwrap();
        let crypto_end = VOLUME_HEADER_LEN + volume_header.crypto_header_length as usize;
        let record_len = opened.crypto_header.block_size as usize + BLOCK_RECORD_FRAMING_LEN;
        let payload_offset = crypto_end + first_envelope.first_block_index as usize * record_len;

        let mut tampered = archive.bytes.clone();
        tampered[payload_offset + 16] ^= 0x01;
        let crc_offset = payload_offset + 16 + opened.crypto_header.block_size as usize;
        let crc = crc32c::crc32c(&tampered[payload_offset..crc_offset]);
        tampered[crc_offset..crc_offset + 4].copy_from_slice(&crc.to_le_bytes());

        let tampered_opened = open_archive(&tampered, &master_key()).unwrap();
        assert!(tampered_opened.fast_verify_defers_payload_semantics());
        tampered_opened.verify_content_fast().unwrap();
        assert!(tampered_opened.verify_content().is_err());
    }

    #[test]
    fn fast_verify_root_auth_archive_requires_full_root_auth_scan() {
        let archive = write_archive_with_root_auth(
            &[RegularFile::new("signed.txt", b"root-auth payload")],
            &master_key(),
            single_stream_options(),
            RootAuthWriterConfig {
                authenticator_id: 0x7777,
                signer_identity_type: 1,
                signer_identity: b"test signer",
                authenticator_value_length: 32,
            },
            |request| Ok(request.archive_root.to_vec()),
        )
        .unwrap();

        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        assert!(!opened.fast_verify_defers_payload_semantics());
        assert!(matches!(
            opened.verify_content_fast().unwrap().mode,
            ContentVerificationMode::Fast
        ));
    }

    #[test]
    fn fast_verify_dictionary_archive_does_not_defer_payload_semantics() {
        let archive = write_archive_with_dictionary(
            &[RegularFile::new("dict.txt", b"dictionary payload")],
            &master_key(),
            single_stream_options(),
            dictionary(),
        )
        .unwrap();

        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        assert!(!opened.fast_verify_defers_payload_semantics());
    }

    #[test]
    fn fast_verify_encrypted_archive_does_not_defer_payload_semantics() {
        let options = WriterOptions {
            aead_algo: AeadAlgo::AesGcmSiv256,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            ..single_stream_options()
        };
        let archive = write_archive(
            &[RegularFile::new("payload.txt", b"encrypted payload")],
            &master_key(),
            options,
        )
        .unwrap();

        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        assert!(!opened.fast_verify_defers_payload_semantics());
    }

    #[test]
    fn fast_verify_repair_archive_does_not_defer_payload_semantics() {
        let options = WriterOptions {
            fec_parity_shards: 2,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            ..single_stream_options()
        };
        let archive = write_archive(
            &[RegularFile::new("payload.txt", b"payload for repair")],
            &master_key(),
            options,
        )
        .unwrap();

        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        assert!(!opened.fast_verify_defers_payload_semantics());
    }

    #[test]
    fn dictionary_archive_opens_lists_verifies_and_extracts_seekable() {
        let archive = write_archive_with_dictionary(
            &[RegularFile::new(
                "dir/dict.txt",
                b"common words common words dictionary payload",
            )],
            &master_key(),
            single_stream_options(),
            dictionary(),
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();

        assert_eq!(opened.crypto_header.has_dictionary, 1);
        assert!(opened.index_root.header.dictionary_data_block_count > 0);
        assert_eq!(
            opened.list_files().unwrap(),
            vec![ArchiveEntry {
                path: "dir/dict.txt".to_string(),
                file_data_size: 44,
                kind: TarEntryKind::Regular,
                mode: 0o644,
                mtime: ArchiveTimestamp::UNIX_EPOCH,
                diagnostics: Vec::new(),
                link_target: None,
                created: None,
                accessed: None,
                attributes: None,
                uid: None,
                gid: None,
                uname: None,
                gname: None,
            }]
        );
        assert_eq!(
            opened.extract_file("dir/dict.txt").unwrap(),
            Some(b"common words common words dictionary payload".to_vec())
        );
        opened.verify().unwrap();
    }

    #[test]
    fn dictionary_object_tamper_fails_before_payload_decompression() {
        let archive = write_archive_with_dictionary(
            &[RegularFile::new(
                "dir/dict.txt",
                b"common words common words dictionary payload",
            )],
            &master_key(),
            single_stream_options(),
            dictionary(),
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        let volume_header = VolumeHeader::parse(&archive.bytes[..VOLUME_HEADER_LEN]).unwrap();
        let crypto_end = VOLUME_HEADER_LEN + volume_header.crypto_header_length as usize;
        let record_len = opened.crypto_header.block_size as usize + BLOCK_RECORD_FRAMING_LEN;
        let dictionary_offset =
            crypto_end + opened.index_root.header.dictionary_first_block as usize * record_len;

        let mut tampered = archive.bytes.clone();
        tampered[dictionary_offset + 16] ^= 0x01;
        let crc_offset = dictionary_offset + 16 + opened.crypto_header.block_size as usize;
        let crc = crc32c::crc32c(&tampered[dictionary_offset..crc_offset]);
        tampered[crc_offset..crc_offset + 4].copy_from_slice(&crc.to_le_bytes());

        assert_eq!(
            open_archive(&tampered, &master_key()).unwrap_err(),
            FormatError::AeadFailure
        );
    }

    #[test]
    fn dictionary_archive_bootstraps_from_sidecar_for_non_seekable_open() {
        let archive = write_archive_with_dictionary(
            &[RegularFile::new(
                "dict-sidecar.txt",
                b"common words common words sidecar payload",
            )],
            &master_key(),
            single_stream_options(),
            dictionary(),
        )
        .unwrap();
        let opened = open_non_seekable_archive(
            &archive.bytes,
            &master_key(),
            Some(&archive.bootstrap_sidecar),
        )
        .unwrap();

        assert_eq!(
            opened.extract_file("dict-sidecar.txt").unwrap(),
            Some(b"common words common words sidecar payload".to_vec())
        );
        opened.verify().unwrap();
    }

    #[test]
    fn non_seekable_full_sidecar_bootstraps_when_terminal_trailer_is_corrupt() {
        let archive = write_archive(
            &[RegularFile::new(
                "sidecar-terminal.txt",
                b"sidecar authority",
            )],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let mut corrupted = archive.bytes.clone();
        corrupt_v41_terminal_recovery(&mut corrupted);
        assert!(open_archive(&corrupted, &master_key()).is_err());

        let opened =
            open_non_seekable_archive(&corrupted, &master_key(), Some(&archive.bootstrap_sidecar))
                .unwrap();

        assert!(opened.volume_trailer.is_none());
        assert_eq!(
            opened.extract_file("sidecar-terminal.txt").unwrap(),
            Some(b"sidecar authority".to_vec())
        );
        opened.verify().unwrap();
    }

    #[test]
    fn dictionary_full_sidecar_bootstraps_when_terminal_material_is_absent() {
        let archive = write_archive_with_dictionary(
            &[RegularFile::new(
                "dict-no-terminal.txt",
                b"common words common words without terminal",
            )],
            &master_key(),
            single_stream_options(),
            dictionary(),
        )
        .unwrap();
        let terminal_offset = terminal_material_offset(&archive.bytes);
        let truncated = archive.bytes[..terminal_offset].to_vec();
        assert!(open_archive(&truncated, &master_key()).is_err());

        let opened =
            open_non_seekable_archive(&truncated, &master_key(), Some(&archive.bootstrap_sidecar))
                .unwrap();

        assert!(opened.volume_trailer.is_none());
        assert_eq!(
            opened.extract_file("dict-no-terminal.txt").unwrap(),
            Some(b"common words common words without terminal".to_vec())
        );
        opened.verify().unwrap();
    }

    #[test]
    fn bootstrap_sidecar_treats_crc_failed_payload_block_as_erasure() {
        let archive = write_archive(
            &[RegularFile::new(
                "sidecar-erasure.txt",
                b"repair through sidecar",
            )],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let mut corrupted = archive.bytes.clone();
        corrupt_first_block_record_payload(&mut corrupted);

        let opened = open_archive_with_bootstrap_sidecar(
            &corrupted,
            &archive.bootstrap_sidecar,
            &master_key(),
        )
        .unwrap();
        assert_eq!(
            opened.extract_file("sidecar-erasure.txt").unwrap(),
            Some(b"repair through sidecar".to_vec())
        );
    }

    #[test]
    fn extraction_rejects_logical_payload_above_total_size_cap() {
        let archive = write_archive(
            &[RegularFile::new("cap.txt", b"payload")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let options = ReaderOptions {
            max_total_extraction_size: 3,
            ..ReaderOptions::default()
        };
        let opened =
            OpenedArchive::open_with_options(&archive.bytes, &master_key(), options).unwrap();

        assert_eq!(
            opened.extract_file("cap.txt").unwrap_err(),
            FormatError::ReaderUnsupported("total extraction size exceeds configured cap")
        );
    }

    #[test]
    fn verify_does_not_apply_extraction_payload_cap() {
        let archive = write_archive(
            &[RegularFile::new("verify-cap.txt", b"payload")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let options = ReaderOptions {
            max_total_extraction_size: 3,
            ..ReaderOptions::default()
        };
        let opened =
            OpenedArchive::open_with_options(&archive.bytes, &master_key(), options).unwrap();

        opened.verify().unwrap();
        assert_eq!(
            opened.extract_file("verify-cap.txt").unwrap_err(),
            FormatError::ReaderUnsupported("total extraction size exceeds configured cap")
        );
    }

    #[test]
    fn verify_streams_past_legacy_in_memory_tar_cap() {
        let data = vec![0x5a; 4096];
        let archive = write_archive(
            &[RegularFile::new("verify-large.txt", &data)],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let options = ReaderOptions {
            max_verify_tar_size: 1,
            ..ReaderOptions::default()
        };
        let opened =
            OpenedArchive::open_with_options(&archive.bytes, &master_key(), options).unwrap();

        opened.verify().unwrap();
    }

    #[test]
    fn dictionary_sidecar_requires_dictionary_record_section() {
        let archive = write_archive_with_dictionary(
            &[RegularFile::new("dict-missing.txt", b"common words")],
            &master_key(),
            single_stream_options(),
            dictionary(),
        )
        .unwrap();
        let header = BootstrapSidecarHeader::parse(
            &archive.bootstrap_sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN],
        )
        .unwrap();
        let mut missing_dictionary =
            archive.bootstrap_sidecar[..header.dictionary_records_offset as usize].to_vec();
        rewrite_sidecar_header(&mut missing_dictionary, &master_key(), |header| {
            header.flags &= !0x04;
            header.dictionary_records_offset = 0;
            header.dictionary_records_length = 0;
        });

        assert_eq!(
            open_non_seekable_archive(&archive.bytes, &master_key(), Some(&missing_dictionary))
                .unwrap_err(),
            FormatError::ReaderUnsupported("dictionary bootstrap required")
        );
    }

    #[test]
    fn dictionary_sidecar_records_are_validated_against_dictionary_extent() {
        let archive = write_archive_with_dictionary(
            &[RegularFile::new("dict-sidecar-kind.txt", b"common words")],
            &master_key(),
            single_stream_options(),
            dictionary(),
        )
        .unwrap();

        let mut wrong_kind = archive.bootstrap_sidecar.clone();
        mutate_sidecar_dictionary_record(&mut wrong_kind, 0, |record| {
            record.kind = BlockKind::IndexRootData;
        });
        assert_eq!(
            open_archive_with_bootstrap_sidecar(&archive.bytes, &wrong_kind, &master_key())
                .unwrap_err(),
            FormatError::InvalidArchive("sidecar BlockRecord section has wrong kind")
        );

        let mut wrong_last = archive.bootstrap_sidecar.clone();
        mutate_sidecar_dictionary_record(&mut wrong_last, 0, |record| {
            record.flags = 0;
        });
        assert_eq!(
            open_archive_with_bootstrap_sidecar(&archive.bytes, &wrong_last, &master_key())
                .unwrap_err(),
            FormatError::InvalidArchive("sidecar BlockRecord section has wrong last-data flag")
        );
    }

    #[test]
    fn non_seekable_random_access_requires_sidecar() {
        let archive = write_archive(
            &[RegularFile::new("file.txt", b"payload")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();

        assert_eq!(
            open_non_seekable_archive(&archive.bytes, &master_key(), None).unwrap_err(),
            FormatError::ReaderUnsupported(
                "non-seekable random access requires a bootstrap sidecar"
            )
        );
        assert!(open_non_seekable_archive(
            &archive.bytes,
            &master_key(),
            Some(&archive.bootstrap_sidecar)
        )
        .is_ok());
    }

    #[test]
    fn non_seekable_bootstrap_rejects_index_root_only_sidecar() {
        let archive = write_archive(
            &[RegularFile::new("sparse.txt", b"sparse sidecar")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let index_root_only = sparse_bootstrap_sidecar(
            &archive.bootstrap_sidecar,
            &master_key(),
            false,
            true,
            false,
        );

        assert_eq!(
            open_non_seekable_archive(&archive.bytes, &master_key(), Some(&index_root_only))
                .unwrap_err(),
            FormatError::ReaderUnsupported(
                "non-seekable bootstrap sidecar requires ManifestFooter and IndexRoot sections"
            )
        );
    }

    #[test]
    fn seekable_sidecar_uses_index_root_records_after_terminal_manifest_authority() {
        let archive = write_archive(
            &[RegularFile::new("sparse-index.txt", b"recover index root")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        let mut corrupted = archive.bytes.clone();
        corrupt_object_extent_records(
            &mut corrupted,
            index_root_extent_from_manifest(&opened.manifest_footer),
        );
        assert!(open_archive(&corrupted, &master_key()).is_err());

        let index_root_only = sparse_bootstrap_sidecar(
            &archive.bootstrap_sidecar,
            &master_key(),
            false,
            true,
            false,
        );
        let recovered =
            open_archive_with_bootstrap_sidecar(&corrupted, &index_root_only, &master_key())
                .unwrap();

        assert_eq!(
            recovered.extract_file("sparse-index.txt").unwrap(),
            Some(b"recover index root".to_vec())
        );
        recovered.verify().unwrap();
    }

    #[test]
    fn seekable_sidecar_uses_dictionary_records_after_index_root_authority() {
        let archive = write_archive_with_dictionary(
            &[RegularFile::new(
                "sparse-dict.txt",
                b"common words common words sparse dictionary",
            )],
            &master_key(),
            single_stream_options(),
            dictionary(),
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        let mut corrupted = archive.bytes.clone();
        corrupt_object_extent_records(
            &mut corrupted,
            dictionary_extent_from_index_root(&opened.index_root).unwrap(),
        );
        assert!(open_archive(&corrupted, &master_key()).is_err());

        let dictionary_only = sparse_bootstrap_sidecar(
            &archive.bootstrap_sidecar,
            &master_key(),
            false,
            false,
            true,
        );
        assert_eq!(
            open_non_seekable_archive(&archive.bytes, &master_key(), Some(&dictionary_only))
                .unwrap_err(),
            FormatError::ReaderUnsupported(
                "non-seekable bootstrap sidecar requires ManifestFooter and IndexRoot sections"
            )
        );

        let recovered =
            open_archive_with_bootstrap_sidecar(&corrupted, &dictionary_only, &master_key())
                .unwrap();
        assert_eq!(
            recovered.extract_file("sparse-dict.txt").unwrap(),
            Some(b"common words common words sparse dictionary".to_vec())
        );
        recovered.verify().unwrap();
    }

    #[test]
    fn sequential_extracts_dictionary_free_tar_stream() {
        let archive = write_archive(
            &[RegularFile::new("seq.txt", b"streaming")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();

        let tar_stream = sequential_extract_tar_stream(&archive.bytes, &master_key()).unwrap();
        let member = parse_tar_member_group(&tar_stream, 4096).unwrap();
        assert_eq!(member.path, b"seq.txt");
        assert_eq!(member.data, b"streaming");
    }

    #[test]
    fn sequential_rejects_logical_payload_above_total_size_cap() {
        let archive = write_archive(
            &[RegularFile::new("seq-cap.txt", b"payload")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let options = ReaderOptions {
            max_total_extraction_size: 3,
            ..ReaderOptions::default()
        };

        assert_eq!(
            sequential_extract_tar_stream_with_options(&archive.bytes, &master_key(), options)
                .unwrap_err(),
            FormatError::ReaderUnsupported("total extraction size exceeds configured cap")
        );
    }

    #[test]
    fn sequential_rejects_tar_stream_above_buffer_cap_during_decode() {
        let archive = write_archive(
            &[RegularFile::new("seq-buffer-cap.txt", b"payload")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let options = ReaderOptions {
            max_verify_tar_size: 512,
            ..ReaderOptions::default()
        };

        assert_eq!(
            sequential_extract_tar_stream_with_options(&archive.bytes, &master_key(), options)
                .unwrap_err(),
            FormatError::ReaderUnsupported(
                "sequential tar stream exceeds configured verification cap"
            )
        );
    }

    #[test]
    fn sequential_repairs_crc_failed_payload_data_when_parity_is_guaranteed() {
        let archive = write_archive(
            &[RegularFile::new("seq-erasure.txt", b"stream repair")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let mut corrupted = archive.bytes;
        corrupt_first_block_record_payload(&mut corrupted);

        let tar_stream = sequential_extract_tar_stream(&corrupted, &master_key()).unwrap();
        let member = parse_tar_member_group(&tar_stream, 4096).unwrap();
        assert_eq!(member.path, b"seq-erasure.txt");
        assert_eq!(member.data, b"stream repair");
    }

    #[test]
    fn sequential_rejects_crc_failed_payload_data_without_guaranteed_parity() {
        let archive = write_archive(
            &[RegularFile::new("seq-no-parity.txt", b"no repair")],
            &master_key(),
            WriterOptions {
                bit_rot_buffer_pct: 0,
                fec_parity_shards: 0,
                index_fec_parity_shards: 0,
                index_root_fec_parity_shards: 0,
                ..single_stream_options()
            },
        )
        .unwrap();
        let mut corrupted = archive.bytes;
        corrupt_first_block_record_payload(&mut corrupted);

        assert_eq!(
            sequential_extract_tar_stream(&corrupted, &master_key()).unwrap_err(),
            FormatError::BadCrc {
                structure: "BlockRecord"
            }
        );
    }

    #[test]
    fn sequential_rejects_when_terminal_authentication_fails_without_returning_bytes() {
        let archive = write_archive(
            &[RegularFile::new(
                "seq.txt",
                b"payload must not be returned after terminal auth failure",
            )],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let mut corrupted = archive.bytes;
        corrupt_v41_terminal_recovery(&mut corrupted);

        match sequential_extract_tar_stream(&corrupted, &master_key()) {
            Ok(bytes) => panic!(
                "sequential helper returned {} decoded byte(s) despite terminal HMAC failure",
                bytes.len()
            ),
            Err(err) => assert_eq!(
                err,
                FormatError::InvalidArchive("no valid v41 CMRA candidate found")
            ),
        }
    }

    #[test]
    fn sequential_rejects_dictionary_archive_without_bootstrap_before_payload_release() {
        let archive = write_archive_with_dictionary(
            &[RegularFile::new(
                "seq-dict.txt",
                b"common words common words dictionary payload",
            )],
            &master_key(),
            single_stream_options(),
            b"common words dictionary",
        )
        .unwrap();

        match sequential_extract_tar_stream(&archive.bytes, &master_key()) {
            Ok(bytes) => panic!(
                "sequential helper returned {} decoded byte(s) for dictionary archive without bootstrap",
                bytes.len()
            ),
            Err(err) => assert_eq!(
                err,
                FormatError::ReaderUnsupported(
                    "dictionary bootstrap required for non-seekable sequential extraction"
                )
            ),
        }
    }

    #[test]
    fn non_seekable_dictionary_error_keeps_missing_bootstrap_wording() {
        let archive = write_archive_with_dictionary(
            &[RegularFile::new(
                "seq-dict-open.txt",
                b"common words common words bootstrap required",
            )],
            &master_key(),
            single_stream_options(),
            b"common words bootstrap",
        )
        .unwrap();

        assert_eq!(
            open_non_seekable_archive(&archive.bytes, &master_key(), None).unwrap_err(),
            FormatError::ReaderUnsupported(
                "non-seekable random access requires a bootstrap sidecar"
            )
        );
    }

    #[test]
    fn sequential_zstd_stream_rejects_skippable_frame_segments() {
        let skippable = [0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0];
        let mut output = Vec::new();

        assert_eq!(
            decode_concatenated_zstd_frames_with_cap(
                &skippable,
                None,
                &mut output,
                usize::MAX,
                None,
            )
            .unwrap_err(),
            FormatError::NotStandardZstdFrame
        );
        assert!(output.is_empty());
    }

    #[test]
    fn live_non_seekable_verify_stream_accepts_single_volume_archive() {
        let archive = write_archive(
            &[RegularFile::new("live.txt", b"stream verify")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();

        let report =
            verify_non_seekable_stream(std::io::Cursor::new(archive.bytes), &master_key()).unwrap();

        assert_eq!(report.file_count, 1);
        assert_eq!(report.total_volumes, 1);
        assert_eq!(report.root_auth, SequentialRootAuthStatus::Absent);
        assert!(report.payload_block_count > 0);
    }

    #[test]
    fn live_non_seekable_verify_stream_accepts_recipientwrap_archive() {
        let master = master_key();
        let archive = write_archive_with_recipient_wrap_records(
            &[RegularFile::new(
                "wrapped-live.txt",
                b"stream recipient verify",
            )],
            &master,
            single_stream_options(),
            vec![recipient_wrap_test_record()],
        )
        .unwrap();

        let mut called = false;
        let report = verify_non_seekable_stream_with_recipient_wrap_resolver_options(
            std::io::Cursor::new(archive.bytes),
            |context| {
                called = true;
                assert_eq!(
                    context.archive_identity.volume_format_rev,
                    VOLUME_FORMAT_REV_45
                );
                assert_eq!(context.record.profile_id, 1);
                Ok(vec![master.0])
            },
            NonSeekableReaderOptions::default(),
        )
        .unwrap();

        assert!(called);
        assert_eq!(report.file_count, 1);
        assert_eq!(report.total_volumes, 1);
        assert_eq!(report.root_auth, SequentialRootAuthStatus::Absent);
    }

    #[test]
    fn live_non_seekable_recipientwrap_resolver_rejects_unencrypted_archive() {
        let archive = write_archive_unencrypted(
            &[RegularFile::new("plain-live.txt", b"plaintext payload")],
            single_stream_options(),
        )
        .unwrap();

        let mut called = false;
        let err = verify_non_seekable_stream_with_recipient_wrap_resolver_options(
            std::io::Cursor::new(archive.bytes),
            |_| {
                called = true;
                Ok(vec![master_key().0])
            },
            NonSeekableReaderOptions::default(),
        )
        .unwrap_err();

        assert!(!called);
        assert_eq!(err, FormatError::KeyMaterialMismatch);
    }

    #[test]
    fn live_non_seekable_verify_stream_accepts_tiny_read_chunks() {
        let archive = write_archive(
            &[RegularFile::new("tiny-chunks.txt", b"one byte at a time")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();

        let report =
            verify_non_seekable_stream(ChunkedReader::new(archive.bytes, 1), &master_key())
                .unwrap();

        assert_eq!(report.file_count, 1);
        assert_eq!(report.tar_total_size % 512, 0);
    }

    #[test]
    fn live_non_seekable_verify_stream_accepts_empty_archive() {
        let archive = write_archive(&[], &master_key(), single_stream_options()).unwrap();

        let report =
            verify_non_seekable_stream(std::io::Cursor::new(archive.bytes), &master_key()).unwrap();

        assert_eq!(report.file_count, 0);
        assert_eq!(report.payload_block_count, 0);
        assert_eq!(report.tar_total_size, 0);
    }

    #[test]
    fn live_non_seekable_verify_rejects_dictionary_archive_without_bootstrap() {
        let archive = write_archive_with_dictionary(
            &[RegularFile::new(
                "live-dict.txt",
                b"common words common words dictionary payload",
            )],
            &master_key(),
            single_stream_options(),
            b"common words dictionary",
        )
        .unwrap();

        assert_eq!(
            verify_non_seekable_stream(std::io::Cursor::new(archive.bytes), &master_key())
                .unwrap_err(),
            FormatError::ReaderUnsupported(
                "dictionary bootstrap required for non-seekable sequential verification"
            )
        );
    }

    #[test]
    fn live_non_seekable_verify_accepts_dictionary_archive_with_bootstrap() {
        let archive = write_archive_with_dictionary(
            &[RegularFile::new(
                "live-dict-sidecar.txt",
                b"common words common words dictionary payload",
            )],
            &master_key(),
            single_stream_options(),
            b"common words dictionary",
        )
        .unwrap();

        let report = verify_non_seekable_stream_with_bootstrap_sidecar(
            std::io::Cursor::new(archive.bytes),
            &archive.bootstrap_sidecar,
            &master_key(),
            NonSeekableReaderOptions::default(),
        )
        .unwrap();

        assert_eq!(report.file_count, 1);
        assert_eq!(report.total_volumes, 1);
    }

    #[test]
    fn live_non_seekable_verify_rejects_terminal_tail_above_cap() {
        let archive = write_archive(
            &[RegularFile::new("tail-cap.txt", b"payload")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let options = NonSeekableReaderOptions {
            max_terminal_tail_size: 8,
            ..NonSeekableReaderOptions::default()
        };

        assert_eq!(
            verify_non_seekable_stream_with_options(
                std::io::Cursor::new(archive.bytes),
                &master_key(),
                options
            )
            .unwrap_err(),
            FormatError::ReaderUnsupported("terminal tail exceeds configured cap")
        );
    }

    #[test]
    fn live_non_seekable_verify_rejects_metadata_above_retention_cap() {
        let archive = write_archive(
            &[RegularFile::new("metadata-cap.txt", b"payload")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let options = NonSeekableReaderOptions {
            max_retained_metadata_bytes: 1,
            ..NonSeekableReaderOptions::default()
        };

        assert_eq!(
            verify_non_seekable_stream_with_options(
                std::io::Cursor::new(archive.bytes),
                &master_key(),
                options
            )
            .unwrap_err(),
            FormatError::ReaderUnsupported("retained metadata exceeds configured streaming cap")
        );
    }

    #[test]
    fn live_non_seekable_verify_repairs_crc_failed_metadata_block() {
        let archive = write_archive(
            &[RegularFile::new("metadata-erasure.txt", b"payload")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let mut corrupted = archive.bytes;
        let slot = first_block_record_slot_with_kind(&corrupted, BlockKind::IndexRootData).unwrap();
        corrupt_block_record_payload_at_slot(&mut corrupted, slot);

        let report =
            verify_non_seekable_stream(std::io::Cursor::new(corrupted), &master_key()).unwrap();

        assert_eq!(report.file_count, 1);
    }

    #[test]
    fn live_non_seekable_verify_rejects_member_count_above_cap() {
        let archive = write_archive(
            &[RegularFile::new("member-cap.txt", b"payload")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let options = NonSeekableReaderOptions {
            max_streamed_member_count: 0,
            ..NonSeekableReaderOptions::default()
        };

        assert_eq!(
            verify_non_seekable_stream_with_options(
                std::io::Cursor::new(archive.bytes),
                &master_key(),
                options
            )
            .unwrap_err(),
            FormatError::ReaderUnsupported("tar member count exceeds configured streaming cap")
        );
    }

    #[test]
    fn live_non_seekable_verify_rejects_total_extraction_cap_during_decode() {
        let archive = write_archive(
            &[RegularFile::new("live-total-cap.txt", b"payload")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let mut options = NonSeekableReaderOptions::default();
        options.reader.max_total_extraction_size = 3;

        assert_eq!(
            verify_non_seekable_stream_with_options(
                std::io::Cursor::new(archive.bytes),
                &master_key(),
                options
            )
            .unwrap_err(),
            FormatError::ReaderUnsupported("total extraction size exceeds configured cap")
        );
    }

    #[test]
    fn live_non_seekable_verify_reports_root_auth_wire_only() {
        let archive = write_archive_with_root_auth(
            &[RegularFile::new("signed-live.txt", b"root-auth stream")],
            &master_key(),
            single_stream_options(),
            test_root_auth_config(),
            |request| Ok(test_root_auth_value(request)),
        )
        .unwrap();

        let report =
            verify_non_seekable_stream(std::io::Cursor::new(archive.bytes), &master_key()).unwrap();

        assert_eq!(report.root_auth, SequentialRootAuthStatus::WireValidOnly);
    }

    #[test]
    fn live_non_seekable_extract_stream_commits_after_terminal_verify() {
        let archive = write_archive(
            &[
                RegularFile::new("alpha.txt", b"alpha"),
                RegularFile::new("nested/beta.txt", b"beta"),
            ],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("out");

        let report = extract_non_seekable_stream_to_dir(
            std::io::Cursor::new(archive.bytes),
            &master_key(),
            &out,
            NonSeekableReaderOptions::default(),
            SafeExtractionOptions::default(),
        )
        .unwrap();

        assert_eq!(report.verification.file_count, 2);
        assert_eq!(report.extracted_member_count, 2);
        assert_eq!(fs::read(out.join("alpha.txt")).unwrap(), b"alpha");
        assert_eq!(fs::read(out.join("nested/beta.txt")).unwrap(), b"beta");
    }

    #[test]
    fn live_non_seekable_extract_stream_accepts_tiny_read_chunks() {
        let archive = write_archive(
            &[RegularFile::new("tiny-extract.txt", b"chunked extraction")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("out");

        extract_non_seekable_stream_to_dir(
            ChunkedReader::new(archive.bytes, 1),
            &master_key(),
            &out,
            NonSeekableReaderOptions::default(),
            SafeExtractionOptions::default(),
        )
        .unwrap();

        assert_eq!(
            fs::read(out.join("tiny-extract.txt")).unwrap(),
            b"chunked extraction"
        );
    }

    #[test]
    fn live_non_seekable_extract_stream_terminal_failure_leaves_no_final_output() {
        let archive = write_archive(
            &[RegularFile::new("late-fail.txt", b"must remain staged")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let mut corrupted = archive.bytes;
        corrupt_v41_terminal_recovery(&mut corrupted);
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("out");

        match extract_non_seekable_stream_to_dir(
            std::io::Cursor::new(corrupted),
            &master_key(),
            &out,
            NonSeekableReaderOptions::default(),
            SafeExtractionOptions::default(),
        )
        .unwrap_err()
        {
            ExtractError::Format(err) => assert_eq!(
                err,
                FormatError::InvalidArchive("no valid v41 CMRA candidate found")
            ),
            ExtractError::Output(err) => panic!("unexpected output error: {err}"),
        }
        assert!(!out.exists());
    }

    #[test]
    fn live_non_seekable_extract_stream_existing_destination_obeys_overwrite_policy() {
        let archive = write_archive(
            &[RegularFile::new("same.txt", b"new")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("out");
        fs::create_dir(&out).unwrap();
        fs::write(out.join("same.txt"), b"old").unwrap();

        match extract_non_seekable_stream_to_dir(
            std::io::Cursor::new(archive.bytes.clone()),
            &master_key(),
            &out,
            NonSeekableReaderOptions::default(),
            SafeExtractionOptions::default(),
        )
        .unwrap_err()
        {
            ExtractError::Format(err) => assert_eq!(err, FormatError::UnsafeOverwrite),
            ExtractError::Output(err) => panic!("unexpected output error: {err}"),
        }
        assert_eq!(fs::read(out.join("same.txt")).unwrap(), b"old");

        extract_non_seekable_stream_to_dir(
            std::io::Cursor::new(archive.bytes),
            &master_key(),
            &out,
            NonSeekableReaderOptions::default(),
            SafeExtractionOptions {
                overwrite_existing: true,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();
        assert_eq!(fs::read(out.join("same.txt")).unwrap(), b"new");
    }

    #[test]
    fn live_non_seekable_list_stream_matches_seekable_final_view() {
        let archive = write_archive(
            &[
                RegularFile::new("a.txt", b"a"),
                RegularFile::new("b.txt", b"bb"),
            ],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let seekable = open_archive(&archive.bytes, &master_key()).unwrap();
        let expected = seekable.list_files().unwrap();

        let report = list_non_seekable_stream(
            std::io::Cursor::new(archive.bytes),
            &master_key(),
            NonSeekableReaderOptions::default(),
        )
        .unwrap();

        assert_eq!(report.verification.file_count, 2);
        assert_eq!(report.entries, expected);
    }

    #[test]
    fn bootstrap_sidecar_rejects_bad_flags_and_trailing_bytes() {
        let archive = write_archive(&[], &master_key(), single_stream_options()).unwrap();
        let mut bad_flags = archive.bootstrap_sidecar.clone();
        rewrite_sidecar_header(&mut bad_flags, &master_key(), |header| {
            header.flags |= 0x08;
        });
        assert_eq!(
            open_archive_with_bootstrap_sidecar(&archive.bytes, &bad_flags, &master_key())
                .unwrap_err(),
            FormatError::UnknownBootstrapSidecarFlags(0x0b)
        );

        let mut trailing = archive.bootstrap_sidecar.clone();
        trailing.push(0);
        assert_eq!(
            open_archive_with_bootstrap_sidecar(&archive.bytes, &trailing, &master_key())
                .unwrap_err(),
            FormatError::NonCanonicalBootstrapSidecarLayout
        );
    }

    #[test]
    fn bootstrap_sidecar_rejects_bad_manifest_footer_semantics() {
        let archive = write_archive(&[], &master_key(), single_stream_options()).unwrap();
        let mut wrong_volume = archive.bootstrap_sidecar.clone();
        mutate_sidecar_manifest(&mut wrong_volume, &master_key(), |footer| {
            footer.volume_index = 1;
        });
        assert_eq!(
            open_archive_with_bootstrap_sidecar(&archive.bytes, &wrong_volume, &master_key())
                .unwrap_err(),
            FormatError::InvalidArchive("sidecar ManifestFooter volume_index must be zero")
        );

        let mut non_authoritative = archive.bootstrap_sidecar.clone();
        mutate_sidecar_manifest(&mut non_authoritative, &master_key(), |footer| {
            footer.is_authoritative = 0;
        });
        assert_eq!(
            open_archive_with_bootstrap_sidecar(&archive.bytes, &non_authoritative, &master_key())
                .unwrap_err(),
            FormatError::InvalidArchive("sidecar ManifestFooter is not authoritative")
        );
    }

    #[test]
    fn sidecar_manifest_validation_does_not_compare_opened_volume_index() {
        let archive = write_archive(&[], &master_key(), single_stream_options()).unwrap();
        let volume_header = VolumeHeader::parse(&archive.bytes[..VOLUME_HEADER_LEN]).unwrap();
        let crypto_start = volume_header.crypto_header_offset as usize;
        let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
        let crypto_header = CryptoHeader::parse(
            &archive.bytes[crypto_start..crypto_end],
            volume_header.crypto_header_length,
        )
        .unwrap();
        let subkeys = Subkeys::derive(
            &master_key(),
            &volume_header.archive_uuid,
            &volume_header.session_id,
        )
        .unwrap();
        let mut opened_header = volume_header;
        opened_header.volume_index = 1;

        let parsed = parse_bootstrap_sidecar(
            &archive.bootstrap_sidecar,
            &opened_header,
            &crypto_header.fixed,
            &subkeys,
        )
        .unwrap();

        assert_eq!(parsed.manifest_footer.unwrap().volume_index, 0);
    }

    #[test]
    fn bootstrap_sidecar_rejects_conflicting_manifest_bootstrap_fields() {
        let archive = write_archive(&[], &master_key(), single_stream_options()).unwrap();
        let mut conflicting = archive.bootstrap_sidecar.clone();
        mutate_sidecar_manifest(&mut conflicting, &master_key(), |footer| {
            footer.index_root_first_block += 1;
        });

        assert_eq!(
            open_archive_with_bootstrap_sidecar(&archive.bytes, &conflicting, &master_key())
                .unwrap_err(),
            FormatError::InvalidArchive("bootstrap sidecar conflicts with terminal ManifestFooter")
        );
    }

    #[test]
    fn sidecar_size_cap_counts_only_present_sparse_sections() {
        let mut crypto_header = test_crypto_header();
        crypto_header.has_dictionary = 1;
        crypto_header.index_root_fec_data_shards = 1;
        crypto_header.index_root_fec_parity_shards = 0;
        let record_len = crypto_header.block_size as u64 + BLOCK_RECORD_FRAMING_LEN as u64;
        let header = BootstrapSidecarHeader {
            archive_uuid: [0x31; 16],
            session_id: [0x42; 16],
            flags: 0x04,
            manifest_footer_offset: 0,
            manifest_footer_length: 0,
            index_root_records_offset: 0,
            index_root_records_length: 0,
            dictionary_records_offset: BOOTSTRAP_SIDECAR_HEADER_LEN as u64,
            dictionary_records_length: record_len,
            sidecar_hmac: [0u8; 32],
            header_crc32c: 0,
        };

        validate_sidecar_size_cap(
            &header,
            &crypto_header,
            BOOTSTRAP_SIDECAR_HEADER_LEN as u64 + record_len,
        )
        .unwrap();
        assert_eq!(
            validate_sidecar_size_cap(
                &header,
                &crypto_header,
                BOOTSTRAP_SIDECAR_HEADER_LEN as u64 + record_len + 1,
            )
            .unwrap_err(),
            FormatError::InvalidArchive("bootstrap sidecar exceeds resource cap")
        );
    }

    #[test]
    fn sidecar_size_cap_rejects_sparse_section_above_class_max() {
        let mut crypto_header = test_crypto_header();
        crypto_header.index_root_fec_data_shards = 1;
        crypto_header.index_root_fec_parity_shards = 0;
        let record_len = crypto_header.block_size as u64 + BLOCK_RECORD_FRAMING_LEN as u64;
        let header = BootstrapSidecarHeader {
            archive_uuid: [0x31; 16],
            session_id: [0x42; 16],
            flags: 0x02,
            manifest_footer_offset: 0,
            manifest_footer_length: 0,
            index_root_records_offset: BOOTSTRAP_SIDECAR_HEADER_LEN as u64,
            index_root_records_length: record_len * 2,
            dictionary_records_offset: 0,
            dictionary_records_length: 0,
            sidecar_hmac: [0u8; 32],
            header_crc32c: 0,
        };

        assert_eq!(
            validate_sidecar_size_cap(
                &header,
                &crypto_header,
                BOOTSTRAP_SIDECAR_HEADER_LEN as u64 + record_len * 2,
            )
            .unwrap_err(),
            FormatError::InvalidArchive("bootstrap sidecar IndexRoot records exceed resource cap")
        );
    }

    #[test]
    fn sidecar_size_cap_uses_wide_arithmetic_for_large_record_classes() {
        let mut crypto_header = test_crypto_header();
        crypto_header.block_size = u32::MAX;
        crypto_header.index_root_fec_data_shards = u16::MAX;
        crypto_header.index_root_fec_parity_shards = u16::MAX;
        let record_len = crypto_header.block_size as u64 + BLOCK_RECORD_FRAMING_LEN as u64;
        let max_records = crypto_header.index_root_fec_data_shards as u64
            + crypto_header.index_root_fec_parity_shards as u64;
        let max_section_len = max_records * record_len;
        let cap = BOOTSTRAP_SIDECAR_HEADER_LEN as u64
            + MANIFEST_FOOTER_LEN as u64
            + max_section_len
            + max_section_len;
        let header = BootstrapSidecarHeader {
            archive_uuid: [0x31; 16],
            session_id: [0x42; 16],
            flags: 0x01 | 0x02 | 0x04,
            manifest_footer_offset: BOOTSTRAP_SIDECAR_HEADER_LEN as u64,
            manifest_footer_length: MANIFEST_FOOTER_LEN as u32,
            index_root_records_offset: 0,
            index_root_records_length: max_section_len,
            dictionary_records_offset: 0,
            dictionary_records_length: max_section_len,
            sidecar_hmac: [0u8; 32],
            header_crc32c: 0,
        };

        validate_sidecar_size_cap(&header, &crypto_header, cap).unwrap();
        assert_eq!(
            validate_sidecar_size_cap(&header, &crypto_header, cap + 1).unwrap_err(),
            FormatError::InvalidArchive("bootstrap sidecar exceeds resource cap")
        );
    }

    #[test]
    fn bootstrap_sidecar_rejects_dictionary_section_for_no_dictionary_archive() {
        let archive = write_archive(&[], &master_key(), single_stream_options()).unwrap();
        let mut with_dictionary = archive.bootstrap_sidecar.clone();
        let header =
            BootstrapSidecarHeader::parse(&with_dictionary[..BOOTSTRAP_SIDECAR_HEADER_LEN])
                .unwrap();
        let record_len = sidecar_record_len(&with_dictionary);
        let first_record = header.index_root_records_offset as usize;
        let copied_record = with_dictionary[first_record..first_record + record_len].to_vec();
        let dictionary_offset = with_dictionary.len() as u64;
        with_dictionary.extend_from_slice(&copied_record);
        rewrite_sidecar_header(&mut with_dictionary, &master_key(), |header| {
            header.flags |= 0x04;
            header.dictionary_records_offset = dictionary_offset;
            header.dictionary_records_length = record_len as u64;
        });

        assert_eq!(
            open_archive_with_bootstrap_sidecar(&archive.bytes, &with_dictionary, &master_key())
                .unwrap_err(),
            FormatError::InvalidArchive(
                "bootstrap sidecar has dictionary records while has_dictionary is false"
            )
        );
    }

    #[test]
    fn bootstrap_sidecar_rejects_missing_duplicate_wrong_kind_and_wrong_last_flag() {
        let archive = write_archive(&[], &master_key(), single_stream_options()).unwrap();
        let mut missing = archive.bootstrap_sidecar.clone();
        let record_len = sidecar_record_len(&missing);
        let new_len = missing.len() - record_len;
        missing.truncate(new_len);
        rewrite_sidecar_header(&mut missing, &master_key(), |header| {
            header.index_root_records_length -= record_len as u64;
        });
        assert_eq!(
            open_archive_with_bootstrap_sidecar(&archive.bytes, &missing, &master_key())
                .unwrap_err(),
            FormatError::InvalidArchive(
                "sidecar BlockRecord section does not match declared extent"
            )
        );

        let mut duplicate = archive.bootstrap_sidecar.clone();
        mutate_sidecar_index_record(&mut duplicate, 1, |record| {
            record.block_index -= 1;
        });
        assert_eq!(
            open_archive_with_bootstrap_sidecar(&archive.bytes, &duplicate, &master_key())
                .unwrap_err(),
            FormatError::InvalidArchive(
                "sidecar BlockRecord section has missing or duplicate blocks"
            )
        );

        let mut misordered = archive.bootstrap_sidecar.clone();
        swap_sidecar_index_records(&mut misordered, 0, 1);
        assert_eq!(
            open_archive_with_bootstrap_sidecar(&archive.bytes, &misordered, &master_key())
                .unwrap_err(),
            FormatError::InvalidArchive(
                "sidecar BlockRecord section has missing or duplicate blocks"
            )
        );

        let mut wrong_kind = archive.bootstrap_sidecar.clone();
        mutate_sidecar_index_record(&mut wrong_kind, 0, |record| {
            record.kind = BlockKind::PayloadData;
        });
        assert_eq!(
            open_archive_with_bootstrap_sidecar(&archive.bytes, &wrong_kind, &master_key())
                .unwrap_err(),
            FormatError::InvalidArchive("sidecar BlockRecord section has wrong kind")
        );

        let mut wrong_last = archive.bootstrap_sidecar.clone();
        mutate_sidecar_index_record(&mut wrong_last, 0, |record| {
            record.flags = 0;
        });
        assert_eq!(
            open_archive_with_bootstrap_sidecar(&archive.bytes, &wrong_last, &master_key())
                .unwrap_err(),
            FormatError::InvalidArchive("sidecar BlockRecord section has wrong last-data flag")
        );
    }

    #[test]
    fn verify_helper_rejects_envelope_frame_coverage_gap() {
        let frames = BTreeMap::from([(
            0,
            FrameEntry {
                frame_index: 0,
                envelope_index: 0,
                offset_in_envelope: 0,
                compressed_size: 10,
                decompressed_size: 512,
                flags: 0,
                tar_stream_offset: 0,
            },
        )]);
        let envelopes = BTreeMap::from([(
            0,
            EnvelopeEntry {
                envelope_index: 0,
                first_block_index: 0,
                data_block_count: 1,
                parity_block_count: 1,
                encrypted_size: 4096,
                plaintext_size: 11,
                first_frame_index: 0,
                frame_count: 1,
            },
        )]);

        assert_eq!(
            validate_envelope_frame_coverage(&frames, &envelopes).unwrap_err(),
            FormatError::InvalidArchive("EnvelopeEntry frame coverage has a gap or overlap")
        );
    }

    #[test]
    fn verify_helper_rejects_file_extent_gaps_and_overlaps() {
        assert!(validate_file_extent_coverage_ranges(&[(512, 512), (0, 512)], 1024).is_ok());
        assert_eq!(
            validate_file_extent_coverage_ranges(&[(0, 512), (1024, 512)], 1536).unwrap_err(),
            FormatError::InvalidArchive("FileEntry extents do not cover tar stream exactly")
        );
        assert_eq!(
            validate_file_extent_coverage_ranges(&[(0, 1024), (512, 512)], 1024).unwrap_err(),
            FormatError::InvalidArchive("FileEntry extents do not cover tar stream exactly")
        );
    }

    #[test]
    fn verify_rejects_authenticated_content_hash_mismatch() {
        let options = WriterOptions {
            index_root_fec_parity_shards: 0,
            ..single_stream_options()
        };
        let archive = write_archive(
            &[RegularFile::new("content-hash.txt", b"hash covered")],
            &master_key(),
            options,
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();

        let mut root = opened.index_root.clone();
        root.header.content_sha256 = [0xa5; 32];
        let root_plaintext = root.to_bytes();
        IndexRoot::parse(
            &root_plaintext,
            false,
            metadata_limits(&opened.crypto_header),
        )
        .unwrap();
        assert_eq!(
            root_plaintext.len() as u32,
            opened.manifest_footer.index_root_decompressed_size
        );

        let compressed_root = compress_zstd_frame(&root_plaintext, options.zstd_level).unwrap();
        let mut next_block_index = opened.manifest_footer.index_root_first_block;
        let replacement = encrypt_test_object(
            &compressed_root,
            &opened.subkeys.index_root_key,
            &opened.subkeys.index_nonce_seed,
            b"idxroot",
            0,
            BlockKind::IndexRootData,
            &mut next_block_index,
            &opened.crypto_header,
            &opened.volume_header,
        );
        assert_eq!(
            replacement.extent.data_block_count,
            opened.manifest_footer.index_root_data_block_count
        );
        assert_eq!(
            replacement.extent.encrypted_size,
            opened.manifest_footer.index_root_encrypted_size
        );

        let volume_header = VolumeHeader::parse(&archive.bytes[..VOLUME_HEADER_LEN]).unwrap();
        let crypto_end = volume_header.crypto_header_offset as usize
            + volume_header.crypto_header_length as usize;
        let record_len = opened.crypto_header.block_size as usize + BLOCK_RECORD_FRAMING_LEN;
        let mut malformed = archive.bytes.clone();
        for record in replacement.records {
            let offset = crypto_end + record.block_index as usize * record_len;
            malformed[offset..offset + record_len].copy_from_slice(&record.to_bytes());
        }

        let reopened = open_archive(&malformed, &master_key()).unwrap();
        assert_eq!(
            reopened.verify().unwrap_err(),
            FormatError::InvalidArchive(
                "IndexRoot content_sha256 does not match decoded tar stream"
            )
        );
    }

    #[test]
    fn verify_rejects_file_entry_tar_path_and_size_mismatches() {
        let (mut path_mismatch, _) = multi_envelope_reader_fixture();
        rewrite_as_single_healthy_file(&mut path_mismatch, |_file, path| {
            path[0] = b'x';
        });
        assert_eq!(
            path_mismatch.verify().unwrap_err(),
            FormatError::InvalidArchive("tar member path does not match FileEntry path")
        );

        let (mut size_mismatch, _) = multi_envelope_reader_fixture();
        rewrite_as_single_healthy_file(&mut size_mismatch, |file, _path| {
            file.file_data_size += 1;
        });
        assert_eq!(
            size_mismatch.verify().unwrap_err(),
            FormatError::InvalidArchive("tar member size does not match FileEntry file_data_size")
        );
    }

    #[test]
    fn verify_rejects_inconsistent_duplicate_local_frame_rows_across_shards() {
        let (mut opened, _) = multi_envelope_reader_fixture();
        let locating = opened.index_root.shards[0].clone();
        let mut duplicate = opened.load_index_shard(&locating).unwrap();
        duplicate.header.shard_index = 1;
        duplicate.frames[0].flags ^= 0x0000_0001;
        let duplicate_plaintext = duplicate.to_bytes();
        let mut next_block_index = opened
            .blocks
            .keys()
            .last()
            .copied()
            .map(|index| index + 1)
            .unwrap_or(0);
        let duplicate_object = encrypt_test_object(
            &compress_zstd_frame(&duplicate_plaintext, 1).unwrap(),
            &opened.subkeys.index_shard_key,
            &opened.subkeys.index_nonce_seed,
            b"idxshard",
            1,
            BlockKind::IndexShardData,
            &mut next_block_index,
            &opened.crypto_header,
            &opened.volume_header,
        );
        insert_records(&mut opened.blocks, &duplicate_object.records);
        opened.index_root.shards.push(ShardEntry {
            shard_index: 1,
            first_block_index: duplicate_object.extent.first_block_index,
            data_block_count: duplicate_object.extent.data_block_count,
            parity_block_count: 0,
            encrypted_size: duplicate_object.extent.encrypted_size,
            decompressed_size: duplicate_plaintext.len() as u32,
            file_count: locating.file_count,
            first_path_hash: locating.first_path_hash,
            last_path_hash: locating.last_path_hash,
        });
        opened.index_root.header.file_count += locating.file_count as u64;

        assert_eq!(
            opened.verify().unwrap_err(),
            FormatError::InvalidArchive("duplicate FrameEntry rows do not match")
        );
    }

    #[test]
    fn verify_rejects_inconsistent_duplicate_local_envelope_rows_across_shards() {
        let (mut opened, _) = multi_envelope_reader_fixture();
        let locating = opened.index_root.shards[0].clone();
        let mut duplicate = opened.load_index_shard(&locating).unwrap();
        duplicate.header.shard_index = 1;
        duplicate.envelopes[0].first_block_index += 1;
        let duplicate_plaintext = duplicate.to_bytes();
        let mut next_block_index = opened
            .blocks
            .keys()
            .last()
            .copied()
            .map(|index| index + 1)
            .unwrap_or(0);
        let duplicate_object = encrypt_test_object(
            &compress_zstd_frame(&duplicate_plaintext, 1).unwrap(),
            &opened.subkeys.index_shard_key,
            &opened.subkeys.index_nonce_seed,
            b"idxshard",
            1,
            BlockKind::IndexShardData,
            &mut next_block_index,
            &opened.crypto_header,
            &opened.volume_header,
        );
        insert_records(&mut opened.blocks, &duplicate_object.records);
        opened.index_root.shards.push(ShardEntry {
            shard_index: 1,
            first_block_index: duplicate_object.extent.first_block_index,
            data_block_count: duplicate_object.extent.data_block_count,
            parity_block_count: 0,
            encrypted_size: duplicate_object.extent.encrypted_size,
            decompressed_size: duplicate_plaintext.len() as u32,
            file_count: locating.file_count,
            first_path_hash: locating.first_path_hash,
            last_path_hash: locating.last_path_hash,
        });
        opened.index_root.header.file_count += locating.file_count as u64;

        assert_eq!(
            opened.verify().unwrap_err(),
            FormatError::InvalidArchive("duplicate EnvelopeEntry rows do not match")
        );
    }

    #[test]
    fn verify_rejects_non_contiguous_global_envelope_indexes() {
        let (mut opened, _) = multi_envelope_reader_fixture();
        replace_first_index_shard(&mut opened, |shard| {
            let frame = shard
                .frames
                .iter_mut()
                .find(|entry| entry.frame_index == 1)
                .unwrap();
            frame.envelope_index = 2;

            let envelope = shard
                .envelopes
                .iter_mut()
                .find(|entry| entry.envelope_index == 1)
                .unwrap();
            envelope.envelope_index = 2;
        });

        assert_eq!(
            opened.verify().unwrap_err(),
            FormatError::InvalidMetadata {
                structure: "EnvelopeEntry",
                reason: "global index coverage has a gap",
            }
        );
    }

    #[test]
    fn verify_rejects_payload_object_extent_overlap() {
        let (mut opened, _) = multi_envelope_reader_fixture();
        replace_first_index_shard(&mut opened, |shard| {
            let first_block_index = shard.envelopes[0].first_block_index;
            shard.envelopes[1].first_block_index = first_block_index;
        });

        assert_eq!(
            opened.verify().unwrap_err(),
            FormatError::InvalidArchive("encrypted object block ranges overlap")
        );
    }

    #[test]
    fn verify_accepts_cross_shard_shared_envelope_frame_union() {
        let volume_header = test_volume_header();
        let crypto_header = test_crypto_header();
        let subkeys = Subkeys::derive(
            &master_key(),
            &volume_header.archive_uuid,
            &volume_header.session_id,
        )
        .unwrap();
        let mut next_block_index = 0u64;
        let mut blocks = BTreeMap::new();

        let alpha = test_member(b"alpha.txt", b"alpha cross shard\n");
        let beta = test_member(b"beta.txt", b"beta cross shard\n");
        let tar_stream = [alpha.as_slice(), beta.as_slice()].concat();
        let frame0_plaintext = compress_zstd_frame(&alpha, 1).unwrap();
        let frame1_plaintext = compress_zstd_frame(&beta, 1).unwrap();
        let envelope_plaintext =
            [frame0_plaintext.as_slice(), frame1_plaintext.as_slice()].concat();
        let payload = encrypt_test_object(
            &envelope_plaintext,
            &subkeys.enc_key,
            &subkeys.nonce_seed,
            b"envelope",
            0,
            BlockKind::PayloadData,
            &mut next_block_index,
            &crypto_header,
            &volume_header,
        );
        insert_records(&mut blocks, &payload.records);

        let envelope = EnvelopeEntry {
            envelope_index: 0,
            first_block_index: payload.extent.first_block_index,
            data_block_count: payload.extent.data_block_count,
            parity_block_count: 0,
            encrypted_size: payload.extent.encrypted_size,
            plaintext_size: envelope_plaintext.len() as u32,
            first_frame_index: 0,
            frame_count: 2,
        };
        let frame0 = FrameEntry {
            frame_index: 0,
            envelope_index: 0,
            offset_in_envelope: 0,
            compressed_size: frame0_plaintext.len() as u32,
            decompressed_size: alpha.len() as u32,
            flags: 0x0000_0003,
            tar_stream_offset: 0,
        };
        let frame1 = FrameEntry {
            frame_index: 1,
            envelope_index: 0,
            offset_in_envelope: frame0_plaintext.len() as u32,
            compressed_size: frame1_plaintext.len() as u32,
            decompressed_size: beta.len() as u32,
            flags: 0x0000_0003,
            tar_stream_offset: alpha.len() as u64,
        };

        let (shard0_plaintext, first0, last0) = build_test_index_shard(
            &[TestFileMeta {
                path: b"alpha.txt".to_vec(),
                frame_index: 0,
                tar_stream_offset: 0,
                member_group_size: alpha.len() as u64,
                file_data_size: b"alpha cross shard\n".len() as u64,
            }],
            &[frame0],
            std::slice::from_ref(&envelope),
        );
        let (mut shard1_plaintext, first1, last1) = build_test_index_shard(
            &[TestFileMeta {
                path: b"beta.txt".to_vec(),
                frame_index: 1,
                tar_stream_offset: alpha.len() as u64,
                member_group_size: beta.len() as u64,
                file_data_size: b"beta cross shard\n".len() as u64,
            }],
            &[frame1],
            std::slice::from_ref(&envelope),
        );
        shard1_plaintext[8..16].copy_from_slice(&1u64.to_le_bytes());

        let shard0 = encrypt_test_object(
            &compress_zstd_frame(&shard0_plaintext, 1).unwrap(),
            &subkeys.index_shard_key,
            &subkeys.index_nonce_seed,
            b"idxshard",
            0,
            BlockKind::IndexShardData,
            &mut next_block_index,
            &crypto_header,
            &volume_header,
        );
        let shard1 = encrypt_test_object(
            &compress_zstd_frame(&shard1_plaintext, 1).unwrap(),
            &subkeys.index_shard_key,
            &subkeys.index_nonce_seed,
            b"idxshard",
            1,
            BlockKind::IndexShardData,
            &mut next_block_index,
            &crypto_header,
            &volume_header,
        );
        insert_records(&mut blocks, &shard0.records);
        insert_records(&mut blocks, &shard1.records);

        let index_root = IndexRoot {
            header: IndexRootHeader {
                frame_count: 2,
                envelope_count: 1,
                file_count: 2,
                payload_block_count: payload.extent.data_block_count as u64,
                tar_total_size: tar_stream.len() as u64,
                content_sha256: sha256_bytes(&tar_stream),
                ..IndexRootHeader::empty()
            },
            shards: vec![
                ShardEntry {
                    shard_index: 0,
                    first_block_index: shard0.extent.first_block_index,
                    data_block_count: shard0.extent.data_block_count,
                    parity_block_count: 0,
                    encrypted_size: shard0.extent.encrypted_size,
                    decompressed_size: shard0_plaintext.len() as u32,
                    file_count: 1,
                    first_path_hash: first0,
                    last_path_hash: last0,
                },
                ShardEntry {
                    shard_index: 1,
                    first_block_index: shard1.extent.first_block_index,
                    data_block_count: shard1.extent.data_block_count,
                    parity_block_count: 0,
                    encrypted_size: shard1.extent.encrypted_size,
                    decompressed_size: shard1_plaintext.len() as u32,
                    file_count: 1,
                    first_path_hash: first1,
                    last_path_hash: last1,
                },
            ],
            directory_hint_shards: Vec::new(),
        };

        let index_root_plaintext = index_root.to_bytes();
        let index_root_object = encrypt_test_object(
            &compress_zstd_frame(&index_root_plaintext, 1).unwrap(),
            &subkeys.index_root_key,
            &subkeys.index_nonce_seed,
            b"idxroot",
            0,
            BlockKind::IndexRootData,
            &mut next_block_index,
            &crypto_header,
            &volume_header,
        );
        insert_records(&mut blocks, &index_root_object.records);

        let archive_uuid = volume_header.archive_uuid;
        let session_id = volume_header.session_id;
        let opened = OpenedArchive {
            options: ReaderOptions::default(),
            observed_archive_bytes: 1_000_000,
            observed_volume_count: 1,
            subkeys,
            blocks,
            lazy_blocks: None,
            crypto_header_bytes: Vec::new(),
            volume_header,
            crypto_header,
            manifest_footer: ManifestFooter {
                archive_uuid,
                session_id,
                volume_index: 0,
                is_authoritative: 1,
                total_volumes: 1,
                index_root_first_block: index_root_object.extent.first_block_index,
                index_root_data_block_count: index_root_object.extent.data_block_count,
                index_root_parity_block_count: 0,
                index_root_encrypted_size: index_root_object.extent.encrypted_size,
                index_root_decompressed_size: index_root_plaintext.len() as u32,
                manifest_hmac: [0u8; 32],
            },
            volume_trailer: Some(VolumeTrailer {
                archive_uuid,
                session_id,
                volume_index: 0,
                block_count: next_block_index,
                bytes_written: 0,
                manifest_footer_offset: 0,
                manifest_footer_length: MANIFEST_FOOTER_LEN as u32,
                closed_at_ns: 0,
                root_auth_footer_offset: 0,
                root_auth_footer_length: 0,
                root_auth_flags: 0,
                trailer_hmac: [0u8; 32],
            }),
            root_auth_footer: None,
            index_root,
            payload_dictionary: None,
        };

        opened.verify().unwrap();
    }

    #[test]
    fn verify_rejects_authenticated_archive_missing_required_directory_hints() {
        let options = WriterOptions {
            index_root_fec_parity_shards: 0,
            ..single_stream_options()
        };
        let archive = write_archive(
            &[RegularFile::new("only.txt", b"only payload")],
            &master_key(),
            options,
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        assert!(opened.index_root.directory_hint_shards.is_empty());

        let mut root = opened.index_root.clone();
        root.header.file_count = DIRECTORY_HINT_REQUIRED_FILE_COUNT + 1;
        root.shards[0].file_count = (DIRECTORY_HINT_REQUIRED_FILE_COUNT + 1) as u32;
        let root_plaintext = root.to_bytes();
        IndexRoot::parse(
            &root_plaintext,
            false,
            metadata_limits(&opened.crypto_header),
        )
        .unwrap();
        assert_eq!(
            root_plaintext.len() as u32,
            opened.manifest_footer.index_root_decompressed_size
        );

        let compressed_root = compress_zstd_frame(&root_plaintext, options.zstd_level).unwrap();
        let mut next_block_index = opened.manifest_footer.index_root_first_block;
        let replacement = encrypt_test_object(
            &compressed_root,
            &opened.subkeys.index_root_key,
            &opened.subkeys.index_nonce_seed,
            b"idxroot",
            0,
            BlockKind::IndexRootData,
            &mut next_block_index,
            &opened.crypto_header,
            &opened.volume_header,
        );
        assert_eq!(
            replacement.extent.first_block_index,
            opened.manifest_footer.index_root_first_block
        );
        assert_eq!(
            replacement.extent.data_block_count,
            opened.manifest_footer.index_root_data_block_count
        );
        assert_eq!(
            replacement.extent.encrypted_size,
            opened.manifest_footer.index_root_encrypted_size
        );

        let volume_header = VolumeHeader::parse(&archive.bytes[..VOLUME_HEADER_LEN]).unwrap();
        let crypto_end = volume_header.crypto_header_offset as usize
            + volume_header.crypto_header_length as usize;
        let record_len = opened.crypto_header.block_size as usize + BLOCK_RECORD_FRAMING_LEN;
        let mut malformed = archive.bytes.clone();
        for record in replacement.records {
            let offset = crypto_end + record.block_index as usize * record_len;
            malformed[offset..offset + record_len].copy_from_slice(&record.to_bytes());
        }

        let reopened = open_archive(&malformed, &master_key()).unwrap();
        assert_eq!(
            reopened.index_root.header.file_count,
            DIRECTORY_HINT_REQUIRED_FILE_COUNT + 1
        );
        assert!(reopened.index_root.directory_hint_shards.is_empty());

        assert_eq!(
            reopened.verify().unwrap_err(),
            FormatError::InvalidArchive("IndexRoot file_count requires directory hints")
        );
    }

    #[test]
    fn expected_directory_hint_rows_include_ancestors_and_directory_entries() {
        let mut map = DirectoryHintMap::new();
        add_expected_directory_hint_rows(&mut map, 2, b"foo/bar/baz.txt", TarEntryKind::Regular);
        add_expected_directory_hint_rows(&mut map, 4, b"foo/bar", TarEntryKind::Directory);

        assert_eq!(map.get(&Vec::new()), Some(&BTreeSet::from([2, 4])));
        assert_eq!(map.get(b"foo".as_slice()), Some(&BTreeSet::from([2, 4])));
        assert_eq!(
            map.get(b"foo/bar".as_slice()),
            Some(&BTreeSet::from([2, 4]))
        );
        assert!(!map.contains_key(b"foo/bar/baz.txt".as_slice()));
        assert!(!map.contains_key(b"foobar".as_slice()));
    }

    #[test]
    fn directory_hint_validation_requires_exact_global_map() {
        let mut expected = DirectoryHintMap::new();
        add_expected_directory_hint_rows(&mut expected, 0, b"foo/bar.txt", TarEntryKind::Regular);
        add_expected_directory_hint_rows(&mut expected, 1, b"foo", TarEntryKind::Directory);
        let rows = sorted_directory_hint_rows(&expected);
        let table = directory_hint_table_from_rows(7, &rows, 2);

        validate_directory_hint_tables_against_expected(std::slice::from_ref(&table), &expected)
            .unwrap();

        let mut missing_root = expected.clone();
        missing_root.remove(&Vec::new());
        let missing_root_rows = sorted_directory_hint_rows(&missing_root);
        let missing_root_table = directory_hint_table_from_rows(8, &missing_root_rows, 2);
        assert_eq!(
            validate_directory_hint_tables_against_expected(&[missing_root_table], &expected)
                .unwrap_err(),
            FormatError::InvalidArchive("directory hint map does not match decoded files")
        );

        let mut expected_missing_directory_entry = expected.clone();
        expected_missing_directory_entry
            .get_mut(b"foo".as_slice())
            .unwrap()
            .remove(&1);
        assert_eq!(
            validate_directory_hint_tables_against_expected(
                std::slice::from_ref(&table),
                &expected_missing_directory_entry,
            )
            .unwrap_err(),
            FormatError::InvalidArchive("directory hint map does not match decoded files")
        );

        let mut extra = expected.clone();
        extra.insert(b"foo/extra".to_vec(), BTreeSet::from([0]));
        let extra_rows = sorted_directory_hint_rows(&extra);
        let extra_table = directory_hint_table_from_rows(9, &extra_rows, 2);
        assert_eq!(
            validate_directory_hint_tables_against_expected(&[extra_table], &expected).unwrap_err(),
            FormatError::InvalidArchive("directory hint map does not match decoded files")
        );
    }

    #[test]
    fn directory_hint_validation_rejects_global_order_mismatch() {
        let mut expected = DirectoryHintMap::new();
        expected.insert(Vec::new(), BTreeSet::from([0]));
        expected.insert(b"alpha".to_vec(), BTreeSet::from([0]));
        let rows = sorted_directory_hint_rows(&expected);
        let first = directory_hint_table_from_rows(8, &rows[..1], 1);
        let second = directory_hint_table_from_rows(9, &rows[1..], 1);

        assert_eq!(
            validate_directory_hint_tables_against_expected(&[second, first], &expected)
                .unwrap_err(),
            FormatError::InvalidArchive("DirectoryHintEntry rows are not globally sorted")
        );
    }

    #[test]
    fn object_extent_rejects_parity_above_class_cap() {
        let crypto_header = CryptoHeaderFixed {
            length: 0,
            compression_algo: CompressionAlgo::ZstdFramed,
            aead_algo: AeadAlgo::AesGcmSiv256,
            fec_algo: FecAlgo::ReedSolomonGF16,
            kdf_algo: KdfAlgo::Raw,
            chunk_size: 1024,
            envelope_target_size: 4096,
            block_size: 4096,
            fec_data_shards: 1,
            fec_parity_shards: 1,
            index_fec_data_shards: 1,
            index_fec_parity_shards: 1,
            index_root_fec_data_shards: 1,
            index_root_fec_parity_shards: 1,
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            has_dictionary: 0,
            max_path_length: 4096,
            expected_volume_size: 0,
        };
        let extent = ObjectExtent {
            first_block_index: 0,
            data_block_count: 1,
            parity_block_count: 2,
            encrypted_size: 4096,
        };

        assert_eq!(
            validate_object_extent(extent, &crypto_header, 1, 1).unwrap_err(),
            FormatError::InvalidArchive("encrypted object exceeds its class parity-shard maximum")
        );
    }

    #[test]
    fn object_extent_rejects_parity_below_recoverability_requirement() {
        let crypto_header = CryptoHeaderFixed {
            length: 0,
            compression_algo: CompressionAlgo::ZstdFramed,
            aead_algo: AeadAlgo::AesGcmSiv256,
            fec_algo: FecAlgo::ReedSolomonGF16,
            kdf_algo: KdfAlgo::Raw,
            chunk_size: 1024,
            envelope_target_size: 4096,
            block_size: 4096,
            fec_data_shards: 1,
            fec_parity_shards: 1,
            index_fec_data_shards: 1,
            index_fec_parity_shards: 1,
            index_root_fec_data_shards: 1,
            index_root_fec_parity_shards: 1,
            stripe_width: 2,
            volume_loss_tolerance: 1,
            bit_rot_buffer_pct: 0,
            has_dictionary: 0,
            max_path_length: 4096,
            expected_volume_size: 0,
        };
        let extent = ObjectExtent {
            first_block_index: 0,
            data_block_count: 1,
            parity_block_count: 0,
            encrypted_size: 4096,
        };

        assert_eq!(
            validate_object_extent(extent, &crypto_header, 1, 1).unwrap_err(),
            FormatError::InvalidArchive(
                "encrypted object parity does not match v41 compute_parity"
            )
        );
    }

    #[test]
    fn encrypted_object_extent_matrix_rejects_overlaps() {
        let (opened, _) = multi_envelope_reader_fixture();
        let loaded_shard = opened
            .load_index_shard(&opened.index_root.shards[0])
            .unwrap();
        let base_envelopes = loaded_shard
            .envelopes
            .iter()
            .map(|entry| (entry.envelope_index, entry.clone()))
            .collect::<BTreeMap<_, _>>();
        let payload_start = loaded_shard.envelopes[0].first_block_index;
        let overlap = FormatError::InvalidArchive("encrypted object block ranges overlap");

        let mut payload_overlap = base_envelopes.clone();
        payload_overlap
            .get_mut(&loaded_shard.envelopes[1].envelope_index)
            .unwrap()
            .first_block_index = payload_start;
        assert_eq!(
            opened
                .validate_encrypted_object_block_ranges(&payload_overlap)
                .unwrap_err(),
            overlap
        );

        let mut shard_overlap = opened.clone();
        let shard = shard_overlap.index_root.shards[0].clone();
        shard_overlap.index_root.shards.push(ShardEntry {
            shard_index: 1,
            ..shard
        });
        assert_eq!(
            shard_overlap
                .validate_encrypted_object_block_ranges(&base_envelopes)
                .unwrap_err(),
            overlap
        );

        let mut dictionary_overlap = opened.clone();
        dictionary_overlap.crypto_header.has_dictionary = 1;
        dictionary_overlap.index_root.header.dictionary_first_block = payload_start;
        dictionary_overlap
            .index_root
            .header
            .dictionary_data_block_count = 1;
        dictionary_overlap
            .index_root
            .header
            .dictionary_parity_block_count = 0;
        dictionary_overlap
            .index_root
            .header
            .dictionary_encrypted_size = 4096;
        dictionary_overlap
            .index_root
            .header
            .dictionary_decompressed_size = 128;
        assert_eq!(
            dictionary_overlap
                .validate_encrypted_object_block_ranges(&base_envelopes)
                .unwrap_err(),
            overlap
        );

        let mut hint_overlap = opened.clone();
        hint_overlap
            .index_root
            .directory_hint_shards
            .push(DirectoryHintShardEntry {
                hint_shard_index: 0,
                first_dir_hash: [0; 8],
                last_dir_hash: [0; 8],
                first_block_index: payload_start,
                data_block_count: 1,
                parity_block_count: 0,
                encrypted_size: 4096,
                decompressed_size: 128,
                entry_count: 1,
            });
        assert_eq!(
            hint_overlap
                .validate_encrypted_object_block_ranges(&base_envelopes)
                .unwrap_err(),
            overlap
        );
    }

    #[test]
    fn load_metadata_object_rejects_per_object_zstd_frame_exactness_mutations() {
        let volume_header = test_volume_header();
        let crypto_header = test_crypto_header();
        let subkeys = Subkeys::derive(
            &master_key(),
            &volume_header.archive_uuid,
            &volume_header.session_id,
        )
        .unwrap();
        let mut next_block_index = 0u64;

        let index_root_payload = b"index root metadata object";
        let index_root_compressed = compress_zstd_frame(index_root_payload, 1).unwrap();
        assert_metadata_object_from_compressed(
            &{
                let mut bytes = index_root_compressed.clone();
                bytes.push(0);
                bytes
            },
            index_root_payload.len(),
            &subkeys,
            &volume_header,
            &crypto_header,
            &subkeys.index_root_key,
            &subkeys.index_nonce_seed,
            b"idxroot",
            0,
            BlockKind::IndexRootData,
            BlockKind::IndexRootParity,
            crypto_header.index_root_fec_data_shards,
            crypto_header.index_root_fec_parity_shards,
            &mut next_block_index,
            FormatError::TrailingBytesAfterZstdFrame,
        );
        assert_metadata_object_from_compressed(
            &index_root_compressed,
            index_root_payload.len() + 1,
            &subkeys,
            &volume_header,
            &crypto_header,
            &subkeys.index_root_key,
            &subkeys.index_nonce_seed,
            b"idxroot",
            0,
            BlockKind::IndexRootData,
            BlockKind::IndexRootParity,
            crypto_header.index_root_fec_data_shards,
            crypto_header.index_root_fec_parity_shards,
            &mut next_block_index,
            FormatError::ZstdDecompressedSizeMismatch {
                expected: index_root_payload.len() + 1,
                actual: index_root_payload.len(),
            },
        );

        let index_shard_payload = b"index shard metadata object";
        let index_shard_compressed = compress_zstd_frame(index_shard_payload, 1).unwrap();
        assert_metadata_object_from_compressed(
            &{
                let mut bytes = index_shard_compressed.clone();
                bytes.push(0);
                bytes
            },
            index_shard_payload.len(),
            &subkeys,
            &volume_header,
            &crypto_header,
            &subkeys.index_shard_key,
            &subkeys.index_nonce_seed,
            b"idxshard",
            1,
            BlockKind::IndexShardData,
            BlockKind::IndexShardParity,
            crypto_header.index_fec_data_shards,
            crypto_header.index_fec_parity_shards,
            &mut next_block_index,
            FormatError::TrailingBytesAfterZstdFrame,
        );
        assert_metadata_object_from_compressed(
            &index_shard_compressed,
            index_shard_payload.len() + 1,
            &subkeys,
            &volume_header,
            &crypto_header,
            &subkeys.index_shard_key,
            &subkeys.index_nonce_seed,
            b"idxshard",
            1,
            BlockKind::IndexShardData,
            BlockKind::IndexShardParity,
            crypto_header.index_fec_data_shards,
            crypto_header.index_fec_parity_shards,
            &mut next_block_index,
            FormatError::ZstdDecompressedSizeMismatch {
                expected: index_shard_payload.len() + 1,
                actual: index_shard_payload.len(),
            },
        );

        let directory_hint_payload = b"directory hint metadata object";
        let directory_hint_compressed = compress_zstd_frame(directory_hint_payload, 1).unwrap();
        assert_metadata_object_from_compressed(
            &{
                let mut bytes = directory_hint_compressed.clone();
                bytes.push(0);
                bytes
            },
            directory_hint_payload.len(),
            &subkeys,
            &volume_header,
            &crypto_header,
            &subkeys.dir_hint_key,
            &subkeys.index_nonce_seed,
            b"dirhint",
            0,
            BlockKind::DirectoryHintData,
            BlockKind::DirectoryHintParity,
            crypto_header.index_fec_data_shards,
            crypto_header.index_fec_parity_shards,
            &mut next_block_index,
            FormatError::TrailingBytesAfterZstdFrame,
        );
        assert_metadata_object_from_compressed(
            &directory_hint_compressed,
            directory_hint_payload.len() + 1,
            &subkeys,
            &volume_header,
            &crypto_header,
            &subkeys.dir_hint_key,
            &subkeys.index_nonce_seed,
            b"dirhint",
            0,
            BlockKind::DirectoryHintData,
            BlockKind::DirectoryHintParity,
            crypto_header.index_fec_data_shards,
            crypto_header.index_fec_parity_shards,
            &mut next_block_index,
            FormatError::ZstdDecompressedSizeMismatch {
                expected: directory_hint_payload.len() + 1,
                actual: directory_hint_payload.len(),
            },
        );

        let dictionary_payload = b"dictionary metadata object";
        let dictionary_compressed = compress_zstd_frame(dictionary_payload, 1).unwrap();
        assert_metadata_object_from_compressed(
            &{
                let mut bytes = dictionary_compressed.clone();
                bytes.push(0);
                bytes
            },
            dictionary_payload.len(),
            &subkeys,
            &volume_header,
            &crypto_header,
            &subkeys.dictionary_key,
            &subkeys.index_nonce_seed,
            b"dict",
            0,
            BlockKind::DictionaryData,
            BlockKind::DictionaryParity,
            crypto_header.index_root_fec_data_shards,
            crypto_header.index_root_fec_parity_shards,
            &mut next_block_index,
            FormatError::TrailingBytesAfterZstdFrame,
        );
        assert_metadata_object_from_compressed(
            &dictionary_compressed,
            dictionary_payload.len() + 1,
            &subkeys,
            &volume_header,
            &crypto_header,
            &subkeys.dictionary_key,
            &subkeys.index_nonce_seed,
            b"dict",
            0,
            BlockKind::DictionaryData,
            BlockKind::DictionaryParity,
            crypto_header.index_root_fec_data_shards,
            crypto_header.index_root_fec_parity_shards,
            &mut next_block_index,
            FormatError::ZstdDecompressedSizeMismatch {
                expected: dictionary_payload.len() + 1,
                actual: dictionary_payload.len(),
            },
        );
    }

    #[test]
    fn load_metadata_object_extent_rejects_encrypted_size_not_data_block_count_times_block_size() {
        let volume_header = test_volume_header();
        let crypto_header = test_crypto_header();
        let subkeys = Subkeys::derive(
            &master_key(),
            &volume_header.archive_uuid,
            &volume_header.session_id,
        )
        .unwrap();
        let mut next_block_index = 0u64;

        let index_root_payload = b"index root metadata object";
        let (index_root_extent, index_root_records) = build_metadata_object_from_payload(
            index_root_payload,
            &subkeys,
            &volume_header,
            &crypto_header,
            &subkeys.index_root_key,
            &subkeys.index_nonce_seed,
            b"idxroot",
            0,
            BlockKind::IndexRootData,
            &mut next_block_index,
        );
        let mut index_root_extent = index_root_extent;
        index_root_extent.encrypted_size = index_root_extent
            .encrypted_size
            .saturating_add(crypto_header.block_size);
        assert_eq!(
            load_metadata_object_from_parts(
                &index_root_records,
                ObjectLoadContext::index_root(
                    &volume_header,
                    &crypto_header,
                    &subkeys,
                    index_root_extent,
                ),
                index_root_payload.len() as u32,
            )
            .unwrap_err(),
            FormatError::InvalidArchive(
                "encrypted object size is not data_block_count * block_size"
            )
        );

        let index_shard_payload = b"index shard metadata object";
        let (index_shard_extent, index_shard_records) = build_metadata_object_from_payload(
            index_shard_payload,
            &subkeys,
            &volume_header,
            &crypto_header,
            &subkeys.index_shard_key,
            &subkeys.index_nonce_seed,
            b"idxshard",
            1,
            BlockKind::IndexShardData,
            &mut next_block_index,
        );
        let mut index_shard_extent = index_shard_extent;
        index_shard_extent.encrypted_size = index_shard_extent
            .encrypted_size
            .saturating_add(crypto_header.block_size);
        assert_eq!(
            load_metadata_object_from_parts(
                &index_shard_records,
                ObjectLoadContext {
                    volume_header: &volume_header,
                    crypto_header: &crypto_header,
                    extent: index_shard_extent,
                    data_kind: BlockKind::IndexShardData,
                    parity_kind: BlockKind::IndexShardParity,
                    key: &subkeys.index_shard_key,
                    nonce_seed: &subkeys.index_nonce_seed,
                    domain: b"idxshard",
                    counter: 1,
                    class_data_shard_max: crypto_header.index_fec_data_shards,
                    class_parity_shard_max: crypto_header.index_fec_parity_shards,
                },
                index_shard_payload.len() as u32,
            )
            .unwrap_err(),
            FormatError::InvalidArchive(
                "encrypted object size is not data_block_count * block_size"
            )
        );

        let directory_hint_payload = b"directory hint metadata object";
        let (directory_hint_extent, directory_hint_records) = build_metadata_object_from_payload(
            directory_hint_payload,
            &subkeys,
            &volume_header,
            &crypto_header,
            &subkeys.dir_hint_key,
            &subkeys.index_nonce_seed,
            b"dirhint",
            0,
            BlockKind::DirectoryHintData,
            &mut next_block_index,
        );
        let mut directory_hint_extent = directory_hint_extent;
        directory_hint_extent.encrypted_size = directory_hint_extent
            .encrypted_size
            .saturating_add(crypto_header.block_size);
        assert_eq!(
            load_metadata_object_from_parts(
                &directory_hint_records,
                ObjectLoadContext {
                    volume_header: &volume_header,
                    crypto_header: &crypto_header,
                    extent: directory_hint_extent,
                    data_kind: BlockKind::DirectoryHintData,
                    parity_kind: BlockKind::DirectoryHintParity,
                    key: &subkeys.dir_hint_key,
                    nonce_seed: &subkeys.index_nonce_seed,
                    domain: b"dirhint",
                    counter: 0,
                    class_data_shard_max: crypto_header.index_fec_data_shards,
                    class_parity_shard_max: crypto_header.index_fec_parity_shards,
                },
                directory_hint_payload.len() as u32,
            )
            .unwrap_err(),
            FormatError::InvalidArchive(
                "encrypted object size is not data_block_count * block_size"
            )
        );

        let dictionary_payload = b"dictionary metadata object";
        let (dictionary_extent, dictionary_records) = build_metadata_object_from_payload(
            dictionary_payload,
            &subkeys,
            &volume_header,
            &crypto_header,
            &subkeys.dictionary_key,
            &subkeys.index_nonce_seed,
            b"dict",
            0,
            BlockKind::DictionaryData,
            &mut next_block_index,
        );
        let mut dictionary_extent = dictionary_extent;
        dictionary_extent.encrypted_size = dictionary_extent
            .encrypted_size
            .saturating_add(crypto_header.block_size);
        assert_eq!(
            load_metadata_object_from_parts(
                &dictionary_records,
                ObjectLoadContext {
                    volume_header: &volume_header,
                    crypto_header: &crypto_header,
                    extent: dictionary_extent,
                    data_kind: BlockKind::DictionaryData,
                    parity_kind: BlockKind::DictionaryParity,
                    key: &subkeys.dictionary_key,
                    nonce_seed: &subkeys.index_nonce_seed,
                    domain: b"dict",
                    counter: 0,
                    class_data_shard_max: crypto_header.index_root_fec_data_shards,
                    class_parity_shard_max: crypto_header.index_root_fec_parity_shards,
                },
                dictionary_payload.len() as u32,
            )
            .unwrap_err(),
            FormatError::InvalidArchive(
                "encrypted object size is not data_block_count * block_size"
            )
        );
    }

    #[test]
    fn opens_complete_multi_volume_archive() {
        let files = [RegularFile::new("alpha.txt", b"hello from volume stripes")];
        let archive = write_archive(
            &files,
            &master_key(),
            WriterOptions {
                stripe_width: 2,
                volume_loss_tolerance: 1,
                ..single_stream_options()
            },
        )
        .unwrap();
        assert_eq!(archive.volumes.len(), 2);

        let volume_refs = archive
            .volumes
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        let opened = open_archive_volumes(&volume_refs, &master_key()).unwrap();

        assert_eq!(opened.volume_header.stripe_width, 2);
        assert_eq!(opened.list_files().unwrap()[0].path, "alpha.txt");
        assert_eq!(
            opened.extract_file("alpha.txt").unwrap(),
            Some(b"hello from volume stripes".to_vec())
        );
        opened.verify().unwrap();
    }

    #[test]
    fn recovers_from_one_missing_volume_when_parity_allows() {
        let files = [RegularFile::new("alpha.txt", b"recover me")];
        let archive = write_archive(
            &files,
            &master_key(),
            WriterOptions {
                stripe_width: 2,
                volume_loss_tolerance: 1,
                ..single_stream_options()
            },
        )
        .unwrap();

        let recovered =
            open_archive_volumes(&[archive.volumes[1].as_slice()], &master_key()).unwrap();
        assert_eq!(
            recovered.extract_file("alpha.txt").unwrap(),
            Some(b"recover me".to_vec())
        );
        recovered.verify().unwrap();
    }

    #[test]
    fn recovers_from_crc_corrupted_block_when_parity_allows() {
        let files = [RegularFile::new("alpha.txt", b"repair corrupt block")];
        let archive = write_archive(
            &files,
            &master_key(),
            WriterOptions {
                stripe_width: 2,
                volume_loss_tolerance: 1,
                ..single_stream_options()
            },
        )
        .unwrap();
        let mut volumes = archive.volumes.clone();
        corrupt_first_block_record_payload(&mut volumes[0]);

        let volume_refs = volumes.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let recovered = open_archive_volumes(&volume_refs, &master_key()).unwrap();

        assert_eq!(
            recovered.extract_file("alpha.txt").unwrap(),
            Some(b"repair corrupt block".to_vec())
        );
        recovered.verify().unwrap();
    }

    #[test]
    fn rejects_multi_volume_count_mismatch_without_tolerance() {
        let files = [RegularFile::new("alpha.txt", b"count check")];
        let archive = write_archive(
            &files,
            &master_key(),
            WriterOptions {
                stripe_width: 3,
                volume_loss_tolerance: 0,
                ..single_stream_options()
            },
        )
        .unwrap();

        assert_eq!(
            open_archive_volumes(&[archive.volumes[0].as_slice()], &master_key()).unwrap_err(),
            FormatError::InvalidArchive("missing volume count exceeds volume_loss_tolerance")
        );
    }

    #[test]
    fn rejects_multi_volume_manifest_bootstrap_field_mismatch() {
        let files = [RegularFile::new("alpha.txt", b"footer mismatch")];
        let archive = write_archive(
            &files,
            &master_key(),
            WriterOptions {
                stripe_width: 2,
                volume_loss_tolerance: 1,
                ..single_stream_options()
            },
        )
        .unwrap();

        let mut bad_first = archive.volumes[0].clone();
        rewrite_manifest_footer(&mut bad_first, &master_key(), |footer| {
            footer.index_root_first_block = footer.index_root_first_block.wrapping_add(1);
        });

        open_archive_volumes(
            &[bad_first.as_slice(), archive.volumes[1].as_slice()],
            &master_key(),
        )
        .unwrap();
    }

    #[test]
    fn repairs_corrupted_index_root_block_in_multi_volume_archive() {
        let files = [RegularFile::new("alpha.txt", b"repair meta root")];
        let archive = write_archive(
            &files,
            &master_key(),
            WriterOptions {
                stripe_width: 2,
                volume_loss_tolerance: 1,
                ..single_stream_options()
            },
        )
        .unwrap();
        let mut volumes = archive.volumes.clone();

        let mut corrupted = false;
        for volume in &mut volumes {
            if let Some(slot) =
                block_record_slots_with_kind(volume, BlockKind::IndexRootData).first()
            {
                corrupt_block_record_payload_at_slot(volume, *slot);
                corrupted = true;
                break;
            }
        }
        assert!(corrupted, "expected an IndexRootData record");

        let volume_refs = volumes.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let opened = open_archive_volumes(&volume_refs, &master_key()).unwrap();
        assert_eq!(
            opened.extract_file("alpha.txt").unwrap(),
            Some(b"repair meta root".to_vec())
        );
        opened.verify().unwrap();
    }

    #[test]
    fn repairs_corrupted_index_shard_block_in_multi_volume_archive() {
        let files = [RegularFile::new("alpha.txt", b"repair meta shard")];
        let archive = write_archive(
            &files,
            &master_key(),
            WriterOptions {
                stripe_width: 2,
                volume_loss_tolerance: 1,
                ..single_stream_options()
            },
        )
        .unwrap();
        let mut volumes = archive.volumes.clone();

        let mut corrupted = false;
        for volume in &mut volumes {
            if let Some(slot) =
                block_record_slots_with_kind(volume, BlockKind::IndexShardData).first()
            {
                corrupt_block_record_payload_at_slot(volume, *slot);
                corrupted = true;
                break;
            }
        }
        assert!(corrupted, "expected an IndexShardData record");

        let volume_refs = volumes.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let opened = open_archive_volumes(&volume_refs, &master_key()).unwrap();
        assert_eq!(
            opened.extract_file("alpha.txt").unwrap(),
            Some(b"repair meta shard".to_vec())
        );
        opened.verify().unwrap();
    }

    #[test]
    fn rejects_missing_volume_when_loss_tolerance_zero_even_with_bitrot_parity() {
        let files = [RegularFile::new(
            "alpha.txt",
            b"bitrot parity is not volume loss",
        )];
        let archive = write_archive(
            &files,
            &master_key(),
            WriterOptions {
                stripe_width: 2,
                volume_loss_tolerance: 0,
                bit_rot_buffer_pct: 1,
                ..single_stream_options()
            },
        )
        .unwrap();

        assert_eq!(
            open_archive_volumes(&[archive.volumes[1].as_slice()], &master_key()).unwrap_err(),
            FormatError::InvalidArchive("missing volume count exceeds volume_loss_tolerance")
        );
    }

    #[test]
    fn repairs_crc_erasure_only_within_parity_budget() {
        let payload = pseudo_random_bytes(12_000);
        let archive = write_archive(
            &[RegularFile::new("rot.bin", &payload)],
            &master_key(),
            small_block_recovery_options(),
        )
        .unwrap();
        let payload_slots = first_payload_data_run_slots(&archive.bytes);
        assert!(
            payload_slots.len() >= 2,
            "fixture must contain a multi-block payload object"
        );

        let mut one_erasure = archive.bytes.clone();
        corrupt_block_record_payload_at_slot(&mut one_erasure, payload_slots[0]);
        let repaired = open_archive(&one_erasure, &master_key()).unwrap();
        assert_eq!(
            repaired.extract_file("rot.bin").unwrap(),
            Some(payload.clone())
        );

        let mut two_erasures = archive.bytes.clone();
        corrupt_block_record_payload_at_slot(&mut two_erasures, payload_slots[0]);
        corrupt_block_record_payload_at_slot(&mut two_erasures, payload_slots[1]);
        let unrepaired = open_archive(&two_erasures, &master_key()).unwrap();
        assert_eq!(
            unrepaired.extract_file("rot.bin").unwrap_err(),
            FormatError::FecTooFewAvailableShards
        );
    }

    #[test]
    fn verify_rejects_missing_required_object_block_extent() {
        let (mut opened, missing_block) = multi_envelope_reader_fixture();
        assert!(opened.blocks.remove(&missing_block).is_some());

        assert_eq!(
            opened.verify().unwrap_err(),
            FormatError::FecTooFewAvailableShards
        );
    }

    #[test]
    fn parity_crc_erasure_does_not_hide_authenticated_data() {
        let payload = pseudo_random_bytes(12_000);
        let archive = write_archive(
            &[RegularFile::new("parity-erasure.bin", &payload)],
            &master_key(),
            parity_rich_recovery_options(),
        )
        .unwrap();
        let payload_slot = first_payload_data_run_slots(&archive.bytes)[0];
        let parity_slots = block_record_slots_with_kind(&archive.bytes, BlockKind::PayloadParity);
        assert!(
            parity_slots.len() >= 2,
            "fixture must contain redundant parity shards"
        );
        let mut corrupted = archive.bytes;
        corrupt_block_record_payload_at_slot(&mut corrupted, payload_slot);
        corrupt_block_record_payload_at_slot(&mut corrupted, parity_slots[0]);

        let opened = open_archive(&corrupted, &master_key()).unwrap();
        assert_eq!(
            opened.extract_file("parity-erasure.bin").unwrap(),
            Some(payload)
        );
        opened.verify().unwrap();
    }

    #[test]
    fn repair_patches_restore_crc_erased_payload_block() {
        let payload = pseudo_random_bytes(12_000);
        let archive = write_archive(
            &[RegularFile::new("rot.bin", &payload)],
            &master_key(),
            small_block_recovery_options(),
        )
        .unwrap();
        let payload_slot = first_payload_data_run_slots(&archive.bytes)[0];
        let mut corrupted = archive.bytes.clone();
        corrupt_block_record_payload_at_slot(&mut corrupted, payload_slot);

        let opened = open_seekable_archive(corrupted.clone(), &master_key()).unwrap();
        opened.verify().unwrap();
        let patches = opened.repair_patches().unwrap();
        assert_eq!(patches.len(), 1);
        apply_repair_patches(&mut corrupted, &patches);

        let repaired = open_seekable_archive(corrupted, &master_key()).unwrap();
        repaired.verify().unwrap();
        assert!(repaired.repair_patches().unwrap().is_empty());
    }

    #[test]
    fn repair_patches_restore_crc_erased_payload_parity_block() {
        let payload = pseudo_random_bytes(12_000);
        let archive = write_archive(
            &[RegularFile::new("parity-erasure.bin", &payload)],
            &master_key(),
            parity_rich_recovery_options(),
        )
        .unwrap();
        let parity_slot = block_record_slots_with_kind(&archive.bytes, BlockKind::PayloadParity)[0];
        let mut corrupted = archive.bytes.clone();
        corrupt_block_record_payload_at_slot(&mut corrupted, parity_slot);

        let opened = open_seekable_archive(corrupted.clone(), &master_key()).unwrap();
        opened.verify().unwrap();
        let patches = opened.repair_patches().unwrap();
        assert_eq!(patches.len(), 1);
        apply_repair_patches(&mut corrupted, &patches);

        let repaired = open_seekable_archive(corrupted, &master_key()).unwrap();
        repaired.verify().unwrap();
        assert!(repaired.repair_patches().unwrap().is_empty());
    }

    #[test]
    fn recovers_physical_odd_block_size_from_cmra_authority() {
        let archive = write_archive(
            &[RegularFile::new("odd-block.txt", b"payload")],
            &master_key(),
            small_block_recovery_options(),
        )
        .unwrap();
        let mut malformed = archive.bytes;
        let volume_header = VolumeHeader::parse(&malformed[..VOLUME_HEADER_LEN]).unwrap();
        let block_size_offset = volume_header.crypto_header_offset as usize + 24;
        malformed[block_size_offset..block_size_offset + 4].copy_from_slice(&4097u32.to_le_bytes());

        let opened = open_archive(&malformed, &master_key()).unwrap();
        assert_ne!(opened.crypto_header.block_size, 4097);
        assert_eq!(
            opened.extract_file("odd-block.txt").unwrap(),
            Some(b"payload".to_vec())
        );
        opened.verify().unwrap();
    }

    #[test]
    fn repairs_structurally_malformed_payload_block_slots() {
        let payload = pseudo_random_bytes(12_000);
        let archive = write_archive(
            &[RegularFile::new("structural-block.bin", &payload)],
            &master_key(),
            small_block_recovery_options(),
        )
        .unwrap();
        let payload_slot = first_payload_data_run_slots(&archive.bytes)[0];

        let mut bad_magic = archive.bytes.clone();
        corrupt_block_record_magic_at_slot(&mut bad_magic, payload_slot);
        assert_eq!(
            open_archive(&bad_magic, &master_key())
                .unwrap()
                .extract_file("structural-block.bin")
                .unwrap(),
            Some(payload.clone())
        );

        let mut bad_reserved = archive.bytes;
        corrupt_block_record_reserved_at_slot(&mut bad_reserved, payload_slot);
        assert_eq!(
            open_archive(&bad_reserved, &master_key())
                .unwrap()
                .extract_file("structural-block.bin")
                .unwrap(),
            Some(payload)
        );
    }

    #[test]
    fn repair_patches_restore_structurally_malformed_payload_block_slot() {
        let payload = pseudo_random_bytes(12_000);
        let archive = write_archive(
            &[RegularFile::new("structural-patch.bin", &payload)],
            &master_key(),
            small_block_recovery_options(),
        )
        .unwrap();
        let payload_slot = first_payload_data_run_slots(&archive.bytes)[0];
        let mut corrupted = archive.bytes.clone();
        corrupt_block_record_magic_at_slot(&mut corrupted, payload_slot);

        let opened = open_seekable_archive(corrupted.clone(), &master_key()).unwrap();
        opened.verify().unwrap();
        assert_eq!(
            opened.extract_file("structural-patch.bin").unwrap(),
            Some(payload)
        );
        let patches = opened.repair_patches().unwrap();
        assert_eq!(patches.len(), 1);
        apply_repair_patches(&mut corrupted, &patches);

        let repaired = open_seekable_archive(corrupted, &master_key()).unwrap();
        repaired.verify().unwrap();
        assert!(repaired.repair_patches().unwrap().is_empty());
    }

    #[test]
    fn repairs_structurally_malformed_index_root_block_slot() {
        let archive = write_archive(
            &[RegularFile::new(
                "structural-index-root.txt",
                b"metadata repair",
            )],
            &master_key(),
            small_block_recovery_options(),
        )
        .unwrap();
        let index_root_slot =
            first_block_record_slot_with_kind(&archive.bytes, BlockKind::IndexRootData).unwrap();
        let mut corrupted = archive.bytes;
        corrupt_block_record_magic_at_slot(&mut corrupted, index_root_slot);

        let opened = open_archive(&corrupted, &master_key()).unwrap();
        assert_eq!(
            opened.extract_file("structural-index-root.txt").unwrap(),
            Some(b"metadata repair".to_vec())
        );
        opened.verify().unwrap();
    }

    #[test]
    fn rejects_parity_block_with_last_data_flag() {
        let archive = write_archive(
            &[RegularFile::new("parity-flag.txt", b"payload")],
            &master_key(),
            small_block_recovery_options(),
        )
        .unwrap();
        let parity_slot =
            first_block_record_slot_with_kind(&archive.bytes, BlockKind::PayloadParity).unwrap();
        let mut malformed = archive.bytes;
        mutate_block_record_at_slot(&mut malformed, parity_slot, |record| {
            record.flags = 0x01;
        });

        assert_eq!(
            open_archive(&malformed, &master_key()).unwrap_err(),
            FormatError::ParityBlockHasLastDataFlag
        );
    }

    #[test]
    fn rejects_missing_and_duplicate_payload_last_data_flags() {
        let payload = pseudo_random_bytes(12_000);
        let archive = write_archive(
            &[RegularFile::new("flags.bin", &payload)],
            &master_key(),
            small_block_recovery_options(),
        )
        .unwrap();
        let payload_slots = first_payload_data_run_slots(&archive.bytes);
        assert!(
            payload_slots.len() >= 2,
            "fixture must contain a multi-block payload object"
        );

        let mut duplicate_last = archive.bytes.clone();
        mutate_block_record_at_slot(&mut duplicate_last, payload_slots[0], |record| {
            record.flags = 0x01;
        });
        let opened = open_archive(&duplicate_last, &master_key()).unwrap();
        assert_eq!(
            opened.extract_file("flags.bin").unwrap_err(),
            FormatError::InvalidArchive("object last-data flag is not on the final data block")
        );

        let mut missing_last = archive.bytes;
        mutate_block_record_at_slot(
            &mut missing_last,
            *payload_slots.last().unwrap(),
            |record| {
                record.flags = 0;
            },
        );
        let opened = open_archive(&missing_last, &master_key()).unwrap();
        assert_eq!(
            opened.extract_file("flags.bin").unwrap_err(),
            FormatError::InvalidArchive("object last-data flag is not on the final data block")
        );
    }

    #[test]
    fn recovers_from_one_corrupt_manifest_footer_copy_when_another_volume_authenticates() {
        let files = [RegularFile::new(
            "footer-copy.txt",
            b"survives one bad footer",
        )];
        let archive = write_archive(
            &files,
            &master_key(),
            WriterOptions {
                stripe_width: 2,
                volume_loss_tolerance: 1,
                ..single_stream_options()
            },
        )
        .unwrap();
        let mut volumes = archive.volumes.clone();
        corrupt_manifest_footer_hmac(&mut volumes[0]);

        let volume_refs = volumes.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let opened = open_archive_volumes(&volume_refs, &master_key()).unwrap();
        assert_eq!(opened.manifest_footer.volume_index, 0);
        assert_eq!(opened.volume_header.volume_index, 0);
        assert_eq!(opened.volume_trailer.as_ref().unwrap().volume_index, 0);
        assert_eq!(
            opened.extract_file("footer-copy.txt").unwrap(),
            Some(b"survives one bad footer".to_vec())
        );
        opened.verify().unwrap();
    }

    #[test]
    fn manifest_footer_corruption_requires_trusted_sidecar() {
        let archive = write_archive(
            &[RegularFile::new("footer.txt", b"sidecar authority")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let manifest_offset = terminal_material_offset(&archive.bytes);
        let mut corrupted = archive.bytes.clone();
        corrupted[manifest_offset + MANIFEST_HMAC_COVERED_LEN] ^= 0x01;
        corrupt_v41_terminal_recovery(&mut corrupted);

        assert!(open_archive(&corrupted, &master_key()).is_err());

        let opened =
            open_non_seekable_archive(&corrupted, &master_key(), Some(&archive.bootstrap_sidecar))
                .unwrap();
        assert!(opened.volume_trailer.is_none());
        assert_eq!(
            opened.extract_file("footer.txt").unwrap(),
            Some(b"sidecar authority".to_vec())
        );
        opened.verify().unwrap();
    }

    #[test]
    fn authenticated_footer_trailer_and_sidecar_hmac_boundaries_are_enforced() {
        let archive = write_archive(
            &[RegularFile::new("hmac-boundary.txt", b"boundary bytes")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let strict_options = ReaderOptions {
            max_trailing_garbage_scan: 0,
            ..ReaderOptions::default()
        };

        let manifest_offset = terminal_material_offset(&archive.bytes);
        for offset in [
            manifest_offset + 71,
            manifest_offset + MANIFEST_HMAC_COVERED_LEN,
        ] {
            let mut corrupted = archive.bytes.clone();
            corrupted[offset] ^= 0x01;
            open_archive(&corrupted, &master_key()).unwrap();
        }

        let trailer_offset = manifest_offset + MANIFEST_FOOTER_LEN;
        for offset in [
            trailer_offset + 75,
            trailer_offset + TRAILER_HMAC_COVERED_LEN,
        ] {
            let mut corrupted = archive.bytes.clone();
            corrupted[offset] ^= 0x01;
            OpenedArchive::open_with_options(&corrupted, &master_key(), strict_options).unwrap();
        }

        let mut covered_sidecar = archive.bootstrap_sidecar.clone();
        let mut header =
            BootstrapSidecarHeader::parse(&covered_sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN])
                .unwrap();
        header.manifest_footer_offset += 1;
        covered_sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN].copy_from_slice(&header.to_bytes());
        assert_eq!(
            open_archive_with_bootstrap_sidecar(&archive.bytes, &covered_sidecar, &master_key())
                .unwrap_err(),
            FormatError::HmacMismatch {
                structure: "BootstrapSidecarHeader"
            }
        );

        let mut tag_sidecar = archive.bootstrap_sidecar.clone();
        let mut header =
            BootstrapSidecarHeader::parse(&tag_sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN]).unwrap();
        header.sidecar_hmac[0] ^= 1;
        tag_sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN].copy_from_slice(&header.to_bytes());
        assert_eq!(
            open_archive_with_bootstrap_sidecar(&archive.bytes, &tag_sidecar, &master_key())
                .unwrap_err(),
            FormatError::HmacMismatch {
                structure: "BootstrapSidecarHeader"
            }
        );

        let mut non_covered_sidecar = archive.bootstrap_sidecar.clone();
        let header =
            BootstrapSidecarHeader::parse(&non_covered_sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN])
                .unwrap();
        let mut header_bytes = header.to_bytes();
        header_bytes[124] ^= 0x01;
        let crc = crc32c::crc32c(&header_bytes[..124]);
        header_bytes[124..128].copy_from_slice(&crc.to_le_bytes());
        non_covered_sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN].copy_from_slice(&header_bytes);
        let opened = open_archive_with_bootstrap_sidecar(
            &archive.bytes,
            &non_covered_sidecar,
            &master_key(),
        )
        .unwrap();
        assert_eq!(
            opened.extract_file("hmac-boundary.txt").unwrap(),
            Some(b"boundary bytes".to_vec())
        );
    }

    #[test]
    fn rejects_authenticated_footer_and_trailer_volume_index_mismatches() {
        let archive = write_archive(
            &[RegularFile::new("volume-index.txt", b"identity")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();

        let mut bad_trailer = archive.bytes.clone();
        rewrite_volume_trailer(&mut bad_trailer, &master_key(), |trailer| {
            trailer.volume_index = 1;
        });
        open_archive(&bad_trailer, &master_key()).unwrap();

        let mut bad_manifest = archive.bytes;
        rewrite_manifest_footer(&mut bad_manifest, &master_key(), |footer| {
            footer.volume_index = 1;
        });
        open_archive(&bad_manifest, &master_key()).unwrap();
    }

    #[test]
    fn rejects_same_key_header_terminal_material_splice() {
        let first = write_archive(
            &[RegularFile::new("splice.txt", b"same shape")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let second = write_archive(
            &[RegularFile::new("splice.txt", b"same shape")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        assert_ne!(first.archive_uuid, second.archive_uuid);
        assert_eq!(
            terminal_material_offset(&first.bytes),
            terminal_material_offset(&second.bytes)
        );
        assert_eq!(first.bytes.len(), second.bytes.len());

        let terminal_offset = terminal_material_offset(&first.bytes);
        let mut spliced = first.bytes.clone();
        spliced[terminal_offset..].copy_from_slice(&second.bytes[terminal_offset..]);

        assert_eq!(
            open_archive(&spliced, &master_key()).unwrap_err(),
            FormatError::InvalidArchive("no valid v41 CMRA candidate found")
        );
    }

    #[test]
    fn rejects_cmra_crypto_header_pre_hmac_mismatch() {
        let kdf_params = crate::crypto::KdfParams::Argon2id {
            t_cost: 1,
            m_cost_kib: 8,
            parallelism: 1,
            salt: b"0123456789abcdef".to_vec(),
        };
        let archive = write_archive_with_kdf(
            &[RegularFile::new("cmra-crypto.txt", b"same fixed header")],
            &master_key(),
            single_stream_options(),
            &kdf_params,
        )
        .unwrap();
        let mut mutated = archive.bytes.clone();
        let volume_header = VolumeHeader::parse(&mutated[..VOLUME_HEADER_LEN]).unwrap();
        let subkeys = Subkeys::derive(
            &master_key(),
            &volume_header.archive_uuid,
            &volume_header.session_id,
        )
        .unwrap();

        rewrite_cmra_image(&mut mutated, CmraRecoveryMode::KeyHolding, |image| {
            let crypto_region = image
                .regions
                .iter_mut()
                .find(|region| region.region_type == 2)
                .unwrap();
            let hmac_offset = crypto_region.bytes.len() - CRYPTO_HEADER_HMAC_LEN;
            let salt_start = CRYPTO_HEADER_FIXED_LEN + 16;
            crypto_region.bytes[salt_start] ^= 0x01;
            let hmac = compute_hmac(
                HmacDomain::CryptoHeader,
                &subkeys.mac_key,
                &volume_header.archive_uuid,
                &volume_header.session_id,
                &crypto_region.bytes[..hmac_offset],
            );
            crypto_region.bytes[hmac_offset..].copy_from_slice(&hmac);
        });

        let final_offset = mutated.len() - CRITICAL_RECOVERY_LOCATOR_LEN;
        let locator = final_recovery_locator(&mutated);
        let crypto_start = volume_header.crypto_header_offset as usize;
        let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
        let parsed_crypto = CryptoHeader::parse(
            &mutated[crypto_start..crypto_end],
            volume_header.crypto_header_length,
        )
        .unwrap();
        assert_eq!(
            parse_locator_cmra_candidate(
                &mutated,
                final_offset,
                locator,
                KeyHoldingTerminalContext {
                    subkeys: &subkeys,
                    volume_header: &volume_header,
                    crypto_header: &parsed_crypto.fixed,
                    crypto_header_bytes: &mutated[crypto_start..crypto_end],
                },
            )
            .unwrap_err(),
            FormatError::InvalidArchive("CMRA CryptoHeader differs from parsed CryptoHeader")
        );
        assert!(open_archive(&mutated, &master_key()).is_err());
    }

    #[test]
    fn recovers_physical_crypto_header_splice_from_cmra_authority() {
        let base = WriterOptions {
            archive_uuid: Some([0x11; 16]),
            session_id: Some([0x22; 16]),
            ..small_block_recovery_options()
        };
        let same_archive = WriterOptions {
            archive_uuid: Some([0x11; 16]),
            session_id: Some([0x33; 16]),
            ..small_block_recovery_options()
        };

        let first = write_archive(
            &[RegularFile::new("splice.txt", b"same shape")],
            &master_key(),
            base,
        )
        .unwrap();
        let second = write_archive(
            &[RegularFile::new("splice.txt", b"same shape")],
            &master_key(),
            same_archive,
        )
        .unwrap();

        let volume_header = VolumeHeader::parse(&first.bytes[..VOLUME_HEADER_LEN]).unwrap();
        let second_volume_header = VolumeHeader::parse(&second.bytes[..VOLUME_HEADER_LEN]).unwrap();
        let crypto_start = volume_header.crypto_header_offset as usize;
        let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
        let second_crypto_end = second_volume_header.crypto_header_offset as usize
            + second_volume_header.crypto_header_length as usize;
        assert_eq!(crypto_end, second_crypto_end);

        let mut spliced = first.bytes.clone();
        spliced[crypto_start..crypto_end].copy_from_slice(&second.bytes[crypto_start..crypto_end]);

        let opened = open_archive(&spliced, &master_key()).unwrap();
        assert_eq!(
            opened.crypto_header_bytes,
            first.bytes[crypto_start..crypto_end].to_vec()
        );
        assert_eq!(
            opened.extract_file("splice.txt").unwrap(),
            Some(b"same shape".to_vec())
        );
        opened.verify().unwrap();
    }

    #[test]
    fn rejects_same_key_object_splice_with_session_mismatch() {
        let first = write_archive(
            &[RegularFile::new("splice.txt", b"same shape")],
            &master_key(),
            WriterOptions {
                archive_uuid: Some([0x11; 16]),
                session_id: Some([0x22; 16]),
                ..single_stream_options()
            },
        )
        .unwrap();
        let second = write_archive(
            &[RegularFile::new("splice.txt", b"same shape")],
            &master_key(),
            WriterOptions {
                archive_uuid: Some([0x11; 16]),
                session_id: Some([0x33; 16]),
                ..single_stream_options()
            },
        )
        .unwrap();

        let volume_header = VolumeHeader::parse(&first.bytes[..VOLUME_HEADER_LEN]).unwrap();
        let crypto_end = volume_header.crypto_header_offset as usize
            + volume_header.crypto_header_length as usize;
        let terminal_offset = terminal_material_offset(&first.bytes);
        let second_terminal_offset = terminal_material_offset(&second.bytes);
        assert_eq!(terminal_offset, second_terminal_offset);

        let mut spliced = first.bytes.clone();
        spliced[crypto_end..terminal_offset]
            .copy_from_slice(&second.bytes[crypto_end..terminal_offset]);

        assert_eq!(
            open_archive(&spliced, &master_key()).unwrap_err(),
            FormatError::AeadFailure
        );
    }

    #[test]
    fn rejects_authenticated_trailer_pointer_and_count_mutations() {
        let archive = write_archive(
            &[RegularFile::new(
                "trailer-range.txt",
                b"authenticated ranges",
            )],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let strict_options = ReaderOptions {
            max_trailing_garbage_scan: 0,
            ..ReaderOptions::default()
        };
        let bytes = archive.bytes;
        let manifest_offset = terminal_material_offset(&bytes);
        let trailer_offset = manifest_offset + MANIFEST_FOOTER_LEN;

        let mut wrong_footer_length = bytes.clone();
        rewrite_volume_trailer(&mut wrong_footer_length, &master_key(), |trailer| {
            trailer.manifest_footer_length = 42;
        });
        OpenedArchive::open_with_options(&wrong_footer_length, &master_key(), strict_options)
            .unwrap();

        for (label, offset) in [
            (
                "offset before trailer by 1",
                manifest_offset.saturating_sub(1),
            ),
            ("offset after trailer", manifest_offset + 1),
            ("offset at stream start", 0),
            ("offset at trailer", trailer_offset),
            ("offset beyond trailer", trailer_offset + 4),
        ] {
            let mut wrong_footer_offset = bytes.clone();
            rewrite_volume_trailer(&mut wrong_footer_offset, &master_key(), |trailer| {
                trailer.manifest_footer_offset = offset as u64;
            });
            open_archive(&wrong_footer_offset, &master_key())
                .unwrap_or_else(|err| panic!("manifest offset case {label}: {err:?}"));
        }

        let mut wrong_bytes_written = bytes.clone();
        rewrite_volume_trailer(&mut wrong_bytes_written, &master_key(), |trailer| {
            trailer.bytes_written += 1;
        });
        open_archive(&wrong_bytes_written, &master_key()).unwrap();

        let mut wrong_block_count = bytes.clone();
        rewrite_volume_trailer(&mut wrong_block_count, &master_key(), |trailer| {
            trailer.block_count += 1;
        });
        open_archive(&wrong_block_count, &master_key()).unwrap();

        let mut wrong_footer_offset = bytes.clone();
        rewrite_volume_trailer(&mut wrong_footer_offset, &master_key(), |trailer| {
            trailer.manifest_footer_offset = bytes.len() as u64 + 1024;
        });
        open_archive(&wrong_footer_offset, &master_key()).unwrap();
    }

    #[test]
    fn rejects_authenticated_trailer_outside_trailing_scan_cap() {
        let archive = write_archive(
            &[RegularFile::new(
                "trailer-trailing-scan.txt",
                b"trailer scan boundaries",
            )],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let options = ReaderOptions {
            max_trailing_garbage_scan: 8,
            ..ReaderOptions::default()
        };

        let mut within_scan = archive.bytes.clone();
        within_scan.resize(within_scan.len() + options.max_trailing_garbage_scan, 0xAA);
        let opened =
            OpenedArchive::open_with_options(&within_scan, &master_key(), options).unwrap();
        assert_eq!(
            opened.extract_file("trailer-trailing-scan.txt").unwrap(),
            Some(b"trailer scan boundaries".to_vec())
        );

        let mut beyond_scan = archive.bytes.clone();
        beyond_scan.resize(
            beyond_scan.len() + max_critical_recovery_scan(options).unwrap() + 1,
            0xAA,
        );
        assert_eq!(
            OpenedArchive::open_with_options(&beyond_scan, &master_key(), options).unwrap_err(),
            FormatError::InvalidArchive("no valid v41 CMRA candidate found")
        );
    }

    #[test]
    fn rejects_authenticated_index_root_extent_size_mismatch_at_open() {
        let archive = write_archive(
            &[RegularFile::new("index-root-size.txt", b"extent size")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let mut malformed = archive.bytes;
        let slot = first_block_record_slot_with_kind(&malformed, BlockKind::IndexRootData)
            .expect("archive should contain IndexRootData");
        mutate_block_record_at_slot(&mut malformed, slot, |record| {
            record.payload[0] ^= 0x55;
        });

        assert_eq!(
            open_archive(&malformed, &master_key()).unwrap_err(),
            FormatError::AeadFailure
        );
    }

    #[test]
    fn rejects_block_record_at_wrong_stripe_position() {
        let files = [RegularFile::new("alpha.txt", b"wrong stripe")];
        let archive = write_archive(
            &files,
            &master_key(),
            WriterOptions {
                stripe_width: 2,
                volume_loss_tolerance: 1,
                ..single_stream_options()
            },
        )
        .unwrap();
        let mut volumes = archive.volumes.clone();
        mutate_first_block_record(&mut volumes[0], |record| {
            record.block_index += 2;
        });

        let volume_refs = volumes.iter().map(Vec::as_slice).collect::<Vec<_>>();
        assert_eq!(
            open_archive_volumes(&volume_refs, &master_key()).unwrap_err(),
            FormatError::InvalidArchive("BlockRecord index does not match volume position")
        );
    }

    #[test]
    fn rejects_decreasing_block_record_index_in_required_region() {
        let archive = write_archive(
            &[RegularFile::new("alpha.txt", b"decreasing block index")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        assert!(block_record_slots(&archive.bytes).len() >= 2);

        let mut malformed = archive.bytes;
        mutate_block_record_at_slot(&mut malformed, 1, |record| {
            record.block_index = 0;
        });

        assert_eq!(
            open_archive(&malformed, &master_key()).unwrap_err(),
            FormatError::InvalidArchive("BlockRecord index does not match volume position")
        );
    }

    #[test]
    fn rejects_duplicate_authenticated_volume_indexes() {
        let files = [RegularFile::new("alpha.txt", b"duplicates")];
        let archive = write_archive(
            &files,
            &master_key(),
            WriterOptions {
                stripe_width: 2,
                volume_loss_tolerance: 1,
                ..single_stream_options()
            },
        )
        .unwrap();

        assert_eq!(
            open_archive_volumes(
                &[archive.volumes[0].as_slice(), archive.volumes[0].as_slice()],
                &master_key()
            )
            .unwrap_err(),
            FormatError::InvalidArchive("duplicate authenticated volume index")
        );
    }

    #[test]
    fn rejects_conflicting_duplicate_authenticated_volume_indexes_by_default() {
        let files = [RegularFile::new("alpha.txt", b"conflicting duplicates")];
        let archive = write_archive(
            &files,
            &master_key(),
            WriterOptions {
                stripe_width: 2,
                volume_loss_tolerance: 1,
                ..single_stream_options()
            },
        )
        .unwrap();
        let mut conflicting = archive.volumes[0].clone();
        corrupt_first_block_record_payload(&mut conflicting);

        assert_eq!(
            open_archive_volumes(
                &[archive.volumes[0].as_slice(), conflicting.as_slice()],
                &master_key()
            )
            .unwrap_err(),
            FormatError::InvalidArchive("duplicate authenticated volume index")
        );
    }

    fn directory_hint_table_from_rows(
        hint_shard_index: u64,
        rows: &[(Vec<u8>, Vec<u32>)],
        shard_count: u32,
    ) -> DirectoryHintTable {
        let mut entries = Vec::new();
        let mut shard_row_indexes = Vec::new();
        let mut string_pool = Vec::new();

        for (path, rows) in rows {
            let path_offset = if path.is_empty() {
                0
            } else {
                let offset = string_pool.len() as u64;
                string_pool.extend_from_slice(path);
                offset
            };
            let shard_list_start_index = shard_row_indexes.len() as u32;
            shard_row_indexes.extend_from_slice(rows);
            entries.push(DirectoryHintEntry {
                dir_hash: hash_prefix(path),
                path_offset,
                path_length: path.len() as u32,
                shard_list_start_index,
                shard_count: rows.len() as u32,
            });
        }

        let table_bytes =
            directory_hint_table_bytes(hint_shard_index, entries, shard_row_indexes, string_pool);
        let locating = DirectoryHintShardEntry {
            hint_shard_index,
            first_dir_hash: hash_prefix(&rows.first().unwrap().0),
            last_dir_hash: hash_prefix(&rows.last().unwrap().0),
            first_block_index: 0,
            data_block_count: 1,
            parity_block_count: 0,
            encrypted_size: 4096,
            decompressed_size: table_bytes.len() as u32,
            entry_count: rows.len() as u64,
        };
        DirectoryHintTable::parse(
            &table_bytes,
            &locating,
            shard_count,
            MetadataLimits::default(),
        )
        .unwrap()
    }

    fn directory_hint_table_bytes(
        hint_shard_index: u64,
        entries: Vec<DirectoryHintEntry>,
        shard_row_indexes: Vec<u32>,
        string_pool: Vec<u8>,
    ) -> Vec<u8> {
        let header_len = DirectoryHintTableHeader {
            version: 1,
            hint_shard_index,
            entry_count: 0,
            entry_table_offset: 0,
            shard_list_offset: 0,
            string_pool_offset: 0,
            string_pool_size: 0,
        }
        .to_bytes()
        .len();
        let entry_len = entries
            .first()
            .map(|entry| entry.to_bytes().len())
            .unwrap_or(0);
        let shard_list_offset = if entries.is_empty() {
            0
        } else {
            header_len + entries.len() * entry_len
        };
        let string_pool_offset = if string_pool.is_empty() {
            0
        } else {
            shard_list_offset + shard_row_indexes.len() * 4
        };

        let header = DirectoryHintTableHeader {
            version: 1,
            hint_shard_index,
            entry_count: entries.len() as u64,
            entry_table_offset: if entries.is_empty() {
                0
            } else {
                header_len as u64
            },
            shard_list_offset: shard_list_offset as u64,
            string_pool_offset: string_pool_offset as u64,
            string_pool_size: string_pool.len() as u64,
        };

        let mut out = Vec::new();
        out.extend_from_slice(&header.to_bytes());
        for entry in entries {
            out.extend_from_slice(&entry.to_bytes());
        }
        for row in shard_row_indexes {
            out.extend_from_slice(&row.to_le_bytes());
        }
        out.extend_from_slice(&string_pool);
        out
    }

    fn corrupt_first_block_record_payload(volume: &mut [u8]) {
        let (record_offset, _) = first_block_record(volume);
        volume[record_offset + 16] ^= 0x55;
    }

    fn corrupt_block_record_payload_at_slot(volume: &mut [u8], slot: usize) {
        let (record_offset, _) = block_record_at_slot(volume, slot);
        volume[record_offset + 16] ^= 0x55;
    }

    fn apply_repair_patches(volume: &mut [u8], patches: &[ArchiveRepairPatch]) {
        for patch in patches {
            let offset = patch.record_offset as usize;
            let end = offset + patch.record_bytes.len();
            volume[offset..end].copy_from_slice(&patch.record_bytes);
        }
    }

    fn corrupt_block_record_magic_at_slot(volume: &mut [u8], slot: usize) {
        let (record_offset, _) = block_record_at_slot(volume, slot);
        volume[record_offset] ^= 0x55;
    }

    fn corrupt_block_record_reserved_at_slot(volume: &mut [u8], slot: usize) {
        let (record_offset, _) = block_record_at_slot(volume, slot);
        volume[record_offset + 14] = 0x01;
    }

    fn corrupt_manifest_footer_hmac(volume: &mut [u8]) {
        let manifest_offset = terminal_material_offset(volume);
        volume[manifest_offset + MANIFEST_HMAC_COVERED_LEN] ^= 0x01;
    }

    fn final_recovery_locator(volume: &[u8]) -> CriticalRecoveryLocator {
        let final_offset = volume.len() - CRITICAL_RECOVERY_LOCATOR_LEN;
        CriticalRecoveryLocator::parse(
            &volume[final_offset..final_offset + CRITICAL_RECOVERY_LOCATOR_LEN],
        )
        .unwrap()
    }

    fn rewrite_cmra_parity_count(volume: &[u8], parity_shard_count: u16) -> Vec<u8> {
        let locator = final_recovery_locator(volume);
        let tuple = CmraDecoderTuple::from(locator);
        assert!(parity_shard_count < tuple.parity_shard_count);
        let cmra_offset = locator.cmra_offset as usize;
        let shard_size = tuple.shard_size as usize;
        let row_len = CRITICAL_METADATA_RECOVERY_SHARD_HEADER_LEN + shard_size;
        let kept_rows = tuple.data_shard_count as usize + parity_shard_count as usize;
        let mut header = CriticalMetadataRecoveryHeader::parse(
            &volume[cmra_offset..cmra_offset + CRITICAL_METADATA_RECOVERY_HEADER_LEN],
        )
        .unwrap();
        header.parity_shard_count = parity_shard_count;

        let mut cmra =
            Vec::with_capacity(CRITICAL_METADATA_RECOVERY_HEADER_LEN + kept_rows * row_len);
        cmra.extend_from_slice(&header.to_bytes());
        let rows_start = cmra_offset + CRITICAL_METADATA_RECOVERY_HEADER_LEN;
        for row in 0..kept_rows {
            let start = rows_start + row * row_len;
            cmra.extend_from_slice(&volume[start..start + row_len]);
        }

        let mut out = Vec::with_capacity(cmra_offset + cmra.len() + LOCATOR_PAIR_LEN);
        out.extend_from_slice(&volume[..cmra_offset]);
        out.extend_from_slice(&cmra);
        let mut mirror = locator;
        mirror.locator_sequence = 1;
        mirror.cmra_length = cmra.len() as u32;
        mirror.cmra_parity_shard_count = parity_shard_count;
        out.extend_from_slice(&mirror.to_bytes());
        let final_locator = CriticalRecoveryLocator {
            volume_format_rev: locator.volume_format_rev,
            locator_sequence: 0,
            ..mirror
        };
        out.extend_from_slice(&final_locator.to_bytes());
        out
    }

    fn rewrite_public_cmra_image(
        volume: &mut [u8],
        mutate: impl FnOnce(&mut CriticalMetadataImage),
    ) {
        rewrite_cmra_image(volume, CmraRecoveryMode::PublicNoKey, mutate);
    }

    fn rewrite_root_auth_footer_revision_bytes(bytes: &mut [u8], revision: u16) {
        bytes[72..74].copy_from_slice(&revision.to_le_bytes());
        let crc_offset = bytes.len() - 4;
        let crc = crc32c::crc32c(&bytes[..crc_offset]);
        bytes[crc_offset..crc_offset + 4].copy_from_slice(&crc.to_le_bytes());
    }

    fn rewrite_cmra_image(
        volume: &mut [u8],
        mode: CmraRecoveryMode,
        mutate: impl FnOnce(&mut CriticalMetadataImage),
    ) {
        let final_offset = volume.len() - CRITICAL_RECOVERY_LOCATOR_LEN;
        let locator = final_recovery_locator(volume);
        let tuple = CmraDecoderTuple::from(locator);
        let recovered = recover_cmra(volume, locator.cmra_offset, Some(tuple), mode).unwrap();
        let mut image = recovered.image;
        mutate(&mut image);
        refresh_critical_image_region_digests(&mut image);
        let image_bytes = image.to_bytes().unwrap();
        assert_eq!(image_bytes.len(), tuple.image_length as usize);

        let shard_size = tuple.shard_size as usize;
        let data_shard_count = tuple.data_shard_count as usize;
        let parity_shard_count = tuple.parity_shard_count as usize;
        assert!(image_bytes.len() <= data_shard_count * shard_size);

        let mut data_shards = Vec::with_capacity(data_shard_count);
        for idx in 0..data_shard_count {
            let start = idx * shard_size;
            let end = (start + shard_size).min(image_bytes.len());
            let mut payload = vec![0u8; shard_size];
            if start < image_bytes.len() {
                payload[..end - start].copy_from_slice(&image_bytes[start..end]);
            }
            data_shards.push(payload);
        }
        let parity_shards = encode_parity_gf16(&data_shards, parity_shard_count).unwrap();
        let image_sha256 = sha256_bytes(&image_bytes);

        let header = CriticalMetadataRecoveryHeader {
            shard_size: tuple.shard_size,
            data_shard_count: tuple.data_shard_count,
            parity_shard_count: tuple.parity_shard_count,
            image_length: tuple.image_length,
            archive_uuid_hint: locator.archive_uuid_hint,
            session_id_hint: locator.session_id_hint,
            volume_index_hint: locator.volume_index_hint,
            image_sha256,
            header_crc32c: 0,
        };
        let mut cmra = Vec::new();
        cmra.extend_from_slice(&header.to_bytes());
        for (idx, payload) in data_shards.into_iter().enumerate() {
            let payload_len = if idx + 1 == data_shard_count {
                image_bytes.len() - idx * shard_size
            } else {
                shard_size
            };
            cmra.extend_from_slice(
                &CriticalMetadataRecoveryShard {
                    shard_index: idx as u16,
                    shard_role: 0,
                    shard_payload_length: payload_len as u32,
                    payload,
                    shard_crc32c: 0,
                }
                .to_bytes(shard_size)
                .unwrap(),
            );
        }
        for (idx, payload) in parity_shards.into_iter().enumerate() {
            cmra.extend_from_slice(
                &CriticalMetadataRecoveryShard {
                    shard_index: (data_shard_count + idx) as u16,
                    shard_role: 1,
                    shard_payload_length: shard_size as u32,
                    payload,
                    shard_crc32c: 0,
                }
                .to_bytes(shard_size)
                .unwrap(),
            );
        }
        assert_eq!(cmra.len() as u64, recovered.cmra_length);
        let cmra_offset = locator.cmra_offset as usize;
        volume[cmra_offset..cmra_offset + cmra.len()].copy_from_slice(&cmra);

        rewrite_locator_image_sha(volume, final_offset, image_sha256);
        let mirror_offset = final_offset - CRITICAL_RECOVERY_LOCATOR_LEN;
        rewrite_locator_image_sha(volume, mirror_offset, image_sha256);
    }

    fn rewrite_cmra_image_variable_len(
        volume: &[u8],
        mode: CmraRecoveryMode,
        mutate: impl FnOnce(&mut CriticalMetadataImage),
    ) -> Vec<u8> {
        let locator = final_recovery_locator(volume);
        let tuple = CmraDecoderTuple::from(locator);
        let recovered = recover_cmra(volume, locator.cmra_offset, Some(tuple), mode).unwrap();
        let mut image = recovered.image;
        mutate(&mut image);
        refresh_critical_image_region_digests(&mut image);
        let image_bytes = image.to_bytes().unwrap();

        let shard_size = tuple.shard_size as usize;
        let data_shard_count = image_bytes.len().div_ceil(shard_size);
        let parity_shard_count = tuple.parity_shard_count as usize;
        assert!(data_shard_count > 0);
        assert!(image_bytes.len() <= data_shard_count * shard_size);

        let mut data_shards = Vec::with_capacity(data_shard_count);
        for idx in 0..data_shard_count {
            let start = idx * shard_size;
            let end = (start + shard_size).min(image_bytes.len());
            let mut payload = vec![0u8; shard_size];
            if start < image_bytes.len() {
                payload[..end - start].copy_from_slice(&image_bytes[start..end]);
            }
            data_shards.push(payload);
        }
        let parity_shards = encode_parity_gf16(&data_shards, parity_shard_count).unwrap();
        let image_sha256 = sha256_bytes(&image_bytes);
        let data_shard_count_u16 = u16::try_from(data_shard_count).unwrap();
        let image_length_u32 = u32::try_from(image_bytes.len()).unwrap();

        let header = CriticalMetadataRecoveryHeader {
            shard_size: tuple.shard_size,
            data_shard_count: data_shard_count_u16,
            parity_shard_count: tuple.parity_shard_count,
            image_length: image_length_u32,
            archive_uuid_hint: locator.archive_uuid_hint,
            session_id_hint: locator.session_id_hint,
            volume_index_hint: locator.volume_index_hint,
            image_sha256,
            header_crc32c: 0,
        };
        let mut cmra = Vec::new();
        cmra.extend_from_slice(&header.to_bytes());
        for (idx, payload) in data_shards.into_iter().enumerate() {
            let payload_len = if idx + 1 == data_shard_count {
                image_bytes.len() - idx * shard_size
            } else {
                shard_size
            };
            cmra.extend_from_slice(
                &CriticalMetadataRecoveryShard {
                    shard_index: idx as u16,
                    shard_role: 0,
                    shard_payload_length: payload_len as u32,
                    payload,
                    shard_crc32c: 0,
                }
                .to_bytes(shard_size)
                .unwrap(),
            );
        }
        for (idx, payload) in parity_shards.into_iter().enumerate() {
            cmra.extend_from_slice(
                &CriticalMetadataRecoveryShard {
                    shard_index: (data_shard_count + idx) as u16,
                    shard_role: 1,
                    shard_payload_length: shard_size as u32,
                    payload,
                    shard_crc32c: 0,
                }
                .to_bytes(shard_size)
                .unwrap(),
            );
        }

        let locator_base = CriticalRecoveryLocator {
            volume_format_rev: image.volume_format_rev,
            cmra_offset: locator.cmra_offset,
            cmra_length: cmra.len() as u32,
            volume_trailer_offset: locator.volume_trailer_offset,
            body_bytes_before_cmra: locator.body_bytes_before_cmra,
            archive_uuid_hint: locator.archive_uuid_hint,
            session_id_hint: locator.session_id_hint,
            volume_index_hint: locator.volume_index_hint,
            locator_sequence: 1,
            cmra_shard_size: tuple.shard_size,
            cmra_data_shard_count: data_shard_count_u16,
            cmra_parity_shard_count: tuple.parity_shard_count,
            cmra_image_length: image_length_u32,
            cmra_image_sha256: image_sha256,
            locator_crc32c: 0,
        };

        let cmra_offset = locator.cmra_offset as usize;
        let mut out = Vec::new();
        out.extend_from_slice(&volume[..cmra_offset]);
        out.extend_from_slice(&cmra);
        out.extend_from_slice(&locator_base.to_bytes());
        out.extend_from_slice(
            &CriticalRecoveryLocator {
                locator_sequence: 0,
                ..locator_base
            }
            .to_bytes(),
        );
        out
    }

    fn rewrite_recovery_locator(
        volume: &mut [u8],
        offset: usize,
        mutate: impl FnOnce(&mut CriticalRecoveryLocator),
    ) {
        let mut locator =
            CriticalRecoveryLocator::parse(&volume[offset..offset + CRITICAL_RECOVERY_LOCATOR_LEN])
                .unwrap();
        mutate(&mut locator);
        volume[offset..offset + CRITICAL_RECOVERY_LOCATOR_LEN].copy_from_slice(&locator.to_bytes());
    }

    fn refresh_critical_image_region_digests(image: &mut CriticalMetadataImage) {
        image.volume_header_sha256 = sha256_bytes(
            &image
                .regions
                .iter()
                .find(|region| region.region_type == 1)
                .unwrap()
                .bytes,
        );
        image.crypto_header_sha256 = sha256_bytes(
            &image
                .regions
                .iter()
                .find(|region| region.region_type == 2)
                .unwrap()
                .bytes,
        );
        image.key_wrap_table_sha256 = image
            .regions
            .iter()
            .find(|region| region.region_type == 6)
            .map(|region| sha256_bytes(&region.bytes))
            .unwrap_or([0u8; 32]);
        image.manifest_footer_sha256 = sha256_bytes(
            &image
                .regions
                .iter()
                .find(|region| region.region_type == 3)
                .unwrap()
                .bytes,
        );
        image.root_auth_footer_sha256 = image
            .regions
            .iter()
            .find(|region| region.region_type == 4)
            .map(|region| sha256_bytes(&region.bytes))
            .unwrap_or([0u8; 32]);
        image.volume_trailer_sha256 = sha256_bytes(
            &image
                .regions
                .iter()
                .find(|region| region.region_type == 5)
                .unwrap()
                .bytes,
        );
    }

    fn rewrite_locator_image_sha(volume: &mut [u8], offset: usize, image_sha256: [u8; 32]) {
        let mut locator =
            CriticalRecoveryLocator::parse(&volume[offset..offset + CRITICAL_RECOVERY_LOCATOR_LEN])
                .unwrap();
        locator.cmra_image_sha256 = image_sha256;
        volume[offset..offset + CRITICAL_RECOVERY_LOCATOR_LEN].copy_from_slice(&locator.to_bytes());
    }

    fn corrupt_v41_terminal_recovery(volume: &mut [u8]) {
        let final_offset = volume.len() - CRITICAL_RECOVERY_LOCATOR_LEN;
        let final_locator = CriticalRecoveryLocator::parse(
            &volume[final_offset..final_offset + CRITICAL_RECOVERY_LOCATOR_LEN],
        )
        .unwrap();
        let mirror_offset = final_offset - CRITICAL_RECOVERY_LOCATOR_LEN;
        volume[final_locator.cmra_offset as usize] ^= 0x55;
        volume[mirror_offset] ^= 0x55;
        volume[final_offset] ^= 0x55;
    }

    fn mutate_first_block_record(volume: &mut [u8], mutate: impl FnOnce(&mut BlockRecord)) {
        let (record_offset, record_len) = first_block_record(volume);
        let block_size = record_len - BLOCK_RECORD_FRAMING_LEN;
        let mut record = BlockRecord::parse(
            &volume[record_offset..record_offset + record_len],
            block_size,
        )
        .unwrap();
        mutate(&mut record);
        volume[record_offset..record_offset + record_len].copy_from_slice(&record.to_bytes());
    }

    fn mutate_block_record_at_slot(
        volume: &mut [u8],
        slot: usize,
        mutate: impl FnOnce(&mut BlockRecord),
    ) {
        let (record_offset, record_len) = block_record_at_slot(volume, slot);
        let block_size = record_len - BLOCK_RECORD_FRAMING_LEN;
        let mut record = BlockRecord::parse(
            &volume[record_offset..record_offset + record_len],
            block_size,
        )
        .unwrap();
        mutate(&mut record);
        volume[record_offset..record_offset + record_len].copy_from_slice(&record.to_bytes());
    }

    fn first_block_record(volume: &[u8]) -> (usize, usize) {
        block_record_at_slot(volume, 0)
    }

    fn block_record_at_slot(volume: &[u8], slot: usize) -> (usize, usize) {
        let volume_header = VolumeHeader::parse(&volume[..VOLUME_HEADER_LEN]).unwrap();
        let crypto_start = volume_header.crypto_header_offset as usize;
        let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
        let crypto_header = CryptoHeader::parse(
            &volume[crypto_start..crypto_end],
            volume_header.crypto_header_length,
        )
        .unwrap();
        let record_len = crypto_header.fixed.block_size as usize + BLOCK_RECORD_FRAMING_LEN;
        let record_offset = crypto_end + slot * record_len;
        assert!(volume.len() >= record_offset + record_len);
        (record_offset, record_len)
    }

    fn first_block_record_slot_with_kind(volume: &[u8], kind: BlockKind) -> Option<usize> {
        block_record_slots(volume)
            .into_iter()
            .enumerate()
            .find_map(|(slot, (_, _, record))| (record.kind == kind).then_some(slot))
    }

    fn block_record_slots_with_kind(volume: &[u8], kind: BlockKind) -> Vec<usize> {
        block_record_slots(volume)
            .into_iter()
            .enumerate()
            .filter_map(|(slot, (_, _, record))| (record.kind == kind).then_some(slot))
            .collect()
    }

    fn first_payload_data_run_slots(volume: &[u8]) -> Vec<usize> {
        let mut slots = Vec::new();
        for (slot, (_, _, record)) in block_record_slots(volume).into_iter().enumerate() {
            if record.kind == BlockKind::PayloadData {
                slots.push(slot);
            } else if !slots.is_empty() {
                break;
            }
        }
        slots
    }

    fn envelope_indices_for_path(opened: &OpenedArchive, path: &str) -> BTreeSet<u64> {
        envelope_entries_for_path(opened, path)
            .into_iter()
            .map(|entry| entry.envelope_index)
            .collect()
    }

    fn envelope_entries_for_path(opened: &OpenedArchive, path: &str) -> Vec<EnvelopeEntry> {
        let normalized =
            normalize_lookup_file_path(path, opened.crypto_header.max_path_length).unwrap();
        let located = opened.locate_index_file(&normalized).unwrap().unwrap();
        let file = &located.shard.files[located.file_index];
        frame_range_for_file(&located.shard, file)
            .unwrap()
            .iter()
            .map(|frame| {
                located
                    .shard
                    .envelopes
                    .iter()
                    .find(|entry| entry.envelope_index == frame.envelope_index)
                    .unwrap()
                    .clone()
            })
            .collect()
    }

    fn block_record_slots(volume: &[u8]) -> Vec<(usize, usize, BlockRecord)> {
        let volume_header = VolumeHeader::parse(&volume[..VOLUME_HEADER_LEN]).unwrap();
        let crypto_start = volume_header.crypto_header_offset as usize;
        let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
        let crypto_header = CryptoHeader::parse(
            &volume[crypto_start..crypto_end],
            volume_header.crypto_header_length,
        )
        .unwrap();
        let record_len = crypto_header.fixed.block_size as usize + BLOCK_RECORD_FRAMING_LEN;
        let manifest_offset = terminal_material_offset(volume);
        assert_eq!((manifest_offset - crypto_end) % record_len, 0);
        let record_count = (manifest_offset - crypto_end) / record_len;
        (0..record_count)
            .map(|slot| {
                let offset = crypto_end + slot * record_len;
                let record = BlockRecord::parse(
                    &volume[offset..offset + record_len],
                    record_len - BLOCK_RECORD_FRAMING_LEN,
                )
                .unwrap();
                (offset, record_len, record)
            })
            .collect()
    }

    fn rewrite_manifest_footer(
        volume: &mut [u8],
        master_key: &MasterKey,
        mutate: impl FnOnce(&mut ManifestFooter),
    ) {
        let volume_header = VolumeHeader::parse(&volume[..VOLUME_HEADER_LEN]).unwrap();
        let offset = terminal_material_offset(volume);
        let mut footer =
            ManifestFooter::parse(&volume[offset..offset + MANIFEST_FOOTER_LEN]).unwrap();
        mutate(&mut footer);
        footer.manifest_hmac = [0u8; 32];
        let mut footer_bytes = footer.to_bytes();
        let subkeys = Subkeys::derive(
            master_key,
            &volume_header.archive_uuid,
            &volume_header.session_id,
        )
        .unwrap();
        footer.manifest_hmac = compute_hmac(
            HmacDomain::ManifestFooter,
            &subkeys.mac_key,
            &volume_header.archive_uuid,
            &volume_header.session_id,
            &footer_bytes[..MANIFEST_HMAC_COVERED_LEN],
        );
        footer_bytes = footer.to_bytes();
        volume[offset..offset + MANIFEST_FOOTER_LEN].copy_from_slice(&footer_bytes);
    }

    fn rewrite_volume_trailer(
        volume: &mut [u8],
        master_key: &MasterKey,
        mutate: impl FnOnce(&mut VolumeTrailer),
    ) {
        let volume_header = VolumeHeader::parse(&volume[..VOLUME_HEADER_LEN]).unwrap();
        let offset = terminal_material_offset(volume) + MANIFEST_FOOTER_LEN;
        let mut trailer =
            VolumeTrailer::parse(&volume[offset..offset + VOLUME_TRAILER_LEN]).unwrap();
        mutate(&mut trailer);
        trailer.trailer_hmac = [0u8; 32];
        let mut trailer_bytes = trailer.to_bytes();
        let subkeys = Subkeys::derive(
            master_key,
            &volume_header.archive_uuid,
            &volume_header.session_id,
        )
        .unwrap();
        trailer.trailer_hmac = compute_hmac(
            HmacDomain::VolumeTrailer,
            &subkeys.mac_key,
            &volume_header.archive_uuid,
            &volume_header.session_id,
            &trailer_bytes[..TRAILER_HMAC_COVERED_LEN],
        );
        trailer_bytes = trailer.to_bytes();
        volume[offset..offset + VOLUME_TRAILER_LEN].copy_from_slice(&trailer_bytes);
    }

    fn rewrite_sidecar_header(
        sidecar: &mut [u8],
        master_key: &MasterKey,
        mutate: impl FnOnce(&mut BootstrapSidecarHeader),
    ) {
        let mut header =
            BootstrapSidecarHeader::parse(&sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN]).unwrap();
        mutate(&mut header);
        write_signed_sidecar_header(sidecar, master_key, &mut header);
    }

    fn write_signed_sidecar_header(
        sidecar: &mut [u8],
        master_key: &MasterKey,
        header: &mut BootstrapSidecarHeader,
    ) {
        header.sidecar_hmac = [0u8; 32];
        let mut header_bytes = header.to_bytes();
        let subkeys =
            Subkeys::derive(master_key, &header.archive_uuid, &header.session_id).unwrap();
        header.sidecar_hmac = compute_hmac(
            HmacDomain::BootstrapSidecar,
            &subkeys.mac_key,
            &header.archive_uuid,
            &header.session_id,
            &header_bytes[..SIDECAR_HMAC_COVERED_LEN],
        );
        header_bytes = header.to_bytes();
        sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN].copy_from_slice(&header_bytes);
    }

    fn sparse_bootstrap_sidecar(
        source: &[u8],
        master_key: &MasterKey,
        include_manifest: bool,
        include_index_root: bool,
        include_dictionary: bool,
    ) -> Vec<u8> {
        let source_header =
            BootstrapSidecarHeader::parse(&source[..BOOTSTRAP_SIDECAR_HEADER_LEN]).unwrap();
        let mut sidecar = vec![0u8; BOOTSTRAP_SIDECAR_HEADER_LEN];
        let mut header = BootstrapSidecarHeader {
            archive_uuid: source_header.archive_uuid,
            session_id: source_header.session_id,
            flags: 0,
            manifest_footer_offset: 0,
            manifest_footer_length: 0,
            index_root_records_offset: 0,
            index_root_records_length: 0,
            dictionary_records_offset: 0,
            dictionary_records_length: 0,
            sidecar_hmac: [0u8; 32],
            header_crc32c: 0,
        };

        if include_manifest {
            assert!(source_header.has_manifest_footer());
            let (offset, length) = append_sidecar_section(
                source,
                &mut sidecar,
                source_header.manifest_footer_offset,
                source_header.manifest_footer_length as u64,
            );
            header.flags |= 0x01;
            header.manifest_footer_offset = offset;
            header.manifest_footer_length = length as u32;
        }
        if include_index_root {
            assert!(source_header.has_index_root_records());
            let (offset, length) = append_sidecar_section(
                source,
                &mut sidecar,
                source_header.index_root_records_offset,
                source_header.index_root_records_length,
            );
            header.flags |= 0x02;
            header.index_root_records_offset = offset;
            header.index_root_records_length = length;
        }
        if include_dictionary {
            assert!(source_header.has_dictionary_records());
            let (offset, length) = append_sidecar_section(
                source,
                &mut sidecar,
                source_header.dictionary_records_offset,
                source_header.dictionary_records_length,
            );
            header.flags |= 0x04;
            header.dictionary_records_offset = offset;
            header.dictionary_records_length = length;
        }

        write_signed_sidecar_header(&mut sidecar, master_key, &mut header);
        sidecar
    }

    fn append_sidecar_section(
        source: &[u8],
        sidecar: &mut Vec<u8>,
        source_offset: u64,
        length: u64,
    ) -> (u64, u64) {
        let source_offset = source_offset as usize;
        let length = length as usize;
        let offset = sidecar.len() as u64;
        sidecar.extend_from_slice(&source[source_offset..source_offset + length]);
        (offset, length as u64)
    }

    fn mutate_sidecar_manifest(
        sidecar: &mut [u8],
        master_key: &MasterKey,
        mutate: impl FnOnce(&mut ManifestFooter),
    ) {
        let header =
            BootstrapSidecarHeader::parse(&sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN]).unwrap();
        let offset = header.manifest_footer_offset as usize;
        let mut footer =
            ManifestFooter::parse(&sidecar[offset..offset + MANIFEST_FOOTER_LEN]).unwrap();
        mutate(&mut footer);
        footer.manifest_hmac = [0u8; 32];
        let mut footer_bytes = footer.to_bytes();
        let subkeys =
            Subkeys::derive(master_key, &footer.archive_uuid, &footer.session_id).unwrap();
        footer.manifest_hmac = compute_hmac(
            HmacDomain::ManifestFooter,
            &subkeys.mac_key,
            &footer.archive_uuid,
            &footer.session_id,
            &footer_bytes[..MANIFEST_HMAC_COVERED_LEN],
        );
        footer_bytes = footer.to_bytes();
        sidecar[offset..offset + MANIFEST_FOOTER_LEN].copy_from_slice(&footer_bytes);
    }

    fn mutate_sidecar_index_record(
        sidecar: &mut [u8],
        record_index: usize,
        mutate: impl FnOnce(&mut BlockRecord),
    ) {
        let header =
            BootstrapSidecarHeader::parse(&sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN]).unwrap();
        let record_len = sidecar_record_len(sidecar);
        let offset = header.index_root_records_offset as usize + record_index * record_len;
        let block_size = record_len - BLOCK_RECORD_FRAMING_LEN;
        let mut record =
            BlockRecord::parse(&sidecar[offset..offset + record_len], block_size).unwrap();
        mutate(&mut record);
        sidecar[offset..offset + record_len].copy_from_slice(&record.to_bytes());
    }

    fn mutate_sidecar_dictionary_record(
        sidecar: &mut [u8],
        record_index: usize,
        mutate: impl FnOnce(&mut BlockRecord),
    ) {
        let header =
            BootstrapSidecarHeader::parse(&sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN]).unwrap();
        let record_len = sidecar_record_len(sidecar);
        let offset = header.dictionary_records_offset as usize + record_index * record_len;
        let block_size = record_len - BLOCK_RECORD_FRAMING_LEN;
        let mut record =
            BlockRecord::parse(&sidecar[offset..offset + record_len], block_size).unwrap();
        mutate(&mut record);
        sidecar[offset..offset + record_len].copy_from_slice(&record.to_bytes());
    }

    fn swap_sidecar_index_records(sidecar: &mut [u8], left: usize, right: usize) {
        let header =
            BootstrapSidecarHeader::parse(&sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN]).unwrap();
        let record_len = sidecar_record_len(sidecar);
        let left_offset = header.index_root_records_offset as usize + left * record_len;
        let right_offset = header.index_root_records_offset as usize + right * record_len;
        for idx in 0..record_len {
            sidecar.swap(left_offset + idx, right_offset + idx);
        }
    }

    fn sidecar_record_len(sidecar: &[u8]) -> usize {
        let header =
            BootstrapSidecarHeader::parse(&sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN]).unwrap();
        let footer_offset = header.manifest_footer_offset as usize;
        let footer =
            ManifestFooter::parse(&sidecar[footer_offset..footer_offset + MANIFEST_FOOTER_LEN])
                .unwrap();
        let index_record_count = footer.index_root_data_block_count as usize
            + footer.index_root_parity_block_count as usize;
        header.index_root_records_length as usize / index_record_count
    }

    fn corrupt_object_extent_records(volume: &mut [u8], extent: ObjectExtent) {
        let volume_header = VolumeHeader::parse(&volume[..VOLUME_HEADER_LEN]).unwrap();
        assert_eq!(volume_header.volume_index, 0);
        assert_eq!(volume_header.stripe_width, 1);
        let crypto_start = volume_header.crypto_header_offset as usize;
        let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
        let crypto_header = CryptoHeader::parse(
            &volume[crypto_start..crypto_end],
            volume_header.crypto_header_length,
        )
        .unwrap();
        let record_len = crypto_header.fixed.block_size as usize + BLOCK_RECORD_FRAMING_LEN;
        let record_count = extent.data_block_count as u64 + extent.parity_block_count as u64;
        for offset in 0..record_count {
            let block_index = extent.first_block_index + offset;
            let record_offset = crypto_end + block_index as usize * record_len;
            volume[record_offset + 16] ^= 0x55;
        }
    }

    fn terminal_material_offset(volume: &[u8]) -> usize {
        let volume_header = VolumeHeader::parse(&volume[..VOLUME_HEADER_LEN]).unwrap();
        let crypto_start = volume_header.crypto_header_offset as usize;
        let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
        let crypto_header = CryptoHeader::parse(
            &volume[crypto_start..crypto_end],
            volume_header.crypto_header_length,
        )
        .unwrap();
        let (_, offset, _) = parse_stream_block_prefix(
            volume,
            crypto_end,
            crypto_header.fixed.block_size as usize,
            &volume_header,
        )
        .unwrap();
        offset
    }

    #[derive(Debug)]
    struct TestObject {
        extent: ObjectExtent,
        records: Vec<BlockRecord>,
    }

    #[derive(Debug)]
    struct TestFileMeta {
        path: Vec<u8>,
        frame_index: u64,
        tar_stream_offset: u64,
        member_group_size: u64,
        file_data_size: u64,
    }

    fn multi_envelope_reader_fixture() -> (OpenedArchive, u64) {
        let volume_header = test_volume_header();
        let crypto_header = test_crypto_header();
        let subkeys = Subkeys::derive(
            &master_key(),
            &volume_header.archive_uuid,
            &volume_header.session_id,
        )
        .unwrap();
        let mut next_block_index = 0u64;
        let mut blocks = BTreeMap::new();

        let healthy = test_member(b"healthy.txt", b"healthy payload\n");
        let broken = test_member(b"broken.txt", b"broken payload\n");
        let tar_stream = [healthy.as_slice(), broken.as_slice()].concat();

        let healthy_frame = compress_zstd_frame(&healthy, 1).unwrap();
        let broken_frame = compress_zstd_frame(&broken, 1).unwrap();

        let healthy_payload = encrypt_test_object(
            &healthy_frame,
            &subkeys.enc_key,
            &subkeys.nonce_seed,
            b"envelope",
            0,
            BlockKind::PayloadData,
            &mut next_block_index,
            &crypto_header,
            &volume_header,
        );
        let broken_payload = encrypt_test_object(
            &broken_frame,
            &subkeys.enc_key,
            &subkeys.nonce_seed,
            b"envelope",
            1,
            BlockKind::PayloadData,
            &mut next_block_index,
            &crypto_header,
            &volume_header,
        );
        let broken_payload_block = broken_payload.extent.first_block_index;
        insert_records(&mut blocks, &healthy_payload.records);
        insert_records(&mut blocks, &broken_payload.records);

        let frames = vec![
            FrameEntry {
                frame_index: 0,
                envelope_index: 0,
                offset_in_envelope: 0,
                compressed_size: healthy_frame.len() as u32,
                decompressed_size: healthy.len() as u32,
                flags: 0x0000_0003,
                tar_stream_offset: 0,
            },
            FrameEntry {
                frame_index: 1,
                envelope_index: 1,
                offset_in_envelope: 0,
                compressed_size: broken_frame.len() as u32,
                decompressed_size: broken.len() as u32,
                flags: 0x0000_0003,
                tar_stream_offset: healthy.len() as u64,
            },
        ];
        let envelopes = vec![
            EnvelopeEntry {
                envelope_index: 0,
                first_block_index: healthy_payload.extent.first_block_index,
                data_block_count: healthy_payload.extent.data_block_count,
                parity_block_count: 0,
                encrypted_size: healthy_payload.extent.encrypted_size,
                plaintext_size: healthy_frame.len() as u32,
                first_frame_index: 0,
                frame_count: 1,
            },
            EnvelopeEntry {
                envelope_index: 1,
                first_block_index: broken_payload.extent.first_block_index,
                data_block_count: broken_payload.extent.data_block_count,
                parity_block_count: 0,
                encrypted_size: broken_payload.extent.encrypted_size,
                plaintext_size: broken_frame.len() as u32,
                first_frame_index: 1,
                frame_count: 1,
            },
        ];
        let files = vec![
            TestFileMeta {
                path: b"healthy.txt".to_vec(),
                frame_index: 0,
                tar_stream_offset: 0,
                member_group_size: healthy.len() as u64,
                file_data_size: b"healthy payload\n".len() as u64,
            },
            TestFileMeta {
                path: b"broken.txt".to_vec(),
                frame_index: 1,
                tar_stream_offset: healthy.len() as u64,
                member_group_size: broken.len() as u64,
                file_data_size: b"broken payload\n".len() as u64,
            },
        ];

        let (index_shard_plaintext, first_path_hash, last_path_hash) =
            build_test_index_shard(&files, &frames, &envelopes);
        let index_shard = encrypt_test_object(
            &compress_zstd_frame(&index_shard_plaintext, 1).unwrap(),
            &subkeys.index_shard_key,
            &subkeys.index_nonce_seed,
            b"idxshard",
            0,
            BlockKind::IndexShardData,
            &mut next_block_index,
            &crypto_header,
            &volume_header,
        );
        insert_records(&mut blocks, &index_shard.records);

        let shard_entry = ShardEntry {
            shard_index: 0,
            first_block_index: index_shard.extent.first_block_index,
            data_block_count: index_shard.extent.data_block_count,
            parity_block_count: 0,
            encrypted_size: index_shard.extent.encrypted_size,
            decompressed_size: index_shard_plaintext.len() as u32,
            file_count: files.len() as u32,
            first_path_hash,
            last_path_hash,
        };
        let mut root_header = IndexRootHeader::empty();
        root_header.frame_count = frames.len() as u64;
        root_header.envelope_count = envelopes.len() as u64;
        root_header.file_count = files.len() as u64;
        root_header.payload_block_count = healthy_payload.extent.data_block_count as u64
            + broken_payload.extent.data_block_count as u64;
        root_header.tar_total_size = tar_stream.len() as u64;
        root_header.content_sha256 = sha256_bytes(&tar_stream);
        let index_root = IndexRoot {
            header: root_header,
            shards: vec![shard_entry],
            directory_hint_shards: Vec::new(),
        };

        let index_root_plaintext = index_root.to_bytes();
        let index_root_object = encrypt_test_object(
            &compress_zstd_frame(&index_root_plaintext, 1).unwrap(),
            &subkeys.index_root_key,
            &subkeys.index_nonce_seed,
            b"idxroot",
            0,
            BlockKind::IndexRootData,
            &mut next_block_index,
            &crypto_header,
            &volume_header,
        );
        insert_records(&mut blocks, &index_root_object.records);

        let archive_uuid = volume_header.archive_uuid;
        let session_id = volume_header.session_id;
        let opened = OpenedArchive {
            options: ReaderOptions::default(),
            observed_archive_bytes: 1_000_000,
            observed_volume_count: 1,
            subkeys,
            blocks,
            lazy_blocks: None,
            crypto_header_bytes: Vec::new(),
            volume_header,
            crypto_header,
            manifest_footer: ManifestFooter {
                archive_uuid,
                session_id,
                volume_index: 0,
                is_authoritative: 1,
                total_volumes: 1,
                index_root_first_block: index_root_object.extent.first_block_index,
                index_root_data_block_count: index_root_object.extent.data_block_count,
                index_root_parity_block_count: 0,
                index_root_encrypted_size: index_root_object.extent.encrypted_size,
                index_root_decompressed_size: index_root_plaintext.len() as u32,
                manifest_hmac: [0u8; 32],
            },
            volume_trailer: Some(VolumeTrailer {
                archive_uuid,
                session_id,
                volume_index: 0,
                block_count: next_block_index,
                bytes_written: 0,
                manifest_footer_offset: 0,
                manifest_footer_length: MANIFEST_FOOTER_LEN as u32,
                closed_at_ns: 0,
                root_auth_footer_offset: 0,
                root_auth_footer_length: 0,
                root_auth_flags: 0,
                trailer_hmac: [0u8; 32],
            }),
            root_auth_footer: None,
            index_root,
            payload_dictionary: None,
        };
        (opened, broken_payload_block)
    }

    fn replace_first_index_shard(opened: &mut OpenedArchive, mutate: impl FnOnce(&mut IndexShard)) {
        let locating = opened.index_root.shards[0].clone();
        let mut shard = opened.load_index_shard(&locating).unwrap();
        mutate(&mut shard);
        let plaintext = shard.to_bytes();
        let mut next_block_index = opened
            .blocks
            .keys()
            .last()
            .copied()
            .map(|index| index + 1)
            .unwrap_or(0);
        let replacement = encrypt_test_object(
            &compress_zstd_frame(&plaintext, 1).unwrap(),
            &opened.subkeys.index_shard_key,
            &opened.subkeys.index_nonce_seed,
            b"idxshard",
            locating.shard_index,
            BlockKind::IndexShardData,
            &mut next_block_index,
            &opened.crypto_header,
            &opened.volume_header,
        );
        insert_records(&mut opened.blocks, &replacement.records);
        opened.index_root.shards[0] = ShardEntry {
            shard_index: locating.shard_index,
            first_block_index: replacement.extent.first_block_index,
            data_block_count: replacement.extent.data_block_count,
            parity_block_count: 0,
            encrypted_size: replacement.extent.encrypted_size,
            decompressed_size: plaintext.len() as u32,
            file_count: shard.files.len() as u32,
            first_path_hash: shard.files.first().unwrap().path_hash,
            last_path_hash: shard.files.last().unwrap().path_hash,
        };
    }

    fn rewrite_as_single_healthy_file(
        opened: &mut OpenedArchive,
        mutate: impl FnOnce(&mut FileEntry, &mut Vec<u8>),
    ) {
        let healthy_path = b"healthy.txt";
        let healthy_payload = b"healthy payload\n";
        let healthy_member = test_member(healthy_path, healthy_payload);
        replace_first_index_shard(opened, |shard| {
            let file_index = (0..shard.files.len())
                .find(|idx| shard.file_path(*idx) == Some(healthy_path.as_slice()))
                .unwrap();
            let mut file = shard.files[file_index].clone();
            let frame = shard
                .frames
                .iter()
                .find(|entry| entry.frame_index == 0)
                .unwrap()
                .clone();
            let envelope = shard
                .envelopes
                .iter()
                .find(|entry| entry.envelope_index == 0)
                .unwrap()
                .clone();
            let mut path = healthy_path.to_vec();

            file.path_offset = 0;
            file.path_length = path.len() as u32;
            file.first_frame_index = 0;
            file.frame_count = 1;
            file.offset_in_first_frame_plaintext = 0;
            file.tar_member_group_size = healthy_member.len() as u64;
            file.file_data_size = healthy_payload.len() as u64;
            file.flags = crate::entry_metadata::EXTENDED_METADATA_V1;
            mutate(&mut file, &mut path);
            file.path_offset = 0;
            file.path_length = path.len() as u32;
            file.path_hash = hash_prefix(&path);

            shard.files = vec![file];
            shard.frames = vec![frame];
            shard.envelopes = vec![envelope];
            shard.string_pool = path;
        });

        opened.index_root.header.file_count = 1;
        opened.index_root.header.frame_count = 1;
        opened.index_root.header.envelope_count = 1;
        opened.index_root.header.payload_block_count = 1;
        opened.index_root.header.tar_total_size = healthy_member.len() as u64;
        opened.index_root.header.content_sha256 = sha256_bytes(&healthy_member);
    }

    fn test_volume_header() -> VolumeHeader {
        VolumeHeader {
            format_version: FORMAT_VERSION,
            volume_format_rev: VOLUME_FORMAT_REV,
            volume_index: 0,
            stripe_width: 1,
            archive_uuid: [0x31; 16],
            session_id: [0x42; 16],
            crypto_header_offset: VOLUME_HEADER_LEN as u32,
            crypto_header_length: CRYPTO_HEADER_FIXED_LEN as u32,
            header_crc32c: 0,
        }
    }

    fn test_crypto_header() -> CryptoHeaderFixed {
        CryptoHeaderFixed {
            length: CRYPTO_HEADER_FIXED_LEN as u32,
            compression_algo: CompressionAlgo::ZstdFramed,
            aead_algo: AeadAlgo::AesGcmSiv256,
            fec_algo: FecAlgo::ReedSolomonGF16,
            kdf_algo: KdfAlgo::Raw,
            chunk_size: 4096,
            envelope_target_size: 8192,
            block_size: 4096,
            fec_data_shards: 4,
            fec_parity_shards: 0,
            index_fec_data_shards: 4,
            index_fec_parity_shards: 0,
            index_root_fec_data_shards: 4,
            index_root_fec_parity_shards: 0,
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            has_dictionary: 0,
            max_path_length: 4096,
            expected_volume_size: 0,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn encrypt_test_object(
        plaintext: &[u8],
        key: &[u8; 32],
        nonce_seed: &[u8; 32],
        domain: &[u8],
        counter: u64,
        data_kind: BlockKind,
        next_block_index: &mut u64,
        crypto_header: &CryptoHeaderFixed,
        volume_header: &VolumeHeader,
    ) -> TestObject {
        let block_size = crypto_header.block_size as usize;
        let encrypted = encrypt_padded_aead_object(
            AeadObjectContext {
                algo: crypto_header.aead_algo,
                key,
                nonce_seed,
                domain,
                archive_uuid: &volume_header.archive_uuid,
                session_id: &volume_header.session_id,
                counter,
            },
            block_size,
            plaintext,
        )
        .unwrap();
        assert_eq!(encrypted.len() % block_size, 0);

        let first_block_index = *next_block_index;
        let data_block_count = encrypted.len() / block_size;
        let records = encrypted
            .chunks(block_size)
            .enumerate()
            .map(|(index, payload)| BlockRecord {
                block_index: first_block_index + index as u64,
                kind: data_kind,
                flags: if index + 1 == data_block_count {
                    0x01
                } else {
                    0
                },
                payload: payload.to_vec(),
                record_crc32c: 0,
            })
            .collect::<Vec<_>>();
        *next_block_index += data_block_count as u64;

        TestObject {
            extent: ObjectExtent {
                first_block_index,
                data_block_count: data_block_count as u32,
                parity_block_count: 0,
                encrypted_size: encrypted.len() as u32,
            },
            records,
        }
    }

    fn insert_records(blocks: &mut BTreeMap<u64, BlockRecord>, records: &[BlockRecord]) {
        for record in records {
            assert!(blocks.insert(record.block_index, record.clone()).is_none());
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn build_metadata_object_from_payload(
        payload: &[u8],
        _subkeys: &Subkeys,
        volume_header: &VolumeHeader,
        crypto_header: &CryptoHeaderFixed,
        key: &[u8; 32],
        nonce_seed: &[u8; 32],
        domain: &[u8],
        counter: u64,
        data_kind: BlockKind,
        next_block_index: &mut u64,
    ) -> (ObjectExtent, BTreeMap<u64, BlockRecord>) {
        let compressed = compress_zstd_frame(payload, 1).unwrap();
        build_metadata_object_from_compressed(
            &compressed,
            key,
            nonce_seed,
            domain,
            counter,
            data_kind,
            next_block_index,
            crypto_header,
            volume_header,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build_metadata_object_from_compressed(
        compressed: &[u8],
        key: &[u8; 32],
        nonce_seed: &[u8; 32],
        domain: &[u8],
        counter: u64,
        data_kind: BlockKind,
        next_block_index: &mut u64,
        crypto_header: &CryptoHeaderFixed,
        volume_header: &VolumeHeader,
    ) -> (ObjectExtent, BTreeMap<u64, BlockRecord>) {
        let object = encrypt_test_object(
            compressed,
            key,
            nonce_seed,
            domain,
            counter,
            data_kind,
            next_block_index,
            crypto_header,
            volume_header,
        );

        let mut blocks = BTreeMap::new();
        for record in object.records {
            blocks.insert(record.block_index, record);
        }
        (object.extent, blocks)
    }

    #[allow(clippy::too_many_arguments)]
    fn assert_metadata_object_from_compressed(
        compressed: &[u8],
        decompressed_size: usize,
        _subkeys: &Subkeys,
        volume_header: &VolumeHeader,
        crypto_header: &CryptoHeaderFixed,
        key: &[u8; 32],
        nonce_seed: &[u8; 32],
        domain: &[u8],
        counter: u64,
        data_kind: BlockKind,
        parity_kind: BlockKind,
        class_data_shards: u16,
        class_parity_shards: u16,
        next_block_index: &mut u64,
        expected: FormatError,
    ) {
        let (extent, blocks) = build_metadata_object_from_compressed(
            compressed,
            key,
            nonce_seed,
            domain,
            counter,
            data_kind,
            next_block_index,
            crypto_header,
            volume_header,
        );
        let error = load_metadata_object_from_parts(
            &blocks,
            ObjectLoadContext {
                volume_header,
                crypto_header,
                extent,
                data_kind,
                parity_kind,
                key,
                nonce_seed,
                domain,
                counter,
                class_data_shard_max: class_data_shards,
                class_parity_shard_max: class_parity_shards,
            },
            decompressed_size as u32,
        )
        .unwrap_err();
        assert_eq!(error, expected);
    }

    fn corrupt_payload_record(blocks: &mut BTreeMap<u64, BlockRecord>, block_index: u64) {
        let record = blocks.get_mut(&block_index).unwrap();
        assert_eq!(record.kind, BlockKind::PayloadData);
        record.payload[0] ^= 0x55;
    }

    fn build_test_index_shard(
        files: &[TestFileMeta],
        frames: &[FrameEntry],
        envelopes: &[EnvelopeEntry],
    ) -> (Vec<u8>, [u8; 8], [u8; 8]) {
        let mut sorted = files
            .iter()
            .map(|file| (hash_prefix(&file.path), file))
            .collect::<Vec<_>>();
        sorted.sort_by(|left, right| {
            (left.0, left.1.path.as_slice(), left.1.tar_stream_offset).cmp(&(
                right.0,
                right.1.path.as_slice(),
                right.1.tar_stream_offset,
            ))
        });

        let mut string_pool = Vec::new();
        let mut file_entries = Vec::with_capacity(sorted.len());
        for (path_hash, file) in &sorted {
            let path_offset = string_pool.len() as u32;
            string_pool.extend_from_slice(&file.path);
            file_entries.push(FileEntry {
                path_hash: *path_hash,
                path_offset,
                path_length: file.path.len() as u32,
                first_frame_index: file.frame_index,
                frame_count: 1,
                offset_in_first_frame_plaintext: 0,
                tar_member_group_size: file.member_group_size,
                file_data_size: file.file_data_size,
                flags: crate::entry_metadata::EXTENDED_METADATA_V1,
                mtime_nsec: 0,
                mtime_sec: 0,
                created_nsec: 0,
                created_sec: 0,
                accessed_nsec: 0,
                accessed_sec: 0,
                uid: 0,
                gid: 0,
                mode: 0,
                attributes: 0,
                uname_offset: 0,
                uname_length: 0,
                gname_offset: 0,
                gname_length: 0,
                link_target_offset: 0,
                link_target_length: 0,
                kind: 0,
                metadata_flags: 0,
                _reserved1: 0,
                _reserved2: 0,
            });
        }

        let header = IndexShardHeader {
            version: 1,
            shard_index: 0,
            file_count: file_entries.len() as u32,
            frame_count: frames.len() as u32,
            envelope_count: envelopes.len() as u32,
            file_table_offset: INDEX_SHARD_HEADER_LEN as u32,
            frame_table_offset: (INDEX_SHARD_HEADER_LEN + file_entries.len() * FILE_ENTRY_LEN)
                as u32,
            envelope_table_offset: (INDEX_SHARD_HEADER_LEN
                + file_entries.len() * FILE_ENTRY_LEN
                + frames.len() * FRAME_ENTRY_LEN) as u32,
            string_pool_offset: (INDEX_SHARD_HEADER_LEN
                + file_entries.len() * FILE_ENTRY_LEN
                + frames.len() * FRAME_ENTRY_LEN
                + envelopes.len() * ENVELOPE_ENTRY_LEN) as u32,
            string_pool_size: string_pool.len() as u32,
        };

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&header.to_bytes());
        for entry in &file_entries {
            bytes.extend_from_slice(&entry.to_bytes());
        }
        for entry in frames {
            bytes.extend_from_slice(&entry.to_bytes());
        }
        for entry in envelopes {
            bytes.extend_from_slice(&entry.to_bytes());
        }
        bytes.extend_from_slice(&string_pool);

        (bytes, sorted.first().unwrap().0, sorted.last().unwrap().0)
    }

    #[test]
    fn opens_lists_and_verifies_archive_with_pax_metadata_and_symlink_target() {
        struct CustomMember<'a> {
            path: &'a str,
            target: &'a [u8],
            created_sec: u64,
            created_nsec: u32,
            accessed_sec: u64,
            accessed_nsec: u32,
        }

        impl<'a> RegularFileSource for CustomMember<'a> {
            fn archive_path(&self) -> &str {
                self.path
            }
            fn entry_kind(&self) -> SourceEntryKind {
                SourceEntryKind::Symlink
            }
            fn link_target(&self) -> Option<&[u8]> {
                Some(self.target)
            }
            fn file_data_size(&self) -> u64 {
                0
            }
            fn mode(&self) -> u32 {
                0o777
            }
            fn mtime(&self) -> ArchiveTimestamp {
                ArchiveTimestamp::new(1_700_000_000, 100_000_000)
            }
            fn portable_metadata(&self) -> PortableFileMetadata {
                let mut primary_pax_records = std::collections::BTreeMap::default();
                primary_pax_records.insert(
                    "LIBARCHIVE.creationtime".into(),
                    ArchiveTimestamp::new(self.created_sec as i64, self.created_nsec)
                        .canonical_pax_value()
                        .unwrap(),
                );
                primary_pax_records.insert(
                    "atime".into(),
                    ArchiveTimestamp::new(self.accessed_sec as i64, self.accessed_nsec)
                        .canonical_pax_value()
                        .unwrap(),
                );

                PortableFileMetadata {
                    source_os: "macos".into(),
                    source_filesystem: "apfs".into(),
                    mode_origin: PortableModeOrigin::Native,
                    posix_owner: Some(PortablePosixOwner {
                        uid: 1001,
                        gid: 1002,
                        uname: Some("alice".into()),
                        gname: Some("devs".into()),
                    }),
                    attributes: Some(0x05),
                    created: None,
                    accessed: None,
                    native: NativeFileMetadata {
                        required_profiles: vec![
                            "macos-backup-v1".into(),
                            "portable-v1".into(),
                            "posix-backup-v1".into(),
                        ],
                        primary_pax_records,
                        auxiliary_records: Vec::new(),
                        ..Default::default()
                    },
                }
            }
            fn open(&self) -> Result<Box<dyn Read + '_>, crate::format::ArchiveWriteError> {
                Ok(Box::new(std::io::Cursor::new(b"")))
            }
        }

        let source = CustomMember {
            path: "links/sym1",
            target: b"target.txt",
            created_sec: 1_700_000_100,
            created_nsec: 500_000_000,
            accessed_sec: 1_700_000_200,
            accessed_nsec: 250_000_000,
        };

        let mut sink = MemoryArchiveSink::default();
        write_archive_sources_to_sink_single_pass(
            &[source],
            &master_key(),
            single_stream_options(),
            &crate::crypto::KdfParams::Raw,
            None,
            None,
            &mut sink,
        )
        .unwrap();
        let archive_bytes = sink.volumes.remove(0);

        let opened = open_archive(&archive_bytes, &master_key()).unwrap();

        let entries = opened.list_files().unwrap();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];

        assert_eq!(entry.path, "links/sym1");
        assert_eq!(entry.kind, TarEntryKind::Symlink);
        assert_eq!(entry.link_target, Some("target.txt".to_string()));
        assert_eq!(
            entry.created,
            Some(ArchiveTimestamp::new(1_700_000_100, 500_000_000))
        );
        assert_eq!(
            entry.accessed,
            Some(ArchiveTimestamp::new(1_700_000_200, 250_000_000))
        );
        assert_eq!(entry.attributes, Some(0x05));
        assert_eq!(entry.uid, Some(1001));
        assert_eq!(entry.gid, Some(1002));
        assert_eq!(entry.uname, Some("alice".to_string()));
        assert_eq!(entry.gname, Some("devs".to_string()));

        let streamed_report = list_non_seekable_stream(
            std::io::Cursor::new(archive_bytes),
            &master_key(),
            NonSeekableReaderOptions::default(),
        )
        .unwrap();
        assert_eq!(streamed_report.entries, entries);
    }

    #[test]
    fn extraction_options_allow_absolute_symlinks_toggle() {
        struct AbsSymlinkSource;

        impl RegularFileSource for AbsSymlinkSource {
            fn archive_path(&self) -> &str {
                "abs_link"
            }
            fn entry_kind(&self) -> SourceEntryKind {
                SourceEntryKind::Symlink
            }
            fn link_target(&self) -> Option<&[u8]> {
                Some(b"/tmp/abs_target")
            }
            fn file_data_size(&self) -> u64 {
                0
            }
            fn mode(&self) -> u32 {
                0o777
            }
            fn mtime(&self) -> ArchiveTimestamp {
                ArchiveTimestamp::new(1_700_000_000, 0)
            }
            fn open(&self) -> Result<Box<dyn Read + '_>, crate::format::ArchiveWriteError> {
                Ok(Box::new(std::io::Cursor::new(b"")))
            }
        }

        let mut sink = MemoryArchiveSink::default();
        write_archive_sources_to_sink_single_pass(
            &[AbsSymlinkSource],
            &master_key(),
            single_stream_options(),
            &crate::crypto::KdfParams::Raw,
            None,
            None,
            &mut sink,
        )
        .unwrap();
        let archive_bytes = sink.volumes.remove(0);
        let opened = open_archive(&archive_bytes, &master_key()).unwrap();

        let tmp = tempfile::tempdir().unwrap();

        let options_disallowed = SafeExtractionOptions {
            allow_absolute_symlinks: false,
            ..Default::default()
        };
        assert_eq!(
            opened
                .extract_indexed_files_to(tmp.path(), options_disallowed, 1)
                .unwrap_err(),
            crate::format::FormatError::UnsafeArchivePath
        );

        let tmp_allowed = tempfile::tempdir().unwrap();
        let options_allowed = SafeExtractionOptions {
            allow_absolute_symlinks: true,
            ..Default::default()
        };
        let res_allowed = opened.extract_indexed_files_to(tmp_allowed.path(), options_allowed, 1);
        match res_allowed {
            Ok(_) => {}
            Err(crate::format::FormatError::FilesystemExtractionFailed(msg)) => {
                assert_eq!(msg, "failed to create symlink");
            }
            Err(other) => panic!("expected Ok or FilesystemExtractionFailed, got {:?}", other),
        }
    }

    fn test_member(path: &[u8], data: &[u8]) -> Vec<u8> {
        let records =
            crate::entry_metadata::portable_primary_pax(path, 0o644, "other", false).unwrap();
        let pax = crate::entry_metadata::encode_canonical_pax(&records).unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(&test_tar_header(
            b"TZAP-PAX/PRIMARY",
            pax.len() as u64,
            0,
            b'x',
        ));
        out.extend_from_slice(&pax);
        out.resize(out.len() + padding_to_512(pax.len()), 0);
        out.extend_from_slice(&test_tar_header(path, data.len() as u64, 0o644, b'0'));
        out.extend_from_slice(data);
        out.resize(out.len() + padding_to_512(data.len()), 0);
        out
    }

    fn test_tar_header(path: &[u8], size: u64, mode: u64, typeflag: u8) -> [u8; 512] {
        let mut header = [0u8; 512];
        header[..path.len()].copy_from_slice(path);
        write_test_tar_octal(&mut header[100..108], mode);
        write_test_tar_octal(&mut header[108..116], 0);
        write_test_tar_octal(&mut header[116..124], 0);
        write_test_tar_octal(&mut header[124..136], size);
        write_test_tar_octal(&mut header[136..148], 0);
        header[148..156].fill(b' ');
        header[156] = typeflag;
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum = header.iter().map(|byte| *byte as u64).sum::<u64>();
        write_test_tar_checksum(&mut header[148..156], checksum);
        header
    }

    fn write_test_tar_octal(field: &mut [u8], value: u64) {
        let digits = format!("{value:o}");
        field.fill(0);
        let start = field.len() - 1 - digits.len();
        field[..start].fill(b'0');
        field[start..start + digits.len()].copy_from_slice(digits.as_bytes());
    }

    fn write_test_tar_checksum(field: &mut [u8], value: u64) {
        let digits = format!("{value:06o}");
        field[0..6].copy_from_slice(digits.as_bytes());
        field[6] = 0;
        field[7] = b' ';
    }

    fn padding_to_512(len: usize) -> usize {
        let remainder = len % 512;
        if remainder == 0 {
            0
        } else {
            512 - remainder
        }
    }
}
