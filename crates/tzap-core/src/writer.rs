use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

use crate::compression::{
    compress_zstd_frame_with_dictionary_and_jobs, compress_zstd_frame_with_jobs,
};
use crate::crypto::{
    aead_encrypt, build_aad, compute_integrity_tag, derive_nonce, HmacDomain, KdfParams, MasterKey,
    Subkeys,
};
use crate::entry_metadata::{
    canonical_base64_encode, encode_canonical_pax, is_source_os,
    parse_auxiliary_declaration_for_writer, parse_auxiliary_record, parse_primary_metadata,
    portable_primary_pax, valid_filesystem_token, validate_group_metadata, ArchiveTimestamp,
    RestoreClass, SparseExtent, CAPTURE_PARTIAL, CAPTURE_REPORT_KIND, EXTENDED_METADATA_V1,
    HAS_AUXILIARY_STREAMS, HAS_NATIVE_METADATA, HAS_SPARSE_EXTENTS, MAX_SPARSE_EXTENTS,
    PORTABLE_PROFILE, REQUIRES_SYSTEM_RESTORE,
};
use crate::fec::encode_parity_gf16;
use crate::format::{
    root_auth_spec_id_for_revision, AeadAlgo, ArchiveWriteError, BlockKind, CompressionAlgo,
    FecAlgo, FormatError, KdfAlgo, BLOCK_RECORD_FRAMING_LEN, BOOTSTRAP_SIDECAR_HEADER_LEN,
    CRITICAL_RECOVERY_LOCATOR_LEN, CRYPTO_EXTENSION_HEADER_LEN, CRYPTO_HEADER_FIXED_LEN,
    CRYPTO_HEADER_HMAC_LEN, FORMAT_VERSION, MANIFEST_FOOTER_LEN, READER_MAX_CMRA_PARITY_PCT,
    READER_MAX_INDEX_ROOT_FEC_CLASS_SHARDS, READER_MAX_ROOT_AUTH_AUTHENTICATOR_VALUE_LEN,
    READER_MAX_ROOT_AUTH_FOOTER_LEN, READER_MAX_ROOT_AUTH_SIGNER_IDENTITY_LEN,
    VOLUME_FORMAT_REV_45, VOLUME_HEADER_LEN, VOLUME_TRAILER_LEN,
};
use crate::metadata::{
    hash_prefix, normalize_lookup_file_path, validate_file_path_bytes, DirectoryHintEntry,
    DirectoryHintShardEntry, DirectoryHintTableHeader, EnvelopeEntry, FileEntry, FrameEntry,
    IndexRoot, IndexRootHeader, IndexShardHeader, ShardEntry, DIRECTORY_HINT_ENTRY_LEN,
    DIRECTORY_HINT_TABLE_LEN, ENVELOPE_ENTRY_LEN, FILE_ENTRY_LEN, FRAME_ENTRY_LEN,
    INDEX_SHARD_HEADER_LEN,
};
use crate::padding::suffix_pad_for_aead;
use crate::root_auth::{
    archive_root_for_revision, critical_metadata_digest, data_block_merkle_leaf_hash_for_revision,
    data_block_merkle_root_from_leaf_hashes_for_revision, fec_layout_digest_for_revision,
    index_digest_for_revision, root_auth_descriptor_digest_for_revision, signer_identity_digest,
    ArchiveRootInputs, CriticalMetadataDigestInputs, FecLayoutObjectRow,
};
use crate::wire::{
    compute_key_wrap_table_digest, BlockRecord, BootstrapSidecarHeader, CriticalMetadataImage,
    CriticalMetadataRecoveryHeader, CriticalMetadataRecoveryShard, CriticalRecoveryLocator,
    CryptoHeader, CryptoHeaderFixed, KeyWrapTableV1, ManifestFooter, RecipientRecordV1,
    RootAuthFooterV1, SerializedRegion, VolumeHeader, VolumeTrailer,
};

const TAR_BLOCK_LEN: usize = 512;
const MAX_REED_SOLOMON_GF16_SHARDS: u64 = 65_535;
const MIN_BLOCK_SIZE: u32 = 4096;
const DEFAULT_BLOCK_SIZE: u32 = 64 * 1024;
const DEFAULT_CHUNK_SIZE: u32 = 256 * 1024;
const DEFAULT_ENVELOPE_TARGET_SIZE: u32 = 1024 * 1024;
const DEFAULT_FEC_DATA_SHARDS: u16 = 224;
const DEFAULT_FEC_PARITY_SHARDS: u16 = 1;
const DEFAULT_INDEX_FEC_DATA_SHARDS: u16 = 16;
const DEFAULT_INDEX_FEC_PARITY_SHARDS: u16 = 1;
const MIN_INDEX_ROOT_FEC_DATA_SHARDS: u16 = 16;
const DEFAULT_INDEX_ROOT_FEC_DATA_SHARDS: u16 = MIN_INDEX_ROOT_FEC_DATA_SHARDS;
const DEFAULT_INDEX_ROOT_FEC_PARITY_SHARDS: u16 = 1;
const DEFAULT_STRIPE_WIDTH: u32 = 8;
const DEFAULT_VOLUME_LOSS_TOLERANCE: u8 = 1;
const DEFAULT_BIT_ROT_BUFFER_PCT: u8 = 5;
const DEFAULT_FILES_PER_INDEX_SHARD: usize = 10_000;
const DIRECTORY_HINT_REQUIRED_FILE_COUNT: usize = 100_000;
const MAX_FILES_PER_INDEX_SHARD: usize = 1_000_000;
const MAX_HASH_PREFIX_RUN_FILES: usize = 50_000;
const DEFAULT_DIRECTORY_HINT_ENTRIES_PER_SHARD: usize = 10_000;
const CMRA_SHARD_SIZE: usize = 512;

#[derive(Clone, Default)]
pub enum KeyWrapRecordSource {
    #[default]
    None,
    Fixed(Vec<RecipientRecordV1>),
    Callback(Arc<dyn Fn() -> Result<Vec<RecipientRecordV1>, FormatError> + Send + Sync>),
}

impl KeyWrapRecordSource {
    pub fn fixed(records: Vec<RecipientRecordV1>) -> Self {
        Self::Fixed(records)
    }

    pub fn callback<F>(callback: F) -> Self
    where
        F: Fn() -> Result<Vec<RecipientRecordV1>, FormatError> + Send + Sync + 'static,
    {
        Self::Callback(Arc::new(callback))
    }

    fn resolve(&self) -> Result<Option<Vec<RecipientRecordV1>>, FormatError> {
        match self {
            Self::None => Ok(None),
            Self::Fixed(records) => Ok(Some(records.clone())),
            Self::Callback(callback) => Ok(Some(callback()?)),
        }
    }
}

fn default_jobs() -> usize {
    std::thread::available_parallelism()
        .map(|jobs| jobs.get())
        .unwrap_or(1)
}

fn volume_format_revision_for_options(_options: &WriterOptions, _kdf_params: &KdfParams) -> u16 {
    // Writer is intentionally canonicalized to v45-only output.
    VOLUME_FORMAT_REV_45
}

fn resolve_key_wrap_artifacts(
    kdf_params: &KdfParams,
    archive_uuid: &[u8; 16],
    session_id: &[u8; 16],
    key_wrap_records: Option<&KeyWrapRecordSource>,
) -> Result<(KdfParams, Option<Vec<u8>>), FormatError> {
    match kdf_params {
        KdfParams::RecipientWrap {
            key_wrap_table_length,
            key_wrap_table_record_count,
            key_wrap_table_version,
            ..
        } => {
            if *key_wrap_table_version != 1 {
                return Err(FormatError::InvalidKdfParams(
                    "recipient-wrap table version must be 1",
                ));
            }
            let Some(records) = key_wrap_records
                .ok_or(FormatError::WriterUnsupported(
                    "RecipientWrap requires key-wrap records",
                ))?
                .resolve()?
            else {
                return Err(FormatError::WriterUnsupported(
                    "RecipientWrap requires key-wrap records",
                ));
            };
            if records.is_empty() {
                return Err(FormatError::WriterUnsupported(
                    "RecipientWrap requires at least one recipient record",
                ));
            }
            let mut recipient_records = Vec::with_capacity(records.len());
            for record in records {
                let mut prepared = record.clone();
                let record_length = u32_len(prepared.to_bytes()?.len(), "RecipientWrap record")?;
                prepared = prepared.with_record_length(record_length);
                recipient_records.push(prepared);
            }
            let declared_record_count = u32_len(
                recipient_records.len(),
                "KeyWrapTableV1 recipient_record_count",
            )?;
            if *key_wrap_table_record_count != 0
                && *key_wrap_table_record_count != declared_record_count
            {
                return Err(FormatError::InvalidKdfParams(
                    "recipient-wrap key_wrap_table_record_count mismatch",
                ));
            }

            let key_wrap_table = KeyWrapTableV1 {
                version: *key_wrap_table_version,
                volume_format_rev: VOLUME_FORMAT_REV_45,
                table_length: 0,
                flags: 0,
                archive_uuid: *archive_uuid,
                session_id: *session_id,
                recipient_record_count: declared_record_count,
                records_offset: 96,
                records_length: 0,
                recipient_records,
            }
            .to_bytes()?;
            let computed_key_wrap_table_length =
                u32_len(key_wrap_table.len(), "KeyWrapTableV1 table_length")?;
            if *key_wrap_table_length != 0
                && computed_key_wrap_table_length != *key_wrap_table_length
            {
                return Err(FormatError::InvalidKdfParams(
                    "recipient-wrap key_wrap_table_length mismatch",
                ));
            }
            let key_wrap_table_digest =
                compute_key_wrap_table_digest(computed_key_wrap_table_length, &key_wrap_table);
            Ok((
                KdfParams::RecipientWrap {
                    key_wrap_table_length: computed_key_wrap_table_length,
                    key_wrap_table_record_count: declared_record_count,
                    key_wrap_table_version: *key_wrap_table_version,
                    key_wrap_table_digest,
                },
                Some(key_wrap_table),
            ))
        }
        _ => Ok((kdf_params.clone(), None)),
    }
}

fn recipient_wrap_kdf_params_for_record_count(
    record_count: usize,
) -> Result<KdfParams, FormatError> {
    Ok(KdfParams::RecipientWrap {
        key_wrap_table_length: 0,
        key_wrap_table_record_count: u32_len(
            record_count,
            "KeyWrapTableV1 recipient_record_count",
        )?,
        key_wrap_table_version: 1,
        key_wrap_table_digest: [0u8; 32],
    })
}

fn stabilized_key_wrap_record_source(
    kdf_params: &KdfParams,
    key_wrap_records: Option<&KeyWrapRecordSource>,
) -> Result<Option<KeyWrapRecordSource>, FormatError> {
    if !matches!(kdf_params, KdfParams::RecipientWrap { .. }) {
        return Ok(None);
    }
    let Some(records) = key_wrap_records
        .ok_or(FormatError::WriterUnsupported(
            "RecipientWrap requires key-wrap records",
        ))?
        .resolve()?
    else {
        return Err(FormatError::WriterUnsupported(
            "RecipientWrap requires key-wrap records",
        ));
    };
    Ok(Some(KeyWrapRecordSource::fixed(records)))
}

fn should_emit_directory_hints(file_count: usize) -> bool {
    file_count > DIRECTORY_HINT_REQUIRED_FILE_COUNT
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriterOptions {
    pub block_size: u32,
    pub chunk_size: u32,
    pub envelope_target_size: u32,
    pub stripe_width: u32,
    pub volume_loss_tolerance: u8,
    pub bit_rot_buffer_pct: u8,
    pub zstd_level: i32,
    pub jobs: usize,
    pub aead_algo: AeadAlgo,
    pub fec_data_shards: u16,
    pub fec_parity_shards: u16,
    pub index_fec_data_shards: u16,
    pub index_fec_parity_shards: u16,
    pub index_root_fec_data_shards: u16,
    pub index_root_fec_parity_shards: u16,
    pub max_path_length: u32,
    pub target_volume_size: Option<u64>,
    pub archive_uuid: Option<[u8; 16]>,
    pub session_id: Option<[u8; 16]>,
    pub closed_at_ns: i64,
}

impl Default for WriterOptions {
    fn default() -> Self {
        Self {
            block_size: DEFAULT_BLOCK_SIZE,
            chunk_size: DEFAULT_CHUNK_SIZE,
            envelope_target_size: DEFAULT_ENVELOPE_TARGET_SIZE,
            stripe_width: DEFAULT_STRIPE_WIDTH,
            volume_loss_tolerance: DEFAULT_VOLUME_LOSS_TOLERANCE,
            bit_rot_buffer_pct: DEFAULT_BIT_ROT_BUFFER_PCT,
            zstd_level: 3,
            jobs: default_jobs(),
            aead_algo: AeadAlgo::AesGcmSiv256,
            fec_data_shards: DEFAULT_FEC_DATA_SHARDS,
            fec_parity_shards: DEFAULT_FEC_PARITY_SHARDS,
            index_fec_data_shards: DEFAULT_INDEX_FEC_DATA_SHARDS,
            index_fec_parity_shards: DEFAULT_INDEX_FEC_PARITY_SHARDS,
            index_root_fec_data_shards: DEFAULT_INDEX_ROOT_FEC_DATA_SHARDS,
            index_root_fec_parity_shards: DEFAULT_INDEX_ROOT_FEC_PARITY_SHARDS,
            max_path_length: 4096,
            target_volume_size: None,
            archive_uuid: None,
            session_id: None,
            closed_at_ns: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootAuthWriterConfig<'a> {
    pub authenticator_id: u16,
    pub signer_identity_type: u16,
    pub signer_identity: &'a [u8],
    pub authenticator_value_length: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootAuthSigningRequest {
    pub root_auth_spec_id: [u8; 24],
    pub archive_uuid: [u8; 16],
    pub session_id: [u8; 16],
    pub archive_root: [u8; 32],
}

pub type RootAuthAuthenticator<'a> =
    dyn FnMut(&RootAuthSigningRequest) -> Result<Vec<u8>, FormatError> + 'a;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PortableModeOrigin {
    Native,
    #[default]
    Projected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortablePosixOwner {
    pub uid: u64,
    pub gid: u64,
    pub uname: Option<String>,
    pub gname: Option<String>,
}

/// Canonical v45 native metadata carried by the primary local-PAX record.
///
/// The writer validates the complete record set using the same parser as the
/// reader. Callers supply only profile-owned native keys; portable identity,
/// timestamps, paths, and the metadata declaration remain writer-owned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeAuxiliaryNameEncoding {
    None,
    Utf8,
    Utf16Le,
    Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeAuxiliaryMetadata {
    pub kind: String,
    pub profile: String,
    pub restore_class: RestoreClass,
    pub native: bool,
    pub name_encoding: NativeAuxiliaryNameEncoding,
    /// Exact decoded name bytes. UTF-16 names are little-endian code units.
    pub name: Vec<u8>,
    pub flags: u64,
    pub logical_size: u64,
    pub payload: Vec<u8>,
    pub meta: BTreeMap<String, Vec<u8>>,
    streamed_payload: Option<StreamedAuxiliaryPayload>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StreamedAuxiliaryPayload {
    stored_size: u64,
    sha256: [u8; 32],
    sparse_extents: Option<Vec<SparseExtent>>,
}

impl NativeAuxiliaryMetadata {
    pub fn new(
        kind: impl Into<String>,
        profile: impl Into<String>,
        restore_class: RestoreClass,
        payload: Vec<u8>,
    ) -> Self {
        let logical_size = payload.len() as u64;
        Self {
            kind: kind.into(),
            profile: profile.into(),
            restore_class,
            native: true,
            name_encoding: NativeAuxiliaryNameEncoding::None,
            name: Vec::new(),
            flags: 0,
            logical_size,
            payload,
            meta: BTreeMap::new(),
            streamed_payload: None,
        }
    }

    /// Declares a re-openable auxiliary payload supplied by
    /// [`RegularFileSource::open_auxiliary`].
    pub fn new_streamed(
        kind: impl Into<String>,
        profile: impl Into<String>,
        restore_class: RestoreClass,
        stored_size: u64,
        sha256: [u8; 32],
    ) -> Self {
        Self {
            kind: kind.into(),
            profile: profile.into(),
            restore_class,
            native: true,
            name_encoding: NativeAuxiliaryNameEncoding::None,
            name: Vec::new(),
            flags: 0,
            logical_size: stored_size,
            payload: Vec::new(),
            meta: BTreeMap::new(),
            streamed_payload: Some(StreamedAuxiliaryPayload {
                stored_size,
                sha256,
                sparse_extents: None,
            }),
        }
    }

    pub fn new_streamed_sparse(
        kind: impl Into<String>,
        profile: impl Into<String>,
        restore_class: RestoreClass,
        logical_size: u64,
        sparse_extents: Vec<SparseExtent>,
        sha256: [u8; 32],
    ) -> Result<Self, FormatError> {
        let map = encode_v45_sparse_map(&sparse_extents, logical_size)?;
        let extent_bytes = sparse_extent_bytes(&sparse_extents, logical_size)?;
        let stored_size = checked_u64_add(map.len() as u64, extent_bytes, "sparse auxiliary")?;
        Ok(Self {
            kind: kind.into(),
            profile: profile.into(),
            restore_class,
            native: true,
            name_encoding: NativeAuxiliaryNameEncoding::None,
            name: Vec::new(),
            flags: 1,
            logical_size,
            payload: Vec::new(),
            meta: BTreeMap::new(),
            streamed_payload: Some(StreamedAuxiliaryPayload {
                stored_size,
                sha256,
                sparse_extents: Some(sparse_extents),
            }),
        })
    }

    pub fn is_streamed(&self) -> bool {
        self.streamed_payload.is_some()
    }

    pub fn streamed_sparse_extents(&self) -> Option<&[SparseExtent]> {
        self.streamed_payload
            .as_ref()
            .and_then(|payload| payload.sparse_extents.as_deref())
    }

    pub fn stored_payload_size(&self) -> u64 {
        self.streamed_payload
            .as_ref()
            .map_or(self.payload.len() as u64, |payload| payload.stored_size)
    }

    fn sha256(&self) -> [u8; 32] {
        self.streamed_payload.as_ref().map_or_else(
            || Sha256::digest(&self.payload).into(),
            |payload| payload.sha256,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NativeFileMetadata {
    pub required_profiles: Vec<String>,
    pub optional_profiles: Vec<String>,
    pub primary_pax_records: BTreeMap<String, Vec<u8>>,
    pub auxiliary_records: Vec<NativeAuxiliaryMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortableFileMetadata {
    pub source_os: String,
    pub source_filesystem: String,
    pub mode_origin: PortableModeOrigin,
    pub posix_owner: Option<PortablePosixOwner>,
    pub attributes: Option<u32>,
    /// Creation (birth) time when available from the source filesystem.
    pub created: Option<ArchiveTimestamp>,
    /// Last access time when available from the source filesystem.
    pub accessed: Option<ArchiveTimestamp>,
    pub native: NativeFileMetadata,
}

/// Filesystem object kind emitted by a [`RegularFileSource`].
///
/// The trait predates revision-45 directory capture, so its historical name is
/// retained for API compatibility. Implementations may now describe a regular
/// file, explicit directory, or symbolic-link member.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SourceEntryKind {
    #[default]
    Regular,
    Directory,
    Symlink,
    Hardlink,
    CharacterDevice,
    BlockDevice,
    Fifo,
    /// Zero-data directory primary whose native metadata contains an exact,
    /// validated Windows mount-point reparse payload.
    ReparseDirectory,
    /// Zero-data regular primary whose native metadata contains an exact opaque Windows reparse
    /// payload that has no safe portable projection.
    ReparseRegular,
}

impl Default for PortableFileMetadata {
    fn default() -> Self {
        Self {
            source_os: "other".into(),
            source_filesystem: "unknown".into(),
            mode_origin: PortableModeOrigin::Projected,
            posix_owner: None,
            attributes: None,
            created: None,
            accessed: None,
            native: NativeFileMetadata::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegularFile<'a> {
    pub path: &'a str,
    pub contents: &'a [u8],
    pub mode: u32,
    pub mtime: ArchiveTimestamp,
    pub portable_metadata: PortableFileMetadata,
}

impl<'a> RegularFile<'a> {
    pub fn new(path: &'a str, contents: &'a [u8]) -> Self {
        Self {
            path,
            contents,
            mode: 0o644,
            mtime: ArchiveTimestamp::UNIX_EPOCH,
            portable_metadata: PortableFileMetadata::default(),
        }
    }
}

/// Re-openable source for one primary archive member.
///
/// The writer may replan when options such as target volume sizing need another
/// pass, so implementations must return a fresh reader from each `open` call.
/// Directory sources return an empty reader and a zero `file_data_size`.
pub trait RegularFileSource {
    fn archive_path(&self) -> &str;
    fn entry_kind(&self) -> SourceEntryKind {
        SourceEntryKind::Regular
    }
    /// Link target bytes for a symbolic-link or hardlink source.
    fn link_target(&self) -> Option<&[u8]> {
        None
    }
    fn file_data_size(&self) -> u64;
    /// Canonical allocated extents for a sparse regular file.
    ///
    /// `file_data_size` remains the logical size. When this returns `Some`,
    /// `open` must yield exactly the concatenated extent bytes in ascending map
    /// order. `Some(&[])` represents an all-hole sparse file.
    fn sparse_extents(&self) -> Option<&[SparseExtent]> {
        None
    }
    fn mode(&self) -> u32;
    fn mtime(&self) -> ArchiveTimestamp;
    fn portable_metadata(&self) -> PortableFileMetadata {
        PortableFileMetadata::default()
    }
    fn open(&self) -> Result<Box<dyn Read + '_>, ArchiveWriteError>;
    /// Opens a streamed auxiliary payload by its canonical ordinal.
    ///
    /// The default serves inline payloads. Sources using
    /// [`NativeAuxiliaryMetadata::new_streamed`] must override this method and
    /// return a fresh reader on every call.
    fn open_auxiliary(&self, ordinal: usize) -> Result<Box<dyn Read + '_>, ArchiveWriteError> {
        let metadata = self.portable_metadata();
        let record =
            metadata
                .native
                .auxiliary_records
                .get(ordinal)
                .ok_or(FormatError::WriterInvariant(
                    "auxiliary source ordinal is missing",
                ))?;
        if record.is_streamed() {
            return Err(FormatError::WriterUnsupported(
                "streamed auxiliary source did not implement open_auxiliary",
            )
            .into());
        }
        Ok(Box::new(Cursor::new(record.payload.clone())))
    }
}

impl RegularFileSource for RegularFile<'_> {
    fn archive_path(&self) -> &str {
        self.path
    }

    fn file_data_size(&self) -> u64 {
        self.contents.len() as u64
    }

    fn mode(&self) -> u32 {
        self.mode
    }

    fn mtime(&self) -> ArchiveTimestamp {
        self.mtime
    }

    fn portable_metadata(&self) -> PortableFileMetadata {
        self.portable_metadata.clone()
    }

    fn open(&self) -> Result<Box<dyn Read + '_>, ArchiveWriteError> {
        Ok(Box::new(Cursor::new(self.contents)))
    }
}

/// One observable phase of archive creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ArchiveWritePhase {
    /// Read and compress source payloads to produce a deterministic archive plan.
    PlanningPayload,
    /// Build index and other metadata plans after the payload layout is known.
    PlanningMetadata,
    /// Read, compress, protect, and write the planned payload blocks.
    EmittingPayload,
    /// Protect and write indexes, recovery metadata, footers, and trailers.
    EmittingMetadata,
}

/// Receives phase-native progress while the archive writer consumes file data.
///
/// Multi-pass writers report source bytes separately for planning and emission.
/// Automatic volume-size replanning may start `PlanningPayload` and
/// `PlanningMetadata` more than once. Each call to
/// [`ArchiveWriteProgressSink::phase_started`] begins a new phase occurrence;
/// within that occurrence, one archive member reports at most its primary
/// source bytes plus its declared streamed auxiliary payload bytes.
pub trait ArchiveWriteProgressSink {
    /// Reports that the writer entered a new creation phase.
    fn phase_started(&mut self, phase: ArchiveWritePhase);

    /// Reports source bytes consumed within one specific writer phase.
    fn source_bytes_read(&mut self, phase: ArchiveWritePhase, archive_path: &str, bytes: u64);
}

pub(crate) struct SourceProgressState<'a> {
    sink: &'a mut dyn ArchiveWriteProgressSink,
    active_phase: Option<ArchiveWritePhase>,
    phase_reported_by_path: BTreeMap<String, u64>,
}

impl<'a> SourceProgressState<'a> {
    fn new(sink: &'a mut dyn ArchiveWriteProgressSink) -> Self {
        Self {
            sink,
            active_phase: None,
            phase_reported_by_path: BTreeMap::new(),
        }
    }

    fn start_phase(&mut self, phase: ArchiveWritePhase) {
        self.active_phase = Some(phase);
        self.phase_reported_by_path.clear();
        self.sink.phase_started(phase);
    }

    fn record(&mut self, archive_path: &str, bytes: u64, file_data_size: u64) {
        if bytes == 0 || file_data_size == 0 {
            return;
        }
        if let Some(phase) = self.active_phase {
            let phase_reported = self
                .phase_reported_by_path
                .entry(archive_path.to_owned())
                .or_default();
            let capped_next = phase_reported.saturating_add(bytes).min(file_data_size);
            let delta = capped_next.saturating_sub(*phase_reported);
            if delta > 0 {
                *phase_reported = capped_next;
                self.sink.source_bytes_read(phase, archive_path, delta);
            }
        }
    }
}

struct ProgressRegularFileSource<'a, S> {
    inner: &'a S,
    source_bytes: u64,
    state: Rc<RefCell<SourceProgressState<'a>>>,
}

impl<S: RegularFileSource> RegularFileSource for ProgressRegularFileSource<'_, S> {
    fn archive_path(&self) -> &str {
        self.inner.archive_path()
    }

    fn entry_kind(&self) -> SourceEntryKind {
        self.inner.entry_kind()
    }

    fn link_target(&self) -> Option<&[u8]> {
        self.inner.link_target()
    }

    fn file_data_size(&self) -> u64 {
        self.inner.file_data_size()
    }

    fn sparse_extents(&self) -> Option<&[SparseExtent]> {
        self.inner.sparse_extents()
    }

    fn mode(&self) -> u32 {
        self.inner.mode()
    }

    fn mtime(&self) -> ArchiveTimestamp {
        self.inner.mtime()
    }

    fn portable_metadata(&self) -> PortableFileMetadata {
        self.inner.portable_metadata()
    }

    fn open(&self) -> Result<Box<dyn Read + '_>, ArchiveWriteError> {
        Ok(Box::new(SourceProgressReader {
            inner: self.inner.open()?,
            archive_path: self.inner.archive_path().to_owned(),
            source_bytes: self.source_bytes,
            state: Rc::clone(&self.state),
        }))
    }

    fn open_auxiliary(&self, ordinal: usize) -> Result<Box<dyn Read + '_>, ArchiveWriteError> {
        Ok(Box::new(SourceProgressReader {
            inner: self.inner.open_auxiliary(ordinal)?,
            archive_path: self.inner.archive_path().to_owned(),
            source_bytes: self.source_bytes,
            state: Rc::clone(&self.state),
        }))
    }
}

struct SourceProgressReader<'a> {
    inner: Box<dyn Read + 'a>,
    archive_path: String,
    source_bytes: u64,
    state: Rc<RefCell<SourceProgressState<'a>>>,
}

impl Read for SourceProgressReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let bytes = self.inner.read(buf)?;
        self.state
            .borrow_mut()
            .record(&self.archive_path, bytes as u64, self.source_bytes);
        Ok(bytes)
    }
}

pub(crate) type SourceProgressHandle<'a> = Rc<RefCell<SourceProgressState<'a>>>;

fn progress_sources<'a, S: RegularFileSource>(
    files: &'a [S],
    sink: &'a mut dyn ArchiveWriteProgressSink,
) -> (
    Vec<ProgressRegularFileSource<'a, S>>,
    SourceProgressHandle<'a>,
) {
    let state = Rc::new(RefCell::new(SourceProgressState::new(sink)));
    let sources = files
        .iter()
        .map(|inner| {
            let source_bytes = inner
                .portable_metadata()
                .native
                .auxiliary_records
                .iter()
                .filter(|record| record.is_streamed())
                .fold(inner.file_data_size(), |total, record| {
                    total.saturating_add(record.stored_payload_size())
                });
            ProgressRegularFileSource {
                inner,
                source_bytes,
                state: Rc::clone(&state),
            }
        })
        .collect();
    (sources, state)
}

/// Streaming destination for archive volumes and optional bootstrap sidecar.
///
/// Calls arrive in archive order for each volume, but records are interleaved
/// across volumes according to the archive stripe layout.
pub trait ArchiveWriteSink {
    fn begin_archive(&mut self, volume_count: usize) -> Result<(), ArchiveWriteError>;
    fn write_volume(&mut self, volume_index: usize, bytes: &[u8]) -> Result<(), ArchiveWriteError>;
    fn write_bootstrap_sidecar(&mut self, bytes: &[u8]) -> Result<(), ArchiveWriteError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenArchiveSummary {
    pub volume_count: usize,
    pub archive_bytes: u64,
    pub bootstrap_sidecar_bytes: u64,
    pub archive_uuid: [u8; 16],
    pub session_id: [u8; 16],
    pub timings: WriterTimings,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WriterTimings {
    pub total: Duration,
    pub plan_payload: Duration,
    pub plan_metadata: Duration,
    pub emit_payload: Duration,
    pub emit_metadata: Duration,
}

impl WriterTimings {
    fn add_assign(&mut self, other: Self) {
        self.total += other.total;
        self.plan_payload += other.plan_payload;
        self.plan_metadata += other.plan_metadata;
        self.emit_payload += other.emit_payload;
        self.emit_metadata += other.emit_metadata;
    }
}

/// In-memory sink used by the compatibility writer APIs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemoryArchiveSink {
    pub volumes: Vec<Vec<u8>>,
    pub bootstrap_sidecar: Vec<u8>,
}

impl ArchiveWriteSink for MemoryArchiveSink {
    fn begin_archive(&mut self, volume_count: usize) -> Result<(), ArchiveWriteError> {
        self.volumes = vec![Vec::new(); volume_count];
        self.bootstrap_sidecar.clear();
        Ok(())
    }

    fn write_volume(&mut self, volume_index: usize, bytes: &[u8]) -> Result<(), ArchiveWriteError> {
        let volume = self
            .volumes
            .get_mut(volume_index)
            .ok_or(FormatError::WriterInvariant(
                "volume sink index is out of bounds",
            ))?;
        volume.extend_from_slice(bytes);
        Ok(())
    }

    fn write_bootstrap_sidecar(&mut self, bytes: &[u8]) -> Result<(), ArchiveWriteError> {
        self.bootstrap_sidecar.extend_from_slice(bytes);
        Ok(())
    }
}

/// Completed archive artifacts produced by the compatibility writer APIs.
///
/// APIs returning this value build all volume bytes before returning. Use the
/// sink writer when archive bytes should be delivered incrementally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenArchive {
    pub bytes: Vec<u8>,
    pub volumes: Vec<Vec<u8>>,
    pub bootstrap_sidecar: Vec<u8>,
    pub archive_uuid: [u8; 16],
    pub session_id: [u8; 16],
    pub timings: WriterTimings,
}

#[derive(Debug, Clone)]
struct TarMember {
    path: Vec<u8>,
    entry_kind: SourceEntryKind,
    link_target: Option<Vec<u8>>,
    tar_member_group_start: u64,
    tar_member_group_size: u64,
    file_data_size: u64,
    sparse_extents: Option<Vec<SparseExtent>>,
    mode: u32,
    mtime: ArchiveTimestamp,
    portable_metadata: PortableFileMetadata,
}

#[derive(Debug, Clone)]
struct PayloadFrame {
    frame_index: u64,
    envelope_index: u64,
    member_index: usize,
    offset_in_envelope: u32,
    compressed_size: u32,
    decompressed_size: u32,
    flags: u32,
    tar_stream_offset: u64,
}

#[derive(Debug, Clone)]
struct FileRow {
    path_hash: [u8; 8],
    path: Vec<u8>,
    member_index: usize,
    member: TarMember,
}

#[derive(Debug, Clone)]
struct PlannedIndexShard {
    shard_index: u64,
    plaintext: Vec<u8>,
    file_count: u32,
    first_path_hash: [u8; 8],
    last_path_hash: [u8; 8],
}

#[derive(Debug, Clone)]
struct PlannedDirectoryHintShard {
    hint_shard_index: u64,
    plaintext: Vec<u8>,
    entry_count: u64,
    first_dir_hash: [u8; 8],
    last_dir_hash: [u8; 8],
}

#[derive(Debug, Clone)]
#[cfg(test)]
struct PayloadEnvelope {
    envelope_index: u64,
    plaintext: Vec<u8>,
}

#[derive(Debug, Clone)]
struct PayloadObject {
    envelope_index: u64,
    plaintext_size: u32,
    object: ObjectExtent,
}

#[derive(Debug, Clone)]
struct EncryptedObject {
    first_block_index: u64,
    data_block_count: u32,
    parity_block_count: u32,
    encrypted_size: u32,
    records: Vec<BlockRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ObjectExtent {
    first_block_index: u64,
    data_block_count: u32,
    parity_block_count: u32,
    encrypted_size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PlannedEncryptedObject {
    data_block_count: u32,
    parity_block_count: u32,
    encrypted_size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MetadataObjectKind {
    IndexRoot,
    Dictionary,
}

impl MetadataObjectKind {
    fn too_large_error(self) -> FormatError {
        match self {
            Self::IndexRoot => FormatError::WriterUnsupported("IndexRoot too large"),
            Self::Dictionary => FormatError::WriterUnsupported("dictionary object too large"),
        }
    }
}

impl ObjectExtent {
    fn new(first_block_index: u64, plan: PlannedEncryptedObject) -> Result<Self, FormatError> {
        Ok(Self {
            first_block_index,
            data_block_count: plan.data_block_count,
            parity_block_count: plan.parity_block_count,
            encrypted_size: plan.encrypted_size,
        })
    }

    fn next_block_index(self) -> Result<u64, FormatError> {
        checked_u64_add(
            self.first_block_index,
            self.data_block_count as u64 + self.parity_block_count as u64,
            "next_block_index",
        )
    }
}

impl From<&EncryptedObject> for ObjectExtent {
    fn from(object: &EncryptedObject) -> Self {
        Self {
            first_block_index: object.first_block_index,
            data_block_count: object.data_block_count,
            parity_block_count: object.parity_block_count,
            encrypted_size: object.encrypted_size,
        }
    }
}

#[derive(Debug, Clone)]
struct PlannedDirectoryHintObject {
    hint_shard_index: u64,
    compressed: Vec<u8>,
    extent: ObjectExtent,
}

struct WriterPlan {
    options: WriterOptions,
    archive_uuid: [u8; 16],
    session_id: [u8; 16],
    crypto_header: Vec<u8>,
    tar_members: Vec<TarMember>,
    frames: Vec<PayloadFrame>,
    payload_objects: Vec<PayloadObject>,
    index_root_plaintext: Vec<u8>,
    compressed_index_root: Vec<u8>,
    index_root_extent: ObjectExtent,
    index_shard_objects: Vec<PlannedIndexShardObject>,
    shard_entries: Vec<ShardEntry>,
    volume_format_rev: u16,
    compressed_dictionary: Option<Vec<u8>>,
    dictionary_extent: Option<(ObjectExtent, u32)>,
    directory_hint_objects: Vec<PlannedDirectoryHintObject>,
    directory_hint_entries: Vec<DirectoryHintShardEntry>,
    root_auth_footer_length: Option<u32>,
    key_wrap_table: Option<Vec<u8>>,
    block_records_offset: u64,
    total_block_count: u64,
}

struct PlannedIndexShardObject {
    shard_index: u64,
    compressed: Vec<u8>,
    extent: ObjectExtent,
}

struct PayloadPlanning {
    tar_members: Vec<TarMember>,
    frames: Vec<PayloadFrame>,
    payload_objects: Vec<PayloadObject>,
    payload_block_count: u64,
    tar_total_size: u64,
    content_sha256: [u8; 32],
}

struct PayloadEnvelopeBuilder {
    envelope_index: u64,
    plaintext: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
struct PayloadFrameMetadataInput {
    frame_index: u64,
    envelope_index: u64,
    member_index: usize,
    offset_in_envelope: u32,
    compressed_size: usize,
    decompressed_size: usize,
    member_start: u64,
    member_offset: u64,
    member_group_size: u64,
}

fn payload_envelope_needs_flush(
    envelope: &PayloadEnvelopeBuilder,
    frame_len: usize,
    options: WriterOptions,
) -> Result<bool, FormatError> {
    let next_len = checked_usize_add(envelope.plaintext.len(), frame_len, "payload")?;
    Ok(!envelope.plaintext.is_empty()
        && (next_len > options.envelope_target_size as usize
            || !payload_object_can_fit(next_len, options)?))
}

fn payload_frame_metadata(input: PayloadFrameMetadataInput) -> Result<PayloadFrame, FormatError> {
    let mut flags = 0u32;
    if input.member_offset == 0 {
        flags |= 0x0000_0001;
    }
    if checked_u64_add(
        input.member_offset,
        input.decompressed_size as u64,
        "payload chunk",
    )? == input.member_group_size
    {
        flags |= 0x0000_0002;
    }
    Ok(PayloadFrame {
        frame_index: input.frame_index,
        envelope_index: input.envelope_index,
        member_index: input.member_index,
        offset_in_envelope: input.offset_in_envelope,
        compressed_size: u32_len(input.compressed_size, "FrameEntry.compressed_size")?,
        decompressed_size: u32_len(input.decompressed_size, "FrameEntry.decompressed_size")?,
        flags,
        tar_stream_offset: checked_u64_add(
            input.member_start,
            input.member_offset,
            "PayloadFrame.tar_stream_offset",
        )?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StreamingRegularMember {
    pub archive_path: Vec<u8>,
    pub entry_kind: SourceEntryKind,
    pub link_target: Option<Vec<u8>>,
    pub file_data_size: u64,
    pub sparse_extents: Option<Vec<SparseExtent>>,
    pub mode: u32,
    pub mtime: ArchiveTimestamp,
    pub portable_metadata: PortableFileMetadata,
}

struct WriterEmissionState {
    volume_headers: Vec<[u8; VOLUME_HEADER_LEN]>,
    bytes_written: Vec<u64>,
    record_counts: Vec<u64>,
    volume_format_rev: u16,
    data_leaf_hashes: Option<Vec<(u64, [u8; 32])>>,
    next_block_index: u64,
}

pub(crate) struct StreamingArchiveWriter<'a, O: ArchiveWriteSink> {
    sink: &'a mut O,
    options: WriterOptions,
    archive_uuid: [u8; 16],
    session_id: [u8; 16],
    crypto_header: Vec<u8>,
    subkeys: Subkeys,
    tar_members: Vec<TarMember>,
    frames: Vec<PayloadFrame>,
    payload_objects: Vec<PayloadObject>,
    payload_block_count: u64,
    tar_total_size: u64,
    hasher: Sha256,
    next_frame_index: u64,
    envelope: PayloadEnvelopeBuilder,
    emission_state: WriterEmissionState,
}

pub fn write_archive(
    files: &[RegularFile<'_>],
    master_key: &MasterKey,
    options: WriterOptions,
) -> Result<WrittenArchive, FormatError> {
    write_archive_inner(
        files,
        master_key,
        options,
        None,
        &KdfParams::Raw,
        None,
        None,
        None,
    )
}

pub fn write_archive_unencrypted(
    files: &[RegularFile<'_>],
    mut options: WriterOptions,
) -> Result<WrittenArchive, FormatError> {
    options.aead_algo = AeadAlgo::None;
    let placeholder = MasterKey::from_raw_key(&[0; 32])?;
    write_archive_inner(
        files,
        &placeholder,
        options,
        None,
        &KdfParams::None,
        None,
        None,
        None,
    )
}

pub fn write_archive_with_kdf(
    files: &[RegularFile<'_>],
    master_key: &MasterKey,
    options: WriterOptions,
    kdf_params: &KdfParams,
) -> Result<WrittenArchive, FormatError> {
    write_archive_inner(
        files, master_key, options, None, kdf_params, None, None, None,
    )
}

pub fn write_archive_with_recipient_wrap_records(
    files: &[RegularFile<'_>],
    master_key: &MasterKey,
    options: WriterOptions,
    records: Vec<RecipientRecordV1>,
) -> Result<WrittenArchive, FormatError> {
    let kdf_params = recipient_wrap_kdf_params_for_record_count(records.len())?;
    let key_wrap_records = KeyWrapRecordSource::fixed(records);
    write_archive_inner(
        files,
        master_key,
        options,
        None,
        &kdf_params,
        None,
        None,
        Some(&key_wrap_records),
    )
}

pub fn write_archive_with_root_auth_and_recipient_wrap_records<F>(
    files: &[RegularFile<'_>],
    master_key: &MasterKey,
    options: WriterOptions,
    records: Vec<RecipientRecordV1>,
    root_auth: RootAuthWriterConfig<'_>,
    mut authenticator: F,
) -> Result<WrittenArchive, FormatError>
where
    F: FnMut(&RootAuthSigningRequest) -> Result<Vec<u8>, FormatError>,
{
    let kdf_params = recipient_wrap_kdf_params_for_record_count(records.len())?;
    let key_wrap_records = KeyWrapRecordSource::fixed(records);
    write_archive_inner(
        files,
        master_key,
        options,
        None,
        &kdf_params,
        Some(root_auth),
        Some(&mut authenticator),
        Some(&key_wrap_records),
    )
}

pub fn write_archive_with_root_auth<F>(
    files: &[RegularFile<'_>],
    master_key: &MasterKey,
    options: WriterOptions,
    root_auth: RootAuthWriterConfig<'_>,
    mut authenticator: F,
) -> Result<WrittenArchive, FormatError>
where
    F: FnMut(&RootAuthSigningRequest) -> Result<Vec<u8>, FormatError>,
{
    let kdf_params = if options.aead_algo.is_encrypted() {
        KdfParams::Raw
    } else {
        KdfParams::None
    };
    write_archive_inner(
        files,
        master_key,
        options,
        None,
        &kdf_params,
        Some(root_auth),
        Some(&mut authenticator),
        None,
    )
}

pub fn write_archive_with_root_auth_and_kdf<F>(
    files: &[RegularFile<'_>],
    master_key: &MasterKey,
    options: WriterOptions,
    kdf_params: &KdfParams,
    root_auth: RootAuthWriterConfig<'_>,
    mut authenticator: F,
) -> Result<WrittenArchive, FormatError>
where
    F: FnMut(&RootAuthSigningRequest) -> Result<Vec<u8>, FormatError>,
{
    write_archive_inner(
        files,
        master_key,
        options,
        None,
        kdf_params,
        Some(root_auth),
        Some(&mut authenticator),
        None,
    )
}

pub fn write_archive_with_dictionary_and_root_auth<F>(
    files: &[RegularFile<'_>],
    master_key: &MasterKey,
    options: WriterOptions,
    dictionary: &[u8],
    root_auth: RootAuthWriterConfig<'_>,
    mut authenticator: F,
) -> Result<WrittenArchive, FormatError>
where
    F: FnMut(&RootAuthSigningRequest) -> Result<Vec<u8>, FormatError>,
{
    write_archive_inner(
        files,
        master_key,
        options,
        Some(dictionary),
        &KdfParams::Raw,
        Some(root_auth),
        Some(&mut authenticator),
        None,
    )
}

pub fn write_archive_with_dictionary_kdf_and_root_auth<F>(
    files: &[RegularFile<'_>],
    master_key: &MasterKey,
    options: WriterOptions,
    dictionary: &[u8],
    kdf_params: &KdfParams,
    root_auth: RootAuthWriterConfig<'_>,
    mut authenticator: F,
) -> Result<WrittenArchive, FormatError>
where
    F: FnMut(&RootAuthSigningRequest) -> Result<Vec<u8>, FormatError>,
{
    write_archive_inner(
        files,
        master_key,
        options,
        Some(dictionary),
        kdf_params,
        Some(root_auth),
        Some(&mut authenticator),
        None,
    )
}

pub fn write_archive_with_dictionary(
    files: &[RegularFile<'_>],
    master_key: &MasterKey,
    options: WriterOptions,
    dictionary: &[u8],
) -> Result<WrittenArchive, FormatError> {
    if dictionary.is_empty() {
        return Err(FormatError::WriterUnsupported(
            "dictionary archives require a non-empty dictionary",
        ));
    }
    if files.is_empty() {
        return Err(FormatError::WriterUnsupported(
            "dictionary archives require at least one file",
        ));
    }
    if dictionary.len() > u32::MAX as usize {
        return Err(FormatError::WriterUnsupported(
            "dictionary decompressed size exceeds u32",
        ));
    }
    write_archive_inner(
        files,
        master_key,
        options,
        Some(dictionary),
        &KdfParams::Raw,
        None,
        None,
        None,
    )
}

pub fn write_archive_with_dictionary_and_kdf(
    files: &[RegularFile<'_>],
    master_key: &MasterKey,
    options: WriterOptions,
    dictionary: &[u8],
    kdf_params: &KdfParams,
) -> Result<WrittenArchive, FormatError> {
    if dictionary.is_empty() {
        return Err(FormatError::WriterUnsupported(
            "dictionary archives require a non-empty dictionary",
        ));
    }
    if files.is_empty() {
        return Err(FormatError::WriterUnsupported(
            "dictionary archives require at least one file",
        ));
    }
    if dictionary.len() > u32::MAX as usize {
        return Err(FormatError::WriterUnsupported(
            "dictionary decompressed size exceeds u32",
        ));
    }
    write_archive_inner(
        files,
        master_key,
        options,
        Some(dictionary),
        kdf_params,
        None,
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn write_archive_sources_to_sink<S, O>(
    files: &[S],
    master_key: &MasterKey,
    options: WriterOptions,
    dictionary: Option<&[u8]>,
    kdf_params: &KdfParams,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    authenticator: Option<&mut RootAuthAuthenticator<'_>>,
    sink: &mut O,
) -> Result<WrittenArchiveSummary, ArchiveWriteError>
where
    S: RegularFileSource,
    O: ArchiveWriteSink,
{
    write_archive_stream_inner(
        files,
        master_key,
        options,
        dictionary,
        kdf_params,
        root_auth,
        authenticator,
        None,
        sink,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn write_archive_sources_to_sink_with_progress<S, O>(
    files: &[S],
    master_key: &MasterKey,
    options: WriterOptions,
    dictionary: Option<&[u8]>,
    kdf_params: &KdfParams,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    authenticator: Option<&mut RootAuthAuthenticator<'_>>,
    sink: &mut O,
    progress: &mut dyn ArchiveWriteProgressSink,
) -> Result<WrittenArchiveSummary, ArchiveWriteError>
where
    S: RegularFileSource,
    O: ArchiveWriteSink,
{
    let (progress_files, progress_state) = progress_sources(files, progress);
    write_archive_stream_inner(
        &progress_files,
        master_key,
        options,
        dictionary,
        kdf_params,
        root_auth,
        authenticator,
        None,
        sink,
        Some(&progress_state),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn write_archive_sources_to_sink_single_pass<S, O>(
    files: &[S],
    master_key: &MasterKey,
    options: WriterOptions,
    kdf_params: &KdfParams,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    authenticator: Option<&mut RootAuthAuthenticator<'_>>,
    sink: &mut O,
) -> Result<WrittenArchiveSummary, ArchiveWriteError>
where
    S: RegularFileSource,
    O: ArchiveWriteSink,
{
    write_single_pass_archive_to_sink(
        master_key,
        options,
        kdf_params,
        root_auth,
        authenticator,
        None,
        sink,
        None,
        |writer| {
            for file in files {
                writer.write_regular_member_from_source(file)?;
            }
            Ok(())
        },
    )
}

#[allow(clippy::too_many_arguments)]
pub fn write_archive_sources_to_sink_single_pass_with_recipient_wrap_records<S, O>(
    files: &[S],
    master_key: &MasterKey,
    options: WriterOptions,
    records: Vec<RecipientRecordV1>,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    authenticator: Option<&mut RootAuthAuthenticator<'_>>,
    sink: &mut O,
) -> Result<WrittenArchiveSummary, ArchiveWriteError>
where
    S: RegularFileSource,
    O: ArchiveWriteSink,
{
    let kdf_params = recipient_wrap_kdf_params_for_record_count(records.len())?;
    let key_wrap_records = KeyWrapRecordSource::fixed(records);
    write_single_pass_archive_to_sink(
        master_key,
        options,
        &kdf_params,
        root_auth,
        authenticator,
        Some(&key_wrap_records),
        sink,
        None,
        |writer| {
            for file in files {
                writer.write_regular_member_from_source(file)?;
            }
            Ok(())
        },
    )
}

#[allow(clippy::too_many_arguments)]
pub fn write_archive_sources_to_sink_single_pass_with_progress<S, O>(
    files: &[S],
    master_key: &MasterKey,
    options: WriterOptions,
    kdf_params: &KdfParams,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    authenticator: Option<&mut RootAuthAuthenticator<'_>>,
    sink: &mut O,
    progress: &mut dyn ArchiveWriteProgressSink,
) -> Result<WrittenArchiveSummary, ArchiveWriteError>
where
    S: RegularFileSource,
    O: ArchiveWriteSink,
{
    let (progress_files, progress_state) = progress_sources(files, progress);
    write_single_pass_archive_to_sink(
        master_key,
        options,
        kdf_params,
        root_auth,
        authenticator,
        None,
        sink,
        Some(&progress_state),
        |writer| {
            for file in &progress_files {
                writer.write_regular_member_from_source(file)?;
            }
            Ok(())
        },
    )
}

#[allow(clippy::too_many_arguments)]
pub fn write_archive_sources_to_sink_ordered_parallel<S, O>(
    files: &[S],
    master_key: &MasterKey,
    options: WriterOptions,
    kdf_params: &KdfParams,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    authenticator: Option<&mut RootAuthAuthenticator<'_>>,
    sink: &mut O,
) -> Result<WrittenArchiveSummary, ArchiveWriteError>
where
    S: RegularFileSource,
    O: ArchiveWriteSink,
{
    write_ordered_parallel_archive_to_sink(
        files,
        master_key,
        options,
        kdf_params,
        root_auth,
        authenticator,
        None,
        sink,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn write_archive_sources_to_sink_ordered_parallel_with_recipient_wrap_records<S, O>(
    files: &[S],
    master_key: &MasterKey,
    options: WriterOptions,
    records: Vec<RecipientRecordV1>,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    authenticator: Option<&mut RootAuthAuthenticator<'_>>,
    sink: &mut O,
) -> Result<WrittenArchiveSummary, ArchiveWriteError>
where
    S: RegularFileSource,
    O: ArchiveWriteSink,
{
    let kdf_params = recipient_wrap_kdf_params_for_record_count(records.len())?;
    let key_wrap_records = KeyWrapRecordSource::fixed(records);
    write_ordered_parallel_archive_to_sink(
        files,
        master_key,
        options,
        &kdf_params,
        root_auth,
        authenticator,
        Some(&key_wrap_records),
        sink,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn write_archive_sources_to_sink_ordered_parallel_with_recipient_wrap_records_and_progress<
    S,
    O,
>(
    files: &[S],
    master_key: &MasterKey,
    options: WriterOptions,
    records: Vec<RecipientRecordV1>,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    authenticator: Option<&mut RootAuthAuthenticator<'_>>,
    sink: &mut O,
    progress: &mut dyn ArchiveWriteProgressSink,
) -> Result<WrittenArchiveSummary, ArchiveWriteError>
where
    S: RegularFileSource,
    O: ArchiveWriteSink,
{
    let kdf_params = recipient_wrap_kdf_params_for_record_count(records.len())?;
    let key_wrap_records = KeyWrapRecordSource::fixed(records);
    let (progress_files, progress_state) = progress_sources(files, progress);
    write_ordered_parallel_archive_to_sink(
        &progress_files,
        master_key,
        options,
        &kdf_params,
        root_auth,
        authenticator,
        Some(&key_wrap_records),
        sink,
        Some(&progress_state),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn write_archive_sources_to_sink_ordered_parallel_with_progress<S, O>(
    files: &[S],
    master_key: &MasterKey,
    options: WriterOptions,
    kdf_params: &KdfParams,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    authenticator: Option<&mut RootAuthAuthenticator<'_>>,
    sink: &mut O,
    progress: &mut dyn ArchiveWriteProgressSink,
) -> Result<WrittenArchiveSummary, ArchiveWriteError>
where
    S: RegularFileSource,
    O: ArchiveWriteSink,
{
    let (progress_files, progress_state) = progress_sources(files, progress);
    write_ordered_parallel_archive_to_sink(
        &progress_files,
        master_key,
        options,
        kdf_params,
        root_auth,
        authenticator,
        None,
        sink,
        Some(&progress_state),
    )
}

#[allow(clippy::too_many_arguments)]
fn write_archive_inner(
    files: &[RegularFile<'_>],
    master_key: &MasterKey,
    options: WriterOptions,
    dictionary: Option<&[u8]>,
    kdf_params: &KdfParams,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    authenticator: Option<&mut RootAuthAuthenticator<'_>>,
    key_wrap_records: Option<&KeyWrapRecordSource>,
) -> Result<WrittenArchive, FormatError> {
    let mut sink = MemoryArchiveSink::default();
    let summary = write_archive_stream_inner(
        files,
        master_key,
        options,
        dictionary,
        kdf_params,
        root_auth,
        authenticator,
        key_wrap_records,
        &mut sink,
        None,
    )
    .map_err(format_error_from_archive_write_error)?;
    Ok(WrittenArchive {
        bytes: sink
            .volumes
            .first()
            .cloned()
            .ok_or(FormatError::WriterInvariant("no volumes emitted"))?,
        volumes: sink.volumes,
        bootstrap_sidecar: sink.bootstrap_sidecar,
        archive_uuid: summary.archive_uuid,
        session_id: summary.session_id,
        timings: summary.timings,
    })
}

fn format_error_from_archive_write_error(error: ArchiveWriteError) -> FormatError {
    match error {
        ArchiveWriteError::Format(error) => error,
        ArchiveWriteError::Io(_) => {
            FormatError::WriterInvariant("in-memory archive writer returned I/O")
        }
    }
}

fn writer_subkeys(
    master_key: &MasterKey,
    aead_algo: AeadAlgo,
    archive_uuid: &[u8; 16],
    session_id: &[u8; 16],
) -> Result<Subkeys, FormatError> {
    if aead_algo.is_encrypted() {
        Subkeys::derive(master_key, archive_uuid, session_id)
    } else {
        Ok(Subkeys::unencrypted_placeholder())
    }
}

#[allow(clippy::too_many_arguments)]
fn write_archive_stream_inner<S, O>(
    files: &[S],
    master_key: &MasterKey,
    options: WriterOptions,
    dictionary: Option<&[u8]>,
    kdf_params: &KdfParams,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    mut authenticator: Option<&mut RootAuthAuthenticator<'_>>,
    key_wrap_records: Option<&KeyWrapRecordSource>,
    sink: &mut O,
    progress: Option<&SourceProgressHandle<'_>>,
) -> Result<WrittenArchiveSummary, ArchiveWriteError>
where
    S: RegularFileSource,
    O: ArchiveWriteSink,
{
    let total_started = Instant::now();
    validate_dictionary_inputs(files.is_empty(), dictionary)?;
    if let Some(root_auth) = root_auth {
        validate_root_auth_writer_config(root_auth)?;
    }
    let mut requested_options = options;
    if requested_options.target_volume_size.is_some() {
        requested_options.stripe_width = requested_options
            .stripe_width
            .max(requested_options.volume_loss_tolerance as u32 + 1);
    }
    let archive_uuid = requested_options
        .archive_uuid
        .unwrap_or_else(|| *Uuid::new_v4().as_bytes());
    let session_id = requested_options
        .session_id
        .unwrap_or_else(|| *Uuid::new_v4().as_bytes());
    let mut accumulated_timings = WriterTimings::default();

    loop {
        let planned_options = plan_writer_options(requested_options)?;
        start_write_phase(progress, ArchiveWritePhase::PlanningPayload);
        let timed_plan = build_writer_plan(
            files,
            master_key,
            planned_options,
            dictionary,
            kdf_params,
            key_wrap_records,
            archive_uuid,
            session_id,
            root_auth,
            progress,
        )?;
        accumulated_timings.add_assign(timed_plan.timings);
        let plan = timed_plan.plan;
        if let Some(target_volume_size) = planned_options.target_volume_size {
            let required = required_stripe_width_for_plan(&plan, master_key, target_volume_size)?;
            if required > planned_options.stripe_width {
                requested_options.stripe_width = required;
                continue;
            }
        }
        start_write_phase(progress, ArchiveWritePhase::EmittingPayload);
        let mut summary = emit_writer_plan(
            files,
            master_key,
            dictionary,
            root_auth,
            authenticator.take(),
            plan,
            sink,
            progress,
        )?;
        summary.timings.add_assign(accumulated_timings);
        summary.timings.total = total_started.elapsed();
        return Ok(summary);
    }
}

fn validate_dictionary_inputs(
    files_are_empty: bool,
    dictionary: Option<&[u8]>,
) -> Result<(), FormatError> {
    if let Some(dictionary) = dictionary {
        if dictionary.is_empty() {
            return Err(FormatError::WriterUnsupported(
                "dictionary archives require a non-empty dictionary",
            ));
        }
        if files_are_empty {
            return Err(FormatError::WriterUnsupported(
                "dictionary archives require at least one file",
            ));
        }
        if dictionary.len() > u32::MAX as usize {
            return Err(FormatError::WriterUnsupported(
                "dictionary decompressed size exceeds u32",
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
struct TimedWriterPlan {
    plan: WriterPlan,
    timings: WriterTimings,
}

#[allow(clippy::too_many_arguments)]
fn build_writer_plan<S: RegularFileSource>(
    files: &[S],
    master_key: &MasterKey,
    options: WriterOptions,
    dictionary: Option<&[u8]>,
    kdf_params: &KdfParams,
    key_wrap_records: Option<&KeyWrapRecordSource>,
    archive_uuid: [u8; 16],
    session_id: [u8; 16],
    root_auth: Option<RootAuthWriterConfig<'_>>,
    progress: Option<&SourceProgressHandle<'_>>,
) -> Result<TimedWriterPlan, ArchiveWriteError> {
    let mut next_block_index = 0u64;
    let payload_started = Instant::now();
    let payload = plan_payload_stream(files, options, dictionary, &mut next_block_index)?;
    let plan_payload = payload_started.elapsed();
    start_write_phase(progress, ArchiveWritePhase::PlanningMetadata);
    let metadata_started = Instant::now();
    let plan = build_writer_plan_from_payload(
        payload,
        next_block_index,
        master_key,
        options,
        dictionary,
        kdf_params,
        key_wrap_records,
        archive_uuid,
        session_id,
        root_auth,
    )?;
    Ok(TimedWriterPlan {
        plan,
        timings: WriterTimings {
            plan_payload,
            plan_metadata: metadata_started.elapsed(),
            ..WriterTimings::default()
        },
    })
}

#[allow(clippy::too_many_arguments)]
fn build_writer_plan_from_payload(
    payload: PayloadPlanning,
    mut next_block_index: u64,
    master_key: &MasterKey,
    mut options: WriterOptions,
    dictionary: Option<&[u8]>,
    kdf_params: &KdfParams,
    key_wrap_records: Option<&KeyWrapRecordSource>,
    archive_uuid: [u8; 16],
    session_id: [u8; 16],
    root_auth: Option<RootAuthWriterConfig<'_>>,
) -> Result<WriterPlan, ArchiveWriteError> {
    let subkeys = writer_subkeys(master_key, options.aead_algo, &archive_uuid, &session_id)?;
    let (resolved_kdf_params, key_wrap_table) =
        resolve_key_wrap_artifacts(kdf_params, &archive_uuid, &session_id, key_wrap_records)?;
    let volume_format_rev = volume_format_revision_for_options(&options, &resolved_kdf_params);
    let (shard_file_rows, planned_index_shards) = if payload.tar_members.is_empty() {
        (Vec::new(), Vec::new())
    } else {
        let rows = sorted_file_rows(&payload.tar_members);
        let shard_file_rows = partition_file_rows(rows)?;
        let planned_index_shards = build_index_shard_plaintexts(
            &shard_file_rows,
            &payload.frames,
            &payload.payload_objects,
            options,
        )?;
        (shard_file_rows, planned_index_shards)
    };

    let mut shard_entries = Vec::with_capacity(planned_index_shards.len());
    let mut index_shard_objects = Vec::with_capacity(planned_index_shards.len());
    for planned in planned_index_shards {
        let compressed =
            compress_zstd_frame_with_jobs(&planned.plaintext, options.zstd_level, options.jobs)?;
        let object_plan = plan_encrypted_object(
            compressed.len(),
            options.index_fec_data_shards,
            options.index_fec_parity_shards,
            options,
        )?;
        let extent = ObjectExtent::new(next_block_index, object_plan)?;
        next_block_index = extent.next_block_index()?;
        shard_entries.push(ShardEntry {
            shard_index: planned.shard_index,
            first_block_index: extent.first_block_index,
            data_block_count: extent.data_block_count,
            parity_block_count: extent.parity_block_count,
            encrypted_size: extent.encrypted_size,
            decompressed_size: u32_len(planned.plaintext.len(), "IndexShard")?,
            file_count: planned.file_count,
            first_path_hash: planned.first_path_hash,
            last_path_hash: planned.last_path_hash,
        });
        index_shard_objects.push(PlannedIndexShardObject {
            shard_index: planned.shard_index,
            compressed,
            extent,
        });
    }

    let compressed_dictionary = dictionary
        .map(|dictionary| {
            compress_zstd_frame_with_jobs(dictionary, options.zstd_level, options.jobs)
        })
        .transpose()?;
    let dictionary_decompressed_size = dictionary
        .map(|dictionary| u32_len(dictionary.len(), "dictionary"))
        .transpose()?;
    let dictionary_plan = compressed_dictionary
        .as_ref()
        .map(|compressed| {
            plan_metadata_object_without_class(
                compressed.len(),
                options,
                MetadataObjectKind::Dictionary,
            )
        })
        .transpose()?;
    let dictionary_extent = dictionary_plan
        .map(|plan| ObjectExtent::new(next_block_index, plan))
        .transpose()?;
    let next_after_dictionary = if let Some(extent) = dictionary_extent {
        extent.next_block_index()?
    } else {
        next_block_index
    };

    let planned_directory_hint_shards = if should_emit_directory_hints(payload.tar_members.len()) {
        build_directory_hint_plaintexts(&shard_file_rows, options)?
    } else {
        Vec::new()
    };
    let mut directory_hint_entries = Vec::with_capacity(planned_directory_hint_shards.len());
    let mut directory_hint_objects = Vec::with_capacity(planned_directory_hint_shards.len());
    let mut planned_next_block_index = next_after_dictionary;
    for planned in planned_directory_hint_shards {
        let compressed =
            compress_zstd_frame_with_jobs(&planned.plaintext, options.zstd_level, options.jobs)?;
        let object_plan = plan_encrypted_object(
            compressed.len(),
            options.index_fec_data_shards,
            options.index_fec_parity_shards,
            options,
        )?;
        let extent = ObjectExtent::new(planned_next_block_index, object_plan)?;
        planned_next_block_index = extent.next_block_index()?;
        directory_hint_entries.push(DirectoryHintShardEntry {
            hint_shard_index: planned.hint_shard_index,
            first_dir_hash: planned.first_dir_hash,
            last_dir_hash: planned.last_dir_hash,
            first_block_index: extent.first_block_index,
            data_block_count: extent.data_block_count,
            parity_block_count: extent.parity_block_count,
            encrypted_size: extent.encrypted_size,
            decompressed_size: u32_len(planned.plaintext.len(), "DirectoryHintTable")?,
            entry_count: planned.entry_count,
        });
        directory_hint_objects.push(PlannedDirectoryHintObject {
            hint_shard_index: planned.hint_shard_index,
            compressed,
            extent,
        });
    }

    let dictionary_extent = dictionary_extent.zip(dictionary_decompressed_size);
    let index_root_plaintext = build_index_root_plaintext(IndexRootPlaintextInput {
        shard_entries: &shard_entries,
        frame_count: payload.frames.len() as u64,
        envelope_count: payload.payload_objects.len() as u64,
        file_count: payload.tar_members.len() as u64,
        payload_block_count: payload.payload_block_count,
        tar_total_size: payload.tar_total_size,
        content_sha256: payload.content_sha256,
        directory_hint_entries: &directory_hint_entries,
        dictionary_extent,
    });
    let compressed_index_root =
        compress_zstd_frame_with_jobs(&index_root_plaintext, options.zstd_level, options.jobs)?;
    let metadata_class = plan_index_root_metadata_class(
        options,
        compressed_index_root.len(),
        compressed_dictionary.as_ref().map(Vec::len),
    )?;
    options = metadata_class.options;
    let crypto_header = build_crypto_header(
        options,
        volume_format_rev,
        dictionary.is_some(),
        &subkeys,
        &archive_uuid,
        &session_id,
        &resolved_kdf_params,
    )?;
    let index_root_extent = ObjectExtent::new(planned_next_block_index, metadata_class.index_root)?;
    let total_block_count = index_root_extent.next_block_index()?;
    let root_auth_footer_length = root_auth
        .map(|config| {
            root_auth_footer_wire_length(
                config.signer_identity.len(),
                config.authenticator_value_length as usize,
            )
        })
        .transpose()?;
    let block_records_offset = checked_u64_add(
        checked_u64_add(
            VOLUME_HEADER_LEN as u64,
            crypto_header.len() as u64,
            "CryptoHeader",
        )?,
        key_wrap_table.as_ref().map(Vec::len).unwrap_or(0) as u64,
        "KeyWrapTableV1",
    )?;

    Ok(WriterPlan {
        options,
        archive_uuid,
        session_id,
        crypto_header,
        tar_members: payload.tar_members,
        frames: payload.frames,
        payload_objects: payload.payload_objects,
        index_root_plaintext,
        compressed_index_root,
        index_root_extent,
        index_shard_objects,
        shard_entries,
        compressed_dictionary,
        dictionary_extent,
        volume_format_rev,
        directory_hint_objects,
        directory_hint_entries,
        root_auth_footer_length,
        key_wrap_table,
        block_records_offset,
        total_block_count,
    })
}

fn plan_payload_stream<S: RegularFileSource>(
    files: &[S],
    options: WriterOptions,
    dictionary: Option<&[u8]>,
    next_block_index: &mut u64,
) -> Result<PayloadPlanning, ArchiveWriteError> {
    let mut tar_members = Vec::with_capacity(files.len());
    let mut frames = Vec::new();
    let mut payload_objects = Vec::new();
    let mut tar_total_size = 0u64;
    let mut hasher = Sha256::new();
    let mut payload_block_count = 0u64;
    let mut next_frame_index = 0u64;
    let mut envelope = PayloadEnvelopeBuilder {
        envelope_index: 0,
        plaintext: Vec::new(),
    };

    for (member_index, file) in files.iter().enumerate() {
        let path = normalize_lookup_file_path(file.archive_path(), options.max_path_length)?;
        let entry_kind = file.entry_kind();
        if entry_kind != SourceEntryKind::Regular && file.file_data_size() != 0 {
            return Err(FormatError::WriterInvariant(
                "non-regular source has non-zero file data size",
            )
            .into());
        }
        let link_target = file.link_target().map(<[u8]>::to_vec);
        let sparse_extents = file.sparse_extents().map(<[SparseExtent]>::to_vec);
        let source_payload_size = sparse_extents
            .as_deref()
            .map(|extents| sparse_extent_bytes(extents, file.file_data_size()))
            .transpose()?
            .unwrap_or(file.file_data_size());
        let portable_metadata = file.portable_metadata();
        let layout = build_primary_member_layout(
            &path,
            entry_kind,
            link_target.as_deref(),
            file.file_data_size(),
            sparse_extents.as_deref(),
            file.mode(),
            file.mtime(),
            &portable_metadata,
        )?;
        let member_start = tar_total_size;
        let member_group_size = primary_member_layout_size(&layout, source_payload_size)?;
        let mut reader = StreamingMemberReader::from_source(
            file,
            &portable_metadata,
            layout,
            source_payload_size,
        )?;
        tar_members.push(TarMember {
            path,
            entry_kind,
            link_target,
            tar_member_group_start: member_start,
            tar_member_group_size: member_group_size,
            file_data_size: file.file_data_size(),
            sparse_extents,
            mode: file.mode(),
            mtime: file.mtime(),
            portable_metadata,
        });
        let mut member_offset = 0u64;
        while member_offset < member_group_size {
            let remaining = member_group_size - member_offset;
            let max_chunk = remaining.min(options.chunk_size as u64);
            let mut chunk = vec![0u8; to_usize_writer(max_chunk, "payload chunk")?];
            reader
                .read_exact(&mut chunk)
                .map_err(ArchiveWriteError::Io)?;
            let mut chunk_len = chunk.len();
            let frame = loop {
                let candidate = &chunk[..chunk_len];
                let frame = if let Some(dictionary) = dictionary {
                    compress_zstd_frame_with_dictionary_and_jobs(
                        candidate,
                        options.zstd_level,
                        dictionary,
                        options.jobs,
                    )?
                } else {
                    compress_zstd_frame_with_jobs(candidate, options.zstd_level, options.jobs)?
                };
                if payload_object_can_fit(frame.len(), options)? {
                    break frame;
                }
                if chunk_len == 1 {
                    return Err(FormatError::WriterUnsupported(
                        "single-byte payload frame exceeds envelope object limits",
                    )
                    .into());
                }
                chunk_len = (chunk_len / 2).max(1);
            };
            if chunk_len < chunk.len() {
                reader.push_back(chunk[chunk_len..].to_vec());
            }
            let chunk = &chunk[..chunk_len];
            hasher.update(chunk);
            append_payload_frame_to_plan(
                PayloadFramePlanState {
                    envelope: &mut envelope,
                    payload_objects: &mut payload_objects,
                    payload_block_count: &mut payload_block_count,
                    next_block_index,
                    frames: &mut frames,
                    next_frame_index: &mut next_frame_index,
                    options,
                },
                PayloadFramePlanInput {
                    frame: &frame,
                    decompressed_size: chunk_len,
                    member_index,
                    member_start,
                    member_offset,
                    member_group_size,
                },
            )?;
            member_offset = checked_u64_add(member_offset, chunk_len as u64, "payload chunk")?;
            tar_total_size = checked_u64_add(tar_total_size, chunk_len as u64, "tar stream")?;
        }
    }

    if !envelope.plaintext.is_empty() {
        flush_payload_envelope_plan(
            &mut envelope,
            &mut payload_objects,
            &mut payload_block_count,
            next_block_index,
            options,
        )?;
    }
    let digest = hasher.finalize();
    let mut content_sha256 = [0u8; 32];
    content_sha256.copy_from_slice(&digest);
    Ok(PayloadPlanning {
        tar_members,
        frames,
        payload_objects,
        payload_block_count,
        tar_total_size,
        content_sha256,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn write_single_pass_archive_to_sink<O, F>(
    master_key: &MasterKey,
    options: WriterOptions,
    kdf_params: &KdfParams,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    authenticator: Option<&mut RootAuthAuthenticator<'_>>,
    key_wrap_records: Option<&KeyWrapRecordSource>,
    sink: &mut O,
    progress: Option<&SourceProgressHandle<'_>>,
    drive_members: F,
) -> Result<WrittenArchiveSummary, ArchiveWriteError>
where
    O: ArchiveWriteSink,
    F: FnOnce(&mut StreamingArchiveWriter<'_, O>) -> Result<(), ArchiveWriteError>,
{
    let total_started = Instant::now();
    validate_single_pass_writer_options(options)?;
    if let Some(root_auth) = root_auth {
        validate_root_auth_writer_config(root_auth)?;
    }
    let options = plan_single_pass_writer_options(options)?;
    let archive_uuid = options
        .archive_uuid
        .unwrap_or_else(|| *Uuid::new_v4().as_bytes());
    let session_id = options
        .session_id
        .unwrap_or_else(|| *Uuid::new_v4().as_bytes());
    let stabilized_key_wrap_records =
        stabilized_key_wrap_record_source(kdf_params, key_wrap_records)?;
    let key_wrap_records = stabilized_key_wrap_records.as_ref().or(key_wrap_records);
    let (resolved_kdf_params, key_wrap_table) =
        resolve_key_wrap_artifacts(kdf_params, &archive_uuid, &session_id, key_wrap_records)?;
    let volume_format_rev = volume_format_revision_for_options(&options, &resolved_kdf_params);
    let subkeys = writer_subkeys(master_key, options.aead_algo, &archive_uuid, &session_id)?;
    let crypto_header = build_crypto_header(
        options,
        volume_format_rev,
        false,
        &subkeys,
        &archive_uuid,
        &session_id,
        &resolved_kdf_params,
    )?;
    let emission_state = begin_writer_emission_state(
        sink,
        options,
        &crypto_header,
        key_wrap_table.as_deref(),
        archive_uuid,
        session_id,
        volume_format_rev,
        root_auth.is_some(),
    )?;

    let mut writer = StreamingArchiveWriter {
        sink,
        options,
        archive_uuid,
        session_id,
        crypto_header,
        subkeys,
        tar_members: Vec::new(),
        frames: Vec::new(),
        payload_objects: Vec::new(),
        payload_block_count: 0,
        tar_total_size: 0,
        hasher: Sha256::new(),
        next_frame_index: 0,
        envelope: PayloadEnvelopeBuilder {
            envelope_index: 0,
            plaintext: Vec::new(),
        },
        emission_state,
    };
    start_write_phase(progress, ArchiveWritePhase::EmittingPayload);
    let emit_payload_started = Instant::now();
    drive_members(&mut writer)?;
    let emit_payload = emit_payload_started.elapsed();
    let mut summary = writer.finish(
        master_key,
        &resolved_kdf_params,
        key_wrap_records,
        root_auth,
        authenticator,
        progress,
    )?;
    summary.timings.emit_payload += emit_payload;
    summary.timings.total = total_started.elapsed();
    Ok(summary)
}

struct OrderedFrameJob {
    frame_index: u64,
    member_index: usize,
    member_start: u64,
    member_offset: u64,
    member_group_size: u64,
    plaintext: Vec<u8>,
}

struct OrderedFrameResult {
    frame_index: u64,
    member_index: usize,
    member_start: u64,
    member_offset: u64,
    member_group_size: u64,
    decompressed_size: usize,
    frame: Vec<u8>,
}

struct OrderedEnvelopeJob {
    envelope_index: u64,
    plaintext: Vec<u8>,
    extent: ObjectExtent,
    collect_data_leaf_hashes: bool,
}

struct OrderedEnvelopeResult {
    envelope_index: u64,
    records: OrderedEnvelopeRecords,
}

enum OrderedEnvelopeRecords {
    Materialized(Vec<BlockRecord>),
    Serialized(Vec<SerializedBlockRecord>),
}

struct SerializedBlockRecord {
    block_index: u64,
    bytes: Vec<u8>,
}

struct OrderedParallelState {
    tar_members: Vec<TarMember>,
    frames: Vec<PayloadFrame>,
    payload_objects: Vec<PayloadObject>,
    payload_block_count: u64,
    tar_total_size: u64,
    hasher: Sha256,
    next_frame_job_index: u64,
    next_frame_result_index: u64,
    next_frame_metadata_index: u64,
    frame_buffer: std::collections::BTreeMap<u64, OrderedFrameResult>,
    envelope: PayloadEnvelopeBuilder,
    next_payload_block_index: u64,
    next_envelope_result_index: u64,
    envelope_buffer: std::collections::BTreeMap<u64, OrderedEnvelopeResult>,
}

impl OrderedParallelState {
    fn new(file_count: usize) -> Self {
        Self {
            tar_members: Vec::with_capacity(file_count),
            frames: Vec::new(),
            payload_objects: Vec::new(),
            payload_block_count: 0,
            tar_total_size: 0,
            hasher: Sha256::new(),
            next_frame_job_index: 0,
            next_frame_result_index: 0,
            next_frame_metadata_index: 0,
            frame_buffer: std::collections::BTreeMap::new(),
            envelope: PayloadEnvelopeBuilder {
                envelope_index: 0,
                plaintext: Vec::new(),
            },
            next_payload_block_index: 0,
            next_envelope_result_index: 0,
            envelope_buffer: std::collections::BTreeMap::new(),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn write_ordered_parallel_archive_to_sink<S, O>(
    files: &[S],
    master_key: &MasterKey,
    options: WriterOptions,
    kdf_params: &KdfParams,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    authenticator: Option<&mut RootAuthAuthenticator<'_>>,
    key_wrap_records: Option<&KeyWrapRecordSource>,
    sink: &mut O,
    progress: Option<&SourceProgressHandle<'_>>,
) -> Result<WrittenArchiveSummary, ArchiveWriteError>
where
    S: RegularFileSource,
    O: ArchiveWriteSink,
{
    write_ordered_parallel_stream_archive_to_sink(
        master_key,
        options,
        kdf_params,
        root_auth,
        authenticator,
        key_wrap_records,
        sink,
        progress,
        |writer| {
            writer.reserve_member_capacity(files.len());
            for file in files {
                writer.write_regular_member_from_source(file)?;
            }
            Ok(())
        },
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn write_ordered_parallel_stream_archive_to_sink<O, F>(
    master_key: &MasterKey,
    options: WriterOptions,
    kdf_params: &KdfParams,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    authenticator: Option<&mut RootAuthAuthenticator<'_>>,
    key_wrap_records: Option<&KeyWrapRecordSource>,
    sink: &mut O,
    progress: Option<&SourceProgressHandle<'_>>,
    drive_members: F,
) -> Result<WrittenArchiveSummary, ArchiveWriteError>
where
    O: ArchiveWriteSink,
    F: FnOnce(&mut OrderedParallelArchiveWriter<'_, O>) -> Result<(), ArchiveWriteError>,
{
    let total_started = Instant::now();
    validate_single_pass_writer_options(options)?;
    if let Some(root_auth) = root_auth {
        validate_root_auth_writer_config(root_auth)?;
    }
    let options = plan_single_pass_writer_options(options)?;
    let archive_uuid = options
        .archive_uuid
        .unwrap_or_else(|| *Uuid::new_v4().as_bytes());
    let session_id = options
        .session_id
        .unwrap_or_else(|| *Uuid::new_v4().as_bytes());
    let stabilized_key_wrap_records =
        stabilized_key_wrap_record_source(kdf_params, key_wrap_records)?;
    let key_wrap_records = stabilized_key_wrap_records.as_ref().or(key_wrap_records);
    let (resolved_kdf_params, key_wrap_table) =
        resolve_key_wrap_artifacts(kdf_params, &archive_uuid, &session_id, key_wrap_records)?;
    let volume_format_rev = volume_format_revision_for_options(&options, &resolved_kdf_params);
    let subkeys = writer_subkeys(master_key, options.aead_algo, &archive_uuid, &session_id)?;
    let crypto_header = build_crypto_header(
        options,
        volume_format_rev,
        false,
        &subkeys,
        &archive_uuid,
        &session_id,
        &resolved_kdf_params,
    )?;
    let mut emission_state = begin_writer_emission_state(
        sink,
        options,
        &crypto_header,
        key_wrap_table.as_deref(),
        archive_uuid,
        session_id,
        volume_format_rev,
        root_auth.is_some(),
    )?;

    start_write_phase(progress, ArchiveWritePhase::EmittingPayload);
    let emit_payload_started = Instant::now();
    let mut ordered = OrderedParallelState::new(0);
    let worker_count = options.jobs.max(1);
    let frame_job_buffer = worker_count.saturating_mul(4).max(1);
    let envelope_job_buffer = worker_count.saturating_mul(2).max(1);
    let subkeys_for_workers = std::sync::Arc::new(subkeys.clone());

    std::thread::scope(|scope| -> Result<(), ArchiveWriteError> {
        let (frame_job_tx, frame_job_rx) =
            std::sync::mpsc::sync_channel::<OrderedFrameJob>(frame_job_buffer);
        let (frame_result_tx, frame_result_rx) =
            std::sync::mpsc::channel::<Result<OrderedFrameResult, ArchiveWriteError>>();
        let frame_job_rx = std::sync::Arc::new(std::sync::Mutex::new(frame_job_rx));

        let (envelope_job_tx, envelope_job_rx) =
            std::sync::mpsc::sync_channel::<OrderedEnvelopeJob>(envelope_job_buffer);
        let (envelope_result_tx, envelope_result_rx) =
            std::sync::mpsc::channel::<Result<OrderedEnvelopeResult, ArchiveWriteError>>();
        let envelope_job_rx = std::sync::Arc::new(std::sync::Mutex::new(envelope_job_rx));

        let frame_handles = (0..worker_count)
            .map(|_| {
                let frame_job_rx = std::sync::Arc::clone(&frame_job_rx);
                let frame_result_tx = frame_result_tx.clone();
                scope.spawn(move || loop {
                    let job = {
                        let receiver = frame_job_rx
                            .lock()
                            .expect("ordered frame receiver poisoned");
                        receiver.recv()
                    };
                    let Ok(job) = job else {
                        break;
                    };
                    let is_error = match build_ordered_frame_result(job, options) {
                        Ok(result) => frame_result_tx.send(Ok(result)).is_err(),
                        Err(error) => {
                            let _ = frame_result_tx.send(Err(error));
                            true
                        }
                    };
                    if is_error {
                        break;
                    }
                })
            })
            .collect::<Vec<_>>();
        drop(frame_result_tx);

        let envelope_handles = (0..worker_count)
            .map(|_| {
                let envelope_job_rx = std::sync::Arc::clone(&envelope_job_rx);
                let envelope_result_tx = envelope_result_tx.clone();
                let subkeys = std::sync::Arc::clone(&subkeys_for_workers);
                scope.spawn(move || loop {
                    let job = {
                        let receiver = envelope_job_rx
                            .lock()
                            .expect("ordered envelope receiver poisoned");
                        receiver.recv()
                    };
                    let Ok(job) = job else {
                        break;
                    };
                    let is_error = match build_ordered_envelope_result(
                        job,
                        &subkeys,
                        options,
                        archive_uuid,
                        session_id,
                    ) {
                        Ok(result) => envelope_result_tx.send(Ok(result)).is_err(),
                        Err(error) => {
                            let _ = envelope_result_tx.send(Err(error));
                            true
                        }
                    };
                    if is_error {
                        break;
                    }
                })
            })
            .collect::<Vec<_>>();
        drop(envelope_result_tx);

        {
            let mut writer = OrderedParallelArchiveWriter {
                frame_job_tx: &frame_job_tx,
                frame_result_rx: &frame_result_rx,
                envelope_job_tx: &envelope_job_tx,
                envelope_result_rx: &envelope_result_rx,
                ordered: &mut ordered,
                sink,
                options,
                emission_state: &mut emission_state,
            };
            drive_members(&mut writer)?;
        }

        drop(frame_job_tx);
        while ordered.next_frame_result_index < ordered.next_frame_job_index {
            receive_ordered_frame_result(
                &frame_result_rx,
                &envelope_job_tx,
                &envelope_result_rx,
                &mut ordered,
                sink,
                options,
                &mut emission_state,
                true,
            )?;
        }
        flush_ordered_parallel_envelope(
            &envelope_job_tx,
            &envelope_result_rx,
            &mut ordered,
            sink,
            options,
            &mut emission_state,
        )?;
        drop(envelope_job_tx);
        while ordered.next_envelope_result_index < ordered.envelope.envelope_index {
            receive_ordered_envelope_result(
                &envelope_result_rx,
                &mut ordered,
                sink,
                options,
                &mut emission_state,
                true,
            )?;
        }

        for handle in frame_handles {
            handle
                .join()
                .map_err(|_| FormatError::WriterInvariant("ordered frame worker panicked"))?;
        }
        for handle in envelope_handles {
            handle
                .join()
                .map_err(|_| FormatError::WriterInvariant("ordered envelope worker panicked"))?;
        }
        Ok(())
    })?;
    let emit_payload = emit_payload_started.elapsed();

    emission_state.next_block_index = ordered.next_payload_block_index;
    let digest = ordered.hasher.finalize();
    let mut content_sha256 = [0u8; 32];
    content_sha256.copy_from_slice(&digest);
    let payload = PayloadPlanning {
        tar_members: ordered.tar_members,
        frames: ordered.frames,
        payload_objects: ordered.payload_objects,
        payload_block_count: ordered.payload_block_count,
        tar_total_size: ordered.tar_total_size,
        content_sha256,
    };
    start_write_phase(progress, ArchiveWritePhase::EmittingMetadata);
    let plan = build_writer_plan_from_payload(
        payload,
        emission_state.next_block_index,
        master_key,
        options,
        None,
        &resolved_kdf_params,
        key_wrap_records,
        archive_uuid,
        session_id,
        root_auth,
    )?;
    if plan.options != options || plan.crypto_header != crypto_header {
        return Err(FormatError::WriterUnsupported(
            "ordered parallel metadata exceeded the predeclared header class",
        )
        .into());
    }
    let mut summary = emit_writer_plan_suffix(
        &subkeys,
        root_auth,
        authenticator,
        plan,
        sink,
        emission_state,
    )?;
    summary.timings.emit_payload += emit_payload;
    summary.timings.total = total_started.elapsed();
    Ok(summary)
}

pub(crate) struct OrderedParallelArchiveWriter<'a, O: ArchiveWriteSink> {
    frame_job_tx: &'a std::sync::mpsc::SyncSender<OrderedFrameJob>,
    frame_result_rx: &'a std::sync::mpsc::Receiver<Result<OrderedFrameResult, ArchiveWriteError>>,
    envelope_job_tx: &'a std::sync::mpsc::SyncSender<OrderedEnvelopeJob>,
    envelope_result_rx:
        &'a std::sync::mpsc::Receiver<Result<OrderedEnvelopeResult, ArchiveWriteError>>,
    ordered: &'a mut OrderedParallelState,
    sink: &'a mut O,
    options: WriterOptions,
    emission_state: &'a mut WriterEmissionState,
}

impl<O: ArchiveWriteSink> OrderedParallelArchiveWriter<'_, O> {
    fn reserve_member_capacity(&mut self, additional: usize) {
        self.ordered.tar_members.reserve(additional);
    }

    pub(crate) fn write_regular_member_from_reader(
        &mut self,
        member: StreamingRegularMember,
        payload: &mut dyn Read,
    ) -> Result<(), ArchiveWriteError> {
        let path = &member.archive_path;
        validate_file_path_bytes(path, self.options.max_path_length)?;
        if member.entry_kind != SourceEntryKind::Regular && member.file_data_size != 0 {
            return Err(FormatError::WriterInvariant(
                "non-regular source has non-zero file data size",
            )
            .into());
        }
        let source_payload_size = member
            .sparse_extents
            .as_deref()
            .map(|extents| sparse_extent_bytes(extents, member.file_data_size))
            .transpose()?
            .unwrap_or(member.file_data_size);
        let prefix = build_primary_member_prefix(
            path,
            member.entry_kind,
            member.link_target.as_deref(),
            member.file_data_size,
            member.sparse_extents.as_deref(),
            member.mode,
            member.mtime,
            &member.portable_metadata,
        )?;
        let member_group_size = checked_u64_add(
            prefix.len() as u64,
            checked_u64_add(
                source_payload_size,
                padding_to_512_u64(source_payload_size),
                "tar member",
            )?,
            "tar member",
        )?;
        let mut reader = StreamingMemberReader::new(Box::new(payload), prefix, source_payload_size);
        self.write_prebuilt_member(member, &mut reader, member_group_size)
    }

    fn write_regular_member_from_source<S: RegularFileSource + ?Sized>(
        &mut self,
        source: &S,
    ) -> Result<(), ArchiveWriteError> {
        let member = StreamingRegularMember {
            archive_path: normalize_lookup_file_path(
                source.archive_path(),
                self.options.max_path_length,
            )?,
            entry_kind: source.entry_kind(),
            link_target: source.link_target().map(<[u8]>::to_vec),
            file_data_size: source.file_data_size(),
            sparse_extents: source.sparse_extents().map(<[SparseExtent]>::to_vec),
            mode: source.mode(),
            mtime: source.mtime(),
            portable_metadata: source.portable_metadata(),
        };
        if member.entry_kind != SourceEntryKind::Regular && member.file_data_size != 0 {
            return Err(FormatError::WriterInvariant(
                "non-regular source has non-zero file data size",
            )
            .into());
        }
        let source_payload_size = member
            .sparse_extents
            .as_deref()
            .map(|extents| sparse_extent_bytes(extents, member.file_data_size))
            .transpose()?
            .unwrap_or(member.file_data_size);
        let layout = build_primary_member_layout(
            &member.archive_path,
            member.entry_kind,
            member.link_target.as_deref(),
            member.file_data_size,
            member.sparse_extents.as_deref(),
            member.mode,
            member.mtime,
            &member.portable_metadata,
        )?;
        let member_group_size = primary_member_layout_size(&layout, source_payload_size)?;
        let mut reader = StreamingMemberReader::from_source(
            source,
            &member.portable_metadata,
            layout,
            source_payload_size,
        )?;
        self.write_prebuilt_member(member, &mut reader, member_group_size)
    }

    fn write_prebuilt_member(
        &mut self,
        member: StreamingRegularMember,
        reader: &mut StreamingMemberReader<'_>,
        member_group_size: u64,
    ) -> Result<(), ArchiveWriteError> {
        let member_start = self.ordered.tar_total_size;
        let member_index = self.ordered.tar_members.len();
        self.ordered.tar_members.push(TarMember {
            path: member.archive_path,
            entry_kind: member.entry_kind,
            link_target: member.link_target,
            tar_member_group_start: member_start,
            tar_member_group_size: member_group_size,
            file_data_size: member.file_data_size,
            sparse_extents: member.sparse_extents,
            mode: member.mode,
            mtime: member.mtime,
            portable_metadata: member.portable_metadata,
        });
        let mut member_offset = 0u64;
        while member_offset < member_group_size {
            let remaining = member_group_size - member_offset;
            let read_len = remaining.min(self.options.chunk_size as u64);
            let mut plaintext = vec![0u8; to_usize_writer(read_len, "payload chunk")?];
            reader
                .read_exact(&mut plaintext)
                .map_err(ArchiveWriteError::Io)?;
            self.ordered.hasher.update(&plaintext);
            let frame_index = self.ordered.next_frame_job_index;
            self.ordered.next_frame_job_index = checked_u64_add(
                self.ordered.next_frame_job_index,
                1,
                "PayloadFrame.frame_index",
            )?;
            send_ordered_frame_job(
                OrderedFrameJob {
                    frame_index,
                    member_index,
                    member_start,
                    member_offset,
                    member_group_size,
                    plaintext,
                },
                self.frame_job_tx,
                self.frame_result_rx,
                self.envelope_job_tx,
                self.envelope_result_rx,
                self.ordered,
                self.sink,
                self.options,
                self.emission_state,
            )?;
            member_offset = checked_u64_add(member_offset, read_len, "payload chunk")?;
            self.ordered.tar_total_size =
                checked_u64_add(self.ordered.tar_total_size, read_len, "tar stream")?;
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn send_ordered_frame_job<O: ArchiveWriteSink>(
    mut job: OrderedFrameJob,
    frame_job_tx: &std::sync::mpsc::SyncSender<OrderedFrameJob>,
    frame_result_rx: &std::sync::mpsc::Receiver<Result<OrderedFrameResult, ArchiveWriteError>>,
    envelope_job_tx: &std::sync::mpsc::SyncSender<OrderedEnvelopeJob>,
    envelope_result_rx: &std::sync::mpsc::Receiver<
        Result<OrderedEnvelopeResult, ArchiveWriteError>,
    >,
    ordered: &mut OrderedParallelState,
    sink: &mut O,
    options: WriterOptions,
    emission_state: &mut WriterEmissionState,
) -> Result<(), ArchiveWriteError> {
    loop {
        match frame_job_tx.try_send(job) {
            Ok(()) => {
                drain_ordered_frame_results(
                    frame_result_rx,
                    envelope_job_tx,
                    envelope_result_rx,
                    ordered,
                    sink,
                    options,
                    emission_state,
                )?;
                return Ok(());
            }
            Err(std::sync::mpsc::TrySendError::Full(returned)) => {
                job = returned;
                receive_ordered_frame_result(
                    frame_result_rx,
                    envelope_job_tx,
                    envelope_result_rx,
                    ordered,
                    sink,
                    options,
                    emission_state,
                    true,
                )?;
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                return Err(FormatError::WriterInvariant("ordered frame worker stopped").into());
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn drain_ordered_frame_results<O: ArchiveWriteSink>(
    frame_result_rx: &std::sync::mpsc::Receiver<Result<OrderedFrameResult, ArchiveWriteError>>,
    envelope_job_tx: &std::sync::mpsc::SyncSender<OrderedEnvelopeJob>,
    envelope_result_rx: &std::sync::mpsc::Receiver<
        Result<OrderedEnvelopeResult, ArchiveWriteError>,
    >,
    ordered: &mut OrderedParallelState,
    sink: &mut O,
    options: WriterOptions,
    emission_state: &mut WriterEmissionState,
) -> Result<(), ArchiveWriteError> {
    while receive_ordered_frame_result(
        frame_result_rx,
        envelope_job_tx,
        envelope_result_rx,
        ordered,
        sink,
        options,
        emission_state,
        false,
    )? {}
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn receive_ordered_frame_result<O: ArchiveWriteSink>(
    frame_result_rx: &std::sync::mpsc::Receiver<Result<OrderedFrameResult, ArchiveWriteError>>,
    envelope_job_tx: &std::sync::mpsc::SyncSender<OrderedEnvelopeJob>,
    envelope_result_rx: &std::sync::mpsc::Receiver<
        Result<OrderedEnvelopeResult, ArchiveWriteError>,
    >,
    ordered: &mut OrderedParallelState,
    sink: &mut O,
    options: WriterOptions,
    emission_state: &mut WriterEmissionState,
    wait: bool,
) -> Result<bool, ArchiveWriteError> {
    let result = if wait {
        match frame_result_rx.recv() {
            Ok(result) => result?,
            Err(_) => {
                return Err(FormatError::WriterInvariant("ordered frame worker stopped").into())
            }
        }
    } else {
        match frame_result_rx.try_recv() {
            Ok(result) => result?,
            Err(std::sync::mpsc::TryRecvError::Empty) => return Ok(false),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => return Ok(false),
        }
    };
    ordered.frame_buffer.insert(result.frame_index, result);
    while let Some(result) = ordered
        .frame_buffer
        .remove(&ordered.next_frame_result_index)
    {
        append_ordered_frame_result(
            result,
            envelope_job_tx,
            envelope_result_rx,
            ordered,
            sink,
            options,
            emission_state,
        )?;
        ordered.next_frame_result_index = checked_u64_add(
            ordered.next_frame_result_index,
            1,
            "PayloadFrame.frame_index",
        )?;
    }
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
fn append_ordered_frame_result<O: ArchiveWriteSink>(
    result: OrderedFrameResult,
    envelope_job_tx: &std::sync::mpsc::SyncSender<OrderedEnvelopeJob>,
    envelope_result_rx: &std::sync::mpsc::Receiver<
        Result<OrderedEnvelopeResult, ArchiveWriteError>,
    >,
    ordered: &mut OrderedParallelState,
    sink: &mut O,
    options: WriterOptions,
    emission_state: &mut WriterEmissionState,
) -> Result<(), ArchiveWriteError> {
    if payload_envelope_needs_flush(&ordered.envelope, result.frame.len(), options)? {
        flush_ordered_parallel_envelope(
            envelope_job_tx,
            envelope_result_rx,
            ordered,
            sink,
            options,
            emission_state,
        )?;
    }
    if ordered.envelope.plaintext.is_empty()
        && !payload_object_can_fit(result.frame.len(), options)?
    {
        return Err(
            FormatError::WriterUnsupported("payload frame exceeds envelope object limits").into(),
        );
    }
    let offset = u32_len(
        ordered.envelope.plaintext.len(),
        "FrameEntry.offset_in_envelope",
    )?;
    ordered.envelope.plaintext.extend_from_slice(&result.frame);
    ordered
        .frames
        .push(payload_frame_metadata(PayloadFrameMetadataInput {
            frame_index: ordered.next_frame_metadata_index,
            envelope_index: ordered.envelope.envelope_index,
            member_index: result.member_index,
            offset_in_envelope: offset,
            compressed_size: result.frame.len(),
            decompressed_size: result.decompressed_size,
            member_start: result.member_start,
            member_offset: result.member_offset,
            member_group_size: result.member_group_size,
        })?);
    ordered.next_frame_metadata_index = checked_u64_add(
        ordered.next_frame_metadata_index,
        1,
        "PayloadFrame.frame_index",
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn flush_ordered_parallel_envelope<O: ArchiveWriteSink>(
    envelope_job_tx: &std::sync::mpsc::SyncSender<OrderedEnvelopeJob>,
    envelope_result_rx: &std::sync::mpsc::Receiver<
        Result<OrderedEnvelopeResult, ArchiveWriteError>,
    >,
    ordered: &mut OrderedParallelState,
    sink: &mut O,
    options: WriterOptions,
    emission_state: &mut WriterEmissionState,
) -> Result<(), ArchiveWriteError> {
    if ordered.envelope.plaintext.is_empty() {
        return Ok(());
    }
    let plaintext_size = u32_len(
        ordered.envelope.plaintext.len(),
        "EnvelopeEntry.plaintext_size",
    )?;
    let object_plan = plan_encrypted_object(
        ordered.envelope.plaintext.len(),
        options.fec_data_shards,
        options.fec_parity_shards,
        options,
    )?;
    let extent = ObjectExtent::new(ordered.next_payload_block_index, object_plan)?;
    ordered.next_payload_block_index = extent.next_block_index()?;
    ordered.payload_block_count = checked_u64_add(
        ordered.payload_block_count,
        extent.data_block_count as u64,
        "payload",
    )?;
    ordered.payload_objects.push(PayloadObject {
        envelope_index: ordered.envelope.envelope_index,
        plaintext_size,
        object: extent,
    });
    let mut job = OrderedEnvelopeJob {
        envelope_index: ordered.envelope.envelope_index,
        plaintext: std::mem::take(&mut ordered.envelope.plaintext),
        extent,
        collect_data_leaf_hashes: emission_state.data_leaf_hashes.is_some(),
    };
    ordered.envelope.envelope_index =
        checked_u64_add(ordered.envelope.envelope_index, 1, "EnvelopeEntry")?;
    loop {
        match envelope_job_tx.try_send(job) {
            Ok(()) => {
                drain_ordered_envelope_results(
                    envelope_result_rx,
                    ordered,
                    sink,
                    options,
                    emission_state,
                )?;
                return Ok(());
            }
            Err(std::sync::mpsc::TrySendError::Full(returned)) => {
                job = returned;
                receive_ordered_envelope_result(
                    envelope_result_rx,
                    ordered,
                    sink,
                    options,
                    emission_state,
                    true,
                )?;
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                return Err(FormatError::WriterInvariant("ordered envelope worker stopped").into());
            }
        }
    }
}

fn drain_ordered_envelope_results<O: ArchiveWriteSink>(
    envelope_result_rx: &std::sync::mpsc::Receiver<
        Result<OrderedEnvelopeResult, ArchiveWriteError>,
    >,
    ordered: &mut OrderedParallelState,
    sink: &mut O,
    options: WriterOptions,
    emission_state: &mut WriterEmissionState,
) -> Result<(), ArchiveWriteError> {
    while receive_ordered_envelope_result(
        envelope_result_rx,
        ordered,
        sink,
        options,
        emission_state,
        false,
    )? {}
    Ok(())
}

fn receive_ordered_envelope_result<O: ArchiveWriteSink>(
    envelope_result_rx: &std::sync::mpsc::Receiver<
        Result<OrderedEnvelopeResult, ArchiveWriteError>,
    >,
    ordered: &mut OrderedParallelState,
    sink: &mut O,
    options: WriterOptions,
    emission_state: &mut WriterEmissionState,
    wait: bool,
) -> Result<bool, ArchiveWriteError> {
    let result = if wait {
        match envelope_result_rx.recv() {
            Ok(result) => result?,
            Err(_) => {
                return Err(FormatError::WriterInvariant("ordered envelope worker stopped").into());
            }
        }
    } else {
        match envelope_result_rx.try_recv() {
            Ok(result) => result?,
            Err(std::sync::mpsc::TryRecvError::Empty) => return Ok(false),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => return Ok(false),
        }
    };
    ordered
        .envelope_buffer
        .insert(result.envelope_index, result);
    while let Some(result) = ordered
        .envelope_buffer
        .remove(&ordered.next_envelope_result_index)
    {
        emit_ordered_envelope_result(result, sink, options, emission_state)?;
        ordered.next_envelope_result_index =
            checked_u64_add(ordered.next_envelope_result_index, 1, "EnvelopeEntry")?;
    }
    Ok(true)
}

fn build_ordered_frame_result(
    job: OrderedFrameJob,
    options: WriterOptions,
) -> Result<OrderedFrameResult, ArchiveWriteError> {
    let frame = compress_zstd_frame_with_jobs(&job.plaintext, options.zstd_level, 1)?;
    Ok(OrderedFrameResult {
        frame_index: job.frame_index,
        member_index: job.member_index,
        member_start: job.member_start,
        member_offset: job.member_offset,
        member_group_size: job.member_group_size,
        decompressed_size: job.plaintext.len(),
        frame,
    })
}

fn build_ordered_envelope_result(
    job: OrderedEnvelopeJob,
    subkeys: &Subkeys,
    options: WriterOptions,
    archive_uuid: [u8; 16],
    session_id: [u8; 16],
) -> Result<OrderedEnvelopeResult, ArchiveWriteError> {
    let context = ObjectEncryptionContext {
        key: &subkeys.enc_key,
        nonce_seed: &subkeys.nonce_seed,
        domain: b"envelope",
        counter: job.envelope_index,
        data_kind: BlockKind::PayloadData,
        parity_kind: BlockKind::PayloadParity,
        data_shard_max: options.fec_data_shards,
        class_parity_shard_max: options.fec_parity_shards,
        archive_uuid: &archive_uuid,
        session_id: &session_id,
    };
    if job.extent.parity_block_count == 0 && !job.collect_data_leaf_hashes {
        return Ok(OrderedEnvelopeResult {
            envelope_index: job.envelope_index,
            records: OrderedEnvelopeRecords::Serialized(serialize_zero_parity_encrypted_object(
                &job.plaintext,
                context,
                job.extent,
                options,
            )?),
        });
    }

    let mut local_next_block_index = job.extent.first_block_index;
    let object = encrypt_object(
        &job.plaintext,
        context,
        &mut local_next_block_index,
        options,
    )?;
    validate_planned_extent(&object, job.extent)?;
    Ok(OrderedEnvelopeResult {
        envelope_index: job.envelope_index,
        records: OrderedEnvelopeRecords::Materialized(object.records),
    })
}

fn emit_ordered_envelope_result<O: ArchiveWriteSink>(
    result: OrderedEnvelopeResult,
    sink: &mut O,
    options: WriterOptions,
    emission_state: &mut WriterEmissionState,
) -> Result<(), ArchiveWriteError> {
    match result.records {
        OrderedEnvelopeRecords::Materialized(records) => {
            for record in &records {
                emit_block_record(
                    sink,
                    options,
                    &mut emission_state.bytes_written,
                    &mut emission_state.record_counts,
                    emission_state.volume_format_rev,
                    &mut emission_state.data_leaf_hashes,
                    record,
                )?;
            }
        }
        OrderedEnvelopeRecords::Serialized(records) => {
            for record in &records {
                emit_serialized_block_record(
                    sink,
                    options,
                    &mut emission_state.bytes_written,
                    &mut emission_state.record_counts,
                    record,
                )?;
            }
        }
    }
    Ok(())
}

fn validate_single_pass_writer_options(options: WriterOptions) -> Result<(), FormatError> {
    if options.volume_loss_tolerance != 0 {
        return Err(FormatError::WriterUnsupported(
            "streaming create cannot tolerate volume loss",
        ));
    }
    if options.target_volume_size.is_some() {
        return Err(FormatError::WriterUnsupported(
            "streaming create does not support target volume sizing",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn begin_writer_emission_state<O: ArchiveWriteSink>(
    sink: &mut O,
    options: WriterOptions,
    crypto_header: &[u8],
    key_wrap_table: Option<&[u8]>,
    archive_uuid: [u8; 16],
    session_id: [u8; 16],
    volume_format_rev: u16,
    collect_data_leaf_hashes: bool,
) -> Result<WriterEmissionState, ArchiveWriteError> {
    let volume_count = usize::try_from(options.stripe_width)
        .map_err(|_| FormatError::WriterUnsupported("stripe_width"))?;
    sink.begin_archive(volume_count)?;

    let mut state = WriterEmissionState {
        volume_headers: Vec::with_capacity(volume_count),
        bytes_written: vec![0u64; volume_count],
        record_counts: vec![0u64; volume_count],
        volume_format_rev,
        data_leaf_hashes: collect_data_leaf_hashes.then(Vec::new),
        next_block_index: 0,
    };

    for volume_index in 0..volume_count {
        let volume_index_u32 = u32::try_from(volume_index)
            .map_err(|_| FormatError::WriterUnsupported("volume_index"))?;
        let volume_header = VolumeHeader {
            format_version: FORMAT_VERSION,
            volume_format_rev,
            volume_index: volume_index_u32,
            stripe_width: options.stripe_width,
            archive_uuid,
            session_id,
            crypto_header_offset: VOLUME_HEADER_LEN as u32,
            crypto_header_length: u32_len(crypto_header.len(), "CryptoHeader")?,
            header_crc32c: 0,
        };
        let volume_header_bytes = volume_header.to_bytes();
        sink.write_volume(volume_index, &volume_header_bytes)?;
        sink.write_volume(volume_index, crypto_header)?;
        let mut bytes_written = checked_u64_add(
            VOLUME_HEADER_LEN as u64,
            crypto_header.len() as u64,
            "volume header",
        )?;
        if let Some(key_wrap_table) = key_wrap_table {
            sink.write_volume(volume_index, key_wrap_table)?;
            bytes_written =
                checked_u64_add(bytes_written, key_wrap_table.len() as u64, "KeyWrapTableV1")?;
        }
        state.bytes_written[volume_index] = bytes_written;
        state.volume_headers.push(volume_header_bytes);
    }

    Ok(state)
}

fn plan_single_pass_writer_options(options: WriterOptions) -> Result<WriterOptions, FormatError> {
    let mut options = plan_writer_options(options)?;
    options.index_root_fec_data_shards = max_single_pass_index_root_data_shards(options)?;
    plan_writer_options(options)
}

fn max_single_pass_index_root_data_shards(options: WriterOptions) -> Result<u16, FormatError> {
    let block_size_limit = (u32::MAX as u64 / options.block_size as u64).min(u16::MAX as u64);
    let mut low = MIN_INDEX_ROOT_FEC_DATA_SHARDS as u64;
    let mut high = block_size_limit;
    let mut best = low;
    while low <= high {
        let mid = low + (high - low) / 2;
        match compute_parity(mid, options) {
            Ok(parity)
                if mid + u64::from(parity) <= READER_MAX_INDEX_ROOT_FEC_CLASS_SHARDS as u64 =>
            {
                best = mid;
                low = mid + 1;
            }
            _ => {
                if mid == 0 {
                    break;
                }
                high = mid - 1;
            }
        }
    }
    u16::try_from(best).map_err(|_| FormatError::WriterUnsupported("index_root_fec_data_shards"))
}

impl<O: ArchiveWriteSink> StreamingArchiveWriter<'_, O> {
    fn write_regular_member_from_source<S: RegularFileSource + ?Sized>(
        &mut self,
        source: &S,
    ) -> Result<(), ArchiveWriteError> {
        let member = StreamingRegularMember {
            archive_path: normalize_lookup_file_path(
                source.archive_path(),
                self.options.max_path_length,
            )?,
            entry_kind: source.entry_kind(),
            link_target: source.link_target().map(<[u8]>::to_vec),
            file_data_size: source.file_data_size(),
            sparse_extents: source.sparse_extents().map(<[SparseExtent]>::to_vec),
            mode: source.mode(),
            mtime: source.mtime(),
            portable_metadata: source.portable_metadata(),
        };
        if member.entry_kind != SourceEntryKind::Regular && member.file_data_size != 0 {
            return Err(FormatError::WriterInvariant(
                "non-regular source has non-zero file data size",
            )
            .into());
        }
        let source_payload_size = member
            .sparse_extents
            .as_deref()
            .map(|extents| sparse_extent_bytes(extents, member.file_data_size))
            .transpose()?
            .unwrap_or(member.file_data_size);
        let layout = build_primary_member_layout(
            &member.archive_path,
            member.entry_kind,
            member.link_target.as_deref(),
            member.file_data_size,
            member.sparse_extents.as_deref(),
            member.mode,
            member.mtime,
            &member.portable_metadata,
        )?;
        let member_group_size = primary_member_layout_size(&layout, source_payload_size)?;
        let mut reader = StreamingMemberReader::from_source(
            source,
            &member.portable_metadata,
            layout,
            source_payload_size,
        )?;
        self.write_prebuilt_member(member, &mut reader, member_group_size)
    }

    fn write_prebuilt_member(
        &mut self,
        member: StreamingRegularMember,
        reader: &mut StreamingMemberReader<'_>,
        member_group_size: u64,
    ) -> Result<(), ArchiveWriteError> {
        let member_start = self.tar_total_size;
        let member_index = self.tar_members.len();
        self.tar_members.push(TarMember {
            path: member.archive_path,
            entry_kind: member.entry_kind,
            link_target: member.link_target,
            tar_member_group_start: member_start,
            tar_member_group_size: member_group_size,
            file_data_size: member.file_data_size,
            sparse_extents: member.sparse_extents,
            mode: member.mode,
            mtime: member.mtime,
            portable_metadata: member.portable_metadata,
        });
        let mut member_offset = 0u64;
        while member_offset < member_group_size {
            let remaining = member_group_size - member_offset;
            let max_chunk = remaining.min(self.options.chunk_size as u64);
            let mut chunk = vec![0u8; to_usize_writer(max_chunk, "payload chunk")?];
            reader
                .read_exact(&mut chunk)
                .map_err(ArchiveWriteError::Io)?;
            let mut chunk_len = chunk.len();
            let frame = loop {
                let candidate = &chunk[..chunk_len];
                let frame = compress_zstd_frame_with_jobs(
                    candidate,
                    self.options.zstd_level,
                    self.options.jobs,
                )?;
                if payload_object_can_fit(frame.len(), self.options)? {
                    break frame;
                }
                if chunk_len == 1 {
                    return Err(FormatError::WriterUnsupported(
                        "single-byte payload frame exceeds envelope object limits",
                    )
                    .into());
                }
                chunk_len = (chunk_len / 2).max(1);
            };
            if chunk_len < chunk.len() {
                reader.push_back(chunk[chunk_len..].to_vec());
            }
            let chunk = &chunk[..chunk_len];
            self.hasher.update(chunk);
            self.append_payload_frame(
                &frame,
                chunk_len,
                member_index,
                member_start,
                member_offset,
                member_group_size,
            )?;
            member_offset = checked_u64_add(member_offset, chunk_len as u64, "payload chunk")?;
            self.tar_total_size =
                checked_u64_add(self.tar_total_size, chunk_len as u64, "tar stream")?;
        }
        Ok(())
    }

    fn append_payload_frame(
        &mut self,
        frame: &[u8],
        decompressed_size: usize,
        member_index: usize,
        member_start: u64,
        member_offset: u64,
        member_group_size: u64,
    ) -> Result<(), ArchiveWriteError> {
        if payload_envelope_needs_flush(&self.envelope, frame.len(), self.options)? {
            self.flush_payload_envelope()?;
        }
        if self.envelope.plaintext.is_empty() && !payload_object_can_fit(frame.len(), self.options)?
        {
            return Err(FormatError::WriterUnsupported(
                "payload frame exceeds envelope object limits",
            )
            .into());
        }
        let offset = u32_len(
            self.envelope.plaintext.len(),
            "FrameEntry.offset_in_envelope",
        )?;
        self.envelope.plaintext.extend_from_slice(frame);
        self.frames
            .push(payload_frame_metadata(PayloadFrameMetadataInput {
                frame_index: self.next_frame_index,
                envelope_index: self.envelope.envelope_index,
                member_index,
                offset_in_envelope: offset,
                compressed_size: frame.len(),
                decompressed_size,
                member_start,
                member_offset,
                member_group_size,
            })?);
        self.next_frame_index =
            checked_u64_add(self.next_frame_index, 1, "PayloadFrame.frame_index")?;
        Ok(())
    }

    fn flush_payload_envelope(&mut self) -> Result<(), ArchiveWriteError> {
        if self.envelope.plaintext.is_empty() {
            return Ok(());
        }
        let plaintext_size = u32_len(
            self.envelope.plaintext.len(),
            "EnvelopeEntry.plaintext_size",
        )?;
        let object_plan = plan_encrypted_object(
            self.envelope.plaintext.len(),
            self.options.fec_data_shards,
            self.options.fec_parity_shards,
            self.options,
        )?;
        let extent = ObjectExtent::new(self.emission_state.next_block_index, object_plan)?;
        let object = encrypt_object(
            &self.envelope.plaintext,
            ObjectEncryptionContext {
                key: &self.subkeys.enc_key,
                nonce_seed: &self.subkeys.nonce_seed,
                domain: b"envelope",
                counter: self.envelope.envelope_index,
                data_kind: BlockKind::PayloadData,
                parity_kind: BlockKind::PayloadParity,
                data_shard_max: self.options.fec_data_shards,
                class_parity_shard_max: self.options.fec_parity_shards,
                archive_uuid: &self.archive_uuid,
                session_id: &self.session_id,
            },
            &mut self.emission_state.next_block_index,
            self.options,
        )?;
        validate_planned_extent(&object, extent)?;
        for record in &object.records {
            emit_block_record(
                self.sink,
                self.options,
                &mut self.emission_state.bytes_written,
                &mut self.emission_state.record_counts,
                self.emission_state.volume_format_rev,
                &mut self.emission_state.data_leaf_hashes,
                record,
            )?;
        }
        self.payload_block_count = checked_u64_add(
            self.payload_block_count,
            extent.data_block_count as u64,
            "payload",
        )?;
        self.payload_objects.push(PayloadObject {
            envelope_index: self.envelope.envelope_index,
            plaintext_size,
            object: extent,
        });
        self.envelope.envelope_index =
            checked_u64_add(self.envelope.envelope_index, 1, "EnvelopeEntry")?;
        self.envelope.plaintext.clear();
        Ok(())
    }

    fn finish(
        mut self,
        master_key: &MasterKey,
        kdf_params: &KdfParams,
        key_wrap_records: Option<&KeyWrapRecordSource>,
        root_auth: Option<RootAuthWriterConfig<'_>>,
        authenticator: Option<&mut RootAuthAuthenticator<'_>>,
        progress: Option<&SourceProgressHandle<'_>>,
    ) -> Result<WrittenArchiveSummary, ArchiveWriteError> {
        self.flush_payload_envelope()?;
        let digest = self.hasher.finalize();
        let mut content_sha256 = [0u8; 32];
        content_sha256.copy_from_slice(&digest);
        let payload = PayloadPlanning {
            tar_members: self.tar_members,
            frames: self.frames,
            payload_objects: self.payload_objects,
            payload_block_count: self.payload_block_count,
            tar_total_size: self.tar_total_size,
            content_sha256,
        };
        start_write_phase(progress, ArchiveWritePhase::EmittingMetadata);
        let plan = build_writer_plan_from_payload(
            payload,
            self.emission_state.next_block_index,
            master_key,
            self.options,
            None,
            kdf_params,
            key_wrap_records,
            self.archive_uuid,
            self.session_id,
            root_auth,
        )?;
        if plan.options != self.options || plan.crypto_header != self.crypto_header {
            return Err(FormatError::WriterUnsupported(
                "streaming tar stdin metadata exceeded the predeclared header class",
            )
            .into());
        }
        emit_writer_plan_suffix(
            &self.subkeys,
            root_auth,
            authenticator,
            plan,
            self.sink,
            self.emission_state,
        )
    }
}

struct PayloadFramePlanState<'a> {
    envelope: &'a mut PayloadEnvelopeBuilder,
    payload_objects: &'a mut Vec<PayloadObject>,
    payload_block_count: &'a mut u64,
    next_block_index: &'a mut u64,
    frames: &'a mut Vec<PayloadFrame>,
    next_frame_index: &'a mut u64,
    options: WriterOptions,
}

struct PayloadFramePlanInput<'a> {
    frame: &'a [u8],
    decompressed_size: usize,
    member_index: usize,
    member_start: u64,
    member_offset: u64,
    member_group_size: u64,
}

fn append_payload_frame_to_plan(
    state: PayloadFramePlanState<'_>,
    input: PayloadFramePlanInput<'_>,
) -> Result<(), FormatError> {
    if payload_envelope_needs_flush(state.envelope, input.frame.len(), state.options)? {
        flush_payload_envelope_plan(
            state.envelope,
            state.payload_objects,
            state.payload_block_count,
            state.next_block_index,
            state.options,
        )?;
    }
    if state.envelope.plaintext.is_empty()
        && !payload_object_can_fit(input.frame.len(), state.options)?
    {
        return Err(FormatError::WriterUnsupported(
            "payload frame exceeds envelope object limits",
        ));
    }
    let offset = u32_len(
        state.envelope.plaintext.len(),
        "FrameEntry.offset_in_envelope",
    )?;
    state.envelope.plaintext.extend_from_slice(input.frame);
    state
        .frames
        .push(payload_frame_metadata(PayloadFrameMetadataInput {
            frame_index: *state.next_frame_index,
            envelope_index: state.envelope.envelope_index,
            member_index: input.member_index,
            offset_in_envelope: offset,
            compressed_size: input.frame.len(),
            decompressed_size: input.decompressed_size,
            member_start: input.member_start,
            member_offset: input.member_offset,
            member_group_size: input.member_group_size,
        })?);
    *state.next_frame_index =
        checked_u64_add(*state.next_frame_index, 1, "PayloadFrame.frame_index")?;
    Ok(())
}

fn flush_payload_envelope_plan(
    envelope: &mut PayloadEnvelopeBuilder,
    payload_objects: &mut Vec<PayloadObject>,
    payload_block_count: &mut u64,
    next_block_index: &mut u64,
    options: WriterOptions,
) -> Result<(), FormatError> {
    let plaintext_size = u32_len(envelope.plaintext.len(), "EnvelopeEntry.plaintext_size")?;
    let object_plan = plan_encrypted_object(
        envelope.plaintext.len(),
        options.fec_data_shards,
        options.fec_parity_shards,
        options,
    )?;
    let extent = ObjectExtent::new(*next_block_index, object_plan)?;
    *next_block_index = extent.next_block_index()?;
    *payload_block_count = checked_u64_add(
        *payload_block_count,
        extent.data_block_count as u64,
        "payload",
    )?;
    payload_objects.push(PayloadObject {
        envelope_index: envelope.envelope_index,
        plaintext_size,
        object: extent,
    });
    envelope.envelope_index = checked_u64_add(envelope.envelope_index, 1, "EnvelopeEntry")?;
    envelope.plaintext.clear();
    Ok(())
}

fn required_stripe_width_for_plan(
    plan: &WriterPlan,
    master_key: &MasterKey,
    target_volume_size: u64,
) -> Result<u32, FormatError> {
    let subkeys = writer_subkeys(
        master_key,
        plan.options.aead_algo,
        &plan.archive_uuid,
        &plan.session_id,
    )?;
    let mut max_volume_size = 0u64;
    let mut max_overhead = 0u64;
    let block_record_len = plan.options.block_size as u64 + BLOCK_RECORD_FRAMING_LEN as u64;
    for volume_index in 0..plan.options.stripe_width {
        let block_count = striped_block_count(
            plan.total_block_count,
            plan.options.stripe_width,
            volume_index,
        );
        let volume_size = planned_v41_volume_size(plan, &subkeys, volume_index, block_count)?;
        max_volume_size = max_volume_size.max(volume_size);
        let record_bytes = checked_u64_mul(block_count, block_record_len, "volume records")?;
        let overhead =
            volume_size
                .checked_sub(record_bytes)
                .ok_or(FormatError::WriterInvariant(
                    "planned volume record overflow",
                ))?;
        max_overhead = max_overhead.max(overhead);
    }
    if max_volume_size <= target_volume_size {
        return Ok(plan.options.stripe_width);
    }
    if target_volume_size <= max_overhead {
        return Err(FormatError::WriterUnsupported(
            "volume-size is too small for per-volume metadata",
        ));
    }

    let records_per_volume = (target_volume_size - max_overhead) / block_record_len;
    if records_per_volume == 0 {
        return Err(FormatError::WriterUnsupported(
            "volume-size is too small for the configured block-size",
        ));
    }

    let required = ceil_div(plan.total_block_count, records_per_volume)?
        .max(plan.options.volume_loss_tolerance as u64 + 1)
        .max(1);
    u32::try_from(required).map_err(|_| FormatError::WriterUnsupported("volume count"))
}

fn planned_v41_volume_size(
    plan: &WriterPlan,
    subkeys: &Subkeys,
    volume_index: u32,
    block_count: u64,
) -> Result<u64, FormatError> {
    let volume_header = VolumeHeader {
        format_version: FORMAT_VERSION,
        volume_format_rev: plan.volume_format_rev,
        volume_index,
        stripe_width: plan.options.stripe_width,
        archive_uuid: plan.archive_uuid,
        session_id: plan.session_id,
        crypto_header_offset: VOLUME_HEADER_LEN as u32,
        crypto_header_length: u32_len(plan.crypto_header.len(), "CryptoHeader")?,
        header_crc32c: 0,
    };
    let volume_header_bytes = volume_header.to_bytes();
    let block_record_len = plan.options.block_size as u64 + BLOCK_RECORD_FRAMING_LEN as u64;
    let block_record_bytes = checked_u64_mul(block_count, block_record_len, "volume records")?;
    let manifest_footer_offset = checked_u64_add(
        plan.block_records_offset,
        block_record_bytes,
        "volume records",
    )?;
    let manifest_footer = build_manifest_footer(
        subkeys,
        plan.options.aead_algo,
        plan.volume_format_rev,
        plan.archive_uuid,
        plan.session_id,
        volume_index,
        plan.options.stripe_width,
        &plan.index_root_extent,
        plan.index_root_plaintext.len(),
    )?;
    let root_auth_footer = plan
        .root_auth_footer_length
        .map(|length| vec![0u8; length as usize]);
    let root_auth_footer_offset = root_auth_footer
        .as_ref()
        .map(|_| {
            checked_u64_add(
                manifest_footer_offset,
                MANIFEST_FOOTER_LEN as u64,
                "RootAuthFooterV1",
            )
        })
        .transpose()?;
    let trailer_offset = checked_u64_add(
        manifest_footer_offset,
        MANIFEST_FOOTER_LEN as u64 + u64::from(plan.root_auth_footer_length.unwrap_or(0)),
        "VolumeTrailer",
    )?;
    let trailer = build_volume_trailer(VolumeTrailerBuildInput {
        subkeys,
        aead_algo: plan.options.aead_algo,
        volume_format_rev: plan.volume_format_rev,
        archive_uuid: plan.archive_uuid,
        session_id: plan.session_id,
        volume_index,
        block_count,
        bytes_written: trailer_offset,
        manifest_footer_offset,
        closed_at_ns: plan.options.closed_at_ns,
        root_auth_footer: root_auth_footer_offset.zip(plan.root_auth_footer_length),
    })?;
    let cmra_offset = checked_u64_add(trailer_offset, VOLUME_TRAILER_LEN as u64, "CMRA")?;
    let cmra = build_v41_cmra(CmraBuildInput {
        volume_format_rev: plan.volume_format_rev,
        volume_header_bytes: &volume_header_bytes,
        crypto_header: &plan.crypto_header,
        block_count,
        block_records_offset: plan.block_records_offset,
        manifest_footer_offset,
        manifest_footer: &manifest_footer,
        root_auth_footer_offset,
        root_auth_footer: root_auth_footer.as_deref(),
        key_wrap_table: plan.key_wrap_table.as_deref(),
        trailer_offset,
        trailer: &trailer,
        cmra_offset,
        options: plan.options,
        archive_uuid: plan.archive_uuid,
        session_id: plan.session_id,
        volume_index,
    })?;
    checked_u64_add(
        checked_u64_add(cmra_offset, cmra.bytes.len() as u64, "CMRA")?,
        (CRITICAL_RECOVERY_LOCATOR_LEN * 2) as u64,
        "critical recovery locators",
    )
}

fn striped_block_count(total_block_count: u64, stripe_width: u32, volume_index: u32) -> u64 {
    let volume_index = volume_index as u64;
    let stripe_width = stripe_width as u64;
    if total_block_count <= volume_index {
        0
    } else {
        (total_block_count - 1 - volume_index) / stripe_width + 1
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_writer_plan<S, O>(
    files: &[S],
    master_key: &MasterKey,
    dictionary: Option<&[u8]>,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    authenticator: Option<&mut RootAuthAuthenticator<'_>>,
    plan: WriterPlan,
    sink: &mut O,
    progress: Option<&SourceProgressHandle<'_>>,
) -> Result<WrittenArchiveSummary, ArchiveWriteError>
where
    S: RegularFileSource,
    O: ArchiveWriteSink,
{
    let subkeys = writer_subkeys(
        master_key,
        plan.options.aead_algo,
        &plan.archive_uuid,
        &plan.session_id,
    )?;
    let mut state = begin_writer_emission_state(
        sink,
        plan.options,
        &plan.crypto_header,
        plan.key_wrap_table.as_deref(),
        plan.archive_uuid,
        plan.session_id,
        plan.volume_format_rev,
        root_auth.is_some(),
    )?;

    let emit_payload_started = Instant::now();
    emit_payload_stream(
        files,
        dictionary,
        &subkeys,
        &plan,
        &mut state.next_block_index,
        sink,
        &mut state.bytes_written,
        &mut state.record_counts,
        &mut state.data_leaf_hashes,
    )?;
    let emit_payload = emit_payload_started.elapsed();

    start_write_phase(progress, ArchiveWritePhase::EmittingMetadata);
    let mut summary =
        emit_writer_plan_suffix(&subkeys, root_auth, authenticator, plan, sink, state)?;
    summary.timings.emit_payload += emit_payload;
    Ok(summary)
}

fn start_write_phase(progress: Option<&SourceProgressHandle<'_>>, phase: ArchiveWritePhase) {
    if let Some(progress) = progress {
        progress.borrow_mut().start_phase(phase);
    }
}

fn emit_writer_plan_suffix<O: ArchiveWriteSink>(
    subkeys: &Subkeys,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    authenticator: Option<&mut RootAuthAuthenticator<'_>>,
    plan: WriterPlan,
    sink: &mut O,
    mut state: WriterEmissionState,
) -> Result<WrittenArchiveSummary, ArchiveWriteError> {
    let emit_metadata_started = Instant::now();
    let volume_count = plan.options.stripe_width as usize;

    for planned in &plan.index_shard_objects {
        emit_encrypted_object(
            &planned.compressed,
            &subkeys.index_shard_key,
            &subkeys.index_nonce_seed,
            b"idxshard",
            planned.shard_index,
            BlockKind::IndexShardData,
            BlockKind::IndexShardParity,
            plan.options.index_fec_data_shards,
            plan.options.index_fec_parity_shards,
            &mut state.next_block_index,
            plan.options,
            &plan.archive_uuid,
            &plan.session_id,
            planned.extent,
            None,
            plan.volume_format_rev,
            sink,
            &mut state.bytes_written,
            &mut state.record_counts,
            &mut state.data_leaf_hashes,
        )?;
    }

    let dictionary_records = if let (Some(compressed), Some((extent, _))) =
        (plan.compressed_dictionary.as_ref(), plan.dictionary_extent)
    {
        let object = emit_encrypted_object(
            compressed,
            &subkeys.dictionary_key,
            &subkeys.index_nonce_seed,
            b"dict",
            0,
            BlockKind::DictionaryData,
            BlockKind::DictionaryParity,
            plan.options.index_root_fec_data_shards,
            plan.options.index_root_fec_parity_shards,
            &mut state.next_block_index,
            plan.options,
            &plan.archive_uuid,
            &plan.session_id,
            extent,
            Some(MetadataObjectKind::Dictionary),
            plan.volume_format_rev,
            sink,
            &mut state.bytes_written,
            &mut state.record_counts,
            &mut state.data_leaf_hashes,
        )?;
        Some(object.records)
    } else {
        None
    };

    for planned in &plan.directory_hint_objects {
        emit_encrypted_object(
            &planned.compressed,
            &subkeys.dir_hint_key,
            &subkeys.index_nonce_seed,
            b"dirhint",
            planned.hint_shard_index,
            BlockKind::DirectoryHintData,
            BlockKind::DirectoryHintParity,
            plan.options.index_fec_data_shards,
            plan.options.index_fec_parity_shards,
            &mut state.next_block_index,
            plan.options,
            &plan.archive_uuid,
            &plan.session_id,
            planned.extent,
            None,
            plan.volume_format_rev,
            sink,
            &mut state.bytes_written,
            &mut state.record_counts,
            &mut state.data_leaf_hashes,
        )?;
    }

    let index_root_object = emit_encrypted_object(
        &plan.compressed_index_root,
        &subkeys.index_root_key,
        &subkeys.index_nonce_seed,
        b"idxroot",
        0,
        BlockKind::IndexRootData,
        BlockKind::IndexRootParity,
        plan.options.index_root_fec_data_shards,
        plan.options.index_root_fec_parity_shards,
        &mut state.next_block_index,
        plan.options,
        &plan.archive_uuid,
        &plan.session_id,
        plan.index_root_extent,
        Some(MetadataObjectKind::IndexRoot),
        plan.volume_format_rev,
        sink,
        &mut state.bytes_written,
        &mut state.record_counts,
        &mut state.data_leaf_hashes,
    )?;
    if state.next_block_index != plan.total_block_count {
        return Err(FormatError::WriterInvariant("streaming writer block plan mismatch").into());
    }

    let volume_zero_manifest = build_manifest_footer(
        subkeys,
        plan.options.aead_algo,
        plan.volume_format_rev,
        plan.archive_uuid,
        plan.session_id,
        0,
        plan.options.stripe_width,
        &plan.index_root_extent,
        plan.index_root_plaintext.len(),
    )?;
    let root_auth_footer = match root_auth {
        Some(config) => {
            let signer = authenticator.ok_or(FormatError::WriterInvariant(
                "missing root-auth authenticator",
            ))?;
            Some(build_root_auth_footer_from_leaf_hashes(
                config,
                signer,
                RootAuthFooterBuildInput {
                    archive_uuid: plan.archive_uuid,
                    session_id: plan.session_id,
                    volume_format_rev: plan.volume_format_rev,
                    options: plan.options,
                    crypto_header: &plan.crypto_header,
                    volume_zero_manifest: &volume_zero_manifest,
                    index_root_plaintext: &plan.index_root_plaintext,
                    index_root_extent: plan.index_root_extent,
                    dictionary_extent: plan.dictionary_extent,
                    shard_entries: &plan.shard_entries,
                    payload_objects: &plan.payload_objects,
                    directory_hint_entries: &plan.directory_hint_entries,
                    data_leaf_hashes: state.data_leaf_hashes.as_deref().ok_or(
                        FormatError::WriterInvariant("missing root-auth data leaf hashes"),
                    )?,
                },
            )?)
        }
        None => None,
    };
    let root_auth_footer_length = root_auth_footer
        .as_ref()
        .map(|footer| u32_len(footer.len(), "RootAuthFooterV1"))
        .transpose()?;

    for volume_index in 0..volume_count {
        let volume_index_u32 = u32::try_from(volume_index)
            .map_err(|_| FormatError::WriterUnsupported("volume_index"))?;
        let manifest_footer_offset = state.bytes_written[volume_index];
        let manifest_footer = build_manifest_footer(
            subkeys,
            plan.options.aead_algo,
            plan.volume_format_rev,
            plan.archive_uuid,
            plan.session_id,
            volume_index_u32,
            plan.options.stripe_width,
            &plan.index_root_extent,
            plan.index_root_plaintext.len(),
        )?;
        sink.write_volume(volume_index, &manifest_footer)?;
        state.bytes_written[volume_index] = checked_u64_add(
            state.bytes_written[volume_index],
            MANIFEST_FOOTER_LEN as u64,
            "ManifestFooter",
        )?;

        let root_auth_footer_offset = if let Some(root_auth_footer) = root_auth_footer.as_ref() {
            let offset = state.bytes_written[volume_index];
            sink.write_volume(volume_index, root_auth_footer)?;
            state.bytes_written[volume_index] = checked_u64_add(
                state.bytes_written[volume_index],
                root_auth_footer.len() as u64,
                "RootAuthFooterV1",
            )?;
            Some(offset)
        } else {
            None
        };

        let trailer_offset = state.bytes_written[volume_index];
        let trailer = build_volume_trailer(VolumeTrailerBuildInput {
            subkeys,
            aead_algo: plan.options.aead_algo,
            volume_format_rev: plan.volume_format_rev,
            archive_uuid: plan.archive_uuid,
            session_id: plan.session_id,
            volume_index: volume_index_u32,
            block_count: state.record_counts[volume_index],
            bytes_written: trailer_offset,
            manifest_footer_offset,
            closed_at_ns: plan.options.closed_at_ns,
            root_auth_footer: root_auth_footer_offset.zip(root_auth_footer_length),
        })?;
        sink.write_volume(volume_index, &trailer)?;
        state.bytes_written[volume_index] = checked_u64_add(
            state.bytes_written[volume_index],
            VOLUME_TRAILER_LEN as u64,
            "VolumeTrailer",
        )?;

        let cmra_offset = state.bytes_written[volume_index];
        let cmra = build_v41_cmra(CmraBuildInput {
            volume_format_rev: plan.volume_format_rev,
            volume_header_bytes: &state.volume_headers[volume_index],
            crypto_header: &plan.crypto_header,
            block_count: state.record_counts[volume_index],
            block_records_offset: plan.block_records_offset,
            manifest_footer_offset,
            manifest_footer: &manifest_footer,
            root_auth_footer_offset,
            root_auth_footer: root_auth_footer.as_deref(),
            key_wrap_table: plan.key_wrap_table.as_deref(),
            trailer_offset,
            trailer: &trailer,
            cmra_offset,
            options: plan.options,
            archive_uuid: plan.archive_uuid,
            session_id: plan.session_id,
            volume_index: volume_index_u32,
        })?;
        sink.write_volume(volume_index, &cmra.bytes)?;
        state.bytes_written[volume_index] = checked_u64_add(
            state.bytes_written[volume_index],
            cmra.bytes.len() as u64,
            "CMRA",
        )?;
        let locator_base = CriticalRecoveryLocator {
            volume_format_rev: plan.volume_format_rev,
            cmra_offset,
            cmra_length: u32_len(cmra.bytes.len(), "CMRA")?,
            volume_trailer_offset: trailer_offset,
            body_bytes_before_cmra: cmra_offset,
            archive_uuid_hint: plan.archive_uuid,
            session_id_hint: plan.session_id,
            volume_index_hint: volume_index_u32,
            locator_sequence: 1,
            cmra_shard_size: cmra.shard_size,
            cmra_data_shard_count: cmra.data_shard_count,
            cmra_parity_shard_count: cmra.parity_shard_count,
            cmra_image_length: cmra.image_length,
            cmra_image_sha256: cmra.image_sha256,
            locator_crc32c: 0,
        };
        let mirror = locator_base.to_bytes();
        sink.write_volume(volume_index, &mirror)?;
        let final_locator = CriticalRecoveryLocator {
            locator_sequence: 0,
            ..locator_base
        }
        .to_bytes();
        sink.write_volume(volume_index, &final_locator)?;
        state.bytes_written[volume_index] = checked_u64_add(
            state.bytes_written[volume_index],
            (CRITICAL_RECOVERY_LOCATOR_LEN * 2) as u64,
            "critical recovery locators",
        )?;

        if volume_index == 0 {
            debug_assert_eq!(volume_zero_manifest, manifest_footer);
        }
    }

    let bootstrap_sidecar_bytes = if plan.options.stripe_width == 1 {
        let sidecar = build_bootstrap_sidecar(
            subkeys,
            plan.options.aead_algo,
            plan.volume_format_rev,
            plan.archive_uuid,
            plan.session_id,
            &volume_zero_manifest,
            &index_root_object.records,
            dictionary_records.as_deref(),
        )?;
        let sidecar_len = sidecar.len() as u64;
        sink.write_bootstrap_sidecar(&sidecar)?;
        sidecar_len
    } else {
        0
    };

    Ok(WrittenArchiveSummary {
        volume_count,
        archive_bytes: state.bytes_written.iter().sum(),
        bootstrap_sidecar_bytes,
        archive_uuid: plan.archive_uuid,
        session_id: plan.session_id,
        timings: WriterTimings {
            emit_metadata: emit_metadata_started.elapsed(),
            ..WriterTimings::default()
        },
    })
}

#[allow(clippy::too_many_arguments)]
fn emit_encrypted_object<O: ArchiveWriteSink>(
    payload: &[u8],
    key: &[u8; 32],
    nonce_seed: &[u8; 32],
    domain: &[u8],
    counter: u64,
    data_kind: BlockKind,
    parity_kind: BlockKind,
    data_shard_max: u16,
    class_parity_shard_max: u16,
    next_block_index: &mut u64,
    options: WriterOptions,
    archive_uuid: &[u8; 16],
    session_id: &[u8; 16],
    expected_extent: ObjectExtent,
    metadata_kind: Option<MetadataObjectKind>,
    volume_format_rev: u16,
    sink: &mut O,
    bytes_written: &mut [u64],
    record_counts: &mut [u64],
    data_leaf_hashes: &mut Option<Vec<(u64, [u8; 32])>>,
) -> Result<EncryptedObject, ArchiveWriteError> {
    let object = encrypt_object(
        payload,
        ObjectEncryptionContext {
            key,
            nonce_seed,
            domain,
            counter,
            data_kind,
            parity_kind,
            data_shard_max,
            class_parity_shard_max,
            archive_uuid,
            session_id,
        },
        next_block_index,
        options,
    )
    .map_err(|error| match metadata_kind {
        Some(kind) => map_metadata_encrypt_error(error, kind),
        None => error,
    })?;
    validate_planned_extent(&object, expected_extent)?;
    for record in &object.records {
        emit_block_record(
            sink,
            options,
            bytes_written,
            record_counts,
            volume_format_rev,
            data_leaf_hashes,
            record,
        )?;
    }
    Ok(object)
}

fn emit_block_record<O: ArchiveWriteSink>(
    sink: &mut O,
    options: WriterOptions,
    bytes_written: &mut [u64],
    record_counts: &mut [u64],
    volume_format_rev: u16,
    data_leaf_hashes: &mut Option<Vec<(u64, [u8; 32])>>,
    record: &BlockRecord,
) -> Result<(), ArchiveWriteError> {
    let volume_index = (record.block_index % options.stripe_width as u64) as usize;
    let record_bytes = record.to_bytes();
    sink.write_volume(volume_index, &record_bytes)?;
    bytes_written[volume_index] = checked_u64_add(
        bytes_written[volume_index],
        record_bytes.len() as u64,
        "BlockRecord",
    )?;
    record_counts[volume_index] =
        checked_u64_add(record_counts[volume_index], 1, "BlockRecord count")?;
    if let Some(data_leaf_hashes) = data_leaf_hashes.as_mut() {
        if record.kind.is_data() {
            data_leaf_hashes.push((
                record.block_index,
                data_block_merkle_leaf_hash_for_revision(
                    FORMAT_VERSION,
                    volume_format_rev,
                    record.block_index,
                    record.kind,
                    record.flags,
                    &record.payload,
                )?,
            ));
        }
    }
    Ok(())
}

fn emit_serialized_block_record<O: ArchiveWriteSink>(
    sink: &mut O,
    options: WriterOptions,
    bytes_written: &mut [u64],
    record_counts: &mut [u64],
    record: &SerializedBlockRecord,
) -> Result<(), ArchiveWriteError> {
    let volume_index = (record.block_index % options.stripe_width as u64) as usize;
    sink.write_volume(volume_index, &record.bytes)?;
    bytes_written[volume_index] = checked_u64_add(
        bytes_written[volume_index],
        record.bytes.len() as u64,
        "BlockRecord",
    )?;
    record_counts[volume_index] =
        checked_u64_add(record_counts[volume_index], 1, "BlockRecord count")?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn emit_payload_stream<S, O>(
    files: &[S],
    dictionary: Option<&[u8]>,
    subkeys: &Subkeys,
    plan: &WriterPlan,
    next_block_index: &mut u64,
    sink: &mut O,
    bytes_written: &mut [u64],
    record_counts: &mut [u64],
    data_leaf_hashes: &mut Option<Vec<(u64, [u8; 32])>>,
) -> Result<(), ArchiveWriteError>
where
    S: RegularFileSource,
    O: ArchiveWriteSink,
{
    let mut envelope = PayloadEnvelopeBuilder {
        envelope_index: 0,
        plaintext: Vec::new(),
    };
    let mut next_frame_index = 0u64;

    for (member_index, file) in files.iter().enumerate() {
        let member = plan
            .tar_members
            .get(member_index)
            .ok_or(FormatError::WriterInvariant(
                "planned tar member is missing",
            ))?;
        let current_path =
            normalize_lookup_file_path(file.archive_path(), plan.options.max_path_length)?;
        if current_path != member.path
            || file.entry_kind() != member.entry_kind
            || file.link_target() != member.link_target.as_deref()
            || file.file_data_size() != member.file_data_size
            || file.sparse_extents() != member.sparse_extents.as_deref()
            || file.mode() != member.mode
            || file.mtime() != member.mtime
            || file.portable_metadata() != member.portable_metadata
        {
            return Err(FormatError::WriterInvariant(
                "file source changed between planning and emission",
            )
            .into());
        }
        let layout = build_primary_member_layout(
            &member.path,
            member.entry_kind,
            member.link_target.as_deref(),
            member.file_data_size,
            member.sparse_extents.as_deref(),
            member.mode,
            member.mtime,
            &member.portable_metadata,
        )?;
        let source_payload_size = member
            .sparse_extents
            .as_deref()
            .map(|extents| sparse_extent_bytes(extents, member.file_data_size))
            .transpose()?
            .unwrap_or(member.file_data_size);
        let actual_member_group_size = primary_member_layout_size(&layout, source_payload_size)?;
        if actual_member_group_size != member.tar_member_group_size {
            return Err(FormatError::WriterInvariant(
                "streamed auxiliary layout changed between planning and emission",
            )
            .into());
        }
        let mut reader = StreamingMemberReader::from_source(
            file,
            &member.portable_metadata,
            layout,
            source_payload_size,
        )?;
        let mut member_offset = 0u64;
        while member_offset < member.tar_member_group_size {
            let remaining = member.tar_member_group_size - member_offset;
            let max_chunk = remaining.min(plan.options.chunk_size as u64);
            let mut chunk = vec![0u8; to_usize_writer(max_chunk, "payload chunk")?];
            reader
                .read_exact(&mut chunk)
                .map_err(ArchiveWriteError::Io)?;
            let mut chunk_len = chunk.len();
            let frame = loop {
                let candidate = &chunk[..chunk_len];
                let frame = if let Some(dictionary) = dictionary {
                    compress_zstd_frame_with_dictionary_and_jobs(
                        candidate,
                        plan.options.zstd_level,
                        dictionary,
                        plan.options.jobs,
                    )?
                } else {
                    compress_zstd_frame_with_jobs(
                        candidate,
                        plan.options.zstd_level,
                        plan.options.jobs,
                    )?
                };
                if payload_object_can_fit(frame.len(), plan.options)? {
                    break frame;
                }
                if chunk_len == 1 {
                    return Err(FormatError::WriterUnsupported(
                        "single-byte payload frame exceeds envelope object limits",
                    )
                    .into());
                }
                chunk_len = (chunk_len / 2).max(1);
            };
            if chunk_len < chunk.len() {
                reader.push_back(chunk[chunk_len..].to_vec());
            }
            append_payload_frame_to_emit(
                &mut envelope,
                &frame,
                chunk_len,
                member_index,
                member.tar_member_group_start,
                member_offset,
                member.tar_member_group_size,
                &mut next_frame_index,
                subkeys,
                plan,
                next_block_index,
                sink,
                bytes_written,
                record_counts,
                data_leaf_hashes,
            )?;
            member_offset = checked_u64_add(member_offset, chunk_len as u64, "payload chunk")?;
        }
    }

    if !envelope.plaintext.is_empty() {
        flush_payload_envelope_emit(
            &mut envelope,
            subkeys,
            plan,
            next_block_index,
            sink,
            bytes_written,
            record_counts,
            data_leaf_hashes,
        )?;
    }
    if next_frame_index != plan.frames.len() as u64
        || envelope.envelope_index != plan.payload_objects.len() as u64
    {
        return Err(FormatError::WriterInvariant("streaming payload plan mismatch").into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn append_payload_frame_to_emit<O: ArchiveWriteSink>(
    envelope: &mut PayloadEnvelopeBuilder,
    frame: &[u8],
    decompressed_size: usize,
    member_index: usize,
    member_start: u64,
    member_offset: u64,
    member_group_size: u64,
    next_frame_index: &mut u64,
    subkeys: &Subkeys,
    plan: &WriterPlan,
    next_block_index: &mut u64,
    sink: &mut O,
    bytes_written: &mut [u64],
    record_counts: &mut [u64],
    data_leaf_hashes: &mut Option<Vec<(u64, [u8; 32])>>,
) -> Result<(), ArchiveWriteError> {
    if payload_envelope_needs_flush(envelope, frame.len(), plan.options)? {
        flush_payload_envelope_emit(
            envelope,
            subkeys,
            plan,
            next_block_index,
            sink,
            bytes_written,
            record_counts,
            data_leaf_hashes,
        )?;
    }
    if envelope.plaintext.is_empty() && !payload_object_can_fit(frame.len(), plan.options)? {
        return Err(
            FormatError::WriterUnsupported("payload frame exceeds envelope object limits").into(),
        );
    }
    let offset = u32_len(envelope.plaintext.len(), "FrameEntry.offset_in_envelope")?;
    let actual = payload_frame_metadata(PayloadFrameMetadataInput {
        frame_index: *next_frame_index,
        envelope_index: envelope.envelope_index,
        member_index,
        offset_in_envelope: offset,
        compressed_size: frame.len(),
        decompressed_size,
        member_start,
        member_offset,
        member_group_size,
    })?;
    let expected =
        plan.frames
            .get(*next_frame_index as usize)
            .ok_or(FormatError::WriterInvariant(
                "planned payload frame is missing",
            ))?;
    if expected.envelope_index != actual.envelope_index
        || expected.member_index != actual.member_index
        || expected.offset_in_envelope != actual.offset_in_envelope
        || expected.compressed_size != actual.compressed_size
        || expected.decompressed_size != actual.decompressed_size
        || expected.flags != actual.flags
        || expected.tar_stream_offset != actual.tar_stream_offset
    {
        return Err(
            FormatError::WriterInvariant("emitted payload frame does not match plan").into(),
        );
    }
    envelope.plaintext.extend_from_slice(frame);
    *next_frame_index = checked_u64_add(*next_frame_index, 1, "PayloadFrame.frame_index")?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn flush_payload_envelope_emit<O: ArchiveWriteSink>(
    envelope: &mut PayloadEnvelopeBuilder,
    subkeys: &Subkeys,
    plan: &WriterPlan,
    next_block_index: &mut u64,
    sink: &mut O,
    bytes_written: &mut [u64],
    record_counts: &mut [u64],
    data_leaf_hashes: &mut Option<Vec<(u64, [u8; 32])>>,
) -> Result<(), ArchiveWriteError> {
    let expected = plan
        .payload_objects
        .get(envelope.envelope_index as usize)
        .ok_or(FormatError::WriterInvariant(
            "planned payload envelope is missing",
        ))?;
    if expected.envelope_index != envelope.envelope_index
        || expected.plaintext_size
            != u32_len(envelope.plaintext.len(), "EnvelopeEntry.plaintext_size")?
    {
        return Err(
            FormatError::WriterInvariant("emitted payload envelope does not match plan").into(),
        );
    }
    emit_encrypted_object(
        &envelope.plaintext,
        &subkeys.enc_key,
        &subkeys.nonce_seed,
        b"envelope",
        envelope.envelope_index,
        BlockKind::PayloadData,
        BlockKind::PayloadParity,
        plan.options.fec_data_shards,
        plan.options.fec_parity_shards,
        next_block_index,
        plan.options,
        &plan.archive_uuid,
        &plan.session_id,
        expected.object,
        None,
        plan.volume_format_rev,
        sink,
        bytes_written,
        record_counts,
        data_leaf_hashes,
    )?;
    envelope.envelope_index = checked_u64_add(envelope.envelope_index, 1, "EnvelopeEntry")?;
    envelope.plaintext.clear();
    Ok(())
}

pub fn write_empty_archive(master_key: &MasterKey) -> Result<WrittenArchive, FormatError> {
    write_archive(&[], master_key, WriterOptions::default())
}

fn plan_writer_options(mut options: WriterOptions) -> Result<WriterOptions, FormatError> {
    if options.jobs == 0 {
        return Err(FormatError::WriterUnsupported("jobs must be at least 1"));
    }
    if options.block_size < MIN_BLOCK_SIZE || options.block_size % 2 != 0 {
        return Err(FormatError::WriterUnsupported(
            "writer requires an even block size of at least 4096",
        ));
    }
    if options.stripe_width == 0 {
        return Err(FormatError::WriterUnsupported(
            "stripe_width must be non-zero",
        ));
    }
    if options.volume_loss_tolerance as u32 >= options.stripe_width {
        return Err(FormatError::WriterUnsupported(
            "volume_loss_tolerance must be less than stripe_width",
        ));
    }
    if options.stripe_width == 1 && options.volume_loss_tolerance != 0 {
        return Err(FormatError::WriterUnsupported(
            "single-volume archives cannot tolerate volume loss",
        ));
    }
    if matches!(options.target_volume_size, Some(0)) {
        return Err(FormatError::WriterUnsupported(
            "target_volume_size must be non-zero",
        ));
    }
    if options.bit_rot_buffer_pct > 100 {
        return Err(FormatError::WriterUnsupported(
            "bit_rot_buffer_pct must be at most 100",
        ));
    }
    if options.chunk_size == 0 || options.chunk_size > options.envelope_target_size {
        return Err(FormatError::WriterUnsupported(
            "chunk_size must be non-zero and no larger than envelope_target_size",
        ));
    }
    if options.fec_data_shards == 0
        || options.index_fec_data_shards == 0
        || options.index_root_fec_data_shards == 0
    {
        return Err(FormatError::WriterUnsupported(
            "FEC data shard class maxima must be non-zero",
        ));
    }
    options.index_root_fec_data_shards = options
        .index_root_fec_data_shards
        .max(MIN_INDEX_ROOT_FEC_DATA_SHARDS);
    options.fec_parity_shards =
        compute_parity_u16(options.fec_data_shards as u64, options, "fec_parity_shards")?;
    options.index_fec_parity_shards = compute_parity_u16(
        options.index_fec_data_shards as u64,
        options,
        "index_fec_parity_shards",
    )?;
    options.index_root_fec_parity_shards = compute_parity_u16(
        options.index_root_fec_data_shards as u64,
        options,
        "index_root_fec_parity_shards",
    )?;
    validate_writer_options_match_reader_caps(options)?;
    Ok(options)
}

fn validate_writer_options_match_reader_caps(options: WriterOptions) -> Result<(), FormatError> {
    CryptoHeaderFixed {
        length: CRYPTO_HEADER_FIXED_LEN as u32,
        compression_algo: CompressionAlgo::ZstdFramed,
        aead_algo: options.aead_algo,
        fec_algo: FecAlgo::ReedSolomonGF16,
        kdf_algo: if options.aead_algo.is_encrypted() {
            KdfAlgo::Raw
        } else {
            KdfAlgo::None
        },
        chunk_size: options.chunk_size,
        envelope_target_size: options.envelope_target_size,
        block_size: options.block_size,
        fec_data_shards: options.fec_data_shards,
        fec_parity_shards: options.fec_parity_shards,
        index_fec_data_shards: options.index_fec_data_shards,
        index_fec_parity_shards: options.index_fec_parity_shards,
        index_root_fec_data_shards: options.index_root_fec_data_shards,
        index_root_fec_parity_shards: options.index_root_fec_parity_shards,
        stripe_width: options.stripe_width,
        volume_loss_tolerance: options.volume_loss_tolerance,
        bit_rot_buffer_pct: options.bit_rot_buffer_pct,
        has_dictionary: 0,
        max_path_length: options.max_path_length,
        expected_volume_size: options.target_volume_size.unwrap_or(0),
    }
    .validate_supported_profile()
}

fn build_crypto_header(
    options: WriterOptions,
    volume_format_rev: u16,
    has_dictionary: bool,
    subkeys: &Subkeys,
    archive_uuid: &[u8; 16],
    session_id: &[u8; 16],
    kdf_params: &KdfParams,
) -> Result<Vec<u8>, FormatError> {
    let kdf_payload = serialize_kdf_params(kdf_params)?;
    let length = CRYPTO_HEADER_FIXED_LEN
        .checked_add(kdf_payload.len())
        .and_then(|value| value.checked_add(CRYPTO_EXTENSION_HEADER_LEN))
        .and_then(|value| value.checked_add(CRYPTO_HEADER_HMAC_LEN))
        .ok_or(FormatError::WriterUnsupported(
            "CryptoHeader length overflow",
        ))?;
    let kdf_algo = match kdf_params {
        KdfParams::None => KdfAlgo::None,
        KdfParams::Raw => KdfAlgo::Raw,
        KdfParams::Argon2id { .. } => KdfAlgo::Argon2id,
        KdfParams::RecipientWrap { .. } => KdfAlgo::RecipientWrap,
    };
    match (options.aead_algo, kdf_algo) {
        (AeadAlgo::None, KdfAlgo::None) => {}
        (aead_algo, KdfAlgo::Raw | KdfAlgo::Argon2id | KdfAlgo::RecipientWrap)
            if aead_algo.is_encrypted() => {}
        _ => {
            return Err(FormatError::InvalidProtectionMode {
                aead_algo: options.aead_algo,
                kdf_algo,
            });
        }
    }
    let fixed = CryptoHeaderFixed {
        length: length as u32,
        compression_algo: CompressionAlgo::ZstdFramed,
        aead_algo: options.aead_algo,
        fec_algo: FecAlgo::ReedSolomonGF16,
        kdf_algo,
        chunk_size: options.chunk_size,
        envelope_target_size: options.envelope_target_size,
        block_size: options.block_size,
        fec_data_shards: options.fec_data_shards,
        fec_parity_shards: options.fec_parity_shards,
        index_fec_data_shards: options.index_fec_data_shards,
        index_fec_parity_shards: options.index_fec_parity_shards,
        index_root_fec_data_shards: options.index_root_fec_data_shards,
        index_root_fec_parity_shards: options.index_root_fec_parity_shards,
        stripe_width: options.stripe_width,
        volume_loss_tolerance: options.volume_loss_tolerance,
        bit_rot_buffer_pct: options.bit_rot_buffer_pct,
        has_dictionary: if has_dictionary { 1 } else { 0 },
        max_path_length: options.max_path_length,
        expected_volume_size: options.target_volume_size.unwrap_or(0),
    };

    let mut bytes = fixed.to_bytes().to_vec();
    bytes.extend_from_slice(&kdf_payload);
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    let hmac = compute_integrity_tag(
        HmacDomain::CryptoHeader,
        options.aead_algo,
        volume_format_rev,
        Some(&subkeys.mac_key),
        archive_uuid,
        session_id,
        &bytes,
    )?;
    bytes.extend_from_slice(&hmac);
    Ok(bytes)
}

fn serialize_kdf_params(params: &KdfParams) -> Result<Vec<u8>, FormatError> {
    let mut bytes = Vec::new();
    match params {
        KdfParams::None => {
            bytes.extend_from_slice(&(KdfAlgo::None as u16).to_le_bytes());
        }
        KdfParams::Raw => {
            bytes.extend_from_slice(&(KdfAlgo::Raw as u16).to_le_bytes());
        }
        KdfParams::Argon2id {
            t_cost,
            m_cost_kib,
            parallelism,
            salt,
        } => {
            if *t_cost == 0 {
                return Err(FormatError::InvalidKdfParams("t_cost must be non-zero"));
            }
            if *parallelism == 0 {
                return Err(FormatError::InvalidKdfParams(
                    "parallelism must be non-zero",
                ));
            }
            let min_memory = parallelism
                .checked_mul(8)
                .ok_or(FormatError::InvalidKdfParams(
                    "m_cost_kib requirement overflow",
                ))?;
            if *m_cost_kib < min_memory {
                return Err(FormatError::InvalidKdfParams(
                    "m_cost_kib must be at least 8 * parallelism",
                ));
            }
            if !(8..=64).contains(&salt.len()) {
                return Err(FormatError::InvalidKdfParams(
                    "argon2id salt length must be 8..64",
                ));
            }
            let salt_len = u16::try_from(salt.len())
                .map_err(|_| FormatError::InvalidKdfParams("argon2id salt too long"))?;
            bytes.extend_from_slice(&(KdfAlgo::Argon2id as u16).to_le_bytes());
            bytes.extend_from_slice(&t_cost.to_le_bytes());
            bytes.extend_from_slice(&m_cost_kib.to_le_bytes());
            bytes.extend_from_slice(&parallelism.to_le_bytes());
            bytes.extend_from_slice(&salt_len.to_le_bytes());
            bytes.extend_from_slice(salt);
        }
        KdfParams::RecipientWrap {
            key_wrap_table_length,
            key_wrap_table_record_count,
            key_wrap_table_version,
            key_wrap_table_digest,
        } => {
            bytes.extend_from_slice(&(KdfAlgo::RecipientWrap as u16).to_le_bytes());
            bytes.extend_from_slice(&key_wrap_table_length.to_le_bytes());
            bytes.extend_from_slice(&key_wrap_table_record_count.to_le_bytes());
            bytes.extend_from_slice(&key_wrap_table_version.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(key_wrap_table_digest);
        }
    }
    Ok(bytes)
}

#[cfg(test)]
fn build_tar_stream<S: RegularFileSource>(
    files: &[S],
    max_path_length: u32,
) -> Result<(Vec<u8>, Vec<TarMember>), FormatError> {
    let mut stream = Vec::new();
    let mut members = Vec::with_capacity(files.len());
    for file in files {
        let path = normalize_lookup_file_path(file.archive_path(), max_path_length)?;
        let start = stream.len() as u64;
        let sparse_extents = file.sparse_extents().map(<[SparseExtent]>::to_vec);
        let source_payload_size = sparse_extents
            .as_deref()
            .map(|extents| sparse_extent_bytes(extents, file.file_data_size()))
            .transpose()?
            .unwrap_or(file.file_data_size());
        let mut member_group = build_primary_member_prefix(
            &path,
            file.entry_kind(),
            file.link_target(),
            file.file_data_size(),
            sparse_extents.as_deref(),
            file.mode(),
            file.mtime(),
            &file.portable_metadata(),
        )?;
        let mut reader = file
            .open()
            .map_err(|_| FormatError::WriterInvariant("test source failed to open"))?;
        let mut payload = Vec::new();
        reader
            .read_to_end(&mut payload)
            .map_err(|_| FormatError::WriterInvariant("test source failed to read"))?;
        if payload.len() as u64 != source_payload_size {
            return Err(FormatError::WriterInvariant(
                "test source payload size mismatch",
            ));
        }
        member_group.extend_from_slice(&payload);
        member_group.resize(
            member_group.len() + padding_to_512(source_payload_size as usize),
            0,
        );
        stream.extend_from_slice(&member_group);
        members.push(TarMember {
            path,
            entry_kind: file.entry_kind(),
            link_target: file.link_target().map(<[u8]>::to_vec),
            tar_member_group_start: start,
            tar_member_group_size: member_group.len() as u64,
            file_data_size: file.file_data_size(),
            sparse_extents,
            mode: file.mode(),
            mtime: file.mtime(),
            portable_metadata: file.portable_metadata(),
        });
    }
    Ok((stream, members))
}

#[cfg(test)]
fn build_payload_envelopes(
    tar_stream: &[u8],
    members: &[TarMember],
    options: WriterOptions,
    dictionary: Option<&[u8]>,
) -> Result<(Vec<PayloadEnvelope>, Vec<PayloadFrame>), FormatError> {
    let chunk_size = options.chunk_size as usize;
    if chunk_size == 0 {
        return Err(FormatError::WriterUnsupported(
            "chunk_size must be non-zero and no larger than envelope_target_size",
        ));
    }
    let envelope_target_size = options.envelope_target_size as usize;
    let mut envelopes = Vec::new();
    let mut current = PayloadEnvelope {
        envelope_index: 0,
        plaintext: Vec::new(),
    };
    let mut frames = Vec::new();
    let mut next_frame_index = 0u64;

    for (member_index, member) in members.iter().enumerate() {
        let start = member.tar_member_group_start as usize;
        let end = checked_usize_add(start, member.tar_member_group_size as usize, "tar member")?;
        let member_bytes = tar_stream
            .get(start..end)
            .ok_or(FormatError::WriterInvariant(
                "tar member range is out of bounds",
            ))?;
        let mut member_offset = 0usize;
        while member_offset < member_bytes.len() {
            let mut chunk_len = (member_bytes.len() - member_offset).min(chunk_size);
            let frame = loop {
                let end = checked_usize_add(member_offset, chunk_len, "payload chunk")?;
                let chunk = &member_bytes[member_offset..end];
                let frame = if let Some(dictionary) = dictionary {
                    compress_zstd_frame_with_dictionary_and_jobs(
                        chunk,
                        options.zstd_level,
                        dictionary,
                        options.jobs,
                    )?
                } else {
                    compress_zstd_frame_with_jobs(chunk, options.zstd_level, options.jobs)?
                };
                if payload_object_can_fit(frame.len(), options)? {
                    break frame;
                }
                if chunk_len == 1 {
                    return Err(FormatError::WriterUnsupported(
                        "single-byte payload frame exceeds envelope object limits",
                    ));
                }
                chunk_len = (chunk_len / 2).max(1);
            };
            let next_len = checked_usize_add(current.plaintext.len(), frame.len(), "payload")?;
            if !current.plaintext.is_empty()
                && (next_len > envelope_target_size || !payload_object_can_fit(next_len, options)?)
            {
                envelopes.push(current);
                current = PayloadEnvelope {
                    envelope_index: envelopes.len() as u64,
                    plaintext: Vec::new(),
                };
            }

            if current.plaintext.is_empty() && !payload_object_can_fit(frame.len(), options)? {
                return Err(FormatError::WriterUnsupported(
                    "payload frame exceeds envelope object limits",
                ));
            }
            let offset = u32_len(current.plaintext.len(), "FrameEntry.offset_in_envelope")?;
            current.plaintext.extend_from_slice(&frame);
            let is_first_member_frame = member_offset == 0;
            let is_last_member_frame =
                checked_usize_add(member_offset, chunk_len, "payload chunk")? == member_bytes.len();
            let mut flags = 0u32;
            if is_first_member_frame {
                flags |= 0x0000_0001;
            }
            if is_last_member_frame {
                flags |= 0x0000_0002;
            }
            frames.push(PayloadFrame {
                frame_index: next_frame_index,
                envelope_index: current.envelope_index,
                member_index,
                offset_in_envelope: offset,
                compressed_size: u32_len(frame.len(), "FrameEntry.compressed_size")?,
                decompressed_size: u32_len(chunk_len, "FrameEntry.decompressed_size")?,
                flags,
                tar_stream_offset: checked_u64_add(
                    member.tar_member_group_start,
                    u64::try_from(member_offset)
                        .map_err(|_| FormatError::WriterUnsupported("chunk offset"))?,
                    "PayloadFrame.tar_stream_offset",
                )?,
            });
            next_frame_index = checked_u64_add(next_frame_index, 1, "PayloadFrame.frame_index")?;
            member_offset = checked_usize_add(member_offset, chunk_len, "payload chunk")?;
        }
    }
    if !current.plaintext.is_empty() {
        envelopes.push(current);
    }
    Ok((envelopes, frames))
}

fn sorted_file_rows(members: &[TarMember]) -> Vec<FileRow> {
    let mut rows = members
        .iter()
        .enumerate()
        .map(|(member_index, member)| FileRow {
            path_hash: hash_prefix(&member.path),
            path: member.path.clone(),
            member_index,
            member: member.clone(),
        })
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        (
            left.path_hash,
            left.path.as_slice(),
            left.member.tar_member_group_start,
        )
            .cmp(&(
                right.path_hash,
                right.path.as_slice(),
                right.member.tar_member_group_start,
            ))
    });
    rows
}

fn partition_file_rows(rows: Vec<FileRow>) -> Result<Vec<Vec<FileRow>>, FormatError> {
    let mut shards = Vec::new();
    let mut start = 0usize;
    while start < rows.len() {
        let mut end = (start + DEFAULT_FILES_PER_INDEX_SHARD).min(rows.len());
        if end < rows.len() && rows[end - 1].path_hash == rows[end].path_hash {
            let boundary_hash = rows[end].path_hash;
            let mut run_start_in_shard = end - 1;
            while run_start_in_shard > start
                && rows[run_start_in_shard - 1].path_hash == boundary_hash
            {
                run_start_in_shard -= 1;
            }
            let mut full_run_start = run_start_in_shard;
            while full_run_start > 0 && rows[full_run_start - 1].path_hash == boundary_hash {
                full_run_start -= 1;
            }
            let mut full_run_end = end + 1;
            while full_run_end < rows.len() && rows[full_run_end].path_hash == boundary_hash {
                full_run_end += 1;
            }
            let full_run_len = full_run_end - full_run_start;
            end = if full_run_len <= MAX_HASH_PREFIX_RUN_FILES {
                full_run_end
            } else {
                (run_start_in_shard + MAX_HASH_PREFIX_RUN_FILES).min(full_run_end)
            };
        }
        if end - start > MAX_FILES_PER_INDEX_SHARD {
            return Err(FormatError::WriterUnsupported(
                "hash-prefix collision run exceeds max_files_per_index_shard",
            ));
        }
        shards.push(rows[start..end].to_vec());
        start = end;
    }
    Ok(shards)
}

fn build_index_shard_plaintexts(
    shard_rows: &[Vec<FileRow>],
    frames: &[PayloadFrame],
    payloads: &[PayloadObject],
    options: WriterOptions,
) -> Result<Vec<PlannedIndexShard>, FormatError> {
    let mut planned = Vec::new();
    for rows in shard_rows {
        append_index_shards_for_rows(&mut planned, rows, frames, payloads, options)?;
    }
    Ok(planned)
}

fn append_index_shards_for_rows(
    planned: &mut Vec<PlannedIndexShard>,
    rows: &[FileRow],
    frames: &[PayloadFrame],
    payloads: &[PayloadObject],
    options: WriterOptions,
) -> Result<(), FormatError> {
    let shard_index =
        u64::try_from(planned.len()).map_err(|_| FormatError::WriterUnsupported("shard_index"))?;
    let candidate = build_index_shard_plaintext(shard_index, rows, frames, payloads, options)?;
    let compressed =
        compress_zstd_frame_with_jobs(&candidate.plaintext, options.zstd_level, options.jobs)?;
    if index_object_can_fit(compressed.len(), options)? {
        planned.push(candidate);
        return Ok(());
    }
    if rows.len() == 1 {
        return Err(FormatError::WriterUnsupported(
            "single-file IndexShard exceeds index object limits",
        ));
    }
    let split_at = split_sorted_file_rows_for_object_limit(rows);
    append_index_shards_for_rows(planned, &rows[..split_at], frames, payloads, options)?;
    append_index_shards_for_rows(planned, &rows[split_at..], frames, payloads, options)
}

fn split_sorted_file_rows_for_object_limit(rows: &[FileRow]) -> usize {
    let midpoint = rows.len() / 2;
    if rows[midpoint - 1].path_hash != rows[midpoint].path_hash {
        return midpoint;
    }

    let boundary_hash = rows[midpoint].path_hash;
    let mut left = midpoint;
    while left > 0 && rows[left - 1].path_hash == boundary_hash {
        left -= 1;
    }
    let mut right = midpoint;
    while right < rows.len() && rows[right].path_hash == boundary_hash {
        right += 1;
    }

    match (left > 0, right < rows.len()) {
        (true, true) if midpoint - left <= right - midpoint => left,
        (true, true) => right,
        (true, false) => left,
        (false, true) => right,
        (false, false) => midpoint,
    }
}

fn build_index_shard_plaintext(
    shard_index: u64,
    file_rows: &[FileRow],
    frames: &[PayloadFrame],
    payloads: &[PayloadObject],
    options: WriterOptions,
) -> Result<PlannedIndexShard, FormatError> {
    let mut string_pool = Vec::new();
    let mut file_entries = Vec::with_capacity(file_rows.len());
    let mut required_frame_indexes = BTreeSet::new();
    for row in file_rows {
        let path_offset = u32_len(string_pool.len(), "FileEntry.path_offset")?;
        string_pool.extend_from_slice(&row.path);
        let (first_frame_index, frame_count) = member_frame_range(row.member_index, frames)?;
        for offset in 0..frame_count as u64 {
            required_frame_indexes.insert(checked_u64_add(
                first_frame_index,
                offset,
                "FileEntry.frame_count",
            )?);
        }
        let (uname_offset, uname_length) = {
            let uname = row
                .member
                .portable_metadata
                .posix_owner
                .as_ref()
                .and_then(|o| o.uname.as_ref());
            match uname {
                Some(val) if !val.is_empty() => {
                    let bytes = val.as_bytes();
                    let offset = u32_len(string_pool.len(), "FileEntry.string_offset")?;
                    string_pool.extend_from_slice(bytes);
                    (offset, u32_len(bytes.len(), "FileEntry.string_length")?)
                }
                _ => (0, 0),
            }
        };

        let (gname_offset, gname_length) = {
            let gname = row
                .member
                .portable_metadata
                .posix_owner
                .as_ref()
                .and_then(|o| o.gname.as_ref());
            match gname {
                Some(val) if !val.is_empty() => {
                    let bytes = val.as_bytes();
                    let offset = u32_len(string_pool.len(), "FileEntry.string_offset")?;
                    string_pool.extend_from_slice(bytes);
                    (offset, u32_len(bytes.len(), "FileEntry.string_length")?)
                }
                _ => (0, 0),
            }
        };

        let (link_target_offset, link_target_length) = {
            match row.member.link_target.as_deref() {
                Some(val) if !val.is_empty() => {
                    let offset = u32_len(string_pool.len(), "FileEntry.string_offset")?;
                    string_pool.extend_from_slice(val);
                    (offset, u32_len(val.len(), "FileEntry.string_length")?)
                }
                _ => (0, 0),
            }
        };

        let kind_u8 = match row.member.entry_kind {
            SourceEntryKind::Regular | SourceEntryKind::ReparseRegular => {
                crate::tar_model::TarEntryKind::Regular.to_u8()
            }
            SourceEntryKind::Directory | SourceEntryKind::ReparseDirectory => {
                crate::tar_model::TarEntryKind::Directory.to_u8()
            }
            SourceEntryKind::Symlink => crate::tar_model::TarEntryKind::Symlink.to_u8(),
            SourceEntryKind::Hardlink => crate::tar_model::TarEntryKind::Hardlink.to_u8(),
            SourceEntryKind::CharacterDevice => {
                crate::tar_model::TarEntryKind::CharacterDevice.to_u8()
            }
            SourceEntryKind::BlockDevice => crate::tar_model::TarEntryKind::BlockDevice.to_u8(),
            SourceEntryKind::Fifo => crate::tar_model::TarEntryKind::Fifo.to_u8(),
        };

        let uid = row
            .member
            .portable_metadata
            .posix_owner
            .as_ref()
            .map(|o| o.uid)
            .unwrap_or(u64::MAX);
        let gid = row
            .member
            .portable_metadata
            .posix_owner
            .as_ref()
            .map(|o| o.gid)
            .unwrap_or(u64::MAX);

        let mut metadata_flags = 0u8;
        if row.member.portable_metadata.created.is_some() {
            metadata_flags |= 1;
        }
        if row.member.portable_metadata.accessed.is_some() {
            metadata_flags |= 2;
        }
        if row.member.portable_metadata.attributes.is_some() {
            metadata_flags |= 4;
        }

        file_entries.push(FileEntry {
            path_hash: row.path_hash,
            path_offset,
            path_length: u32_len(row.path.len(), "FileEntry.path_length")?,
            first_frame_index,
            frame_count,
            offset_in_first_frame_plaintext: 0,
            tar_member_group_size: row.member.tar_member_group_size,
            file_data_size: row.member.file_data_size,
            flags: v45_portable_file_entry_flags(
                row.member.mode,
                row.member.sparse_extents.is_some(),
                &row.member.portable_metadata,
            ),
            mtime_nsec: row.member.mtime.nanoseconds,
            mtime_sec: row.member.mtime.seconds,
            created_nsec: row
                .member
                .portable_metadata
                .created
                .as_ref()
                .map(|t| t.nanoseconds)
                .unwrap_or(0),
            created_sec: row
                .member
                .portable_metadata
                .created
                .as_ref()
                .map(|t| t.seconds)
                .unwrap_or(0),
            accessed_nsec: row
                .member
                .portable_metadata
                .accessed
                .as_ref()
                .map(|t| t.nanoseconds)
                .unwrap_or(0),
            accessed_sec: row
                .member
                .portable_metadata
                .accessed
                .as_ref()
                .map(|t| t.seconds)
                .unwrap_or(0),
            uid,
            gid,
            mode: row.member.mode,
            attributes: row.member.portable_metadata.attributes.unwrap_or(0),
            uname_offset,
            uname_length,
            gname_offset,
            gname_length,
            link_target_offset,
            link_target_length,
            kind: kind_u8,
            metadata_flags,
            _reserved1: 0,
            _reserved2: 0,
        });
    }

    let frame_entries = frames
        .iter()
        .filter(|frame| required_frame_indexes.contains(&frame.frame_index))
        .map(|frame| FrameEntry {
            frame_index: frame.frame_index,
            envelope_index: frame.envelope_index,
            offset_in_envelope: frame.offset_in_envelope,
            compressed_size: frame.compressed_size,
            decompressed_size: frame.decompressed_size,
            flags: frame.flags,
            tar_stream_offset: frame.tar_stream_offset,
        })
        .collect::<Vec<_>>();
    let required_envelope_indexes = frame_entries
        .iter()
        .map(|frame| frame.envelope_index)
        .collect::<BTreeSet<_>>();
    let envelope_entries = payloads
        .iter()
        .filter(|payload| required_envelope_indexes.contains(&payload.envelope_index))
        .map(|payload| {
            let (first_frame_index, frame_count) =
                envelope_frame_range(payload.envelope_index, frames)?;
            Ok(EnvelopeEntry {
                envelope_index: payload.envelope_index,
                first_block_index: payload.object.first_block_index,
                data_block_count: payload.object.data_block_count,
                parity_block_count: payload.object.parity_block_count,
                encrypted_size: payload.object.encrypted_size,
                plaintext_size: payload.plaintext_size,
                first_frame_index,
                frame_count,
            })
        })
        .collect::<Result<Vec<_>, FormatError>>()?;

    let plaintext = serialize_index_shard(
        shard_index,
        &file_entries,
        &frame_entries,
        &envelope_entries,
        &string_pool,
        options,
    )?;
    let first_path_hash = file_rows
        .first()
        .ok_or(FormatError::WriterInvariant("empty planned IndexShard"))?
        .path_hash;
    let last_path_hash = file_rows
        .last()
        .ok_or(FormatError::WriterInvariant("empty planned IndexShard"))?
        .path_hash;
    Ok(PlannedIndexShard {
        shard_index,
        plaintext,
        file_count: u32_len(file_rows.len(), "IndexShard.file_count")?,
        first_path_hash,
        last_path_hash,
    })
}

fn serialize_index_shard(
    shard_index: u64,
    files: &[FileEntry],
    frames: &[FrameEntry],
    envelopes: &[EnvelopeEntry],
    string_pool: &[u8],
    _options: WriterOptions,
) -> Result<Vec<u8>, FormatError> {
    let mut cursor = INDEX_SHARD_HEADER_LEN;
    let file_table_offset = table_offset(files.len(), cursor)?;
    cursor = checked_usize_add(cursor, files.len() * FILE_ENTRY_LEN, "IndexShard")?;
    let frame_table_offset = table_offset(frames.len(), cursor)?;
    cursor = checked_usize_add(cursor, frames.len() * FRAME_ENTRY_LEN, "IndexShard")?;
    let envelope_table_offset = table_offset(envelopes.len(), cursor)?;
    cursor = checked_usize_add(cursor, envelopes.len() * ENVELOPE_ENTRY_LEN, "IndexShard")?;
    let string_pool_offset = table_offset(string_pool.len(), cursor)?;

    let header = IndexShardHeader {
        version: 1,
        shard_index,
        file_count: u32_len(files.len(), "IndexShard.file_count")?,
        frame_count: u32_len(frames.len(), "IndexShard.frame_count")?,
        envelope_count: u32_len(envelopes.len(), "IndexShard.envelope_count")?,
        file_table_offset,
        frame_table_offset,
        envelope_table_offset,
        string_pool_offset,
        string_pool_size: u32_len(string_pool.len(), "IndexShard.string_pool_size")?,
    };

    let mut bytes = Vec::with_capacity(cursor + string_pool.len());
    bytes.extend_from_slice(&header.to_bytes());
    for entry in files {
        bytes.extend_from_slice(&entry.to_bytes());
    }
    for entry in frames {
        bytes.extend_from_slice(&entry.to_bytes());
    }
    for entry in envelopes {
        bytes.extend_from_slice(&entry.to_bytes());
    }
    bytes.extend_from_slice(string_pool);
    Ok(bytes)
}

fn build_directory_hint_plaintexts(
    shard_rows: &[Vec<FileRow>],
    options: WriterOptions,
) -> Result<Vec<PlannedDirectoryHintShard>, FormatError> {
    let mut map = BTreeMap::<Vec<u8>, BTreeSet<u32>>::new();
    for (shard_row_index, rows) in shard_rows.iter().enumerate() {
        let shard_row_index = u32::try_from(shard_row_index)
            .map_err(|_| FormatError::WriterUnsupported("directory hint shard row index"))?;
        for row in rows {
            add_directory_hint_rows(&mut map, shard_row_index, &row.path);
        }
    }

    let rows = map
        .into_iter()
        .map(|(path, shard_rows)| (hash_prefix(&path), path, shard_rows))
        .collect::<Vec<_>>();
    let mut rows = rows;
    rows.sort_by(|left, right| (left.0, left.1.as_slice()).cmp(&(right.0, right.1.as_slice())));

    let mut planned = Vec::new();
    for chunk in rows.chunks(DEFAULT_DIRECTORY_HINT_ENTRIES_PER_SHARD) {
        append_directory_hint_shards_for_rows(&mut planned, chunk, options)?;
    }
    Ok(planned)
}

fn append_directory_hint_shards_for_rows(
    planned: &mut Vec<PlannedDirectoryHintShard>,
    rows: &[([u8; 8], Vec<u8>, BTreeSet<u32>)],
    options: WriterOptions,
) -> Result<(), FormatError> {
    let hint_shard_index = u64::try_from(planned.len())
        .map_err(|_| FormatError::WriterUnsupported("hint_shard_index"))?;
    let candidate = build_directory_hint_plaintext(hint_shard_index, rows)?;
    let compressed =
        compress_zstd_frame_with_jobs(&candidate.plaintext, options.zstd_level, options.jobs)?;
    if index_object_can_fit(compressed.len(), options)? {
        planned.push(candidate);
        return Ok(());
    }
    if rows.len() == 1 {
        return Err(FormatError::WriterUnsupported(
            "single DirectoryHintEntry exceeds index object limits",
        ));
    }
    let split_at = rows.len() / 2;
    append_directory_hint_shards_for_rows(planned, &rows[..split_at], options)?;
    append_directory_hint_shards_for_rows(planned, &rows[split_at..], options)
}

fn add_directory_hint_rows(
    map: &mut BTreeMap<Vec<u8>, BTreeSet<u32>>,
    shard_row_index: u32,
    path: &[u8],
) {
    map.entry(Vec::new()).or_default().insert(shard_row_index);
    let mut cursor = 0usize;
    while let Some(position) = path[cursor..].iter().position(|byte| *byte == b'/') {
        let slash = cursor + position;
        if slash > 0 {
            map.entry(path[..slash].to_vec())
                .or_default()
                .insert(shard_row_index);
        }
        cursor = slash + 1;
    }
}

fn build_directory_hint_plaintext(
    hint_shard_index: u64,
    rows: &[([u8; 8], Vec<u8>, BTreeSet<u32>)],
) -> Result<PlannedDirectoryHintShard, FormatError> {
    let mut entries = Vec::with_capacity(rows.len());
    let mut shard_row_indexes = Vec::new();
    let mut string_pool = Vec::new();

    for (dir_hash, path, shard_rows) in rows {
        let path_offset = if path.is_empty() {
            0
        } else {
            u64::try_from(string_pool.len())
                .map_err(|_| FormatError::WriterUnsupported("DirectoryHintEntry.path_offset"))?
        };
        if !path.is_empty() {
            string_pool.extend_from_slice(path);
        }
        let shard_list_start_index = u32_len(
            shard_row_indexes.len(),
            "DirectoryHintEntry.shard_list_start_index",
        )?;
        shard_row_indexes.extend(shard_rows.iter().copied());
        entries.push(DirectoryHintEntry {
            dir_hash: *dir_hash,
            path_offset,
            path_length: u32_len(path.len(), "DirectoryHintEntry.path_length")?,
            shard_list_start_index,
            shard_count: u32_len(shard_rows.len(), "DirectoryHintEntry.shard_count")?,
        });
    }

    let plaintext = serialize_directory_hint_table(
        hint_shard_index,
        &entries,
        &shard_row_indexes,
        &string_pool,
    )?;
    let first_dir_hash = rows
        .first()
        .ok_or(FormatError::WriterInvariant("empty directory hint shard"))?
        .0;
    let last_dir_hash = rows
        .last()
        .ok_or(FormatError::WriterInvariant("empty directory hint shard"))?
        .0;
    Ok(PlannedDirectoryHintShard {
        hint_shard_index,
        plaintext,
        entry_count: rows.len() as u64,
        first_dir_hash,
        last_dir_hash,
    })
}

fn serialize_directory_hint_table(
    hint_shard_index: u64,
    entries: &[DirectoryHintEntry],
    shard_row_indexes: &[u32],
    string_pool: &[u8],
) -> Result<Vec<u8>, FormatError> {
    let entry_table_offset = table_offset(entries.len(), DIRECTORY_HINT_TABLE_LEN)?;
    let shard_list_cursor = checked_usize_add(
        DIRECTORY_HINT_TABLE_LEN,
        entries.len() * DIRECTORY_HINT_ENTRY_LEN,
        "DirectoryHintTable",
    )?;
    let shard_list_offset = table_offset(shard_row_indexes.len(), shard_list_cursor)?;
    let string_pool_cursor = checked_usize_add(
        shard_list_cursor,
        shard_row_indexes.len() * 4,
        "DirectoryHintTable",
    )?;
    let string_pool_offset = if string_pool.is_empty() {
        0
    } else {
        u64::try_from(string_pool_cursor)
            .map_err(|_| FormatError::WriterUnsupported("DirectoryHintTable.string_pool_offset"))?
    };
    let header = DirectoryHintTableHeader {
        version: 1,
        hint_shard_index,
        entry_count: entries.len() as u64,
        entry_table_offset: entry_table_offset as u64,
        shard_list_offset: shard_list_offset as u64,
        string_pool_offset,
        string_pool_size: string_pool.len() as u64,
    };

    let mut bytes = Vec::with_capacity(string_pool_cursor + string_pool.len());
    bytes.extend_from_slice(&header.to_bytes());
    for entry in entries {
        bytes.extend_from_slice(&entry.to_bytes());
    }
    for row in shard_row_indexes {
        bytes.extend_from_slice(&row.to_le_bytes());
    }
    bytes.extend_from_slice(string_pool);
    Ok(bytes)
}

#[derive(Debug, Clone, Copy)]
struct IndexRootPlaintextInput<'a> {
    shard_entries: &'a [ShardEntry],
    frame_count: u64,
    envelope_count: u64,
    file_count: u64,
    payload_block_count: u64,
    tar_total_size: u64,
    content_sha256: [u8; 32],
    directory_hint_entries: &'a [DirectoryHintShardEntry],
    dictionary_extent: Option<(ObjectExtent, u32)>,
}

fn build_index_root_plaintext(input: IndexRootPlaintextInput<'_>) -> Vec<u8> {
    let mut header = IndexRootHeader::empty();
    header.frame_count = input.frame_count;
    header.envelope_count = input.envelope_count;
    header.file_count = input.file_count;
    header.payload_block_count = input.payload_block_count;
    header.tar_total_size = input.tar_total_size;
    header.content_sha256 = input.content_sha256;
    if let Some((dictionary, decompressed_size)) = input.dictionary_extent {
        header.dictionary_first_block = dictionary.first_block_index;
        header.dictionary_data_block_count = dictionary.data_block_count;
        header.dictionary_parity_block_count = dictionary.parity_block_count;
        header.dictionary_encrypted_size = dictionary.encrypted_size;
        header.dictionary_decompressed_size = decompressed_size;
    }
    let root = IndexRoot {
        header,
        shards: input.shard_entries.to_vec(),
        directory_hint_shards: input.directory_hint_entries.to_vec(),
    };
    root.to_bytes()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MetadataClassPlan {
    options: WriterOptions,
    index_root: PlannedEncryptedObject,
    dictionary: Option<PlannedEncryptedObject>,
}

fn plan_index_root_metadata_class(
    mut options: WriterOptions,
    compressed_index_root_len: usize,
    compressed_dictionary_len: Option<usize>,
) -> Result<MetadataClassPlan, FormatError> {
    let index_root = plan_metadata_object_without_class(
        compressed_index_root_len,
        options,
        MetadataObjectKind::IndexRoot,
    )?;
    let dictionary = compressed_dictionary_len
        .map(|len| plan_metadata_object_without_class(len, options, MetadataObjectKind::Dictionary))
        .transpose()?;
    let required_data_shards = u32::from(options.index_root_fec_data_shards)
        .max(MIN_INDEX_ROOT_FEC_DATA_SHARDS as u32)
        .max(index_root.data_block_count)
        .max(dictionary.map(|plan| plan.data_block_count).unwrap_or(0));
    let required_data_shards = u16::try_from(required_data_shards)
        .map_err(|_| MetadataObjectKind::IndexRoot.too_large_error())?;
    options.index_root_fec_data_shards = required_data_shards;
    let required_parity_shards = compute_parity_u16(
        options.index_root_fec_data_shards as u64,
        options,
        "index_root_fec_parity_shards",
    )?;
    options.index_root_fec_parity_shards = options
        .index_root_fec_parity_shards
        .max(required_parity_shards);
    ensure_metadata_object_fits_class(index_root, options, MetadataObjectKind::IndexRoot)?;
    if let Some(dictionary) = dictionary {
        ensure_metadata_object_fits_class(dictionary, options, MetadataObjectKind::Dictionary)?;
    }
    Ok(MetadataClassPlan {
        options,
        index_root,
        dictionary,
    })
}

fn plan_metadata_object_without_class(
    payload_len: usize,
    options: WriterOptions,
    kind: MetadataObjectKind,
) -> Result<PlannedEncryptedObject, FormatError> {
    let plan = plan_encrypted_object_without_class(payload_len, options)
        .map_err(|_| kind.too_large_error())?;
    if plan.data_block_count > u16::MAX as u32 || plan.parity_block_count > u16::MAX as u32 {
        return Err(kind.too_large_error());
    }
    validate_object_shard_total(plan.data_block_count, plan.parity_block_count)
        .map_err(|_| kind.too_large_error())?;
    Ok(plan)
}

fn ensure_metadata_object_fits_class(
    plan: PlannedEncryptedObject,
    options: WriterOptions,
    kind: MetadataObjectKind,
) -> Result<(), FormatError> {
    if plan.data_block_count > options.index_root_fec_data_shards as u32 {
        return Err(kind.too_large_error());
    }
    if plan.parity_block_count > options.index_root_fec_parity_shards as u32 {
        return Err(kind.too_large_error());
    }
    validate_object_shard_total(plan.data_block_count, plan.parity_block_count)
        .map_err(|_| kind.too_large_error())
}

fn payload_object_can_fit(payload_len: usize, options: WriterOptions) -> Result<bool, FormatError> {
    encrypted_object_can_fit(
        payload_len,
        options.fec_data_shards,
        options.fec_parity_shards,
        options,
    )
}

fn index_object_can_fit(payload_len: usize, options: WriterOptions) -> Result<bool, FormatError> {
    encrypted_object_can_fit(
        payload_len,
        options.index_fec_data_shards,
        options.index_fec_parity_shards,
        options,
    )
}

fn encrypted_object_can_fit(
    payload_len: usize,
    data_shard_max: u16,
    parity_shard_max: u16,
    options: WriterOptions,
) -> Result<bool, FormatError> {
    match plan_encrypted_object(payload_len, data_shard_max, parity_shard_max, options) {
        Ok(_) => Ok(true),
        Err(FormatError::WriterUnsupported("encrypted object exceeds u32 size limit"))
        | Err(FormatError::WriterUnsupported(
            "encrypted object exceeds its data shard class maximum",
        ))
        | Err(FormatError::WriterUnsupported(
            "encrypted object exceeds its parity shard class maximum",
        ))
        | Err(FormatError::WriterUnsupported(
            "encrypted object exceeds ReedSolomonGF16 shard limit",
        )) => Ok(false),
        Err(err) => Err(err),
    }
}

fn plan_encrypted_object(
    payload_len: usize,
    data_shard_max: u16,
    parity_shard_max: u16,
    options: WriterOptions,
) -> Result<PlannedEncryptedObject, FormatError> {
    let plan = plan_encrypted_object_without_class(payload_len, options)?;
    if plan.data_block_count > data_shard_max as u32 {
        return Err(FormatError::WriterUnsupported(
            "encrypted object exceeds its data shard class maximum",
        ));
    }
    if plan.parity_block_count > parity_shard_max as u32 {
        return Err(FormatError::WriterUnsupported(
            "encrypted object exceeds its parity shard class maximum",
        ));
    }
    validate_object_shard_total(plan.data_block_count, plan.parity_block_count)?;
    Ok(plan)
}

fn plan_encrypted_object_without_class(
    payload_len: usize,
    options: WriterOptions,
) -> Result<PlannedEncryptedObject, FormatError> {
    let (data_block_count, encrypted_size) = encrypted_object_data_extent(payload_len, options)?;
    let parity_block_count = compute_parity(data_block_count as u64, options)?;
    Ok(PlannedEncryptedObject {
        data_block_count,
        parity_block_count,
        encrypted_size,
    })
}

fn encrypted_object_data_extent(
    payload_len: usize,
    options: WriterOptions,
) -> Result<(u32, u32), FormatError> {
    let block_size = options.block_size as usize;
    let tag_len = options.aead_algo.tag_len();
    let total_before_padding =
        payload_len
            .checked_add(tag_len)
            .ok_or(FormatError::WriterUnsupported(
                "encrypted object size overflow",
            ))?;
    let remainder = total_before_padding % block_size;
    let encrypted_size = if remainder == 0 {
        total_before_padding
            .checked_add(block_size)
            .ok_or(FormatError::WriterUnsupported(
                "encrypted object size overflow",
            ))?
    } else {
        total_before_padding
            .checked_add(block_size - remainder)
            .ok_or(FormatError::WriterUnsupported(
                "encrypted object size overflow",
            ))?
    };
    let encrypted_size = u32_len(encrypted_size, "encrypted_size")
        .map_err(|_| FormatError::WriterUnsupported("encrypted object exceeds u32 size limit"))?;
    Ok((encrypted_size / options.block_size, encrypted_size))
}

#[derive(Debug, Clone, Copy)]
struct ObjectEncryptionContext<'a> {
    key: &'a [u8; 32],
    nonce_seed: &'a [u8; 32],
    domain: &'a [u8],
    counter: u64,
    data_kind: BlockKind,
    parity_kind: BlockKind,
    data_shard_max: u16,
    class_parity_shard_max: u16,
    archive_uuid: &'a [u8; 16],
    session_id: &'a [u8; 16],
}

fn encrypt_object(
    payload: &[u8],
    context: ObjectEncryptionContext<'_>,
    next_block_index: &mut u64,
    options: WriterOptions,
) -> Result<EncryptedObject, FormatError> {
    let block_size = options.block_size as usize;
    let encrypted = encrypt_object_payload(payload, context, options)?;
    if encrypted.len() % block_size != 0 {
        return Err(FormatError::WriterInvariant(
            "encrypted object is not block aligned",
        ));
    }
    let encrypted_size = u32_len(encrypted.len(), "encrypted_size")?;
    let data_shards = encrypted
        .chunks(block_size)
        .map(|chunk| chunk.to_vec())
        .collect::<Vec<_>>();
    let data_block_count = u32_len(data_shards.len(), "data_block_count")?;
    if data_block_count == 0 {
        return Err(FormatError::WriterInvariant(
            "encrypted object has no data blocks",
        ));
    }
    if data_block_count > context.data_shard_max as u32 {
        return Err(FormatError::WriterUnsupported(
            "encrypted object exceeds its data shard class maximum",
        ));
    }
    let required_parity = compute_object_parity(
        data_block_count as u64,
        options,
        context.class_parity_shard_max as u32,
    )?;
    if required_parity > context.class_parity_shard_max as u32 {
        return Err(FormatError::WriterUnsupported(
            "encrypted object exceeds its parity shard class maximum",
        ));
    }
    validate_object_shard_total(data_block_count, required_parity)?;
    let parity_count = required_parity as u16;
    let parity_shards = if parity_count == 0 {
        Vec::new()
    } else {
        encode_parity_gf16(&data_shards, parity_count as usize)?
    };

    let first_block_index = *next_block_index;
    let mut records = Vec::with_capacity(data_shards.len() + parity_shards.len());
    for (index, payload) in data_shards.into_iter().enumerate() {
        records.push(BlockRecord {
            block_index: checked_u64_add(first_block_index, index as u64, "BlockRecord")?,
            kind: context.data_kind,
            flags: if index + 1 == data_block_count as usize {
                0x01
            } else {
                0
            },
            payload,
            record_crc32c: 0,
        });
    }
    let parity_first_block = checked_u64_add(first_block_index, data_block_count as u64, "FEC")?;
    for (index, payload) in parity_shards.into_iter().enumerate() {
        records.push(BlockRecord {
            block_index: checked_u64_add(parity_first_block, index as u64, "BlockRecord")?,
            kind: context.parity_kind,
            flags: 0,
            payload,
            record_crc32c: 0,
        });
    }

    *next_block_index = checked_u64_add(
        first_block_index,
        data_block_count as u64 + parity_count as u64,
        "next_block_index",
    )?;

    Ok(EncryptedObject {
        first_block_index,
        data_block_count,
        parity_block_count: parity_count as u32,
        encrypted_size,
        records,
    })
}

fn serialize_zero_parity_encrypted_object(
    payload: &[u8],
    context: ObjectEncryptionContext<'_>,
    expected_extent: ObjectExtent,
    options: WriterOptions,
) -> Result<Vec<SerializedBlockRecord>, FormatError> {
    let planned = plan_encrypted_object(
        payload.len(),
        context.data_shard_max,
        context.class_parity_shard_max,
        options,
    )?;
    if planned.parity_block_count != 0 || expected_extent.parity_block_count != 0 {
        return Err(FormatError::WriterInvariant(
            "zero-parity serialization received a parity object",
        ));
    }
    if planned.data_block_count != expected_extent.data_block_count
        || planned.encrypted_size != expected_extent.encrypted_size
    {
        return Err(FormatError::WriterInvariant(
            "encrypted object did not match planned sizing",
        ));
    }

    let block_size = options.block_size as usize;
    let encrypted = encrypt_object_payload(payload, context, options)?;
    if encrypted.len() != expected_extent.encrypted_size as usize
        || encrypted.len() % block_size != 0
    {
        return Err(FormatError::WriterInvariant(
            "encrypted object did not match planned sizing",
        ));
    }
    let data_block_count = encrypted.len() / block_size;
    if data_block_count == 0 || data_block_count != expected_extent.data_block_count as usize {
        return Err(FormatError::WriterInvariant(
            "encrypted object did not match planned sizing",
        ));
    }

    let mut records = Vec::with_capacity(data_block_count);
    for (index, chunk) in encrypted.chunks(block_size).enumerate() {
        let block_index = checked_u64_add(
            expected_extent.first_block_index,
            index as u64,
            "BlockRecord",
        )?;
        let flags = if index + 1 == data_block_count {
            0x01
        } else {
            0
        };
        records.push(SerializedBlockRecord {
            block_index,
            bytes: BlockRecord::to_bytes_from_parts(block_index, context.data_kind, flags, chunk),
        });
    }
    Ok(records)
}

fn encrypt_object_payload(
    payload: &[u8],
    context: ObjectEncryptionContext<'_>,
    options: WriterOptions,
) -> Result<Vec<u8>, FormatError> {
    let block_size = options.block_size as usize;
    let padded = suffix_pad_for_aead(payload, options.aead_algo.tag_len(), block_size)?;
    if matches!(options.aead_algo, AeadAlgo::None) {
        return Ok(padded);
    }
    let nonce = derive_nonce(
        context.nonce_seed,
        context.domain,
        context.archive_uuid,
        context.session_id,
        context.counter,
        options.aead_algo.nonce_len(),
    )?;
    let aad = build_aad(
        context.domain,
        context.archive_uuid,
        context.session_id,
        context.counter,
    )?;
    aead_encrypt(options.aead_algo, context.key, &nonce, &aad, &padded)
}

fn validate_planned_object(
    object: &EncryptedObject,
    expected: PlannedEncryptedObject,
) -> Result<(), FormatError> {
    if object.data_block_count != expected.data_block_count
        || object.parity_block_count != expected.parity_block_count
        || object.encrypted_size != expected.encrypted_size
    {
        return Err(FormatError::WriterInvariant(
            "encrypted object did not match planned sizing",
        ));
    }
    Ok(())
}

fn validate_planned_extent(
    object: &EncryptedObject,
    expected: ObjectExtent,
) -> Result<(), FormatError> {
    validate_planned_object(
        object,
        PlannedEncryptedObject {
            data_block_count: expected.data_block_count,
            parity_block_count: expected.parity_block_count,
            encrypted_size: expected.encrypted_size,
        },
    )?;
    if object.first_block_index != expected.first_block_index {
        return Err(FormatError::WriterInvariant(
            "encrypted object did not match planned extent",
        ));
    }
    Ok(())
}

fn map_metadata_encrypt_error(error: FormatError, kind: MetadataObjectKind) -> FormatError {
    match error {
        FormatError::WriterUnsupported("encrypted object exceeds u32 size limit")
        | FormatError::WriterUnsupported("encrypted object exceeds its data shard class maximum")
        | FormatError::WriterUnsupported(
            "encrypted object exceeds its parity shard class maximum",
        )
        | FormatError::WriterUnsupported("encrypted object exceeds ReedSolomonGF16 shard limit") => {
            kind.too_large_error()
        }
        other => other,
    }
}

#[derive(Debug, Clone, Copy)]
struct RootAuthFooterBuildInput<'a> {
    archive_uuid: [u8; 16],
    session_id: [u8; 16],
    volume_format_rev: u16,
    options: WriterOptions,
    crypto_header: &'a [u8],
    volume_zero_manifest: &'a [u8; MANIFEST_FOOTER_LEN],
    index_root_plaintext: &'a [u8],
    index_root_extent: ObjectExtent,
    dictionary_extent: Option<(ObjectExtent, u32)>,
    shard_entries: &'a [ShardEntry],
    payload_objects: &'a [PayloadObject],
    directory_hint_entries: &'a [DirectoryHintShardEntry],
    data_leaf_hashes: &'a [(u64, [u8; 32])],
}

fn build_root_auth_footer_from_leaf_hashes(
    config: RootAuthWriterConfig<'_>,
    authenticator: &mut RootAuthAuthenticator<'_>,
    input: RootAuthFooterBuildInput<'_>,
) -> Result<Vec<u8>, FormatError> {
    let mut sorted_leaf_hashes = input.data_leaf_hashes.to_vec();
    sorted_leaf_hashes.sort_by_key(|(block_index, _)| *block_index);
    let leaf_hashes = sorted_leaf_hashes
        .iter()
        .map(|(_, leaf_hash)| *leaf_hash)
        .collect::<Vec<_>>();
    let total_data_block_count = u64::try_from(leaf_hashes.len())
        .map_err(|_| FormatError::WriterUnsupported("root-auth data block count"))?;
    let data_block_merkle_root = data_block_merkle_root_from_leaf_hashes_for_revision(
        FORMAT_VERSION,
        input.volume_format_rev,
        &leaf_hashes,
    )?;

    let parsed_crypto = CryptoHeader::parse(
        input.crypto_header,
        u32_len(input.crypto_header.len(), "CryptoHeader")?,
    )?;
    let footer_length = root_auth_footer_wire_length(
        config.signer_identity.len(),
        config.authenticator_value_length as usize,
    )?;
    let root_auth_descriptor_digest = root_auth_descriptor_digest_for_revision(
        FORMAT_VERSION,
        input.volume_format_rev,
        config.authenticator_id,
        config.signer_identity_type,
        config.signer_identity,
        config.authenticator_value_length,
        footer_length,
    )?;
    let signer_identity_digest =
        signer_identity_digest(config.signer_identity_type, config.signer_identity)?;
    let manifest_pre_hmac = manifest_footer_global_pre_hmac_bytes(input.volume_zero_manifest);
    let critical_metadata_digest = critical_metadata_digest(CriticalMetadataDigestInputs {
        archive_uuid: input.archive_uuid,
        session_id: input.session_id,
        format_version: FORMAT_VERSION,
        volume_format_rev: input.volume_format_rev,
        stripe_width: input.options.stripe_width,
        total_volumes: input.options.stripe_width,
        compression_algo: parsed_crypto.fixed.compression_algo,
        aead_algo: parsed_crypto.fixed.aead_algo,
        fec_algo: parsed_crypto.fixed.fec_algo,
        kdf_algo: parsed_crypto.fixed.kdf_algo,
        crypto_header_pre_hmac_bytes: parsed_crypto.hmac_covered_bytes,
        chunk_size: parsed_crypto.fixed.chunk_size,
        envelope_target_size: parsed_crypto.fixed.envelope_target_size,
        block_size: parsed_crypto.fixed.block_size,
        fec_data_shards: parsed_crypto.fixed.fec_data_shards,
        fec_parity_shards: parsed_crypto.fixed.fec_parity_shards,
        index_fec_data_shards: parsed_crypto.fixed.index_fec_data_shards,
        index_fec_parity_shards: parsed_crypto.fixed.index_fec_parity_shards,
        index_root_fec_data_shards: parsed_crypto.fixed.index_root_fec_data_shards,
        index_root_fec_parity_shards: parsed_crypto.fixed.index_root_fec_parity_shards,
        volume_loss_tolerance: parsed_crypto.fixed.volume_loss_tolerance,
        bit_rot_buffer_pct: parsed_crypto.fixed.bit_rot_buffer_pct,
        has_dictionary: parsed_crypto.fixed.has_dictionary,
        manifest_footer_global_pre_hmac_bytes: &manifest_pre_hmac,
        index_root_first_block: input.index_root_extent.first_block_index,
        index_root_data_block_count: input.index_root_extent.data_block_count,
        index_root_parity_block_count: input.index_root_extent.parity_block_count,
        index_root_encrypted_size: input.index_root_extent.encrypted_size,
        index_root_decompressed_size: u32_len(input.index_root_plaintext.len(), "IndexRoot")?,
        root_auth_descriptor_digest,
    })?;
    let index_digest = index_digest_for_revision(
        FORMAT_VERSION,
        input.volume_format_rev,
        input.index_root_plaintext,
    )?;
    let fec_layout_rows = writer_fec_layout_rows_from_extents(
        input.index_root_extent,
        u32_len(input.index_root_plaintext.len(), "IndexRoot")?,
        input.dictionary_extent,
        input.shard_entries,
        input.payload_objects,
        input.directory_hint_entries,
    );
    let expected_data_block_count = fec_layout_rows.iter().try_fold(0u64, |total, row| {
        if row.present {
            checked_u64_add(
                total,
                row.data_block_count as u64,
                "root-auth data block count",
            )
        } else {
            Ok(total)
        }
    })?;
    if expected_data_block_count != total_data_block_count {
        return Err(FormatError::WriterInvariant(
            "root-auth data block count does not match FEC layout",
        ));
    }
    let fec_layout_digest =
        fec_layout_digest_for_revision(FORMAT_VERSION, input.volume_format_rev, &fec_layout_rows)?;
    let archive_root = archive_root_for_revision(ArchiveRootInputs {
        archive_uuid: input.archive_uuid,
        session_id: input.session_id,
        format_version: FORMAT_VERSION,
        volume_format_rev: input.volume_format_rev,
        compression_algo: parsed_crypto.fixed.compression_algo,
        aead_algo: parsed_crypto.fixed.aead_algo,
        fec_algo: parsed_crypto.fixed.fec_algo,
        kdf_algo: parsed_crypto.fixed.kdf_algo,
        critical_metadata_digest,
        index_digest,
        fec_layout_digest,
        total_data_block_count,
        data_block_merkle_root,
        root_auth_descriptor_digest,
        signer_identity_digest,
    })?;
    let authenticator_value = authenticator(&RootAuthSigningRequest {
        root_auth_spec_id: root_auth_spec_id_for_revision(FORMAT_VERSION, input.volume_format_rev)?,
        archive_uuid: input.archive_uuid,
        session_id: input.session_id,
        archive_root,
    })?;
    if authenticator_value.len() != config.authenticator_value_length as usize {
        return Err(FormatError::WriterUnsupported(
            "root-auth authenticator length mismatch",
        ));
    }

    RootAuthFooterV1 {
        archive_uuid: input.archive_uuid,
        session_id: input.session_id,
        format_version: FORMAT_VERSION,
        volume_format_rev: input.volume_format_rev,
        authenticator_id: config.authenticator_id,
        signer_identity_type: config.signer_identity_type,
        signer_identity_bytes: config.signer_identity.to_vec(),
        authenticator_value,
        total_data_block_count,
        critical_metadata_digest,
        index_digest,
        fec_layout_digest,
        data_block_merkle_root,
        signer_identity_digest,
        archive_root,
        footer_crc32c: 0,
    }
    .to_bytes()
}

fn writer_fec_layout_rows_from_extents(
    index_root_extent: ObjectExtent,
    index_root_plain_size: u32,
    dictionary_extent: Option<(ObjectExtent, u32)>,
    shard_entries: &[ShardEntry],
    payload_objects: &[PayloadObject],
    directory_hint_entries: &[DirectoryHintShardEntry],
) -> Vec<FecLayoutObjectRow> {
    let mut rows = Vec::new();
    rows.push(FecLayoutObjectRow {
        object_class: 1,
        present: true,
        object_id: 0,
        first_block_index: index_root_extent.first_block_index,
        data_block_count: index_root_extent.data_block_count,
        parity_block_count: index_root_extent.parity_block_count,
        encrypted_size: index_root_extent.encrypted_size,
        plain_size: index_root_plain_size,
    });
    if let Some((dictionary, decompressed_size)) = dictionary_extent {
        rows.push(FecLayoutObjectRow {
            object_class: 2,
            present: true,
            object_id: 0,
            first_block_index: dictionary.first_block_index,
            data_block_count: dictionary.data_block_count,
            parity_block_count: dictionary.parity_block_count,
            encrypted_size: dictionary.encrypted_size,
            plain_size: decompressed_size,
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
    for entry in shard_entries {
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
    for payload in payload_objects {
        rows.push(FecLayoutObjectRow {
            object_class: 4,
            present: true,
            object_id: payload.envelope_index,
            first_block_index: payload.object.first_block_index,
            data_block_count: payload.object.data_block_count,
            parity_block_count: payload.object.parity_block_count,
            encrypted_size: payload.object.encrypted_size,
            plain_size: payload.plaintext_size,
        });
    }
    for entry in directory_hint_entries {
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
    rows
}

fn manifest_footer_global_pre_hmac_bytes(manifest_footer: &[u8; MANIFEST_FOOTER_LEN]) -> [u8; 104] {
    let mut bytes = [0u8; 104];
    bytes.copy_from_slice(&manifest_footer[..104]);
    bytes[36..40].fill(0);
    bytes
}

fn root_auth_footer_wire_length(
    signer_identity_len: usize,
    authenticator_value_len: usize,
) -> Result<u32, FormatError> {
    validate_root_auth_variable_lengths_for_writer(signer_identity_len, authenticator_value_len)?;
    let len = crate::format::ROOT_AUTH_FOOTER_FIXED_LEN
        .checked_add(signer_identity_len)
        .and_then(|value| value.checked_add(authenticator_value_len))
        .and_then(|value| value.checked_add(4))
        .ok_or(FormatError::WriterUnsupported(
            "RootAuthFooterV1 length overflow",
        ))?;
    if len > READER_MAX_ROOT_AUTH_FOOTER_LEN as usize {
        return Err(FormatError::ReaderResourceLimitExceeded {
            field: "RootAuthFooterV1 length",
            cap: READER_MAX_ROOT_AUTH_FOOTER_LEN as u64,
            actual: len as u64,
        });
    }
    u32::try_from(len).map_err(|_| FormatError::WriterUnsupported("RootAuthFooterV1 length"))
}

fn validate_root_auth_writer_config(config: RootAuthWriterConfig<'_>) -> Result<(), FormatError> {
    root_auth_footer_wire_length(
        config.signer_identity.len(),
        config.authenticator_value_length as usize,
    )?;
    Ok(())
}

fn validate_root_auth_variable_lengths_for_writer(
    signer_identity_len: usize,
    authenticator_value_len: usize,
) -> Result<(), FormatError> {
    if signer_identity_len > READER_MAX_ROOT_AUTH_SIGNER_IDENTITY_LEN as usize {
        return Err(FormatError::ReaderResourceLimitExceeded {
            field: "RootAuthFooterV1 signer identity length",
            cap: READER_MAX_ROOT_AUTH_SIGNER_IDENTITY_LEN as u64,
            actual: signer_identity_len as u64,
        });
    }
    if authenticator_value_len > READER_MAX_ROOT_AUTH_AUTHENTICATOR_VALUE_LEN as usize {
        return Err(FormatError::ReaderResourceLimitExceeded {
            field: "RootAuthFooterV1 authenticator value length",
            cap: READER_MAX_ROOT_AUTH_AUTHENTICATOR_VALUE_LEN as u64,
            actual: authenticator_value_len as u64,
        });
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_manifest_footer(
    subkeys: &Subkeys,
    aead_algo: AeadAlgo,
    volume_format_rev: u16,
    archive_uuid: [u8; 16],
    session_id: [u8; 16],
    volume_index: u32,
    total_volumes: u32,
    index_root_extent: &ObjectExtent,
    index_root_decompressed_size: usize,
) -> Result<[u8; MANIFEST_FOOTER_LEN], FormatError> {
    let mut footer = ManifestFooter {
        archive_uuid,
        session_id,
        volume_index,
        is_authoritative: 1,
        total_volumes,
        index_root_first_block: index_root_extent.first_block_index,
        index_root_data_block_count: index_root_extent.data_block_count,
        index_root_parity_block_count: index_root_extent.parity_block_count,
        index_root_encrypted_size: index_root_extent.encrypted_size,
        index_root_decompressed_size: u32_len(index_root_decompressed_size, "IndexRoot")?,
        manifest_hmac: [0u8; 32],
    };
    let mut bytes = footer.to_bytes();
    footer.manifest_hmac = compute_integrity_tag(
        HmacDomain::ManifestFooter,
        aead_algo,
        volume_format_rev,
        Some(&subkeys.mac_key),
        &archive_uuid,
        &session_id,
        &bytes[..104],
    )?;
    bytes = footer.to_bytes();
    Ok(bytes)
}

#[derive(Debug, Clone, Copy)]
struct VolumeTrailerBuildInput<'a> {
    subkeys: &'a Subkeys,
    aead_algo: AeadAlgo,
    volume_format_rev: u16,
    archive_uuid: [u8; 16],
    session_id: [u8; 16],
    volume_index: u32,
    block_count: u64,
    bytes_written: u64,
    manifest_footer_offset: u64,
    closed_at_ns: i64,
    root_auth_footer: Option<(u64, u32)>,
}

fn build_volume_trailer(
    input: VolumeTrailerBuildInput<'_>,
) -> Result<[u8; VOLUME_TRAILER_LEN], FormatError> {
    let (root_auth_footer_offset, root_auth_footer_length, root_auth_flags) =
        match input.root_auth_footer {
            Some((offset, length)) => (offset, length, 0x0000_0001),
            None => (0, 0, 0),
        };
    let mut trailer = VolumeTrailer {
        archive_uuid: input.archive_uuid,
        session_id: input.session_id,
        volume_index: input.volume_index,
        block_count: input.block_count,
        bytes_written: input.bytes_written,
        manifest_footer_offset: input.manifest_footer_offset,
        manifest_footer_length: MANIFEST_FOOTER_LEN as u32,
        closed_at_ns: input.closed_at_ns,
        root_auth_footer_offset,
        root_auth_footer_length,
        root_auth_flags,
        trailer_hmac: [0u8; 32],
    };
    let mut bytes = trailer.to_bytes();
    trailer.trailer_hmac = compute_integrity_tag(
        HmacDomain::VolumeTrailer,
        input.aead_algo,
        input.volume_format_rev,
        Some(&input.subkeys.mac_key),
        &input.archive_uuid,
        &input.session_id,
        &bytes[..96],
    )?;
    bytes = trailer.to_bytes();
    Ok(bytes)
}

struct BuiltCmra {
    bytes: Vec<u8>,
    shard_size: u32,
    data_shard_count: u16,
    parity_shard_count: u16,
    image_length: u32,
    image_sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
struct CmraBuildInput<'a> {
    volume_format_rev: u16,
    volume_header_bytes: &'a [u8; VOLUME_HEADER_LEN],
    crypto_header: &'a [u8],
    block_count: u64,
    block_records_offset: u64,
    manifest_footer_offset: u64,
    manifest_footer: &'a [u8; MANIFEST_FOOTER_LEN],
    root_auth_footer_offset: Option<u64>,
    root_auth_footer: Option<&'a [u8]>,
    key_wrap_table: Option<&'a [u8]>,
    trailer_offset: u64,
    trailer: &'a [u8; VOLUME_TRAILER_LEN],
    cmra_offset: u64,
    options: WriterOptions,
    archive_uuid: [u8; 16],
    session_id: [u8; 16],
    volume_index: u32,
}

fn build_v41_cmra(input: CmraBuildInput<'_>) -> Result<BuiltCmra, FormatError> {
    let block_record_len = input.options.block_size as u64 + BLOCK_RECORD_FRAMING_LEN as u64;
    let crypto_end = VOLUME_HEADER_LEN as u64 + input.crypto_header.len() as u64;
    let block_records_offset = input.block_records_offset;
    let key_wrap_table = input
        .key_wrap_table
        .map(|table| {
            if table.is_empty() {
                return Err(FormatError::WriterInvariant(
                    "KeyWrapTableV1 must include at least one recipient record",
                ));
            }
            let key_wrap_table_length = u32_len(table.len(), "KeyWrapTableV1 table_length")?;
            Ok((table, key_wrap_table_length))
        })
        .transpose()?;
    if input.volume_format_rev != VOLUME_FORMAT_REV_45 && key_wrap_table.is_some() {
        return Err(FormatError::WriterInvariant(
            "KeyWrapTableV1 requires volume_format_rev 45",
        ));
    }
    let key_wrap_table_length = key_wrap_table.map(|(_, length)| u64::from(length));
    let expected_block_records_offset = match key_wrap_table_length {
        Some(length) => checked_u64_add(crypto_end, length, "KeyWrapTableV1")?,
        None => crypto_end,
    };
    if block_records_offset != expected_block_records_offset {
        return Err(FormatError::WriterInvariant(
            "CMRA block records offset does not match key-wrap table layout",
        ));
    }
    let block_records_length = checked_u64_mul(
        input.block_count,
        block_record_len,
        "CMRA BlockRecord length overflow",
    )?;
    let manifest_end = input
        .manifest_footer_offset
        .checked_add(MANIFEST_FOOTER_LEN as u64)
        .ok_or(FormatError::WriterUnsupported("CMRA terminal overflow"))?;
    let root_auth_footer_length = input
        .root_auth_footer
        .map(|footer| u32_len(footer.len(), "RootAuthFooterV1"))
        .transpose()?;
    match (input.root_auth_footer_offset, root_auth_footer_length) {
        (Some(offset), Some(length)) => {
            if manifest_end != offset
                || offset
                    .checked_add(length as u64)
                    .ok_or(FormatError::WriterUnsupported("CMRA terminal overflow"))?
                    != input.trailer_offset
            {
                return Err(FormatError::WriterInvariant(
                    "RootAuthFooter does not sit between ManifestFooter and VolumeTrailer",
                ));
            }
        }
        (None, None) => {
            if manifest_end != input.trailer_offset {
                return Err(FormatError::WriterInvariant(
                    "ManifestFooter does not end at VolumeTrailer",
                ));
            }
        }
        _ => {
            return Err(FormatError::WriterInvariant(
                "RootAuthFooter offset/bytes mismatch",
            ));
        }
    }
    let body_bytes_before_cmra = input
        .trailer_offset
        .checked_add(VOLUME_TRAILER_LEN as u64)
        .ok_or(FormatError::WriterUnsupported("CMRA terminal overflow"))?;
    if body_bytes_before_cmra != input.cmra_offset {
        return Err(FormatError::WriterInvariant(
            "CMRA does not start after VolumeTrailer",
        ));
    }

    let mut regions = vec![
        SerializedRegion {
            region_type: 1,
            offset: 0,
            bytes: input.volume_header_bytes.to_vec(),
        },
        SerializedRegion {
            region_type: 2,
            offset: VOLUME_HEADER_LEN as u64,
            bytes: input.crypto_header.to_vec(),
        },
    ];
    if let Some((table, _)) = key_wrap_table {
        regions.push(SerializedRegion {
            region_type: 6,
            offset: crypto_end,
            bytes: table.to_vec(),
        });
    }
    regions.push(SerializedRegion {
        region_type: 3,
        offset: input.manifest_footer_offset,
        bytes: input.manifest_footer.to_vec(),
    });
    if let (Some(offset), Some(footer)) = (input.root_auth_footer_offset, input.root_auth_footer) {
        regions.push(SerializedRegion {
            region_type: 4,
            offset,
            bytes: footer.to_vec(),
        });
    }
    regions.push(SerializedRegion {
        region_type: 5,
        offset: input.trailer_offset,
        bytes: input.trailer.to_vec(),
    });
    let root_auth_flag = if input.root_auth_footer.is_some() {
        0x0000_0001
    } else {
        0
    };
    let key_wrap_flag = if key_wrap_table.is_some() {
        0x0000_0002
    } else {
        0
    };
    let image = CriticalMetadataImage {
        volume_format_rev: input.volume_format_rev,
        archive_uuid: input.archive_uuid,
        session_id: input.session_id,
        volume_index: input.volume_index,
        stripe_width: input.options.stripe_width,
        layout_flags: root_auth_flag | key_wrap_flag,
        volume_header_offset: 0,
        volume_header_length: VOLUME_HEADER_LEN as u32,
        crypto_header_offset: VOLUME_HEADER_LEN as u64,
        crypto_header_length: u32_len(input.crypto_header.len(), "CryptoHeader")?,
        key_wrap_table_offset: key_wrap_table.map(|_| crypto_end).unwrap_or(0),
        key_wrap_table_length: key_wrap_table.map(|(_, length)| length).unwrap_or(0),
        block_records_offset,
        block_records_length,
        block_count: input.block_count,
        manifest_footer_offset: input.manifest_footer_offset,
        manifest_footer_length: MANIFEST_FOOTER_LEN as u32,
        root_auth_footer_offset: input.root_auth_footer_offset.unwrap_or(0),
        root_auth_footer_length: root_auth_footer_length.unwrap_or(0),
        volume_trailer_offset: input.trailer_offset,
        volume_trailer_length: VOLUME_TRAILER_LEN as u32,
        body_bytes_before_cmra,
        volume_header_sha256: sha256_bytes(input.volume_header_bytes),
        crypto_header_sha256: sha256_bytes(input.crypto_header),
        key_wrap_table_sha256: key_wrap_table
            .map(|(table, _)| sha256_bytes(table))
            .unwrap_or([0u8; 32]),
        manifest_footer_sha256: sha256_bytes(input.manifest_footer),
        root_auth_footer_sha256: input
            .root_auth_footer
            .map(sha256_bytes)
            .unwrap_or([0u8; 32]),
        volume_trailer_sha256: sha256_bytes(input.trailer),
        regions,
    };
    let image_bytes = image.to_bytes()?;
    let image_sha256 = sha256_bytes(&image_bytes);
    let data_shard_count = ceil_div(image_bytes.len() as u64, CMRA_SHARD_SIZE as u64)?;
    let data_shard_count_u16 = u16::try_from(data_shard_count)
        .map_err(|_| FormatError::WriterUnsupported("CMRA data shard count"))?;
    let parity_lower = cmra_min_parity_shards(data_shard_count, input.options.bit_rot_buffer_pct)?;
    let parity_upper = cmra_min_parity_shards(data_shard_count, READER_MAX_CMRA_PARITY_PCT as u8)?;
    if parity_lower > parity_upper {
        return Err(FormatError::WriterUnsupported("CMRA parity bounds"));
    }
    let parity_shard_count_u16 = u16::try_from(parity_lower)
        .map_err(|_| FormatError::WriterUnsupported("CMRA parity shard count"))?;

    let mut data_shards = Vec::with_capacity(data_shard_count as usize);
    for idx in 0..data_shard_count as usize {
        let start = idx * CMRA_SHARD_SIZE;
        let end = (start + CMRA_SHARD_SIZE).min(image_bytes.len());
        let mut shard = vec![0u8; CMRA_SHARD_SIZE];
        if start < image_bytes.len() {
            shard[..end - start].copy_from_slice(&image_bytes[start..end]);
        }
        data_shards.push(shard);
    }
    let parity_shards = encode_parity_gf16(&data_shards, parity_shard_count_u16 as usize)?;

    let header = CriticalMetadataRecoveryHeader {
        shard_size: CMRA_SHARD_SIZE as u32,
        data_shard_count: data_shard_count_u16,
        parity_shard_count: parity_shard_count_u16,
        image_length: u32_len(image_bytes.len(), "CriticalMetadataImageV1")?,
        archive_uuid_hint: input.archive_uuid,
        session_id_hint: input.session_id,
        volume_index_hint: input.volume_index,
        image_sha256,
        header_crc32c: 0,
    };
    let mut cmra = Vec::new();
    cmra.extend_from_slice(&header.to_bytes());
    for (idx, payload) in data_shards.into_iter().enumerate() {
        let payload_len = if idx + 1 == data_shard_count as usize {
            let final_len = image_bytes.len() - idx * CMRA_SHARD_SIZE;
            if final_len == 0 {
                CMRA_SHARD_SIZE
            } else {
                final_len
            }
        } else {
            CMRA_SHARD_SIZE
        };
        cmra.extend_from_slice(
            &CriticalMetadataRecoveryShard {
                shard_index: u16::try_from(idx)
                    .map_err(|_| FormatError::WriterUnsupported("CMRA shard index"))?,
                shard_role: 0,
                shard_payload_length: u32_len(payload_len, "CMRA shard payload")?,
                payload,
                shard_crc32c: 0,
            }
            .to_bytes(CMRA_SHARD_SIZE)?,
        );
    }
    for (idx, payload) in parity_shards.into_iter().enumerate() {
        let shard_index = data_shard_count
            .checked_add(idx as u64)
            .ok_or(FormatError::WriterUnsupported("CMRA shard index overflow"))?;
        cmra.extend_from_slice(
            &CriticalMetadataRecoveryShard {
                shard_index: u16::try_from(shard_index)
                    .map_err(|_| FormatError::WriterUnsupported("CMRA shard index"))?,
                shard_role: 1,
                shard_payload_length: CMRA_SHARD_SIZE as u32,
                payload,
                shard_crc32c: 0,
            }
            .to_bytes(CMRA_SHARD_SIZE)?,
        );
    }

    Ok(BuiltCmra {
        bytes: cmra,
        shard_size: CMRA_SHARD_SIZE as u32,
        data_shard_count: data_shard_count_u16,
        parity_shard_count: parity_shard_count_u16,
        image_length: u32_len(image_bytes.len(), "CriticalMetadataImageV1")?,
        image_sha256,
    })
}

fn cmra_min_parity_shards(data_shard_count: u64, pct: u8) -> Result<u64, FormatError> {
    let by_pct = ceil_div(
        checked_u64_mul(data_shard_count, pct as u64, "CMRA parity overflow")?,
        100,
    )?;
    Ok(2u64.max(by_pct))
}

fn compute_object_parity(
    data_block_count: u64,
    options: WriterOptions,
    class_parity_shard_max: u32,
) -> Result<u32, FormatError> {
    let computed = compute_parity(data_block_count, options)?;
    if computed > class_parity_shard_max {
        return Err(FormatError::WriterUnsupported(
            "encrypted object exceeds its parity shard class maximum",
        ));
    }
    Ok(computed)
}

fn validate_object_shard_total(
    data_block_count: u32,
    parity_block_count: u32,
) -> Result<(), FormatError> {
    let total = checked_u64_add(
        data_block_count as u64,
        parity_block_count as u64,
        "encrypted object shard total overflow",
    )?;
    if total > MAX_REED_SOLOMON_GF16_SHARDS {
        return Err(FormatError::WriterUnsupported(
            "encrypted object exceeds ReedSolomonGF16 shard limit",
        ));
    }
    Ok(())
}

fn compute_parity_u16(
    data_block_count: u64,
    options: WriterOptions,
    field: &'static str,
) -> Result<u16, FormatError> {
    let parity = compute_parity(data_block_count, options)?;
    u16::try_from(parity).map_err(|_| FormatError::WriterUnsupported(field))
}

fn compute_parity(data_block_count: u64, options: WriterOptions) -> Result<u32, FormatError> {
    let min_parity = if options.volume_loss_tolerance > 0 || options.bit_rot_buffer_pct > 0 {
        1u64
    } else {
        0u64
    };
    let mut parity = 0u64;
    for _ in 0..100 {
        let total = data_block_count
            .checked_add(parity)
            .ok_or(FormatError::WriterUnsupported("parity total overflow"))?;
        let by_volume = checked_u64_mul(
            options.volume_loss_tolerance as u64,
            ceil_div(total, options.stripe_width as u64)?,
            "volume-loss parity overflow",
        )?;
        let by_bitrot = ceil_div(
            checked_u64_mul(
                total,
                options.bit_rot_buffer_pct as u64,
                "bit-rot parity overflow",
            )?,
            100,
        )?;
        let next = by_volume
            .checked_add(by_bitrot)
            .ok_or(FormatError::WriterUnsupported("parity overflow"))?
            .max(min_parity);
        if next == parity {
            return u32::try_from(next).map_err(|_| FormatError::WriterUnsupported("parity count"));
        }
        parity = next;
    }
    Err(FormatError::WriterUnsupported(
        "parity calculation did not converge",
    ))
}

fn ceil_div(numerator: u64, denominator: u64) -> Result<u64, FormatError> {
    if denominator == 0 {
        return Err(FormatError::WriterUnsupported("division by zero"));
    }
    numerator
        .checked_add(denominator - 1)
        .ok_or(FormatError::WriterUnsupported("ceiling division overflow"))
        .map(|value| value / denominator)
}

fn checked_u64_mul(lhs: u64, rhs: u64, field: &'static str) -> Result<u64, FormatError> {
    lhs.checked_mul(rhs)
        .ok_or(FormatError::WriterUnsupported(field))
}

#[allow(clippy::too_many_arguments)]
fn build_bootstrap_sidecar(
    subkeys: &Subkeys,
    aead_algo: AeadAlgo,
    volume_format_rev: u16,
    archive_uuid: [u8; 16],
    session_id: [u8; 16],
    manifest_footer: &[u8; MANIFEST_FOOTER_LEN],
    index_root_records: &[BlockRecord],
    dictionary_records: Option<&[BlockRecord]>,
) -> Result<Vec<u8>, FormatError> {
    let index_records_len = index_root_records.iter().try_fold(0usize, |sum, record| {
        checked_usize_add(sum, record.to_bytes().len(), "bootstrap sidecar")
    })?;
    let dictionary_records_len = dictionary_records
        .unwrap_or(&[])
        .iter()
        .try_fold(0usize, |sum, record| {
            checked_usize_add(sum, record.to_bytes().len(), "bootstrap sidecar")
        })?;
    let manifest_offset = BOOTSTRAP_SIDECAR_HEADER_LEN as u64;
    let index_root_offset = manifest_offset + MANIFEST_FOOTER_LEN as u64;
    let dictionary_offset = if dictionary_records.is_some() {
        index_root_offset + index_records_len as u64
    } else {
        0
    };
    let mut header = BootstrapSidecarHeader {
        archive_uuid,
        session_id,
        flags: if dictionary_records.is_some() {
            0x07
        } else {
            0x03
        },
        manifest_footer_offset: manifest_offset,
        manifest_footer_length: MANIFEST_FOOTER_LEN as u32,
        index_root_records_offset: index_root_offset,
        index_root_records_length: index_records_len as u64,
        dictionary_records_offset: dictionary_offset,
        dictionary_records_length: dictionary_records_len as u64,
        sidecar_hmac: [0u8; 32],
        header_crc32c: 0,
    };
    let mut header_bytes = header.to_bytes();
    header.sidecar_hmac = compute_integrity_tag(
        HmacDomain::BootstrapSidecar,
        aead_algo,
        volume_format_rev,
        Some(&subkeys.mac_key),
        &archive_uuid,
        &session_id,
        &header_bytes[..92],
    )?;
    header_bytes = header.to_bytes();

    let mut sidecar = Vec::with_capacity(
        BOOTSTRAP_SIDECAR_HEADER_LEN
            + MANIFEST_FOOTER_LEN
            + index_records_len
            + dictionary_records_len,
    );
    sidecar.extend_from_slice(&header_bytes);
    sidecar.extend_from_slice(manifest_footer);
    for record in index_root_records {
        sidecar.extend_from_slice(&record.to_bytes());
    }
    if let Some(dictionary_records) = dictionary_records {
        for record in dictionary_records {
            sidecar.extend_from_slice(&record.to_bytes());
        }
    }
    Ok(sidecar)
}

struct StreamingMemberReader<'a> {
    sections: Vec<StreamingMemberSection<'a>>,
    section_index: usize,
    pushback: Vec<u8>,
}

struct StreamingMemberSection<'a> {
    reader: Option<Box<dyn Read + 'a>>,
    opener: Option<SectionOpener<'a>>,
    remaining: u64,
    remaining_padding: u64,
    expected_sha256: Option<[u8; 32]>,
    hasher: Sha256,
    source_eof_checked: bool,
}

type SectionOpener<'a> = Box<dyn FnOnce() -> Result<Box<dyn Read + 'a>, ArchiveWriteError> + 'a>;

impl<'a> StreamingMemberSection<'a> {
    fn bytes(bytes: Vec<u8>) -> Self {
        let size = bytes.len() as u64;
        Self {
            reader: Some(Box::new(Cursor::new(bytes))),
            opener: None,
            remaining: size,
            remaining_padding: 0,
            expected_sha256: None,
            hasher: Sha256::new(),
            source_eof_checked: false,
        }
    }

    fn payload(reader: Box<dyn Read + 'a>, size: u64, expected_sha256: Option<[u8; 32]>) -> Self {
        Self {
            reader: Some(reader),
            opener: None,
            remaining: size,
            remaining_padding: padding_to_512_u64(size),
            expected_sha256,
            hasher: Sha256::new(),
            source_eof_checked: false,
        }
    }

    fn deferred_payload(
        opener: SectionOpener<'a>,
        size: u64,
        expected_sha256: Option<[u8; 32]>,
    ) -> Self {
        Self {
            reader: None,
            opener: Some(opener),
            remaining: size,
            remaining_padding: padding_to_512_u64(size),
            expected_sha256,
            hasher: Sha256::new(),
            source_eof_checked: false,
        }
    }

    fn reader(&mut self) -> std::io::Result<&mut Box<dyn Read + 'a>> {
        if self.reader.is_none() {
            let opener = self
                .opener
                .take()
                .ok_or_else(|| std::io::Error::other("streaming member section has no source"))?;
            self.reader = Some(opener().map_err(|error| std::io::Error::other(error.to_string()))?);
        }
        Ok(self.reader.as_mut().expect("reader was initialized"))
    }
}

impl Read for StreamingMemberSection<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.remaining > 0 {
            let limit = out
                .len()
                .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
            let count = self.reader()?.read(&mut out[..limit])?;
            if count == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "member source ended before its declared size",
                ));
            }
            self.remaining -= count as u64;
            if self.expected_sha256.is_some() {
                self.hasher.update(&out[..count]);
            }
            return Ok(count);
        }
        if !self.source_eof_checked {
            let mut extra = [0u8; 1];
            if self.reader()?.read(&mut extra)? != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "member source exceeded its declared size",
                ));
            }
            if let Some(expected) = self.expected_sha256 {
                let actual: [u8; 32] = self.hasher.clone().finalize().into();
                if actual != expected {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "auxiliary source changed after metadata capture",
                    ));
                }
            }
            self.source_eof_checked = true;
            self.reader = None;
        }
        if self.remaining_padding > 0 {
            let count = out
                .len()
                .min(usize::try_from(self.remaining_padding).unwrap_or(usize::MAX));
            out[..count].fill(0);
            self.remaining_padding -= count as u64;
            return Ok(count);
        }
        Ok(0)
    }
}

impl<'a> StreamingMemberReader<'a> {
    fn new(file: Box<dyn Read + 'a>, prefix: Vec<u8>, file_size: u64) -> Self {
        Self {
            sections: vec![
                StreamingMemberSection::bytes(prefix),
                StreamingMemberSection::payload(file, file_size, None),
            ],
            section_index: 0,
            pushback: Vec::new(),
        }
    }

    fn from_source<S: RegularFileSource + ?Sized>(
        source: &'a S,
        metadata: &PortableFileMetadata,
        layout: PrimaryMemberLayout,
        primary_size: u64,
    ) -> Result<Self, ArchiveWriteError> {
        let mut sections = Vec::with_capacity(layout.auxiliary.len() * 2 + 2);
        for (ordinal, auxiliary) in layout.auxiliary.into_iter().enumerate() {
            sections.push(StreamingMemberSection::bytes(auxiliary.bytes));
            let record = metadata.native.auxiliary_records.get(ordinal).ok_or(
                FormatError::WriterInvariant("planned auxiliary source ordinal is missing"),
            )?;
            if record.is_streamed() {
                sections.push(StreamingMemberSection::deferred_payload(
                    Box::new(move || source.open_auxiliary(ordinal)),
                    auxiliary.stored_size,
                    Some(auxiliary.sha256),
                ));
            } else {
                sections.push(StreamingMemberSection::payload(
                    Box::new(Cursor::new(record.payload.clone())),
                    auxiliary.stored_size,
                    Some(auxiliary.sha256),
                ));
            }
            if record.stored_payload_size() != auxiliary.stored_size {
                return Err(FormatError::WriterInvariant(
                    "auxiliary source declaration changed while opening",
                )
                .into());
            }
        }
        sections.push(StreamingMemberSection::bytes(layout.primary));
        sections.push(StreamingMemberSection::deferred_payload(
            Box::new(move || source.open()),
            primary_size,
            None,
        ));
        Ok(Self {
            sections,
            section_index: 0,
            pushback: Vec::new(),
        })
    }

    fn push_back(&mut self, bytes: Vec<u8>) {
        if bytes.is_empty() {
            return;
        }
        if self.pushback.is_empty() {
            self.pushback = bytes;
        } else {
            let mut merged = bytes;
            merged.extend_from_slice(&self.pushback);
            self.pushback = merged;
        }
    }
}

impl Read for StreamingMemberReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }

        let mut written = 0usize;
        if !self.pushback.is_empty() {
            let count = out.len().min(self.pushback.len());
            out[..count].copy_from_slice(&self.pushback[..count]);
            self.pushback.drain(..count);
            written += count;
            if written == out.len() {
                return Ok(written);
            }
        }

        while written < out.len() && self.section_index < self.sections.len() {
            let count = self.sections[self.section_index].read(&mut out[written..])?;
            if count == 0 {
                self.section_index += 1;
            } else {
                written += count;
            }
        }

        Ok(written)
    }
}

#[cfg(test)]
fn build_regular_file_member_prefix(
    path: &[u8],
    file_size: u64,
    mode: u32,
    mtime: ArchiveTimestamp,
    portable_metadata: &PortableFileMetadata,
) -> Result<Vec<u8>, FormatError> {
    build_primary_member_prefix(
        path,
        SourceEntryKind::Regular,
        None,
        file_size,
        None,
        mode,
        mtime,
        portable_metadata,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_primary_member_prefix(
    path: &[u8],
    entry_kind: SourceEntryKind,
    link_target: Option<&[u8]>,
    file_size: u64,
    sparse_extents: Option<&[SparseExtent]>,
    mode: u32,
    mtime: ArchiveTimestamp,
    portable_metadata: &PortableFileMetadata,
) -> Result<Vec<u8>, FormatError> {
    let layout = build_primary_member_layout(
        path,
        entry_kind,
        link_target,
        file_size,
        sparse_extents,
        mode,
        mtime,
        portable_metadata,
    )?;
    let mut out = Vec::new();
    for (ordinal, auxiliary) in layout.auxiliary.iter().enumerate() {
        let record = &portable_metadata.native.auxiliary_records[ordinal];
        if record.is_streamed() {
            return Err(FormatError::WriterUnsupported(
                "this writer path does not accept streamed auxiliary payloads",
            ));
        }
        out.extend_from_slice(&auxiliary.bytes);
        out.extend_from_slice(&record.payload);
        out.resize(
            out.len() + padding_to_512_u64(auxiliary.stored_size) as usize,
            0,
        );
    }
    out.extend_from_slice(&layout.primary);
    Ok(out)
}

struct PrimaryMemberLayout {
    auxiliary: Vec<NativeAuxiliaryMemberPrefix>,
    primary: Vec<u8>,
}

fn primary_member_layout_size(
    layout: &PrimaryMemberLayout,
    primary_payload_size: u64,
) -> Result<u64, FormatError> {
    let mut size = 0u64;
    for auxiliary in &layout.auxiliary {
        size = checked_u64_add(size, auxiliary.bytes.len() as u64, "auxiliary member")?;
        size = checked_u64_add(size, auxiliary.stored_size, "auxiliary member")?;
        size = checked_u64_add(
            size,
            padding_to_512_u64(auxiliary.stored_size),
            "auxiliary member",
        )?;
    }
    size = checked_u64_add(size, layout.primary.len() as u64, "primary member")?;
    size = checked_u64_add(size, primary_payload_size, "primary member")?;
    checked_u64_add(
        size,
        padding_to_512_u64(primary_payload_size),
        "primary member",
    )
}

#[allow(clippy::too_many_arguments)]
fn build_primary_member_layout(
    path: &[u8],
    entry_kind: SourceEntryKind,
    link_target: Option<&[u8]>,
    file_size: u64,
    sparse_extents: Option<&[SparseExtent]>,
    mode: u32,
    mtime: ArchiveTimestamp,
    portable_metadata: &PortableFileMetadata,
) -> Result<PrimaryMemberLayout, FormatError> {
    if entry_kind != SourceEntryKind::Regular && (file_size != 0 || sparse_extents.is_some()) {
        return Err(FormatError::WriterInvariant(
            "non-regular member has non-zero file data size",
        ));
    }
    match (entry_kind, link_target) {
        (SourceEntryKind::Symlink, Some(target)) => {
            crate::tar_model::validate_symlink_target(path, target)?;
        }
        (SourceEntryKind::Hardlink, Some(target)) => {
            validate_file_path_bytes(target, u32::MAX)?;
            if target == path {
                return Err(FormatError::WriterInvariant("hardlink aliases itself"));
            }
            if portable_metadata.native != NativeFileMetadata::default() {
                return Err(FormatError::WriterInvariant(
                    "hardlink alias carries native file-object metadata",
                ));
            }
        }
        (SourceEntryKind::Symlink, None) => {
            return Err(FormatError::WriterInvariant(
                "symlink member has no link target",
            ));
        }
        (_, Some(_)) => {
            return Err(FormatError::WriterInvariant(
                "non-link member has a link target",
            ));
        }
        (_, None) => {}
    }
    let sparse_map = sparse_extents
        .map(|extents| encode_v45_sparse_map(extents, file_size))
        .transpose()?;
    let stored_extent_bytes = sparse_extents
        .map(|extents| sparse_extent_bytes(extents, file_size))
        .transpose()?
        .unwrap_or(file_size);
    let stored_size = checked_u64_add(
        sparse_map.as_ref().map_or(0, |map| map.len() as u64),
        stored_extent_bytes,
        "sparse primary stored size",
    )?;
    let use_path_override = sparse_map.is_none() && path_requires_pax(path);
    validate_portable_file_metadata(portable_metadata)?;
    let reparse_placeholder = portable_metadata
        .native
        .primary_pax_records
        .contains_key("TZAP.windows.reparse-placeholder");
    if matches!(
        entry_kind,
        SourceEntryKind::ReparseDirectory | SourceEntryKind::ReparseRegular
    ) != reparse_placeholder
    {
        return Err(FormatError::WriterInvariant(
            "Windows reparse source kind and placeholder metadata disagree",
        ));
    }
    let mut pax_records =
        portable_primary_pax(path, mode, &portable_metadata.source_os, use_path_override)?;
    pax_records.insert(
        "TZAP.metadata.source-filesystem".into(),
        portable_metadata.source_filesystem.as_bytes().to_vec(),
    );
    pax_records.insert(
        "TZAP.portable.mode-origin".into(),
        match portable_metadata.mode_origin {
            PortableModeOrigin::Native => b"native".to_vec(),
            PortableModeOrigin::Projected => b"projected".to_vec(),
        },
    );
    if let Some(attributes) = portable_metadata.attributes {
        pax_records.insert(
            "TZAP.portable.attributes".into(),
            hex::encode(attributes.to_be_bytes()).into_bytes(),
        );
    }
    for (key, timestamp) in [
        ("LIBARCHIVE.creationtime", portable_metadata.created),
        ("atime", portable_metadata.accessed),
    ] {
        if let Some(timestamp) = timestamp {
            let value = timestamp.canonical_pax_value()?;
            if let Some(native_value) = portable_metadata.native.primary_pax_records.get(key) {
                if native_value != &value {
                    return Err(FormatError::WriterUnsupported(
                        "portable timestamp conflicts with native primary metadata",
                    ));
                }
            } else {
                pax_records.insert(key.into(), value);
            }
        }
    }
    if sparse_map.is_some() {
        pax_records.insert("GNU.sparse.major".into(), b"1".to_vec());
        pax_records.insert("GNU.sparse.minor".into(), b"0".to_vec());
        pax_records.insert("GNU.sparse.name".into(), path.to_vec());
        pax_records.insert(
            "GNU.sparse.realsize".into(),
            file_size.to_string().into_bytes(),
        );
    }
    merge_native_primary_metadata(&mut pax_records, &portable_metadata.native)?;
    if portable_metadata
        .native
        .auxiliary_records
        .iter()
        .any(|record| record.kind == CAPTURE_REPORT_KIND)
    {
        pax_records.insert("TZAP.metadata.capture-status".into(), b"partial".to_vec());
    }
    let use_linkpath_override = link_target.is_some_and(|target| target.len() > 100);
    if use_linkpath_override {
        pax_records.insert(
            "linkpath".into(),
            link_target.expect("link target was checked").to_vec(),
        );
    }
    let primary_identity = prepare_primary_tar_identity(&mut pax_records, portable_metadata)?;
    let header_mtime = if mtime.nanoseconds == 0 && mtime.seconds >= 0 {
        let seconds = mtime.seconds as u64;
        if tar_octal_fits(12, seconds) {
            seconds
        } else {
            pax_records.insert("mtime".into(), mtime.canonical_pax_value()?);
            0
        }
    } else {
        pax_records.insert("mtime".into(), mtime.canonical_pax_value()?);
        0
    };
    let header_size = if tar_octal_fits(12, stored_size) {
        stored_size
    } else {
        pax_records.insert("size".into(), stored_size.to_string().into_bytes());
        0
    };
    let primary_metadata = parse_primary_metadata(&pax_records).map_err(|_| {
        FormatError::WriterUnsupported("native primary metadata is not a valid v45 declaration")
    })?;
    let mut parsed_auxiliary = Vec::with_capacity(portable_metadata.native.auxiliary_records.len());
    let mut auxiliary = Vec::with_capacity(portable_metadata.native.auxiliary_records.len());
    for (ordinal, record) in portable_metadata
        .native
        .auxiliary_records
        .iter()
        .enumerate()
    {
        let ordinal = u32::try_from(ordinal).map_err(|_| {
            FormatError::WriterUnsupported("auxiliary record count exceeds revision-45 range")
        })?;
        let member = build_native_auxiliary_member_prefix(ordinal, record)?;
        parsed_auxiliary.push(member.parsed.clone());
        auxiliary.push(member);
    }
    validate_group_metadata(&primary_metadata, &parsed_auxiliary).map_err(|_| {
        FormatError::WriterUnsupported("native auxiliary metadata is not a valid v45 declaration")
    })?;
    let pax_payload = encode_canonical_pax(&pax_records)?;
    let pax_header = build_ustar_header(b"TZAP-PAX/PRIMARY", pax_payload.len() as u64, 0, 0, b'x')?;
    let mut primary = Vec::new();
    primary.extend_from_slice(&pax_header);
    primary.extend_from_slice(&pax_payload);
    primary.resize(primary.len() + padding_to_512(pax_payload.len()), 0);

    let header_path = if sparse_map.is_some() {
        b"GNUSparseFile.0/TZAP".to_vec()
    } else if use_path_override {
        b"TZAP-PRIMARY".to_vec()
    } else {
        path.to_vec()
    };

    let typeflag = match entry_kind {
        SourceEntryKind::Regular | SourceEntryKind::ReparseRegular => b'0',
        SourceEntryKind::Directory | SourceEntryKind::ReparseDirectory => b'5',
        SourceEntryKind::Symlink => b'2',
        SourceEntryKind::Hardlink => b'1',
        SourceEntryKind::CharacterDevice => b'3',
        SourceEntryKind::BlockDevice => b'4',
        SourceEntryKind::Fifo => b'6',
    };
    let mut header = build_ustar_header(&header_path, header_size, mode, header_mtime, typeflag)?;
    if let Some(target) = link_target.filter(|_| !use_linkpath_override) {
        header[157..157 + target.len()].copy_from_slice(target);
        finalize_tar_checksum(&mut header)?;
    }
    apply_primary_tar_identity(&mut header, &primary_identity)?;
    if matches!(
        entry_kind,
        SourceEntryKind::CharacterDevice | SourceEntryKind::BlockDevice
    ) {
        let parse_device = |key: &str| -> Result<u64, FormatError> {
            let value = pax_records.get(key).ok_or(FormatError::WriterInvariant(
                "device member lacks device-number metadata",
            ))?;
            let text = std::str::from_utf8(value).map_err(|_| {
                FormatError::WriterUnsupported("device number is not canonical decimal")
            })?;
            text.parse::<u64>().map_err(|_| {
                FormatError::WriterUnsupported("device number is not canonical decimal")
            })
        };
        let major = parse_device("TZAP.posix.device-major")?;
        let minor = parse_device("TZAP.posix.device-minor")?;
        if tar_octal_fits(8, major) {
            write_tar_octal(&mut header[329..337], major)?;
        }
        if tar_octal_fits(8, minor) {
            write_tar_octal(&mut header[337..345], minor)?;
        }
        finalize_tar_checksum(&mut header)?;
    }
    primary.extend_from_slice(&header);
    if let Some(sparse_map) = sparse_map {
        primary.extend_from_slice(&sparse_map);
    }
    Ok(PrimaryMemberLayout { auxiliary, primary })
}

fn sparse_extent_bytes(extents: &[SparseExtent], logical_size: u64) -> Result<u64, FormatError> {
    if extents.len() > MAX_SPARSE_EXTENTS {
        return Err(FormatError::WriterUnsupported(
            "sparse extent count exceeds revision-45 limit",
        ));
    }
    let mut previous_end = 0u64;
    let mut stored_size = 0u64;
    for (index, extent) in extents.iter().enumerate() {
        if extent.length == 0 || extent.offset < previous_end {
            return Err(FormatError::WriterUnsupported(
                "sparse extents overlap or have zero length",
            ));
        }
        if index != 0 && extent.offset == previous_end {
            return Err(FormatError::WriterUnsupported(
                "adjacent sparse extents must be merged",
            ));
        }
        let end = extent
            .offset
            .checked_add(extent.length)
            .ok_or(FormatError::WriterUnsupported("sparse extent overflow"))?;
        if end > logical_size {
            return Err(FormatError::WriterUnsupported(
                "sparse extent exceeds logical size",
            ));
        }
        stored_size =
            stored_size
                .checked_add(extent.length)
                .ok_or(FormatError::WriterUnsupported(
                    "sparse stored size overflow",
                ))?;
        previous_end = end;
    }
    Ok(stored_size)
}

pub fn encode_v45_sparse_map(
    extents: &[SparseExtent],
    logical_size: u64,
) -> Result<Vec<u8>, FormatError> {
    sparse_extent_bytes(extents, logical_size)?;
    let mut map = Vec::new();
    map.extend_from_slice(extents.len().to_string().as_bytes());
    map.push(b'\n');
    for extent in extents {
        map.extend_from_slice(extent.offset.to_string().as_bytes());
        map.push(b'\n');
        map.extend_from_slice(extent.length.to_string().as_bytes());
        map.push(b'\n');
    }
    let padding = padding_to_512(map.len());
    map.resize(
        map.len()
            .checked_add(padding)
            .ok_or(FormatError::WriterUnsupported("sparse map size overflow"))?,
        0,
    );
    Ok(map)
}

struct NativeAuxiliaryMemberPrefix {
    bytes: Vec<u8>,
    stored_size: u64,
    sha256: [u8; 32],
    parsed: crate::entry_metadata::AuxiliaryRecord,
}

fn build_native_auxiliary_member_prefix(
    ordinal: u32,
    record: &NativeAuxiliaryMetadata,
) -> Result<NativeAuxiliaryMemberPrefix, FormatError> {
    if record.is_streamed()
        && !matches!(
            record.kind.as_str(),
            "windows.alternate-data"
                | "windows.property-data"
                | "windows.efs-raw"
                | "macos.resource-fork"
                | "generic.xattr"
        )
        && !record.kind.starts_with("x.")
    {
        return Err(FormatError::WriterUnsupported(
            "this auxiliary kind requires inline structural payload validation",
        ));
    }
    let mut pax_records = BTreeMap::new();
    pax_records.insert("TZAP.aux.version".into(), b"1".to_vec());
    pax_records.insert("TZAP.aux.kind".into(), record.kind.as_bytes().to_vec());
    pax_records.insert(
        "TZAP.aux.profile".into(),
        record.profile.as_bytes().to_vec(),
    );
    pax_records.insert(
        "TZAP.aux.restore-class".into(),
        match record.restore_class {
            RestoreClass::None => b"none".to_vec(),
            RestoreClass::Portable => b"portable".to_vec(),
            RestoreClass::SameOs => b"same-os".to_vec(),
            RestoreClass::System => b"system".to_vec(),
        },
    );
    pax_records.insert(
        "TZAP.aux.native".into(),
        if record.native { b"1" } else { b"0" }.to_vec(),
    );
    let (name_encoding, encoded_name) = match record.name_encoding {
        NativeAuxiliaryNameEncoding::None => ("none", record.name.clone()),
        NativeAuxiliaryNameEncoding::Utf8 => ("utf8", record.name.clone()),
        NativeAuxiliaryNameEncoding::Utf16Le => {
            ("utf16le-base64", canonical_base64_encode(&record.name))
        }
        NativeAuxiliaryNameEncoding::Bytes => {
            ("bytes-base64", canonical_base64_encode(&record.name))
        }
    };
    pax_records.insert(
        "TZAP.aux.name-encoding".into(),
        name_encoding.as_bytes().to_vec(),
    );
    pax_records.insert("TZAP.aux.name".into(), encoded_name);
    pax_records.insert(
        "TZAP.aux.flags".into(),
        hex::encode(record.flags.to_be_bytes()).into_bytes(),
    );
    pax_records.insert(
        "TZAP.aux.logical-size".into(),
        record.logical_size.to_string().into_bytes(),
    );
    let digest = record.sha256();
    pax_records.insert("TZAP.aux.sha256".into(), hex::encode(digest).into_bytes());
    for (key, value) in &record.meta {
        if pax_records.insert(key.clone(), value.clone()).is_some() {
            return Err(FormatError::WriterUnsupported(
                "auxiliary metadata collides with a writer-owned key",
            ));
        }
    }

    let stored_size = record.stored_payload_size();
    let header_size = if tar_octal_fits(12, stored_size) {
        stored_size
    } else {
        pax_records.insert("size".into(), stored_size.to_string().into_bytes());
        0
    };
    let parsed = if record.is_streamed() {
        parse_auxiliary_declaration_for_writer(&pax_records, ordinal, stored_size)
    } else {
        parse_auxiliary_record(&pax_records, ordinal, stored_size, &record.payload)
    }?;
    let pax_payload = encode_canonical_pax(&pax_records)?;
    let pax_label = format!("TZAP-PAX/AUX/{ordinal:08x}");
    let pax_header =
        build_ustar_header(pax_label.as_bytes(), pax_payload.len() as u64, 0, 0, b'x')?;
    let auxiliary_label = format!("TZAP-AUX/{ordinal:08x}");
    let auxiliary_header = build_ustar_header(auxiliary_label.as_bytes(), header_size, 0, 0, b'Z')?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&pax_header);
    bytes.extend_from_slice(&pax_payload);
    bytes.resize(bytes.len() + padding_to_512(pax_payload.len()), 0);
    bytes.extend_from_slice(&auxiliary_header);
    Ok(NativeAuxiliaryMemberPrefix {
        bytes,
        stored_size,
        sha256: digest,
        parsed,
    })
}

fn merge_native_primary_metadata(
    pax_records: &mut crate::entry_metadata::PaxRecords,
    native: &NativeFileMetadata,
) -> Result<(), FormatError> {
    if native.required_profiles.is_empty()
        && native.optional_profiles.is_empty()
        && native.primary_pax_records.is_empty()
        && native.auxiliary_records.is_empty()
    {
        return Ok(());
    }
    let mut required = native.required_profiles.clone();
    required.push("portable-v1".into());
    required.sort();
    required.dedup();
    let mut optional = native.optional_profiles.clone();
    optional.sort();
    optional.dedup();
    if required
        .iter()
        .any(|profile| optional.binary_search(profile).is_ok())
    {
        return Err(FormatError::WriterUnsupported(
            "metadata profile is both required and optional",
        ));
    }
    pax_records.insert(
        "TZAP.metadata.required-profiles".into(),
        required.join(",").into_bytes(),
    );
    pax_records.insert(
        "TZAP.metadata.optional-profiles".into(),
        optional.join(",").into_bytes(),
    );
    for (key, value) in &native.primary_pax_records {
        if pax_records.contains_key(key)
            || matches!(
                key.as_str(),
                "path" | "linkpath" | "size" | "uid" | "gid" | "uname" | "gname" | "mtime"
            )
            || key.starts_with("TZAP.metadata.")
            || key.starts_with("TZAP.portable.")
        {
            return Err(FormatError::WriterUnsupported(
                "native metadata collides with a writer-owned primary key",
            ));
        }
        pax_records.insert(key.clone(), value.clone());
    }
    Ok(())
}

#[derive(Debug, Default)]
struct PrimaryTarIdentity {
    uid: u64,
    gid: u64,
    uname: Vec<u8>,
    gname: Vec<u8>,
}

fn validate_portable_file_metadata(metadata: &PortableFileMetadata) -> Result<(), FormatError> {
    if !is_source_os(&metadata.source_os) {
        return Err(FormatError::WriterUnsupported("invalid metadata source OS"));
    }
    if !valid_filesystem_token(&metadata.source_filesystem) {
        return Err(FormatError::WriterUnsupported(
            "invalid metadata source filesystem",
        ));
    }
    if metadata
        .attributes
        .is_some_and(|attributes| attributes & !0x0f != 0)
    {
        return Err(FormatError::WriterUnsupported(
            "portable attributes contain reserved bits",
        ));
    }
    Ok(())
}

fn prepare_primary_tar_identity(
    pax_records: &mut crate::entry_metadata::PaxRecords,
    metadata: &PortableFileMetadata,
) -> Result<PrimaryTarIdentity, FormatError> {
    let Some(owner) = &metadata.posix_owner else {
        return Ok(PrimaryTarIdentity::default());
    };
    pax_records.insert("TZAP.portable.owner-kind".into(), b"posix".to_vec());
    let uid = if tar_octal_fits(8, owner.uid) {
        owner.uid
    } else {
        pax_records.insert("uid".into(), owner.uid.to_string().into_bytes());
        0
    };
    let gid = if tar_octal_fits(8, owner.gid) {
        owner.gid
    } else {
        pax_records.insert("gid".into(), owner.gid.to_string().into_bytes());
        0
    };
    let uname = prepare_primary_name(pax_records, "uname", owner.uname.as_deref())?;
    let gname = prepare_primary_name(pax_records, "gname", owner.gname.as_deref())?;
    Ok(PrimaryTarIdentity {
        uid,
        gid,
        uname,
        gname,
    })
}

fn prepare_primary_name(
    pax_records: &mut crate::entry_metadata::PaxRecords,
    key: &'static str,
    name: Option<&str>,
) -> Result<Vec<u8>, FormatError> {
    let Some(name) = name else {
        return Ok(Vec::new());
    };
    if name.is_empty() || name.contains('\0') || name.nfc().collect::<String>() != name {
        return Err(FormatError::WriterUnsupported(
            "portable owner name is not canonical NFC UTF-8",
        ));
    }
    if name.len() <= 32 {
        Ok(name.as_bytes().to_vec())
    } else {
        pax_records.insert(key.into(), name.as_bytes().to_vec());
        Ok(Vec::new())
    }
}

fn apply_primary_tar_identity(
    header: &mut [u8; TAR_BLOCK_LEN],
    identity: &PrimaryTarIdentity,
) -> Result<(), FormatError> {
    write_tar_octal(&mut header[108..116], identity.uid)?;
    write_tar_octal(&mut header[116..124], identity.gid)?;
    header[265..297].fill(0);
    header[265..265 + identity.uname.len()].copy_from_slice(&identity.uname);
    header[297..329].fill(0);
    header[297..297 + identity.gname.len()].copy_from_slice(&identity.gname);
    finalize_tar_checksum(header)
}

#[cfg(test)]
fn build_regular_file_member_group(
    path: &[u8],
    contents: &[u8],
    mode: u32,
    mtime: ArchiveTimestamp,
    portable_metadata: &PortableFileMetadata,
) -> Result<Vec<u8>, FormatError> {
    let mut out = build_regular_file_member_prefix(
        path,
        contents.len() as u64,
        mode,
        mtime,
        portable_metadata,
    )?;
    out.extend_from_slice(contents);
    out.resize(out.len() + padding_to_512(contents.len()), 0);
    Ok(out)
}

fn path_requires_pax(path: &[u8]) -> bool {
    path.len() > 100
}

fn v45_portable_file_entry_flags(
    mode: u32,
    primary_sparse: bool,
    metadata: &PortableFileMetadata,
) -> u32 {
    EXTENDED_METADATA_V1
        | if metadata
            .native
            .auxiliary_records
            .iter()
            .any(|record| record.kind == CAPTURE_REPORT_KIND)
        {
            CAPTURE_PARTIAL
        } else {
            0
        }
        | if metadata.native.auxiliary_records.is_empty() {
            0
        } else {
            HAS_AUXILIARY_STREAMS
        }
        | if metadata
            .native
            .required_profiles
            .iter()
            .chain(&metadata.native.optional_profiles)
            .any(|profile| profile != PORTABLE_PROFILE)
            || !metadata.native.primary_pax_records.is_empty()
            || metadata
                .native
                .auxiliary_records
                .iter()
                .any(|record| record.native)
        {
            HAS_NATIVE_METADATA
        } else {
            0
        }
        | if primary_sparse
            || metadata
                .native
                .auxiliary_records
                .iter()
                .any(|record| record.flags & 1 != 0)
        {
            HAS_SPARSE_EXTENTS
        } else {
            0
        }
        | if mode & 0o6000 != 0
            || metadata.posix_owner.is_some()
            || native_metadata_requires_system_restore(&metadata.native, &metadata.source_os)
            || metadata
                .native
                .auxiliary_records
                .iter()
                .any(|record| record.restore_class == RestoreClass::System)
        {
            REQUIRES_SYSTEM_RESTORE
        } else {
            0
        }
}

fn native_metadata_requires_system_restore(native: &NativeFileMetadata, source_os: &str) -> bool {
    native.primary_pax_records.iter().any(|(key, value)| {
        key.starts_with("TZAP.posix.device-")
            || key == "TZAP.linux.whiteout"
            || key == "TZAP.linux.project-id"
            || key == "TZAP.windows.reparse-placeholder"
            || key == "TZAP.windows.directory-case-sensitive"
            || key.starts_with("LIBARCHIVE.xattr.security")
            || key.starts_with("LIBARCHIVE.xattr.trusted")
            || key.starts_with("LIBARCHIVE.xattr.system")
            || (source_os == "linux"
                && key.starts_with("LIBARCHIVE.xattr.")
                && !key.starts_with("LIBARCHIVE.xattr.user.")
                && !key.starts_with("LIBARCHIVE.xattr.com.apple."))
            || (key == "TZAP.linux.fsflags"
                && std::str::from_utf8(value)
                    .ok()
                    .and_then(|value| u64::from_str_radix(value, 16).ok())
                    .is_some_and(|flags| flags & 0x30 != 0))
            || (key == "TZAP.bsd.st-flags"
                && std::str::from_utf8(value)
                    .ok()
                    .and_then(|value| u64::from_str_radix(value, 16).ok())
                    .is_some_and(|flags| flags & 0x0006_0006 != 0))
            || (key == "TZAP.macos.st-flags"
                && std::str::from_utf8(value)
                    .ok()
                    .and_then(|value| u64::from_str_radix(value, 16).ok())
                    .is_some_and(|flags| flags & 0x009f_0086 != 0))
            || (key == "TZAP.windows.data-stream-attributes"
                && std::str::from_utf8(value)
                    .ok()
                    .and_then(|value| u32::from_str_radix(value, 16).ok())
                    .is_some_and(|flags| flags & 0x0000_0002 != 0))
            || (key == "SCHILY.fflags"
                && std::str::from_utf8(value).ok().is_some_and(|value| {
                    value.split(',').any(|token| {
                        matches!(
                            token,
                            "append" | "immutable" | "sappnd" | "schg" | "uappnd" | "uchg"
                        )
                    })
                }))
    })
}

fn build_ustar_header(
    path: &[u8],
    size: u64,
    mode: u32,
    mtime: u64,
    typeflag: u8,
) -> Result<[u8; TAR_BLOCK_LEN], FormatError> {
    if path.len() > 100 {
        return Err(FormatError::WriterUnsupported(
            "ustar path exceeds name field",
        ));
    }
    let mut header = [0u8; TAR_BLOCK_LEN];
    header[0..path.len()].copy_from_slice(path);
    write_tar_octal(&mut header[100..108], mode as u64)?;
    write_tar_octal(&mut header[108..116], 0)?;
    write_tar_octal(&mut header[116..124], 0)?;
    write_tar_octal(&mut header[124..136], size)?;
    write_tar_octal(&mut header[136..148], mtime)?;
    header[148..156].fill(b' ');
    header[156] = typeflag;
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    finalize_tar_checksum(&mut header)?;
    Ok(header)
}

fn finalize_tar_checksum(header: &mut [u8; TAR_BLOCK_LEN]) -> Result<(), FormatError> {
    header[148..156].fill(b' ');
    let checksum = header.iter().map(|byte| *byte as u32).sum::<u32>() as u64;
    write_tar_checksum(&mut header[148..156], checksum)
}

fn write_tar_octal(field: &mut [u8], mut value: u64) -> Result<(), FormatError> {
    if field.is_empty() {
        return Err(FormatError::WriterUnsupported("tar octal field overflow"));
    }
    let mut i = field.len() - 1;
    field[i] = 0;

    if value == 0 {
        if i == 0 {
            return Err(FormatError::WriterUnsupported("tar octal field overflow"));
        }
        i -= 1;
        field[i] = b'0';
    } else {
        while value > 0 {
            if i == 0 {
                return Err(FormatError::WriterUnsupported("tar octal field overflow"));
            }
            i -= 1;
            field[i] = b'0' + (value & 7) as u8;
            value >>= 3;
        }
    }
    while i > 0 {
        i -= 1;
        field[i] = b'0';
    }
    Ok(())
}

fn tar_octal_fits(field_len: usize, mut value: u64) -> bool {
    if field_len == 0 {
        return false;
    }
    let max_digits = field_len - 1;
    let mut digits = 0;
    if value == 0 {
        digits = 1;
    }
    while value > 0 {
        digits += 1;
        value >>= 3;
    }
    digits <= max_digits
}

fn write_tar_checksum(field: &mut [u8], mut value: u64) -> Result<(), FormatError> {
    if field.len() < 8 {
        return Err(FormatError::WriterUnsupported(
            "tar checksum field overflow",
        ));
    }
    let mut i = 6;
    while i > 0 {
        i -= 1;
        field[i] = b'0' + (value & 7) as u8;
        value >>= 3;
    }
    if value > 0 {
        return Err(FormatError::WriterUnsupported(
            "tar checksum field overflow",
        ));
    }
    field[6] = 0;
    field[7] = b' ';
    Ok(())
}

fn member_frame_range(
    member_index: usize,
    frames: &[PayloadFrame],
) -> Result<(u64, u32), FormatError> {
    let first = frames
        .iter()
        .find(|frame| frame.member_index == member_index)
        .map(|frame| frame.frame_index)
        .ok_or(FormatError::WriterInvariant("member frame is missing"))?;
    let count = frames
        .iter()
        .filter(|frame| frame.member_index == member_index)
        .count();
    Ok((first, u32_len(count, "FileEntry.frame_count")?))
}

fn envelope_frame_range(
    envelope_index: u64,
    frames: &[PayloadFrame],
) -> Result<(u64, u32), FormatError> {
    let first = frames
        .iter()
        .find(|frame| frame.envelope_index == envelope_index)
        .map(|frame| frame.frame_index)
        .ok_or(FormatError::WriterInvariant("envelope frame is missing"))?;
    let count = frames
        .iter()
        .filter(|frame| frame.envelope_index == envelope_index)
        .count();
    Ok((first, u32_len(count, "EnvelopeEntry.frame_count")?))
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
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

fn table_offset(len: usize, cursor: usize) -> Result<u32, FormatError> {
    if len == 0 {
        Ok(0)
    } else {
        u32_len(cursor, "table offset")
    }
}

fn u32_len(value: usize, field: &'static str) -> Result<u32, FormatError> {
    u32::try_from(value).map_err(|_| FormatError::WriterUnsupported(field))
}

fn to_usize_writer(value: u64, field: &'static str) -> Result<usize, FormatError> {
    usize::try_from(value).map_err(|_| FormatError::WriterUnsupported(field))
}

fn checked_usize_add(lhs: usize, rhs: usize, field: &'static str) -> Result<usize, FormatError> {
    lhs.checked_add(rhs)
        .ok_or(FormatError::WriterUnsupported(field))
}

fn checked_u64_add(lhs: u64, rhs: u64, field: &'static str) -> Result<u64, FormatError> {
    lhs.checked_add(rhs)
        .ok_or(FormatError::WriterUnsupported(field))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{verify_hmac, Subkeys};
    use crate::metadata::{DirectoryHintTable, IndexShard, MetadataLimits};
    use crate::reader::{open_archive, open_archive_with_recipient_wrap_resolver};
    use crate::tar_model::parse_tar_member_group;
    use crate::wire::{CriticalRecoveryLocator, CryptoHeader};
    use std::cell::RefCell;
    use std::io::{self, Read};
    use std::rc::Rc;

    #[test]
    fn writer_defaults_use_v41_sizing_and_parallel_mode() {
        let options = WriterOptions::default();

        assert_eq!(options.chunk_size, 256 * 1024);
        assert_eq!(options.envelope_target_size, 1024 * 1024);
        assert_eq!(options.block_size, 64 * 1024);
        assert_eq!(options.stripe_width, 8);
        assert_eq!(options.volume_loss_tolerance, 1);
        assert_eq!(options.fec_data_shards, 224);
        assert_eq!(options.index_fec_data_shards, 16);
        assert_eq!(
            options.index_root_fec_data_shards,
            MIN_INDEX_ROOT_FEC_DATA_SHARDS
        );
        assert_eq!(options.bit_rot_buffer_pct, 5);
        assert_eq!(options.jobs, default_jobs());
        assert!(options.jobs >= 1);
    }

    #[test]
    fn emission_state_collects_data_leaf_hashes_only_for_root_auth() {
        let options = single_volume_metadata_test_options();
        let archive_uuid = [1u8; 16];
        let session_id = [2u8; 16];
        let crypto_header = b"test crypto header";

        let mut unsigned_sink = MemoryArchiveSink::default();
        let volume_format_rev = volume_format_revision_for_options(&options, &KdfParams::None);
        let unsigned = begin_writer_emission_state(
            &mut unsigned_sink,
            options,
            crypto_header,
            None,
            archive_uuid,
            session_id,
            volume_format_rev,
            false,
        )
        .unwrap();
        assert!(unsigned.data_leaf_hashes.is_none());

        let mut signed_sink = MemoryArchiveSink::default();
        let volume_format_rev = volume_format_revision_for_options(&options, &KdfParams::None);
        let signed = begin_writer_emission_state(
            &mut signed_sink,
            options,
            crypto_header,
            None,
            archive_uuid,
            session_id,
            volume_format_rev,
            true,
        )
        .unwrap();
        assert_eq!(signed.data_leaf_hashes.as_deref(), Some([].as_slice()));
    }

    #[test]
    fn ordered_envelope_serializes_zero_parity_without_root_auth_leaf_collection() {
        let options = plan_writer_options(WriterOptions {
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            aead_algo: AeadAlgo::None,
            ..WriterOptions::default()
        })
        .unwrap();
        let payload = deterministic_bytes(options.block_size as usize * 2 + 17);
        let extent = ObjectExtent::new(
            11,
            plan_encrypted_object(
                payload.len(),
                options.fec_data_shards,
                options.fec_parity_shards,
                options,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(extent.parity_block_count, 0);
        assert_eq!(extent.data_block_count, 3);
        let subkeys = Subkeys::unencrypted_placeholder();

        let result = build_ordered_envelope_result(
            OrderedEnvelopeJob {
                envelope_index: 3,
                plaintext: payload.clone(),
                extent,
                collect_data_leaf_hashes: false,
            },
            &subkeys,
            options,
            [1u8; 16],
            [2u8; 16],
        )
        .unwrap();

        match result.records {
            OrderedEnvelopeRecords::Serialized(records) => {
                assert_eq!(records.len(), extent.data_block_count as usize);
                let parsed =
                    BlockRecord::parse(&records[0].bytes, options.block_size as usize).unwrap();
                assert_eq!(parsed.block_index, extent.first_block_index);
                assert_eq!(parsed.kind, BlockKind::PayloadData);
                assert!(!parsed.is_last_data());
                let last =
                    BlockRecord::parse(&records[2].bytes, options.block_size as usize).unwrap();
                assert_eq!(last.block_index, extent.first_block_index + 2);
                assert_eq!(last.kind, BlockKind::PayloadData);
                assert!(last.is_last_data());
            }
            OrderedEnvelopeRecords::Materialized(_) => {
                panic!("zero-parity unsigned envelope should use serialized records")
            }
        }

        let result = build_ordered_envelope_result(
            OrderedEnvelopeJob {
                envelope_index: 3,
                plaintext: payload,
                extent,
                collect_data_leaf_hashes: true,
            },
            &subkeys,
            options,
            [1u8; 16],
            [2u8; 16],
        )
        .unwrap();

        match result.records {
            OrderedEnvelopeRecords::Materialized(records) => {
                assert_eq!(records.len(), extent.data_block_count as usize);
            }
            OrderedEnvelopeRecords::Serialized(_) => {
                panic!("root-auth leaf collection requires materialized records")
            }
        }
    }

    #[test]
    fn ordered_envelope_serializes_encrypted_zero_parity_like_materialized_path() {
        let options = plan_writer_options(WriterOptions {
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            aead_algo: AeadAlgo::AesGcmSiv256,
            ..WriterOptions::default()
        })
        .unwrap();
        let payload = deterministic_bytes(options.block_size as usize * 2 + 17);
        let extent = ObjectExtent::new(
            29,
            plan_encrypted_object(
                payload.len(),
                options.fec_data_shards,
                options.fec_parity_shards,
                options,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(extent.parity_block_count, 0);
        assert_eq!(extent.data_block_count, 3);
        let archive_uuid = [3u8; 16];
        let session_id = [4u8; 16];
        let master_key = MasterKey::from_raw_key(&[0x5a; 32]).unwrap();
        let subkeys = Subkeys::derive(&master_key, &archive_uuid, &session_id).unwrap();

        let serialized = build_ordered_envelope_result(
            OrderedEnvelopeJob {
                envelope_index: 7,
                plaintext: payload.clone(),
                extent,
                collect_data_leaf_hashes: false,
            },
            &subkeys,
            options,
            archive_uuid,
            session_id,
        )
        .unwrap();
        let serialized_bytes = match serialized.records {
            OrderedEnvelopeRecords::Serialized(records) => records
                .into_iter()
                .map(|record| record.bytes)
                .collect::<Vec<_>>(),
            OrderedEnvelopeRecords::Materialized(_) => {
                panic!("zero-parity encrypted envelope should use serialized records")
            }
        };

        let materialized = build_ordered_envelope_result(
            OrderedEnvelopeJob {
                envelope_index: 7,
                plaintext: payload,
                extent,
                collect_data_leaf_hashes: true,
            },
            &subkeys,
            options,
            archive_uuid,
            session_id,
        )
        .unwrap();
        let materialized_bytes = match materialized.records {
            OrderedEnvelopeRecords::Materialized(records) => records
                .iter()
                .map(BlockRecord::to_bytes)
                .collect::<Vec<_>>(),
            OrderedEnvelopeRecords::Serialized(_) => {
                panic!("root-auth leaf collection requires materialized records")
            }
        };

        assert_eq!(serialized_bytes, materialized_bytes);
    }

    #[test]
    fn writer_options_reject_zero_jobs() {
        let err = plan_writer_options(WriterOptions {
            jobs: 0,
            ..WriterOptions::default()
        })
        .unwrap_err();

        assert_eq!(
            err,
            FormatError::WriterUnsupported("jobs must be at least 1")
        );
    }

    #[test]
    fn production_writer_defaults_generate_distinct_v4_identities() {
        let master_key = MasterKey::from_raw_key(&[9u8; 32]).unwrap();
        let first = write_archive(&[], &master_key, WriterOptions::default()).unwrap();
        let second = write_archive(&[], &master_key, WriterOptions::default()).unwrap();

        assert_ne!(first.archive_uuid, [0u8; 16]);
        assert_ne!(first.session_id, [0u8; 16]);
        assert_ne!(second.archive_uuid, [0u8; 16]);
        assert_ne!(second.session_id, [0u8; 16]);
        assert_ne!(first.archive_uuid, first.session_id);
        assert_ne!(first.archive_uuid, second.archive_uuid);
        assert_ne!(first.session_id, second.session_id);

        for raw in [
            first.archive_uuid,
            first.session_id,
            second.archive_uuid,
            second.session_id,
        ] {
            let id = Uuid::from_bytes(raw);
            assert_eq!(id.get_version_num(), 4);
        }

        let deterministic = WriterOptions {
            archive_uuid: Some([0x44; 16]),
            session_id: Some([0x55; 16]),
            ..WriterOptions::default()
        };
        let fixture = write_archive(&[], &master_key, deterministic).unwrap();
        assert_eq!(fixture.archive_uuid, [0x44; 16]);
        assert_eq!(fixture.session_id, [0x55; 16]);
    }

    #[test]
    fn writer_partitions_multiple_default_sized_index_shards() {
        let members = (0..=DEFAULT_FILES_PER_INDEX_SHARD)
            .map(|idx| TarMember {
                path: format!("file-{idx:05}.txt").into_bytes(),
                entry_kind: SourceEntryKind::Regular,
                link_target: None,
                tar_member_group_start: idx as u64 * 512,
                tar_member_group_size: 512,
                file_data_size: 0,
                sparse_extents: None,
                mode: 0o644,
                mtime: ArchiveTimestamp::UNIX_EPOCH,
                portable_metadata: PortableFileMetadata::default(),
            })
            .collect::<Vec<_>>();

        let shards = partition_file_rows(sorted_file_rows(&members)).unwrap();

        assert_eq!(shards.len(), 2);
        assert_eq!(shards[0].len(), DEFAULT_FILES_PER_INDEX_SHARD);
        assert_eq!(shards[1].len(), 1);
    }

    #[test]
    fn writer_extends_shard_for_bounded_hash_prefix_run() {
        let mut rows = Vec::new();
        rows.extend((0..9_000).map(|idx| test_file_row(idx, [0u8; 8])));
        rows.extend((9_000..54_000).map(|idx| test_file_row(idx, [1u8; 8])));
        rows.push(test_file_row(54_000, [2u8; 8]));

        let shards = partition_file_rows(rows).unwrap();

        assert_eq!(shards.len(), 2);
        assert_eq!(shards[0].len(), 54_000);
        assert!(shards[0]
            .iter()
            .skip(9_000)
            .all(|row| row.path_hash == [1u8; 8]));
        assert_eq!(shards[1][0].path_hash, [2u8; 8]);
    }

    #[test]
    fn writer_splits_oversized_hash_prefix_run_at_writer_ceiling() {
        let rows = (0..MAX_HASH_PREFIX_RUN_FILES + 1)
            .map(|idx| test_file_row(idx, [7u8; 8]))
            .collect::<Vec<_>>();

        let shards = partition_file_rows(rows).unwrap();

        assert_eq!(shards.len(), 2);
        assert_eq!(shards[0].len(), MAX_HASH_PREFIX_RUN_FILES);
        assert_eq!(shards[1].len(), 1);
    }

    #[test]
    fn writer_builds_directory_hint_rows_for_ancestor_directories() {
        let shard_rows = vec![
            vec![FileRow {
                path_hash: hash_prefix(b"a/b/one.txt"),
                path: b"a/b/one.txt".to_vec(),
                member_index: 0,
                member: TarMember {
                    path: b"a/b/one.txt".to_vec(),
                    entry_kind: SourceEntryKind::Regular,
                    link_target: None,
                    tar_member_group_start: 0,
                    tar_member_group_size: 512,
                    file_data_size: 0,
                    sparse_extents: None,
                    mode: 0o644,
                    mtime: ArchiveTimestamp::UNIX_EPOCH,
                    portable_metadata: PortableFileMetadata::default(),
                },
            }],
            vec![FileRow {
                path_hash: hash_prefix(b"a/c/two.txt"),
                path: b"a/c/two.txt".to_vec(),
                member_index: 1,
                member: TarMember {
                    path: b"a/c/two.txt".to_vec(),
                    entry_kind: SourceEntryKind::Regular,
                    link_target: None,
                    tar_member_group_start: 512,
                    tar_member_group_size: 512,
                    file_data_size: 0,
                    sparse_extents: None,
                    mode: 0o644,
                    mtime: ArchiveTimestamp::UNIX_EPOCH,
                    portable_metadata: PortableFileMetadata::default(),
                },
            }],
        ];

        let options = plan_writer_options(WriterOptions::default()).unwrap();
        let planned = build_directory_hint_plaintexts(&shard_rows, options).unwrap();
        assert_eq!(planned.len(), 1);
        let locating = DirectoryHintShardEntry {
            hint_shard_index: planned[0].hint_shard_index,
            first_dir_hash: planned[0].first_dir_hash,
            last_dir_hash: planned[0].last_dir_hash,
            first_block_index: 0,
            data_block_count: 1,
            parity_block_count: 0,
            encrypted_size: 4096,
            decompressed_size: planned[0].plaintext.len() as u32,
            entry_count: planned[0].entry_count,
        };
        let table = DirectoryHintTable::parse(
            &planned[0].plaintext,
            &locating,
            2,
            MetadataLimits::default(),
        )
        .unwrap();

        let root = table.lookup_directory_index(b"").unwrap();
        assert_eq!(table.shard_rows_for_entry(root).unwrap(), &[0, 1]);
        let a = table.lookup_directory_index(b"a").unwrap();
        assert_eq!(table.shard_rows_for_entry(a).unwrap(), &[0, 1]);
        let ab = table.lookup_directory_index(b"a/b").unwrap();
        assert_eq!(table.shard_rows_for_entry(ab).unwrap(), &[0]);
    }

    #[test]
    fn directory_hints_are_required_only_above_v41_threshold() {
        assert!(!should_emit_directory_hints(0));
        assert!(!should_emit_directory_hints(
            DIRECTORY_HINT_REQUIRED_FILE_COUNT
        ));
        assert!(should_emit_directory_hints(
            DIRECTORY_HINT_REQUIRED_FILE_COUNT + 1
        ));
    }

    #[test]
    fn regular_file_writer_uses_local_pax_path_for_long_and_non_ascii_paths() {
        let long_path = format!("dir/{}.txt", "a".repeat(120));
        let unicode_path = "unicode/e\u{301}.txt";
        let files = [
            RegularFile::new(&long_path, b"long path"),
            RegularFile::new(unicode_path, b"unicode path"),
        ];

        let (tar_stream, members) = build_tar_stream(&files, 4096).unwrap();

        for (member, expected_path, expected_data) in [
            (&members[0], long_path.as_bytes(), b"long path".as_slice()),
            (
                &members[1],
                "unicode/\u{e9}.txt".as_bytes(),
                b"unicode path".as_slice(),
            ),
        ] {
            let start = member.tar_member_group_start as usize;
            let end = start + member.tar_member_group_size as usize;
            let group = &tar_stream[start..end];
            assert_eq!(group[156], b'x');
            let parsed = parse_tar_member_group(group, 4096).unwrap();
            assert_eq!(parsed.path, expected_path);
            assert_eq!(parsed.data, expected_data);
        }
    }

    #[test]
    fn regular_file_writer_emits_no_global_metadata_or_tar_eof() {
        let long_path = format!("dir/{}.txt", "a".repeat(120));
        let files = [
            RegularFile::new("plain.txt", b"plain contents"),
            RegularFile::new(&long_path, b"long path contents"),
        ];

        let (tar_stream, members) = build_tar_stream(&files, 4096).unwrap();

        let member_bytes = members
            .iter()
            .map(|member| member.tar_member_group_size)
            .sum::<u64>();
        assert_eq!(tar_stream.len() as u64, member_bytes);
        assert!(!tar_stream[tar_stream.len() - TAR_BLOCK_LEN * 2..]
            .chunks(TAR_BLOCK_LEN)
            .all(|block| block.iter().all(|byte| *byte == 0)));

        for member in members {
            let start = member.tar_member_group_start as usize;
            let end = start + member.tar_member_group_size as usize;
            assert_path_specific_member_group(&tar_stream[start..end]);
        }
    }

    struct SparseTestSource {
        logical_size: u64,
        extents: Vec<SparseExtent>,
        extent_bytes: Vec<u8>,
    }

    impl RegularFileSource for SparseTestSource {
        fn archive_path(&self) -> &str {
            "sparse.bin"
        }

        fn file_data_size(&self) -> u64 {
            self.logical_size
        }

        fn sparse_extents(&self) -> Option<&[SparseExtent]> {
            Some(&self.extents)
        }

        fn mode(&self) -> u32 {
            0o644
        }

        fn mtime(&self) -> ArchiveTimestamp {
            ArchiveTimestamp::UNIX_EPOCH
        }

        fn open(&self) -> Result<Box<dyn Read + '_>, ArchiveWriteError> {
            Ok(Box::new(Cursor::new(self.extent_bytes.as_slice())))
        }
    }

    #[test]
    fn sparse_writer_emits_canonical_gnu_sparse_primary_and_all_hole_file() {
        for source in [
            SparseTestSource {
                logical_size: 32,
                extents: vec![
                    SparseExtent {
                        offset: 4,
                        length: 3,
                    },
                    SparseExtent {
                        offset: 16,
                        length: 2,
                    },
                    SparseExtent {
                        offset: 30,
                        length: 2,
                    },
                ],
                extent_bytes: b"abcdeyz".to_vec(),
            },
            SparseTestSource {
                logical_size: 1 << 20,
                extents: Vec::new(),
                extent_bytes: Vec::new(),
            },
        ] {
            let expected_map_prefix = format!("{}\n", source.extents.len());
            let (tar_stream, members) = build_tar_stream(&[source], 4096).unwrap();
            let parsed = parse_tar_member_group(&tar_stream, 4096).unwrap();
            assert_eq!(parsed.path, b"sparse.bin");
            assert_eq!(parsed.logical_size, members[0].file_data_size);
            let layout = parsed.v45_metadata.sparse_layout.unwrap();
            assert_eq!(layout.logical_size, members[0].file_data_size);
            assert_eq!(layout.extents, members[0].sparse_extents.clone().unwrap());
            assert!(parsed.data.starts_with(expected_map_prefix.as_bytes()));
        }
    }

    #[test]
    fn sparse_writer_rejects_noncanonical_extent_maps() {
        for extents in [
            vec![SparseExtent {
                offset: 0,
                length: 0,
            }],
            vec![
                SparseExtent {
                    offset: 0,
                    length: 2,
                },
                SparseExtent {
                    offset: 2,
                    length: 2,
                },
            ],
            vec![SparseExtent {
                offset: 9,
                length: 2,
            }],
        ] {
            let source = SparseTestSource {
                logical_size: 10,
                extents,
                extent_bytes: Vec::new(),
            };
            assert!(build_tar_stream(&[source], 4096).is_err());
        }
    }

    #[test]
    fn sparse_writer_indexes_logical_size_and_streams_expanded_content() {
        let source = SparseTestSource {
            logical_size: 12,
            extents: vec![
                SparseExtent {
                    offset: 2,
                    length: 3,
                },
                SparseExtent {
                    offset: 9,
                    length: 2,
                },
            ],
            extent_bytes: b"abcxy".to_vec(),
        };
        let master_key = MasterKey::from_raw_key(&[7u8; 32]).unwrap();
        let mut sink = MemoryArchiveSink::default();
        write_archive_sources_to_sink(
            &[source],
            &master_key,
            single_volume_metadata_test_options(),
            None,
            &KdfParams::Raw,
            None,
            None,
            &mut sink,
        )
        .unwrap();

        let opened = open_archive(&sink.volumes[0], &master_key).unwrap();
        opened.verify().unwrap();
        let entry = opened.lookup_index_entry("sparse.bin").unwrap().unwrap();
        assert_eq!(entry.file_data_size, 12);
        assert_ne!(entry.flags & HAS_SPARSE_EXTENTS, 0);
        assert_eq!(
            opened.extract_file("sparse.bin").unwrap().unwrap(),
            b"\0\0abc\0\0\0\0xy\0"
        );
    }

    #[test]
    fn regular_file_writer_round_trips_mode_and_mtime() {
        let group = build_regular_file_member_group(
            b"script.sh",
            b"#!/bin/sh\n",
            0o755,
            ArchiveTimestamp::from_seconds(1_700_000_000),
            &PortableFileMetadata::default(),
        )
        .unwrap();

        let parsed = parse_tar_member_group(&group, 4096).unwrap();

        assert_eq!(parsed.mode, 0o755);
        assert_eq!(parsed.mtime, ArchiveTimestamp::from_seconds(1_700_000_000));
    }

    #[test]
    fn regular_file_writer_round_trips_nanosecond_and_pre_epoch_mtimes() {
        for expected in [
            ArchiveTimestamp::new(1_700_000_000, 123_456_789),
            ArchiveTimestamp::new(-1, 500_000_000),
        ] {
            let group = build_regular_file_member_group(
                b"dated.txt",
                b"dated",
                0o644,
                expected,
                &PortableFileMetadata::default(),
            )
            .unwrap();
            let parsed = parse_tar_member_group(&group, 4096).unwrap();
            assert_eq!(parsed.mtime, expected);
            assert_eq!(
                parsed.v45_metadata.portable_mirror.mtime,
                (expected.seconds, expected.nanoseconds)
            );
        }
    }

    #[test]
    fn regular_file_writer_rejects_invalid_timestamp_nanoseconds() {
        assert!(matches!(
            build_regular_file_member_group(
                b"dated.txt",
                b"dated",
                0o644,
                ArchiveTimestamp::new(0, 1_000_000_000),
                &PortableFileMetadata::default(),
            ),
            Err(FormatError::WriterUnsupported(
                "timestamp nanoseconds must be less than one billion"
            ))
        ));
    }

    #[test]
    fn macos_entitlement_and_superuser_flags_require_system_restore() {
        for flags in [0x0000_0080u64, 0x0008_0000, 0x0010_0000, 0x0080_0000] {
            let mut native = NativeFileMetadata::default();
            native.primary_pax_records.insert(
                "TZAP.macos.st-flags".into(),
                format!("{flags:016x}").into_bytes(),
            );
            assert!(native_metadata_requires_system_restore(&native, "macos"));
        }
    }

    #[test]
    fn linux_bsd_macos_immutable_flags_require_system_restore() {
        let mut native = NativeFileMetadata::default();
        native.primary_pax_records.insert(
            "TZAP.linux.fsflags".into(),
            "0000000000000030".into(), // append and immutable
        );
        assert!(native_metadata_requires_system_restore(&native, "linux"));

        let mut native = NativeFileMetadata::default();
        native.primary_pax_records.insert(
            "TZAP.bsd.st-flags".into(),
            "0000000000060006".into(), // append and immutable
        );
        assert!(native_metadata_requires_system_restore(&native, "freebsd"));

        let mut native = NativeFileMetadata::default();
        native.primary_pax_records.insert(
            "TZAP.macos.st-flags".into(),
            "0000000000040000".into(), // SF_IMMUTABLE
        );
        assert!(native_metadata_requires_system_restore(&native, "macos"));

        let mut native = NativeFileMetadata::default();
        native
            .primary_pax_records
            .insert("SCHILY.fflags".into(), "uchg,uappnd".into());
        assert!(native_metadata_requires_system_restore(&native, "linux"));
    }

    #[test]
    fn windows_reparse_and_attributes_require_system_restore() {
        let mut native = NativeFileMetadata::default();
        native
            .primary_pax_records
            .insert("TZAP.windows.reparse-placeholder".into(), "1".into());
        assert!(native_metadata_requires_system_restore(&native, "windows"));

        let mut native = NativeFileMetadata::default();
        native.primary_pax_records.insert(
            "TZAP.windows.data-stream-attributes".into(),
            "00000002".into(), // stream contains security
        );
        assert!(native_metadata_requires_system_restore(&native, "windows"));
    }

    #[test]
    fn regular_file_writer_round_trips_portable_owner_origin_and_attributes() {
        let portable_metadata = PortableFileMetadata {
            source_os: "other-unix".into(),
            source_filesystem: "ext4".into(),
            mode_origin: PortableModeOrigin::Native,
            posix_owner: Some(PortablePosixOwner {
                uid: 9_000_000,
                gid: 42,
                uname: Some("tést-user".into()),
                gname: Some("archive".into()),
            }),
            attributes: Some(1),
            created: None,
            accessed: None,
            native: NativeFileMetadata::default(),
        };
        let group = build_regular_file_member_group(
            b"owned.txt",
            b"owned",
            0o640,
            ArchiveTimestamp::UNIX_EPOCH,
            &portable_metadata,
        )
        .unwrap();
        let parsed = parse_tar_member_group(&group, 4096).unwrap();

        assert!(parsed.v45_metadata.declaration.owner_kind_posix);
        assert!(parsed.v45_metadata.declaration.mode_origin_native);
        assert_eq!(parsed.v45_metadata.declaration.source_os, "other-unix");
        assert_eq!(parsed.v45_metadata.declaration.source_filesystem, "ext4");
        assert_eq!(parsed.v45_metadata.portable_mirror.uid, Some(9_000_000));
        assert_eq!(parsed.v45_metadata.portable_mirror.gid, Some(42));
        assert_eq!(
            parsed.v45_metadata.portable_mirror.uname.as_deref(),
            Some("tést-user".as_bytes())
        );
        assert_eq!(parsed.v45_metadata.portable_mirror.attributes, Some(1));
        assert_ne!(
            parsed.v45_metadata.file_entry_flags & REQUIRES_SYSTEM_RESTORE,
            0
        );
    }

    #[test]
    fn regular_file_writer_serializes_portable_creation_and_access_times() {
        let created = ArchiveTimestamp::new(1_600_000_000, 123_456_789);
        let accessed = ArchiveTimestamp::new(1_700_000_000, 987_654_321);
        let portable_metadata = PortableFileMetadata {
            created: Some(created),
            accessed: Some(accessed),
            ..PortableFileMetadata::default()
        };

        let group = build_regular_file_member_group(
            b"timestamps.txt",
            b"timestamps",
            0o644,
            ArchiveTimestamp::UNIX_EPOCH,
            &portable_metadata,
        )
        .unwrap();
        let parsed = parse_tar_member_group(&group, 4096).unwrap();

        assert_eq!(
            parsed
                .v45_metadata
                .primary_records
                .get("LIBARCHIVE.creationtime")
                .map(Vec::as_slice),
            Some(b"1600000000.123456789".as_slice())
        );
        assert_eq!(
            parsed
                .v45_metadata
                .primary_records
                .get("atime")
                .map(Vec::as_slice),
            Some(b"1700000000.987654321".as_slice())
        );
    }

    #[test]
    fn directory_writer_emits_type_and_portable_ownership_metadata() {
        let portable_metadata = PortableFileMetadata {
            source_os: "other-unix".into(),
            source_filesystem: "unknown".into(),
            mode_origin: PortableModeOrigin::Native,
            posix_owner: Some(PortablePosixOwner {
                uid: 9_000_000,
                gid: 42,
                uname: Some("directory-owner".into()),
                gname: Some("archive".into()),
            }),
            attributes: None,
            created: None,
            accessed: None,
            native: NativeFileMetadata::default(),
        };
        let bytes = build_primary_member_prefix(
            b"empty-dir",
            SourceEntryKind::Directory,
            None,
            0,
            None,
            0o2750,
            ArchiveTimestamp::new(1_700_000_000, 123_456_789),
            &portable_metadata,
        )
        .unwrap();
        let parsed = parse_tar_member_group(&bytes, 4096).unwrap();

        assert_eq!(parsed.kind, crate::tar_model::TarEntryKind::Directory);
        assert_eq!(parsed.logical_size, 0);
        assert_eq!(parsed.v45_metadata.portable_mirror.mode, 0o2750);
        assert_eq!(parsed.v45_metadata.portable_mirror.uid, Some(9_000_000));
        assert_eq!(parsed.v45_metadata.portable_mirror.gid, Some(42));
        assert_eq!(
            parsed.v45_metadata.portable_mirror.mtime,
            (1_700_000_000, 123_456_789)
        );
    }

    #[test]
    fn posix_special_writer_emits_fifo_and_device_primaries() {
        let mut portable = PortableFileMetadata {
            source_os: "linux".into(),
            mode_origin: PortableModeOrigin::Native,
            native: NativeFileMetadata {
                required_profiles: vec!["posix-backup-v1".into(), "linux-backup-v1".into()],
                ..NativeFileMetadata::default()
            },
            ..PortableFileMetadata::default()
        };
        let fifo = build_primary_member_prefix(
            b"pipe",
            SourceEntryKind::Fifo,
            None,
            0,
            None,
            0o640,
            ArchiveTimestamp::UNIX_EPOCH,
            &portable,
        )
        .unwrap();
        assert_eq!(
            parse_tar_member_group(&fifo, 4096).unwrap().kind,
            crate::tar_model::TarEntryKind::Fifo
        );

        portable
            .native
            .primary_pax_records
            .insert("TZAP.posix.device-major".into(), b"1".to_vec());
        portable
            .native
            .primary_pax_records
            .insert("TZAP.posix.device-minor".into(), b"3".to_vec());
        let device = build_primary_member_prefix(
            b"null",
            SourceEntryKind::CharacterDevice,
            None,
            0,
            None,
            0o666,
            ArchiveTimestamp::UNIX_EPOCH,
            &portable,
        )
        .unwrap();
        assert_eq!(
            parse_tar_member_group(&device, 4096).unwrap().kind,
            crate::tar_model::TarEntryKind::CharacterDevice
        );
    }

    #[test]
    fn symlink_writer_emits_target_and_fractional_mtime() {
        let mtime = ArchiveTimestamp::new(1_700_000_321, 654_321_000);
        let bytes = build_primary_member_prefix(
            b"links/current",
            SourceEntryKind::Symlink,
            Some(b"../target.txt"),
            0,
            None,
            0o777,
            mtime,
            &PortableFileMetadata::default(),
        )
        .unwrap();
        let parsed = parse_tar_member_group(&bytes, 4096).unwrap();

        assert_eq!(parsed.kind, crate::tar_model::TarEntryKind::Symlink);
        assert_eq!(
            parsed.link_target.as_deref(),
            Some(b"../target.txt".as_slice())
        );
        assert_eq!(parsed.mtime, mtime);
        assert_eq!(
            parsed.v45_metadata.portable_mirror.mtime,
            (mtime.seconds, mtime.nanoseconds)
        );
    }

    #[test]
    fn hardlink_writer_emits_zero_data_alias_with_portable_mirror_only() {
        let portable = PortableFileMetadata {
            source_os: "other-unix".into(),
            source_filesystem: "ext4".into(),
            mode_origin: PortableModeOrigin::Native,
            posix_owner: Some(PortablePosixOwner {
                uid: 1000,
                gid: 100,
                uname: Some("owner".into()),
                gname: Some("group".into()),
            }),
            attributes: Some(1),
            created: None,
            accessed: None,
            native: NativeFileMetadata::default(),
        };
        let bytes = build_primary_member_prefix(
            b"aliases/beta",
            SourceEntryKind::Hardlink,
            Some(b"aliases/alpha"),
            0,
            None,
            0o640,
            ArchiveTimestamp::new(1_700_000_000, 123_456_700),
            &portable,
        )
        .unwrap();
        let parsed = parse_tar_member_group(&bytes, 4096).unwrap();
        assert_eq!(parsed.kind, crate::tar_model::TarEntryKind::Hardlink);
        assert_eq!(parsed.logical_size, 0);
        assert_eq!(
            parsed.link_target.as_deref(),
            Some(b"aliases/alpha".as_slice())
        );
        assert_eq!(
            parsed.v45_metadata.declaration.required_profiles,
            ["portable-v1"]
        );
        assert!(parsed.v45_metadata.auxiliary.is_empty());
        assert_eq!(parsed.v45_metadata.portable_mirror.mode, 0o640);
        assert_eq!(parsed.v45_metadata.portable_mirror.uid, Some(1000));
        assert_eq!(parsed.v45_metadata.portable_mirror.attributes, Some(1));
    }

    #[test]
    fn hardlink_writer_rejects_native_file_object_metadata() {
        let mut portable = PortableFileMetadata::default();
        portable
            .native
            .primary_pax_records
            .insert("TZAP.unix.ctime-observed".into(), b"1".to_vec());
        assert!(matches!(
            build_primary_member_prefix(
                b"beta",
                SourceEntryKind::Hardlink,
                Some(b"alpha"),
                0,
                None,
                0o644,
                ArchiveTimestamp::UNIX_EPOCH,
                &portable,
            ),
            Err(FormatError::WriterInvariant(
                "hardlink alias carries native file-object metadata"
            ))
        ));
    }

    #[test]
    fn regular_file_writer_rejects_reserved_portable_attribute_bits() {
        let portable_metadata = PortableFileMetadata {
            attributes: Some(1 << 4),
            ..PortableFileMetadata::default()
        };
        assert_eq!(
            build_regular_file_member_group(
                b"attributes.txt",
                b"data",
                0o644,
                ArchiveTimestamp::UNIX_EPOCH,
                &portable_metadata,
            )
            .unwrap_err(),
            FormatError::WriterUnsupported("portable attributes contain reserved bits")
        );
    }

    #[test]
    fn regular_file_writer_emits_and_flags_valid_native_primary_metadata() {
        let mut native = NativeFileMetadata {
            required_profiles: vec!["posix-backup-v1".into()],
            ..NativeFileMetadata::default()
        };
        native.primary_pax_records.insert(
            "LIBARCHIVE.xattr.user.comment".into(),
            crate::entry_metadata::canonical_base64_encode(b"preserved"),
        );
        let metadata = PortableFileMetadata {
            source_os: "linux".into(),
            source_filesystem: "ext4".into(),
            native,
            ..PortableFileMetadata::default()
        };
        let group = build_regular_file_member_group(
            b"native.txt",
            b"data",
            0o640,
            ArchiveTimestamp::UNIX_EPOCH,
            &metadata,
        )
        .unwrap();
        let parsed = parse_tar_member_group(&group, 4096).unwrap();

        assert_eq!(
            parsed.v45_metadata.declaration.required_profiles,
            vec!["portable-v1", "posix-backup-v1"]
        );
        assert_eq!(
            parsed
                .v45_metadata
                .primary_records
                .get("LIBARCHIVE.xattr.user.comment")
                .map(Vec::as_slice),
            Some(b"cHJlc2VydmVk".as_slice())
        );
        assert_ne!(
            parsed.v45_metadata.file_entry_flags & HAS_NATIVE_METADATA,
            0
        );
    }

    #[test]
    fn regular_file_writer_emits_valid_native_auxiliary_metadata() {
        let mut native = NativeFileMetadata {
            required_profiles: vec!["posix-backup-v1".into()],
            ..NativeFileMetadata::default()
        };
        let mut auxiliary = NativeAuxiliaryMetadata::new(
            "generic.xattr",
            "posix-backup-v1",
            RestoreClass::SameOs,
            b"large xattr value".to_vec(),
        );
        auxiliary.name_encoding = NativeAuxiliaryNameEncoding::Bytes;
        auxiliary.name = b"user.large".to_vec();
        native.auxiliary_records.push(auxiliary);
        let metadata = PortableFileMetadata {
            source_os: "linux".into(),
            native,
            ..PortableFileMetadata::default()
        };

        let group = build_regular_file_member_group(
            b"native-aux.txt",
            b"contents",
            0o640,
            ArchiveTimestamp::from_seconds(12),
            &metadata,
        )
        .unwrap();
        let parsed = parse_tar_member_group(&group, 4096).unwrap();

        assert_eq!(parsed.v45_metadata.auxiliary.len(), 1);
        assert_eq!(parsed.v45_metadata.auxiliary[0].kind, "generic.xattr");
        assert_eq!(parsed.v45_metadata.auxiliary[0].decoded_name, b"user.large");
        assert_ne!(
            parsed.v45_metadata.file_entry_flags & HAS_AUXILIARY_STREAMS,
            0
        );
    }

    #[test]
    fn regular_file_writer_emits_capture_partial_flag_when_capture_report_present() {
        let mut native = NativeFileMetadata::default();
        let mut auxiliary = NativeAuxiliaryMetadata::new(
            "tzap.capture-report",
            "tzap-core-v1",
            RestoreClass::None,
            b"tzap-capture-report-v1\nportable-v1\ttzap-core-v1\texcluded-policy\tdetail\n"
                .to_vec(),
        );
        auxiliary.native = false;
        auxiliary.name_encoding = NativeAuxiliaryNameEncoding::None;
        auxiliary.name = vec![];
        native.auxiliary_records.push(auxiliary);
        let metadata = PortableFileMetadata {
            source_os: "linux".into(),
            native,
            ..PortableFileMetadata::default()
        };

        let group = build_regular_file_member_group(
            b"capture-report.txt",
            b"contents",
            0o640,
            ArchiveTimestamp::from_seconds(12),
            &metadata,
        )
        .unwrap();
        let parsed = parse_tar_member_group(&group, 4096).unwrap();

        assert_eq!(parsed.v45_metadata.auxiliary.len(), 1);
        assert_eq!(parsed.v45_metadata.auxiliary[0].kind, "tzap.capture-report");
        assert_ne!(parsed.v45_metadata.file_entry_flags & CAPTURE_PARTIAL, 0);
    }

    #[test]
    fn streamed_auxiliary_sources_work_across_writer_modes_and_verify_digest() {
        struct StreamedSource {
            metadata: PortableFileMetadata,
            payload: Vec<u8>,
        }

        impl RegularFileSource for StreamedSource {
            fn archive_path(&self) -> &str {
                "streamed-aux.txt"
            }

            fn file_data_size(&self) -> u64 {
                8
            }

            fn mode(&self) -> u32 {
                0o640
            }

            fn mtime(&self) -> ArchiveTimestamp {
                ArchiveTimestamp::from_seconds(12)
            }

            fn portable_metadata(&self) -> PortableFileMetadata {
                self.metadata.clone()
            }

            fn open(&self) -> Result<Box<dyn Read + '_>, ArchiveWriteError> {
                Ok(Box::new(Cursor::new(b"contents".as_slice())))
            }

            fn open_auxiliary(
                &self,
                ordinal: usize,
            ) -> Result<Box<dyn Read + '_>, ArchiveWriteError> {
                assert_eq!(ordinal, 0);
                Ok(Box::new(Cursor::new(self.payload.as_slice())))
            }
        }

        let payload = deterministic_bytes(1024 * 1024 + 17);
        let digest: [u8; 32] = Sha256::digest(&payload).into();
        let mut auxiliary = NativeAuxiliaryMetadata::new_streamed(
            "generic.xattr",
            "posix-backup-v1",
            RestoreClass::SameOs,
            payload.len() as u64,
            digest,
        );
        auxiliary.name_encoding = NativeAuxiliaryNameEncoding::Bytes;
        auxiliary.name = b"user.large".to_vec();
        let mut source = StreamedSource {
            metadata: PortableFileMetadata {
                source_os: "linux".into(),
                native: NativeFileMetadata {
                    required_profiles: vec!["posix-backup-v1".into()],
                    auxiliary_records: vec![auxiliary],
                    ..NativeFileMetadata::default()
                },
                ..PortableFileMetadata::default()
            },
            payload,
        };
        let key = MasterKey::from_raw_key(&[17u8; 32]).unwrap();
        let options = WriterOptions {
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            ..WriterOptions::default()
        };

        let mut two_pass = MemoryArchiveSink::default();
        write_archive_sources_to_sink(
            std::slice::from_ref(&source),
            &key,
            options,
            None,
            &KdfParams::Raw,
            None,
            None,
            &mut two_pass,
        )
        .unwrap();
        open_archive(&two_pass.volumes[0], &key)
            .unwrap()
            .verify_content()
            .unwrap();

        let mut single_pass = MemoryArchiveSink::default();
        write_archive_sources_to_sink_single_pass(
            std::slice::from_ref(&source),
            &key,
            options,
            &KdfParams::Raw,
            None,
            None,
            &mut single_pass,
        )
        .unwrap();
        open_archive(&single_pass.volumes[0], &key)
            .unwrap()
            .verify_content()
            .unwrap();

        let mut ordered = MemoryArchiveSink::default();
        write_archive_sources_to_sink_ordered_parallel(
            std::slice::from_ref(&source),
            &key,
            options,
            &KdfParams::Raw,
            None,
            None,
            &mut ordered,
        )
        .unwrap();
        open_archive(&ordered.volumes[0], &key)
            .unwrap()
            .verify_content()
            .unwrap();

        let mut progress_sink = MemoryArchiveSink::default();
        let mut progress = RecordingWriteProgress::default();
        write_archive_sources_to_sink_single_pass_with_progress(
            std::slice::from_ref(&source),
            &key,
            options,
            &KdfParams::Raw,
            None,
            None,
            &mut progress_sink,
            &mut progress,
        )
        .unwrap();
        assert_eq!(
            progress.bytes_for(ArchiveWritePhase::EmittingPayload),
            8 + source.payload.len() as u64
        );

        source.metadata.native.auxiliary_records[0]
            .streamed_payload
            .as_mut()
            .unwrap()
            .sha256[0] ^= 1;
        let mut rejected = MemoryArchiveSink::default();
        assert!(write_archive_sources_to_sink(
            std::slice::from_ref(&source),
            &key,
            options,
            None,
            &KdfParams::Raw,
            None,
            None,
            &mut rejected,
        )
        .is_err());
    }

    #[test]
    fn writer_splits_large_payload_across_seekable_envelopes() {
        let master_key = MasterKey::from_raw_key(&[8u8; 32]).unwrap();
        let data = deterministic_bytes(2 * 1024 * 1024);
        let archive = write_archive(
            &[RegularFile::new("large.bin", &data)],
            &master_key,
            WriterOptions {
                stripe_width: 1,
                volume_loss_tolerance: 0,
                bit_rot_buffer_pct: 0,
                ..WriterOptions::default()
            },
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key).unwrap();

        assert_eq!(opened.list_files().unwrap()[0].path, "large.bin");
        assert_eq!(opened.extract_file("large.bin").unwrap(), Some(data));
        opened.verify().unwrap();
        assert!(opened.index_root.header.envelope_count > 1);
    }

    #[test]
    fn split_member_frames_carry_exact_boundary_flags() {
        let data = deterministic_bytes(12 * 1024);
        let files = [RegularFile::new("large.bin", &data)];
        let options = WriterOptions {
            chunk_size: 1024,
            envelope_target_size: 64 * 1024,
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            ..WriterOptions::default()
        };
        let (tar_stream, members) = build_tar_stream(&files, options.max_path_length).unwrap();
        let (_, frames) = build_payload_envelopes(&tar_stream, &members, options, None).unwrap();

        assert!(frames.len() > 2);
        assert_eq!(frames.first().unwrap().flags, 0x0000_0001);
        assert_eq!(frames.last().unwrap().flags, 0x0000_0002);
        assert!(frames[1..frames.len() - 1]
            .iter()
            .all(|frame| frame.flags == 0));
    }

    #[test]
    fn spanning_payload_derives_exact_multi_frame_multi_envelope_stats() {
        let data = deterministic_bytes(13 * 1024);
        let files = [RegularFile::new("spanning.bin", &data)];
        let options = plan_writer_options(WriterOptions {
            block_size: MIN_BLOCK_SIZE,
            chunk_size: 1024,
            envelope_target_size: 2500,
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            fec_parity_shards: 0,
            index_fec_parity_shards: 0,
            index_root_fec_parity_shards: 0,
            ..WriterOptions::default()
        })
        .unwrap();
        let mut next_block_index = 0u64;

        let payload = plan_payload_stream(&files, options, None, &mut next_block_index).unwrap();
        let expected_tar_total_size =
            3 * TAR_BLOCK_LEN as u64 + data.len() as u64 + padding_to_512(data.len()) as u64;
        let (tar_stream, _) = build_tar_stream(&files, options.max_path_length).unwrap();

        assert_eq!(payload.tar_members.len(), 1);
        assert_eq!(payload.tar_members[0].tar_member_group_start, 0);
        assert_eq!(
            payload.tar_members[0].tar_member_group_size,
            expected_tar_total_size
        );
        assert_eq!(payload.tar_total_size, expected_tar_total_size);
        assert_eq!(payload.content_sha256, sha256_bytes(&tar_stream));
        assert_eq!(payload.frames.len(), 15);
        assert_eq!(payload.payload_objects.len(), 7);
        assert_eq!(payload.payload_block_count, 7);
        assert_eq!(next_block_index, 7);

        for (idx, frame) in payload.frames.iter().enumerate() {
            let expected_decompressed_size = if idx == 14 { 512 } else { 1024 };
            let expected_flags = match idx {
                0 => 0x0000_0001,
                14 => 0x0000_0002,
                _ => 0,
            };
            let expected_offset = payload.frames[..idx]
                .iter()
                .filter(|prior| prior.envelope_index == frame.envelope_index)
                .map(|prior| prior.compressed_size)
                .sum::<u32>();

            assert_eq!(frame.frame_index, idx as u64);
            assert_eq!(frame.member_index, 0);
            assert!((frame.envelope_index as usize) < payload.payload_objects.len());
            assert_eq!(frame.offset_in_envelope, expected_offset);
            assert_eq!(frame.decompressed_size, expected_decompressed_size);
            assert_eq!(frame.flags, expected_flags);
            assert_eq!(frame.tar_stream_offset, idx as u64 * 1024);
        }

        for (idx, object) in payload.payload_objects.iter().enumerate() {
            let expected_plaintext_size = payload
                .frames
                .iter()
                .filter(|frame| frame.envelope_index == idx as u64)
                .map(|frame| frame.compressed_size)
                .sum::<u32>();

            assert_eq!(object.envelope_index, idx as u64);
            assert_eq!(object.plaintext_size, expected_plaintext_size);
            assert_eq!(object.object.first_block_index, idx as u64);
            assert_eq!(object.object.data_block_count, 1);
            assert_eq!(object.object.parity_block_count, 0);
            assert_eq!(object.object.encrypted_size, options.block_size);
        }

        let shard_rows = partition_file_rows(sorted_file_rows(&payload.tar_members)).unwrap();
        let planned_shards = build_index_shard_plaintexts(
            &shard_rows,
            &payload.frames,
            &payload.payload_objects,
            options,
        )
        .unwrap();
        assert_eq!(planned_shards.len(), 1);
        let locating_shard = ShardEntry {
            shard_index: planned_shards[0].shard_index,
            first_block_index: 0,
            data_block_count: 1,
            parity_block_count: 0,
            encrypted_size: options.block_size,
            decompressed_size: planned_shards[0].plaintext.len() as u32,
            file_count: planned_shards[0].file_count,
            first_path_hash: planned_shards[0].first_path_hash,
            last_path_hash: planned_shards[0].last_path_hash,
        };
        let shard = IndexShard::parse(
            &planned_shards[0].plaintext,
            &locating_shard,
            MetadataLimits::default(),
        )
        .unwrap();
        assert_eq!(shard.header.file_count, 1);
        assert_eq!(shard.header.frame_count, 15);
        assert_eq!(shard.header.envelope_count, 7);
        assert_eq!(shard.files[0].first_frame_index, 0);
        assert_eq!(shard.files[0].frame_count, 15);
        assert_eq!(
            shard.files[0].tar_member_group_size,
            expected_tar_total_size
        );
        assert_eq!(shard.files[0].file_data_size, data.len() as u64);

        for (idx, frame) in shard.frames.iter().enumerate() {
            assert_eq!(frame.frame_index, idx as u64);
            assert_eq!(frame.envelope_index, payload.frames[idx].envelope_index);
            assert_eq!(
                frame.offset_in_envelope,
                payload.frames[idx].offset_in_envelope
            );
            assert_eq!(frame.compressed_size, payload.frames[idx].compressed_size);
            assert_eq!(
                frame.decompressed_size,
                payload.frames[idx].decompressed_size
            );
            assert_eq!(frame.flags, payload.frames[idx].flags);
            assert_eq!(
                frame.tar_stream_offset,
                payload.frames[idx].tar_stream_offset
            );
        }

        for (idx, envelope) in shard.envelopes.iter().enumerate() {
            assert_eq!(envelope.envelope_index, idx as u64);
            assert_eq!(envelope.first_block_index, idx as u64);
            assert_eq!(envelope.data_block_count, 1);
            assert_eq!(envelope.parity_block_count, 0);
            assert_eq!(envelope.encrypted_size, options.block_size);
            assert_eq!(
                envelope.plaintext_size,
                payload.payload_objects[idx].plaintext_size
            );
            let envelope_frames: Vec<_> = payload
                .frames
                .iter()
                .filter(|frame| frame.envelope_index == idx as u64)
                .collect();
            assert_eq!(
                envelope.first_frame_index,
                envelope_frames.first().unwrap().frame_index
            );
            assert_eq!(envelope.frame_count, envelope_frames.len() as u32);
        }

        let master_key = MasterKey::from_raw_key(&[6u8; 32]).unwrap();
        let plan = build_writer_plan_from_payload(
            payload,
            next_block_index,
            &master_key,
            options,
            None,
            &KdfParams::Raw,
            None,
            [0x44; 16],
            [0x55; 16],
            None,
        )
        .unwrap();
        let index_root =
            IndexRoot::parse(&plan.index_root_plaintext, false, MetadataLimits::default()).unwrap();

        assert_eq!(index_root.header.frame_count, 15);
        assert_eq!(index_root.header.envelope_count, 7);
        assert_eq!(index_root.header.file_count, 1);
        assert_eq!(index_root.header.payload_block_count, 7);
        assert_eq!(index_root.header.tar_total_size, expected_tar_total_size);
        assert_eq!(index_root.header.content_sha256, sha256_bytes(&tar_stream));
    }

    #[test]
    fn writes_empty_archive_with_authentic_bootstrap_structures() {
        let master_key = MasterKey::from_raw_key(&[7u8; 32]).unwrap();
        let archive = write_empty_archive(&master_key).unwrap();
        let bytes = archive.bytes;

        let volume_header = VolumeHeader::parse(&bytes[..VOLUME_HEADER_LEN]).unwrap();
        assert_eq!(volume_header.archive_uuid, archive.archive_uuid);
        assert_eq!(volume_header.session_id, archive.session_id);

        let crypto_start = VOLUME_HEADER_LEN;
        let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
        let crypto_header = CryptoHeader::parse(
            &bytes[crypto_start..crypto_end],
            volume_header.crypto_header_length,
        )
        .unwrap();
        let subkeys =
            Subkeys::derive(&master_key, &archive.archive_uuid, &archive.session_id).unwrap();
        verify_hmac(
            HmacDomain::CryptoHeader,
            &subkeys.mac_key,
            &archive.archive_uuid,
            &archive.session_id,
            crypto_header.hmac_covered_bytes,
            &crypto_header.header_hmac,
        )
        .unwrap();

        let locator =
            CriticalRecoveryLocator::parse(&bytes[bytes.len() - CRITICAL_RECOVERY_LOCATOR_LEN..])
                .unwrap();
        let trailer_offset = locator.volume_trailer_offset as usize;
        let trailer =
            VolumeTrailer::parse(&bytes[trailer_offset..trailer_offset + VOLUME_TRAILER_LEN])
                .unwrap();
        assert_eq!(trailer.bytes_written, trailer_offset as u64);
        verify_hmac(
            HmacDomain::VolumeTrailer,
            &subkeys.mac_key,
            &archive.archive_uuid,
            &archive.session_id,
            &bytes[trailer_offset..trailer_offset + 96],
            &trailer.trailer_hmac,
        )
        .unwrap();

        let manifest_offset = trailer.manifest_footer_offset as usize;
        let manifest_end = manifest_offset + MANIFEST_FOOTER_LEN;
        let manifest = ManifestFooter::parse(&bytes[manifest_offset..manifest_end]).unwrap();
        assert_eq!(manifest.is_authoritative, 1);
        assert_eq!(manifest.total_volumes, DEFAULT_STRIPE_WIDTH);
        verify_hmac(
            HmacDomain::ManifestFooter,
            &subkeys.mac_key,
            &archive.archive_uuid,
            &archive.session_id,
            &bytes[manifest_offset..manifest_offset + 104],
            &manifest.manifest_hmac,
        )
        .unwrap();
    }

    #[test]
    fn parity_auto_scaling_matches_v41_examples() {
        let options = WriterOptions {
            fec_data_shards: 224,
            stripe_width: 8,
            volume_loss_tolerance: 1,
            bit_rot_buffer_pct: 5,
            ..WriterOptions::default()
        };

        assert_eq!(compute_parity(224, options).unwrap(), 48);
        assert_eq!(compute_parity(17, options).unwrap(), 5);
    }

    #[test]
    fn parity_auto_scaling_rejects_non_convergent_budget() {
        let err = compute_parity(
            1,
            WriterOptions {
                stripe_width: 2,
                volume_loss_tolerance: 1,
                bit_rot_buffer_pct: 50,
                ..WriterOptions::default()
            },
        )
        .unwrap_err();

        assert_eq!(
            err,
            FormatError::WriterUnsupported("parity calculation did not converge")
        );
    }

    #[test]
    fn zero_parity_is_allowed_when_no_recovery_margin_is_requested() {
        let planned = plan_writer_options(WriterOptions {
            bit_rot_buffer_pct: 0,
            stripe_width: 1,
            volume_loss_tolerance: 0,
            fec_parity_shards: 0,
            index_fec_parity_shards: 0,
            index_root_fec_parity_shards: 0,
            ..WriterOptions::default()
        })
        .unwrap();

        assert_eq!(planned.fec_parity_shards, 0);
        assert_eq!(planned.index_fec_parity_shards, 0);
        assert_eq!(planned.index_root_fec_parity_shards, 0);
        assert_eq!(compute_parity(1, planned).unwrap(), 0);
    }

    #[test]
    fn index_root_data_shard_maximum_obeys_v41_minimum() {
        let planned = plan_writer_options(WriterOptions {
            index_root_fec_data_shards: 1,
            ..WriterOptions::default()
        })
        .unwrap();

        assert_eq!(
            planned.index_root_fec_data_shards,
            MIN_INDEX_ROOT_FEC_DATA_SHARDS
        );
    }

    #[test]
    fn metadata_class_planning_raises_index_root_class_above_default() {
        let options = plan_writer_options(WriterOptions {
            block_size: MIN_BLOCK_SIZE,
            index_root_fec_parity_shards: 0,
            bit_rot_buffer_pct: 0,
            ..WriterOptions::default()
        })
        .unwrap();
        let index_root_payload_len = payload_len_for_encrypted_data_blocks(64, options);

        let planned =
            plan_index_root_metadata_class(options, index_root_payload_len, None).unwrap();

        assert_eq!(planned.index_root.data_block_count, 64);
        assert_eq!(planned.options.index_root_fec_data_shards, 64);
        assert_eq!(
            planned.options.index_root_fec_parity_shards,
            compute_parity_u16(
                planned.options.index_root_fec_data_shards as u64,
                planned.options,
                "index_root_fec_parity_shards",
            )
            .unwrap()
        );
    }

    #[test]
    fn single_pass_writer_predeclares_metadata_class_before_payload_streaming() {
        let planned = plan_single_pass_writer_options(WriterOptions {
            block_size: MIN_BLOCK_SIZE,
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            index_root_fec_parity_shards: 0,
            ..WriterOptions::default()
        })
        .unwrap();

        assert!(planned.index_root_fec_data_shards > DEFAULT_INDEX_ROOT_FEC_DATA_SHARDS);
        let index_root_payload_len = payload_len_for_encrypted_data_blocks(
            u32::from(planned.index_root_fec_data_shards - 1),
            planned,
        );
        let metadata_class =
            plan_index_root_metadata_class(planned, index_root_payload_len, None).unwrap();

        assert_eq!(metadata_class.options, planned);
    }

    #[test]
    fn metadata_class_planning_rejects_oversized_index_root() {
        let options = single_volume_metadata_test_options();
        let index_root_payload_len =
            payload_len_for_encrypted_data_blocks(u16::MAX as u32 + 1, options);

        let err =
            plan_index_root_metadata_class(options, index_root_payload_len, None).unwrap_err();

        assert_eq!(err, FormatError::WriterUnsupported("IndexRoot too large"));
    }

    #[test]
    fn metadata_class_planning_rejects_index_root_u32_encrypted_size_overflow() {
        let options = single_volume_metadata_test_options();
        let index_root_payload_len = u32::MAX as usize - options.aead_algo.tag_len() + 1;

        let err =
            plan_index_root_metadata_class(options, index_root_payload_len, None).unwrap_err();

        assert_eq!(err, FormatError::WriterUnsupported("IndexRoot too large"));
    }

    #[test]
    fn metadata_class_planning_rejects_oversized_dictionary() {
        let options = single_volume_metadata_test_options();
        let dictionary_payload_len =
            payload_len_for_encrypted_data_blocks(u16::MAX as u32 + 1, options);

        let err =
            plan_index_root_metadata_class(options, 1, Some(dictionary_payload_len)).unwrap_err();

        assert_eq!(
            err,
            FormatError::WriterUnsupported("dictionary object too large")
        );
    }

    #[test]
    fn metadata_class_planning_rejects_gf16_total_overflow_for_dictionary() {
        let options = plan_writer_options(WriterOptions {
            block_size: MIN_BLOCK_SIZE,
            stripe_width: 8,
            volume_loss_tolerance: 1,
            bit_rot_buffer_pct: 5,
            ..WriterOptions::default()
        })
        .unwrap();
        let dictionary_payload_len = payload_len_for_encrypted_data_blocks(60_000, options);

        let err =
            plan_index_root_metadata_class(options, 1, Some(dictionary_payload_len)).unwrap_err();

        assert_eq!(
            err,
            FormatError::WriterUnsupported("dictionary object too large")
        );
    }

    #[test]
    fn written_archive_authenticates_final_index_root_fec_class() {
        let master_key = MasterKey::from_raw_key(&[9u8; 32]).unwrap();
        let dictionary = deterministic_bytes(80 * 1024);
        let file = RegularFile::new("uses-dictionary.txt", b"payload");
        let archive = write_archive_with_dictionary(
            &[file],
            &master_key,
            WriterOptions {
                block_size: MIN_BLOCK_SIZE,
                stripe_width: 1,
                volume_loss_tolerance: 0,
                bit_rot_buffer_pct: 0,
                index_root_fec_parity_shards: 0,
                ..WriterOptions::default()
            },
            &dictionary,
        )
        .unwrap();

        let volume_header = VolumeHeader::parse(&archive.bytes[..VOLUME_HEADER_LEN]).unwrap();
        let crypto_start = VOLUME_HEADER_LEN;
        let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
        let crypto_header = CryptoHeader::parse(
            &archive.bytes[crypto_start..crypto_end],
            volume_header.crypto_header_length,
        )
        .unwrap();
        let subkeys =
            Subkeys::derive(&master_key, &archive.archive_uuid, &archive.session_id).unwrap();
        verify_hmac(
            HmacDomain::CryptoHeader,
            &subkeys.mac_key,
            &archive.archive_uuid,
            &archive.session_id,
            crypto_header.hmac_covered_bytes,
            &crypto_header.header_hmac,
        )
        .unwrap();

        assert!(crypto_header.fixed.index_root_fec_data_shards > MIN_INDEX_ROOT_FEC_DATA_SHARDS);
        assert_eq!(crypto_header.fixed.index_root_fec_parity_shards, 0);
        let opened = open_archive(&archive.bytes, &master_key).unwrap();
        assert_eq!(
            opened.extract_file("uses-dictionary.txt").unwrap(),
            Some(b"payload".to_vec())
        );
        opened.verify().unwrap();
    }

    #[test]
    fn object_parity_uses_per_object_recurrence_even_with_larger_class_max() {
        let options = WriterOptions {
            bit_rot_buffer_pct: 0,
            stripe_width: 1,
            volume_loss_tolerance: 0,
            fec_parity_shards: 1,
            ..WriterOptions::default()
        };

        assert_eq!(compute_object_parity(1, options, 1).unwrap(), 0);
    }

    #[test]
    fn object_total_shards_obeys_reed_solomon_limit() {
        assert!(validate_object_shard_total(65_535, 0).is_ok());
        assert_eq!(
            validate_object_shard_total(65_535, 1).unwrap_err(),
            FormatError::WriterUnsupported("encrypted object exceeds ReedSolomonGF16 shard limit")
        );
    }

    #[test]
    fn argon2id_kdf_serialization_rejects_memory_requirement_overflow() {
        assert_eq!(
            serialize_kdf_params(&KdfParams::Argon2id {
                t_cost: 1,
                m_cost_kib: u32::MAX,
                parallelism: u32::MAX,
                salt: b"12345678".to_vec(),
            })
            .unwrap_err(),
            FormatError::InvalidKdfParams("m_cost_kib requirement overflow")
        );
    }

    #[test]
    fn recipient_wrap_kdf_serialization() {
        let params = KdfParams::RecipientWrap {
            key_wrap_table_length: 16,
            key_wrap_table_record_count: 4,
            key_wrap_table_version: 1,
            key_wrap_table_digest: [0xaau8; 32],
        };
        let serialized = serialize_kdf_params(&params).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(&(KdfAlgo::RecipientWrap as u16).to_le_bytes());
        expected.extend_from_slice(&16u32.to_le_bytes());
        expected.extend_from_slice(&4u32.to_le_bytes());
        expected.extend_from_slice(&1u16.to_le_bytes());
        expected.extend_from_slice(&0u16.to_le_bytes());
        expected.extend_from_slice(&[0xaau8; 32]);
        assert_eq!(serialized, expected);
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

    #[test]
    fn writer_options_reject_reader_resource_cap_excesses() {
        assert_eq!(
            plan_writer_options(WriterOptions {
                stripe_width: crate::format::READER_MAX_STRIPE_WIDTH + 1,
                volume_loss_tolerance: 0,
                ..WriterOptions::default()
            })
            .unwrap_err(),
            FormatError::ReaderResourceLimitExceeded {
                field: "stripe_width",
                cap: crate::format::READER_MAX_STRIPE_WIDTH as u64,
                actual: crate::format::READER_MAX_STRIPE_WIDTH as u64 + 1,
            }
        );
        assert_eq!(
            plan_writer_options(WriterOptions {
                block_size: crate::format::READER_MAX_BLOCK_SIZE + 2,
                ..WriterOptions::default()
            })
            .unwrap_err(),
            FormatError::ReaderResourceLimitExceeded {
                field: "block_size",
                cap: crate::format::READER_MAX_BLOCK_SIZE as u64,
                actual: crate::format::READER_MAX_BLOCK_SIZE as u64 + 2,
            }
        );
        assert_eq!(
            plan_writer_options(WriterOptions {
                chunk_size: crate::format::READER_MAX_CHUNK_SIZE + 1,
                envelope_target_size: crate::format::READER_MAX_CHUNK_SIZE + 1,
                ..WriterOptions::default()
            })
            .unwrap_err(),
            FormatError::ReaderResourceLimitExceeded {
                field: "chunk_size",
                cap: crate::format::READER_MAX_CHUNK_SIZE as u64,
                actual: crate::format::READER_MAX_CHUNK_SIZE as u64 + 1,
            }
        );
        assert_eq!(
            plan_writer_options(WriterOptions {
                max_path_length: crate::format::READER_MAX_PATH_LENGTH + 1,
                ..WriterOptions::default()
            })
            .unwrap_err(),
            FormatError::ReaderResourceLimitExceeded {
                field: "max_path_length",
                cap: crate::format::READER_MAX_PATH_LENGTH as u64,
                actual: crate::format::READER_MAX_PATH_LENGTH as u64 + 1,
            }
        );
        assert_eq!(
            plan_writer_options(WriterOptions {
                bit_rot_buffer_pct: 0,
                stripe_width: 1,
                volume_loss_tolerance: 0,
                fec_data_shards: crate::format::READER_MAX_FEC_CLASS_SHARDS as u16 + 1,
                ..WriterOptions::default()
            })
            .unwrap_err(),
            FormatError::ReaderResourceLimitExceeded {
                field: "fec_data_shards + fec_parity_shards",
                cap: crate::format::READER_MAX_FEC_CLASS_SHARDS as u64,
                actual: crate::format::READER_MAX_FEC_CLASS_SHARDS as u64 + 1,
            }
        );
    }

    #[test]
    fn root_auth_writer_config_rejects_reader_cap_excess_before_authenticator() {
        let master_key = MasterKey::from_raw_key(&[7u8; 32]).unwrap();
        let mut authenticator_called = false;
        let err = write_archive_with_root_auth(
            &[RegularFile::new("signed.txt", b"payload")],
            &master_key,
            single_volume_metadata_test_options(),
            RootAuthWriterConfig {
                authenticator_id: 1,
                signer_identity_type: 1,
                signer_identity: b"signer",
                authenticator_value_length: READER_MAX_ROOT_AUTH_AUTHENTICATOR_VALUE_LEN + 1,
            },
            |_| {
                authenticator_called = true;
                Ok(Vec::new())
            },
        )
        .unwrap_err();

        assert!(!authenticator_called);
        assert_eq!(
            err,
            FormatError::ReaderResourceLimitExceeded {
                field: "RootAuthFooterV1 authenticator value length",
                cap: READER_MAX_ROOT_AUTH_AUTHENTICATOR_VALUE_LEN as u64,
                actual: READER_MAX_ROOT_AUTH_AUTHENTICATOR_VALUE_LEN as u64 + 1,
            }
        );
    }

    #[test]
    fn root_auth_writer_accepts_128_kib_authenticator_value() {
        let master_key = MasterKey::from_raw_key(&[8u8; 32]).unwrap();
        let authenticator_value = vec![0x5a; READER_MAX_ROOT_AUTH_AUTHENTICATOR_VALUE_LEN as usize];
        let expected_value = authenticator_value.clone();
        let archive = write_archive_with_root_auth(
            &[RegularFile::new("signed.txt", b"payload")],
            &master_key,
            single_volume_metadata_test_options(),
            RootAuthWriterConfig {
                authenticator_id: 0xcafe,
                signer_identity_type: 1,
                signer_identity: b"certificate-profile-signer",
                authenticator_value_length: READER_MAX_ROOT_AUTH_AUTHENTICATOR_VALUE_LEN,
            },
            |_| Ok(authenticator_value.clone()),
        )
        .unwrap();

        let opened = open_archive(&archive.bytes, &master_key).unwrap();
        let footer = opened.root_auth_footer.as_ref().unwrap();
        assert_eq!(footer.authenticator_id, 0xcafe);
        assert_eq!(
            footer.authenticator_value.as_slice(),
            expected_value.as_slice()
        );

        let verification = opened
            .verify_root_auth_with(|footer, _| {
                Ok(footer.authenticator_id == 0xcafe
                    && footer.authenticator_value.as_slice() == expected_value.as_slice())
            })
            .unwrap();
        assert_eq!(verification.authenticator_id, 0xcafe);
    }

    #[test]
    fn streaming_writer_sink_round_trips_archive() {
        let files = [
            RegularFile::new("alpha.txt", b"alpha"),
            RegularFile::new("nested/beta.txt", b"beta payload"),
        ];
        let master_key = MasterKey::from_raw_key(&[7u8; 32]).unwrap();
        let mut sink = MemoryArchiveSink::default();

        let summary = write_archive_sources_to_sink(
            &files,
            &master_key,
            single_volume_metadata_test_options(),
            None,
            &KdfParams::Raw,
            None,
            None,
            &mut sink,
        )
        .unwrap();

        assert_eq!(summary.volume_count, 1);
        let opened = crate::reader::open_archive(&sink.volumes[0], &master_key).unwrap();
        assert_eq!(
            opened.extract_file("nested/beta.txt").unwrap(),
            Some(b"beta payload".to_vec())
        );
    }

    #[test]
    fn ordered_sink_writer_round_trips_recipientwrap_records() {
        let files = [RegularFile::new("wrapped.txt", b"recipient sink payload")];
        let master_key = MasterKey::from_raw_key(&[9u8; 32]).unwrap();
        let mut sink = MemoryArchiveSink::default();

        let summary = write_archive_sources_to_sink_ordered_parallel_with_recipient_wrap_records(
            &files,
            &master_key,
            single_volume_metadata_test_options(),
            vec![recipient_wrap_test_record()],
            None,
            None,
            &mut sink,
        )
        .unwrap();

        assert_eq!(summary.volume_count, 1);
        let opened =
            open_archive_with_recipient_wrap_resolver(&sink.volumes[0], |_| Ok(vec![master_key.0]))
                .unwrap();
        assert_eq!(
            opened.extract_file("wrapped.txt").unwrap(),
            Some(b"recipient sink payload".to_vec())
        );
    }

    #[test]
    fn ordered_sink_writer_indexes_v45_metadata_flags_from_member_semantics() {
        let mut sparse_payload = vec![0u8; TAR_BLOCK_LEN];
        sparse_payload[..2].copy_from_slice(b"0\n");
        let mut sparse_fork = NativeAuxiliaryMetadata::new(
            "macos.resource-fork",
            "macos-backup-v1",
            RestoreClass::SameOs,
            sparse_payload,
        );
        sparse_fork.flags = 1;
        sparse_fork.logical_size = 4096;

        let sparse_metadata = PortableFileMetadata {
            source_os: "macos".into(),
            native: NativeFileMetadata {
                required_profiles: vec!["macos-backup-v1".into(), "posix-backup-v1".into()],
                auxiliary_records: vec![sparse_fork],
                ..NativeFileMetadata::default()
            },
            ..PortableFileMetadata::default()
        };
        let portable_only_metadata = PortableFileMetadata {
            native: NativeFileMetadata {
                required_profiles: vec![PORTABLE_PROFILE.into()],
                ..NativeFileMetadata::default()
            },
            ..PortableFileMetadata::default()
        };
        let files = [
            RegularFile {
                path: "sparse-fork.bin",
                contents: b"primary",
                mode: 0o644,
                mtime: ArchiveTimestamp::UNIX_EPOCH,
                portable_metadata: sparse_metadata,
            },
            RegularFile {
                path: "portable-only.bin",
                contents: b"portable",
                mode: 0o644,
                mtime: ArchiveTimestamp::UNIX_EPOCH,
                portable_metadata: portable_only_metadata,
            },
        ];
        let master_key = MasterKey::from_raw_key(&[0x45; 32]).unwrap();
        let mut sink = MemoryArchiveSink::default();

        write_archive_sources_to_sink_ordered_parallel(
            &files,
            &master_key,
            single_volume_metadata_test_options(),
            &KdfParams::Raw,
            None,
            None,
            &mut sink,
        )
        .unwrap();

        let opened = open_archive(&sink.volumes[0], &master_key).unwrap();
        opened.verify().unwrap();
        let entries = opened.list_index_entries().unwrap();
        let sparse = entries
            .iter()
            .find(|entry| entry.path == "sparse-fork.bin")
            .unwrap();
        assert_ne!(sparse.flags & HAS_SPARSE_EXTENTS, 0);
        let portable_only = entries
            .iter()
            .find(|entry| entry.path == "portable-only.bin")
            .unwrap();
        assert_eq!(portable_only.flags & HAS_NATIVE_METADATA, 0);
    }

    #[test]
    fn single_pass_sink_writer_round_trips_recipientwrap_records() {
        let files = [RegularFile::new(
            "wrapped.txt",
            b"recipient single-pass sink payload",
        )];
        let master_key = MasterKey::from_raw_key(&[9u8; 32]).unwrap();
        let mut sink = MemoryArchiveSink::default();

        let summary = write_archive_sources_to_sink_single_pass_with_recipient_wrap_records(
            &files,
            &master_key,
            single_volume_metadata_test_options(),
            vec![recipient_wrap_test_record()],
            None,
            None,
            &mut sink,
        )
        .unwrap();

        assert_eq!(summary.volume_count, 1);
        let opened =
            open_archive_with_recipient_wrap_resolver(&sink.volumes[0], |_| Ok(vec![master_key.0]))
                .unwrap();
        assert_eq!(
            opened.extract_file("wrapped.txt").unwrap(),
            Some(b"recipient single-pass sink payload".to_vec())
        );
        opened.verify().unwrap();
    }

    #[test]
    fn single_pass_sink_writer_round_trips_recipientwrap_root_auth() {
        let files = [RegularFile::new(
            "wrapped.txt",
            b"recipient single-pass signed payload",
        )];
        let master_key = MasterKey::from_raw_key(&[9u8; 32]).unwrap();
        let mut sink = MemoryArchiveSink::default();

        let summary = write_archive_sources_to_sink_single_pass_with_recipient_wrap_records(
            &files,
            &master_key,
            single_volume_metadata_test_options(),
            vec![recipient_wrap_test_record()],
            Some(RootAuthWriterConfig {
                authenticator_id: 0x44,
                signer_identity_type: 1,
                signer_identity: b"recipient-wrap-single-pass",
                authenticator_value_length: 32,
            }),
            Some(&mut |request| Ok(request.archive_root.to_vec())),
            &mut sink,
        )
        .unwrap();

        assert_eq!(summary.volume_count, 1);
        let opened =
            open_archive_with_recipient_wrap_resolver(&sink.volumes[0], |_| Ok(vec![master_key.0]))
                .unwrap();
        let verification = opened
            .verify_root_auth_with(|footer, archive_root| {
                Ok(footer.authenticator_id == 0x44
                    && footer.authenticator_value.as_slice() == archive_root)
            })
            .unwrap();
        assert_eq!(verification.volume_format_rev, VOLUME_FORMAT_REV_45);
    }

    #[test]
    fn single_pass_writer_rejects_recipientwrap_kdf_without_records_before_writing() {
        let files = [RegularFile::new("wrapped.txt", b"recipient sink payload")];
        let master_key = MasterKey::from_raw_key(&[9u8; 32]).unwrap();
        let mut sink = MemoryArchiveSink::default();
        let kdf_params = KdfParams::RecipientWrap {
            key_wrap_table_length: 0,
            key_wrap_table_record_count: 1,
            key_wrap_table_version: 1,
            key_wrap_table_digest: [0u8; 32],
        };

        let err = write_archive_sources_to_sink_single_pass(
            &files,
            &master_key,
            single_volume_metadata_test_options(),
            &kdf_params,
            None,
            None,
            &mut sink,
        )
        .unwrap_err();

        match err {
            ArchiveWriteError::Format(FormatError::WriterUnsupported(message)) => {
                assert_eq!(message, "RecipientWrap requires key-wrap records");
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert!(sink.volumes.is_empty());
    }

    #[test]
    fn ordered_sink_writer_rejects_recipientwrap_kdf_without_records_before_writing() {
        let files = [RegularFile::new("wrapped.txt", b"recipient sink payload")];
        let master_key = MasterKey::from_raw_key(&[9u8; 32]).unwrap();
        let mut sink = MemoryArchiveSink::default();
        let kdf_params = KdfParams::RecipientWrap {
            key_wrap_table_length: 0,
            key_wrap_table_record_count: 1,
            key_wrap_table_version: 1,
            key_wrap_table_digest: [0u8; 32],
        };

        let err = write_archive_sources_to_sink_ordered_parallel(
            &files,
            &master_key,
            single_volume_metadata_test_options(),
            &kdf_params,
            None,
            None,
            &mut sink,
        )
        .unwrap_err();

        match err {
            ArchiveWriteError::Format(FormatError::WriterUnsupported(message)) => {
                assert_eq!(message, "RecipientWrap requires key-wrap records");
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert!(sink.volumes.is_empty());
    }

    #[test]
    fn streaming_writer_bounds_source_reads_and_sink_writes_for_large_file() {
        let file_size = 3 * 1024 * 1024;
        let stats = Rc::new(RefCell::new(GeneratedSourceStats::default()));
        let file = GeneratedFileSource {
            path: "large/generated.bin",
            len: file_size,
            stats: Rc::clone(&stats),
        };
        let master_key = MasterKey::from_raw_key(&[3u8; 32]).unwrap();
        let options = plan_writer_options(WriterOptions {
            block_size: MIN_BLOCK_SIZE,
            chunk_size: 16 * 1024,
            envelope_target_size: 64 * 1024,
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            fec_parity_shards: 0,
            index_fec_parity_shards: 0,
            index_root_fec_parity_shards: 0,
            ..WriterOptions::default()
        })
        .unwrap();
        let mut sink = TrackingArchiveSink::default();

        let summary = write_archive_sources_to_sink_single_pass(
            &[file],
            &master_key,
            options,
            &KdfParams::Raw,
            None,
            None,
            &mut sink,
        )
        .unwrap();

        let stats = stats.borrow();
        assert_eq!(stats.open_count, 1);
        assert_eq!(stats.total_read, file_size as u64);
        assert!(stats.max_read_request <= options.chunk_size as usize);
        assert_eq!(summary.volume_count, 1);
        assert_eq!(summary.archive_bytes, sink.volume_bytes.iter().sum());
        assert_eq!(
            summary.bootstrap_sidecar_bytes,
            sink.bootstrap_sidecar_bytes
        );
        assert!(sink.max_write_len <= 128 * 1024);
    }

    #[test]
    fn sink_writer_progress_reports_source_bytes_for_each_multi_pass_phase() {
        let file_size = 512 * 1024;
        let stats = Rc::new(RefCell::new(GeneratedSourceStats::default()));
        let file = GeneratedFileSource {
            path: "large/generated.bin",
            len: file_size,
            stats: Rc::clone(&stats),
        };
        let master_key = MasterKey::from_raw_key(&[4u8; 32]).unwrap();
        let options = WriterOptions {
            block_size: MIN_BLOCK_SIZE,
            chunk_size: 16 * 1024,
            envelope_target_size: 64 * 1024,
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            fec_parity_shards: 0,
            index_fec_parity_shards: 0,
            index_root_fec_parity_shards: 0,
            ..WriterOptions::default()
        };
        let mut sink = MemoryArchiveSink::default();
        let mut progress = RecordingWriteProgress::default();

        let summary = write_archive_sources_to_sink_with_progress(
            &[file],
            &master_key,
            options,
            None,
            &KdfParams::Raw,
            None,
            None,
            &mut sink,
            &mut progress,
        )
        .unwrap();

        let stats = stats.borrow();
        assert!(stats.open_count > 1);
        assert_eq!(
            progress.bytes_for(ArchiveWritePhase::PlanningPayload),
            file_size as u64
        );
        assert_eq!(
            progress.bytes_for(ArchiveWritePhase::EmittingPayload),
            file_size as u64
        );
        assert_eq!(summary.volume_count, 1);
        assert!(!sink.volumes.is_empty());
    }

    #[test]
    fn sink_writer_progress_reports_multi_pass_phases_and_phase_bytes() {
        let file_size = 512 * 1024;
        let stats = Rc::new(RefCell::new(GeneratedSourceStats::default()));
        let file = GeneratedFileSource {
            path: "large/generated.bin",
            len: file_size,
            stats: Rc::clone(&stats),
        };
        let master_key = MasterKey::from_raw_key(&[4u8; 32]).unwrap();
        let options = WriterOptions {
            block_size: MIN_BLOCK_SIZE,
            chunk_size: 16 * 1024,
            envelope_target_size: 64 * 1024,
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            fec_parity_shards: 0,
            index_fec_parity_shards: 0,
            index_root_fec_parity_shards: 0,
            ..WriterOptions::default()
        };
        let mut sink = MemoryArchiveSink::default();
        let mut progress = RecordingWriteProgress::default();

        write_archive_sources_to_sink_with_progress(
            &[file],
            &master_key,
            options,
            None,
            &KdfParams::Raw,
            None,
            None,
            &mut sink,
            &mut progress,
        )
        .unwrap();

        assert_eq!(
            progress.phases,
            vec![
                ArchiveWritePhase::PlanningPayload,
                ArchiveWritePhase::PlanningMetadata,
                ArchiveWritePhase::EmittingPayload,
                ArchiveWritePhase::EmittingMetadata,
            ]
        );
        assert_eq!(
            progress.bytes_for(ArchiveWritePhase::PlanningPayload),
            file_size as u64
        );
        assert_eq!(
            progress.bytes_for(ArchiveWritePhase::EmittingPayload),
            file_size as u64
        );
    }

    #[test]
    fn sink_writer_progress_reports_each_volume_size_replanning_attempt() {
        let file_size = 64 * 1024;
        let mut contents = Vec::with_capacity(file_size);
        let mut random = 0x1234_5678u32;
        for _ in 0..file_size {
            random = random.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            contents.push((random >> 24) as u8);
        }
        let file = RegularFile::new("sized.bin", &contents);
        let master_key = MasterKey::from_raw_key(&[9u8; 32]).unwrap();
        let options = WriterOptions {
            block_size: 4 * 1024,
            chunk_size: 4 * 1024,
            envelope_target_size: 128 * 1024,
            stripe_width: 1,
            volume_loss_tolerance: 1,
            target_volume_size: Some(8 * 1024),
            ..WriterOptions::default()
        };
        let mut sink = MemoryArchiveSink::default();
        let mut progress = RecordingWriteProgress::default();

        write_archive_sources_to_sink_with_progress(
            &[file],
            &master_key,
            options,
            None,
            &KdfParams::Raw,
            None,
            None,
            &mut sink,
            &mut progress,
        )
        .unwrap();

        let planning_attempts = progress
            .phases
            .iter()
            .filter(|phase| **phase == ArchiveWritePhase::PlanningPayload)
            .count();
        assert!(planning_attempts > 1);
        assert_eq!(
            progress.phases.len(),
            planning_attempts * 2 + 2,
            "each planning attempt has payload and metadata phases before emission",
        );
        for phases in progress.phases[..planning_attempts * 2].chunks_exact(2) {
            assert_eq!(
                phases,
                [
                    ArchiveWritePhase::PlanningPayload,
                    ArchiveWritePhase::PlanningMetadata,
                ]
            );
        }
        assert_eq!(
            &progress.phases[planning_attempts * 2..],
            [
                ArchiveWritePhase::EmittingPayload,
                ArchiveWritePhase::EmittingMetadata,
            ]
        );
        assert_eq!(
            progress.bytes_for(ArchiveWritePhase::PlanningPayload),
            file_size as u64 * planning_attempts as u64,
        );
        assert_eq!(
            progress.bytes_for(ArchiveWritePhase::EmittingPayload),
            file_size as u64,
        );
    }

    #[test]
    fn single_pass_progress_reports_emission_phases() {
        let file_size = 128 * 1024;
        let stats = Rc::new(RefCell::new(GeneratedSourceStats::default()));
        let file = GeneratedFileSource {
            path: "single/generated.bin",
            len: file_size,
            stats,
        };
        let master_key = MasterKey::from_raw_key(&[5u8; 32]).unwrap();
        let options = progress_test_writer_options();
        let mut sink = MemoryArchiveSink::default();
        let mut progress = RecordingWriteProgress::default();

        write_archive_sources_to_sink_single_pass_with_progress(
            &[file],
            &master_key,
            options,
            &KdfParams::Raw,
            None,
            None,
            &mut sink,
            &mut progress,
        )
        .unwrap();

        assert_eq!(
            progress.phases,
            vec![
                ArchiveWritePhase::EmittingPayload,
                ArchiveWritePhase::EmittingMetadata,
            ]
        );
        assert_eq!(
            progress.bytes_for(ArchiveWritePhase::EmittingPayload),
            file_size as u64
        );
    }

    #[test]
    fn ordered_parallel_progress_reports_emission_phases() {
        let file_size = 128 * 1024;
        let stats = Rc::new(RefCell::new(GeneratedSourceStats::default()));
        let file = GeneratedFileSource {
            path: "parallel/generated.bin",
            len: file_size,
            stats,
        };
        let master_key = MasterKey::from_raw_key(&[6u8; 32]).unwrap();
        let options = progress_test_writer_options();
        let mut sink = MemoryArchiveSink::default();
        let mut progress = RecordingWriteProgress::default();

        write_archive_sources_to_sink_ordered_parallel_with_progress(
            &[file],
            &master_key,
            options,
            &KdfParams::Raw,
            None,
            None,
            &mut sink,
            &mut progress,
        )
        .unwrap();

        assert_eq!(
            progress.phases,
            vec![
                ArchiveWritePhase::EmittingPayload,
                ArchiveWritePhase::EmittingMetadata,
            ]
        );
        assert_eq!(
            progress.bytes_for(ArchiveWritePhase::EmittingPayload),
            file_size as u64
        );
    }

    fn progress_test_writer_options() -> WriterOptions {
        WriterOptions {
            block_size: MIN_BLOCK_SIZE,
            chunk_size: 16 * 1024,
            envelope_target_size: 64 * 1024,
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            fec_parity_shards: 0,
            index_fec_parity_shards: 0,
            index_root_fec_parity_shards: 0,
            ..WriterOptions::default()
        }
    }

    #[derive(Default)]
    struct RecordingWriteProgress {
        phases: Vec<ArchiveWritePhase>,
        phase_bytes: BTreeMap<ArchiveWritePhase, u64>,
    }

    impl RecordingWriteProgress {
        fn bytes_for(&self, phase: ArchiveWritePhase) -> u64 {
            self.phase_bytes.get(&phase).copied().unwrap_or_default()
        }
    }

    impl ArchiveWriteProgressSink for RecordingWriteProgress {
        fn phase_started(&mut self, phase: ArchiveWritePhase) {
            self.phases.push(phase);
        }

        fn source_bytes_read(&mut self, phase: ArchiveWritePhase, _archive_path: &str, bytes: u64) {
            let total = self.phase_bytes.entry(phase).or_default();
            *total = total.saturating_add(bytes);
        }
    }

    #[derive(Default)]
    struct GeneratedSourceStats {
        open_count: usize,
        total_read: u64,
        max_read_request: usize,
    }

    struct GeneratedFileSource {
        path: &'static str,
        len: usize,
        stats: Rc<RefCell<GeneratedSourceStats>>,
    }

    impl RegularFileSource for GeneratedFileSource {
        fn archive_path(&self) -> &str {
            self.path
        }

        fn file_data_size(&self) -> u64 {
            self.len as u64
        }

        fn mode(&self) -> u32 {
            0o644
        }

        fn mtime(&self) -> ArchiveTimestamp {
            ArchiveTimestamp::UNIX_EPOCH
        }

        fn open(&self) -> Result<Box<dyn Read + '_>, ArchiveWriteError> {
            self.stats.borrow_mut().open_count += 1;
            Ok(Box::new(GeneratedReader {
                remaining: self.len,
                position: 0,
                stats: Rc::clone(&self.stats),
            }))
        }
    }

    struct GeneratedReader {
        remaining: usize,
        position: usize,
        stats: Rc<RefCell<GeneratedSourceStats>>,
    }

    impl Read for GeneratedReader {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Ok(0);
            }
            let count = out.len().min(self.remaining);
            for (offset, byte) in out[..count].iter_mut().enumerate() {
                let position = self.position + offset;
                *byte = position.wrapping_mul(31).wrapping_add(17) as u8;
            }
            self.position += count;
            self.remaining -= count;
            let mut stats = self.stats.borrow_mut();
            stats.total_read += count as u64;
            stats.max_read_request = stats.max_read_request.max(out.len());
            Ok(count)
        }
    }

    #[derive(Default)]
    struct TrackingArchiveSink {
        volume_bytes: Vec<u64>,
        bootstrap_sidecar_bytes: u64,
        max_write_len: usize,
    }

    impl ArchiveWriteSink for TrackingArchiveSink {
        fn begin_archive(&mut self, volume_count: usize) -> Result<(), ArchiveWriteError> {
            self.volume_bytes = vec![0; volume_count];
            self.bootstrap_sidecar_bytes = 0;
            self.max_write_len = 0;
            Ok(())
        }

        fn write_volume(
            &mut self,
            volume_index: usize,
            bytes: &[u8],
        ) -> Result<(), ArchiveWriteError> {
            let volume =
                self.volume_bytes
                    .get_mut(volume_index)
                    .ok_or(FormatError::WriterInvariant(
                        "tracking sink volume index is out of bounds",
                    ))?;
            *volume += bytes.len() as u64;
            self.max_write_len = self.max_write_len.max(bytes.len());
            Ok(())
        }

        fn write_bootstrap_sidecar(&mut self, bytes: &[u8]) -> Result<(), ArchiveWriteError> {
            self.bootstrap_sidecar_bytes += bytes.len() as u64;
            self.max_write_len = self.max_write_len.max(bytes.len());
            Ok(())
        }
    }

    fn deterministic_bytes(len: usize) -> Vec<u8> {
        let mut state = 0x4d41_4d45u32;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            out.push((state >> 24) as u8);
        }
        out
    }

    fn single_volume_metadata_test_options() -> WriterOptions {
        plan_writer_options(WriterOptions {
            block_size: MIN_BLOCK_SIZE,
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            index_root_fec_parity_shards: 0,
            ..WriterOptions::default()
        })
        .unwrap()
    }

    fn payload_len_for_encrypted_data_blocks(
        data_block_count: u32,
        options: WriterOptions,
    ) -> usize {
        assert!(data_block_count > 0);
        if data_block_count == 1 {
            return 1;
        }
        let block_size = options.block_size as usize;
        (data_block_count as usize - 1) * block_size - options.aead_algo.tag_len() + 1
    }

    fn assert_path_specific_member_group(group: &[u8]) {
        let mut cursor = 0usize;
        let mut saw_main = false;
        while cursor < group.len() {
            let header = &group[cursor..cursor + TAR_BLOCK_LEN];
            assert!(
                header.iter().any(|byte| *byte != 0),
                "writer emitted tar zero block inside member group"
            );
            let typeflag = header[156];
            assert_ne!(typeflag, b'g', "writer emitted global PAX metadata");
            assert!(
                !matches!(typeflag, b'V' | b'M' | b'N'),
                "writer emitted global GNU metadata"
            );
            assert!(
                matches!(typeflag, b'x' | b'0'),
                "writer emitted unexpected tar record type {typeflag:?}"
            );
            if typeflag == b'0' {
                saw_main = true;
            }
            let size = read_test_tar_octal(&header[124..136]);
            cursor += TAR_BLOCK_LEN + size + padding_to_512(size);
        }
        assert_eq!(cursor, group.len());
        assert!(saw_main);
    }

    fn read_test_tar_octal(field: &[u8]) -> usize {
        let mut value = 0usize;
        for byte in field {
            match *byte {
                0 | b' ' => break,
                b'0'..=b'7' => {
                    value = value * 8 + usize::from(*byte - b'0');
                }
                other => panic!("malformed test tar octal byte {other:?}"),
            }
        }
        value
    }

    fn test_file_row(idx: usize, path_hash: [u8; 8]) -> FileRow {
        let path = format!("file-{idx:05}.txt").into_bytes();
        FileRow {
            path_hash,
            path: path.clone(),
            member_index: idx,
            member: TarMember {
                path,
                entry_kind: SourceEntryKind::Regular,
                link_target: None,
                tar_member_group_start: idx as u64 * 512,
                tar_member_group_size: 512,
                file_data_size: 0,
                sparse_extents: None,
                mode: 0o644,
                mtime: ArchiveTimestamp::UNIX_EPOCH,
                portable_metadata: PortableFileMetadata::default(),
            },
        }
    }
}
