use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::{Cursor, Read};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::compression::compress_zstd_frame_with_jobs;
use crate::crypto::{KdfParams, MasterKey, Subkeys};
use crate::entry_metadata::{ArchiveTimestamp, RestoreClass, SparseExtent};
use crate::format::{
    AeadAlgo, ArchiveWriteError, BlockKind, FormatError, FORMAT_VERSION, READER_MAX_INDEX_ROOT_FEC_CLASS_SHARDS, VOLUME_FORMAT_REV_45, VOLUME_HEADER_LEN,
};
use crate::metadata::{normalize_lookup_file_path, DirectoryHintShardEntry, ShardEntry};
use crate::wire::{compute_key_wrap_table_digest, BlockRecord, KeyWrapTableV1, RecipientRecordV1, VolumeHeader};

pub mod envelope;
pub mod parallel;
pub mod plan;

#[cfg(test)]
mod tests;

pub use envelope::*;
pub(crate) use parallel::*;
pub(crate) use plan::*;

pub(crate) const DEFAULT_BLOCK_SIZE: u32 = 64 * 1024;
pub(crate) const DEFAULT_CHUNK_SIZE: u32 = 256 * 1024;
pub(crate) const DEFAULT_ENVELOPE_TARGET_SIZE: u32 = 1024 * 1024;
pub(crate) const DEFAULT_FEC_DATA_SHARDS: u16 = 224;
pub(crate) const DEFAULT_FEC_PARITY_SHARDS: u16 = 1;
pub(crate) const DEFAULT_INDEX_FEC_DATA_SHARDS: u16 = 16;
pub(crate) const DEFAULT_INDEX_FEC_PARITY_SHARDS: u16 = 1;
pub(crate) const MIN_INDEX_ROOT_FEC_DATA_SHARDS: u16 = 16;
pub(crate) const DEFAULT_INDEX_ROOT_FEC_DATA_SHARDS: u16 = MIN_INDEX_ROOT_FEC_DATA_SHARDS;
pub(crate) const DEFAULT_INDEX_ROOT_FEC_PARITY_SHARDS: u16 = 1;
pub(crate) const DEFAULT_STRIPE_WIDTH: u32 = 8;
pub(crate) const DEFAULT_VOLUME_LOSS_TOLERANCE: u8 = 1;
pub(crate) const DEFAULT_BIT_ROT_BUFFER_PCT: u8 = 5;
pub(crate) const DEFAULT_FILES_PER_INDEX_SHARD: usize = 10_000;
pub(crate) const DIRECTORY_HINT_REQUIRED_FILE_COUNT: usize = 100_000;
pub(crate) const MAX_FILES_PER_INDEX_SHARD: usize = 1_000_000;
pub(crate) const MAX_HASH_PREFIX_RUN_FILES: usize = 50_000;
pub(crate) const DEFAULT_DIRECTORY_HINT_ENTRIES_PER_SHARD: usize = 10_000;
pub(crate) const CMRA_SHARD_SIZE: usize = 512;

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

    pub fn resolve(&self) -> Result<Option<Vec<RecipientRecordV1>>, FormatError> {
        match self {
            Self::None => Ok(None),
            Self::Fixed(records) => Ok(Some(records.clone())),
            Self::Callback(callback) => Ok(Some(callback()?)),
        }
    }
}

pub(crate) fn default_jobs() -> usize {
    std::thread::available_parallelism().map(|jobs| jobs.get()).unwrap_or(1)
}

pub(crate) fn volume_format_revision_for_options(_options: &WriterOptions, _kdf_params: &KdfParams) -> u16 {
    // Writer is intentionally canonicalized to v45-only output.
    VOLUME_FORMAT_REV_45
}

pub(crate) fn resolve_key_wrap_artifacts(
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
                return Err(FormatError::InvalidKdfParams("recipient-wrap table version must be 1"));
            }
            let Some(records) = key_wrap_records
                .ok_or(FormatError::WriterUnsupported("RecipientWrap requires key-wrap records"))?
                .resolve()?
            else {
                return Err(FormatError::WriterUnsupported("RecipientWrap requires key-wrap records"));
            };
            if records.is_empty() {
                return Err(FormatError::WriterUnsupported("RecipientWrap requires at least one recipient record"));
            }
            let mut recipient_records = Vec::with_capacity(records.len());
            for record in records {
                let mut prepared = record.clone();
                let record_length = u32_len(prepared.to_bytes()?.len(), "RecipientWrap record")?;
                prepared = prepared.with_record_length(record_length);
                recipient_records.push(prepared);
            }
            let declared_record_count = u32_len(recipient_records.len(), "KeyWrapTableV1 recipient_record_count")?;
            if *key_wrap_table_record_count != 0 && *key_wrap_table_record_count != declared_record_count {
                return Err(FormatError::InvalidKdfParams("recipient-wrap key_wrap_table_record_count mismatch"));
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
            let computed_key_wrap_table_length = u32_len(key_wrap_table.len(), "KeyWrapTableV1 table_length")?;
            if *key_wrap_table_length != 0 && computed_key_wrap_table_length != *key_wrap_table_length {
                return Err(FormatError::InvalidKdfParams("recipient-wrap key_wrap_table_length mismatch"));
            }
            let key_wrap_table_digest = compute_key_wrap_table_digest(computed_key_wrap_table_length, &key_wrap_table);
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

pub(crate) fn recipient_wrap_kdf_params_for_record_count(record_count: usize) -> Result<KdfParams, FormatError> {
    Ok(KdfParams::RecipientWrap {
        key_wrap_table_length: 0,
        key_wrap_table_record_count: u32_len(record_count, "KeyWrapTableV1 recipient_record_count")?,
        key_wrap_table_version: 1,
        key_wrap_table_digest: [0u8; 32],
    })
}

pub(crate) fn stabilized_key_wrap_record_source(
    kdf_params: &KdfParams,
    key_wrap_records: Option<&KeyWrapRecordSource>,
) -> Result<Option<KeyWrapRecordSource>, FormatError> {
    if !matches!(kdf_params, KdfParams::RecipientWrap { .. }) {
        return Ok(None);
    }
    let Some(records) = key_wrap_records
        .ok_or(FormatError::WriterUnsupported("RecipientWrap requires key-wrap records"))?
        .resolve()?
    else {
        return Err(FormatError::WriterUnsupported("RecipientWrap requires key-wrap records"));
    };
    Ok(Some(KeyWrapRecordSource::fixed(records)))
}

pub(crate) fn should_emit_directory_hints(file_count: usize) -> bool {
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

pub type RootAuthAuthenticator<'a> = dyn FnMut(&RootAuthSigningRequest) -> Result<Vec<u8>, FormatError> + 'a;

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
    pub(crate) streamed_payload: Option<StreamedAuxiliaryPayload>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StreamedAuxiliaryPayload {
    pub stored_size: u64,
    pub sha256: [u8; 32],
    pub sparse_extents: Option<Vec<SparseExtent>>,
}

impl NativeAuxiliaryMetadata {
    pub fn new(kind: impl Into<String>, profile: impl Into<String>, restore_class: RestoreClass, payload: Vec<u8>) -> Self {
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
    pub fn new_streamed(kind: impl Into<String>, profile: impl Into<String>, restore_class: RestoreClass, stored_size: u64, sha256: [u8; 32]) -> Self {
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
        self.streamed_payload.as_ref().and_then(|payload| payload.sparse_extents.as_deref())
    }

    pub fn stored_payload_size(&self) -> u64 {
        self.streamed_payload.as_ref().map_or(self.payload.len() as u64, |payload| payload.stored_size)
    }

    pub fn sha256(&self) -> [u8; 32] {
        self.streamed_payload
            .as_ref()
            .map_or_else(|| Sha256::digest(&self.payload).into(), |payload| payload.sha256)
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
        let record = metadata
            .native
            .auxiliary_records
            .get(ordinal)
            .ok_or(FormatError::WriterInvariant("auxiliary source ordinal is missing"))?;
        if record.is_streamed() {
            return Err(FormatError::WriterUnsupported("streamed auxiliary source did not implement open_auxiliary").into());
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
    pub fn new(sink: &'a mut dyn ArchiveWriteProgressSink) -> Self {
        Self {
            sink,
            active_phase: None,
            phase_reported_by_path: BTreeMap::new(),
        }
    }

    pub fn start_phase(&mut self, phase: ArchiveWritePhase) {
        self.active_phase = Some(phase);
        self.phase_reported_by_path.clear();
        self.sink.phase_started(phase);
    }

    pub fn record(&mut self, archive_path: &str, bytes: u64, file_data_size: u64) {
        if bytes == 0 || file_data_size == 0 {
            return;
        }
        if let Some(phase) = self.active_phase {
            let phase_reported = self.phase_reported_by_path.entry(archive_path.to_owned()).or_default();
            let capped_next = phase_reported.saturating_add(bytes).min(file_data_size);
            let delta = capped_next.saturating_sub(*phase_reported);
            if delta > 0 {
                *phase_reported = capped_next;
                self.sink.source_bytes_read(phase, archive_path, delta);
            }
        }
    }
}

pub(crate) struct ProgressRegularFileSource<'a, S> {
    pub inner: &'a S,
    pub source_bytes: u64,
    pub state: Rc<RefCell<SourceProgressState<'a>>>,
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

pub(crate) struct SourceProgressReader<'a> {
    pub inner: Box<dyn Read + 'a>,
    pub archive_path: String,
    pub source_bytes: u64,
    pub state: Rc<RefCell<SourceProgressState<'a>>>,
}

impl Read for SourceProgressReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let bytes = self.inner.read(buf)?;
        self.state.borrow_mut().record(&self.archive_path, bytes as u64, self.source_bytes);
        Ok(bytes)
    }
}

pub(crate) type SourceProgressHandle<'a> = Rc<RefCell<SourceProgressState<'a>>>;

pub(crate) fn progress_sources<'a, S: RegularFileSource>(
    files: &'a [S],
    sink: &'a mut dyn ArchiveWriteProgressSink,
) -> (Vec<ProgressRegularFileSource<'a, S>>, SourceProgressHandle<'a>) {
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
                .fold(inner.file_data_size(), |total, record| total.saturating_add(record.stored_payload_size()));
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
    pub fn add_assign(&mut self, other: Self) {
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
            .ok_or(FormatError::WriterInvariant("volume sink index is out of bounds"))?;
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
pub(crate) struct TarMember {
    pub path: Vec<u8>,
    pub entry_kind: SourceEntryKind,
    pub link_target: Option<Vec<u8>>,
    pub tar_member_group_start: u64,
    pub tar_member_group_size: u64,
    pub file_data_size: u64,
    pub sparse_extents: Option<Vec<SparseExtent>>,
    pub mode: u32,
    pub mtime: ArchiveTimestamp,
    pub portable_metadata: PortableFileMetadata,
}

#[derive(Debug, Clone)]
pub(crate) struct PayloadFrame {
    pub frame_index: u64,
    pub envelope_index: u64,
    pub member_index: usize,
    pub offset_in_envelope: u32,
    pub compressed_size: u32,
    pub decompressed_size: u32,
    pub flags: u32,
    pub tar_stream_offset: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct FileRow {
    pub path_hash: [u8; 8],
    pub path: Vec<u8>,
    pub member_index: usize,
    pub member: TarMember,
}

#[derive(Debug, Clone)]
pub(crate) struct PlannedIndexShard {
    pub shard_index: u64,
    pub plaintext: Vec<u8>,
    pub file_count: u32,
    pub first_path_hash: [u8; 8],
    pub last_path_hash: [u8; 8],
}

#[derive(Debug, Clone)]
pub(crate) struct PlannedDirectoryHintShard {
    pub hint_shard_index: u64,
    pub plaintext: Vec<u8>,
    pub entry_count: u64,
    pub first_dir_hash: [u8; 8],
    pub last_dir_hash: [u8; 8],
}

#[derive(Debug, Clone)]
#[cfg(test)]
pub(crate) struct PayloadEnvelope {
    pub envelope_index: u64,
    pub plaintext: Vec<u8>,
}

#[derive(Debug, Clone)]
pub(crate) struct PayloadObject {
    pub envelope_index: u64,
    pub plaintext_size: u32,
    pub object: ObjectExtent,
}

#[derive(Debug, Clone)]
pub(crate) struct EncryptedObject {
    pub first_block_index: u64,
    pub data_block_count: u32,
    pub parity_block_count: u32,
    pub encrypted_size: u32,
    pub records: Vec<BlockRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ObjectExtent {
    pub first_block_index: u64,
    pub data_block_count: u32,
    pub parity_block_count: u32,
    pub encrypted_size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PlannedEncryptedObject {
    pub data_block_count: u32,
    pub parity_block_count: u32,
    pub encrypted_size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MetadataObjectKind {
    IndexRoot,
    Dictionary,
}

impl MetadataObjectKind {
    pub fn too_large_error(self) -> FormatError {
        match self {
            Self::IndexRoot => FormatError::WriterUnsupported("IndexRoot too large"),
            Self::Dictionary => FormatError::WriterUnsupported("dictionary object too large"),
        }
    }
}

impl ObjectExtent {
    pub fn new(first_block_index: u64, plan: PlannedEncryptedObject) -> Result<Self, FormatError> {
        Ok(Self {
            first_block_index,
            data_block_count: plan.data_block_count,
            parity_block_count: plan.parity_block_count,
            encrypted_size: plan.encrypted_size,
        })
    }

    pub fn next_block_index(self) -> Result<u64, FormatError> {
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
pub(crate) struct PlannedDirectoryHintObject {
    pub hint_shard_index: u64,
    pub compressed: Vec<u8>,
    pub extent: ObjectExtent,
}

pub(crate) struct WriterPlan {
    pub options: WriterOptions,
    pub archive_uuid: [u8; 16],
    pub session_id: [u8; 16],
    pub crypto_header: Vec<u8>,
    pub tar_members: Vec<TarMember>,
    pub frames: Vec<PayloadFrame>,
    pub payload_objects: Vec<PayloadObject>,
    pub index_root_plaintext: Vec<u8>,
    pub compressed_index_root: Vec<u8>,
    pub index_root_extent: ObjectExtent,
    pub index_shard_objects: Vec<PlannedIndexShardObject>,
    pub shard_entries: Vec<ShardEntry>,
    pub volume_format_rev: u16,
    pub compressed_dictionary: Option<Vec<u8>>,
    pub dictionary_extent: Option<(ObjectExtent, u32)>,
    pub directory_hint_objects: Vec<PlannedDirectoryHintObject>,
    pub directory_hint_entries: Vec<DirectoryHintShardEntry>,
    pub root_auth_footer_length: Option<u32>,
    pub key_wrap_table: Option<Vec<u8>>,
    pub block_records_offset: u64,
    pub total_block_count: u64,
}

pub(crate) struct PlannedIndexShardObject {
    pub shard_index: u64,
    pub compressed: Vec<u8>,
    pub extent: ObjectExtent,
}

pub(crate) struct PayloadPlanning {
    pub tar_members: Vec<TarMember>,
    pub frames: Vec<PayloadFrame>,
    pub payload_objects: Vec<PayloadObject>,
    pub payload_block_count: u64,
    pub tar_total_size: u64,
    pub content_sha256: [u8; 32],
}

pub(crate) struct PayloadEnvelopeBuilder {
    pub envelope_index: u64,
    pub plaintext: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct PayloadFrameMetadataInput {
    pub frame_index: u64,
    pub envelope_index: u64,
    pub member_index: usize,
    pub offset_in_envelope: u32,
    pub compressed_size: usize,
    pub decompressed_size: usize,
    pub member_start: u64,
    pub member_offset: u64,
    pub member_group_size: u64,
}

pub(crate) fn payload_envelope_needs_flush(envelope: &PayloadEnvelopeBuilder, frame_len: usize, options: WriterOptions) -> Result<bool, FormatError> {
    let next_len = checked_usize_add(envelope.plaintext.len(), frame_len, "payload")?;
    Ok(!envelope.plaintext.is_empty() && (next_len > options.envelope_target_size as usize || !payload_object_can_fit(next_len, options)?))
}

pub(crate) fn payload_frame_metadata(input: PayloadFrameMetadataInput) -> Result<PayloadFrame, FormatError> {
    let mut flags = 0u32;
    if input.member_offset == 0 {
        flags |= 0x0000_0001;
    }
    if checked_u64_add(input.member_offset, input.decompressed_size as u64, "payload chunk")? == input.member_group_size {
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
        tar_stream_offset: checked_u64_add(input.member_start, input.member_offset, "PayloadFrame.tar_stream_offset")?,
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

pub(crate) struct WriterEmissionState {
    pub volume_headers: Vec<[u8; VOLUME_HEADER_LEN]>,
    pub bytes_written: Vec<u64>,
    pub record_counts: Vec<u64>,
    pub volume_format_rev: u16,
    pub data_leaf_hashes: Option<Vec<(u64, [u8; 32])>>,
    pub next_block_index: u64,
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

pub fn write_archive(files: &[RegularFile<'_>], master_key: &MasterKey, options: WriterOptions) -> Result<WrittenArchive, FormatError> {
    write_archive_inner(files, master_key, options, None, &KdfParams::Raw, None, None, None)
}

pub fn write_archive_unencrypted(files: &[RegularFile<'_>], mut options: WriterOptions) -> Result<WrittenArchive, FormatError> {
    options.aead_algo = AeadAlgo::None;
    let placeholder = MasterKey::from_raw_key(&[0; 32])?;
    write_archive_inner(files, &placeholder, options, None, &KdfParams::None, None, None, None)
}

pub fn write_archive_with_kdf(
    files: &[RegularFile<'_>],
    master_key: &MasterKey,
    options: WriterOptions,
    kdf_params: &KdfParams,
) -> Result<WrittenArchive, FormatError> {
    write_archive_inner(files, master_key, options, None, kdf_params, None, None, None)
}

pub fn write_archive_with_recipient_wrap_records(
    files: &[RegularFile<'_>],
    master_key: &MasterKey,
    options: WriterOptions,
    records: Vec<RecipientRecordV1>,
) -> Result<WrittenArchive, FormatError> {
    let kdf_params = recipient_wrap_kdf_params_for_record_count(records.len())?;
    let key_wrap_records = KeyWrapRecordSource::fixed(records);
    write_archive_inner(files, master_key, options, None, &kdf_params, None, None, Some(&key_wrap_records))
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
    let kdf_params = if options.aead_algo.is_encrypted() { KdfParams::Raw } else { KdfParams::None };
    write_archive_inner(files, master_key, options, None, &kdf_params, Some(root_auth), Some(&mut authenticator), None)
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
    write_archive_inner(files, master_key, options, None, kdf_params, Some(root_auth), Some(&mut authenticator), None)
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
        return Err(FormatError::WriterUnsupported("dictionary archives require a non-empty dictionary"));
    }
    if files.is_empty() {
        return Err(FormatError::WriterUnsupported("dictionary archives require at least one file"));
    }
    if dictionary.len() > u32::MAX as usize {
        return Err(FormatError::WriterUnsupported("dictionary decompressed size exceeds u32"));
    }
    write_archive_inner(files, master_key, options, Some(dictionary), &KdfParams::Raw, None, None, None)
}

pub fn write_archive_with_dictionary_and_kdf(
    files: &[RegularFile<'_>],
    master_key: &MasterKey,
    options: WriterOptions,
    dictionary: &[u8],
    kdf_params: &KdfParams,
) -> Result<WrittenArchive, FormatError> {
    if dictionary.is_empty() {
        return Err(FormatError::WriterUnsupported("dictionary archives require a non-empty dictionary"));
    }
    if files.is_empty() {
        return Err(FormatError::WriterUnsupported("dictionary archives require at least one file"));
    }
    if dictionary.len() > u32::MAX as usize {
        return Err(FormatError::WriterUnsupported("dictionary decompressed size exceeds u32"));
    }
    write_archive_inner(files, master_key, options, Some(dictionary), kdf_params, None, None, None)
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
    write_archive_stream_inner(files, master_key, options, dictionary, kdf_params, root_auth, authenticator, None, sink, None)
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
    write_single_pass_archive_to_sink(master_key, options, kdf_params, root_auth, authenticator, None, sink, None, |writer| {
        for file in files {
            writer.write_regular_member_from_source(file)?;
        }
        Ok(())
    })
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
    write_ordered_parallel_archive_to_sink(files, master_key, options, kdf_params, root_auth, authenticator, None, sink, None)
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
pub fn write_archive_sources_to_sink_ordered_parallel_with_recipient_wrap_records_and_progress<S, O>(
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
pub(crate) fn write_archive_inner(
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
        bytes: sink.volumes.first().cloned().ok_or(FormatError::WriterInvariant("no volumes emitted"))?,
        volumes: sink.volumes,
        bootstrap_sidecar: sink.bootstrap_sidecar,
        archive_uuid: summary.archive_uuid,
        session_id: summary.session_id,
        timings: summary.timings,
    })
}

pub(crate) fn format_error_from_archive_write_error(error: ArchiveWriteError) -> FormatError {
    match error {
        ArchiveWriteError::Format(error) => error,
        ArchiveWriteError::Io(_) => FormatError::WriterInvariant("in-memory archive writer returned I/O"),
    }
}

pub(crate) fn writer_subkeys(master_key: &MasterKey, aead_algo: AeadAlgo, archive_uuid: &[u8; 16], session_id: &[u8; 16]) -> Result<Subkeys, FormatError> {
    if aead_algo.is_encrypted() {
        Subkeys::derive(master_key, archive_uuid, session_id)
    } else {
        Ok(Subkeys::unencrypted_placeholder())
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn write_archive_stream_inner<S, O>(
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
        requested_options.stripe_width = requested_options.stripe_width.max(requested_options.volume_loss_tolerance as u32 + 1);
    }
    let archive_uuid = requested_options.archive_uuid.unwrap_or_else(|| *Uuid::new_v4().as_bytes());
    let session_id = requested_options.session_id.unwrap_or_else(|| *Uuid::new_v4().as_bytes());
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
        let mut summary = emit_writer_plan(files, master_key, dictionary, root_auth, authenticator.take(), plan, sink, progress)?;
        summary.timings.add_assign(accumulated_timings);
        summary.timings.total = total_started.elapsed();
        return Ok(summary);
    }
}

pub(crate) fn validate_dictionary_inputs(files_are_empty: bool, dictionary: Option<&[u8]>) -> Result<(), FormatError> {
    if let Some(dictionary) = dictionary {
        if dictionary.is_empty() {
            return Err(FormatError::WriterUnsupported("dictionary archives require a non-empty dictionary"));
        }
        if files_are_empty {
            return Err(FormatError::WriterUnsupported("dictionary archives require at least one file"));
        }
        if dictionary.len() > u32::MAX as usize {
            return Err(FormatError::WriterUnsupported("dictionary decompressed size exceeds u32"));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_single_pass_writer_options(options: WriterOptions) -> Result<(), FormatError> {
    if options.volume_loss_tolerance != 0 {
        return Err(FormatError::WriterUnsupported("streaming create cannot tolerate volume loss"));
    }
    if options.target_volume_size.is_some() {
        return Err(FormatError::WriterUnsupported("streaming create does not support target volume sizing"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn begin_writer_emission_state<O: ArchiveWriteSink>(
    sink: &mut O,
    options: WriterOptions,
    crypto_header: &[u8],
    key_wrap_table: Option<&[u8]>,
    archive_uuid: [u8; 16],
    session_id: [u8; 16],
    volume_format_rev: u16,
    collect_data_leaf_hashes: bool,
) -> Result<WriterEmissionState, ArchiveWriteError> {
    let volume_count = usize::try_from(options.stripe_width).map_err(|_| FormatError::WriterUnsupported("stripe_width"))?;
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
        let volume_index_u32 = u32::try_from(volume_index).map_err(|_| FormatError::WriterUnsupported("volume_index"))?;
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
        let mut bytes_written = checked_u64_add(VOLUME_HEADER_LEN as u64, crypto_header.len() as u64, "volume header")?;
        if let Some(key_wrap_table) = key_wrap_table {
            sink.write_volume(volume_index, key_wrap_table)?;
            bytes_written = checked_u64_add(bytes_written, key_wrap_table.len() as u64, "KeyWrapTableV1")?;
        }
        state.bytes_written[volume_index] = bytes_written;
        state.volume_headers.push(volume_header_bytes);
    }

    Ok(state)
}

pub(crate) fn plan_single_pass_writer_options(options: WriterOptions) -> Result<WriterOptions, FormatError> {
    let mut options = plan_writer_options(options)?;
    options.index_root_fec_data_shards = max_single_pass_index_root_data_shards(options)?;
    plan_writer_options(options)
}

pub(crate) fn max_single_pass_index_root_data_shards(options: WriterOptions) -> Result<u16, FormatError> {
    let block_size_limit = (u32::MAX as u64 / options.block_size as u64).min(u16::MAX as u64);
    let mut low = MIN_INDEX_ROOT_FEC_DATA_SHARDS as u64;
    let mut high = block_size_limit;
    let mut best = low;
    while low <= high {
        let mid = low + (high - low) / 2;
        match compute_parity(mid, options) {
            Ok(parity) if mid + u64::from(parity) <= READER_MAX_INDEX_ROOT_FEC_CLASS_SHARDS as u64 => {
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
    pub fn write_regular_member_from_source<S: RegularFileSource + ?Sized>(&mut self, source: &S) -> Result<(), ArchiveWriteError> {
        let member = StreamingRegularMember {
            archive_path: normalize_lookup_file_path(source.archive_path(), self.options.max_path_length)?,
            entry_kind: source.entry_kind(),
            link_target: source.link_target().map(<[u8]>::to_vec),
            file_data_size: source.file_data_size(),
            sparse_extents: source.sparse_extents().map(<[SparseExtent]>::to_vec),
            mode: source.mode(),
            mtime: source.mtime(),
            portable_metadata: source.portable_metadata(),
        };
        if member.entry_kind != SourceEntryKind::Regular && member.file_data_size != 0 {
            return Err(FormatError::WriterInvariant("non-regular source has non-zero file data size").into());
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
        let mut reader = StreamingMemberReader::from_source(source, &member.portable_metadata, layout, source_payload_size)?;
        self.write_prebuilt_member(member, &mut reader, member_group_size)
    }

    pub fn write_prebuilt_member(
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
            reader.read_exact(&mut chunk).map_err(ArchiveWriteError::Io)?;
            let mut chunk_len = chunk.len();
            let frame = loop {
                let candidate = &chunk[..chunk_len];
                let frame = compress_zstd_frame_with_jobs(candidate, self.options.zstd_level, self.options.jobs)?;
                if payload_object_can_fit(frame.len(), self.options)? {
                    break frame;
                }
                if chunk_len == 1 {
                    return Err(FormatError::WriterUnsupported("single-byte payload frame exceeds envelope object limits").into());
                }
                chunk_len = (chunk_len / 2).max(1);
            };
            if chunk_len < chunk.len() {
                reader.push_back(chunk[chunk_len..].to_vec());
            }
            let chunk = &chunk[..chunk_len];
            self.hasher.update(chunk);
            self.append_payload_frame(&frame, chunk_len, member_index, member_start, member_offset, member_group_size)?;
            member_offset = checked_u64_add(member_offset, chunk_len as u64, "payload chunk")?;
            self.tar_total_size = checked_u64_add(self.tar_total_size, chunk_len as u64, "tar stream")?;
        }
        Ok(())
    }

    pub fn append_payload_frame(
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
        if self.envelope.plaintext.is_empty() && !payload_object_can_fit(frame.len(), self.options)? {
            return Err(FormatError::WriterUnsupported("payload frame exceeds envelope object limits").into());
        }
        let offset = u32_len(self.envelope.plaintext.len(), "FrameEntry.offset_in_envelope")?;
        self.envelope.plaintext.extend_from_slice(frame);
        self.frames.push(payload_frame_metadata(PayloadFrameMetadataInput {
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
        self.next_frame_index = checked_u64_add(self.next_frame_index, 1, "PayloadFrame.frame_index")?;
        Ok(())
    }

    pub fn flush_payload_envelope(&mut self) -> Result<(), ArchiveWriteError> {
        if self.envelope.plaintext.is_empty() {
            return Ok(());
        }
        let plaintext_size = u32_len(self.envelope.plaintext.len(), "EnvelopeEntry.plaintext_size")?;
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
        self.payload_block_count = checked_u64_add(self.payload_block_count, extent.data_block_count as u64, "payload")?;
        self.payload_objects.push(PayloadObject {
            envelope_index: self.envelope.envelope_index,
            plaintext_size,
            object: extent,
        });
        self.envelope.envelope_index = checked_u64_add(self.envelope.envelope_index, 1, "EnvelopeEntry")?;
        self.envelope.plaintext.clear();
        Ok(())
    }

    pub fn finish(
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
            return Err(FormatError::WriterUnsupported("streaming tar stdin metadata exceeded the predeclared header class").into());
        }
        emit_writer_plan_suffix(&self.subkeys, root_auth, authenticator, plan, self.sink, self.emission_state)
    }
}
