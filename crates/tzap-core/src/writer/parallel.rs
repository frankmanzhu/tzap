use std::io::Read;
use std::time::Instant;

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::compression::compress_zstd_frame_with_jobs;
use crate::crypto::{KdfParams, MasterKey, Subkeys};
use crate::entry_metadata::SparseExtent;
use crate::format::{ArchiveWriteError, BlockKind, FormatError};
use crate::metadata::{normalize_lookup_file_path, validate_file_path_bytes};
use crate::wire::BlockRecord;

use super::*;

pub(crate) struct OrderedFrameJob {
    pub frame_index: u64,
    pub member_index: usize,
    pub member_start: u64,
    pub member_offset: u64,
    pub member_group_size: u64,
    pub plaintext: Vec<u8>,
}

pub(crate) struct OrderedFrameResult {
    pub frame_index: u64,
    pub member_index: usize,
    pub member_start: u64,
    pub member_offset: u64,
    pub member_group_size: u64,
    pub decompressed_size: usize,
    pub frame: Vec<u8>,
}

pub(crate) struct OrderedEnvelopeJob {
    pub envelope_index: u64,
    pub plaintext: Vec<u8>,
    pub extent: ObjectExtent,
    pub collect_data_leaf_hashes: bool,
}

pub(crate) struct OrderedEnvelopeResult {
    pub envelope_index: u64,
    pub records: OrderedEnvelopeRecords,
}

pub(crate) enum OrderedEnvelopeRecords {
    Materialized(Vec<BlockRecord>),
    Serialized(Vec<SerializedBlockRecord>),
}

pub(crate) struct SerializedBlockRecord {
    pub block_index: u64,
    pub bytes: Vec<u8>,
}

pub(crate) struct OrderedParallelState {
    pub tar_members: Vec<TarMember>,
    pub frames: Vec<PayloadFrame>,
    pub payload_objects: Vec<PayloadObject>,
    pub payload_block_count: u64,
    pub tar_total_size: u64,
    pub hasher: Sha256,
    pub next_frame_job_index: u64,
    pub next_frame_result_index: u64,
    pub next_frame_metadata_index: u64,
    pub frame_buffer: std::collections::BTreeMap<u64, OrderedFrameResult>,
    pub envelope: PayloadEnvelopeBuilder,
    pub next_payload_block_index: u64,
    pub next_envelope_result_index: u64,
    pub envelope_buffer: std::collections::BTreeMap<u64, OrderedEnvelopeResult>,
}

impl OrderedParallelState {
    pub fn new(file_count: usize) -> Self {
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
            envelope: PayloadEnvelopeBuilder { envelope_index: 0, plaintext: Vec::new() },
            next_payload_block_index: 0,
            next_envelope_result_index: 0,
            envelope_buffer: std::collections::BTreeMap::new(),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn write_ordered_parallel_archive_to_sink<S, O>(
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
    write_ordered_parallel_stream_archive_to_sink(master_key, options, kdf_params, root_auth, authenticator, key_wrap_records, sink, progress, |writer| {
        writer.reserve_member_capacity(files.len());
        for file in files {
            writer.write_regular_member_from_source(file)?;
        }
        Ok(())
    })
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
    let archive_uuid = options.archive_uuid.unwrap_or_else(|| *Uuid::new_v4().as_bytes());
    let session_id = options.session_id.unwrap_or_else(|| *Uuid::new_v4().as_bytes());
    let stabilized_key_wrap_records = stabilized_key_wrap_record_source(kdf_params, key_wrap_records)?;
    let key_wrap_records = stabilized_key_wrap_records.as_ref().or(key_wrap_records);
    let (resolved_kdf_params, key_wrap_table) = resolve_key_wrap_artifacts(kdf_params, &archive_uuid, &session_id, key_wrap_records)?;
    let volume_format_rev = volume_format_revision_for_options(&options, &resolved_kdf_params);
    let subkeys = writer_subkeys(master_key, options.aead_algo, &archive_uuid, &session_id)?;
    let crypto_header = build_crypto_header(options, volume_format_rev, false, &subkeys, &archive_uuid, &session_id, &resolved_kdf_params)?;
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
        let (frame_job_tx, frame_job_rx) = std::sync::mpsc::sync_channel::<OrderedFrameJob>(frame_job_buffer);
        let (frame_result_tx, frame_result_rx) = std::sync::mpsc::channel::<Result<OrderedFrameResult, ArchiveWriteError>>();
        let frame_job_rx = std::sync::Arc::new(std::sync::Mutex::new(frame_job_rx));

        let (envelope_job_tx, envelope_job_rx) = std::sync::mpsc::sync_channel::<OrderedEnvelopeJob>(envelope_job_buffer);
        let (envelope_result_tx, envelope_result_rx) = std::sync::mpsc::channel::<Result<OrderedEnvelopeResult, ArchiveWriteError>>();
        let envelope_job_rx = std::sync::Arc::new(std::sync::Mutex::new(envelope_job_rx));

        let frame_handles = (0..worker_count)
            .map(|_| {
                let frame_job_rx = std::sync::Arc::clone(&frame_job_rx);
                let frame_result_tx = frame_result_tx.clone();
                scope.spawn(move || loop {
                    let job = {
                        let receiver = frame_job_rx.lock().expect("ordered frame receiver poisoned");
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
                        let receiver = envelope_job_rx.lock().expect("ordered envelope receiver poisoned");
                        receiver.recv()
                    };
                    let Ok(job) = job else {
                        break;
                    };
                    let is_error = match build_ordered_envelope_result(job, &subkeys, options, archive_uuid, session_id) {
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
            receive_ordered_frame_result(&frame_result_rx, &envelope_job_tx, &envelope_result_rx, &mut ordered, sink, options, &mut emission_state, true)?;
        }
        flush_ordered_parallel_envelope(&envelope_job_tx, &envelope_result_rx, &mut ordered, sink, options, &mut emission_state)?;
        drop(envelope_job_tx);
        while ordered.next_envelope_result_index < ordered.envelope.envelope_index {
            receive_ordered_envelope_result(&envelope_result_rx, &mut ordered, sink, options, &mut emission_state, true)?;
        }

        for handle in frame_handles {
            handle.join().map_err(|_| FormatError::WriterInvariant("ordered frame worker panicked"))?;
        }
        for handle in envelope_handles {
            handle.join().map_err(|_| FormatError::WriterInvariant("ordered envelope worker panicked"))?;
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
        return Err(FormatError::WriterUnsupported("ordered parallel metadata exceeded the predeclared header class").into());
    }
    let mut summary = emit_writer_plan_suffix(&subkeys, root_auth, authenticator, plan, sink, emission_state)?;
    summary.timings.emit_payload += emit_payload;
    summary.timings.total = total_started.elapsed();
    Ok(summary)
}

pub(crate) struct OrderedParallelArchiveWriter<'a, O: ArchiveWriteSink> {
    frame_job_tx: &'a std::sync::mpsc::SyncSender<OrderedFrameJob>,
    frame_result_rx: &'a std::sync::mpsc::Receiver<Result<OrderedFrameResult, ArchiveWriteError>>,
    envelope_job_tx: &'a std::sync::mpsc::SyncSender<OrderedEnvelopeJob>,
    envelope_result_rx: &'a std::sync::mpsc::Receiver<Result<OrderedEnvelopeResult, ArchiveWriteError>>,
    ordered: &'a mut OrderedParallelState,
    sink: &'a mut O,
    options: WriterOptions,
    emission_state: &'a mut WriterEmissionState,
}

impl<O: ArchiveWriteSink> OrderedParallelArchiveWriter<'_, O> {
    pub fn reserve_member_capacity(&mut self, additional: usize) {
        self.ordered.tar_members.reserve(additional);
    }

    pub(crate) fn write_regular_member_from_reader(&mut self, member: StreamingRegularMember, payload: &mut dyn Read) -> Result<(), ArchiveWriteError> {
        let path = &member.archive_path;
        validate_file_path_bytes(path, self.options.max_path_length)?;
        if member.entry_kind != SourceEntryKind::Regular && member.file_data_size != 0 {
            return Err(FormatError::WriterInvariant("non-regular source has non-zero file data size").into());
        }
        let source_payload_size =
            member.sparse_extents.as_deref().map(|extents| sparse_extent_bytes(extents, member.file_data_size)).transpose()?.unwrap_or(member.file_data_size);
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
        let member_group_size =
            checked_u64_add(prefix.len() as u64, checked_u64_add(source_payload_size, padding_to_512_u64(source_payload_size), "tar member")?, "tar member")?;
        let mut reader = StreamingMemberReader::new(Box::new(payload), prefix, source_payload_size);
        self.write_prebuilt_member(member, &mut reader, member_group_size)
    }

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
        let source_payload_size =
            member.sparse_extents.as_deref().map(|extents| sparse_extent_bytes(extents, member.file_data_size)).transpose()?.unwrap_or(member.file_data_size);
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
            reader.read_exact(&mut plaintext).map_err(ArchiveWriteError::Io)?;
            self.ordered.hasher.update(&plaintext);
            let frame_index = self.ordered.next_frame_job_index;
            self.ordered.next_frame_job_index = checked_u64_add(self.ordered.next_frame_job_index, 1, "PayloadFrame.frame_index")?;
            send_ordered_frame_job(
                OrderedFrameJob { frame_index, member_index, member_start, member_offset, member_group_size, plaintext },
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
            self.ordered.tar_total_size = checked_u64_add(self.ordered.tar_total_size, read_len, "tar stream")?;
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn send_ordered_frame_job<O: ArchiveWriteSink>(
    mut job: OrderedFrameJob,
    frame_job_tx: &std::sync::mpsc::SyncSender<OrderedFrameJob>,
    frame_result_rx: &std::sync::mpsc::Receiver<Result<OrderedFrameResult, ArchiveWriteError>>,
    envelope_job_tx: &std::sync::mpsc::SyncSender<OrderedEnvelopeJob>,
    envelope_result_rx: &std::sync::mpsc::Receiver<Result<OrderedEnvelopeResult, ArchiveWriteError>>,
    ordered: &mut OrderedParallelState,
    sink: &mut O,
    options: WriterOptions,
    emission_state: &mut WriterEmissionState,
) -> Result<(), ArchiveWriteError> {
    loop {
        match frame_job_tx.try_send(job) {
            Ok(()) => {
                drain_ordered_frame_results(frame_result_rx, envelope_job_tx, envelope_result_rx, ordered, sink, options, emission_state)?;
                return Ok(());
            }
            Err(std::sync::mpsc::TrySendError::Full(returned)) => {
                job = returned;
                receive_ordered_frame_result(frame_result_rx, envelope_job_tx, envelope_result_rx, ordered, sink, options, emission_state, true)?;
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                return Err(FormatError::WriterInvariant("ordered frame worker stopped").into());
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn drain_ordered_frame_results<O: ArchiveWriteSink>(
    frame_result_rx: &std::sync::mpsc::Receiver<Result<OrderedFrameResult, ArchiveWriteError>>,
    envelope_job_tx: &std::sync::mpsc::SyncSender<OrderedEnvelopeJob>,
    envelope_result_rx: &std::sync::mpsc::Receiver<Result<OrderedEnvelopeResult, ArchiveWriteError>>,
    ordered: &mut OrderedParallelState,
    sink: &mut O,
    options: WriterOptions,
    emission_state: &mut WriterEmissionState,
) -> Result<(), ArchiveWriteError> {
    while receive_ordered_frame_result(frame_result_rx, envelope_job_tx, envelope_result_rx, ordered, sink, options, emission_state, false)? {}
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn receive_ordered_frame_result<O: ArchiveWriteSink>(
    frame_result_rx: &std::sync::mpsc::Receiver<Result<OrderedFrameResult, ArchiveWriteError>>,
    envelope_job_tx: &std::sync::mpsc::SyncSender<OrderedEnvelopeJob>,
    envelope_result_rx: &std::sync::mpsc::Receiver<Result<OrderedEnvelopeResult, ArchiveWriteError>>,
    ordered: &mut OrderedParallelState,
    sink: &mut O,
    options: WriterOptions,
    emission_state: &mut WriterEmissionState,
    wait: bool,
) -> Result<bool, ArchiveWriteError> {
    let result = if wait {
        match frame_result_rx.recv() {
            Ok(result) => result?,
            Err(_) => return Err(FormatError::WriterInvariant("ordered frame worker stopped").into()),
        }
    } else {
        match frame_result_rx.try_recv() {
            Ok(result) => result?,
            Err(std::sync::mpsc::TryRecvError::Empty) => return Ok(false),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => return Ok(false),
        }
    };
    ordered.frame_buffer.insert(result.frame_index, result);
    while let Some(result) = ordered.frame_buffer.remove(&ordered.next_frame_result_index) {
        append_ordered_frame_result(result, envelope_job_tx, envelope_result_rx, ordered, sink, options, emission_state)?;
        ordered.next_frame_result_index = checked_u64_add(ordered.next_frame_result_index, 1, "PayloadFrame.frame_index")?;
    }
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn append_ordered_frame_result<O: ArchiveWriteSink>(
    result: OrderedFrameResult,
    envelope_job_tx: &std::sync::mpsc::SyncSender<OrderedEnvelopeJob>,
    envelope_result_rx: &std::sync::mpsc::Receiver<Result<OrderedEnvelopeResult, ArchiveWriteError>>,
    ordered: &mut OrderedParallelState,
    sink: &mut O,
    options: WriterOptions,
    emission_state: &mut WriterEmissionState,
) -> Result<(), ArchiveWriteError> {
    if payload_envelope_needs_flush(&ordered.envelope, result.frame.len(), options)? {
        flush_ordered_parallel_envelope(envelope_job_tx, envelope_result_rx, ordered, sink, options, emission_state)?;
    }
    if ordered.envelope.plaintext.is_empty() && !payload_object_can_fit(result.frame.len(), options)? {
        return Err(FormatError::WriterUnsupported("payload frame exceeds envelope object limits").into());
    }
    let offset = u32_len(ordered.envelope.plaintext.len(), "FrameEntry.offset_in_envelope")?;
    ordered.envelope.plaintext.extend_from_slice(&result.frame);
    ordered.frames.push(payload_frame_metadata(PayloadFrameMetadataInput {
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
    ordered.next_frame_metadata_index = checked_u64_add(ordered.next_frame_metadata_index, 1, "PayloadFrame.frame_index")?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn flush_ordered_parallel_envelope<O: ArchiveWriteSink>(
    envelope_job_tx: &std::sync::mpsc::SyncSender<OrderedEnvelopeJob>,
    envelope_result_rx: &std::sync::mpsc::Receiver<Result<OrderedEnvelopeResult, ArchiveWriteError>>,
    ordered: &mut OrderedParallelState,
    sink: &mut O,
    options: WriterOptions,
    emission_state: &mut WriterEmissionState,
) -> Result<(), ArchiveWriteError> {
    if ordered.envelope.plaintext.is_empty() {
        return Ok(());
    }
    let plaintext_size = u32_len(ordered.envelope.plaintext.len(), "EnvelopeEntry.plaintext_size")?;
    let object_plan = plan_encrypted_object(ordered.envelope.plaintext.len(), options.fec_data_shards, options.fec_parity_shards, options)?;
    let extent = ObjectExtent::new(ordered.next_payload_block_index, object_plan)?;
    ordered.next_payload_block_index = extent.next_block_index()?;
    ordered.payload_block_count = checked_u64_add(ordered.payload_block_count, extent.data_block_count as u64, "payload")?;
    ordered.payload_objects.push(PayloadObject { envelope_index: ordered.envelope.envelope_index, plaintext_size, object: extent });
    let mut job = OrderedEnvelopeJob {
        envelope_index: ordered.envelope.envelope_index,
        plaintext: std::mem::take(&mut ordered.envelope.plaintext),
        extent,
        collect_data_leaf_hashes: emission_state.data_leaf_hashes.is_some(),
    };
    ordered.envelope.envelope_index = checked_u64_add(ordered.envelope.envelope_index, 1, "EnvelopeEntry")?;
    loop {
        match envelope_job_tx.try_send(job) {
            Ok(()) => {
                drain_ordered_envelope_results(envelope_result_rx, ordered, sink, options, emission_state)?;
                return Ok(());
            }
            Err(std::sync::mpsc::TrySendError::Full(returned)) => {
                job = returned;
                receive_ordered_envelope_result(envelope_result_rx, ordered, sink, options, emission_state, true)?;
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                return Err(FormatError::WriterInvariant("ordered envelope worker stopped").into());
            }
        }
    }
}

pub(crate) fn drain_ordered_envelope_results<O: ArchiveWriteSink>(
    envelope_result_rx: &std::sync::mpsc::Receiver<Result<OrderedEnvelopeResult, ArchiveWriteError>>,
    ordered: &mut OrderedParallelState,
    sink: &mut O,
    options: WriterOptions,
    emission_state: &mut WriterEmissionState,
) -> Result<(), ArchiveWriteError> {
    while receive_ordered_envelope_result(envelope_result_rx, ordered, sink, options, emission_state, false)? {}
    Ok(())
}

pub(crate) fn receive_ordered_envelope_result<O: ArchiveWriteSink>(
    envelope_result_rx: &std::sync::mpsc::Receiver<Result<OrderedEnvelopeResult, ArchiveWriteError>>,
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
    ordered.envelope_buffer.insert(result.envelope_index, result);
    while let Some(result) = ordered.envelope_buffer.remove(&ordered.next_envelope_result_index) {
        emit_ordered_envelope_result(result, sink, options, emission_state)?;
        ordered.next_envelope_result_index = checked_u64_add(ordered.next_envelope_result_index, 1, "EnvelopeEntry")?;
    }
    Ok(true)
}

pub(crate) fn build_ordered_frame_result(job: OrderedFrameJob, options: WriterOptions) -> Result<OrderedFrameResult, ArchiveWriteError> {
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

pub(crate) fn build_ordered_envelope_result(
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
            records: OrderedEnvelopeRecords::Serialized(serialize_zero_parity_encrypted_object(&job.plaintext, context, job.extent, options)?),
        });
    }

    let mut local_next_block_index = job.extent.first_block_index;
    let object = encrypt_object(&job.plaintext, context, &mut local_next_block_index, options)?;
    validate_planned_extent(&object, job.extent)?;
    Ok(OrderedEnvelopeResult { envelope_index: job.envelope_index, records: OrderedEnvelopeRecords::Materialized(object.records) })
}

pub(crate) fn emit_ordered_envelope_result<O: ArchiveWriteSink>(
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
                emit_serialized_block_record(sink, options, &mut emission_state.bytes_written, &mut emission_state.record_counts, record)?;
            }
        }
    }
    Ok(())
}
