use std::io::Read;
use std::time::Instant;

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::compression::{
    compress_zstd_frame_with_dictionary_and_jobs, compress_zstd_frame_with_jobs,
};
use crate::crypto::{KdfParams, MasterKey, Subkeys};
use crate::entry_metadata::SparseExtent;
use crate::format::{
    ArchiveWriteError, BlockKind, FormatError, BLOCK_RECORD_FRAMING_LEN,
    CRITICAL_RECOVERY_LOCATOR_LEN, FORMAT_VERSION, MANIFEST_FOOTER_LEN, VOLUME_HEADER_LEN,
    VOLUME_TRAILER_LEN,
};
use crate::metadata::{normalize_lookup_file_path, DirectoryHintShardEntry, ShardEntry};
use crate::wire::{CriticalRecoveryLocator, VolumeHeader};

use super::*;

pub(crate) struct TimedWriterPlan {
    pub plan: WriterPlan,
    pub timings: WriterTimings,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_writer_plan<S: RegularFileSource>(
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
pub(crate) fn build_writer_plan_from_payload(
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

pub(crate) fn plan_payload_stream<S: RegularFileSource>(
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

pub(crate) struct PayloadFramePlanState<'a> {
    pub envelope: &'a mut PayloadEnvelopeBuilder,
    pub payload_objects: &'a mut Vec<PayloadObject>,
    pub payload_block_count: &'a mut u64,
    pub next_block_index: &'a mut u64,
    pub frames: &'a mut Vec<PayloadFrame>,
    pub next_frame_index: &'a mut u64,
    pub options: WriterOptions,
}

pub(crate) struct PayloadFramePlanInput<'a> {
    pub frame: &'a [u8],
    pub decompressed_size: usize,
    pub member_index: usize,
    pub member_start: u64,
    pub member_offset: u64,
    pub member_group_size: u64,
}

pub(crate) fn append_payload_frame_to_plan(
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

pub(crate) fn flush_payload_envelope_plan(
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

pub(crate) fn required_stripe_width_for_plan(
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
        let volume_size = planned_v45_volume_size(plan, &subkeys, volume_index, block_count)?;
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

pub(crate) fn planned_v45_volume_size(
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
    let cmra = build_v45_cmra(CmraBuildInput {
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

pub(crate) fn striped_block_count(
    total_block_count: u64,
    stripe_width: u32,
    volume_index: u32,
) -> u64 {
    let volume_index = volume_index as u64;
    let stripe_width = stripe_width as u64;
    if total_block_count <= volume_index {
        0
    } else {
        (total_block_count - 1 - volume_index) / stripe_width + 1
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn emit_writer_plan<S, O>(
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

pub(crate) fn start_write_phase(
    progress: Option<&SourceProgressHandle<'_>>,
    phase: ArchiveWritePhase,
) {
    if let Some(progress) = progress {
        progress.borrow_mut().start_phase(phase);
    }
}

pub(crate) fn emit_writer_plan_suffix<O: ArchiveWriteSink>(
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
        let cmra = build_v45_cmra(CmraBuildInput {
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
