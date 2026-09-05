use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read};

use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::compression::{compress_zstd_frame_with_dictionary_and_jobs, compress_zstd_frame_with_jobs};
use crate::crypto::{aead_encrypt, build_aad, compute_integrity_tag, derive_nonce, HmacDomain, KdfParams, MasterKey, Subkeys};
use crate::entry_metadata::{
    canonical_base64_encode, encode_canonical_pax, is_source_os, parse_auxiliary_declaration_for_writer, parse_auxiliary_record, parse_primary_metadata,
    portable_primary_pax, valid_filesystem_token, validate_group_metadata, ArchiveTimestamp, RestoreClass, SparseExtent, CAPTURE_PARTIAL, CAPTURE_REPORT_KIND,
    EXTENDED_METADATA_V1, HAS_AUXILIARY_STREAMS, HAS_NATIVE_METADATA, HAS_SPARSE_EXTENTS, MAX_SPARSE_EXTENTS, PORTABLE_PROFILE, REQUIRES_SYSTEM_RESTORE,
};
use crate::fec::encode_parity_gf16;
use crate::format::{
    root_auth_spec_id_for_revision, AeadAlgo, ArchiveWriteError, BlockKind, CompressionAlgo, FecAlgo, FormatError, KdfAlgo, BLOCK_RECORD_FRAMING_LEN,
    BOOTSTRAP_SIDECAR_HEADER_LEN, CRYPTO_EXTENSION_HEADER_LEN, CRYPTO_HEADER_FIXED_LEN, CRYPTO_HEADER_HMAC_LEN, FORMAT_VERSION, MANIFEST_FOOTER_LEN,
    READER_MAX_CMRA_PARITY_PCT, READER_MAX_ROOT_AUTH_AUTHENTICATOR_VALUE_LEN, READER_MAX_ROOT_AUTH_FOOTER_LEN, READER_MAX_ROOT_AUTH_SIGNER_IDENTITY_LEN,
    VOLUME_FORMAT_REV_45, VOLUME_HEADER_LEN, VOLUME_TRAILER_LEN,
};
use crate::metadata::{
    hash_prefix, normalize_lookup_file_path, validate_file_path_bytes, DirectoryHintEntry, DirectoryHintShardEntry, DirectoryHintTableHeader, EnvelopeEntry,
    FileEntry, FrameEntry, IndexRoot, IndexRootHeader, IndexShardHeader, ShardEntry, DIRECTORY_HINT_ENTRY_LEN, DIRECTORY_HINT_TABLE_LEN, ENVELOPE_ENTRY_LEN,
    FILE_ENTRY_LEN, FRAME_ENTRY_LEN, INDEX_SHARD_HEADER_LEN,
};
use crate::padding::suffix_pad_for_aead;
use crate::root_auth::{
    archive_root_for_revision, critical_metadata_digest, data_block_merkle_leaf_hash_for_revision, data_block_merkle_root_from_leaf_hashes_for_revision,
    fec_layout_digest_for_revision, index_digest_for_revision, root_auth_descriptor_digest_for_revision, signer_identity_digest, ArchiveRootInputs,
    CriticalMetadataDigestInputs, FecLayoutObjectRow,
};
use crate::wire::{
    BlockRecord, BootstrapSidecarHeader, CriticalMetadataImage, CriticalMetadataRecoveryHeader, CriticalMetadataRecoveryShard, CryptoHeader, CryptoHeaderFixed,
    ManifestFooter, RootAuthFooterV1, SerializedRegion, VolumeTrailer,
};

pub(crate) const TAR_BLOCK_LEN: usize = 512;
const MAX_REED_SOLOMON_GF16_SHARDS: u64 = 65_535;
pub(crate) const MIN_BLOCK_SIZE: u32 = 4096;

use super::*;

#[allow(clippy::too_many_arguments)]
pub(crate) fn emit_encrypted_object<O: ArchiveWriteSink>(
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
        ObjectEncryptionContext { key, nonce_seed, domain, counter, data_kind, parity_kind, data_shard_max, class_parity_shard_max, archive_uuid, session_id },
        next_block_index,
        options,
    )
    .map_err(|error| match metadata_kind {
        Some(kind) => map_metadata_encrypt_error(error, kind),
        None => error,
    })?;
    validate_planned_extent(&object, expected_extent)?;
    for record in &object.records {
        emit_block_record(sink, options, bytes_written, record_counts, volume_format_rev, data_leaf_hashes, record)?;
    }
    Ok(object)
}

pub(crate) fn emit_block_record<O: ArchiveWriteSink>(
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
    bytes_written[volume_index] = checked_u64_add(bytes_written[volume_index], record_bytes.len() as u64, "BlockRecord")?;
    record_counts[volume_index] = checked_u64_add(record_counts[volume_index], 1, "BlockRecord count")?;
    if let Some(data_leaf_hashes) = data_leaf_hashes.as_mut() {
        if record.kind.is_data() {
            data_leaf_hashes.push((
                record.block_index,
                data_block_merkle_leaf_hash_for_revision(FORMAT_VERSION, volume_format_rev, record.block_index, record.kind, record.flags, &record.payload)?,
            ));
        }
    }
    Ok(())
}

pub(crate) fn emit_serialized_block_record<O: ArchiveWriteSink>(
    sink: &mut O,
    options: WriterOptions,
    bytes_written: &mut [u64],
    record_counts: &mut [u64],
    record: &SerializedBlockRecord,
) -> Result<(), ArchiveWriteError> {
    let volume_index = (record.block_index % options.stripe_width as u64) as usize;
    sink.write_volume(volume_index, &record.bytes)?;
    bytes_written[volume_index] = checked_u64_add(bytes_written[volume_index], record.bytes.len() as u64, "BlockRecord")?;
    record_counts[volume_index] = checked_u64_add(record_counts[volume_index], 1, "BlockRecord count")?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn emit_payload_stream<S, O>(
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
    let mut envelope = PayloadEnvelopeBuilder { envelope_index: 0, plaintext: Vec::new() };
    let mut next_frame_index = 0u64;

    for (member_index, file) in files.iter().enumerate() {
        let member = plan.tar_members.get(member_index).ok_or(FormatError::WriterInvariant("planned tar member is missing"))?;
        let current_path = normalize_lookup_file_path(file.archive_path(), plan.options.max_path_length)?;
        if current_path != member.path
            || file.entry_kind() != member.entry_kind
            || file.link_target() != member.link_target.as_deref()
            || file.file_data_size() != member.file_data_size
            || file.sparse_extents() != member.sparse_extents.as_deref()
            || file.mode() != member.mode
            || file.mtime() != member.mtime
            || file.portable_metadata() != member.portable_metadata
        {
            return Err(FormatError::WriterInvariant("file source changed between planning and emission").into());
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
        let source_payload_size =
            member.sparse_extents.as_deref().map(|extents| sparse_extent_bytes(extents, member.file_data_size)).transpose()?.unwrap_or(member.file_data_size);
        let actual_member_group_size = primary_member_layout_size(&layout, source_payload_size)?;
        if actual_member_group_size != member.tar_member_group_size {
            return Err(FormatError::WriterInvariant("streamed auxiliary layout changed between planning and emission").into());
        }
        let mut reader = StreamingMemberReader::from_source(file, &member.portable_metadata, layout, source_payload_size)?;
        let mut member_offset = 0u64;
        while member_offset < member.tar_member_group_size {
            let remaining = member.tar_member_group_size - member_offset;
            let max_chunk = remaining.min(plan.options.chunk_size as u64);
            let mut chunk = vec![0u8; to_usize_writer(max_chunk, "payload chunk")?];
            reader.read_exact(&mut chunk).map_err(ArchiveWriteError::Io)?;
            let mut chunk_len = chunk.len();
            let frame = loop {
                let candidate = &chunk[..chunk_len];
                let frame = if let Some(dictionary) = dictionary {
                    compress_zstd_frame_with_dictionary_and_jobs(candidate, plan.options.zstd_level, dictionary, plan.options.jobs)?
                } else {
                    compress_zstd_frame_with_jobs(candidate, plan.options.zstd_level, plan.options.jobs)?
                };
                if payload_object_can_fit(frame.len(), plan.options)? {
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
        flush_payload_envelope_emit(&mut envelope, subkeys, plan, next_block_index, sink, bytes_written, record_counts, data_leaf_hashes)?;
    }
    if next_frame_index != plan.frames.len() as u64 || envelope.envelope_index != plan.payload_objects.len() as u64 {
        return Err(FormatError::WriterInvariant("streaming payload plan mismatch").into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn append_payload_frame_to_emit<O: ArchiveWriteSink>(
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
        flush_payload_envelope_emit(envelope, subkeys, plan, next_block_index, sink, bytes_written, record_counts, data_leaf_hashes)?;
    }
    if envelope.plaintext.is_empty() && !payload_object_can_fit(frame.len(), plan.options)? {
        return Err(FormatError::WriterUnsupported("payload frame exceeds envelope object limits").into());
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
    let expected = plan.frames.get(*next_frame_index as usize).ok_or(FormatError::WriterInvariant("planned payload frame is missing"))?;
    if expected.envelope_index != actual.envelope_index
        || expected.member_index != actual.member_index
        || expected.offset_in_envelope != actual.offset_in_envelope
        || expected.compressed_size != actual.compressed_size
        || expected.decompressed_size != actual.decompressed_size
        || expected.flags != actual.flags
        || expected.tar_stream_offset != actual.tar_stream_offset
    {
        return Err(FormatError::WriterInvariant("emitted payload frame does not match plan").into());
    }
    envelope.plaintext.extend_from_slice(frame);
    *next_frame_index = checked_u64_add(*next_frame_index, 1, "PayloadFrame.frame_index")?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn flush_payload_envelope_emit<O: ArchiveWriteSink>(
    envelope: &mut PayloadEnvelopeBuilder,
    subkeys: &Subkeys,
    plan: &WriterPlan,
    next_block_index: &mut u64,
    sink: &mut O,
    bytes_written: &mut [u64],
    record_counts: &mut [u64],
    data_leaf_hashes: &mut Option<Vec<(u64, [u8; 32])>>,
) -> Result<(), ArchiveWriteError> {
    let expected = plan.payload_objects.get(envelope.envelope_index as usize).ok_or(FormatError::WriterInvariant("planned payload envelope is missing"))?;
    if expected.envelope_index != envelope.envelope_index || expected.plaintext_size != u32_len(envelope.plaintext.len(), "EnvelopeEntry.plaintext_size")? {
        return Err(FormatError::WriterInvariant("emitted payload envelope does not match plan").into());
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

pub(crate) fn plan_writer_options(mut options: WriterOptions) -> Result<WriterOptions, FormatError> {
    if options.jobs == 0 {
        return Err(FormatError::WriterUnsupported("jobs must be at least 1"));
    }
    if options.block_size < MIN_BLOCK_SIZE || options.block_size % 2 != 0 {
        return Err(FormatError::WriterUnsupported("writer requires an even block size of at least 4096"));
    }
    if options.stripe_width == 0 {
        return Err(FormatError::WriterUnsupported("stripe_width must be non-zero"));
    }
    if options.volume_loss_tolerance as u32 >= options.stripe_width {
        return Err(FormatError::WriterUnsupported("volume_loss_tolerance must be less than stripe_width"));
    }
    if options.stripe_width == 1 && options.volume_loss_tolerance != 0 {
        return Err(FormatError::WriterUnsupported("single-volume archives cannot tolerate volume loss"));
    }
    if matches!(options.target_volume_size, Some(0)) {
        return Err(FormatError::WriterUnsupported("target_volume_size must be non-zero"));
    }
    if options.bit_rot_buffer_pct > 100 {
        return Err(FormatError::WriterUnsupported("bit_rot_buffer_pct must be at most 100"));
    }
    if options.chunk_size == 0 || options.chunk_size > options.envelope_target_size {
        return Err(FormatError::WriterUnsupported("chunk_size must be non-zero and no larger than envelope_target_size"));
    }
    if options.fec_data_shards == 0 || options.index_fec_data_shards == 0 || options.index_root_fec_data_shards == 0 {
        return Err(FormatError::WriterUnsupported("FEC data shard class maxima must be non-zero"));
    }
    options.index_root_fec_data_shards = options.index_root_fec_data_shards.max(MIN_INDEX_ROOT_FEC_DATA_SHARDS);
    options.fec_parity_shards = compute_parity_u16(options.fec_data_shards as u64, options, "fec_parity_shards")?;
    options.index_fec_parity_shards = compute_parity_u16(options.index_fec_data_shards as u64, options, "index_fec_parity_shards")?;
    options.index_root_fec_parity_shards = compute_parity_u16(options.index_root_fec_data_shards as u64, options, "index_root_fec_parity_shards")?;
    validate_writer_options_match_reader_caps(options)?;
    Ok(options)
}

pub(crate) fn validate_writer_options_match_reader_caps(options: WriterOptions) -> Result<(), FormatError> {
    CryptoHeaderFixed {
        length: CRYPTO_HEADER_FIXED_LEN as u32,
        compression_algo: CompressionAlgo::ZstdFramed,
        aead_algo: options.aead_algo,
        fec_algo: FecAlgo::ReedSolomonGF16,
        kdf_algo: if options.aead_algo.is_encrypted() { KdfAlgo::Raw } else { KdfAlgo::None },
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

pub(crate) fn build_crypto_header(
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
        .ok_or(FormatError::WriterUnsupported("CryptoHeader length overflow"))?;
    let kdf_algo = match kdf_params {
        KdfParams::None => KdfAlgo::None,
        KdfParams::Raw => KdfAlgo::Raw,
        KdfParams::Argon2id { .. } => KdfAlgo::Argon2id,
        KdfParams::RecipientWrap { .. } => KdfAlgo::RecipientWrap,
    };
    match (options.aead_algo, kdf_algo) {
        (AeadAlgo::None, KdfAlgo::None) => {}
        (aead_algo, KdfAlgo::Raw | KdfAlgo::Argon2id | KdfAlgo::RecipientWrap) if aead_algo.is_encrypted() => {}
        _ => {
            return Err(FormatError::InvalidProtectionMode { aead_algo: options.aead_algo, kdf_algo });
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
    let hmac = compute_integrity_tag(HmacDomain::CryptoHeader, options.aead_algo, volume_format_rev, Some(&subkeys.mac_key), archive_uuid, session_id, &bytes)?;
    bytes.extend_from_slice(&hmac);
    Ok(bytes)
}

pub(crate) fn serialize_kdf_params(params: &KdfParams) -> Result<Vec<u8>, FormatError> {
    let mut bytes = Vec::new();
    match params {
        KdfParams::None => {
            bytes.extend_from_slice(&(KdfAlgo::None as u16).to_le_bytes());
        }
        KdfParams::Raw => {
            bytes.extend_from_slice(&(KdfAlgo::Raw as u16).to_le_bytes());
        }
        KdfParams::Argon2id { t_cost, m_cost_kib, parallelism, salt } => {
            if *t_cost == 0 {
                return Err(FormatError::InvalidKdfParams("t_cost must be non-zero"));
            }
            if *parallelism == 0 {
                return Err(FormatError::InvalidKdfParams("parallelism must be non-zero"));
            }
            let min_memory = parallelism.checked_mul(8).ok_or(FormatError::InvalidKdfParams("m_cost_kib requirement overflow"))?;
            if *m_cost_kib < min_memory {
                return Err(FormatError::InvalidKdfParams("m_cost_kib must be at least 8 * parallelism"));
            }
            if !(8..=64).contains(&salt.len()) {
                return Err(FormatError::InvalidKdfParams("argon2id salt length must be 8..64"));
            }
            let salt_len = u16::try_from(salt.len()).map_err(|_| FormatError::InvalidKdfParams("argon2id salt too long"))?;
            bytes.extend_from_slice(&(KdfAlgo::Argon2id as u16).to_le_bytes());
            bytes.extend_from_slice(&t_cost.to_le_bytes());
            bytes.extend_from_slice(&m_cost_kib.to_le_bytes());
            bytes.extend_from_slice(&parallelism.to_le_bytes());
            bytes.extend_from_slice(&salt_len.to_le_bytes());
            bytes.extend_from_slice(salt);
        }
        KdfParams::RecipientWrap { key_wrap_table_length, key_wrap_table_record_count, key_wrap_table_version, key_wrap_table_digest } => {
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
pub(crate) fn build_tar_stream<S: RegularFileSource>(files: &[S], max_path_length: u32) -> Result<(Vec<u8>, Vec<TarMember>), FormatError> {
    let mut stream = Vec::new();
    let mut members = Vec::with_capacity(files.len());
    for file in files {
        let path = normalize_lookup_file_path(file.archive_path(), max_path_length)?;
        let start = stream.len() as u64;
        let sparse_extents = file.sparse_extents().map(<[SparseExtent]>::to_vec);
        let source_payload_size =
            sparse_extents.as_deref().map(|extents| sparse_extent_bytes(extents, file.file_data_size())).transpose()?.unwrap_or(file.file_data_size());
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
        let mut reader = file.open().map_err(|_| FormatError::WriterInvariant("test source failed to open"))?;
        let mut payload = Vec::new();
        reader.read_to_end(&mut payload).map_err(|_| FormatError::WriterInvariant("test source failed to read"))?;
        if payload.len() as u64 != source_payload_size {
            return Err(FormatError::WriterInvariant("test source payload size mismatch"));
        }
        member_group.extend_from_slice(&payload);
        member_group.resize(member_group.len() + padding_to_512(source_payload_size as usize), 0);
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
pub(crate) fn build_payload_envelopes(
    tar_stream: &[u8],
    members: &[TarMember],
    options: WriterOptions,
    dictionary: Option<&[u8]>,
) -> Result<(Vec<PayloadEnvelope>, Vec<PayloadFrame>), FormatError> {
    let chunk_size = options.chunk_size as usize;
    if chunk_size == 0 {
        return Err(FormatError::WriterUnsupported("chunk_size must be non-zero and no larger than envelope_target_size"));
    }
    let envelope_target_size = options.envelope_target_size as usize;
    let mut envelopes = Vec::new();
    let mut current = PayloadEnvelope { envelope_index: 0, plaintext: Vec::new() };
    let mut frames = Vec::new();
    let mut next_frame_index = 0u64;

    for (member_index, member) in members.iter().enumerate() {
        let start = member.tar_member_group_start as usize;
        let end = checked_usize_add(start, member.tar_member_group_size as usize, "tar member")?;
        let member_bytes = tar_stream.get(start..end).ok_or(FormatError::WriterInvariant("tar member range is out of bounds"))?;
        let mut member_offset = 0usize;
        while member_offset < member_bytes.len() {
            let mut chunk_len = (member_bytes.len() - member_offset).min(chunk_size);
            let frame = loop {
                let end = checked_usize_add(member_offset, chunk_len, "payload chunk")?;
                let chunk = &member_bytes[member_offset..end];
                let frame = if let Some(dictionary) = dictionary {
                    compress_zstd_frame_with_dictionary_and_jobs(chunk, options.zstd_level, dictionary, options.jobs)?
                } else {
                    compress_zstd_frame_with_jobs(chunk, options.zstd_level, options.jobs)?
                };
                if payload_object_can_fit(frame.len(), options)? {
                    break frame;
                }
                if chunk_len == 1 {
                    return Err(FormatError::WriterUnsupported("single-byte payload frame exceeds envelope object limits"));
                }
                chunk_len = (chunk_len / 2).max(1);
            };
            let next_len = checked_usize_add(current.plaintext.len(), frame.len(), "payload")?;
            if !current.plaintext.is_empty() && (next_len > envelope_target_size || !payload_object_can_fit(next_len, options)?) {
                envelopes.push(current);
                current = PayloadEnvelope { envelope_index: envelopes.len() as u64, plaintext: Vec::new() };
            }

            if current.plaintext.is_empty() && !payload_object_can_fit(frame.len(), options)? {
                return Err(FormatError::WriterUnsupported("payload frame exceeds envelope object limits"));
            }
            let offset = u32_len(current.plaintext.len(), "FrameEntry.offset_in_envelope")?;
            current.plaintext.extend_from_slice(&frame);
            let is_first_member_frame = member_offset == 0;
            let is_last_member_frame = checked_usize_add(member_offset, chunk_len, "payload chunk")? == member_bytes.len();
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
                    u64::try_from(member_offset).map_err(|_| FormatError::WriterUnsupported("chunk offset"))?,
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

pub(crate) fn sorted_file_rows(members: &[TarMember]) -> Vec<FileRow> {
    let mut rows = members
        .iter()
        .enumerate()
        .map(|(member_index, member)| FileRow { path_hash: hash_prefix(&member.path), path: member.path.clone(), member_index, member: member.clone() })
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        (left.path_hash, left.path.as_slice(), left.member.tar_member_group_start).cmp(&(
            right.path_hash,
            right.path.as_slice(),
            right.member.tar_member_group_start,
        ))
    });
    rows
}

pub(crate) fn partition_file_rows(rows: Vec<FileRow>) -> Result<Vec<Vec<FileRow>>, FormatError> {
    let mut shards = Vec::new();
    let mut start = 0usize;
    while start < rows.len() {
        let mut end = (start + DEFAULT_FILES_PER_INDEX_SHARD).min(rows.len());
        if end < rows.len() && rows[end - 1].path_hash == rows[end].path_hash {
            let boundary_hash = rows[end].path_hash;
            let mut run_start_in_shard = end - 1;
            while run_start_in_shard > start && rows[run_start_in_shard - 1].path_hash == boundary_hash {
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
            end = if full_run_len <= MAX_HASH_PREFIX_RUN_FILES { full_run_end } else { (run_start_in_shard + MAX_HASH_PREFIX_RUN_FILES).min(full_run_end) };
        }
        if end - start > MAX_FILES_PER_INDEX_SHARD {
            return Err(FormatError::WriterUnsupported("hash-prefix collision run exceeds max_files_per_index_shard"));
        }
        shards.push(rows[start..end].to_vec());
        start = end;
    }
    Ok(shards)
}

pub(crate) fn build_index_shard_plaintexts(
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

pub(crate) fn append_index_shards_for_rows(
    planned: &mut Vec<PlannedIndexShard>,
    rows: &[FileRow],
    frames: &[PayloadFrame],
    payloads: &[PayloadObject],
    options: WriterOptions,
) -> Result<(), FormatError> {
    let shard_index = u64::try_from(planned.len()).map_err(|_| FormatError::WriterUnsupported("shard_index"))?;
    let candidate = build_index_shard_plaintext(shard_index, rows, frames, payloads, options)?;
    let compressed = compress_zstd_frame_with_jobs(&candidate.plaintext, options.zstd_level, options.jobs)?;
    if index_object_can_fit(compressed.len(), options)? {
        planned.push(candidate);
        return Ok(());
    }
    if rows.len() == 1 {
        return Err(FormatError::WriterUnsupported("single-file IndexShard exceeds index object limits"));
    }
    let split_at = split_sorted_file_rows_for_object_limit(rows);
    append_index_shards_for_rows(planned, &rows[..split_at], frames, payloads, options)?;
    append_index_shards_for_rows(planned, &rows[split_at..], frames, payloads, options)
}

pub(crate) fn split_sorted_file_rows_for_object_limit(rows: &[FileRow]) -> usize {
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

pub(crate) fn build_index_shard_plaintext(
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
            required_frame_indexes.insert(checked_u64_add(first_frame_index, offset, "FileEntry.frame_count")?);
        }
        let (uname_offset, uname_length) = {
            let uname = row.member.portable_metadata.posix_owner.as_ref().and_then(|o| o.uname.as_ref());
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
            let gname = row.member.portable_metadata.posix_owner.as_ref().and_then(|o| o.gname.as_ref());
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
            SourceEntryKind::Regular | SourceEntryKind::ReparseRegular => crate::tar_model::TarEntryKind::Regular.to_u8(),
            SourceEntryKind::Directory | SourceEntryKind::ReparseDirectory => crate::tar_model::TarEntryKind::Directory.to_u8(),
            SourceEntryKind::Symlink => crate::tar_model::TarEntryKind::Symlink.to_u8(),
            SourceEntryKind::Hardlink => crate::tar_model::TarEntryKind::Hardlink.to_u8(),
            SourceEntryKind::CharacterDevice => crate::tar_model::TarEntryKind::CharacterDevice.to_u8(),
            SourceEntryKind::BlockDevice => crate::tar_model::TarEntryKind::BlockDevice.to_u8(),
            SourceEntryKind::Fifo => crate::tar_model::TarEntryKind::Fifo.to_u8(),
        };

        let uid = row.member.portable_metadata.posix_owner.as_ref().map(|o| o.uid).unwrap_or(u64::MAX);
        let gid = row.member.portable_metadata.posix_owner.as_ref().map(|o| o.gid).unwrap_or(u64::MAX);

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
            flags: v45_portable_file_entry_flags(row.member.mode, row.member.sparse_extents.is_some(), &row.member.portable_metadata),
            mtime_nsec: row.member.mtime.nanoseconds,
            mtime_sec: row.member.mtime.seconds,
            created_nsec: row.member.portable_metadata.created.as_ref().map(|t| t.nanoseconds).unwrap_or(0),
            created_sec: row.member.portable_metadata.created.as_ref().map(|t| t.seconds).unwrap_or(0),
            accessed_nsec: row.member.portable_metadata.accessed.as_ref().map(|t| t.nanoseconds).unwrap_or(0),
            accessed_sec: row.member.portable_metadata.accessed.as_ref().map(|t| t.seconds).unwrap_or(0),
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
    let required_envelope_indexes = frame_entries.iter().map(|frame| frame.envelope_index).collect::<BTreeSet<_>>();
    let envelope_entries = payloads
        .iter()
        .filter(|payload| required_envelope_indexes.contains(&payload.envelope_index))
        .map(|payload| {
            let (first_frame_index, frame_count) = envelope_frame_range(payload.envelope_index, frames)?;
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

    let plaintext = serialize_index_shard(shard_index, &file_entries, &frame_entries, &envelope_entries, &string_pool, options)?;
    let first_path_hash = file_rows.first().ok_or(FormatError::WriterInvariant("empty planned IndexShard"))?.path_hash;
    let last_path_hash = file_rows.last().ok_or(FormatError::WriterInvariant("empty planned IndexShard"))?.path_hash;
    Ok(PlannedIndexShard { shard_index, plaintext, file_count: u32_len(file_rows.len(), "IndexShard.file_count")?, first_path_hash, last_path_hash })
}

pub(crate) fn serialize_index_shard(
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

pub(crate) fn build_directory_hint_plaintexts(shard_rows: &[Vec<FileRow>], options: WriterOptions) -> Result<Vec<PlannedDirectoryHintShard>, FormatError> {
    let mut map = BTreeMap::<Vec<u8>, BTreeSet<u32>>::new();
    for (shard_row_index, rows) in shard_rows.iter().enumerate() {
        let shard_row_index = u32::try_from(shard_row_index).map_err(|_| FormatError::WriterUnsupported("directory hint shard row index"))?;
        for row in rows {
            add_directory_hint_rows(&mut map, shard_row_index, &row.path, row.member.entry_kind);
        }
    }

    let rows = map.into_iter().map(|(path, shard_rows)| (hash_prefix(&path), path, shard_rows)).collect::<Vec<_>>();
    let mut rows = rows;
    rows.sort_by(|left, right| (left.0, left.1.as_slice()).cmp(&(right.0, right.1.as_slice())));

    let mut planned = Vec::new();
    for chunk in rows.chunks(DEFAULT_DIRECTORY_HINT_ENTRIES_PER_SHARD) {
        append_directory_hint_shards_for_rows(&mut planned, chunk, options)?;
    }
    Ok(planned)
}

pub(crate) fn append_directory_hint_shards_for_rows(
    planned: &mut Vec<PlannedDirectoryHintShard>,
    rows: &[([u8; 8], Vec<u8>, BTreeSet<u32>)],
    options: WriterOptions,
) -> Result<(), FormatError> {
    let hint_shard_index = u64::try_from(planned.len()).map_err(|_| FormatError::WriterUnsupported("hint_shard_index"))?;
    let candidate = build_directory_hint_plaintext(hint_shard_index, rows)?;
    let compressed = compress_zstd_frame_with_jobs(&candidate.plaintext, options.zstd_level, options.jobs)?;
    if index_object_can_fit(compressed.len(), options)? {
        planned.push(candidate);
        return Ok(());
    }
    if rows.len() == 1 {
        return Err(FormatError::WriterUnsupported("single DirectoryHintEntry exceeds index object limits"));
    }
    let split_at = rows.len() / 2;
    append_directory_hint_shards_for_rows(planned, &rows[..split_at], options)?;
    append_directory_hint_shards_for_rows(planned, &rows[split_at..], options)
}

pub(crate) fn add_directory_hint_rows(map: &mut BTreeMap<Vec<u8>, BTreeSet<u32>>, shard_row_index: u32, path: &[u8], entry_kind: SourceEntryKind) {
    map.entry(Vec::new()).or_default().insert(shard_row_index);
    let mut cursor = 0usize;
    while let Some(position) = path[cursor..].iter().position(|byte| *byte == b'/') {
        let slash = cursor + position;
        if slash > 0 {
            map.entry(path[..slash].to_vec()).or_default().insert(shard_row_index);
        }
        cursor = slash + 1;
    }
    // §29 writer rule 14: hints include every FileEntry path whose decoded
    // primary entry is itself a directory — including leaf directories that no
    // descendant's ancestor prefixes cover. Must mirror the reader's
    // `add_expected_directory_hint_rows` (kind == Directory), which validates
    // this table for exact equality.
    if matches!(entry_kind, SourceEntryKind::Directory | SourceEntryKind::ReparseDirectory) {
        map.entry(path.to_vec()).or_default().insert(shard_row_index);
    }
}

pub(crate) fn build_directory_hint_plaintext(
    hint_shard_index: u64,
    rows: &[([u8; 8], Vec<u8>, BTreeSet<u32>)],
) -> Result<PlannedDirectoryHintShard, FormatError> {
    let mut entries = Vec::with_capacity(rows.len());
    let mut shard_row_indexes = Vec::new();
    let mut string_pool = Vec::new();

    for (dir_hash, path, shard_rows) in rows {
        let path_offset =
            if path.is_empty() { 0 } else { u64::try_from(string_pool.len()).map_err(|_| FormatError::WriterUnsupported("DirectoryHintEntry.path_offset"))? };
        if !path.is_empty() {
            string_pool.extend_from_slice(path);
        }
        let shard_list_start_index = u32_len(shard_row_indexes.len(), "DirectoryHintEntry.shard_list_start_index")?;
        shard_row_indexes.extend(shard_rows.iter().copied());
        entries.push(DirectoryHintEntry {
            dir_hash: *dir_hash,
            path_offset,
            path_length: u32_len(path.len(), "DirectoryHintEntry.path_length")?,
            shard_list_start_index,
            shard_count: u32_len(shard_rows.len(), "DirectoryHintEntry.shard_count")?,
        });
    }

    let plaintext = serialize_directory_hint_table(hint_shard_index, &entries, &shard_row_indexes, &string_pool)?;
    let first_dir_hash = rows.first().ok_or(FormatError::WriterInvariant("empty directory hint shard"))?.0;
    let last_dir_hash = rows.last().ok_or(FormatError::WriterInvariant("empty directory hint shard"))?.0;
    Ok(PlannedDirectoryHintShard { hint_shard_index, plaintext, entry_count: rows.len() as u64, first_dir_hash, last_dir_hash })
}

pub(crate) fn serialize_directory_hint_table(
    hint_shard_index: u64,
    entries: &[DirectoryHintEntry],
    shard_row_indexes: &[u32],
    string_pool: &[u8],
) -> Result<Vec<u8>, FormatError> {
    let entry_table_offset = table_offset(entries.len(), DIRECTORY_HINT_TABLE_LEN)?;
    let shard_list_cursor = checked_usize_add(DIRECTORY_HINT_TABLE_LEN, entries.len() * DIRECTORY_HINT_ENTRY_LEN, "DirectoryHintTable")?;
    let shard_list_offset = table_offset(shard_row_indexes.len(), shard_list_cursor)?;
    let string_pool_cursor = checked_usize_add(shard_list_cursor, shard_row_indexes.len() * 4, "DirectoryHintTable")?;
    let string_pool_offset = if string_pool.is_empty() {
        0
    } else {
        u64::try_from(string_pool_cursor).map_err(|_| FormatError::WriterUnsupported("DirectoryHintTable.string_pool_offset"))?
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
pub(crate) struct IndexRootPlaintextInput<'a> {
    pub shard_entries: &'a [ShardEntry],
    pub frame_count: u64,
    pub envelope_count: u64,
    pub file_count: u64,
    pub payload_block_count: u64,
    pub tar_total_size: u64,
    pub content_sha256: [u8; 32],
    pub directory_hint_entries: &'a [DirectoryHintShardEntry],
    pub dictionary_extent: Option<(ObjectExtent, u32)>,
}

pub(crate) fn build_index_root_plaintext(input: IndexRootPlaintextInput<'_>) -> Vec<u8> {
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
    let root = IndexRoot { header, shards: input.shard_entries.to_vec(), directory_hint_shards: input.directory_hint_entries.to_vec() };
    root.to_bytes()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MetadataClassPlan {
    pub options: WriterOptions,
    pub index_root: PlannedEncryptedObject,
    pub dictionary: Option<PlannedEncryptedObject>,
}

pub(crate) fn plan_index_root_metadata_class(
    mut options: WriterOptions,
    compressed_index_root_len: usize,
    compressed_dictionary_len: Option<usize>,
) -> Result<MetadataClassPlan, FormatError> {
    let index_root = plan_metadata_object_without_class(compressed_index_root_len, options, MetadataObjectKind::IndexRoot)?;
    let dictionary = compressed_dictionary_len.map(|len| plan_metadata_object_without_class(len, options, MetadataObjectKind::Dictionary)).transpose()?;
    let required_data_shards = u32::from(options.index_root_fec_data_shards)
        .max(MIN_INDEX_ROOT_FEC_DATA_SHARDS as u32)
        .max(index_root.data_block_count)
        .max(dictionary.map(|plan| plan.data_block_count).unwrap_or(0));
    let required_data_shards = u16::try_from(required_data_shards).map_err(|_| MetadataObjectKind::IndexRoot.too_large_error())?;
    options.index_root_fec_data_shards = required_data_shards;
    let required_parity_shards = compute_parity_u16(options.index_root_fec_data_shards as u64, options, "index_root_fec_parity_shards")?;
    options.index_root_fec_parity_shards = options.index_root_fec_parity_shards.max(required_parity_shards);
    ensure_metadata_object_fits_class(index_root, options, MetadataObjectKind::IndexRoot)?;
    if let Some(dictionary) = dictionary {
        ensure_metadata_object_fits_class(dictionary, options, MetadataObjectKind::Dictionary)?;
    }
    Ok(MetadataClassPlan { options, index_root, dictionary })
}

pub(crate) fn plan_metadata_object_without_class(
    payload_len: usize,
    options: WriterOptions,
    kind: MetadataObjectKind,
) -> Result<PlannedEncryptedObject, FormatError> {
    let plan = plan_encrypted_object_without_class(payload_len, options).map_err(|_| kind.too_large_error())?;
    if plan.data_block_count > u16::MAX as u32 || plan.parity_block_count > u16::MAX as u32 {
        return Err(kind.too_large_error());
    }
    validate_object_shard_total(plan.data_block_count, plan.parity_block_count).map_err(|_| kind.too_large_error())?;
    Ok(plan)
}

pub(crate) fn ensure_metadata_object_fits_class(plan: PlannedEncryptedObject, options: WriterOptions, kind: MetadataObjectKind) -> Result<(), FormatError> {
    if plan.data_block_count > options.index_root_fec_data_shards as u32 {
        return Err(kind.too_large_error());
    }
    if plan.parity_block_count > options.index_root_fec_parity_shards as u32 {
        return Err(kind.too_large_error());
    }
    validate_object_shard_total(plan.data_block_count, plan.parity_block_count).map_err(|_| kind.too_large_error())
}

pub(crate) fn payload_object_can_fit(payload_len: usize, options: WriterOptions) -> Result<bool, FormatError> {
    encrypted_object_can_fit(payload_len, options.fec_data_shards, options.fec_parity_shards, options)
}

pub(crate) fn index_object_can_fit(payload_len: usize, options: WriterOptions) -> Result<bool, FormatError> {
    encrypted_object_can_fit(payload_len, options.index_fec_data_shards, options.index_fec_parity_shards, options)
}

pub(crate) fn encrypted_object_can_fit(payload_len: usize, data_shard_max: u16, parity_shard_max: u16, options: WriterOptions) -> Result<bool, FormatError> {
    match plan_encrypted_object(payload_len, data_shard_max, parity_shard_max, options) {
        Ok(_) => Ok(true),
        Err(FormatError::WriterUnsupported("encrypted object exceeds u32 size limit"))
        | Err(FormatError::WriterUnsupported("encrypted object exceeds its data shard class maximum"))
        | Err(FormatError::WriterUnsupported("encrypted object exceeds its parity shard class maximum"))
        | Err(FormatError::WriterUnsupported("encrypted object exceeds ReedSolomonGF16 shard limit")) => Ok(false),
        Err(err) => Err(err),
    }
}

pub(crate) fn plan_encrypted_object(
    payload_len: usize,
    data_shard_max: u16,
    parity_shard_max: u16,
    options: WriterOptions,
) -> Result<PlannedEncryptedObject, FormatError> {
    let plan = plan_encrypted_object_without_class(payload_len, options)?;
    if plan.data_block_count > data_shard_max as u32 {
        return Err(FormatError::WriterUnsupported("encrypted object exceeds its data shard class maximum"));
    }
    if plan.parity_block_count > parity_shard_max as u32 {
        return Err(FormatError::WriterUnsupported("encrypted object exceeds its parity shard class maximum"));
    }
    validate_object_shard_total(plan.data_block_count, plan.parity_block_count)?;
    Ok(plan)
}

pub(crate) fn plan_encrypted_object_without_class(payload_len: usize, options: WriterOptions) -> Result<PlannedEncryptedObject, FormatError> {
    let (data_block_count, encrypted_size) = encrypted_object_data_extent(payload_len, options)?;
    let parity_block_count = compute_parity(data_block_count as u64, options)?;
    Ok(PlannedEncryptedObject { data_block_count, parity_block_count, encrypted_size })
}

pub(crate) fn encrypted_object_data_extent(payload_len: usize, options: WriterOptions) -> Result<(u32, u32), FormatError> {
    let block_size = options.block_size as usize;
    let tag_len = options.aead_algo.tag_len();
    let total_before_padding = payload_len.checked_add(tag_len).ok_or(FormatError::WriterUnsupported("encrypted object size overflow"))?;
    let remainder = total_before_padding % block_size;
    let encrypted_size = if remainder == 0 {
        total_before_padding.checked_add(block_size).ok_or(FormatError::WriterUnsupported("encrypted object size overflow"))?
    } else {
        total_before_padding.checked_add(block_size - remainder).ok_or(FormatError::WriterUnsupported("encrypted object size overflow"))?
    };
    let encrypted_size = u32_len(encrypted_size, "encrypted_size").map_err(|_| FormatError::WriterUnsupported("encrypted object exceeds u32 size limit"))?;
    Ok((encrypted_size / options.block_size, encrypted_size))
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ObjectEncryptionContext<'a> {
    pub key: &'a [u8; 32],
    pub nonce_seed: &'a [u8; 32],
    pub domain: &'a [u8],
    pub counter: u64,
    pub data_kind: BlockKind,
    pub parity_kind: BlockKind,
    pub data_shard_max: u16,
    pub class_parity_shard_max: u16,
    pub archive_uuid: &'a [u8; 16],
    pub session_id: &'a [u8; 16],
}

pub(crate) fn encrypt_object(
    payload: &[u8],
    context: ObjectEncryptionContext<'_>,
    next_block_index: &mut u64,
    options: WriterOptions,
) -> Result<EncryptedObject, FormatError> {
    let block_size = options.block_size as usize;
    let encrypted = encrypt_object_payload(payload, context, options)?;
    if encrypted.len() % block_size != 0 {
        return Err(FormatError::WriterInvariant("encrypted object is not block aligned"));
    }
    let encrypted_size = u32_len(encrypted.len(), "encrypted_size")?;
    let data_shards = encrypted.chunks(block_size).map(|chunk| chunk.to_vec()).collect::<Vec<_>>();
    let data_block_count = u32_len(data_shards.len(), "data_block_count")?;
    if data_block_count == 0 {
        return Err(FormatError::WriterInvariant("encrypted object has no data blocks"));
    }
    if data_block_count > context.data_shard_max as u32 {
        return Err(FormatError::WriterUnsupported("encrypted object exceeds its data shard class maximum"));
    }
    let required_parity = compute_object_parity(data_block_count as u64, options, context.class_parity_shard_max as u32)?;
    if required_parity > context.class_parity_shard_max as u32 {
        return Err(FormatError::WriterUnsupported("encrypted object exceeds its parity shard class maximum"));
    }
    validate_object_shard_total(data_block_count, required_parity)?;
    let parity_count = required_parity as u16;
    let parity_shards = if parity_count == 0 { Vec::new() } else { encode_parity_gf16(&data_shards, parity_count as usize)? };

    let first_block_index = *next_block_index;
    let mut records = Vec::with_capacity(data_shards.len() + parity_shards.len());
    for (index, payload) in data_shards.into_iter().enumerate() {
        records.push(BlockRecord {
            block_index: checked_u64_add(first_block_index, index as u64, "BlockRecord")?,
            kind: context.data_kind,
            flags: if index + 1 == data_block_count as usize { 0x01 } else { 0 },
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

    *next_block_index = checked_u64_add(first_block_index, data_block_count as u64 + parity_count as u64, "next_block_index")?;

    Ok(EncryptedObject { first_block_index, data_block_count, parity_block_count: parity_count as u32, encrypted_size, records })
}

pub(crate) fn serialize_zero_parity_encrypted_object(
    payload: &[u8],
    context: ObjectEncryptionContext<'_>,
    expected_extent: ObjectExtent,
    options: WriterOptions,
) -> Result<Vec<SerializedBlockRecord>, FormatError> {
    let planned = plan_encrypted_object(payload.len(), context.data_shard_max, context.class_parity_shard_max, options)?;
    if planned.parity_block_count != 0 || expected_extent.parity_block_count != 0 {
        return Err(FormatError::WriterInvariant("zero-parity serialization received a parity object"));
    }
    if planned.data_block_count != expected_extent.data_block_count || planned.encrypted_size != expected_extent.encrypted_size {
        return Err(FormatError::WriterInvariant("encrypted object did not match planned sizing"));
    }

    let block_size = options.block_size as usize;
    let encrypted = encrypt_object_payload(payload, context, options)?;
    if encrypted.len() != expected_extent.encrypted_size as usize || encrypted.len() % block_size != 0 {
        return Err(FormatError::WriterInvariant("encrypted object did not match planned sizing"));
    }
    let data_block_count = encrypted.len() / block_size;
    if data_block_count == 0 || data_block_count != expected_extent.data_block_count as usize {
        return Err(FormatError::WriterInvariant("encrypted object did not match planned sizing"));
    }

    let mut records = Vec::with_capacity(data_block_count);
    for (index, chunk) in encrypted.chunks(block_size).enumerate() {
        let block_index = checked_u64_add(expected_extent.first_block_index, index as u64, "BlockRecord")?;
        let flags = if index + 1 == data_block_count { 0x01 } else { 0 };
        records.push(SerializedBlockRecord { block_index, bytes: BlockRecord::to_bytes_from_parts(block_index, context.data_kind, flags, chunk) });
    }
    Ok(records)
}

pub(crate) fn encrypt_object_payload(payload: &[u8], context: ObjectEncryptionContext<'_>, options: WriterOptions) -> Result<Vec<u8>, FormatError> {
    let block_size = options.block_size as usize;
    let padded = suffix_pad_for_aead(payload, options.aead_algo.tag_len(), block_size)?;
    if matches!(options.aead_algo, AeadAlgo::None) {
        return Ok(padded);
    }
    let nonce = derive_nonce(context.nonce_seed, context.domain, context.archive_uuid, context.session_id, context.counter, options.aead_algo.nonce_len())?;
    let aad = build_aad(context.domain, context.archive_uuid, context.session_id, context.counter)?;
    aead_encrypt(options.aead_algo, context.key, &nonce, &aad, &padded)
}

pub(crate) fn validate_planned_object(object: &EncryptedObject, expected: PlannedEncryptedObject) -> Result<(), FormatError> {
    if object.data_block_count != expected.data_block_count
        || object.parity_block_count != expected.parity_block_count
        || object.encrypted_size != expected.encrypted_size
    {
        return Err(FormatError::WriterInvariant("encrypted object did not match planned sizing"));
    }
    Ok(())
}

pub(crate) fn validate_planned_extent(object: &EncryptedObject, expected: ObjectExtent) -> Result<(), FormatError> {
    validate_planned_object(
        object,
        PlannedEncryptedObject {
            data_block_count: expected.data_block_count,
            parity_block_count: expected.parity_block_count,
            encrypted_size: expected.encrypted_size,
        },
    )?;
    if object.first_block_index != expected.first_block_index {
        return Err(FormatError::WriterInvariant("encrypted object did not match planned extent"));
    }
    Ok(())
}

pub(crate) fn map_metadata_encrypt_error(error: FormatError, kind: MetadataObjectKind) -> FormatError {
    match error {
        FormatError::WriterUnsupported("encrypted object exceeds u32 size limit")
        | FormatError::WriterUnsupported("encrypted object exceeds its data shard class maximum")
        | FormatError::WriterUnsupported("encrypted object exceeds its parity shard class maximum")
        | FormatError::WriterUnsupported("encrypted object exceeds ReedSolomonGF16 shard limit") => kind.too_large_error(),
        other => other,
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RootAuthFooterBuildInput<'a> {
    pub archive_uuid: [u8; 16],
    pub session_id: [u8; 16],
    pub volume_format_rev: u16,
    pub options: WriterOptions,
    pub crypto_header: &'a [u8],
    pub volume_zero_manifest: &'a [u8; MANIFEST_FOOTER_LEN],
    pub index_root_plaintext: &'a [u8],
    pub index_root_extent: ObjectExtent,
    pub dictionary_extent: Option<(ObjectExtent, u32)>,
    pub shard_entries: &'a [ShardEntry],
    pub payload_objects: &'a [PayloadObject],
    pub directory_hint_entries: &'a [DirectoryHintShardEntry],
    pub data_leaf_hashes: &'a [(u64, [u8; 32])],
}

pub(crate) fn build_root_auth_footer_from_leaf_hashes(
    config: RootAuthWriterConfig<'_>,
    authenticator: &mut RootAuthAuthenticator<'_>,
    input: RootAuthFooterBuildInput<'_>,
) -> Result<Vec<u8>, FormatError> {
    let mut sorted_leaf_hashes = input.data_leaf_hashes.to_vec();
    sorted_leaf_hashes.sort_by_key(|(block_index, _)| *block_index);
    let leaf_hashes = sorted_leaf_hashes.iter().map(|(_, leaf_hash)| *leaf_hash).collect::<Vec<_>>();
    let total_data_block_count = u64::try_from(leaf_hashes.len()).map_err(|_| FormatError::WriterUnsupported("root-auth data block count"))?;
    let data_block_merkle_root = data_block_merkle_root_from_leaf_hashes_for_revision(FORMAT_VERSION, input.volume_format_rev, &leaf_hashes)?;

    let parsed_crypto = CryptoHeader::parse(input.crypto_header, u32_len(input.crypto_header.len(), "CryptoHeader")?)?;
    let footer_length = root_auth_footer_wire_length(config.signer_identity.len(), config.authenticator_value_length as usize)?;
    let root_auth_descriptor_digest = root_auth_descriptor_digest_for_revision(
        FORMAT_VERSION,
        input.volume_format_rev,
        config.authenticator_id,
        config.signer_identity_type,
        config.signer_identity,
        config.authenticator_value_length,
        footer_length,
    )?;
    let signer_identity_digest = signer_identity_digest(config.signer_identity_type, config.signer_identity)?;
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
    let index_digest = index_digest_for_revision(FORMAT_VERSION, input.volume_format_rev, input.index_root_plaintext)?;
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
            checked_u64_add(total, row.data_block_count as u64, "root-auth data block count")
        } else {
            Ok(total)
        }
    })?;
    if expected_data_block_count != total_data_block_count {
        return Err(FormatError::WriterInvariant("root-auth data block count does not match FEC layout"));
    }
    let fec_layout_digest = fec_layout_digest_for_revision(FORMAT_VERSION, input.volume_format_rev, &fec_layout_rows)?;
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
        return Err(FormatError::WriterUnsupported("root-auth authenticator length mismatch"));
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

pub(crate) fn writer_fec_layout_rows_from_extents(
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

pub(crate) fn manifest_footer_global_pre_hmac_bytes(manifest_footer: &[u8; MANIFEST_FOOTER_LEN]) -> [u8; 104] {
    let mut bytes = [0u8; 104];
    bytes.copy_from_slice(&manifest_footer[..104]);
    bytes[36..40].fill(0);
    bytes
}

pub(crate) fn root_auth_footer_wire_length(signer_identity_len: usize, authenticator_value_len: usize) -> Result<u32, FormatError> {
    validate_root_auth_variable_lengths_for_writer(signer_identity_len, authenticator_value_len)?;
    let len = crate::format::ROOT_AUTH_FOOTER_FIXED_LEN
        .checked_add(signer_identity_len)
        .and_then(|value| value.checked_add(authenticator_value_len))
        .and_then(|value| value.checked_add(4))
        .ok_or(FormatError::WriterUnsupported("RootAuthFooterV1 length overflow"))?;
    if len > READER_MAX_ROOT_AUTH_FOOTER_LEN as usize {
        return Err(FormatError::ReaderResourceLimitExceeded {
            field: "RootAuthFooterV1 length",
            cap: READER_MAX_ROOT_AUTH_FOOTER_LEN as u64,
            actual: len as u64,
        });
    }
    u32::try_from(len).map_err(|_| FormatError::WriterUnsupported("RootAuthFooterV1 length"))
}

pub(crate) fn validate_root_auth_writer_config(config: RootAuthWriterConfig<'_>) -> Result<(), FormatError> {
    root_auth_footer_wire_length(config.signer_identity.len(), config.authenticator_value_length as usize)?;
    Ok(())
}

pub(crate) fn validate_root_auth_variable_lengths_for_writer(signer_identity_len: usize, authenticator_value_len: usize) -> Result<(), FormatError> {
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
pub(crate) fn build_manifest_footer(
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
    footer.manifest_hmac =
        compute_integrity_tag(HmacDomain::ManifestFooter, aead_algo, volume_format_rev, Some(&subkeys.mac_key), &archive_uuid, &session_id, &bytes[..104])?;
    bytes = footer.to_bytes();
    Ok(bytes)
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct VolumeTrailerBuildInput<'a> {
    pub subkeys: &'a Subkeys,
    pub aead_algo: AeadAlgo,
    pub volume_format_rev: u16,
    pub archive_uuid: [u8; 16],
    pub session_id: [u8; 16],
    pub volume_index: u32,
    pub block_count: u64,
    pub bytes_written: u64,
    pub manifest_footer_offset: u64,
    pub closed_at_ns: i64,
    pub root_auth_footer: Option<(u64, u32)>,
}

pub(crate) fn build_volume_trailer(input: VolumeTrailerBuildInput<'_>) -> Result<[u8; VOLUME_TRAILER_LEN], FormatError> {
    let (root_auth_footer_offset, root_auth_footer_length, root_auth_flags) = match input.root_auth_footer {
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

pub(crate) struct BuiltCmra {
    pub bytes: Vec<u8>,
    pub shard_size: u32,
    pub data_shard_count: u16,
    pub parity_shard_count: u16,
    pub image_length: u32,
    pub image_sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CmraBuildInput<'a> {
    pub volume_format_rev: u16,
    pub volume_header_bytes: &'a [u8; VOLUME_HEADER_LEN],
    pub crypto_header: &'a [u8],
    pub block_count: u64,
    pub block_records_offset: u64,
    pub manifest_footer_offset: u64,
    pub manifest_footer: &'a [u8; MANIFEST_FOOTER_LEN],
    pub root_auth_footer_offset: Option<u64>,
    pub root_auth_footer: Option<&'a [u8]>,
    pub key_wrap_table: Option<&'a [u8]>,
    pub trailer_offset: u64,
    pub trailer: &'a [u8; VOLUME_TRAILER_LEN],
    pub cmra_offset: u64,
    pub options: WriterOptions,
    pub archive_uuid: [u8; 16],
    pub session_id: [u8; 16],
    pub volume_index: u32,
}

pub(crate) fn build_v45_cmra(input: CmraBuildInput<'_>) -> Result<BuiltCmra, FormatError> {
    let block_record_len = input.options.block_size as u64 + BLOCK_RECORD_FRAMING_LEN as u64;
    let crypto_end = VOLUME_HEADER_LEN as u64 + input.crypto_header.len() as u64;
    let block_records_offset = input.block_records_offset;
    let key_wrap_table = input
        .key_wrap_table
        .map(|table| {
            if table.is_empty() {
                return Err(FormatError::WriterInvariant("KeyWrapTableV1 must include at least one recipient record"));
            }
            let key_wrap_table_length = u32_len(table.len(), "KeyWrapTableV1 table_length")?;
            Ok((table, key_wrap_table_length))
        })
        .transpose()?;
    if input.volume_format_rev != VOLUME_FORMAT_REV_45 && key_wrap_table.is_some() {
        return Err(FormatError::WriterInvariant("KeyWrapTableV1 requires volume_format_rev 45"));
    }
    let key_wrap_table_length = key_wrap_table.map(|(_, length)| u64::from(length));
    let expected_block_records_offset = match key_wrap_table_length {
        Some(length) => checked_u64_add(crypto_end, length, "KeyWrapTableV1")?,
        None => crypto_end,
    };
    if block_records_offset != expected_block_records_offset {
        return Err(FormatError::WriterInvariant("CMRA block records offset does not match key-wrap table layout"));
    }
    let block_records_length = checked_u64_mul(input.block_count, block_record_len, "CMRA BlockRecord length overflow")?;
    let manifest_end = input.manifest_footer_offset.checked_add(MANIFEST_FOOTER_LEN as u64).ok_or(FormatError::WriterUnsupported("CMRA terminal overflow"))?;
    let root_auth_footer_length = input.root_auth_footer.map(|footer| u32_len(footer.len(), "RootAuthFooterV1")).transpose()?;
    match (input.root_auth_footer_offset, root_auth_footer_length) {
        (Some(offset), Some(length)) => {
            if manifest_end != offset
                || offset.checked_add(length as u64).ok_or(FormatError::WriterUnsupported("CMRA terminal overflow"))? != input.trailer_offset
            {
                return Err(FormatError::WriterInvariant("RootAuthFooter does not sit between ManifestFooter and VolumeTrailer"));
            }
        }
        (None, None) => {
            if manifest_end != input.trailer_offset {
                return Err(FormatError::WriterInvariant("ManifestFooter does not end at VolumeTrailer"));
            }
        }
        _ => {
            return Err(FormatError::WriterInvariant("RootAuthFooter offset/bytes mismatch"));
        }
    }
    let body_bytes_before_cmra = input.trailer_offset.checked_add(VOLUME_TRAILER_LEN as u64).ok_or(FormatError::WriterUnsupported("CMRA terminal overflow"))?;
    if body_bytes_before_cmra != input.cmra_offset {
        return Err(FormatError::WriterInvariant("CMRA does not start after VolumeTrailer"));
    }

    let mut regions = vec![
        SerializedRegion { region_type: 1, offset: 0, bytes: input.volume_header_bytes.to_vec() },
        SerializedRegion { region_type: 2, offset: VOLUME_HEADER_LEN as u64, bytes: input.crypto_header.to_vec() },
    ];
    if let Some((table, _)) = key_wrap_table {
        regions.push(SerializedRegion { region_type: 6, offset: crypto_end, bytes: table.to_vec() });
    }
    regions.push(SerializedRegion { region_type: 3, offset: input.manifest_footer_offset, bytes: input.manifest_footer.to_vec() });
    if let (Some(offset), Some(footer)) = (input.root_auth_footer_offset, input.root_auth_footer) {
        regions.push(SerializedRegion { region_type: 4, offset, bytes: footer.to_vec() });
    }
    regions.push(SerializedRegion { region_type: 5, offset: input.trailer_offset, bytes: input.trailer.to_vec() });
    let root_auth_flag = if input.root_auth_footer.is_some() { 0x0000_0001 } else { 0 };
    let key_wrap_flag = if key_wrap_table.is_some() { 0x0000_0002 } else { 0 };
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
        key_wrap_table_sha256: key_wrap_table.map(|(table, _)| sha256_bytes(table)).unwrap_or([0u8; 32]),
        manifest_footer_sha256: sha256_bytes(input.manifest_footer),
        root_auth_footer_sha256: input.root_auth_footer.map(sha256_bytes).unwrap_or([0u8; 32]),
        volume_trailer_sha256: sha256_bytes(input.trailer),
        regions,
    };
    let image_bytes = image.to_bytes()?;
    let image_sha256 = sha256_bytes(&image_bytes);
    let data_shard_count = ceil_div(image_bytes.len() as u64, CMRA_SHARD_SIZE as u64)?;
    let data_shard_count_u16 = u16::try_from(data_shard_count).map_err(|_| FormatError::WriterUnsupported("CMRA data shard count"))?;
    let parity_lower = cmra_min_parity_shards(data_shard_count, input.options.bit_rot_buffer_pct)?;
    let parity_upper = cmra_min_parity_shards(data_shard_count, READER_MAX_CMRA_PARITY_PCT as u8)?;
    if parity_lower > parity_upper {
        return Err(FormatError::WriterUnsupported("CMRA parity bounds"));
    }
    let parity_shard_count_u16 = u16::try_from(parity_lower).map_err(|_| FormatError::WriterUnsupported("CMRA parity shard count"))?;

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
                shard_index: u16::try_from(idx).map_err(|_| FormatError::WriterUnsupported("CMRA shard index"))?,
                shard_role: 0,
                shard_payload_length: u32_len(payload_len, "CMRA shard payload")?,
                payload,
                shard_crc32c: 0,
            }
            .to_bytes(CMRA_SHARD_SIZE)?,
        );
    }
    for (idx, payload) in parity_shards.into_iter().enumerate() {
        let shard_index = data_shard_count.checked_add(idx as u64).ok_or(FormatError::WriterUnsupported("CMRA shard index overflow"))?;
        cmra.extend_from_slice(
            &CriticalMetadataRecoveryShard {
                shard_index: u16::try_from(shard_index).map_err(|_| FormatError::WriterUnsupported("CMRA shard index"))?,
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

pub(crate) fn cmra_min_parity_shards(data_shard_count: u64, pct: u8) -> Result<u64, FormatError> {
    let by_pct = ceil_div(checked_u64_mul(data_shard_count, pct as u64, "CMRA parity overflow")?, 100)?;
    Ok(2u64.max(by_pct))
}

pub(crate) fn compute_object_parity(data_block_count: u64, options: WriterOptions, class_parity_shard_max: u32) -> Result<u32, FormatError> {
    let computed = compute_parity(data_block_count, options)?;
    if computed > class_parity_shard_max {
        return Err(FormatError::WriterUnsupported("encrypted object exceeds its parity shard class maximum"));
    }
    Ok(computed)
}

pub(crate) fn validate_object_shard_total(data_block_count: u32, parity_block_count: u32) -> Result<(), FormatError> {
    let total = checked_u64_add(data_block_count as u64, parity_block_count as u64, "encrypted object shard total overflow")?;
    if total > MAX_REED_SOLOMON_GF16_SHARDS {
        return Err(FormatError::WriterUnsupported("encrypted object exceeds ReedSolomonGF16 shard limit"));
    }
    Ok(())
}

pub(crate) fn compute_parity_u16(data_block_count: u64, options: WriterOptions, field: &'static str) -> Result<u16, FormatError> {
    let parity = compute_parity(data_block_count, options)?;
    u16::try_from(parity).map_err(|_| FormatError::WriterUnsupported(field))
}

pub(crate) fn compute_parity(data_block_count: u64, options: WriterOptions) -> Result<u32, FormatError> {
    let min_parity = if options.volume_loss_tolerance > 0 || options.bit_rot_buffer_pct > 0 { 1u64 } else { 0u64 };
    let mut parity = 0u64;
    for _ in 0..100 {
        let total = data_block_count.checked_add(parity).ok_or(FormatError::WriterUnsupported("parity total overflow"))?;
        let by_volume = checked_u64_mul(options.volume_loss_tolerance as u64, ceil_div(total, options.stripe_width as u64)?, "volume-loss parity overflow")?;
        let by_bitrot = ceil_div(checked_u64_mul(total, options.bit_rot_buffer_pct as u64, "bit-rot parity overflow")?, 100)?;
        let next = by_volume.checked_add(by_bitrot).ok_or(FormatError::WriterUnsupported("parity overflow"))?.max(min_parity);
        if next == parity {
            return u32::try_from(next).map_err(|_| FormatError::WriterUnsupported("parity count"));
        }
        parity = next;
    }
    Err(FormatError::WriterUnsupported("parity calculation did not converge"))
}

pub(crate) fn ceil_div(numerator: u64, denominator: u64) -> Result<u64, FormatError> {
    if denominator == 0 {
        return Err(FormatError::WriterUnsupported("division by zero"));
    }
    numerator.checked_add(denominator - 1).ok_or(FormatError::WriterUnsupported("ceiling division overflow")).map(|value| value / denominator)
}

pub(crate) fn checked_u64_mul(lhs: u64, rhs: u64, field: &'static str) -> Result<u64, FormatError> {
    lhs.checked_mul(rhs).ok_or(FormatError::WriterUnsupported(field))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_bootstrap_sidecar(
    subkeys: &Subkeys,
    aead_algo: AeadAlgo,
    volume_format_rev: u16,
    archive_uuid: [u8; 16],
    session_id: [u8; 16],
    manifest_footer: &[u8; MANIFEST_FOOTER_LEN],
    index_root_records: &[BlockRecord],
    dictionary_records: Option<&[BlockRecord]>,
) -> Result<Vec<u8>, FormatError> {
    let index_records_len = index_root_records.iter().try_fold(0usize, |sum, record| checked_usize_add(sum, record.to_bytes().len(), "bootstrap sidecar"))?;
    let dictionary_records_len =
        dictionary_records.unwrap_or(&[]).iter().try_fold(0usize, |sum, record| checked_usize_add(sum, record.to_bytes().len(), "bootstrap sidecar"))?;
    let manifest_offset = BOOTSTRAP_SIDECAR_HEADER_LEN as u64;
    let index_root_offset = manifest_offset + MANIFEST_FOOTER_LEN as u64;
    let dictionary_offset = if dictionary_records.is_some() { index_root_offset + index_records_len as u64 } else { 0 };
    let mut header = BootstrapSidecarHeader {
        archive_uuid,
        session_id,
        flags: if dictionary_records.is_some() { 0x07 } else { 0x03 },
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

    let mut sidecar = Vec::with_capacity(BOOTSTRAP_SIDECAR_HEADER_LEN + MANIFEST_FOOTER_LEN + index_records_len + dictionary_records_len);
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

pub(crate) struct StreamingMemberReader<'a> {
    pub sections: Vec<StreamingMemberSection<'a>>,
    pub section_index: usize,
    pub pushback: Vec<u8>,
}

pub(crate) struct StreamingMemberSection<'a> {
    pub reader: Option<Box<dyn Read + 'a>>,
    pub opener: Option<SectionOpener<'a>>,
    pub remaining: u64,
    pub remaining_padding: u64,
    pub expected_sha256: Option<[u8; 32]>,
    pub hasher: Sha256,
    pub source_eof_checked: bool,
}

pub(crate) type SectionOpener<'a> = Box<dyn FnOnce() -> Result<Box<dyn Read + 'a>, ArchiveWriteError> + 'a>;

impl<'a> StreamingMemberSection<'a> {
    pub fn bytes(bytes: Vec<u8>) -> Self {
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

    pub fn payload(reader: Box<dyn Read + 'a>, size: u64, expected_sha256: Option<[u8; 32]>) -> Self {
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

    pub fn deferred_payload(opener: SectionOpener<'a>, size: u64, expected_sha256: Option<[u8; 32]>) -> Self {
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

    pub fn reader(&mut self) -> std::io::Result<&mut Box<dyn Read + 'a>> {
        if self.reader.is_none() {
            let opener = self.opener.take().ok_or_else(|| std::io::Error::other("streaming member section has no source"))?;
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
            let limit = out.len().min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
            let count = self.reader()?.read(&mut out[..limit])?;
            if count == 0 {
                return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "member source ended before its declared size"));
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
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "member source exceeded its declared size"));
            }
            if let Some(expected) = self.expected_sha256 {
                let actual: [u8; 32] = self.hasher.clone().finalize().into();
                if actual != expected {
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "auxiliary source changed after metadata capture"));
                }
            }
            self.source_eof_checked = true;
            self.reader = None;
        }
        if self.remaining_padding > 0 {
            let count = out.len().min(usize::try_from(self.remaining_padding).unwrap_or(usize::MAX));
            out[..count].fill(0);
            self.remaining_padding -= count as u64;
            return Ok(count);
        }
        Ok(0)
    }
}

impl<'a> StreamingMemberReader<'a> {
    pub fn new(file: Box<dyn Read + 'a>, prefix: Vec<u8>, file_size: u64) -> Self {
        Self {
            sections: vec![StreamingMemberSection::bytes(prefix), StreamingMemberSection::payload(file, file_size, None)],
            section_index: 0,
            pushback: Vec::new(),
        }
    }

    pub fn from_source<S: RegularFileSource + ?Sized>(
        source: &'a S,
        metadata: &PortableFileMetadata,
        layout: PrimaryMemberLayout,
        primary_size: u64,
    ) -> Result<Self, ArchiveWriteError> {
        let mut sections = Vec::with_capacity(layout.auxiliary.len() * 2 + 2);
        for (ordinal, auxiliary) in layout.auxiliary.into_iter().enumerate() {
            sections.push(StreamingMemberSection::bytes(auxiliary.bytes));
            let record = metadata.native.auxiliary_records.get(ordinal).ok_or(FormatError::WriterInvariant("planned auxiliary source ordinal is missing"))?;
            if record.is_streamed() {
                sections.push(StreamingMemberSection::deferred_payload(
                    Box::new(move || source.open_auxiliary(ordinal)),
                    auxiliary.stored_size,
                    Some(auxiliary.sha256),
                ));
            } else {
                sections.push(StreamingMemberSection::payload(Box::new(Cursor::new(record.payload.clone())), auxiliary.stored_size, Some(auxiliary.sha256)));
            }
            if record.stored_payload_size() != auxiliary.stored_size {
                return Err(FormatError::WriterInvariant("auxiliary source declaration changed while opening").into());
            }
        }
        sections.push(StreamingMemberSection::bytes(layout.primary));
        sections.push(StreamingMemberSection::deferred_payload(Box::new(move || source.open()), primary_size, None));
        Ok(Self { sections, section_index: 0, pushback: Vec::new() })
    }

    pub fn push_back(&mut self, bytes: Vec<u8>) {
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
pub(crate) fn build_regular_file_member_prefix(
    path: &[u8],
    file_size: u64,
    mode: u32,
    mtime: ArchiveTimestamp,
    portable_metadata: &PortableFileMetadata,
) -> Result<Vec<u8>, FormatError> {
    build_primary_member_prefix(path, SourceEntryKind::Regular, None, file_size, None, mode, mtime, portable_metadata)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_primary_member_prefix(
    path: &[u8],
    entry_kind: SourceEntryKind,
    link_target: Option<&[u8]>,
    file_size: u64,
    sparse_extents: Option<&[SparseExtent]>,
    mode: u32,
    mtime: ArchiveTimestamp,
    portable_metadata: &PortableFileMetadata,
) -> Result<Vec<u8>, FormatError> {
    let layout = build_primary_member_layout(path, entry_kind, link_target, file_size, sparse_extents, mode, mtime, portable_metadata)?;
    let mut out = Vec::new();
    for (ordinal, auxiliary) in layout.auxiliary.iter().enumerate() {
        let record = &portable_metadata.native.auxiliary_records[ordinal];
        if record.is_streamed() {
            return Err(FormatError::WriterUnsupported("this writer path does not accept streamed auxiliary payloads"));
        }
        out.extend_from_slice(&auxiliary.bytes);
        out.extend_from_slice(&record.payload);
        out.resize(out.len() + padding_to_512_u64(auxiliary.stored_size) as usize, 0);
    }
    out.extend_from_slice(&layout.primary);
    Ok(out)
}

pub(crate) struct PrimaryMemberLayout {
    pub auxiliary: Vec<NativeAuxiliaryMemberPrefix>,
    pub primary: Vec<u8>,
}

pub(crate) fn primary_member_layout_size(layout: &PrimaryMemberLayout, primary_payload_size: u64) -> Result<u64, FormatError> {
    let mut size = 0u64;
    for auxiliary in &layout.auxiliary {
        size = checked_u64_add(size, auxiliary.bytes.len() as u64, "auxiliary member")?;
        size = checked_u64_add(size, auxiliary.stored_size, "auxiliary member")?;
        size = checked_u64_add(size, padding_to_512_u64(auxiliary.stored_size), "auxiliary member")?;
    }
    size = checked_u64_add(size, layout.primary.len() as u64, "primary member")?;
    size = checked_u64_add(size, primary_payload_size, "primary member")?;
    checked_u64_add(size, padding_to_512_u64(primary_payload_size), "primary member")
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_primary_member_layout(
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
        return Err(FormatError::WriterInvariant("non-regular member has non-zero file data size"));
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
                return Err(FormatError::WriterInvariant("hardlink alias carries native file-object metadata"));
            }
        }
        (SourceEntryKind::Symlink, None) => {
            return Err(FormatError::WriterInvariant("symlink member has no link target"));
        }
        (_, Some(_)) => {
            return Err(FormatError::WriterInvariant("non-link member has a link target"));
        }
        (_, None) => {}
    }
    let sparse_map = sparse_extents.map(|extents| encode_v45_sparse_map(extents, file_size)).transpose()?;
    let stored_extent_bytes = sparse_extents.map(|extents| sparse_extent_bytes(extents, file_size)).transpose()?.unwrap_or(file_size);
    let stored_size = checked_u64_add(sparse_map.as_ref().map_or(0, |map| map.len() as u64), stored_extent_bytes, "sparse primary stored size")?;
    let use_path_override = sparse_map.is_none() && path_requires_pax(path);
    validate_portable_file_metadata(portable_metadata)?;
    let reparse_placeholder = portable_metadata.native.primary_pax_records.contains_key("TZAP.windows.reparse-placeholder");
    if matches!(entry_kind, SourceEntryKind::ReparseDirectory | SourceEntryKind::ReparseRegular) != reparse_placeholder {
        return Err(FormatError::WriterInvariant("Windows reparse source kind and placeholder metadata disagree"));
    }
    let mut pax_records = portable_primary_pax(path, mode, &portable_metadata.source_os, use_path_override)?;
    pax_records.insert("TZAP.metadata.source-filesystem".into(), portable_metadata.source_filesystem.as_bytes().to_vec());
    pax_records.insert(
        "TZAP.portable.mode-origin".into(),
        match portable_metadata.mode_origin {
            PortableModeOrigin::Native => b"native".to_vec(),
            PortableModeOrigin::Projected => b"projected".to_vec(),
        },
    );
    if let Some(attributes) = portable_metadata.attributes {
        pax_records.insert("TZAP.portable.attributes".into(), hex::encode(attributes.to_be_bytes()).into_bytes());
    }
    for (key, timestamp) in [("LIBARCHIVE.creationtime", portable_metadata.created), ("atime", portable_metadata.accessed)] {
        if let Some(timestamp) = timestamp {
            let value = timestamp.canonical_pax_value()?;
            if let Some(native_value) = portable_metadata.native.primary_pax_records.get(key) {
                if native_value != &value {
                    return Err(FormatError::WriterUnsupported("portable timestamp conflicts with native primary metadata"));
                }
            } else {
                pax_records.insert(key.into(), value);
                // LIBARCHIVE.creationtime (unlike atime, uid, gid, ...) is
                // owned by POSIX_PROFILE for these source OSes per
                // validate_profile_owned_primary_fields's source_profile
                // match; declaring it without that profile fails the
                // writer's own round-trip parse. This must stay scoped to
                // exactly this insertion (not a blanket per-source-OS rule in
                // portable_primary_pax) since portable-v1-only is a hard
                // invariant elsewhere, e.g. hardlink aliases.
                if key == "LIBARCHIVE.creationtime" && crate::entry_metadata::source_os_requires_posix_profile(&portable_metadata.source_os) {
                    pax_records.insert("TZAP.metadata.required-profiles".into(), format!("{PORTABLE_PROFILE},{}", crate::entry_metadata::POSIX_PROFILE).into_bytes());
                }
            }
        }
    }
    if sparse_map.is_some() {
        pax_records.insert("GNU.sparse.major".into(), b"1".to_vec());
        pax_records.insert("GNU.sparse.minor".into(), b"0".to_vec());
        pax_records.insert("GNU.sparse.name".into(), path.to_vec());
        pax_records.insert("GNU.sparse.realsize".into(), file_size.to_string().into_bytes());
    }
    merge_native_primary_metadata(&mut pax_records, &portable_metadata.native)?;
    if portable_metadata.native.auxiliary_records.iter().any(|record| record.kind == CAPTURE_REPORT_KIND) {
        pax_records.insert("TZAP.metadata.capture-status".into(), b"partial".to_vec());
    }
    let use_linkpath_override = link_target.is_some_and(|target| target.len() > 100);
    if use_linkpath_override {
        pax_records.insert("linkpath".into(), link_target.expect("link target was checked").to_vec());
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
    let primary_metadata =
        parse_primary_metadata(&pax_records).map_err(|_| FormatError::WriterUnsupported("native primary metadata is not a valid v45 declaration"))?;
    let mut parsed_auxiliary = Vec::with_capacity(portable_metadata.native.auxiliary_records.len());
    let mut auxiliary = Vec::with_capacity(portable_metadata.native.auxiliary_records.len());
    for (ordinal, record) in portable_metadata.native.auxiliary_records.iter().enumerate() {
        let ordinal = u32::try_from(ordinal).map_err(|_| FormatError::WriterUnsupported("auxiliary record count exceeds revision-45 range"))?;
        let member = build_native_auxiliary_member_prefix(ordinal, record)?;
        parsed_auxiliary.push(member.parsed.clone());
        auxiliary.push(member);
    }
    validate_group_metadata(&primary_metadata, &parsed_auxiliary)
        .map_err(|_| FormatError::WriterUnsupported("native auxiliary metadata is not a valid v45 declaration"))?;
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
    if matches!(entry_kind, SourceEntryKind::CharacterDevice | SourceEntryKind::BlockDevice) {
        let parse_device = |key: &str| -> Result<u64, FormatError> {
            let value = pax_records.get(key).ok_or(FormatError::WriterInvariant("device member lacks device-number metadata"))?;
            let text = std::str::from_utf8(value).map_err(|_| FormatError::WriterUnsupported("device number is not canonical decimal"))?;
            text.parse::<u64>().map_err(|_| FormatError::WriterUnsupported("device number is not canonical decimal"))
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

pub(crate) fn sparse_extent_bytes(extents: &[SparseExtent], logical_size: u64) -> Result<u64, FormatError> {
    if extents.len() > MAX_SPARSE_EXTENTS {
        return Err(FormatError::WriterUnsupported("sparse extent count exceeds revision-45 limit"));
    }
    let mut previous_end = 0u64;
    let mut stored_size = 0u64;
    for (index, extent) in extents.iter().enumerate() {
        if extent.length == 0 || extent.offset < previous_end {
            return Err(FormatError::WriterUnsupported("sparse extents overlap or have zero length"));
        }
        if index != 0 && extent.offset == previous_end {
            return Err(FormatError::WriterUnsupported("adjacent sparse extents must be merged"));
        }
        let end = extent.offset.checked_add(extent.length).ok_or(FormatError::WriterUnsupported("sparse extent overflow"))?;
        if end > logical_size {
            return Err(FormatError::WriterUnsupported("sparse extent exceeds logical size"));
        }
        stored_size = stored_size.checked_add(extent.length).ok_or(FormatError::WriterUnsupported("sparse stored size overflow"))?;
        previous_end = end;
    }
    Ok(stored_size)
}

pub fn encode_v45_sparse_map(extents: &[SparseExtent], logical_size: u64) -> Result<Vec<u8>, FormatError> {
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
    map.resize(map.len().checked_add(padding).ok_or(FormatError::WriterUnsupported("sparse map size overflow"))?, 0);
    Ok(map)
}

pub(crate) struct NativeAuxiliaryMemberPrefix {
    pub bytes: Vec<u8>,
    pub stored_size: u64,
    pub sha256: [u8; 32],
    pub parsed: crate::entry_metadata::AuxiliaryRecord,
}

pub(crate) fn build_native_auxiliary_member_prefix(ordinal: u32, record: &NativeAuxiliaryMetadata) -> Result<NativeAuxiliaryMemberPrefix, FormatError> {
    if record.is_streamed()
        && !matches!(record.kind.as_str(), "windows.alternate-data" | "windows.property-data" | "windows.efs-raw" | "macos.resource-fork" | "generic.xattr")
        && !record.kind.starts_with("x.")
    {
        return Err(FormatError::WriterUnsupported("this auxiliary kind requires inline structural payload validation"));
    }
    let mut pax_records = BTreeMap::new();
    pax_records.insert("TZAP.aux.version".into(), b"1".to_vec());
    pax_records.insert("TZAP.aux.kind".into(), record.kind.as_bytes().to_vec());
    pax_records.insert("TZAP.aux.profile".into(), record.profile.as_bytes().to_vec());
    pax_records.insert(
        "TZAP.aux.restore-class".into(),
        match record.restore_class {
            RestoreClass::None => b"none".to_vec(),
            RestoreClass::Portable => b"portable".to_vec(),
            RestoreClass::SameOs => b"same-os".to_vec(),
            RestoreClass::System => b"system".to_vec(),
        },
    );
    pax_records.insert("TZAP.aux.native".into(), if record.native { b"1" } else { b"0" }.to_vec());
    let (name_encoding, encoded_name) = match record.name_encoding {
        NativeAuxiliaryNameEncoding::None => ("none", record.name.clone()),
        NativeAuxiliaryNameEncoding::Utf8 => ("utf8", record.name.clone()),
        NativeAuxiliaryNameEncoding::Utf16Le => ("utf16le-base64", canonical_base64_encode(&record.name)),
        NativeAuxiliaryNameEncoding::Bytes => ("bytes-base64", canonical_base64_encode(&record.name)),
    };
    pax_records.insert("TZAP.aux.name-encoding".into(), name_encoding.as_bytes().to_vec());
    pax_records.insert("TZAP.aux.name".into(), encoded_name);
    pax_records.insert("TZAP.aux.flags".into(), hex::encode(record.flags.to_be_bytes()).into_bytes());
    pax_records.insert("TZAP.aux.logical-size".into(), record.logical_size.to_string().into_bytes());
    let digest = record.sha256();
    pax_records.insert("TZAP.aux.sha256".into(), hex::encode(digest).into_bytes());
    for (key, value) in &record.meta {
        if pax_records.insert(key.clone(), value.clone()).is_some() {
            return Err(FormatError::WriterUnsupported("auxiliary metadata collides with a writer-owned key"));
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
    let pax_header = build_ustar_header(pax_label.as_bytes(), pax_payload.len() as u64, 0, 0, b'x')?;
    let auxiliary_label = format!("TZAP-AUX/{ordinal:08x}");
    let auxiliary_header = build_ustar_header(auxiliary_label.as_bytes(), header_size, 0, 0, b'Z')?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&pax_header);
    bytes.extend_from_slice(&pax_payload);
    bytes.resize(bytes.len() + padding_to_512(pax_payload.len()), 0);
    bytes.extend_from_slice(&auxiliary_header);
    Ok(NativeAuxiliaryMemberPrefix { bytes, stored_size, sha256: digest, parsed })
}

pub(crate) fn merge_native_primary_metadata(pax_records: &mut crate::entry_metadata::PaxRecords, native: &NativeFileMetadata) -> Result<(), FormatError> {
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
    if required.iter().any(|profile| optional.binary_search(profile).is_ok()) {
        return Err(FormatError::WriterUnsupported("metadata profile is both required and optional"));
    }
    pax_records.insert("TZAP.metadata.required-profiles".into(), required.join(",").into_bytes());
    pax_records.insert("TZAP.metadata.optional-profiles".into(), optional.join(",").into_bytes());
    for (key, value) in &native.primary_pax_records {
        if pax_records.contains_key(key)
            || matches!(key.as_str(), "path" | "linkpath" | "size" | "uid" | "gid" | "uname" | "gname" | "mtime")
            || key.starts_with("TZAP.metadata.")
            || key.starts_with("TZAP.portable.")
        {
            return Err(FormatError::WriterUnsupported("native metadata collides with a writer-owned primary key"));
        }
        pax_records.insert(key.clone(), value.clone());
    }
    Ok(())
}

#[derive(Debug, Default)]
pub(crate) struct PrimaryTarIdentity {
    pub uid: u64,
    pub gid: u64,
    pub uname: Vec<u8>,
    pub gname: Vec<u8>,
}

pub(crate) fn validate_portable_file_metadata(metadata: &PortableFileMetadata) -> Result<(), FormatError> {
    if !is_source_os(&metadata.source_os) {
        return Err(FormatError::WriterUnsupported("invalid metadata source OS"));
    }
    if !valid_filesystem_token(&metadata.source_filesystem) {
        return Err(FormatError::WriterUnsupported("invalid metadata source filesystem"));
    }
    if metadata.attributes.is_some_and(|attributes| attributes & !0x0f != 0) {
        return Err(FormatError::WriterUnsupported("portable attributes contain reserved bits"));
    }
    Ok(())
}

pub(crate) fn prepare_primary_tar_identity(
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
    Ok(PrimaryTarIdentity { uid, gid, uname, gname })
}

pub(crate) fn prepare_primary_name(pax_records: &mut crate::entry_metadata::PaxRecords, key: &'static str, name: Option<&str>) -> Result<Vec<u8>, FormatError> {
    let Some(name) = name else {
        return Ok(Vec::new());
    };
    if name.is_empty() || name.contains('\0') || name.nfc().collect::<String>() != name {
        return Err(FormatError::WriterUnsupported("portable owner name is not canonical NFC UTF-8"));
    }
    if name.len() <= 32 {
        Ok(name.as_bytes().to_vec())
    } else {
        pax_records.insert(key.into(), name.as_bytes().to_vec());
        Ok(Vec::new())
    }
}

pub(crate) fn apply_primary_tar_identity(header: &mut [u8; TAR_BLOCK_LEN], identity: &PrimaryTarIdentity) -> Result<(), FormatError> {
    write_tar_octal(&mut header[108..116], identity.uid)?;
    write_tar_octal(&mut header[116..124], identity.gid)?;
    header[265..297].fill(0);
    header[265..265 + identity.uname.len()].copy_from_slice(&identity.uname);
    header[297..329].fill(0);
    header[297..297 + identity.gname.len()].copy_from_slice(&identity.gname);
    finalize_tar_checksum(header)
}

#[cfg(test)]
pub(crate) fn build_regular_file_member_group(
    path: &[u8],
    contents: &[u8],
    mode: u32,
    mtime: ArchiveTimestamp,
    portable_metadata: &PortableFileMetadata,
) -> Result<Vec<u8>, FormatError> {
    let mut out = build_regular_file_member_prefix(path, contents.len() as u64, mode, mtime, portable_metadata)?;
    out.extend_from_slice(contents);
    out.resize(out.len() + padding_to_512(contents.len()), 0);
    Ok(out)
}

pub(crate) fn path_requires_pax(path: &[u8]) -> bool {
    path.len() > 100
}

pub(crate) fn v45_portable_file_entry_flags(mode: u32, primary_sparse: bool, metadata: &PortableFileMetadata) -> u32 {
    EXTENDED_METADATA_V1
        | if metadata.native.auxiliary_records.iter().any(|record| record.kind == CAPTURE_REPORT_KIND) { CAPTURE_PARTIAL } else { 0 }
        | if metadata.native.auxiliary_records.is_empty() { 0 } else { HAS_AUXILIARY_STREAMS }
        | if metadata.native.required_profiles.iter().chain(&metadata.native.optional_profiles).any(|profile| profile != PORTABLE_PROFILE)
            || !metadata.native.primary_pax_records.is_empty()
            || metadata.native.auxiliary_records.iter().any(|record| record.native)
            || (metadata.created.is_some()
                && !metadata.native.primary_pax_records.contains_key("LIBARCHIVE.creationtime")
                && crate::entry_metadata::source_os_requires_posix_profile(&metadata.source_os))
        {
            HAS_NATIVE_METADATA
        } else {
            0
        }
        | if primary_sparse || metadata.native.auxiliary_records.iter().any(|record| record.flags & 1 != 0) { HAS_SPARSE_EXTENTS } else { 0 }
        | if mode & 0o6000 != 0
            || metadata.posix_owner.is_some()
            || native_metadata_requires_system_restore(&metadata.native, &metadata.source_os)
            || metadata.native.auxiliary_records.iter().any(|record| record.restore_class == RestoreClass::System)
        {
            REQUIRES_SYSTEM_RESTORE
        } else {
            0
        }
}

pub(crate) fn native_metadata_requires_system_restore(native: &NativeFileMetadata, source_os: &str) -> bool {
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
                && std::str::from_utf8(value).ok().and_then(|value| u64::from_str_radix(value, 16).ok()).is_some_and(|flags| flags & 0x30 != 0))
            || (key == "TZAP.bsd.st-flags"
                && std::str::from_utf8(value).ok().and_then(|value| u64::from_str_radix(value, 16).ok()).is_some_and(|flags| flags & 0x0006_0006 != 0))
            || (key == "TZAP.macos.st-flags"
                && std::str::from_utf8(value).ok().and_then(|value| u64::from_str_radix(value, 16).ok()).is_some_and(|flags| flags & 0x009f_0086 != 0))
            || (key == "TZAP.windows.data-stream-attributes"
                && std::str::from_utf8(value).ok().and_then(|value| u32::from_str_radix(value, 16).ok()).is_some_and(|flags| flags & 0x0000_0002 != 0))
            || (key == "SCHILY.fflags"
                && std::str::from_utf8(value)
                    .ok()
                    .is_some_and(|value| value.split(',').any(|token| matches!(token, "append" | "immutable" | "sappnd" | "schg" | "uappnd" | "uchg"))))
    })
}

pub(crate) fn build_ustar_header(path: &[u8], size: u64, mode: u32, mtime: u64, typeflag: u8) -> Result<[u8; TAR_BLOCK_LEN], FormatError> {
    if path.len() > 100 {
        return Err(FormatError::WriterUnsupported("ustar path exceeds name field"));
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

pub(crate) fn finalize_tar_checksum(header: &mut [u8; TAR_BLOCK_LEN]) -> Result<(), FormatError> {
    header[148..156].fill(b' ');
    let checksum = header.iter().map(|byte| *byte as u32).sum::<u32>() as u64;
    write_tar_checksum(&mut header[148..156], checksum)
}

pub(crate) fn write_tar_octal(field: &mut [u8], mut value: u64) -> Result<(), FormatError> {
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

pub(crate) fn tar_octal_fits(field_len: usize, mut value: u64) -> bool {
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

pub(crate) fn write_tar_checksum(field: &mut [u8], mut value: u64) -> Result<(), FormatError> {
    if field.len() < 8 {
        return Err(FormatError::WriterUnsupported("tar checksum field overflow"));
    }
    let mut i = 6;
    while i > 0 {
        i -= 1;
        field[i] = b'0' + (value & 7) as u8;
        value >>= 3;
    }
    if value > 0 {
        return Err(FormatError::WriterUnsupported("tar checksum field overflow"));
    }
    field[6] = 0;
    field[7] = b' ';
    Ok(())
}

pub(crate) fn member_frame_range(member_index: usize, frames: &[PayloadFrame]) -> Result<(u64, u32), FormatError> {
    let first = frames
        .iter()
        .find(|frame| frame.member_index == member_index)
        .map(|frame| frame.frame_index)
        .ok_or(FormatError::WriterInvariant("member frame is missing"))?;
    let count = frames.iter().filter(|frame| frame.member_index == member_index).count();
    Ok((first, u32_len(count, "FileEntry.frame_count")?))
}

pub(crate) fn envelope_frame_range(envelope_index: u64, frames: &[PayloadFrame]) -> Result<(u64, u32), FormatError> {
    let first = frames
        .iter()
        .find(|frame| frame.envelope_index == envelope_index)
        .map(|frame| frame.frame_index)
        .ok_or(FormatError::WriterInvariant("envelope frame is missing"))?;
    let count = frames.iter().filter(|frame| frame.envelope_index == envelope_index).count();
    Ok((first, u32_len(count, "EnvelopeEntry.frame_count")?))
}

pub(crate) fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub(crate) fn padding_to_512(len: usize) -> usize {
    let remainder = len % TAR_BLOCK_LEN;
    if remainder == 0 {
        0
    } else {
        TAR_BLOCK_LEN - remainder
    }
}

pub(crate) fn padding_to_512_u64(len: u64) -> u64 {
    let remainder = len % TAR_BLOCK_LEN as u64;
    if remainder == 0 {
        0
    } else {
        TAR_BLOCK_LEN as u64 - remainder
    }
}

pub(crate) fn table_offset(len: usize, cursor: usize) -> Result<u32, FormatError> {
    if len == 0 {
        Ok(0)
    } else {
        u32_len(cursor, "table offset")
    }
}

pub(crate) fn u32_len(value: usize, field: &'static str) -> Result<u32, FormatError> {
    u32::try_from(value).map_err(|_| FormatError::WriterUnsupported(field))
}

pub(crate) fn to_usize_writer(value: u64, field: &'static str) -> Result<usize, FormatError> {
    usize::try_from(value).map_err(|_| FormatError::WriterUnsupported(field))
}

pub(crate) fn checked_usize_add(lhs: usize, rhs: usize, field: &'static str) -> Result<usize, FormatError> {
    lhs.checked_add(rhs).ok_or(FormatError::WriterUnsupported(field))
}

pub(crate) fn checked_u64_add(lhs: u64, rhs: u64, field: &'static str) -> Result<u64, FormatError> {
    lhs.checked_add(rhs).ok_or(FormatError::WriterUnsupported(field))
}
