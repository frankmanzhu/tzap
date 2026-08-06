use super::*;

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::thread;

use sha2::{Digest, Sha256};

use crate::compression::{decompress_exact_zstd_frame, validate_exact_zstd_frame};
use crate::crypto::{
    decrypt_padded_aead_object, verify_integrity_tag, AeadObjectContext, HmacDomain,
    MasterKey, Subkeys,
};
use crate::fec::repair_data_gf16;
use crate::format::{
    BlockKind, FormatError,
    BLOCK_RECORD_FRAMING_LEN,
    CRITICAL_RECOVERY_LOCATOR_LEN, LOCATOR_PAIR_LEN, VOLUME_HEADER_LEN,
};
use crate::metadata::{
    hash_prefix, DirectoryHintShardEntry, DirectoryHintTable,
    EnvelopeEntry, FileEntry, FrameEntry, IndexRoot, IndexShard, MetadataLimits, ShardEntry,
};
use crate::raw_stream_profile::reject_unsupported_raw_stream_profile;
#[cfg(windows)]
use crate::tar_model::replay_windows_descendant_metadata;
use crate::tar_model::{
    validate_tar_stream_total_extraction_size,
    TarEntryKind, TarStreamTotalExtractionSizeValidator,
};
use crate::wire::{
    BlockRecord, CriticalMetadataImage,
    CryptoHeader, CryptoHeaderFixed, ExtensionTlv, ManifestFooter,
    RootAuthFooterV1, VolumeHeader, VolumeTrailer,
};


#[derive(Debug)]
pub(crate) struct ParsedBlockRegion {
    pub(crate) blocks: BTreeMap<u64, BlockRecord>,
    pub(crate) erased_block_indices: BTreeSet<u64>,
}

pub(crate) fn parse_block_region(
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

pub(crate) fn validate_seekable_block_region_layout(
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

pub(crate) fn parse_public_block_observation(
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

pub(crate) fn block_record_len(block_size: usize) -> Result<u64, FormatError> {
    let len = block_size
        .checked_add(BLOCK_RECORD_FRAMING_LEN)
        .ok_or(FormatError::InvalidArchive("BlockRecord length overflow"))?;
    u64::try_from(len).map_err(|_| FormatError::InvalidArchive("BlockRecord length overflow"))
}

pub(crate) fn checked_u64_mul(lhs: u64, rhs: u64, reason: &'static str) -> Result<u64, FormatError> {
    lhs.checked_mul(rhs)
        .ok_or(FormatError::InvalidArchive(reason))
}

pub(crate) fn parse_stream_block_prefix(
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

pub(crate) fn parse_sequential_block_or_erasure(
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

pub(crate) fn parse_terminal_material(
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

pub(crate) fn terminal_candidate_reaches_eof(
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
pub(crate) struct PendingSequentialEnvelope {
    pub(crate) data_shards: Vec<Option<Vec<u8>>>,
    pub(crate) parity_shards: Vec<Option<Vec<u8>>>,
    pub(crate) saw_last_data: bool,
    pub(crate) awaiting_tentative_parity: bool,
}

impl PendingSequentialEnvelope {
    fn is_empty(&self) -> bool {
        self.data_shards.is_empty() && self.parity_shards.is_empty()
    }
}

pub(crate) fn handle_sequential_payload_erasure(
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

pub(crate) fn sequential_payload_parity_is_guaranteed(crypto_header: &CryptoHeaderFixed) -> bool {
    crypto_header.fec_parity_shards > 0
        && (crypto_header.volume_loss_tolerance > 0 || crypto_header.bit_rot_buffer_pct > 0)
}

pub(crate) fn sequential_extract_tar_stream_with_options(
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

pub(crate) fn validate_sequential_supported_volume(
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

pub(crate) struct SequentialEnvelopeDecodeContext<'a> {
    pub(crate) crypto_header: &'a CryptoHeaderFixed,
    pub(crate) subkeys: &'a Subkeys,
    pub(crate) volume_header: &'a VolumeHeader,
    pub(crate) next_envelope_index: &'a mut u64,
    pub(crate) tar_stream: &'a mut Vec<u8>,
    pub(crate) max_tar_stream_size: usize,
    pub(crate) tar_stream_total_validator: &'a mut TarStreamTotalExtractionSizeValidator,
}

pub(crate) fn finalize_sequential_envelope(
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

pub(crate) fn decode_concatenated_zstd_frames_with_cap(
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

pub(crate) fn read_zstd_frame_to_capped_output<R: Read>(
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

pub(crate) fn load_archive_dictionary(
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
pub(crate) struct ObjectLoadContext<'a> {
    pub(crate) volume_header: &'a VolumeHeader,
    pub(crate) crypto_header: &'a CryptoHeaderFixed,
    pub(crate) extent: ObjectExtent,
    pub(crate) data_kind: BlockKind,
    pub(crate) parity_kind: BlockKind,
    pub(crate) key: &'a [u8; 32],
    pub(crate) nonce_seed: &'a [u8; 32],
    pub(crate) domain: &'a [u8],
    pub(crate) counter: u64,
    pub(crate) class_data_shard_max: u16,
    pub(crate) class_parity_shard_max: u16,
}

impl<'a> ObjectLoadContext<'a> {
    pub(crate) fn index_root(
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

    pub(crate) fn index_shard(
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

    pub(crate) fn directory_hint(
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

    pub(crate) fn payload(
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

pub(crate) fn dictionary_extent_from_index_root(index_root: &IndexRoot) -> Result<ObjectExtent, FormatError> {
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

pub(crate) fn load_metadata_object_from_parts(
    blocks: &impl BlockProvider,
    context: ObjectLoadContext<'_>,
    decompressed_size: u32,
) -> Result<Vec<u8>, FormatError> {
    let compressed = load_decrypted_object_from_parts(blocks, context)?;
    decompress_exact_zstd_frame(&compressed, decompressed_size as usize)
}

pub(crate) fn load_decrypted_object_from_parts(
    blocks: &impl BlockProvider,
    context: ObjectLoadContext<'_>,
) -> Result<Vec<u8>, FormatError> {
    load_decrypted_object_from_parts_with_parity_policy(blocks, context, ParityReadPolicy::Always)
}

pub(crate) fn load_decrypted_object_from_parts_with_parity_policy(
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

pub(crate) fn load_repaired_object_data_shards_from_parts(
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
pub(crate) fn load_repaired_object_data_shards_from_parts_with_parity_policy(
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

pub(crate) fn validate_object_extent(
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

pub(crate) fn ceil_div_u64(numerator: u64, denominator: u64) -> Result<u64, FormatError> {
    if denominator == 0 {
        return Err(FormatError::InvalidArchive("division by zero"));
    }
    numerator
        .checked_add(denominator - 1)
        .ok_or(FormatError::InvalidArchive("ceiling division overflow"))
        .map(|value| value / denominator)
}

pub(crate) fn frame_range_for_file<'b>(
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

pub(crate) fn metadata_limits(crypto_header: &CryptoHeaderFixed) -> MetadataLimits {
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

pub(crate) fn verify_dense_keys<T>(
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

pub(crate) fn validate_envelope_frame_coverage(
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

pub(crate) fn validate_global_file_table_order(shards: &[IndexShard]) -> Result<(), FormatError> {
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

pub(crate) fn validate_global_file_table_key_step(
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

pub(crate) fn validate_file_extent_coverage_ranges(
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

pub(crate) fn add_expected_directory_hint_rows(
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

pub(crate) fn validate_directory_hint_tables_against_expected(
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

pub(crate) fn sorted_directory_hint_rows(map: &DirectoryHintMap) -> Vec<(Vec<u8>, Vec<u32>)> {
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

pub(crate) fn validate_exact_coverage_ranges(
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

pub(crate) fn validate_exact_coverage_ranges_u64(
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

pub(crate) fn object_block_range(
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

pub(crate) fn validate_non_overlapping_object_ranges(ranges: &mut [(u64, u64)]) -> Result<(), FormatError> {
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

pub(crate) fn utf8_path(bytes: &[u8]) -> Result<String, FormatError> {
    std::str::from_utf8(bytes)
        .map(|path| path.to_owned())
        .map_err(|_| FormatError::UnsafeArchivePath)
}

pub(crate) fn manifest_footer_global_pre_hmac_bytes(manifest_footer: &ManifestFooter) -> [u8; 104] {
    let mut bytes = [0u8; 104];
    bytes.copy_from_slice(&manifest_footer.to_bytes()[..104]);
    bytes[36..40].fill(0);
    bytes
}

pub(crate) fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub(crate) fn slice<'b>(
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

pub(crate) fn read_at_vec(
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

pub(crate) fn read_at_vec_unchecked(
    reader: &dyn ArchiveReadAt,
    offset: u64,
    len: usize,
) -> Result<Vec<u8>, FormatError> {
    let mut out = vec![0u8; len];
    reader.read_exact_at(offset, &mut out)?;
    Ok(out)
}

pub(crate) fn parallel_map_ref<T, U, F>(items: &[T], jobs: usize, f: F) -> Result<Vec<U>, FormatError>
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

pub(crate) fn checked_add(lhs: usize, rhs: usize, structure: &'static str) -> Result<usize, FormatError> {
    lhs.checked_add(rhs)
        .ok_or(FormatError::InvalidArchive(structure))
}

pub(crate) fn checked_u64_add(lhs: u64, rhs: u64, structure: &'static str) -> Result<u64, FormatError> {
    lhs.checked_add(rhs)
        .ok_or(FormatError::InvalidArchive(structure))
}

pub(crate) fn to_usize(value: u64, structure: &'static str) -> Result<usize, FormatError> {
    usize::try_from(value).map_err(|_| FormatError::InvalidArchive(structure))
}

