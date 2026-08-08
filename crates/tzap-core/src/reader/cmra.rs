use super::*;

use crate::crypto::{verify_integrity_tag, HmacDomain, KdfParams, MasterKey, Subkeys};
use crate::fec::repair_data_gf16;
use crate::format::{
    FormatError, BLOCK_RECORD_FRAMING_LEN, CRITICAL_METADATA_IMAGE_FIXED_LEN, CRITICAL_METADATA_RECOVERY_HEADER_LEN,
    CRITICAL_METADATA_RECOVERY_SHARD_HEADER_LEN, CRITICAL_RECOVERY_LOCATOR_LEN, CRYPTO_HEADER_HMAC_LEN, IMAGE_CRC_LEN, LOCATOR_PAIR_LEN, MANIFEST_FOOTER_LEN,
    READER_MAX_CMRA_PARITY_PCT, READER_MAX_CRYPTO_HEADER_LEN, READER_MAX_KEY_WRAP_TABLE_LEN, READER_MAX_ROOT_AUTH_FOOTER_LEN, SERIALIZED_REGION_HEADER_LEN,
    VOLUME_HEADER_LEN, VOLUME_TRAILER_LEN,
};
use crate::raw_stream_profile::reject_unsupported_raw_stream_profile;
use crate::wire::{
    compute_key_wrap_table_digest, CriticalMetadataImage, CriticalMetadataRecoveryHeader, CriticalMetadataRecoveryShard, CriticalRecoveryLocator, CryptoHeader,
    CryptoHeaderFixed, KeyWrapTableV1, ManifestFooter, RootAuthFooterV1, VolumeHeader, VolumeTrailer,
};

#[derive(Debug)]
pub(crate) struct V45Terminal {
    pub(crate) image: CriticalMetadataImage,
    pub(crate) manifest_footer_bytes: Vec<u8>,
    pub(crate) root_auth_footer_bytes: Option<Vec<u8>>,
    pub(crate) root_auth_footer: Option<RootAuthFooterV1>,
    pub(crate) volume_trailer: VolumeTrailer,
}

pub(crate) struct SequentialTerminalMaterial {
    pub(crate) manifest_footer: ManifestFooter,
    pub(crate) volume_trailer: VolumeTrailer,
    pub(crate) root_auth_footer: Option<RootAuthFooterV1>,
}

#[derive(Debug)]
pub(crate) struct V45PublicTerminal {
    pub(crate) image: CriticalMetadataImage,
    pub(crate) root_auth_footer_bytes: Vec<u8>,
    pub(crate) root_auth_footer: RootAuthFooterV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CmraDecoderTuple {
    pub(crate) shard_size: u32,
    pub(crate) data_shard_count: u16,
    pub(crate) parity_shard_count: u16,
    pub(crate) image_length: u32,
    pub(crate) image_sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CmraIdentityHints {
    pub(crate) archive_uuid: [u8; 16],
    pub(crate) session_id: [u8; 16],
    pub(crate) volume_index: u32,
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
pub(crate) struct RecoveredCmra {
    pub(crate) image: CriticalMetadataImage,
    pub(crate) tuple: CmraDecoderTuple,
    pub(crate) header_hints: Option<CmraIdentityHints>,
    pub(crate) cmra_length: u64,
}

#[derive(Debug)]
pub(crate) struct TerminalCandidate {
    pub(crate) terminal: V45Terminal,
    pub(crate) anchor: usize,
    pub(crate) locator_sequence: Option<u32>,
    pub(crate) cmra_offset: u64,
    pub(crate) cmra_length: u64,
}

#[derive(Debug)]
pub(crate) struct PublicTerminalCandidate {
    pub(crate) terminal: V45PublicTerminal,
    pub(crate) anchor: usize,
    pub(crate) cmra_offset: u64,
    pub(crate) cmra_length: u64,
}

#[derive(Debug)]
pub(crate) struct RecoveredTerminalAuthority {
    pub(crate) terminal: V45Terminal,
    pub(crate) volume_header: VolumeHeader,
    pub(crate) crypto_header: CryptoHeaderFixed,
    pub(crate) crypto_header_bytes: Vec<u8>,
    pub(crate) subkeys: Subkeys,
    pub(crate) kdf_params: KdfParams,
}

#[derive(Debug)]
pub(crate) struct RecoveredRecipientWrapTerminalAuthority {
    pub(crate) terminal: V45Terminal,
    pub(crate) volume_header: VolumeHeader,
    pub(crate) crypto_header: CryptoHeaderFixed,
    pub(crate) crypto_header_bytes: Vec<u8>,
    pub(crate) key_wrap_table_bytes: Vec<u8>,
    pub(crate) block_records_start: u64,
    pub(crate) subkeys: Subkeys,
}

#[derive(Debug)]
pub(crate) struct TerminalAuthorityCandidate {
    pub(crate) authority: RecoveredTerminalAuthority,
    pub(crate) anchor: usize,
    pub(crate) cmra_offset: u64,
    pub(crate) cmra_length: u64,
}

#[derive(Debug)]
pub(crate) struct RecipientWrapTerminalAuthorityCandidate {
    pub(crate) authority: RecoveredRecipientWrapTerminalAuthority,
    pub(crate) anchor: usize,
    pub(crate) cmra_offset: u64,
    pub(crate) cmra_length: u64,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum CmraRecoveryMode {
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

pub(crate) fn locate_v45_terminal(bytes: &[u8], context: KeyHoldingTerminalContext<'_>, options: ReaderOptions) -> Result<V45Terminal, FormatError> {
    locate_v45_terminal_candidate(bytes, context, options).map(|candidate| candidate.terminal)
}

pub(crate) fn locate_v45_terminal_read_at(
    reader: &dyn ArchiveReadAt,
    len: u64,
    context: KeyHoldingTerminalContext<'_>,
    options: ReaderOptions,
) -> Result<V45Terminal, FormatError> {
    let mut candidates = Vec::new();
    if len >= CRITICAL_RECOVERY_LOCATOR_LEN as u64 {
        let final_offset = len - CRITICAL_RECOVERY_LOCATOR_LEN as u64;
        collect_v45_locator_candidate_read_at(reader, final_offset, 0, context, &mut candidates);
    }
    if len >= LOCATOR_PAIR_LEN as u64 {
        let mirror_offset = len - LOCATOR_PAIR_LEN as u64;
        collect_v45_locator_candidate_read_at(reader, mirror_offset, 1, context, &mut candidates);
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
                collect_v45_locator_candidate_read_at(reader, absolute_offset, 2, context, &mut candidates);
            } else if tail.get(offset..offset + 4) == Some(b"TZCR") {
                if let Ok(candidate) = parse_locatorless_cmra_candidate_read_at(reader, absolute_offset, context) {
                    candidates.push(candidate);
                }
            }
            if offset == 0 {
                break;
            }
            offset -= 1;
        }
    }

    choose_v45_terminal_candidate(candidates).map(|candidate| candidate.terminal)
}

pub(crate) fn locate_v45_terminal_authority(bytes: &[u8], master_key: &MasterKey, options: ReaderOptions) -> Result<RecoveredTerminalAuthority, FormatError> {
    let mut candidates = Vec::new();
    if bytes.len() >= CRITICAL_RECOVERY_LOCATOR_LEN {
        let final_offset = bytes.len() - CRITICAL_RECOVERY_LOCATOR_LEN;
        collect_v45_locator_authority_candidate(bytes, final_offset, 0, master_key, &mut candidates);
    }
    if bytes.len() >= LOCATOR_PAIR_LEN {
        let mirror_offset = bytes.len() - LOCATOR_PAIR_LEN;
        collect_v45_locator_authority_candidate(bytes, mirror_offset, 1, master_key, &mut candidates);
    }

    if candidates.is_empty() {
        let scan = max_critical_recovery_scan(options)?;
        let scan_start = bytes.len().saturating_sub(scan);
        let mut offset = bytes.len().saturating_sub(4);
        while offset >= scan_start {
            if bytes.get(offset..offset + 4) == Some(b"TZCL") {
                collect_v45_locator_authority_candidate(bytes, offset, 2, master_key, &mut candidates);
            } else if bytes.get(offset..offset + 4) == Some(b"TZCR") {
                if let Ok(candidate) = parse_locatorless_cmra_authority_candidate(bytes, offset, master_key) {
                    candidates.push(candidate);
                }
            }
            if offset == 0 {
                break;
            }
            offset -= 1;
        }
    }

    choose_v45_terminal_authority_candidate(candidates).map(|candidate| candidate.authority)
}

pub(crate) fn locate_v45_recipient_wrap_terminal_authority<F>(
    bytes: &[u8],
    resolver: &mut F,
    options: ReaderOptions,
) -> Result<RecoveredRecipientWrapTerminalAuthority, FormatError>
where
    F: FnMut(RecipientWrapRecordContext<'_>) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
{
    let mut candidates = Vec::new();
    if bytes.len() >= CRITICAL_RECOVERY_LOCATOR_LEN {
        let final_offset = bytes.len() - CRITICAL_RECOVERY_LOCATOR_LEN;
        collect_v45_recipient_wrap_locator_authority_candidate(bytes, final_offset, 0, resolver, &mut candidates);
    }
    if bytes.len() >= LOCATOR_PAIR_LEN {
        let mirror_offset = bytes.len() - LOCATOR_PAIR_LEN;
        collect_v45_recipient_wrap_locator_authority_candidate(bytes, mirror_offset, 1, resolver, &mut candidates);
    }

    if candidates.is_empty() {
        let scan = max_critical_recovery_scan(options)?;
        let scan_start = bytes.len().saturating_sub(scan);
        let mut offset = bytes.len().saturating_sub(4);
        while offset >= scan_start {
            if bytes.get(offset..offset + 4) == Some(b"TZCL") {
                collect_v45_recipient_wrap_locator_authority_candidate(bytes, offset, 2, resolver, &mut candidates);
            } else if bytes.get(offset..offset + 4) == Some(b"TZCR") {
                if let Ok(candidate) = parse_locatorless_cmra_recipient_wrap_authority_candidate(bytes, offset, resolver) {
                    candidates.push(candidate);
                }
            }
            if offset == 0 {
                break;
            }
            offset -= 1;
        }
    }

    choose_v45_recipient_wrap_terminal_authority_candidate(candidates).map(|candidate| candidate.authority)
}

pub(crate) fn locate_v45_recipient_wrap_terminal_authority_read_at<F>(
    reader: &dyn ArchiveReadAt,
    len: u64,
    resolver: &mut F,
    options: ReaderOptions,
) -> Result<RecoveredRecipientWrapTerminalAuthority, FormatError>
where
    F: FnMut(RecipientWrapRecordContext<'_>) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
{
    let mut candidates = Vec::new();
    if len >= CRITICAL_RECOVERY_LOCATOR_LEN as u64 {
        let final_offset = len - CRITICAL_RECOVERY_LOCATOR_LEN as u64;
        collect_v45_recipient_wrap_locator_authority_candidate_read_at(reader, final_offset, 0, resolver, &mut candidates);
    }
    if len >= LOCATOR_PAIR_LEN as u64 {
        let mirror_offset = len - LOCATOR_PAIR_LEN as u64;
        collect_v45_recipient_wrap_locator_authority_candidate_read_at(reader, mirror_offset, 1, resolver, &mut candidates);
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
                collect_v45_recipient_wrap_locator_authority_candidate_read_at(reader, absolute_offset, 2, resolver, &mut candidates);
            } else if tail.get(offset..offset + 4) == Some(b"TZCR") {
                if let Ok(candidate) = parse_locatorless_cmra_recipient_wrap_authority_candidate_read_at(reader, absolute_offset, resolver) {
                    candidates.push(candidate);
                }
            }
            if offset == 0 {
                break;
            }
            offset -= 1;
        }
    }

    choose_v45_recipient_wrap_terminal_authority_candidate(candidates).map(|candidate| candidate.authority)
}

pub(crate) fn locate_v45_terminal_authority_read_at(
    reader: &dyn ArchiveReadAt,
    len: u64,
    master_key: &MasterKey,
    options: ReaderOptions,
) -> Result<RecoveredTerminalAuthority, FormatError> {
    let mut candidates = Vec::new();
    if len >= CRITICAL_RECOVERY_LOCATOR_LEN as u64 {
        let final_offset = len - CRITICAL_RECOVERY_LOCATOR_LEN as u64;
        collect_v45_locator_authority_candidate_read_at(reader, final_offset, 0, master_key, &mut candidates);
    }
    if len >= LOCATOR_PAIR_LEN as u64 {
        let mirror_offset = len - LOCATOR_PAIR_LEN as u64;
        collect_v45_locator_authority_candidate_read_at(reader, mirror_offset, 1, master_key, &mut candidates);
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
                collect_v45_locator_authority_candidate_read_at(reader, absolute_offset, 2, master_key, &mut candidates);
            } else if tail.get(offset..offset + 4) == Some(b"TZCR") {
                if let Ok(candidate) = parse_locatorless_cmra_authority_candidate_read_at(reader, absolute_offset, master_key) {
                    candidates.push(candidate);
                }
            }
            if offset == 0 {
                break;
            }
            offset -= 1;
        }
    }

    choose_v45_terminal_authority_candidate(candidates).map(|candidate| candidate.authority)
}

pub(crate) fn locate_v45_terminal_candidate(
    bytes: &[u8],
    context: KeyHoldingTerminalContext<'_>,
    options: ReaderOptions,
) -> Result<TerminalCandidate, FormatError> {
    let mut candidates = Vec::new();
    if bytes.len() >= CRITICAL_RECOVERY_LOCATOR_LEN {
        let final_offset = bytes.len() - CRITICAL_RECOVERY_LOCATOR_LEN;
        collect_v45_locator_candidate(bytes, final_offset, 0, context, &mut candidates);
    }
    if bytes.len() >= LOCATOR_PAIR_LEN {
        let mirror_offset = bytes.len() - LOCATOR_PAIR_LEN;
        collect_v45_locator_candidate(bytes, mirror_offset, 1, context, &mut candidates);
    }

    if candidates.is_empty() {
        let scan = max_critical_recovery_scan(options)?;
        let scan_start = bytes.len().saturating_sub(scan);
        let mut offset = bytes.len().saturating_sub(4);
        while offset >= scan_start {
            if bytes.get(offset..offset + 4) == Some(b"TZCL") {
                collect_v45_locator_candidate(bytes, offset, 2, context, &mut candidates);
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

    choose_v45_terminal_candidate(candidates)
}

pub(crate) fn locate_v45_public_terminal(
    bytes: &[u8],
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeader<'_>,
    options: ReaderOptions,
) -> Result<V45PublicTerminal, FormatError> {
    let mut candidates = Vec::new();
    if bytes.len() >= CRITICAL_RECOVERY_LOCATOR_LEN {
        let final_offset = bytes.len() - CRITICAL_RECOVERY_LOCATOR_LEN;
        collect_v45_public_locator_candidate(bytes, final_offset, 0, volume_header, crypto_header, &mut candidates);
    }
    if bytes.len() >= LOCATOR_PAIR_LEN {
        let mirror_offset = bytes.len() - LOCATOR_PAIR_LEN;
        collect_v45_public_locator_candidate(bytes, mirror_offset, 1, volume_header, crypto_header, &mut candidates);
    }

    if candidates.is_empty() {
        let scan = max_critical_recovery_scan(options)?;
        let scan_start = bytes.len().saturating_sub(scan);
        let mut offset = bytes.len().saturating_sub(4);
        while offset >= scan_start {
            if bytes.get(offset..offset + 4) == Some(b"TZCL") {
                collect_v45_public_locator_candidate(bytes, offset, 2, volume_header, crypto_header, &mut candidates);
            } else if bytes.get(offset..offset + 4) == Some(b"TZCR") {
                if let Ok(candidate) = parse_public_locatorless_cmra_candidate(bytes, offset, volume_header, crypto_header) {
                    candidates.push(candidate);
                }
            }
            if offset == 0 {
                break;
            }
            offset -= 1;
        }
    }

    choose_v45_public_terminal_candidate(candidates).map(|candidate| candidate.terminal)
}

pub(crate) fn locate_v45_public_terminal_read_at(
    reader: &dyn ArchiveReadAt,
    len: u64,
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeader<'_>,
    options: ReaderOptions,
) -> Result<V45PublicTerminal, FormatError> {
    let mut candidates = Vec::new();
    if len >= CRITICAL_RECOVERY_LOCATOR_LEN as u64 {
        let final_offset = len - CRITICAL_RECOVERY_LOCATOR_LEN as u64;
        collect_v45_public_locator_candidate_read_at(reader, final_offset, 0, volume_header, crypto_header, &mut candidates);
    }
    if len >= LOCATOR_PAIR_LEN as u64 {
        let mirror_offset = len - LOCATOR_PAIR_LEN as u64;
        collect_v45_public_locator_candidate_read_at(reader, mirror_offset, 1, volume_header, crypto_header, &mut candidates);
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
                collect_v45_public_locator_candidate_read_at(reader, absolute_offset, 2, volume_header, crypto_header, &mut candidates);
            } else if tail.get(offset..offset + 4) == Some(b"TZCR") {
                if let Ok(candidate) = parse_public_locatorless_cmra_candidate_read_at(reader, absolute_offset, volume_header, crypto_header) {
                    candidates.push(candidate);
                }
            }
            if offset == 0 {
                break;
            }
            offset -= 1;
        }
    }

    choose_v45_public_terminal_candidate(candidates).map(|candidate| candidate.terminal)
}

/// Recovers the terminal image's `layout_flags` without validating the public
/// terminal, to distinguish an unsigned archive (root-auth flag clear) from a
/// corrupt one (no recoverable image). Bounded: reads only the final/mirror
/// critical-recovery locator and the CMRA image. Returns `Ok(None)` when no
/// matching locator or recoverable image exists.
pub(crate) fn public_no_key_layout_flags(reader: &dyn ArchiveReadAt, len: u64) -> Result<Option<u32>, FormatError> {
    if len >= CRITICAL_RECOVERY_LOCATOR_LEN as u64 {
        let final_offset = len - CRITICAL_RECOVERY_LOCATOR_LEN as u64;
        if let Some(flags) = public_no_key_layout_flags_at(reader, final_offset, 0)? {
            return Ok(Some(flags));
        }
    }
    if len >= LOCATOR_PAIR_LEN as u64 {
        let mirror_offset = len - LOCATOR_PAIR_LEN as u64;
        if let Some(flags) = public_no_key_layout_flags_at(reader, mirror_offset, 1)? {
            return Ok(Some(flags));
        }
    }
    Ok(None)
}

fn public_no_key_layout_flags_at(reader: &dyn ArchiveReadAt, offset: u64, expected_sequence: u32) -> Result<Option<u32>, FormatError> {
    let Ok(raw) = read_at_vec(reader, offset, CRITICAL_RECOVERY_LOCATOR_LEN, "CriticalRecoveryLocator") else {
        return Ok(None);
    };
    let Ok(locator) = CriticalRecoveryLocator::parse(&raw) else {
        return Ok(None);
    };
    if locator.locator_sequence != expected_sequence {
        return Ok(None);
    }
    let tuple = CmraDecoderTuple::from(locator);
    let Ok(recovered) = recover_cmra_read_at(reader, locator.cmra_offset, Some(tuple), CmraRecoveryMode::PublicNoKey) else {
        return Ok(None);
    };
    Ok(Some(recovered.image.layout_flags))
}

pub(crate) fn collect_v45_locator_candidate(
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

pub(crate) fn collect_v45_locator_candidate_read_at(
    reader: &dyn ArchiveReadAt,
    offset: u64,
    expected_sequence: u32,
    context: KeyHoldingTerminalContext<'_>,
    candidates: &mut Vec<TerminalCandidate>,
) {
    let Ok(raw) = read_at_vec(reader, offset, CRITICAL_RECOVERY_LOCATOR_LEN, "CriticalRecoveryLocator") else {
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

pub(crate) fn collect_v45_locator_authority_candidate(
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
    if let Ok(candidate) = parse_locator_cmra_authority_candidate(bytes, offset, locator, master_key) {
        candidates.push(candidate);
    }
}

pub(crate) fn collect_v45_recipient_wrap_locator_authority_candidate<F>(
    bytes: &[u8],
    offset: usize,
    expected_sequence: u32,
    resolver: &mut F,
    candidates: &mut Vec<RecipientWrapTerminalAuthorityCandidate>,
) where
    F: FnMut(RecipientWrapRecordContext<'_>) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
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
    if let Ok(candidate) = parse_locator_cmra_recipient_wrap_authority_candidate(bytes, offset, locator, resolver) {
        candidates.push(candidate);
    }
}

pub(crate) fn collect_v45_recipient_wrap_locator_authority_candidate_read_at<F>(
    reader: &dyn ArchiveReadAt,
    offset: u64,
    expected_sequence: u32,
    resolver: &mut F,
    candidates: &mut Vec<RecipientWrapTerminalAuthorityCandidate>,
) where
    F: FnMut(RecipientWrapRecordContext<'_>) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
{
    let Ok(raw) = read_at_vec(reader, offset, CRITICAL_RECOVERY_LOCATOR_LEN, "CriticalRecoveryLocator") else {
        return;
    };
    let Ok(locator) = CriticalRecoveryLocator::parse(&raw) else {
        return;
    };
    if expected_sequence <= 1 && locator.locator_sequence != expected_sequence {
        return;
    }
    if let Ok(candidate) = parse_locator_cmra_recipient_wrap_authority_candidate_read_at(reader, offset, locator, resolver) {
        candidates.push(candidate);
    }
}

pub(crate) fn collect_v45_locator_authority_candidate_read_at(
    reader: &dyn ArchiveReadAt,
    offset: u64,
    expected_sequence: u32,
    master_key: &MasterKey,
    candidates: &mut Vec<TerminalAuthorityCandidate>,
) {
    let Ok(raw) = read_at_vec(reader, offset, CRITICAL_RECOVERY_LOCATOR_LEN, "CriticalRecoveryLocator") else {
        return;
    };
    let Ok(locator) = CriticalRecoveryLocator::parse(&raw) else {
        return;
    };
    if expected_sequence <= 1 && locator.locator_sequence != expected_sequence {
        return;
    }
    if let Ok(candidate) = parse_locator_cmra_authority_candidate_read_at(reader, offset, locator, master_key) {
        candidates.push(candidate);
    }
}

pub(crate) fn collect_v45_public_locator_candidate(
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
    if let Ok(candidate) = parse_public_locator_cmra_candidate(bytes, offset, locator, volume_header, crypto_header) {
        candidates.push(candidate);
    }
}

pub(crate) fn collect_v45_public_locator_candidate_read_at(
    reader: &dyn ArchiveReadAt,
    offset: u64,
    expected_sequence: u32,
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeader<'_>,
    candidates: &mut Vec<PublicTerminalCandidate>,
) {
    let Ok(raw) = read_at_vec(reader, offset, CRITICAL_RECOVERY_LOCATOR_LEN, "CriticalRecoveryLocator") else {
        return;
    };
    let Ok(locator) = CriticalRecoveryLocator::parse(&raw) else {
        return;
    };
    if expected_sequence <= 1 && locator.locator_sequence != expected_sequence {
        return;
    }
    if let Ok(candidate) = parse_public_locator_cmra_candidate_read_at(reader, offset, locator, volume_header, crypto_header) {
        candidates.push(candidate);
    }
}

pub(crate) fn choose_v45_terminal_candidate(mut candidates: Vec<TerminalCandidate>) -> Result<TerminalCandidate, FormatError> {
    candidates.sort_by_key(|candidate| candidate.anchor);
    let winner = candidates.pop().ok_or(FormatError::InvalidArchive("no valid v45 CMRA candidate found"))?;
    if let Some(previous) = candidates.last() {
        if previous.anchor == winner.anchor && (previous.cmra_offset != winner.cmra_offset || previous.cmra_length != winner.cmra_length) {
            return Err(FormatError::InvalidArchive("ambiguous v45 CMRA candidates"));
        }
    }
    Ok(winner)
}

pub(crate) fn choose_v45_terminal_authority_candidate(mut candidates: Vec<TerminalAuthorityCandidate>) -> Result<TerminalAuthorityCandidate, FormatError> {
    candidates.sort_by_key(|candidate| candidate.anchor);
    let winner = candidates.pop().ok_or(FormatError::InvalidArchive("no valid v45 CMRA candidate found"))?;
    if let Some(previous) = candidates.last() {
        if previous.anchor == winner.anchor && (previous.cmra_offset != winner.cmra_offset || previous.cmra_length != winner.cmra_length) {
            return Err(FormatError::InvalidArchive("ambiguous v45 CMRA candidates"));
        }
    }
    Ok(winner)
}

pub(crate) fn choose_v45_recipient_wrap_terminal_authority_candidate(
    mut candidates: Vec<RecipientWrapTerminalAuthorityCandidate>,
) -> Result<RecipientWrapTerminalAuthorityCandidate, FormatError> {
    candidates.sort_by_key(|candidate| candidate.anchor);
    let winner = candidates.pop().ok_or(FormatError::InvalidArchive("no valid v45 CMRA candidate found"))?;
    if let Some(previous) = candidates.last() {
        if previous.anchor == winner.anchor && (previous.cmra_offset != winner.cmra_offset || previous.cmra_length != winner.cmra_length) {
            return Err(FormatError::InvalidArchive("ambiguous v45 CMRA candidates"));
        }
    }
    Ok(winner)
}

pub(crate) fn choose_v45_public_terminal_candidate(mut candidates: Vec<PublicTerminalCandidate>) -> Result<PublicTerminalCandidate, FormatError> {
    candidates.sort_by_key(|candidate| candidate.anchor);
    let winner = candidates
        .pop()
        .ok_or(FormatError::InvalidArchive("no valid v45 public CMRA candidate found"))?;
    if let Some(previous) = candidates.last() {
        if previous.anchor == winner.anchor && (previous.cmra_offset != winner.cmra_offset || previous.cmra_length != winner.cmra_length) {
            return Err(FormatError::InvalidArchive("ambiguous v45 public CMRA candidates"));
        }
    }
    Ok(winner)
}

pub(crate) fn parse_locator_cmra_candidate(
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
    let recovered = recover_cmra(bytes, locator.cmra_offset, Some(tuple), CmraRecoveryMode::KeyHolding)?;
    if recovered.tuple != tuple {
        return Err(FormatError::InvalidArchive("CMRA decoder tuple mismatch"));
    }
    if expected_cmra_length != recovered.cmra_length {
        return Err(FormatError::InvalidArchive("locator CMRA length mismatch"));
    }
    validate_locator_image_boundary(locator, &recovered.image)?;
    validate_cmra_identity_hints(recovered.header_hints, Some(CmraIdentityHints::from(locator)), &recovered.image)?;
    let terminal = validate_recovered_terminal(recovered.image, recovered.tuple, bytes, context, false)?;
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

pub(crate) fn parse_locator_cmra_candidate_read_at(
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
    validate_locator_position(to_usize(locator_offset, "CriticalRecoveryLocator")?, locator)?;
    let recovered = recover_cmra_read_at(reader, locator.cmra_offset, Some(tuple), CmraRecoveryMode::KeyHolding)?;
    if recovered.tuple != tuple {
        return Err(FormatError::InvalidArchive("CMRA decoder tuple mismatch"));
    }
    if expected_cmra_length != recovered.cmra_length {
        return Err(FormatError::InvalidArchive("locator CMRA length mismatch"));
    }
    validate_locator_image_boundary(locator, &recovered.image)?;
    validate_cmra_identity_hints(recovered.header_hints, Some(CmraIdentityHints::from(locator)), &recovered.image)?;
    let terminal = validate_recovered_terminal_read_at(recovered.image, recovered.tuple, reader, context, false)?;
    Ok(TerminalCandidate {
        terminal,
        anchor: to_usize(
            checked_u64_add(locator_offset, CRITICAL_RECOVERY_LOCATOR_LEN as u64, "locator anchor overflow")?,
            "locator anchor overflow",
        )?,
        locator_sequence: Some(locator.locator_sequence),
        cmra_offset: locator.cmra_offset,
        cmra_length: recovered.cmra_length,
    })
}

pub(crate) fn parse_locator_cmra_authority_candidate(
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
    let recovered = recover_cmra(bytes, locator.cmra_offset, Some(tuple), CmraRecoveryMode::KeyHolding)?;
    if recovered.tuple != tuple {
        return Err(FormatError::InvalidArchive("CMRA decoder tuple mismatch"));
    }
    if expected_cmra_length != recovered.cmra_length {
        return Err(FormatError::InvalidArchive("locator CMRA length mismatch"));
    }
    validate_locator_image_boundary(locator, &recovered.image)?;
    validate_cmra_identity_hints(recovered.header_hints, Some(CmraIdentityHints::from(locator)), &recovered.image)?;
    let cmra_length = recovered.cmra_length;
    let authority = validate_recovered_terminal_authority(recovered.image, recovered.tuple, master_key, false)?;
    Ok(TerminalAuthorityCandidate {
        authority,
        anchor: locator_offset
            .checked_add(CRITICAL_RECOVERY_LOCATOR_LEN)
            .ok_or(FormatError::InvalidArchive("locator anchor overflow"))?,
        cmra_offset: locator.cmra_offset,
        cmra_length,
    })
}

pub(crate) fn parse_locator_cmra_recipient_wrap_authority_candidate<F>(
    bytes: &[u8],
    locator_offset: usize,
    locator: CriticalRecoveryLocator,
    resolver: &mut F,
) -> Result<RecipientWrapTerminalAuthorityCandidate, FormatError>
where
    F: FnMut(RecipientWrapRecordContext<'_>) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
{
    let tuple = CmraDecoderTuple::from(locator);
    validate_cmra_decoder_tuple(tuple)?;
    let expected_cmra_length = cmra_serialized_length(tuple)?;
    if locator.cmra_length as u64 != expected_cmra_length {
        return Err(FormatError::InvalidArchive("locator CMRA length mismatch"));
    }
    validate_locator_position(locator_offset, locator)?;
    let recovered = recover_cmra(bytes, locator.cmra_offset, Some(tuple), CmraRecoveryMode::KeyHolding)?;
    if recovered.tuple != tuple {
        return Err(FormatError::InvalidArchive("CMRA decoder tuple mismatch"));
    }
    if expected_cmra_length != recovered.cmra_length {
        return Err(FormatError::InvalidArchive("locator CMRA length mismatch"));
    }
    validate_locator_image_boundary(locator, &recovered.image)?;
    validate_cmra_identity_hints(recovered.header_hints, Some(CmraIdentityHints::from(locator)), &recovered.image)?;
    let cmra_length = recovered.cmra_length;
    let authority = validate_recovered_recipient_wrap_terminal_authority(recovered.image, recovered.tuple, resolver, false)?;
    Ok(RecipientWrapTerminalAuthorityCandidate {
        authority,
        anchor: locator_offset
            .checked_add(CRITICAL_RECOVERY_LOCATOR_LEN)
            .ok_or(FormatError::InvalidArchive("locator anchor overflow"))?,
        cmra_offset: locator.cmra_offset,
        cmra_length,
    })
}

pub(crate) fn parse_locator_cmra_recipient_wrap_authority_candidate_read_at<F>(
    reader: &dyn ArchiveReadAt,
    locator_offset: u64,
    locator: CriticalRecoveryLocator,
    resolver: &mut F,
) -> Result<RecipientWrapTerminalAuthorityCandidate, FormatError>
where
    F: FnMut(RecipientWrapRecordContext<'_>) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
{
    let tuple = CmraDecoderTuple::from(locator);
    validate_cmra_decoder_tuple(tuple)?;
    let expected_cmra_length = cmra_serialized_length(tuple)?;
    if locator.cmra_length as u64 != expected_cmra_length {
        return Err(FormatError::InvalidArchive("locator CMRA length mismatch"));
    }
    validate_locator_position(to_usize(locator_offset, "CriticalRecoveryLocator")?, locator)?;
    let recovered = recover_cmra_read_at(reader, locator.cmra_offset, Some(tuple), CmraRecoveryMode::KeyHolding)?;
    if recovered.tuple != tuple {
        return Err(FormatError::InvalidArchive("CMRA decoder tuple mismatch"));
    }
    if expected_cmra_length != recovered.cmra_length {
        return Err(FormatError::InvalidArchive("locator CMRA length mismatch"));
    }
    validate_locator_image_boundary(locator, &recovered.image)?;
    validate_cmra_identity_hints(recovered.header_hints, Some(CmraIdentityHints::from(locator)), &recovered.image)?;
    let cmra_length = recovered.cmra_length;
    let authority = validate_recovered_recipient_wrap_terminal_authority(recovered.image, recovered.tuple, resolver, false)?;
    Ok(RecipientWrapTerminalAuthorityCandidate {
        authority,
        anchor: to_usize(
            checked_u64_add(locator_offset, CRITICAL_RECOVERY_LOCATOR_LEN as u64, "locator anchor overflow")?,
            "locator anchor overflow",
        )?,
        cmra_offset: locator.cmra_offset,
        cmra_length,
    })
}

pub(crate) fn parse_locator_cmra_authority_candidate_read_at(
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
    validate_locator_position(to_usize(locator_offset, "CriticalRecoveryLocator")?, locator)?;
    let recovered = recover_cmra_read_at(reader, locator.cmra_offset, Some(tuple), CmraRecoveryMode::KeyHolding)?;
    if recovered.tuple != tuple {
        return Err(FormatError::InvalidArchive("CMRA decoder tuple mismatch"));
    }
    if expected_cmra_length != recovered.cmra_length {
        return Err(FormatError::InvalidArchive("locator CMRA length mismatch"));
    }
    validate_locator_image_boundary(locator, &recovered.image)?;
    validate_cmra_identity_hints(recovered.header_hints, Some(CmraIdentityHints::from(locator)), &recovered.image)?;
    let cmra_length = recovered.cmra_length;
    let authority = validate_recovered_terminal_authority(recovered.image, recovered.tuple, master_key, false)?;
    Ok(TerminalAuthorityCandidate {
        authority,
        anchor: to_usize(
            checked_u64_add(locator_offset, CRITICAL_RECOVERY_LOCATOR_LEN as u64, "locator anchor overflow")?,
            "locator anchor overflow",
        )?,
        cmra_offset: locator.cmra_offset,
        cmra_length,
    })
}

pub(crate) fn parse_public_locator_cmra_candidate(
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
    let recovered = recover_cmra(bytes, locator.cmra_offset, Some(tuple), CmraRecoveryMode::PublicNoKey)?;
    if recovered.tuple != tuple {
        return Err(FormatError::InvalidArchive("CMRA decoder tuple mismatch"));
    }
    if expected_cmra_length != recovered.cmra_length {
        return Err(FormatError::InvalidArchive("locator CMRA length mismatch"));
    }
    validate_locator_image_boundary(locator, &recovered.image)?;
    validate_cmra_identity_hints(recovered.header_hints, Some(CmraIdentityHints::from(locator)), &recovered.image)?;
    let terminal = validate_recovered_public_terminal(recovered.image, bytes, volume_header, crypto_header, false)?;
    Ok(PublicTerminalCandidate {
        terminal,
        anchor: locator_offset
            .checked_add(CRITICAL_RECOVERY_LOCATOR_LEN)
            .ok_or(FormatError::InvalidArchive("locator anchor overflow"))?,
        cmra_offset: locator.cmra_offset,
        cmra_length: recovered.cmra_length,
    })
}

pub(crate) fn parse_public_locator_cmra_candidate_read_at(
    reader: &dyn ArchiveReadAt,
    locator_offset: u64,
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
    validate_locator_position(to_usize(locator_offset, "CriticalRecoveryLocator")?, locator)?;
    let recovered = recover_cmra_read_at(reader, locator.cmra_offset, Some(tuple), CmraRecoveryMode::PublicNoKey)?;
    if recovered.tuple != tuple {
        return Err(FormatError::InvalidArchive("CMRA decoder tuple mismatch"));
    }
    if expected_cmra_length != recovered.cmra_length {
        return Err(FormatError::InvalidArchive("locator CMRA length mismatch"));
    }
    validate_locator_image_boundary(locator, &recovered.image)?;
    validate_cmra_identity_hints(recovered.header_hints, Some(CmraIdentityHints::from(locator)), &recovered.image)?;
    let terminal = validate_recovered_public_terminal_read_at(recovered.image, reader, volume_header, crypto_header, false)?;
    Ok(PublicTerminalCandidate {
        terminal,
        anchor: to_usize(
            checked_u64_add(locator_offset, CRITICAL_RECOVERY_LOCATOR_LEN as u64, "locator anchor")?,
            "locator anchor overflow",
        )?,
        cmra_offset: locator.cmra_offset,
        cmra_length: recovered.cmra_length,
    })
}

pub(crate) fn parse_locatorless_cmra_candidate(
    bytes: &[u8],
    cmra_offset: usize,
    context: KeyHoldingTerminalContext<'_>,
) -> Result<TerminalCandidate, FormatError> {
    let recovered = recover_cmra(bytes, cmra_offset as u64, None, CmraRecoveryMode::KeyHolding)?;
    if recovered.image.body_bytes_before_cmra != cmra_offset as u64 {
        return Err(FormatError::InvalidArchive("locatorless CMRA boundary mismatch"));
    }
    if recovered
        .image
        .volume_trailer_offset
        .checked_add(VOLUME_TRAILER_LEN as u64)
        .ok_or(FormatError::InvalidArchive("CMRA boundary overflow"))?
        != cmra_offset as u64
    {
        return Err(FormatError::InvalidArchive("locatorless trailer boundary mismatch"));
    }
    validate_cmra_identity_hints(recovered.header_hints, None, &recovered.image)?;
    let terminal = validate_recovered_terminal(recovered.image, recovered.tuple, bytes, context, true)?;
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

pub(crate) fn parse_locatorless_cmra_candidate_read_at(
    reader: &dyn ArchiveReadAt,
    cmra_offset: u64,
    context: KeyHoldingTerminalContext<'_>,
) -> Result<TerminalCandidate, FormatError> {
    let recovered = recover_cmra_read_at(reader, cmra_offset, None, CmraRecoveryMode::KeyHolding)?;
    if recovered.image.body_bytes_before_cmra != cmra_offset {
        return Err(FormatError::InvalidArchive("locatorless CMRA boundary mismatch"));
    }
    if recovered
        .image
        .volume_trailer_offset
        .checked_add(VOLUME_TRAILER_LEN as u64)
        .ok_or(FormatError::InvalidArchive("CMRA boundary overflow"))?
        != cmra_offset
    {
        return Err(FormatError::InvalidArchive("locatorless trailer boundary mismatch"));
    }
    validate_cmra_identity_hints(recovered.header_hints, None, &recovered.image)?;
    let terminal = validate_recovered_terminal_read_at(recovered.image, recovered.tuple, reader, context, true)?;
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

pub(crate) fn parse_locatorless_cmra_authority_candidate(
    bytes: &[u8],
    cmra_offset: usize,
    master_key: &MasterKey,
) -> Result<TerminalAuthorityCandidate, FormatError> {
    let recovered = recover_cmra(bytes, cmra_offset as u64, None, CmraRecoveryMode::KeyHolding)?;
    if recovered.image.body_bytes_before_cmra != cmra_offset as u64 {
        return Err(FormatError::InvalidArchive("locatorless CMRA boundary mismatch"));
    }
    if recovered
        .image
        .volume_trailer_offset
        .checked_add(VOLUME_TRAILER_LEN as u64)
        .ok_or(FormatError::InvalidArchive("CMRA boundary overflow"))?
        != cmra_offset as u64
    {
        return Err(FormatError::InvalidArchive("locatorless trailer boundary mismatch"));
    }
    validate_cmra_identity_hints(recovered.header_hints, None, &recovered.image)?;
    let cmra_length = recovered.cmra_length;
    let authority = validate_recovered_terminal_authority(recovered.image, recovered.tuple, master_key, true)?;
    Ok(TerminalAuthorityCandidate {
        authority,
        anchor: cmra_offset
            .checked_add(to_usize(cmra_length, "CMRA")?)
            .ok_or(FormatError::InvalidArchive("CMRA anchor overflow"))?,
        cmra_offset: cmra_offset as u64,
        cmra_length,
    })
}

pub(crate) fn parse_locatorless_cmra_recipient_wrap_authority_candidate<F>(
    bytes: &[u8],
    cmra_offset: usize,
    resolver: &mut F,
) -> Result<RecipientWrapTerminalAuthorityCandidate, FormatError>
where
    F: FnMut(RecipientWrapRecordContext<'_>) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
{
    let recovered = recover_cmra(bytes, cmra_offset as u64, None, CmraRecoveryMode::KeyHolding)?;
    if recovered.image.body_bytes_before_cmra != cmra_offset as u64 {
        return Err(FormatError::InvalidArchive("locatorless CMRA boundary mismatch"));
    }
    if recovered
        .image
        .volume_trailer_offset
        .checked_add(VOLUME_TRAILER_LEN as u64)
        .ok_or(FormatError::InvalidArchive("CMRA boundary overflow"))?
        != cmra_offset as u64
    {
        return Err(FormatError::InvalidArchive("locatorless trailer boundary mismatch"));
    }
    validate_cmra_identity_hints(recovered.header_hints, None, &recovered.image)?;
    let cmra_length = recovered.cmra_length;
    let authority = validate_recovered_recipient_wrap_terminal_authority(recovered.image, recovered.tuple, resolver, true)?;
    Ok(RecipientWrapTerminalAuthorityCandidate {
        authority,
        anchor: cmra_offset
            .checked_add(to_usize(cmra_length, "CMRA")?)
            .ok_or(FormatError::InvalidArchive("CMRA anchor overflow"))?,
        cmra_offset: cmra_offset as u64,
        cmra_length,
    })
}

pub(crate) fn parse_locatorless_cmra_recipient_wrap_authority_candidate_read_at<F>(
    reader: &dyn ArchiveReadAt,
    cmra_offset: u64,
    resolver: &mut F,
) -> Result<RecipientWrapTerminalAuthorityCandidate, FormatError>
where
    F: FnMut(RecipientWrapRecordContext<'_>) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
{
    let recovered = recover_cmra_read_at(reader, cmra_offset, None, CmraRecoveryMode::KeyHolding)?;
    if recovered.image.body_bytes_before_cmra != cmra_offset {
        return Err(FormatError::InvalidArchive("locatorless CMRA boundary mismatch"));
    }
    if recovered
        .image
        .volume_trailer_offset
        .checked_add(VOLUME_TRAILER_LEN as u64)
        .ok_or(FormatError::InvalidArchive("CMRA boundary overflow"))?
        != cmra_offset
    {
        return Err(FormatError::InvalidArchive("locatorless trailer boundary mismatch"));
    }
    validate_cmra_identity_hints(recovered.header_hints, None, &recovered.image)?;
    let cmra_length = recovered.cmra_length;
    let authority = validate_recovered_recipient_wrap_terminal_authority(recovered.image, recovered.tuple, resolver, true)?;
    Ok(RecipientWrapTerminalAuthorityCandidate {
        authority,
        anchor: to_usize(checked_u64_add(cmra_offset, cmra_length, "CMRA anchor overflow")?, "CMRA anchor overflow")?,
        cmra_offset,
        cmra_length,
    })
}

pub(crate) fn parse_locatorless_cmra_authority_candidate_read_at(
    reader: &dyn ArchiveReadAt,
    cmra_offset: u64,
    master_key: &MasterKey,
) -> Result<TerminalAuthorityCandidate, FormatError> {
    let recovered = recover_cmra_read_at(reader, cmra_offset, None, CmraRecoveryMode::KeyHolding)?;
    if recovered.image.body_bytes_before_cmra != cmra_offset {
        return Err(FormatError::InvalidArchive("locatorless CMRA boundary mismatch"));
    }
    if recovered
        .image
        .volume_trailer_offset
        .checked_add(VOLUME_TRAILER_LEN as u64)
        .ok_or(FormatError::InvalidArchive("CMRA boundary overflow"))?
        != cmra_offset
    {
        return Err(FormatError::InvalidArchive("locatorless trailer boundary mismatch"));
    }
    validate_cmra_identity_hints(recovered.header_hints, None, &recovered.image)?;
    let cmra_length = recovered.cmra_length;
    let authority = validate_recovered_terminal_authority(recovered.image, recovered.tuple, master_key, true)?;
    Ok(TerminalAuthorityCandidate {
        authority,
        anchor: to_usize(checked_u64_add(cmra_offset, cmra_length, "CMRA anchor overflow")?, "CMRA anchor overflow")?,
        cmra_offset,
        cmra_length,
    })
}

pub(crate) fn parse_public_locatorless_cmra_candidate(
    bytes: &[u8],
    cmra_offset: usize,
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeader<'_>,
) -> Result<PublicTerminalCandidate, FormatError> {
    let recovered = recover_cmra(bytes, cmra_offset as u64, None, CmraRecoveryMode::PublicNoKey)?;
    if recovered.image.body_bytes_before_cmra != cmra_offset as u64 {
        return Err(FormatError::InvalidArchive("locatorless CMRA boundary mismatch"));
    }
    if recovered
        .image
        .volume_trailer_offset
        .checked_add(VOLUME_TRAILER_LEN as u64)
        .ok_or(FormatError::InvalidArchive("CMRA boundary overflow"))?
        != cmra_offset as u64
    {
        return Err(FormatError::InvalidArchive("locatorless trailer boundary mismatch"));
    }
    validate_cmra_identity_hints(recovered.header_hints, None, &recovered.image)?;
    let terminal = validate_recovered_public_terminal(recovered.image, bytes, volume_header, crypto_header, true)?;
    Ok(PublicTerminalCandidate {
        terminal,
        anchor: cmra_offset
            .checked_add(to_usize(recovered.cmra_length, "CMRA")?)
            .ok_or(FormatError::InvalidArchive("CMRA anchor overflow"))?,
        cmra_offset: cmra_offset as u64,
        cmra_length: recovered.cmra_length,
    })
}

pub(crate) fn parse_public_locatorless_cmra_candidate_read_at(
    reader: &dyn ArchiveReadAt,
    cmra_offset: u64,
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeader<'_>,
) -> Result<PublicTerminalCandidate, FormatError> {
    let recovered = recover_cmra_read_at(reader, cmra_offset, None, CmraRecoveryMode::PublicNoKey)?;
    if recovered.image.body_bytes_before_cmra != cmra_offset {
        return Err(FormatError::InvalidArchive("locatorless CMRA boundary mismatch"));
    }
    if recovered
        .image
        .volume_trailer_offset
        .checked_add(VOLUME_TRAILER_LEN as u64)
        .ok_or(FormatError::InvalidArchive("CMRA boundary overflow"))?
        != cmra_offset
    {
        return Err(FormatError::InvalidArchive("locatorless trailer boundary mismatch"));
    }
    validate_cmra_identity_hints(recovered.header_hints, None, &recovered.image)?;
    let terminal = validate_recovered_public_terminal_read_at(recovered.image, reader, volume_header, crypto_header, true)?;
    Ok(PublicTerminalCandidate {
        terminal,
        anchor: to_usize(
            checked_u64_add(cmra_offset, recovered.cmra_length, "CMRA anchor overflow")?,
            "CMRA anchor overflow",
        )?,
        cmra_offset,
        cmra_length: recovered.cmra_length,
    })
}

pub(crate) fn validate_locator_position(locator_offset: usize, locator: CriticalRecoveryLocator) -> Result<(), FormatError> {
    if locator.cmra_offset != locator.body_bytes_before_cmra {
        return Err(FormatError::InvalidArchive("locator CMRA boundary mismatch"));
    }
    if locator
        .volume_trailer_offset
        .checked_add(VOLUME_TRAILER_LEN as u64)
        .ok_or(FormatError::InvalidArchive("locator trailer overflow"))?
        != locator.cmra_offset
    {
        return Err(FormatError::InvalidArchive("locator trailer boundary mismatch"));
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
        return Err(FormatError::InvalidArchive("locator position does not match sequence"));
    }
    Ok(())
}

pub(crate) fn validate_locator_image_boundary(locator: CriticalRecoveryLocator, image: &CriticalMetadataImage) -> Result<(), FormatError> {
    if locator.volume_format_rev != image.volume_format_rev
        || locator.volume_trailer_offset != image.volume_trailer_offset
        || locator.body_bytes_before_cmra != image.body_bytes_before_cmra
        || image
            .volume_trailer_offset
            .checked_add(VOLUME_TRAILER_LEN as u64)
            .ok_or(FormatError::InvalidArchive("CMRA image boundary overflow"))?
            != locator.cmra_offset
    {
        return Err(FormatError::InvalidArchive("locator and CMRA image boundaries differ"));
    }
    Ok(())
}

pub(crate) fn validate_cmra_identity_hints(
    header_hints: Option<CmraIdentityHints>,
    locator_hints: Option<CmraIdentityHints>,
    image: &CriticalMetadataImage,
) -> Result<(), FormatError> {
    if let (Some(header), Some(locator)) = (header_hints, locator_hints) {
        if header != locator {
            return Err(FormatError::InvalidArchive("CMRA header and locator identity hints differ"));
        }
    }
    for hints in [header_hints, locator_hints].into_iter().flatten() {
        if hints.archive_uuid != image.archive_uuid || hints.session_id != image.session_id || hints.volume_index != image.volume_index {
            return Err(FormatError::InvalidArchive("CMRA identity hints do not match recovered image"));
        }
    }
    Ok(())
}

pub(crate) fn recover_cmra(
    bytes: &[u8],
    cmra_offset: u64,
    locator_tuple: Option<CmraDecoderTuple>,
    mode: CmraRecoveryMode,
) -> Result<RecoveredCmra, FormatError> {
    let offset = to_usize(cmra_offset, "CMRA")?;
    let header_bytes = slice(bytes, offset, CRITICAL_METADATA_RECOVERY_HEADER_LEN, "CriticalMetadataRecoveryHeader")?;
    let (tuple, header_hints) = recover_cmra_header_tuple(header_bytes, locator_tuple)?;
    validate_cmra_decoder_tuple(tuple)?;
    let cmra_length = cmra_serialized_length(tuple)?;
    let cmra_len = to_usize(cmra_length, "CMRA")?;
    let cmra_bytes = slice(bytes, offset, cmra_len, "CMRA")?;
    recover_cmra_from_bytes(cmra_bytes, tuple, header_hints, cmra_length, mode)
}

pub(crate) fn recover_cmra_read_at(
    reader: &dyn ArchiveReadAt,
    cmra_offset: u64,
    locator_tuple: Option<CmraDecoderTuple>,
    mode: CmraRecoveryMode,
) -> Result<RecoveredCmra, FormatError> {
    let header_bytes = read_at_vec(reader, cmra_offset, CRITICAL_METADATA_RECOVERY_HEADER_LEN, "CriticalMetadataRecoveryHeader")?;
    let (tuple, header_hints) = recover_cmra_header_tuple(&header_bytes, locator_tuple)?;
    validate_cmra_decoder_tuple(tuple)?;
    let cmra_length = cmra_serialized_length(tuple)?;
    let cmra_bytes = read_at_vec(reader, cmra_offset, to_usize(cmra_length, "CMRA")?, "CMRA")?;
    recover_cmra_from_bytes(&cmra_bytes, tuple, header_hints, cmra_length, mode)
}

pub(crate) fn recover_cmra_header_tuple(
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
        (Ok(header), None) => (CmraDecoderTuple::from(header), Some(CmraIdentityHints::from(header))),
        (Err(_), Some(tuple)) => (tuple, None),
        (Err(err), _) => return Err(err),
    })
}

pub(crate) fn recover_cmra_from_bytes(
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
                let data_slot = data_shards.get_mut(idx).ok_or(FormatError::InvalidArchive("CMRA data shard out of range"))?;
                *data_slot = Some(shard.payload);
            } else {
                let parity_idx = idx - tuple.data_shard_count as usize;
                let parity_slot = parity_shards
                    .get_mut(parity_idx)
                    .ok_or(FormatError::InvalidArchive("CMRA parity shard out of range"))?;
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

pub(crate) fn validate_cmra_decoder_tuple(tuple: CmraDecoderTuple) -> Result<(), FormatError> {
    let shard_size = tuple.shard_size as u64;
    if !(512..=4096).contains(&shard_size) || shard_size % 2 != 0 {
        return Err(FormatError::InvalidArchive("CMRA shard_size is invalid"));
    }
    let image_length = tuple.image_length as u64;
    let min = critical_image_min();
    let cap = critical_image_cap()?;
    if image_length < min || image_length > cap {
        return Err(FormatError::InvalidArchive("CMRA image_length is outside bounds"));
    }
    let expected_data_shards = ceil_div_u64(image_length, shard_size)?;
    if expected_data_shards == 0 || expected_data_shards != tuple.data_shard_count as u64 {
        return Err(FormatError::InvalidArchive("CMRA data_shard_count does not match image length"));
    }
    let max_parity = 2u64.max(ceil_div_u64(
        checked_u64_mul(expected_data_shards, READER_MAX_CMRA_PARITY_PCT as u64, "CMRA parity overflow")?,
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

pub(crate) fn validate_cmra_writer_parity_lower_bound(tuple: CmraDecoderTuple, bit_rot_buffer_pct: u8) -> Result<(), FormatError> {
    let min_parity = 2u64.max(ceil_div_u64(
        checked_u64_mul(tuple.data_shard_count as u64, bit_rot_buffer_pct as u64, "CMRA parity lower-bound overflow")?,
        100,
    )?);
    if (tuple.parity_shard_count as u64) < min_parity {
        return Err(FormatError::InvalidArchive(
            "CMRA parity shard count is below authenticated bit-rot lower bound",
        ));
    }
    Ok(())
}

pub(crate) fn validate_cmra_shard(shard: &CriticalMetadataRecoveryShard, serialized_idx: usize, tuple: CmraDecoderTuple) -> Result<(), FormatError> {
    if shard.shard_index as usize != serialized_idx {
        return Err(FormatError::InvalidArchive("CMRA shards are not in canonical order"));
    }
    let data_count = tuple.data_shard_count as usize;
    let shard_size = tuple.shard_size as usize;
    if serialized_idx < data_count {
        if shard.shard_role != 0 {
            return Err(FormatError::InvalidArchive("CMRA data shard has wrong role"));
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
            return Err(FormatError::InvalidArchive("CMRA data shard payload length is non-canonical"));
        }
        if serialized_idx + 1 == data_count && shard.payload[expected_len..].iter().any(|byte| *byte != 0) {
            return Err(FormatError::InvalidArchive("CMRA final data shard padding is non-zero"));
        }
    } else {
        if shard.shard_role != 1 {
            return Err(FormatError::InvalidArchive("CMRA parity shard has wrong role"));
        }
        if shard.shard_payload_length as usize != shard_size {
            return Err(FormatError::InvalidArchive("CMRA parity shard payload length is non-canonical"));
        }
    }
    Ok(())
}

pub(crate) fn validate_critical_metadata_image(image: &CriticalMetadataImage, mode: CmraRecoveryMode) -> Result<(), FormatError> {
    let root_auth_present = image.layout_flags & 0x0000_0001 != 0;
    let key_wrap_layout_present = image.layout_flags & 0x0000_0002 != 0;
    let key_wrap_region = image.region(6);
    if key_wrap_layout_present != key_wrap_region.is_some() {
        return Err(FormatError::InvalidArchive("CriticalMetadataImage key-wrap layout flag mismatch"));
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
        return Err(FormatError::InvalidArchive("CriticalMetadataImage fixed layout is invalid"));
    }
    if root_auth_present {
        if image.root_auth_footer_offset == 0 || image.root_auth_footer_length == 0 || image.root_auth_footer_length > READER_MAX_ROOT_AUTH_FOOTER_LEN {
            return Err(FormatError::InvalidArchive("CriticalMetadataImage root-auth range is invalid"));
        }
    } else if image.root_auth_footer_offset != 0 || image.root_auth_footer_length != 0 || image.root_auth_footer_sha256 != [0u8; 32] {
        return Err(FormatError::InvalidArchive("CriticalMetadataImage root-auth fields must be zero when absent"));
    }
    let block_record_len = image_block_record_len_from_region(image)?;
    let block_record_len_u64 = u64::try_from(block_record_len).map_err(|_| FormatError::InvalidArchive("BlockRecord length overflow"))?;
    match mode {
        CmraRecoveryMode::KeyHolding => {
            let expected_len = image
                .block_count
                .checked_mul(block_record_len_u64)
                .ok_or(FormatError::InvalidArchive("BlockRecord region length overflow"))?;
            if image.block_records_length != expected_len {
                return Err(FormatError::InvalidArchive("CriticalMetadataImage terminal equations are invalid"));
            }
        }
        CmraRecoveryMode::PublicNoKey => {
            if image.block_records_length % block_record_len_u64 != 0 {
                return Err(FormatError::InvalidArchive("CriticalMetadataImage BlockRecord region is not aligned"));
            }
        }
    }
    let crypto_header_end = image
        .crypto_header_offset
        .checked_add(image.crypto_header_length as u64)
        .ok_or(FormatError::InvalidArchive("CryptoHeader boundary overflow"))?;
    let expected_block_records_offset = if key_wrap_present {
        let key_wrap_region = key_wrap_region.ok_or(FormatError::InvalidArchive("missing CriticalMetadataImage key-wrap region"))?;
        if image.key_wrap_table_offset != crypto_header_end
            || image.key_wrap_table_length == 0
            || key_wrap_region.offset != image.key_wrap_table_offset
            || key_wrap_region.bytes.len() != image.key_wrap_table_length as usize
        {
            return Err(FormatError::InvalidArchive("CriticalMetadataImage key-wrap region is malformed"));
        }
        image
            .key_wrap_table_offset
            .checked_add(image.key_wrap_table_length as u64)
            .ok_or(FormatError::InvalidArchive("KeyWrapTableV1 boundary overflow"))?
    } else {
        if image.key_wrap_table_offset != 0 || image.key_wrap_table_length != 0 || image.key_wrap_table_sha256 != [0u8; 32] {
            return Err(FormatError::InvalidArchive("CriticalMetadataImage key-wrap fields must be zero when absent"));
        }
        crypto_header_end
    };
    if image.block_records_offset != expected_block_records_offset
        || image.manifest_footer_offset
            != image
                .block_records_offset
                .checked_add(image.block_records_length)
                .ok_or(FormatError::InvalidArchive("ManifestFooter boundary overflow"))?
    {
        return Err(FormatError::InvalidArchive("CriticalMetadataImage terminal equations are invalid"));
    }
    let manifest_end = image
        .manifest_footer_offset
        .checked_add(MANIFEST_FOOTER_LEN as u64)
        .ok_or(FormatError::InvalidArchive("RootAuthFooter boundary overflow"))?;
    if root_auth_present {
        if image.root_auth_footer_offset != manifest_end
            || image
                .root_auth_footer_offset
                .checked_add(image.root_auth_footer_length as u64)
                .ok_or(FormatError::InvalidArchive("VolumeTrailer boundary overflow"))?
                != image.volume_trailer_offset
        {
            return Err(FormatError::InvalidArchive("CriticalMetadataImage root-auth terminal equations are invalid"));
        }
    } else if image.volume_trailer_offset != manifest_end {
        return Err(FormatError::InvalidArchive("CriticalMetadataImage unsigned terminal equations are invalid"));
    }
    let expected_types: &[u16] = match (key_wrap_present, root_auth_present) {
        (false, false) => &[1, 2, 3, 5],
        (false, true) => &[1, 2, 3, 4, 5],
        (true, false) => &[1, 2, 6, 3, 5],
        (true, true) => &[1, 2, 6, 3, 4, 5],
    };
    if image.regions.len() != expected_types.len() || image.regions.iter().map(|region| region.region_type).ne(expected_types.iter().copied()) {
        return Err(FormatError::InvalidArchive("CriticalMetadataImage regions are not canonical"));
    }
    validate_image_region(image, 1, image.volume_header_offset, image.volume_header_length)?;
    validate_image_region(image, 2, image.crypto_header_offset, image.crypto_header_length)?;
    validate_image_region(image, 3, image.manifest_footer_offset, image.manifest_footer_length)?;
    if key_wrap_present {
        validate_image_region(image, 6, image.key_wrap_table_offset, image.key_wrap_table_length)?;
    }
    if root_auth_present {
        validate_image_region(image, 4, image.root_auth_footer_offset, image.root_auth_footer_length)?;
    }
    validate_image_region(image, 5, image.volume_trailer_offset, image.volume_trailer_length)?;
    if sha256_region(image, 1)? != image.volume_header_sha256
        || sha256_region(image, 2)? != image.crypto_header_sha256
        || (key_wrap_present && sha256_region(image, 6)? != image.key_wrap_table_sha256)
        || (!key_wrap_present && image.key_wrap_table_sha256 != [0u8; 32])
        || sha256_region(image, 3)? != image.manifest_footer_sha256
        || (root_auth_present && sha256_region(image, 4)? != image.root_auth_footer_sha256)
        || (!root_auth_present && image.root_auth_footer_sha256 != [0u8; 32])
        || sha256_region(image, 5)? != image.volume_trailer_sha256
    {
        return Err(FormatError::InvalidArchive("CriticalMetadataImage region digest mismatch"));
    }
    Ok(())
}

pub(crate) fn image_block_record_len_from_region(image: &CriticalMetadataImage) -> Result<usize, FormatError> {
    let crypto_region = image.region(2).ok_or(FormatError::InvalidArchive("missing CryptoHeader region"))?;
    let crypto = CryptoHeader::parse(&crypto_region.bytes, image.crypto_header_length)?;
    crypto.fixed.validate_supported_profile()?;
    Ok(crypto.fixed.block_size as usize + BLOCK_RECORD_FRAMING_LEN)
}

pub(crate) fn validate_image_region(image: &CriticalMetadataImage, region_type: u16, offset: u64, length: u32) -> Result<(), FormatError> {
    let region = image
        .region(region_type)
        .ok_or(FormatError::InvalidArchive("missing CriticalMetadataImage region"))?;
    if region.offset != offset || region.bytes.len() != length as usize {
        return Err(FormatError::InvalidArchive("CriticalMetadataImage region range mismatch"));
    }
    Ok(())
}

/// §30.5.1.1: `image.crypto_header_length` MUST equal
/// `VolumeHeader.crypto_header_length` (and, transitively, `CryptoHeader.length`).
fn validate_image_crypto_header_length(image: &CriticalMetadataImage, volume_header: &VolumeHeader) -> Result<(), FormatError> {
    if image.crypto_header_length != volume_header.crypto_header_length {
        return Err(FormatError::InvalidArchive("CMRA crypto header length does not match recovered VolumeHeader"));
    }
    Ok(())
}

pub(crate) fn validate_image_identity(
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
        return Err(FormatError::InvalidArchive("CriticalMetadataImage identity does not match selected volume"));
    }
    Ok(())
}

pub(crate) fn validate_image_key_wrap_table(image: &CriticalMetadataImage, volume_header: &VolumeHeader, kdf_params: &KdfParams) -> Result<(), FormatError> {
    match kdf_params {
        KdfParams::RecipientWrap {
            key_wrap_table_length,
            key_wrap_table_record_count,
            key_wrap_table_digest,
            ..
        } => {
            if image.layout_flags & 0x0000_0002 == 0 || image.key_wrap_table_length != *key_wrap_table_length {
                return Err(FormatError::InvalidArchive("CriticalMetadataImage key-wrap fields do not match KdfParams"));
            }
            let region = image
                .region(6)
                .ok_or(FormatError::InvalidArchive("missing CriticalMetadataImage key-wrap region"))?;
            if region.offset != image.key_wrap_table_offset || region.bytes.len() != *key_wrap_table_length as usize {
                return Err(FormatError::InvalidArchive("CriticalMetadataImage key-wrap region is malformed"));
            }
            if compute_key_wrap_table_digest(*key_wrap_table_length, &region.bytes) != *key_wrap_table_digest {
                return Err(FormatError::IntegrityDigestMismatch { structure: "KeyWrapTableV1" });
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
                return Err(FormatError::InvalidArchive("CriticalMetadataImage key-wrap fields must be zero when absent"));
            }
            Ok(())
        }
    }
}

pub(crate) fn sha256_region(image: &CriticalMetadataImage, region_type: u16) -> Result<[u8; 32], FormatError> {
    Ok(sha256_bytes(
        &image
            .region(region_type)
            .ok_or(FormatError::InvalidArchive("missing CriticalMetadataImage region"))?
            .bytes,
    ))
}

pub(crate) fn validate_recovered_terminal_authority(
    image: CriticalMetadataImage,
    tuple: CmraDecoderTuple,
    master_key: &MasterKey,
    require_cmra_boundary_magic: bool,
) -> Result<RecoveredTerminalAuthority, FormatError> {
    let volume_header_region = image.region(1).ok_or(FormatError::InvalidArchive("missing VolumeHeader region"))?;
    let volume_header = VolumeHeader::parse(&volume_header_region.bytes)?;
    validate_image_crypto_header_length(&image, &volume_header)?;
    let crypto_region = image.region(2).ok_or(FormatError::InvalidArchive("missing CryptoHeader region"))?;
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
    validate_seekable_supported_volume(&volume_header, &parsed_crypto.fixed, &parsed_crypto.extensions)?;
    validate_crypto_class_parity_exactness(&parsed_crypto.fixed)?;
    let crypto_header = parsed_crypto.fixed.clone();
    if crypto_header.bit_rot_buffer_pct == 0 {
        return Err(FormatError::InvalidArchive("CMRA startup recovery requires a nonzero bit-rot budget"));
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

pub(crate) fn validate_recovered_recipient_wrap_terminal_authority<F>(
    image: CriticalMetadataImage,
    tuple: CmraDecoderTuple,
    resolver: &mut F,
    require_cmra_boundary_magic: bool,
) -> Result<RecoveredRecipientWrapTerminalAuthority, FormatError>
where
    F: FnMut(RecipientWrapRecordContext<'_>) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
{
    let volume_header_region = image.region(1).ok_or(FormatError::InvalidArchive("missing VolumeHeader region"))?;
    let volume_header = VolumeHeader::parse(&volume_header_region.bytes)?;
    validate_image_crypto_header_length(&image, &volume_header)?;
    let crypto_region = image.region(2).ok_or(FormatError::InvalidArchive("missing CryptoHeader region"))?;
    let crypto_header_bytes = crypto_region.bytes.clone();
    let parsed_crypto = CryptoHeader::parse(&crypto_header_bytes, image.crypto_header_length)?;
    if !matches!(parsed_crypto.kdf_params, KdfParams::RecipientWrap { .. }) || !parsed_crypto.fixed.aead_algo.is_encrypted() {
        return Err(FormatError::KeyMaterialMismatch);
    }
    validate_seekable_supported_volume(&volume_header, &parsed_crypto.fixed, &[])?;
    validate_crypto_class_parity_exactness(&parsed_crypto.fixed)?;
    if parsed_crypto.fixed.bit_rot_buffer_pct == 0 {
        return Err(FormatError::InvalidArchive("CMRA startup recovery requires a nonzero bit-rot budget"));
    }
    validate_cmra_writer_parity_lower_bound(tuple, parsed_crypto.fixed.bit_rot_buffer_pct)?;
    validate_image_key_wrap_table(&image, &volume_header, &parsed_crypto.kdf_params)?;
    let key_wrap_region = image
        .region(6)
        .ok_or(FormatError::InvalidArchive("missing CriticalMetadataImage key-wrap region"))?;
    let startup_key_wrap_table = parse_startup_key_wrap_table_bytes(&volume_header, &parsed_crypto.kdf_params, key_wrap_region.bytes.clone())?;
    let subkeys = recipient_wrap_subkeys_from_table(&volume_header, &parsed_crypto, &startup_key_wrap_table.table, resolver)?;
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

pub(crate) fn validate_recovered_terminal(
    image: CriticalMetadataImage,
    tuple: CmraDecoderTuple,
    bytes: &[u8],
    context: KeyHoldingTerminalContext<'_>,
    require_cmra_boundary_magic: bool,
) -> Result<V45Terminal, FormatError> {
    let cmra_offset = to_usize(image.body_bytes_before_cmra, "CMRA")?;
    let cmra_boundary_magic_ok = bytes.get(cmra_offset..cmra_offset + 4) == Some(b"TZCR");
    validate_recovered_terminal_inner(image, tuple, require_cmra_boundary_magic, cmra_boundary_magic_ok, context)
}

pub(crate) fn validate_recovered_terminal_read_at(
    image: CriticalMetadataImage,
    tuple: CmraDecoderTuple,
    reader: &dyn ArchiveReadAt,
    context: KeyHoldingTerminalContext<'_>,
    require_cmra_boundary_magic: bool,
) -> Result<V45Terminal, FormatError> {
    let mut magic = [0u8; 4];
    reader.read_exact_at(image.body_bytes_before_cmra, &mut magic)?;
    validate_recovered_terminal_inner(image, tuple, require_cmra_boundary_magic, magic == *b"TZCR", context)
}

pub(crate) fn validate_recovered_terminal_inner(
    image: CriticalMetadataImage,
    tuple: CmraDecoderTuple,
    require_cmra_boundary_magic: bool,
    cmra_boundary_magic_ok: bool,
    context: KeyHoldingTerminalContext<'_>,
) -> Result<V45Terminal, FormatError> {
    let subkeys = context.subkeys;
    let volume_header = context.volume_header;
    let crypto_header = context.crypto_header;
    let volume_header_region = image.region(1).ok_or(FormatError::InvalidArchive("missing VolumeHeader region"))?;
    let recovered_volume_header = VolumeHeader::parse(&volume_header_region.bytes)?;
    if &recovered_volume_header != volume_header {
        return Err(FormatError::InvalidArchive("CMRA VolumeHeader differs from parsed VolumeHeader"));
    }
    validate_image_crypto_header_length(&image, &recovered_volume_header)?;
    validate_image_identity(&image, volume_header, crypto_header)?;
    let crypto_region = image.region(2).ok_or(FormatError::InvalidArchive("missing CryptoHeader region"))?;
    let recovered_crypto = CryptoHeader::parse(&crypto_region.bytes, image.crypto_header_length)?;
    if recovered_crypto.fixed != *crypto_header {
        return Err(FormatError::InvalidArchive("CMRA CryptoHeader differs from parsed CryptoHeader"));
    }
    let recovered_pre_hmac_len = crypto_region
        .bytes
        .len()
        .checked_sub(CRYPTO_HEADER_HMAC_LEN)
        .ok_or(FormatError::InvalidArchive("CMRA CryptoHeader is too short"))?;
    let parsed_pre_hmac_len = context
        .crypto_header_bytes
        .len()
        .checked_sub(CRYPTO_HEADER_HMAC_LEN)
        .ok_or(FormatError::InvalidArchive("CryptoHeader is too short"))?;
    if recovered_pre_hmac_len != parsed_pre_hmac_len || crypto_region.bytes[..recovered_pre_hmac_len] != context.crypto_header_bytes[..parsed_pre_hmac_len] {
        return Err(FormatError::InvalidArchive("CMRA CryptoHeader differs from parsed CryptoHeader"));
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

    let manifest_region = image.region(3).ok_or(FormatError::InvalidArchive("missing ManifestFooter region"))?;
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
        let root_auth_region = image.region(4).ok_or(FormatError::InvalidArchive("missing RootAuthFooter region"))?;
        let footer = RootAuthFooterV1::parse(&root_auth_region.bytes)?;
        if footer.format_version != volume_header.format_version || footer.volume_format_rev != volume_header.volume_format_rev {
            return Err(FormatError::InvalidArchive("RootAuthFooter format/revision does not match VolumeHeader"));
        }
        if footer.archive_uuid != volume_header.archive_uuid
            || footer.session_id != volume_header.session_id
            || footer.footer_length()? != image.root_auth_footer_length
        {
            return Err(FormatError::InvalidArchive("RootAuthFooter identity or length does not match terminal image"));
        }
        Some(footer)
    } else {
        None
    };

    let trailer_region = image.region(5).ok_or(FormatError::InvalidArchive("missing VolumeTrailer region"))?;
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
    validate_v45_trailer_equations(&image, &trailer)?;

    if require_cmra_boundary_magic && !cmra_boundary_magic_ok {
        return Err(FormatError::InvalidArchive("CMRA is not at image boundary"));
    }

    let manifest_footer_bytes = manifest_region.bytes.clone();
    let root_auth_footer_bytes = image.region(4).map(|region| region.bytes.clone());
    Ok(V45Terminal {
        image,
        manifest_footer_bytes,
        root_auth_footer_bytes,
        root_auth_footer,
        volume_trailer: trailer,
    })
}

pub(crate) fn validate_recovered_public_terminal(
    image: CriticalMetadataImage,
    bytes: &[u8],
    volume_header: &VolumeHeader,
    public_crypto_header: &CryptoHeader<'_>,
    require_cmra_boundary_magic: bool,
) -> Result<V45PublicTerminal, FormatError> {
    let cmra_offset = to_usize(image.body_bytes_before_cmra, "CMRA")?;
    let cmra_boundary_magic_ok = bytes.get(cmra_offset..cmra_offset + 4) == Some(b"TZCR");
    validate_recovered_public_terminal_inner(image, volume_header, public_crypto_header, require_cmra_boundary_magic, cmra_boundary_magic_ok)
}

pub(crate) fn validate_recovered_public_terminal_read_at(
    image: CriticalMetadataImage,
    reader: &dyn ArchiveReadAt,
    volume_header: &VolumeHeader,
    public_crypto_header: &CryptoHeader<'_>,
    require_cmra_boundary_magic: bool,
) -> Result<V45PublicTerminal, FormatError> {
    let mut magic = [0u8; 4];
    reader.read_exact_at(image.body_bytes_before_cmra, &mut magic)?;
    validate_recovered_public_terminal_inner(image, volume_header, public_crypto_header, require_cmra_boundary_magic, magic == *b"TZCR")
}

pub(crate) fn validate_recovered_public_terminal_inner(
    image: CriticalMetadataImage,
    volume_header: &VolumeHeader,
    public_crypto_header: &CryptoHeader<'_>,
    require_cmra_boundary_magic: bool,
    cmra_boundary_magic_ok: bool,
) -> Result<V45PublicTerminal, FormatError> {
    if image.layout_flags & 0x0000_0001 == 0 {
        return Err(FormatError::ReaderUnsupported("public no-key verification requires root-auth"));
    }
    let volume_header_region = image.region(1).ok_or(FormatError::InvalidArchive("missing VolumeHeader region"))?;
    let recovered_volume_header = VolumeHeader::parse(&volume_header_region.bytes)?;
    if &recovered_volume_header != volume_header {
        return Err(FormatError::InvalidArchive("CMRA VolumeHeader differs from parsed VolumeHeader"));
    }
    validate_image_crypto_header_length(&image, &recovered_volume_header)?;
    validate_image_identity(&image, volume_header, &public_crypto_header.fixed)?;
    let crypto_region = image.region(2).ok_or(FormatError::InvalidArchive("missing CryptoHeader region"))?;
    let recovered_crypto = CryptoHeader::parse(&crypto_region.bytes, image.crypto_header_length)?;
    if !public_crypto_headers_agree(&recovered_crypto.fixed, &public_crypto_header.fixed)
        || !public_kdf_profiles_agree(&recovered_crypto.kdf_params, &public_crypto_header.kdf_params)
    {
        return Err(FormatError::InvalidArchive("CMRA CryptoHeader differs from parsed CryptoHeader"));
    }
    recovered_crypto.validate_extension_semantics()?;
    validate_image_key_wrap_table(&image, volume_header, &recovered_crypto.kdf_params)?;

    image.region(3).ok_or(FormatError::InvalidArchive("missing ManifestFooter region"))?;

    let root_auth_region = image.region(4).ok_or(FormatError::InvalidArchive("missing RootAuthFooter region"))?;
    let root_auth_footer = RootAuthFooterV1::parse(&root_auth_region.bytes)?;
    if root_auth_footer.format_version != volume_header.format_version || root_auth_footer.volume_format_rev != volume_header.volume_format_rev {
        return Err(FormatError::InvalidArchive("public RootAuthFooter format/revision does not match VolumeHeader"));
    }
    if root_auth_footer.archive_uuid != volume_header.archive_uuid
        || root_auth_footer.session_id != volume_header.session_id
        || root_auth_footer.footer_length()? != image.root_auth_footer_length
    {
        return Err(FormatError::InvalidArchive(
            "public RootAuthFooter identity or length does not match terminal image",
        ));
    }

    let trailer_region = image.region(5).ok_or(FormatError::InvalidArchive("missing VolumeTrailer region"))?;
    let trailer = VolumeTrailer::parse(&trailer_region.bytes)?;
    validate_trailer_identity(volume_header, &trailer)?;
    validate_v45_public_trailer_profile(&image, &trailer)?;

    if require_cmra_boundary_magic && !cmra_boundary_magic_ok {
        return Err(FormatError::InvalidArchive("CMRA is not at image boundary"));
    }

    let root_auth_footer_bytes = root_auth_region.bytes.clone();
    Ok(V45PublicTerminal {
        image,
        root_auth_footer_bytes,
        root_auth_footer,
    })
}

pub(crate) fn validate_v45_trailer_equations(image: &CriticalMetadataImage, trailer: &VolumeTrailer) -> Result<(), FormatError> {
    let root_auth_present = image.layout_flags & 0x0000_0001 != 0;
    if trailer.bytes_written != image.volume_trailer_offset
        || trailer.manifest_footer_offset != image.manifest_footer_offset
        || trailer.manifest_footer_length != MANIFEST_FOOTER_LEN as u32
        || trailer.block_count != image.block_count
    {
        return Err(FormatError::InvalidArchive("VolumeTrailer does not match v45 terminal layout"));
    }
    if root_auth_present {
        if trailer.root_auth_flags != 0x0000_0001
            || trailer.root_auth_footer_offset != image.root_auth_footer_offset
            || trailer.root_auth_footer_length != image.root_auth_footer_length
            || image.root_auth_footer_offset
                != image
                    .manifest_footer_offset
                    .checked_add(MANIFEST_FOOTER_LEN as u64)
                    .ok_or(FormatError::InvalidArchive("RootAuthFooter trailer boundary overflow"))?
            || image
                .root_auth_footer_offset
                .checked_add(image.root_auth_footer_length as u64)
                .ok_or(FormatError::InvalidArchive("RootAuthFooter trailer boundary overflow"))?
                != image.volume_trailer_offset
        {
            return Err(FormatError::InvalidArchive("VolumeTrailer root-auth fields do not match v45 terminal layout"));
        }
    } else if trailer.root_auth_footer_offset != 0 || trailer.root_auth_footer_length != 0 || trailer.root_auth_flags != 0 {
        return Err(FormatError::InvalidArchive("VolumeTrailer root-auth fields must be zero when absent"));
    }
    Ok(())
}

pub(crate) fn validate_v45_public_trailer_profile(image: &CriticalMetadataImage, trailer: &VolumeTrailer) -> Result<(), FormatError> {
    if trailer.bytes_written != image.volume_trailer_offset
        || trailer.manifest_footer_offset != image.manifest_footer_offset
        || trailer.manifest_footer_length != MANIFEST_FOOTER_LEN as u32
    {
        return Err(FormatError::InvalidArchive("VolumeTrailer does not match v45 public terminal layout"));
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
                .ok_or(FormatError::InvalidArchive("RootAuthFooter trailer boundary overflow"))?
        || image
            .root_auth_footer_offset
            .checked_add(image.root_auth_footer_length as u64)
            .ok_or(FormatError::InvalidArchive("RootAuthFooter trailer boundary overflow"))?
            != image.volume_trailer_offset
    {
        return Err(FormatError::InvalidArchive(
            "VolumeTrailer root-auth fields do not match v45 public terminal layout",
        ));
    }
    Ok(())
}

pub(crate) fn critical_image_min() -> u64 {
    const MIN_CRYPTO_HEADER_LEN: u64 = 116;
    CRITICAL_METADATA_IMAGE_FIXED_LEN as u64
        + 4 * SERIALIZED_REGION_HEADER_LEN as u64
        + VOLUME_HEADER_LEN as u64
        + MIN_CRYPTO_HEADER_LEN
        + MANIFEST_FOOTER_LEN as u64
        + VOLUME_TRAILER_LEN as u64
        + IMAGE_CRC_LEN as u64
}

pub(crate) fn critical_image_cap() -> Result<u64, FormatError> {
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
        total.checked_add(value).ok_or(FormatError::InvalidArchive("critical image cap overflow"))
    })
}

pub(crate) fn cmra_serialized_length(tuple: CmraDecoderTuple) -> Result<u64, FormatError> {
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

pub(crate) fn cmra_worst_case_cap() -> Result<u64, FormatError> {
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
            data_shard_count: u16::try_from(data).map_err(|_| FormatError::InvalidArchive("CMRA cap data shard overflow"))?,
            parity_shard_count: u16::try_from(parity).map_err(|_| FormatError::InvalidArchive("CMRA cap parity shard overflow"))?,
            image_length: u32::try_from(cap).map_err(|_| FormatError::InvalidArchive("CMRA cap image overflow"))?,
            image_sha256: [0u8; 32],
        };
        worst = worst.max(cmra_serialized_length(tuple)?);
        shard_size += 2;
    }
    Ok(worst)
}

pub(crate) fn v45_terminal_tail_cap() -> Result<usize, FormatError> {
    let total = [
        MANIFEST_FOOTER_LEN as u64,
        READER_MAX_ROOT_AUTH_FOOTER_LEN as u64,
        VOLUME_TRAILER_LEN as u64,
        cmra_worst_case_cap()?,
        LOCATOR_PAIR_LEN as u64,
    ]
    .into_iter()
    .try_fold(0u64, |sum, value| {
        sum.checked_add(value).ok_or(FormatError::InvalidArchive("terminal tail cap overflow"))
    })?;
    usize::try_from(total).map_err(|_| FormatError::InvalidArchive("terminal tail cap overflow"))
}

pub(crate) fn max_critical_recovery_scan(options: ReaderOptions) -> Result<usize, FormatError> {
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
