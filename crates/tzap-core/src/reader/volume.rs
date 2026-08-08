use super::*;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::crypto::{verify_integrity_tag, HmacDomain, KdfParams, MasterKey, Subkeys};
use crate::format::{
    FormatError, MANIFEST_FOOTER_LEN, VOLUME_FORMAT_REV_45, VOLUME_HEADER_LEN, VOLUME_TRAILER_LEN,
};
use crate::raw_stream_profile::reject_unsupported_raw_stream_profile;
use crate::root_auth::{
    archive_root_for_revision, data_block_merkle_root_for_revision,
    root_auth_descriptor_digest_for_revision, signer_identity_digest, ArchiveRootInputs,
    DataBlockMerkleLeaf,
};
use crate::wire::{
    compute_key_wrap_table_digest, BlockRecord, CryptoHeader, CryptoHeaderFixed, ExtensionTlv,
    KeyWrapTableV1, ManifestFooter, RootAuthFooterV1, VolumeHeader, VolumeTrailer,
};

#[derive(Debug)]
pub(crate) struct ParsedSeekableVolume {
    pub(crate) volume_header: VolumeHeader,
    pub(crate) crypto_header: CryptoHeaderFixed,
    pub(crate) crypto_header_bytes: Vec<u8>,
    pub(crate) key_wrap_table_bytes: Option<Vec<u8>>,
    pub(crate) subkeys: Subkeys,
    pub(crate) manifest_footer: Option<ManifestFooter>,
    pub(crate) manifest_footer_error: Option<FormatError>,
    pub(crate) root_auth_footer: Option<RootAuthFooterV1>,
    pub(crate) root_auth_footer_bytes: Option<Vec<u8>>,
    pub(crate) volume_trailer: VolumeTrailer,
    pub(crate) blocks: BTreeMap<u64, BlockRecord>,
    pub(crate) erased_block_indices: BTreeSet<u64>,
}

pub(crate) struct ParsedSeekableReadAtVolume {
    pub(crate) reader: Arc<dyn ArchiveReadAt>,
    pub(crate) volume_header: VolumeHeader,
    pub(crate) crypto_header: CryptoHeaderFixed,
    pub(crate) crypto_header_bytes: Vec<u8>,
    pub(crate) key_wrap_table_bytes: Option<Vec<u8>>,
    pub(crate) subkeys: Subkeys,
    pub(crate) manifest_footer: Option<ManifestFooter>,
    pub(crate) manifest_footer_error: Option<FormatError>,
    pub(crate) root_auth_footer: Option<RootAuthFooterV1>,
    pub(crate) root_auth_footer_bytes: Option<Vec<u8>>,
    pub(crate) volume_trailer: VolumeTrailer,
    pub(crate) block_records_start: u64,
}

pub(crate) struct ParsedOpenPrefix {
    pub(crate) volume_header: VolumeHeader,
    pub(crate) crypto_header: CryptoHeaderFixed,
    pub(crate) crypto_header_bytes: Vec<u8>,
    pub(crate) key_wrap_table_bytes: Option<Vec<u8>>,
    pub(crate) block_records_start: u64,
    pub(crate) subkeys: Subkeys,
}

pub(crate) struct ParsedReadAtOpenPrefix {
    pub(crate) volume_header: VolumeHeader,
    pub(crate) crypto_header: CryptoHeaderFixed,
    pub(crate) crypto_header_bytes: Vec<u8>,
    pub(crate) key_wrap_table_bytes: Option<Vec<u8>>,
    pub(crate) block_records_start: u64,
    pub(crate) subkeys: Subkeys,
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

pub(crate) fn parse_seekable_volume(
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

pub(crate) fn parse_seekable_volume_with_recipient_wrap_resolver<F>(
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

pub(crate) fn parse_seekable_volume_with_prefix(
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

    let terminal = locate_v45_terminal(
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

pub(crate) fn parse_seekable_volume_from_recovered_terminal(
    bytes: &[u8],
    master_key: &MasterKey,
    options: ReaderOptions,
) -> Result<ParsedSeekableVolume, FormatError> {
    let authority = locate_v45_terminal_authority(bytes, master_key, options)?;
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

pub(crate) fn parse_seekable_volume_with_recipient_wrap_resolver_from_recovered_terminal<F>(
    bytes: &[u8],
    resolver: &mut F,
    options: ReaderOptions,
) -> Result<ParsedSeekableVolume, FormatError>
where
    F: FnMut(
        RecipientWrapRecordContext<'_>,
    ) -> Result<Vec<RecipientWrapCandidateMasterKey>, FormatError>,
{
    let authority = locate_v45_recipient_wrap_terminal_authority(bytes, resolver, options)?;
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

pub(crate) fn recipient_wrap_prefix_error_precludes_recovery(error: &FormatError) -> bool {
    matches!(
        error,
        FormatError::UnsupportedVolumeFormatRevision { .. }
            | FormatError::ReaderUnsupported(_)
            | FormatError::InvalidArchive(
                "VolumeHeader and CryptoHeader stripe_width differ"
                    | "fec_parity_shards does not match v45 compute_parity"
                    | "index_fec_parity_shards does not match v45 compute_parity"
                    | "index_root_fec_parity_shards does not match v45 compute_parity"
            )
    )
}

pub(crate) fn parse_open_prefix(
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

pub(crate) fn prefix_uses_recipient_wrap(bytes: &[u8]) -> bool {
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

pub(crate) fn parse_open_prefix_with_recipient_wrap_resolver<F>(
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
pub(crate) fn finish_parse_seekable_volume(
    bytes: &[u8],
    volume_header: VolumeHeader,
    crypto_header: CryptoHeaderFixed,
    crypto_header_bytes: Vec<u8>,
    key_wrap_table_bytes: Option<Vec<u8>>,
    block_records_start: u64,
    subkeys: Subkeys,
    terminal: V45Terminal,
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

pub(crate) fn parse_seekable_read_at_volume(
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

pub(crate) fn parse_seekable_read_at_volume_with_recipient_wrap_resolver<F>(
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

pub(crate) fn parse_seekable_read_at_volume_with_prefix(
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

    let terminal = locate_v45_terminal_read_at(
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

pub(crate) fn parse_seekable_read_at_volume_from_recovered_terminal(
    reader: Arc<dyn ArchiveReadAt>,
    observed_len: u64,
    master_key: &MasterKey,
    options: ReaderOptions,
) -> Result<ParsedSeekableReadAtVolume, FormatError> {
    let authority =
        locate_v45_terminal_authority_read_at(reader.as_ref(), observed_len, master_key, options)?;
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

pub(crate) fn parse_seekable_read_at_volume_with_recipient_wrap_resolver_from_recovered_terminal<
    F,
>(
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
    let authority = locate_v45_recipient_wrap_terminal_authority_read_at(
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

pub(crate) fn parse_read_at_open_prefix(
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

pub(crate) fn parse_read_at_open_prefix_with_recipient_wrap_resolver<F>(
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
pub(crate) fn finish_parse_seekable_read_at_volume(
    reader: Arc<dyn ArchiveReadAt>,
    volume_header: VolumeHeader,
    crypto_header: CryptoHeaderFixed,
    crypto_header_bytes: Vec<u8>,
    key_wrap_table_bytes: Option<Vec<u8>>,
    block_records_start: u64,
    subkeys: Subkeys,
    terminal: V45Terminal,
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
pub(crate) struct ParsedPublicNoKeyVolume {
    pub(crate) volume_header: VolumeHeader,
    pub(crate) crypto_header: CryptoHeaderFixed,
    pub(crate) kdf_params: KdfParams,
    pub(crate) root_auth_footer: RootAuthFooterV1,
    pub(crate) root_auth_footer_bytes: Vec<u8>,
    pub(crate) blocks: BTreeMap<u64, BlockRecord>,
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

/// Footer-only inspection of a single volume's public no-key metadata.
///
/// Unlike [`public_no_key_verify_volumes_with_options`], this reads only the
/// volume header, crypto header, and the bounded critical-recovery tail
/// (locators + CMRA image) through [`ArchiveReadAt`] — never the data blocks —
/// so memory use is O(1) with respect to archive size. The footer's signature
/// is *not* validated here; callers verify `archive_root` (recomputed from
/// footer + crypto-header fields only, including the *claimed*
/// `data_block_merkle_root`) against the embedded signer identity themselves.
#[derive(Debug)]
pub struct PublicNoKeyFooterInspection {
    pub volume_header: VolumeHeader,
    pub crypto_header: CryptoHeaderFixed,
    pub kdf_params: KdfParams,
    pub root_auth_footer: RootAuthFooterV1,
    pub root_auth_footer_bytes: Vec<u8>,
    pub archive_root: [u8; 32],
}

/// Outcome of [`public_no_key_inspect_footer`].
#[derive(Debug)]
// The inspection is produced once per call and moved, never cloned; boxing
// would only add an allocation for a single-value result.
#[allow(clippy::large_enum_variant)]
pub enum PublicNoKeyFooterStatus {
    /// A root-auth footer was recovered; `archive_root` is recomputed and
    /// self-consistent, but the signature is not yet verified.
    Signed(PublicNoKeyFooterInspection),
    /// The volume is a valid v45 archive but carries no root-auth footer.
    Unsigned,
}

pub fn public_no_key_inspect_footer(
    reader: &dyn ArchiveReadAt,
    options: ReaderOptions,
) -> Result<PublicNoKeyFooterStatus, FormatError> {
    validate_reader_options(options)?;
    let len = reader.len()?;
    if len < (VOLUME_HEADER_LEN + VOLUME_TRAILER_LEN) as u64 {
        return Err(FormatError::InvalidLength {
            structure: "archive",
            expected: VOLUME_HEADER_LEN + VOLUME_TRAILER_LEN,
            actual: to_usize(len, "archive length")?,
        });
    }
    let volume_header_bytes = read_at_vec(reader, 0, VOLUME_HEADER_LEN, "archive")?;
    let volume_header = VolumeHeader::parse(&volume_header_bytes)?;
    parse_volume_format_dispatch(&volume_header)?;
    let crypto_start = volume_header.crypto_header_offset as u64;
    let crypto_len = volume_header.crypto_header_length as usize;
    let crypto_bytes = read_at_vec(reader, crypto_start, crypto_len, "CryptoHeader")?;
    let parsed_crypto = CryptoHeader::parse(&crypto_bytes, volume_header.crypto_header_length)?;
    parsed_crypto.validate_extension_semantics()?;
    validate_seekable_supported_volume(
        &volume_header,
        &parsed_crypto.fixed,
        &parsed_crypto.extensions,
    )?;
    validate_crypto_class_parity_exactness(&parsed_crypto.fixed)?;

    let terminal = match locate_v45_public_terminal_read_at(
        reader,
        len,
        &volume_header,
        &parsed_crypto,
        options,
    ) {
        Ok(terminal) => terminal,
        Err(err) => {
            // Distinguish an unsigned archive (root-auth flag clear) from a
            // corrupt one: the public terminal locators are present either
            // way, but the root-auth layout check fails for unsigned volumes.
            if let Some(flags) = public_no_key_layout_flags(reader, len)? {
                if flags & 0x0000_0001 == 0 {
                    return Ok(PublicNoKeyFooterStatus::Unsigned);
                }
            }
            return Err(err);
        }
    };
    let archive_root =
        recompute_public_archive_root(&terminal.root_auth_footer, &parsed_crypto.fixed)?;
    if archive_root != terminal.root_auth_footer.archive_root {
        return Err(FormatError::InvalidArchive(
            "public no-key archive_root mismatch",
        ));
    }
    Ok(PublicNoKeyFooterStatus::Signed(
        PublicNoKeyFooterInspection {
            volume_header,
            crypto_header: parsed_crypto.fixed,
            kdf_params: parsed_crypto.kdf_params,
            root_auth_footer: terminal.root_auth_footer,
            root_auth_footer_bytes: terminal.root_auth_footer_bytes,
            archive_root,
        },
    ))
}

pub(crate) fn parse_public_no_key_volume(
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

    let terminal = locate_v45_public_terminal(bytes, &volume_header, &parsed_crypto, options)?;
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

pub(crate) fn public_crypto_headers_agree(
    left: &CryptoHeaderFixed,
    right: &CryptoHeaderFixed,
) -> bool {
    left.length == right.length
        && left.stripe_width == right.stripe_width
        && left.block_size == right.block_size
        && left.compression_algo == right.compression_algo
        && left.aead_algo == right.aead_algo
        && left.fec_algo == right.fec_algo
        && left.kdf_algo == right.kdf_algo
}

pub(crate) fn public_kdf_profiles_agree(left: &KdfParams, right: &KdfParams) -> bool {
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

pub(crate) fn recompute_public_archive_root(
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

pub(crate) fn parse_valid_manifest_footer(
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

pub(crate) fn manifest_footer_copy_error_is_recoverable(error: &FormatError) -> bool {
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

pub(crate) fn validate_seekable_supported_volume(
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
            "fec_parity_shards does not match v45 compute_parity",
        ));
    }
    let index = required_object_parity(crypto_header.index_fec_data_shards as u64, crypto_header)?;
    if crypto_header.index_fec_parity_shards as u32 != index {
        return Err(FormatError::InvalidArchive(
            "index_fec_parity_shards does not match v45 compute_parity",
        ));
    }
    let index_root = required_object_parity(
        crypto_header.index_root_fec_data_shards as u64,
        crypto_header,
    )?;
    if crypto_header.index_root_fec_parity_shards as u32 != index_root {
        return Err(FormatError::InvalidArchive(
            "index_root_fec_parity_shards does not match v45 compute_parity",
        ));
    }
    Ok(())
}

pub(crate) fn validate_volume_set_member(
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

pub(crate) fn validate_key_wrap_table_bytes_match(
    first_key_wrap_table_bytes: &Option<Vec<u8>>,
    candidate_key_wrap_table_bytes: &Option<Vec<u8>>,
) -> Result<(), FormatError> {
    if candidate_key_wrap_table_bytes != first_key_wrap_table_bytes {
        return Err(FormatError::InvalidArchive("KeyWrapTableV1 copies differ"));
    }
    Ok(())
}

pub(crate) fn validate_volume_set_member_metadata(
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

pub(crate) fn validate_complete_global_block_coverage(
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
