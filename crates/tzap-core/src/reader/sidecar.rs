use super::*;

use std::collections::BTreeMap;

use crate::crypto::{verify_integrity_tag, HmacDomain, Subkeys};
use crate::format::{
    BlockKind, FormatError, BLOCK_RECORD_FRAMING_LEN, BOOTSTRAP_SIDECAR_HEADER_LEN,
    MANIFEST_FOOTER_LEN,
};
use crate::metadata::IndexRoot;
#[cfg(windows)]
use crate::tar_model::replay_windows_descendant_metadata;
use crate::wire::{
    BlockRecord, BootstrapSidecarHeader, CryptoHeaderFixed, ManifestFooter, VolumeHeader,
    VolumeTrailer,
};

pub(crate) fn validate_bootstrap_single_volume_input(
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
pub(crate) struct ParsedBootstrapSidecar {
    pub(crate) manifest_footer: Option<ManifestFooter>,
    pub(crate) index_root_records_section: Option<(u64, u64)>,
    pub(crate) dictionary_records_section: Option<(u64, u64)>,
}

pub(crate) struct NonSeekableBootstrapMaterial {
    pub(crate) manifest_footer: ManifestFooter,
    pub(crate) payload_dictionary: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BootstrapSidecarUse {
    SeekableAssist,
    NonSeekableRandomAccess,
}

impl ParsedBootstrapSidecar {
    pub(crate) fn require_sections_for(
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

pub(crate) fn parse_bootstrap_sidecar(
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

pub(crate) fn index_root_extent_from_manifest(manifest_footer: &ManifestFooter) -> ObjectExtent {
    ObjectExtent {
        first_block_index: manifest_footer.index_root_first_block,
        data_block_count: manifest_footer.index_root_data_block_count,
        parity_block_count: manifest_footer.index_root_parity_block_count,
        encrypted_size: manifest_footer.index_root_encrypted_size,
    }
}

pub(crate) fn insert_sidecar_records(
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

pub(crate) fn validate_sidecar_manifest_footer(
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

pub(crate) fn validate_sidecar_size_cap(
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
pub(crate) struct SidecarBlockRecordsSection {
    pub(crate) offset: u64,
    pub(crate) length: u64,
    pub(crate) extent: ObjectExtent,
    pub(crate) data_kind: BlockKind,
    pub(crate) parity_kind: BlockKind,
    pub(crate) structure: &'static str,
}

pub(crate) fn parse_sidecar_block_records(
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

pub(crate) fn validate_trailer_identity(
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

pub(crate) fn validate_manifest_footer(
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
