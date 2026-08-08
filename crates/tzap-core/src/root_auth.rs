use sha2::{Digest, Sha256};

use crate::format::{
    root_auth_spec_id_for_revision, AeadAlgo, BlockKind, CompressionAlgo, FecAlgo, FormatError, KdfAlgo, FORMAT_VERSION, VOLUME_FORMAT_REV,
    VOLUME_FORMAT_REV_45,
};

const ROOT_AUTH_DESCRIPTOR_DOMAIN: &[u8] = b"tzap-root-auth-descriptor-v1\0";
const ARCHIVE_ROOT_DOMAIN_V45: &[u8] = b"tzap-archive-root-v45\0";
const CRYPTO_HEADER_PRE_HMAC_DOMAIN_V45: &[u8] = b"tzap-crypto-header-pre-hmac-v45\0";
const MANIFEST_FOOTER_GLOBAL_PRE_HMAC_DOMAIN_V45: &[u8] = b"tzap-manifest-footer-global-pre-hmac-v45\0";
const CRITICAL_METADATA_DOMAIN_V45: &[u8] = b"tzap-critical-metadata-v45\0";
const INDEX_ROOT_DOMAIN_V45: &[u8] = b"tzap-index-root-v45\0";
const FEC_LAYOUT_DOMAIN_V45: &[u8] = b"tzap-fec-layout-v45\0";
const DATA_BLOCK_MERKLE_DOMAIN_V45: &[u8] = b"tzap-data-block-merkle-v45\0";
const EMPTY_MERKLE_DOMAIN: &[u8] = b"tzap-empty-merkle-tree-v1\0";
const SIGNER_IDENTITY_DOMAIN: &[u8] = b"tzap-signer-identity-v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FecLayoutObjectRow {
    pub object_class: u8,
    pub present: bool,
    pub object_id: u64,
    pub first_block_index: u64,
    pub data_block_count: u32,
    pub parity_block_count: u32,
    pub encrypted_size: u32,
    pub plain_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataBlockMerkleLeaf {
    pub block_index: u64,
    pub kind: BlockKind,
    pub flags: u8,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub struct CriticalMetadataDigestInputs<'a> {
    pub archive_uuid: [u8; 16],
    pub session_id: [u8; 16],
    pub format_version: u16,
    pub volume_format_rev: u16,
    pub stripe_width: u32,
    pub total_volumes: u32,
    pub compression_algo: CompressionAlgo,
    pub aead_algo: AeadAlgo,
    pub fec_algo: FecAlgo,
    pub kdf_algo: KdfAlgo,
    pub crypto_header_pre_hmac_bytes: &'a [u8],
    pub chunk_size: u32,
    pub envelope_target_size: u32,
    pub block_size: u32,
    pub fec_data_shards: u16,
    pub fec_parity_shards: u16,
    pub index_fec_data_shards: u16,
    pub index_fec_parity_shards: u16,
    pub index_root_fec_data_shards: u16,
    pub index_root_fec_parity_shards: u16,
    pub volume_loss_tolerance: u8,
    pub bit_rot_buffer_pct: u8,
    pub has_dictionary: u8,
    pub manifest_footer_global_pre_hmac_bytes: &'a [u8],
    pub index_root_first_block: u64,
    pub index_root_data_block_count: u32,
    pub index_root_parity_block_count: u32,
    pub index_root_encrypted_size: u32,
    pub index_root_decompressed_size: u32,
    pub root_auth_descriptor_digest: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
pub struct ArchiveRootInputs {
    pub archive_uuid: [u8; 16],
    pub session_id: [u8; 16],
    pub format_version: u16,
    pub volume_format_rev: u16,
    pub compression_algo: CompressionAlgo,
    pub aead_algo: AeadAlgo,
    pub fec_algo: FecAlgo,
    pub kdf_algo: KdfAlgo,
    pub critical_metadata_digest: [u8; 32],
    pub index_digest: [u8; 32],
    pub fec_layout_digest: [u8; 32],
    pub total_data_block_count: u64,
    pub data_block_merkle_root: [u8; 32],
    pub root_auth_descriptor_digest: [u8; 32],
    pub signer_identity_digest: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
struct RootAuthRevisionParams {
    root_auth_spec_id: [u8; 24],
    archive_root_domain: &'static [u8],
    crypto_header_pre_hmac_domain: &'static [u8],
    manifest_footer_global_pre_hmac_domain: &'static [u8],
    critical_metadata_domain: &'static [u8],
    index_root_domain: &'static [u8],
    fec_layout_domain: &'static [u8],
    data_block_merkle_domain: &'static [u8],
}

fn root_auth_revision_params(format_version: u16, volume_format_rev: u16) -> Result<RootAuthRevisionParams, FormatError> {
    let root_auth_spec_id = root_auth_spec_id_for_revision(format_version, volume_format_rev)?;
    if volume_format_rev != VOLUME_FORMAT_REV_45 {
        return Err(FormatError::UnsupportedVolumeFormatRevision {
            format_version,
            volume_format_rev,
            reader_max_supported_revision: VOLUME_FORMAT_REV_45,
        });
    }
    Ok(RootAuthRevisionParams {
        root_auth_spec_id,
        archive_root_domain: ARCHIVE_ROOT_DOMAIN_V45,
        crypto_header_pre_hmac_domain: CRYPTO_HEADER_PRE_HMAC_DOMAIN_V45,
        manifest_footer_global_pre_hmac_domain: MANIFEST_FOOTER_GLOBAL_PRE_HMAC_DOMAIN_V45,
        critical_metadata_domain: CRITICAL_METADATA_DOMAIN_V45,
        index_root_domain: INDEX_ROOT_DOMAIN_V45,
        fec_layout_domain: FEC_LAYOUT_DOMAIN_V45,
        data_block_merkle_domain: DATA_BLOCK_MERKLE_DOMAIN_V45,
    })
}

pub fn root_auth_descriptor_digest(
    authenticator_id: u16,
    signer_identity_type: u16,
    signer_identity_bytes: &[u8],
    authenticator_value_length: u32,
    footer_length: u32,
) -> Result<[u8; 32], FormatError> {
    root_auth_descriptor_digest_for_revision(
        FORMAT_VERSION,
        VOLUME_FORMAT_REV,
        authenticator_id,
        signer_identity_type,
        signer_identity_bytes,
        authenticator_value_length,
        footer_length,
    )
}

pub fn root_auth_descriptor_digest_for_revision(
    format_version: u16,
    volume_format_rev: u16,
    authenticator_id: u16,
    signer_identity_type: u16,
    signer_identity_bytes: &[u8],
    authenticator_value_length: u32,
    footer_length: u32,
) -> Result<[u8; 32], FormatError> {
    let params = root_auth_revision_params(format_version, volume_format_rev)?;
    let signer_identity_length =
        u32::try_from(signer_identity_bytes.len()).map_err(|_| FormatError::InvalidArchive("root-auth signer identity length overflow"))?;
    let signer_identity_hash = sha256_bytes(signer_identity_bytes);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(ROOT_AUTH_DESCRIPTOR_DOMAIN);
    bytes.extend_from_slice(&params.root_auth_spec_id);
    push_u16(&mut bytes, authenticator_id);
    push_u16(&mut bytes, signer_identity_type);
    push_u32(&mut bytes, signer_identity_length);
    bytes.extend_from_slice(&signer_identity_hash);
    push_u32(&mut bytes, authenticator_value_length);
    push_u32(&mut bytes, footer_length);
    Ok(sha256_bytes(&bytes))
}

pub fn signer_identity_digest(signer_identity_type: u16, signer_identity_bytes: &[u8]) -> Result<[u8; 32], FormatError> {
    let signer_identity_length =
        u32::try_from(signer_identity_bytes.len()).map_err(|_| FormatError::InvalidArchive("root-auth signer identity length overflow"))?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(SIGNER_IDENTITY_DOMAIN);
    push_u16(&mut bytes, signer_identity_type);
    push_u32(&mut bytes, signer_identity_length);
    bytes.extend_from_slice(signer_identity_bytes);
    Ok(sha256_bytes(&bytes))
}

pub fn critical_metadata_digest(inputs: CriticalMetadataDigestInputs<'_>) -> Result<[u8; 32], FormatError> {
    let params = root_auth_revision_params(inputs.format_version, inputs.volume_format_rev)?;
    let crypto_header_pre_hmac_digest = len_prefixed_digest(params.crypto_header_pre_hmac_domain, inputs.crypto_header_pre_hmac_bytes)?;
    let manifest_footer_global_pre_hmac_digest =
        len_prefixed_digest(params.manifest_footer_global_pre_hmac_domain, inputs.manifest_footer_global_pre_hmac_bytes)?;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(params.critical_metadata_domain);
    bytes.extend_from_slice(&inputs.archive_uuid);
    bytes.extend_from_slice(&inputs.session_id);
    push_u16(&mut bytes, inputs.format_version);
    push_u16(&mut bytes, inputs.volume_format_rev);
    push_u32(&mut bytes, inputs.stripe_width);
    push_u32(&mut bytes, inputs.total_volumes);
    push_u16(&mut bytes, inputs.compression_algo as u16);
    push_u16(&mut bytes, inputs.aead_algo as u16);
    push_u16(&mut bytes, inputs.fec_algo as u16);
    push_u16(&mut bytes, inputs.kdf_algo as u16);
    bytes.extend_from_slice(&crypto_header_pre_hmac_digest);
    push_u32(&mut bytes, inputs.chunk_size);
    push_u32(&mut bytes, inputs.envelope_target_size);
    push_u32(&mut bytes, inputs.block_size);
    push_u16(&mut bytes, inputs.fec_data_shards);
    push_u16(&mut bytes, inputs.fec_parity_shards);
    push_u16(&mut bytes, inputs.index_fec_data_shards);
    push_u16(&mut bytes, inputs.index_fec_parity_shards);
    push_u16(&mut bytes, inputs.index_root_fec_data_shards);
    push_u16(&mut bytes, inputs.index_root_fec_parity_shards);
    bytes.push(inputs.volume_loss_tolerance);
    bytes.push(inputs.bit_rot_buffer_pct);
    bytes.push(inputs.has_dictionary);
    bytes.extend_from_slice(&manifest_footer_global_pre_hmac_digest);
    push_u64(&mut bytes, inputs.index_root_first_block);
    push_u32(&mut bytes, inputs.index_root_data_block_count);
    push_u32(&mut bytes, inputs.index_root_parity_block_count);
    push_u32(&mut bytes, inputs.index_root_encrypted_size);
    push_u32(&mut bytes, inputs.index_root_decompressed_size);
    bytes.extend_from_slice(&inputs.root_auth_descriptor_digest);
    Ok(sha256_bytes(&bytes))
}

pub fn index_digest(index_root_plaintext: &[u8]) -> [u8; 32] {
    index_digest_for_revision(FORMAT_VERSION, VOLUME_FORMAT_REV, index_root_plaintext).expect("default RootAuth revision is supported")
}

pub fn index_digest_for_revision(format_version: u16, volume_format_rev: u16, index_root_plaintext: &[u8]) -> Result<[u8; 32], FormatError> {
    let params = root_auth_revision_params(format_version, volume_format_rev)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(params.index_root_domain);
    bytes.extend_from_slice(index_root_plaintext);
    Ok(sha256_bytes(&bytes))
}

pub fn fec_layout_digest(rows: &[FecLayoutObjectRow]) -> Result<[u8; 32], FormatError> {
    fec_layout_digest_for_revision(FORMAT_VERSION, VOLUME_FORMAT_REV, rows)
}

pub fn fec_layout_digest_for_revision(format_version: u16, volume_format_rev: u16, rows: &[FecLayoutObjectRow]) -> Result<[u8; 32], FormatError> {
    let params = root_auth_revision_params(format_version, volume_format_rev)?;
    let row_count = u32::try_from(rows.len()).map_err(|_| FormatError::InvalidArchive("root-auth FEC row count overflow"))?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(params.fec_layout_domain);
    push_u32(&mut bytes, row_count);
    for row in rows {
        bytes.push(row.object_class);
        bytes.push(if row.present { 1 } else { 0 });
        push_u16(&mut bytes, 0);
        push_u64(&mut bytes, row.object_id);
        push_u64(&mut bytes, row.first_block_index);
        push_u32(&mut bytes, row.data_block_count);
        push_u32(&mut bytes, row.parity_block_count);
        push_u32(&mut bytes, row.encrypted_size);
        push_u32(&mut bytes, row.plain_size);
    }
    Ok(sha256_bytes(&bytes))
}

pub fn data_block_merkle_root(leaves: &[DataBlockMerkleLeaf]) -> [u8; 32] {
    data_block_merkle_root_for_revision(FORMAT_VERSION, VOLUME_FORMAT_REV, leaves).expect("default RootAuth revision is supported")
}

pub fn data_block_merkle_root_for_revision(format_version: u16, volume_format_rev: u16, leaves: &[DataBlockMerkleLeaf]) -> Result<[u8; 32], FormatError> {
    let params = root_auth_revision_params(format_version, volume_format_rev)?;
    if leaves.is_empty() {
        return Ok(empty_data_block_merkle_root(params));
    }

    let leaf_hashes = leaves
        .iter()
        .map(|leaf| data_block_merkle_leaf_hash_with_params(params, leaf.block_index, leaf.kind, leaf.flags, &leaf.payload))
        .collect::<Vec<_>>();
    Ok(data_block_merkle_root_from_leaf_hashes_with_params(params, &leaf_hashes))
}

pub fn data_block_merkle_leaf_hash(block_index: u64, kind: BlockKind, flags: u8, payload: &[u8]) -> [u8; 32] {
    data_block_merkle_leaf_hash_for_revision(FORMAT_VERSION, VOLUME_FORMAT_REV, block_index, kind, flags, payload)
        .expect("default RootAuth revision is supported")
}

pub fn data_block_merkle_leaf_hash_for_revision(
    format_version: u16,
    volume_format_rev: u16,
    block_index: u64,
    kind: BlockKind,
    flags: u8,
    payload: &[u8],
) -> Result<[u8; 32], FormatError> {
    let params = root_auth_revision_params(format_version, volume_format_rev)?;
    Ok(data_block_merkle_leaf_hash_with_params(params, block_index, kind, flags, payload))
}

fn data_block_merkle_leaf_hash_with_params(params: RootAuthRevisionParams, block_index: u64, kind: BlockKind, flags: u8, payload: &[u8]) -> [u8; 32] {
    let mut leaf_payload = Vec::with_capacity(10 + payload.len());
    push_u64(&mut leaf_payload, block_index);
    leaf_payload.push(kind as u8);
    leaf_payload.push(flags);
    leaf_payload.extend_from_slice(payload);

    let mut bytes = Vec::new();
    bytes.push(0x00);
    bytes.extend_from_slice(params.data_block_merkle_domain);
    bytes.extend_from_slice(&leaf_payload);
    sha256_bytes(&bytes)
}

pub fn data_block_merkle_root_from_leaf_hashes(leaf_hashes: &[[u8; 32]]) -> [u8; 32] {
    data_block_merkle_root_from_leaf_hashes_for_revision(FORMAT_VERSION, VOLUME_FORMAT_REV, leaf_hashes).expect("default RootAuth revision is supported")
}

pub fn data_block_merkle_root_from_leaf_hashes_for_revision(
    format_version: u16,
    volume_format_rev: u16,
    leaf_hashes: &[[u8; 32]],
) -> Result<[u8; 32], FormatError> {
    let params = root_auth_revision_params(format_version, volume_format_rev)?;
    Ok(data_block_merkle_root_from_leaf_hashes_with_params(params, leaf_hashes))
}

fn data_block_merkle_root_from_leaf_hashes_with_params(params: RootAuthRevisionParams, leaf_hashes: &[[u8; 32]]) -> [u8; 32] {
    if leaf_hashes.is_empty() {
        return empty_data_block_merkle_root(params);
    }

    let mut level = leaf_hashes.to_vec();

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut idx = 0usize;
        while idx < level.len() {
            if idx + 1 == level.len() {
                next.push(level[idx]);
            } else {
                let mut bytes = Vec::new();
                bytes.push(0x01);
                bytes.extend_from_slice(params.data_block_merkle_domain);
                bytes.extend_from_slice(&level[idx]);
                bytes.extend_from_slice(&level[idx + 1]);
                next.push(sha256_bytes(&bytes));
            }
            idx += 2;
        }
        level = next;
    }
    level[0]
}

fn empty_data_block_merkle_root(params: RootAuthRevisionParams) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(EMPTY_MERKLE_DOMAIN);
    bytes.extend_from_slice(params.data_block_merkle_domain);
    sha256_bytes(&bytes)
}

pub fn archive_root(inputs: ArchiveRootInputs) -> [u8; 32] {
    archive_root_for_revision(inputs).expect("ArchiveRootInputs revision is supported")
}

pub fn archive_root_for_revision(inputs: ArchiveRootInputs) -> Result<[u8; 32], FormatError> {
    let params = root_auth_revision_params(inputs.format_version, inputs.volume_format_rev)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(params.archive_root_domain);
    bytes.extend_from_slice(&params.root_auth_spec_id);
    bytes.extend_from_slice(&inputs.archive_uuid);
    bytes.extend_from_slice(&inputs.session_id);
    push_u16(&mut bytes, inputs.format_version);
    push_u16(&mut bytes, inputs.volume_format_rev);
    push_u16(&mut bytes, inputs.compression_algo as u16);
    push_u16(&mut bytes, inputs.aead_algo as u16);
    push_u16(&mut bytes, inputs.fec_algo as u16);
    push_u16(&mut bytes, inputs.kdf_algo as u16);
    bytes.extend_from_slice(&inputs.critical_metadata_digest);
    bytes.extend_from_slice(&inputs.index_digest);
    bytes.extend_from_slice(&inputs.fec_layout_digest);
    push_u64(&mut bytes, inputs.total_data_block_count);
    bytes.extend_from_slice(&inputs.data_block_merkle_root);
    bytes.extend_from_slice(&inputs.root_auth_descriptor_digest);
    bytes.extend_from_slice(&inputs.signer_identity_digest);
    Ok(sha256_bytes(&bytes))
}

fn len_prefixed_digest(domain: &[u8], payload: &[u8]) -> Result<[u8; 32], FormatError> {
    let length = u32::try_from(payload.len()).map_err(|_| FormatError::InvalidArchive("root-auth digest input length overflow"))?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(domain);
    push_u32(&mut bytes, length);
    bytes.extend_from_slice(payload);
    Ok(sha256_bytes(&bytes))
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn push_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_archive_inputs(volume_format_rev: u16, kdf_algo: KdfAlgo, critical_metadata_digest: [u8; 32]) -> ArchiveRootInputs {
        ArchiveRootInputs {
            archive_uuid: [1; 16],
            session_id: [2; 16],
            format_version: FORMAT_VERSION,
            volume_format_rev,
            compression_algo: CompressionAlgo::None,
            aead_algo: AeadAlgo::None,
            fec_algo: FecAlgo::None,
            kdf_algo,
            critical_metadata_digest,
            index_digest: [3; 32],
            fec_layout_digest: [4; 32],
            total_data_block_count: 2,
            data_block_merkle_root: [5; 32],
            root_auth_descriptor_digest: [6; 32],
            signer_identity_digest: [7; 32],
        }
    }

    fn sample_critical_inputs<'a>(
        volume_format_rev: u16,
        kdf_algo: KdfAlgo,
        crypto_header_pre_hmac_bytes: &'a [u8],
        root_auth_descriptor_digest: [u8; 32],
    ) -> CriticalMetadataDigestInputs<'a> {
        CriticalMetadataDigestInputs {
            archive_uuid: [1; 16],
            session_id: [2; 16],
            format_version: FORMAT_VERSION,
            volume_format_rev,
            stripe_width: 1,
            total_volumes: 1,
            compression_algo: CompressionAlgo::None,
            aead_algo: AeadAlgo::None,
            fec_algo: FecAlgo::None,
            kdf_algo,
            crypto_header_pre_hmac_bytes,
            chunk_size: 256 * 1024,
            envelope_target_size: 1024 * 1024,
            block_size: 64 * 1024,
            fec_data_shards: 1,
            fec_parity_shards: 0,
            index_fec_data_shards: 1,
            index_fec_parity_shards: 0,
            index_root_fec_data_shards: 1,
            index_root_fec_parity_shards: 0,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            has_dictionary: 0,
            manifest_footer_global_pre_hmac_bytes: b"manifest-footer-pre-hmac",
            index_root_first_block: 0,
            index_root_data_block_count: 1,
            index_root_parity_block_count: 0,
            index_root_encrypted_size: 4096,
            index_root_decompressed_size: 256,
            root_auth_descriptor_digest,
        }
    }

    #[test]
    fn root_auth_wrappers_use_current_revision_domains() {
        let descriptor = root_auth_descriptor_digest(1, 1, b"identity", 64, 512).unwrap();
        assert_eq!(
            descriptor,
            root_auth_descriptor_digest_for_revision(FORMAT_VERSION, VOLUME_FORMAT_REV, 1, 1, b"identity", 64, 512,).unwrap()
        );

        assert_eq!(
            index_digest(b"index-root"),
            index_digest_for_revision(FORMAT_VERSION, VOLUME_FORMAT_REV, b"index-root").unwrap()
        );
        assert_eq!(
            data_block_merkle_root_from_leaf_hashes(&[[9; 32], [10; 32]]),
            data_block_merkle_root_from_leaf_hashes_for_revision(FORMAT_VERSION, VOLUME_FORMAT_REV, &[[9; 32], [10; 32]],).unwrap()
        );

        let inputs = sample_archive_inputs(VOLUME_FORMAT_REV, KdfAlgo::None, [8; 32]);
        assert_eq!(archive_root(inputs), archive_root_for_revision(inputs).unwrap());
    }

    #[test]
    fn archive_root_rejects_legacy_revision_43() {
        assert_eq!(
            archive_root_for_revision(sample_archive_inputs(43, KdfAlgo::None, [8; 32])).unwrap_err(),
            FormatError::UnsupportedVolumeFormatRevision {
                format_version: FORMAT_VERSION,
                volume_format_rev: 43,
                reader_max_supported_revision: VOLUME_FORMAT_REV_45,
            }
        );
        archive_root_for_revision(sample_archive_inputs(VOLUME_FORMAT_REV_45, KdfAlgo::None, [8; 32])).unwrap();
    }

    #[test]
    fn v45_recipient_wrap_archive_root_commits_keywrap_table_digest() {
        let descriptor = root_auth_descriptor_digest_for_revision(FORMAT_VERSION, VOLUME_FORMAT_REV_45, 1, 1, b"identity", 64, 512).unwrap();
        let critical_a = critical_metadata_digest(sample_critical_inputs(
            VOLUME_FORMAT_REV_45,
            KdfAlgo::RecipientWrap,
            b"crypto-header-pre-hmac keywrap-table-digest A",
            descriptor,
        ))
        .unwrap();
        let critical_b = critical_metadata_digest(sample_critical_inputs(
            VOLUME_FORMAT_REV_45,
            KdfAlgo::RecipientWrap,
            b"crypto-header-pre-hmac keywrap-table-digest B",
            descriptor,
        ))
        .unwrap();

        assert_ne!(critical_a, critical_b);
        assert_ne!(
            archive_root_for_revision(sample_archive_inputs(VOLUME_FORMAT_REV_45, KdfAlgo::RecipientWrap, critical_a,)).unwrap(),
            archive_root_for_revision(sample_archive_inputs(VOLUME_FORMAT_REV_45, KdfAlgo::RecipientWrap, critical_b,)).unwrap(),
        );
    }
}
