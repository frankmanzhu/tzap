use tzap_core::compression::compress_zstd_frame;
use tzap_core::entry_metadata::EXTENDED_METADATA_V1;
use tzap_core::format::{
    AeadAlgo, BlockKind, CompressionAlgo, FecAlgo, KdfAlgo, CRITICAL_METADATA_RECOVERY_HEADER_LEN,
    CRYPTO_EXTENSION_HEADER_LEN, CRYPTO_HEADER_FIXED_LEN, CRYPTO_HEADER_HMAC_LEN, FORMAT_VERSION,
    MANIFEST_FOOTER_LEN, VOLUME_FORMAT_REV, VOLUME_HEADER_LEN,
};
use tzap_core::metadata::{
    hash_prefix, DirectoryHintEntry, DirectoryHintShardEntry, DirectoryHintTable,
    DirectoryHintTableHeader, EnvelopeEntry, FileEntry, FrameEntry, IndexRoot, IndexRootHeader,
    IndexShard, IndexShardHeader, MetadataLimits, ShardEntry, DIRECTORY_HINT_ENTRY_LEN,
    DIRECTORY_HINT_TABLE_LEN, ENVELOPE_ENTRY_LEN, FILE_ENTRY_LEN, FRAME_ENTRY_LEN,
    INDEX_SHARD_HEADER_LEN,
};
use tzap_core::padding::suffix_pad_for_aead;
use tzap_core::wire::{
    BlockRecord, BootstrapSidecarHeader, CriticalMetadataImage, CriticalMetadataRecoveryHeader,
    CriticalMetadataRecoveryShard, CriticalRecoveryLocator, CryptoHeaderFixed, ManifestFooter,
    RootAuthFooterV1, SerializedRegion, VolumeHeader, VolumeTrailer,
};

pub struct Seed {
    pub target: &'static str,
    pub name: &'static str,
    pub bytes: Vec<u8>,
}

pub fn structured_seeds() -> Vec<Seed> {
    vec![
        fixed("valid-volume-header", valid_volume_header()),
        fixed(
            "valid-crypto-header-with-tlv",
            valid_crypto_header_with_tlv(),
        ),
        fixed("valid-block-record-crc", valid_block_record()),
        fixed("valid-manifest-footer", valid_manifest_footer()),
        fixed("valid-root-auth-footer", valid_root_auth_footer()),
        fixed(
            "valid-ed25519-authenticator-value",
            valid_ed25519_authenticator_value(),
        ),
        fixed("valid-volume-trailer", valid_volume_trailer()),
        fixed(
            "valid-critical-metadata-image",
            valid_critical_metadata_image(),
        ),
        fixed("valid-cmra-header", valid_cmra_header()),
        fixed("valid-cmra-data-shard", valid_cmra_data_shard()),
        fixed(
            "valid-critical-recovery-locator",
            valid_critical_recovery_locator(),
        ),
        fixed(
            "valid-bootstrap-sidecar-header",
            valid_bootstrap_sidecar_header(),
        ),
        metadata("valid-empty-index-root", valid_empty_index_root()),
        metadata(
            "valid-index-root-with-shard-and-hint",
            valid_index_root_with_rows(),
        ),
        metadata("valid-index-shard", valid_index_shard()),
        metadata("valid-directory-hint-table", valid_directory_hint_table()),
        compressed(
            "valid-zstd-frame-with-size-prefix",
            valid_zstd_frame_with_size_prefix(),
        ),
        compressed("valid-wide-padding", valid_wide_padding()),
    ]
}

pub fn assert_structured_seed_success(seed: &Seed) -> Result<(), String> {
    match (seed.target, seed.name) {
        ("parse_fixed_structures", "valid-volume-header") => {
            VolumeHeader::parse(&seed.bytes).map_err(|err| err.to_string())?;
        }
        ("parse_fixed_structures", "valid-crypto-header-with-tlv") => {
            let header = tzap_core::wire::CryptoHeader::parse(&seed.bytes, seed.bytes.len() as u32)
                .map_err(|err| err.to_string())?;
            header
                .validate_extension_semantics()
                .map_err(|err| err.to_string())?;
        }
        ("parse_fixed_structures", "valid-block-record-crc") => {
            BlockRecord::parse(&seed.bytes, b"seed-block-bytes".len())
                .map_err(|err| err.to_string())?;
        }
        ("parse_fixed_structures", "valid-manifest-footer") => {
            ManifestFooter::parse(&seed.bytes).map_err(|err| err.to_string())?;
        }
        ("parse_fixed_structures", "valid-root-auth-footer") => {
            RootAuthFooterV1::parse(&seed.bytes).map_err(|err| err.to_string())?;
        }
        ("parse_fixed_structures", "valid-volume-trailer") => {
            VolumeTrailer::parse(&seed.bytes).map_err(|err| err.to_string())?;
        }
        ("parse_fixed_structures", "valid-critical-metadata-image") => {
            CriticalMetadataImage::parse(&seed.bytes).map_err(|err| err.to_string())?;
        }
        ("parse_fixed_structures", "valid-cmra-header") => {
            CriticalMetadataRecoveryHeader::parse(&seed.bytes).map_err(|err| err.to_string())?;
        }
        ("parse_fixed_structures", "valid-cmra-data-shard") => {
            CriticalMetadataRecoveryShard::parse(&seed.bytes, 16).map_err(|err| err.to_string())?;
        }
        ("parse_fixed_structures", "valid-critical-recovery-locator") => {
            CriticalRecoveryLocator::parse(&seed.bytes).map_err(|err| err.to_string())?;
        }
        ("parse_fixed_structures", "valid-bootstrap-sidecar-header") => {
            BootstrapSidecarHeader::parse(&seed.bytes).map_err(|err| err.to_string())?;
        }
        ("parse_metadata", "valid-empty-index-root") => {
            IndexRoot::parse(&seed.bytes, false, MetadataLimits::default())
                .map_err(|err| err.to_string())?;
        }
        ("parse_metadata", "valid-index-root-with-shard-and-hint") => {
            IndexRoot::parse(&seed.bytes, false, MetadataLimits::default())
                .map_err(|err| err.to_string())?;
        }
        ("parse_metadata", "valid-index-shard") => {
            let path_hash = hash_prefix(b"file.txt");
            let locating = ShardEntry {
                shard_index: 0,
                first_block_index: 10,
                data_block_count: 1,
                parity_block_count: 0,
                encrypted_size: 4096,
                decompressed_size: seed.bytes.len() as u32,
                file_count: 1,
                first_path_hash: path_hash,
                last_path_hash: path_hash,
            };
            IndexShard::parse(&seed.bytes, &locating, MetadataLimits::default())
                .map_err(|err| err.to_string())?;
        }
        ("parse_metadata", "valid-directory-hint-table") => {
            let dir_hash = hash_prefix(b"dir");
            let locating = DirectoryHintShardEntry {
                hint_shard_index: 0,
                first_dir_hash: dir_hash,
                last_dir_hash: dir_hash,
                first_block_index: 0,
                data_block_count: 1,
                parity_block_count: 0,
                encrypted_size: 4096,
                decompressed_size: seed.bytes.len() as u32,
                entry_count: 1,
            };
            DirectoryHintTable::parse(&seed.bytes, &locating, 1, MetadataLimits::default())
                .map_err(|err| err.to_string())?;
        }
        ("parse_compressed_and_padding", "valid-zstd-frame-with-size-prefix") => {
            let expected_size = u32::from_le_bytes(
                seed.bytes[..4]
                    .try_into()
                    .expect("fixed seed includes size prefix"),
            ) as usize;
            tzap_core::compression::decompress_exact_zstd_frame(&seed.bytes[4..], expected_size)
                .map_err(|err| err.to_string())?;
        }
        ("parse_compressed_and_padding", "valid-wide-padding") => {
            tzap_core::padding::depad_suffix_padding(&seed.bytes).map_err(|err| err.to_string())?;
        }
        _ => {}
    }
    Ok(())
}

fn fixed(name: &'static str, bytes: Vec<u8>) -> Seed {
    Seed {
        target: "parse_fixed_structures",
        name,
        bytes,
    }
}

fn metadata(name: &'static str, bytes: Vec<u8>) -> Seed {
    Seed {
        target: "parse_metadata",
        name,
        bytes,
    }
}

fn compressed(name: &'static str, bytes: Vec<u8>) -> Seed {
    Seed {
        target: "parse_compressed_and_padding",
        name,
        bytes,
    }
}

fn uuid() -> [u8; 16] {
    *b"seed-archive-id!"
}

fn session() -> [u8; 16] {
    *b"seed-session-id!"
}

fn valid_volume_header() -> Vec<u8> {
    VolumeHeader {
        format_version: FORMAT_VERSION,
        volume_format_rev: VOLUME_FORMAT_REV,
        volume_index: 0,
        stripe_width: 1,
        archive_uuid: uuid(),
        session_id: session(),
        crypto_header_offset: VOLUME_HEADER_LEN as u32,
        crypto_header_length: valid_crypto_header_with_tlv().len() as u32,
        header_crc32c: 0,
    }
    .to_bytes()
    .to_vec()
}

fn valid_crypto_header_with_tlv() -> Vec<u8> {
    let length = CRYPTO_HEADER_FIXED_LEN
        + 2
        + CRYPTO_EXTENSION_HEADER_LEN
        + 4
        + CRYPTO_EXTENSION_HEADER_LEN
        + CRYPTO_HEADER_HMAC_LEN;
    let fixed = CryptoHeaderFixed {
        length: length as u32,
        compression_algo: CompressionAlgo::ZstdFramed,
        aead_algo: AeadAlgo::AesGcmSiv256,
        fec_algo: FecAlgo::ReedSolomonGF16,
        kdf_algo: KdfAlgo::Raw,
        chunk_size: 262_144,
        envelope_target_size: 4 * 1024 * 1024,
        block_size: 4096,
        fec_data_shards: 16,
        fec_parity_shards: 2,
        index_fec_data_shards: 16,
        index_fec_parity_shards: 2,
        index_root_fec_data_shards: 16,
        index_root_fec_parity_shards: 2,
        stripe_width: 1,
        volume_loss_tolerance: 0,
        bit_rot_buffer_pct: 5,
        has_dictionary: 0,
        max_path_length: 4096,
        expected_volume_size: 0,
    };
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&fixed.to_bytes());
    bytes.extend_from_slice(&(KdfAlgo::Raw as u16).to_le_bytes());
    bytes.extend_from_slice(&0x1234u16.to_le_bytes());
    bytes.extend_from_slice(&4u32.to_le_bytes());
    bytes.extend_from_slice(b"seed");
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&[0xab; CRYPTO_HEADER_HMAC_LEN]);
    bytes
}

fn valid_block_record() -> Vec<u8> {
    BlockRecord {
        block_index: 0,
        kind: BlockKind::PayloadData,
        flags: 0x01,
        payload: b"seed-block-bytes".to_vec(),
        record_crc32c: 0,
    }
    .to_bytes()
}

fn valid_manifest_footer() -> Vec<u8> {
    ManifestFooter {
        archive_uuid: uuid(),
        session_id: session(),
        volume_index: 0,
        is_authoritative: 1,
        total_volumes: 1,
        index_root_first_block: 1,
        index_root_data_block_count: 1,
        index_root_parity_block_count: 0,
        index_root_encrypted_size: 4096,
        index_root_decompressed_size: 128,
        manifest_hmac: [0xcd; 32],
    }
    .to_bytes()
    .to_vec()
}

fn valid_root_auth_footer() -> Vec<u8> {
    RootAuthFooterV1 {
        archive_uuid: uuid(),
        session_id: session(),
        format_version: FORMAT_VERSION,
        volume_format_rev: VOLUME_FORMAT_REV,
        authenticator_id: 0x0002,
        signer_identity_type: 1,
        signer_identity_bytes: [0x11; 32].to_vec(),
        authenticator_value: [0x22; 68].to_vec(),
        total_data_block_count: 1,
        critical_metadata_digest: [0x31; 32],
        index_digest: [0x32; 32],
        fec_layout_digest: [0x33; 32],
        data_block_merkle_root: [0x34; 32],
        signer_identity_digest: [0x35; 32],
        archive_root: [0x36; 32],
        footer_crc32c: 0,
    }
    .to_bytes()
    .expect("fixed root-auth footer seed builds")
}

fn valid_ed25519_authenticator_value() -> Vec<u8> {
    let mut value = vec![0u8; 68];
    value[0..2].copy_from_slice(&1u16.to_le_bytes());
    value[4..68].copy_from_slice(&[0x23; 64]);
    value
}

fn valid_volume_trailer() -> Vec<u8> {
    VolumeTrailer {
        archive_uuid: uuid(),
        session_id: session(),
        volume_index: 0,
        block_count: 1,
        bytes_written: 4096,
        manifest_footer_offset: 4096,
        manifest_footer_length: MANIFEST_FOOTER_LEN as u32,
        closed_at_ns: 0,
        root_auth_footer_offset: 0,
        root_auth_footer_length: 0,
        root_auth_flags: 0,
        trailer_hmac: [0xef; 32],
    }
    .to_bytes()
    .to_vec()
}

fn valid_critical_metadata_image() -> Vec<u8> {
    CriticalMetadataImage {
        volume_format_rev: VOLUME_FORMAT_REV,
        archive_uuid: uuid(),
        session_id: session(),
        volume_index: 0,
        stripe_width: 1,
        layout_flags: 0,
        volume_header_offset: 0,
        volume_header_length: VOLUME_HEADER_LEN as u32,
        crypto_header_offset: VOLUME_HEADER_LEN as u64,
        crypto_header_length: valid_crypto_header_with_tlv().len() as u32,
        key_wrap_table_offset: 0,
        key_wrap_table_length: 0,
        block_records_offset: 256,
        block_records_length: 4096,
        block_count: 1,
        manifest_footer_offset: 4352,
        manifest_footer_length: MANIFEST_FOOTER_LEN as u32,
        root_auth_footer_offset: 0,
        root_auth_footer_length: 0,
        volume_trailer_offset: 4488,
        volume_trailer_length: 128,
        body_bytes_before_cmra: 4616,
        volume_header_sha256: [0x41; 32],
        crypto_header_sha256: [0x42; 32],
        key_wrap_table_sha256: [0; 32],
        manifest_footer_sha256: [0x43; 32],
        root_auth_footer_sha256: [0; 32],
        volume_trailer_sha256: [0x44; 32],
        regions: vec![SerializedRegion {
            region_type: 1,
            offset: 0,
            bytes: b"VH".to_vec(),
        }],
    }
    .to_bytes()
    .expect("fixed critical metadata image seed builds")
}

fn valid_cmra_header() -> Vec<u8> {
    CriticalMetadataRecoveryHeader {
        shard_size: 16,
        data_shard_count: 1,
        parity_shard_count: 1,
        image_length: valid_critical_metadata_image().len() as u32,
        archive_uuid_hint: uuid(),
        session_id_hint: session(),
        volume_index_hint: 0,
        image_sha256: [0x45; 32],
        header_crc32c: 0,
    }
    .to_bytes()
    .to_vec()
}

fn valid_cmra_data_shard() -> Vec<u8> {
    CriticalMetadataRecoveryShard {
        shard_index: 0,
        shard_role: 0,
        shard_payload_length: 16,
        payload: [0x46; 16].to_vec(),
        shard_crc32c: 0,
    }
    .to_bytes(16)
    .expect("fixed CMRA shard seed builds")
}

fn valid_critical_recovery_locator() -> Vec<u8> {
    CriticalRecoveryLocator {
        volume_format_rev: VOLUME_FORMAT_REV,
        cmra_offset: 4616,
        cmra_length: CRITICAL_METADATA_RECOVERY_HEADER_LEN as u32 + 2 * (16 + 16),
        volume_trailer_offset: 4488,
        body_bytes_before_cmra: 4616,
        archive_uuid_hint: uuid(),
        session_id_hint: session(),
        volume_index_hint: 0,
        locator_sequence: 0,
        cmra_shard_size: 16,
        cmra_data_shard_count: 1,
        cmra_parity_shard_count: 1,
        cmra_image_length: valid_critical_metadata_image().len() as u32,
        cmra_image_sha256: [0x45; 32],
        locator_crc32c: 0,
    }
    .to_bytes()
    .to_vec()
}

fn valid_bootstrap_sidecar_header() -> Vec<u8> {
    BootstrapSidecarHeader {
        archive_uuid: uuid(),
        session_id: session(),
        flags: 0x03,
        manifest_footer_offset: 128,
        manifest_footer_length: MANIFEST_FOOTER_LEN as u32,
        index_root_records_offset: 128 + MANIFEST_FOOTER_LEN as u64,
        index_root_records_length: 40,
        dictionary_records_offset: 0,
        dictionary_records_length: 0,
        sidecar_hmac: [0x55; 32],
        header_crc32c: 0,
    }
    .to_bytes()
    .to_vec()
}

fn valid_empty_index_root() -> Vec<u8> {
    IndexRoot {
        header: IndexRootHeader::empty(),
        shards: Vec::new(),
        directory_hint_shards: Vec::new(),
    }
    .to_bytes()
}

fn valid_index_root_with_rows() -> Vec<u8> {
    let file_hash = hash_prefix(b"file.txt");
    let dir_hash = hash_prefix(b"dir");
    IndexRoot {
        header: IndexRootHeader {
            file_count: 1,
            frame_count: 1,
            envelope_count: 1,
            payload_block_count: 1,
            tar_total_size: 512,
            ..IndexRootHeader::empty()
        },
        shards: vec![ShardEntry {
            shard_index: 0,
            first_block_index: 2,
            data_block_count: 1,
            parity_block_count: 0,
            encrypted_size: 4096,
            decompressed_size: 256,
            file_count: 1,
            first_path_hash: file_hash,
            last_path_hash: file_hash,
        }],
        directory_hint_shards: vec![DirectoryHintShardEntry {
            hint_shard_index: 0,
            first_dir_hash: dir_hash,
            last_dir_hash: dir_hash,
            first_block_index: 3,
            data_block_count: 1,
            parity_block_count: 0,
            encrypted_size: 4096,
            decompressed_size: 128,
            entry_count: 1,
        }],
    }
    .to_bytes()
}

fn valid_index_shard() -> Vec<u8> {
    let path = b"file.txt";
    let path_hash = hash_prefix(path);
    let frame_table_offset = INDEX_SHARD_HEADER_LEN + FILE_ENTRY_LEN;
    let envelope_table_offset = frame_table_offset + FRAME_ENTRY_LEN;
    let string_pool_offset = envelope_table_offset + ENVELOPE_ENTRY_LEN;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(
        &IndexShardHeader {
            version: 1,
            shard_index: 0,
            file_count: 1,
            frame_count: 1,
            envelope_count: 1,
            file_table_offset: INDEX_SHARD_HEADER_LEN as u32,
            frame_table_offset: frame_table_offset as u32,
            envelope_table_offset: envelope_table_offset as u32,
            string_pool_offset: string_pool_offset as u32,
            string_pool_size: path.len() as u32,
        }
        .to_bytes(),
    );
    bytes.extend_from_slice(
        &FileEntry {
            path_hash,
            path_offset: 0,
            path_length: path.len() as u32,
            first_frame_index: 0,
            frame_count: 1,
            offset_in_first_frame_plaintext: 0,
            tar_member_group_size: 1536,
            file_data_size: 0,
            flags: EXTENDED_METADATA_V1,
            mtime_nsec: 0,
            mtime_sec: 0,
            created_nsec: 0,
            created_sec: 0,
            accessed_nsec: 0,
            accessed_sec: 0,
            uid: 0,
            gid: 0,
            mode: 0,
            attributes: 0,
            uname_offset: 0,
            uname_length: 0,
            gname_offset: 0,
            gname_length: 0,
            link_target_offset: 0,
            link_target_length: 0,
            kind: 0,
            metadata_flags: 0,
            _reserved1: 0,
            _reserved2: 0,
        }
        .to_bytes(),
    );
    bytes.extend_from_slice(
        &FrameEntry {
            frame_index: 0,
            envelope_index: 0,
            offset_in_envelope: 0,
            compressed_size: 128,
            decompressed_size: 1536,
            flags: 0,
            tar_stream_offset: 0,
        }
        .to_bytes(),
    );
    bytes.extend_from_slice(
        &EnvelopeEntry {
            envelope_index: 0,
            first_block_index: 0,
            data_block_count: 1,
            parity_block_count: 0,
            encrypted_size: 4096,
            plaintext_size: 128,
            first_frame_index: 0,
            frame_count: 1,
        }
        .to_bytes(),
    );
    bytes.extend_from_slice(path);
    bytes
}

fn valid_directory_hint_table() -> Vec<u8> {
    let path = b"dir";
    let shard_list_offset = DIRECTORY_HINT_TABLE_LEN + DIRECTORY_HINT_ENTRY_LEN;
    let string_pool_offset = shard_list_offset + 4;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(
        &DirectoryHintTableHeader {
            version: 1,
            hint_shard_index: 0,
            entry_count: 1,
            entry_table_offset: DIRECTORY_HINT_TABLE_LEN as u64,
            shard_list_offset: shard_list_offset as u64,
            string_pool_offset: string_pool_offset as u64,
            string_pool_size: path.len() as u64,
        }
        .to_bytes(),
    );
    bytes.extend_from_slice(
        &DirectoryHintEntry {
            dir_hash: hash_prefix(path),
            path_offset: 0,
            path_length: path.len() as u32,
            shard_list_start_index: 0,
            shard_count: 1,
        }
        .to_bytes(),
    );
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(path);
    bytes
}

fn valid_zstd_frame_with_size_prefix() -> Vec<u8> {
    let payload = b"payload";
    let mut bytes = (payload.len() as u32).to_le_bytes().to_vec();
    bytes.extend_from_slice(&compress_zstd_frame(payload, 1).expect("fixed zstd seed compresses"));
    bytes
}

fn valid_wide_padding() -> Vec<u8> {
    suffix_pad_for_aead(&vec![0x42; 4080], 16, 4096).expect("fixed padding seed builds")
}
