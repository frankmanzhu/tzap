use tzap_core::compression::{compress_zstd_frame, decompress_exact_zstd_frame};
use tzap_core::crypto::{
    aead_decrypt, aead_encrypt, build_aad, derive_nonce, KdfParams, MasterKey, Subkeys,
};
use tzap_core::entry_metadata::EXTENDED_METADATA_V1;
use tzap_core::fec::encode_parity_gf16;
use tzap_core::format::{
    AeadAlgo, FormatError, CRITICAL_RECOVERY_LOCATOR_LEN, CRYPTO_HEADER_HMAC_LEN, FORMAT_VERSION,
    MASTER_KEY_LEN, READER_MAX_SUPPORTED_VOLUME_FORMAT_REV, SUBKEY_LEN, VOLUME_FORMAT_REV,
    VOLUME_HEADER_LEN,
};
use tzap_core::metadata::{
    hash_prefix, normalize_lookup_directory_path, normalize_lookup_file_path,
    validate_file_path_bytes, DirectoryHintEntry, DirectoryHintShardEntry, DirectoryHintTable,
    DirectoryHintTableHeader, EnvelopeEntry, FileEntry, FrameEntry, IndexRoot, IndexRootHeader,
    IndexShard, IndexShardHeader, MetadataLimits, ShardEntry,
};
use tzap_core::reader::{open_archive, open_archive_volumes};
use tzap_core::tar_model::parse_tar_member_group;
use tzap_core::wire::{CriticalRecoveryLocator, CryptoHeader, VolumeHeader};
use tzap_core::writer::{write_archive, write_archive_with_dictionary, RegularFile, WriterOptions};

fn master_key() -> MasterKey {
    MasterKey::from_raw_key(&[0x5a; MASTER_KEY_LEN]).unwrap()
}

fn deterministic_options(seed: u8) -> WriterOptions {
    WriterOptions {
        archive_uuid: Some([seed; 16]),
        session_id: Some([seed.wrapping_add(1); 16]),
        closed_at_ns: 123_456_789,
        stripe_width: 1,
        volume_loss_tolerance: 0,
        bit_rot_buffer_pct: 0,
        ..WriterOptions::default()
    }
}

fn final_locator(volume: &[u8]) -> CriticalRecoveryLocator {
    let final_offset = volume.len() - CRITICAL_RECOVERY_LOCATOR_LEN;
    CriticalRecoveryLocator::parse(
        &volume[final_offset..final_offset + CRITICAL_RECOVERY_LOCATOR_LEN],
    )
    .unwrap()
}

fn corrupt_v41_terminal_recovery(volume: &mut [u8]) {
    let locator = final_locator(volume);
    let final_offset = volume.len() - CRITICAL_RECOVERY_LOCATOR_LEN;
    let mirror_offset = final_offset - CRITICAL_RECOVERY_LOCATOR_LEN;
    volume[locator.cmra_offset as usize] ^= 0x55;
    volume[mirror_offset] ^= 0x55;
    volume[final_offset] ^= 0x55;
}

#[test]
fn golden_fixtures_are_deterministic_and_readable() {
    let files = [
        RegularFile::new("alpha.txt", b"alpha payload"),
        RegularFile::new("dir/beta.txt", b"beta payload"),
    ];
    let one = write_archive(&files, &master_key(), deterministic_options(0x11)).unwrap();
    let two = write_archive(&files, &master_key(), deterministic_options(0x11)).unwrap();

    assert_eq!(one.bytes, two.bytes);
    assert_eq!(one.bootstrap_sidecar, two.bootstrap_sidecar);

    let opened = open_archive(&one.bytes, &master_key()).unwrap();
    opened.verify().unwrap();
    assert_eq!(
        opened.extract_file("dir/beta.txt").unwrap(),
        Some(b"beta payload".to_vec())
    );
}

#[test]
fn mutation_fixture_generator_rejects_authentication_and_revision_mutations() {
    let archive = write_archive(
        &[RegularFile::new("mutate.txt", b"mutation target")],
        &master_key(),
        deterministic_options(0x21),
    )
    .unwrap();

    for revision in [
        VOLUME_FORMAT_REV - 1,
        READER_MAX_SUPPORTED_VOLUME_FORMAT_REV + 1,
    ] {
        let mut mutated = archive.bytes.clone();
        let mut header = VolumeHeader::parse(&mutated[..VOLUME_HEADER_LEN]).unwrap();
        header.volume_format_rev = revision;
        mutated[..VOLUME_HEADER_LEN].copy_from_slice(&header.to_bytes());
        assert_eq!(
            open_archive(&mutated, &master_key()).unwrap_err(),
            FormatError::UnsupportedVolumeFormatRevision {
                format_version: FORMAT_VERSION,
                volume_format_rev: revision,
                reader_max_supported_revision: READER_MAX_SUPPORTED_VOLUME_FORMAT_REV,
            }
        );
    }

    let mut crypto_hmac = archive.bytes.clone();
    let header = VolumeHeader::parse(&crypto_hmac[..VOLUME_HEADER_LEN]).unwrap();
    let crypto_hmac_offset = header.crypto_header_offset as usize
        + header.crypto_header_length as usize
        - CRYPTO_HEADER_HMAC_LEN;
    crypto_hmac[crypto_hmac_offset] ^= 0x01;
    assert_eq!(
        open_archive(&crypto_hmac, &master_key()).unwrap_err(),
        FormatError::HmacMismatch {
            structure: "CryptoHeader"
        }
    );

    let mut trailer_hmac = archive.bytes.clone();
    let trailer_hmac_offset = final_locator(&trailer_hmac).volume_trailer_offset as usize + 96;
    trailer_hmac[trailer_hmac_offset] ^= 0x01;
    open_archive(&trailer_hmac, &master_key())
        .unwrap()
        .verify()
        .unwrap();
    corrupt_v41_terminal_recovery(&mut trailer_hmac);
    assert_eq!(
        open_archive(&trailer_hmac, &master_key()).unwrap_err(),
        FormatError::InvalidArchive("no valid v41 CMRA candidate found")
    );

    let mut payload_tamper = archive.bytes.clone();
    let crypto_header_offset = header.crypto_header_offset as usize;
    let crypto_header_end = crypto_header_offset + header.crypto_header_length as usize;
    let crypto_header = CryptoHeader::parse(
        &payload_tamper[crypto_header_offset..crypto_header_end],
        header.crypto_header_length,
    )
    .unwrap();
    let block_size = crypto_header.fixed.block_size as usize;
    let record_offset = crypto_header_end;
    payload_tamper[record_offset + 16] ^= 0x55;
    let crc_offset = record_offset + 16 + block_size;
    let crc = crc32c::crc32c(&payload_tamper[record_offset..crc_offset]);
    payload_tamper[crc_offset..crc_offset + 4].copy_from_slice(&crc.to_le_bytes());
    assert_eq!(
        open_archive(&payload_tamper, &master_key())
            .unwrap()
            .verify()
            .unwrap_err(),
        FormatError::AeadFailure
    );
}

#[test]
fn minimal_file_entry_frame_range_corpus_cases() {
    let path = b"minimal.txt";
    let path_hash = hash_prefix(path);

    let single_frame = index_shard_bytes(
        0,
        vec![file_entry(path, 0, 0, 1, 0, 1536, 7)],
        vec![frame_entry(0, 0, 0, 16, 2048, 0)],
        vec![envelope_entry(0, 0, 16, 0, 1)],
        path.to_vec(),
    );
    IndexShard::parse(
        &single_frame,
        &locating_shard(0, 1, path_hash, path_hash, single_frame.len()),
        MetadataLimits::default(),
    )
    .unwrap();

    let spanning_partial_final = index_shard_bytes(
        0,
        vec![file_entry(path, 0, 0, 2, 0, 1536, 7)],
        vec![
            frame_entry(0, 0, 0, 16, 1024, 0),
            frame_entry(1, 0, 16, 16, 1024, 1024),
        ],
        vec![envelope_entry(0, 0, 32, 0, 2)],
        path.to_vec(),
    );
    IndexShard::parse(
        &spanning_partial_final,
        &locating_shard(0, 1, path_hash, path_hash, spanning_partial_final.len()),
        MetadataLimits::default(),
    )
    .unwrap();

    let non_minimal = index_shard_bytes(
        0,
        vec![file_entry(path, 0, 0, 2, 0, 1536, 7)],
        vec![
            frame_entry(0, 0, 0, 16, 2048, 0),
            frame_entry(1, 0, 16, 16, 512, 2048),
        ],
        vec![envelope_entry(0, 0, 32, 0, 2)],
        path.to_vec(),
    );
    assert_eq!(
        IndexShard::parse(
            &non_minimal,
            &locating_shard(0, 1, path_hash, path_hash, non_minimal.len()),
            MetadataLimits::default(),
        )
        .unwrap_err(),
        FormatError::InvalidMetadata {
            structure: "FileEntry",
            reason: "frame range is not minimal",
        }
    );
}

#[test]
fn exact_file_lookup_is_independent_from_directory_hints() {
    let archive = write_archive(
        &[RegularFile::new("foo", b"regular file named foo")],
        &master_key(),
        deterministic_options(0x31),
    )
    .unwrap();
    let opened = open_archive(&archive.bytes, &master_key()).unwrap();

    assert!(opened.index_root.directory_hint_shards.is_empty());
    assert_eq!(
        opened.extract_file("foo").unwrap(),
        Some(b"regular file named foo".to_vec())
    );

    let misleading_hint_root = IndexRoot {
        header: IndexRootHeader::empty(),
        shards: Vec::new(),
        directory_hint_shards: vec![DirectoryHintShardEntry {
            hint_shard_index: 99,
            first_dir_hash: hash_prefix(b"foo"),
            last_dir_hash: hash_prefix(b"foo"),
            first_block_index: 1,
            data_block_count: 1,
            parity_block_count: 0,
            encrypted_size: 4096,
            decompressed_size: 128,
            entry_count: 1,
        }],
    };
    assert!(misleading_hint_root
        .candidate_shards_for_path(b"foo", MetadataLimits::default())
        .unwrap()
        .is_empty());
}

#[test]
fn exact_directory_entry_and_descendant_hints_have_distinct_authority() {
    let dir = b"foo";
    let dir_hash = hash_prefix(dir);
    let exact_directory_shard = index_shard_bytes(
        0,
        vec![file_entry(dir, 0, 0, 1, 0, 1536, 0)],
        vec![frame_entry(0, 0, 0, 16, 1536, 0)],
        vec![envelope_entry(0, 0, 16, 0, 1)],
        dir.to_vec(),
    );
    let parsed_exact = IndexShard::parse(
        &exact_directory_shard,
        &locating_shard(0, 1, dir_hash, dir_hash, exact_directory_shard.len()),
        MetadataLimits::default(),
    )
    .unwrap();
    assert_eq!(parsed_exact.lookup_file_index(dir), Some(0));

    let hint_table = directory_hint_table_bytes(
        3,
        vec![DirectoryHintEntry {
            dir_hash,
            path_offset: 0,
            path_length: dir.len() as u32,
            shard_list_start_index: 0,
            shard_count: 1,
        }],
        vec![0],
        dir.to_vec(),
    );
    let hint = DirectoryHintTable::parse(
        &hint_table,
        &DirectoryHintShardEntry {
            hint_shard_index: 3,
            first_dir_hash: dir_hash,
            last_dir_hash: dir_hash,
            first_block_index: 8,
            data_block_count: 1,
            parity_block_count: 0,
            encrypted_size: 4096,
            decompressed_size: hint_table.len() as u32,
            entry_count: 1,
        },
        1,
        MetadataLimits::default(),
    )
    .unwrap();
    let normalized_dir = normalize_lookup_directory_path("foo/", 4096).unwrap();
    assert_eq!(hint.lookup_directory_index(&normalized_dir), Some(0));
    assert_eq!(hint.entry_path(0), Some(dir.as_slice()));
    assert_eq!(hint.shard_row_indexes, vec![0]);
}

#[test]
fn directory_hint_equal_start_ordering_uses_last_hash_before_index() {
    let h = [0x40; 8];
    let z = [0x90; 8];
    let file_hash = hash_prefix(b"foo/bar");
    let canonical = IndexRoot {
        header: IndexRootHeader {
            file_count: 1,
            ..IndexRootHeader::empty()
        },
        shards: vec![ShardEntry {
            shard_index: 0,
            first_block_index: 10,
            data_block_count: 1,
            parity_block_count: 1,
            encrypted_size: 4096,
            decompressed_size: 256,
            file_count: 1,
            first_path_hash: file_hash,
            last_path_hash: file_hash,
        }],
        directory_hint_shards: vec![
            DirectoryHintShardEntry {
                hint_shard_index: 9,
                first_dir_hash: h,
                last_dir_hash: h,
                first_block_index: 20,
                data_block_count: 1,
                parity_block_count: 1,
                encrypted_size: 4096,
                decompressed_size: 128,
                entry_count: 1,
            },
            DirectoryHintShardEntry {
                hint_shard_index: 1,
                first_dir_hash: h,
                last_dir_hash: z,
                first_block_index: 22,
                data_block_count: 1,
                parity_block_count: 1,
                encrypted_size: 4096,
                decompressed_size: 128,
                entry_count: 1,
            },
        ],
    };
    IndexRoot::parse(&canonical.to_bytes(), false, MetadataLimits::default()).unwrap();

    let mut inverted = canonical.clone();
    inverted.directory_hint_shards.swap(0, 1);
    assert_eq!(
        IndexRoot::parse(&inverted.to_bytes(), false, MetadataLimits::default()).unwrap_err(),
        FormatError::InvalidMetadata {
            structure: "IndexRoot",
            reason: "DirectoryHintShardEntry rows are not sorted",
        }
    );
}

#[test]
fn metadata_path_hash_bindings_reject_silent_misroutes() {
    let file_path = b"hash-bound.txt";
    let wrong_file_hash = hash_prefix(b"other-file.txt");
    let mut wrong_file = file_entry(file_path, 0, 0, 1, 0, 1536, 1);
    wrong_file.path_hash = wrong_file_hash;
    let file_shard = index_shard_bytes(
        0,
        vec![wrong_file],
        vec![frame_entry(0, 0, 0, 16, 1536, 0)],
        vec![envelope_entry(0, 0, 16, 0, 1)],
        file_path.to_vec(),
    );
    assert_eq!(
        IndexShard::parse(
            &file_shard,
            &locating_shard(0, 1, wrong_file_hash, wrong_file_hash, file_shard.len()),
            MetadataLimits::default(),
        )
        .unwrap_err(),
        FormatError::InvalidMetadata {
            structure: "FileEntry",
            reason: "path hash does not match string-pool path",
        }
    );

    let dir_path = b"hash-dir";
    let wrong_dir_hash = hash_prefix(b"other-dir");
    let hint_table = directory_hint_table_bytes(
        5,
        vec![DirectoryHintEntry {
            dir_hash: wrong_dir_hash,
            path_offset: 0,
            path_length: dir_path.len() as u32,
            shard_list_start_index: 0,
            shard_count: 1,
        }],
        vec![0],
        dir_path.to_vec(),
    );
    assert_eq!(
        DirectoryHintTable::parse(
            &hint_table,
            &DirectoryHintShardEntry {
                hint_shard_index: 5,
                first_dir_hash: wrong_dir_hash,
                last_dir_hash: wrong_dir_hash,
                first_block_index: 10,
                data_block_count: 1,
                parity_block_count: 0,
                encrypted_size: 4096,
                decompressed_size: hint_table.len() as u32,
                entry_count: 1,
            },
            1,
            MetadataLimits::default(),
        )
        .unwrap_err(),
        FormatError::InvalidMetadata {
            structure: "DirectoryHintEntry",
            reason: "dir_hash does not match string-pool path",
        }
    );
}

#[test]
fn reserved_file_entry_flags_are_rejected_before_lookup() {
    let path = b"reserved-flag.txt";
    let path_hash = hash_prefix(path);
    let mut flagged = file_entry(path, 0, 0, 1, 0, 1536, 1);
    flagged.flags = EXTENDED_METADATA_V1 | (1 << 6);
    let shard = index_shard_bytes(
        0,
        vec![flagged],
        vec![frame_entry(0, 0, 0, 16, 1536, 0)],
        vec![envelope_entry(0, 0, 16, 0, 1)],
        path.to_vec(),
    );

    assert_eq!(
        IndexShard::parse(
            &shard,
            &locating_shard(0, 1, path_hash, path_hash, shard.len()),
            MetadataLimits::default(),
        )
        .unwrap_err(),
        FormatError::InvalidMetadata {
            structure: "FileEntry",
            reason: "unknown revision-45 flags are non-zero",
        }
    );
}

#[test]
fn hash_prefix_ordering_is_raw_digest_byte_order() {
    let low = [0x01, 0xff, 0, 0, 0, 0, 0, 0];
    let high = [0x02, 0x00, 0, 0, 0, 0, 0, 0];
    let same_prefix_low_last = [0x10, 0, 0, 0, 0, 0, 0, 0x01];
    let same_prefix_high_last = [0x10, 0, 0, 0, 0, 0, 0, 0x02];

    let accepted = index_root_with_shard_hashes(vec![
        (0, low, low),
        (1, high, high),
        (2, same_prefix_low_last, same_prefix_low_last),
        (3, same_prefix_high_last, same_prefix_high_last),
    ]);
    IndexRoot::parse(&accepted.to_bytes(), false, MetadataLimits::default()).unwrap();

    let rejected = index_root_with_shard_hashes(vec![(0, high, high), (1, low, low)]);
    assert_eq!(
        IndexRoot::parse(&rejected.to_bytes(), false, MetadataLimits::default()).unwrap_err(),
        FormatError::InvalidMetadata {
            structure: "IndexRoot",
            reason: "ShardEntry rows are not sorted",
        }
    );
}

#[test]
fn hash_prefix_ordering_rejects_little_endian_integer_reinterpretation() {
    let raw_low_but_le_high = [0x00, 0x00, 0, 0, 0, 0, 0, 0x02];
    let raw_high_but_le_low = [0x01, 0x00, 0, 0, 0, 0, 0, 0x00];

    let raw_byte_order = index_root_with_shard_hashes(vec![
        (0, raw_low_but_le_high, raw_low_but_le_high),
        (1, raw_high_but_le_low, raw_high_but_le_low),
    ]);
    IndexRoot::parse(&raw_byte_order.to_bytes(), false, MetadataLimits::default()).unwrap();

    let little_endian_integer_order = index_root_with_shard_hashes(vec![
        (0, raw_high_but_le_low, raw_high_but_le_low),
        (1, raw_low_but_le_high, raw_low_but_le_high),
    ]);
    assert_eq!(
        IndexRoot::parse(
            &little_endian_integer_order.to_bytes(),
            false,
            MetadataLimits::default(),
        )
        .unwrap_err(),
        FormatError::InvalidMetadata {
            structure: "IndexRoot",
            reason: "ShardEntry rows are not sorted",
        }
    );
}

#[test]
fn argon2id_profile_vector_is_pinned() {
    let params = KdfParams::Argon2id {
        t_cost: 1,
        m_cost_kib: 8,
        parallelism: 1,
        salt: b"12345678".to_vec(),
    };
    let master = MasterKey::derive_from_passphrase(&params, "e\u{301}").unwrap();

    assert_eq!(
        hex::encode(master.0),
        "24709642204c04bf88fb36550c478769eb10a0400c0493c9695d30fbf7082241"
    );

    assert!(MasterKey::derive_from_passphrase(
        &KdfParams::Argon2id {
            t_cost: 0,
            m_cost_kib: 8,
            parallelism: 1,
            salt: b"12345678".to_vec(),
        },
        "e\u{301}",
    )
    .is_err());
}

#[test]
fn hkdf_subkey_and_nonce_vectors_are_literal() {
    let raw_key = core::array::from_fn::<_, MASTER_KEY_LEN, _>(|idx| idx as u8);
    let archive_uuid = core::array::from_fn::<_, 16, _>(|idx| 0x10 + idx as u8);
    let session_id = core::array::from_fn::<_, 16, _>(|idx| 0xa0 + idx as u8);
    let master = MasterKey::from_raw_key(&raw_key).unwrap();
    let subkeys = Subkeys::derive(&master, &archive_uuid, &session_id).unwrap();

    assert_eq!(
        hex::encode(subkeys.enc_key),
        "fdcc2d13c382611e7734a32394569baab5dd642e22ee82979dd4696651593276"
    );
    assert_eq!(
        hex::encode(subkeys.mac_key),
        "08cb773f32e45da15f29fdd991e7a18ca67089a3ec88065fee88545cadd044d3"
    );
    assert_eq!(
        hex::encode(subkeys.nonce_seed),
        "acfc4ce61dadfbf0d28f5ec6f9b93948dc4856581e04df659ed6e2ae395cf467"
    );
    assert_eq!(
        hex::encode(subkeys.index_root_key),
        "d2617cad0621d674f971871f8546385e2fd4382e231678f7220f4806bd96cfa4"
    );
    assert_eq!(
        hex::encode(subkeys.index_shard_key),
        "0c230a67fb429145383c317a09c61da356b0da3e2b4b8118ce4319267297bfe4"
    );
    assert_eq!(
        hex::encode(subkeys.dictionary_key),
        "de521049dcb6775dd857cb8be9cb79272ee59b4dd24c9f4cd7bc85c6151b7598"
    );
    assert_eq!(
        hex::encode(subkeys.dir_hint_key),
        "fa750e7ff0353c78b5e6ef1cb992198d6e80289510d277ef28e777f3c8ef7a2d"
    );
    assert_eq!(
        hex::encode(subkeys.index_nonce_seed),
        "d394349347fb27c9a6f9a7518ca5e5747315624a56f012242f122b2d37dd6d6b"
    );

    assert_eq!(
        hex::encode(
            derive_nonce(
                &subkeys.nonce_seed,
                b"envelope",
                &archive_uuid,
                &session_id,
                7,
                12,
            )
            .unwrap()
        ),
        "cfeb02d3a8c9089af250f096"
    );
    assert_eq!(
        hex::encode(
            derive_nonce(
                &subkeys.nonce_seed,
                b"idxroot",
                &archive_uuid,
                &session_id,
                0,
                12,
            )
            .unwrap()
        ),
        "439d845528c52fc6140fcd13"
    );
    assert_eq!(
        hex::encode(
            derive_nonce(
                &subkeys.nonce_seed,
                b"dict",
                &archive_uuid,
                &session_id,
                0,
                24,
            )
            .unwrap()
        ),
        "0d8694130bdc757c8acde58dec9c23bf5a0f69ad62727414"
    );
}

#[test]
fn aead_combined_output_tag_is_final_and_authenticated() {
    for algo in [
        AeadAlgo::AesGcmSiv256,
        AeadAlgo::XChaCha20Poly1305,
        AeadAlgo::AesGcm256,
    ] {
        let key = [0x61; SUBKEY_LEN];
        let archive_uuid = [0x62; 16];
        let session_id = [0x63; 16];
        let nonce = derive_nonce(
            &[0x64; SUBKEY_LEN],
            b"corpus-aead",
            &archive_uuid,
            &session_id,
            7,
            algo.nonce_len(),
        )
        .unwrap();
        let aad = build_aad(b"corpus-aead", &archive_uuid, &session_id, 7).unwrap();
        let plaintext = b"combined-output-vector";
        let combined = aead_encrypt(algo, &key, &nonce, &aad, plaintext).unwrap();

        assert_eq!(combined.len(), plaintext.len() + algo.tag_len());
        assert_eq!(
            aead_decrypt(algo, &key, &nonce, &aad, &combined).unwrap(),
            plaintext
        );

        let tag_start = combined.len() - algo.tag_len();
        let mut prefixed_tag = combined[tag_start..].to_vec();
        prefixed_tag.extend_from_slice(&combined[..tag_start]);
        assert_eq!(
            aead_decrypt(algo, &key, &nonce, &aad, &prefixed_tag).unwrap_err(),
            FormatError::AeadFailure
        );

        let mut truncated = combined.clone();
        truncated.pop();
        assert_eq!(
            aead_decrypt(algo, &key, &nonce, &aad, &truncated).unwrap_err(),
            FormatError::AeadFailure
        );

        let mut extra_tag = combined.clone();
        extra_tag.extend_from_slice(&combined[tag_start..]);
        assert_eq!(
            aead_decrypt(algo, &key, &nonce, &aad, &extra_tag).unwrap_err(),
            FormatError::AeadFailure
        );
    }
}

#[test]
fn reed_solomon_gf16_wire_vector_is_pinned() {
    let data = vec![vec![0x01, 0x00, 0x02, 0x00], vec![0x03, 0x00, 0x04, 0x00]];

    assert_eq!(
        encode_parity_gf16(&data, 2).unwrap(),
        vec![vec![0x04, 0x88, 0x04, 0xf0], vec![0x02, 0x78, 0x05, 0xf0]]
    );

    assert_eq!(
        encode_parity_gf16(&[vec![0u8; 3]], 1).unwrap_err(),
        FormatError::FecOddShardSize
    );
}

#[test]
fn directory_hint_counter_uniqueness_and_non_row_position_values() {
    let h = [0x20; 8];
    let file_hash = hash_prefix(b"child.txt");
    let root = IndexRoot {
        header: IndexRootHeader {
            file_count: 1,
            ..IndexRootHeader::empty()
        },
        shards: vec![ShardEntry {
            shard_index: 0,
            first_block_index: 1,
            data_block_count: 1,
            parity_block_count: 1,
            encrypted_size: 4096,
            decompressed_size: 128,
            file_count: 1,
            first_path_hash: file_hash,
            last_path_hash: file_hash,
        }],
        directory_hint_shards: vec![
            DirectoryHintShardEntry {
                hint_shard_index: 77,
                first_dir_hash: h,
                last_dir_hash: h,
                first_block_index: 3,
                data_block_count: 1,
                parity_block_count: 1,
                encrypted_size: 4096,
                decompressed_size: 128,
                entry_count: 1,
            },
            DirectoryHintShardEntry {
                hint_shard_index: 88,
                first_dir_hash: [0x21; 8],
                last_dir_hash: [0x21; 8],
                first_block_index: 5,
                data_block_count: 1,
                parity_block_count: 1,
                encrypted_size: 4096,
                decompressed_size: 128,
                entry_count: 1,
            },
        ],
    };
    IndexRoot::parse(&root.to_bytes(), false, MetadataLimits::default()).unwrap();

    let mut duplicate = root;
    duplicate.directory_hint_shards[1].hint_shard_index = 77;
    assert_eq!(
        IndexRoot::parse(&duplicate.to_bytes(), false, MetadataLimits::default()).unwrap_err(),
        FormatError::InvalidMetadata {
            structure: "DirectoryHintShardEntry",
            reason: "duplicate hint shard index",
        }
    );
}

#[test]
fn shard_boundary_metadata_bindings_are_checked() {
    let path = b"bound.txt";
    let path_hash = hash_prefix(path);
    let shard = index_shard_bytes(
        7,
        vec![file_entry(path, 0, 0, 1, 0, 1536, 5)],
        vec![frame_entry(0, 0, 0, 16, 1536, 0)],
        vec![envelope_entry(0, 10, 16, 0, 1)],
        path.to_vec(),
    );

    let mut wrong_count = locating_shard(7, 2, path_hash, path_hash, shard.len());
    assert_eq!(
        IndexShard::parse(&shard, &wrong_count, MetadataLimits::default()).unwrap_err(),
        FormatError::InvalidMetadata {
            structure: "IndexShard",
            reason: "file count does not match locating ShardEntry",
        }
    );

    wrong_count.file_count = 1;
    wrong_count.first_path_hash = [0; 8];
    assert_eq!(
        IndexShard::parse(&shard, &wrong_count, MetadataLimits::default()).unwrap_err(),
        FormatError::InvalidMetadata {
            structure: "IndexShard",
            reason: "first FileEntry hash does not match ShardEntry",
        }
    );

    let dir_hash = hash_prefix(b"dir");
    let table = directory_hint_table_bytes(
        4,
        vec![DirectoryHintEntry {
            dir_hash,
            path_offset: 0,
            path_length: 3,
            shard_list_start_index: 0,
            shard_count: 1,
        }],
        vec![0],
        b"dir".to_vec(),
    );
    let locating = DirectoryHintShardEntry {
        hint_shard_index: 4,
        first_dir_hash: dir_hash,
        last_dir_hash: dir_hash,
        first_block_index: 0,
        data_block_count: 1,
        parity_block_count: 0,
        encrypted_size: 4096,
        decompressed_size: table.len() as u32,
        entry_count: 1,
    };
    tzap_core::metadata::DirectoryHintTable::parse(&table, &locating, 1, MetadataLimits::default())
        .unwrap();

    let mut wrong_dir_bounds = locating.clone();
    wrong_dir_bounds.last_dir_hash = [0xff; 8];
    assert_eq!(
        tzap_core::metadata::DirectoryHintTable::parse(
            &table,
            &wrong_dir_bounds,
            1,
            MetadataLimits::default(),
        )
        .unwrap_err(),
        FormatError::InvalidMetadata {
            structure: "DirectoryHintTable",
            reason: "last DirectoryHintEntry hash does not match locating row",
        }
    );

    let empty_table = directory_hint_table_bytes(4, Vec::new(), Vec::new(), Vec::new());
    let mut zero_entries = locating;
    zero_entries.entry_count = 0;
    assert_eq!(
        tzap_core::metadata::DirectoryHintTable::parse(
            &empty_table,
            &zero_entries,
            1,
            MetadataLimits::default(),
        )
        .unwrap_err(),
        FormatError::InvalidMetadata {
            structure: "DirectoryHintTable",
            reason: "located directory hint shard is empty",
        }
    );
}

#[test]
fn sparse_local_frame_offsets_allow_unrelated_frame_index_gaps() {
    let a = b"a.txt";
    let z = b"z.txt";
    let mut file_rows = vec![
        (a.as_slice(), file_entry(a, 0, 0, 1, 0, 1536, 1), 0u64),
        (z.as_slice(), file_entry(z, 5, 2, 1, 0, 1536, 1), 1537u64),
    ];
    file_rows.sort_by_key(|(path, _, start)| (hash_prefix(path), path.to_vec(), *start));
    let first_hash = hash_prefix(file_rows[0].0);
    let last_hash = hash_prefix(file_rows[1].0);
    let mut string_pool = Vec::new();
    string_pool.extend_from_slice(a);
    string_pool.extend_from_slice(z);

    let shard = index_shard_bytes(
        0,
        file_rows.into_iter().map(|(_, file, _)| file).collect(),
        vec![
            frame_entry(0, 0, 0, 16, 1536, 0),
            frame_entry(2, 1, 0, 16, 1536, 1537),
        ],
        vec![
            envelope_entry(0, 0, 16, 0, 1),
            envelope_entry(1, 10, 16, 2, 1),
        ],
        string_pool,
    );
    IndexShard::parse(
        &shard,
        &locating_shard(0, 2, first_hash, last_hash, shard.len()),
        MetadataLimits::default(),
    )
    .unwrap();
}

#[test]
fn metadata_zstd_exactness_mutation_corpus() {
    let plaintext = b"metadata exact frame";
    let compressed = compress_zstd_frame(plaintext, 1).unwrap();
    assert_eq!(
        decompress_exact_zstd_frame(&compressed, plaintext.len()).unwrap(),
        plaintext
    );

    let mut trailing = compressed.clone();
    trailing.push(0);
    assert_eq!(
        decompress_exact_zstd_frame(&trailing, plaintext.len()).unwrap_err(),
        FormatError::TrailingBytesAfterZstdFrame
    );

    let mut concatenated = compressed.clone();
    concatenated.extend_from_slice(&compressed);
    assert_eq!(
        decompress_exact_zstd_frame(&concatenated, plaintext.len()).unwrap_err(),
        FormatError::TrailingBytesAfterZstdFrame
    );

    let skippable = [0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0];
    assert_eq!(
        decompress_exact_zstd_frame(&skippable, 0).unwrap_err(),
        FormatError::NotStandardZstdFrame
    );

    assert_eq!(
        decompress_exact_zstd_frame(&compressed, plaintext.len() + 1).unwrap_err(),
        FormatError::ZstdDecompressedSizeMismatch {
            expected: plaintext.len() + 1,
            actual: plaintext.len(),
        }
    );
}

#[test]
fn payload_zstd_frame_validity_rejects_arbitrary_and_truncated_frames() {
    assert_eq!(
        decompress_exact_zstd_frame(b"not a zstd payload frame", 24).unwrap_err(),
        FormatError::NotStandardZstdFrame
    );

    let plaintext = b"payload frame validity";
    let compressed = compress_zstd_frame(plaintext, 1).unwrap();
    assert_eq!(
        decompress_exact_zstd_frame(&compressed[..compressed.len() - 1], plaintext.len())
            .unwrap_err(),
        FormatError::InvalidZstdFrame
    );

    assert_eq!(
        decompress_exact_zstd_frame(&compressed[..4], plaintext.len()).unwrap_err(),
        FormatError::InvalidZstdFrame
    );
}

#[test]
fn fec_effective_object_ceiling_is_enforced() {
    let data = vec![Vec::new(); 65_535];
    assert_eq!(
        encode_parity_gf16(&data, 1).unwrap_err(),
        FormatError::FecTooManyShards(65_536)
    );
}

#[test]
fn volume_format_revision_freshness_is_pinned_to_current_revision() {
    let base = VolumeHeader {
        format_version: FORMAT_VERSION,
        volume_format_rev: VOLUME_FORMAT_REV,
        volume_index: 0,
        stripe_width: 1,
        archive_uuid: [0x01; 16],
        session_id: [0x02; 16],
        crypto_header_offset: VOLUME_HEADER_LEN as u32,
        crypto_header_length: 110,
        header_crc32c: 0,
    };
    VolumeHeader::parse(&base.to_bytes()).unwrap();

    for rev in [
        VOLUME_FORMAT_REV - 1,
        READER_MAX_SUPPORTED_VOLUME_FORMAT_REV + 1,
    ] {
        let mut mutated = base.clone();
        mutated.volume_format_rev = rev;
        let parsed = VolumeHeader::parse(&mutated.to_bytes()).unwrap();
        assert_eq!(
            parsed.parse_volume_format_revision().unwrap_err(),
            FormatError::UnsupportedVolumeFormatRevision {
                format_version: FORMAT_VERSION,
                volume_format_rev: rev,
                reader_max_supported_revision: READER_MAX_SUPPORTED_VOLUME_FORMAT_REV,
            }
        );
    }
}

#[test]
fn cross_platform_path_rejections_are_host_independent() {
    for path in [
        "",
        "/absolute",
        "a//b",
        "a/./b",
        "a/../b",
        "a\0b",
        "a\\b",
        "a:b",
        "C:/drive",
        "C:\\drive",
        "\\\\server\\share",
        "COM1",
        "nul.txt",
    ] {
        assert!(
            validate_file_path_bytes(path.as_bytes(), 4096).is_err(),
            "{path}"
        );
        assert!(normalize_lookup_file_path(path, 4096).is_err(), "{path}");
    }

    assert_eq!(
        normalize_lookup_file_path("dir/e\u{301}.txt", 4096).unwrap(),
        "dir/é.txt".as_bytes()
    );
    assert_eq!(
        normalize_lookup_directory_path("dir/e\u{301}/", 4096).unwrap(),
        "dir/é".as_bytes()
    );
}

#[test]
fn deterministic_round_trip_property_matrix() {
    for (case, file_count, stripe_width, dictionary) in [
        (0u8, 0usize, 1u32, None),
        (1, 1, 1, None),
        (2, 3, 1, None),
        (3, 2, 2, None),
        (
            4,
            2,
            1,
            Some(b"common words common words corpus dictionary".as_slice()),
        ),
    ] {
        let contents = (0..file_count)
            .map(|idx| {
                (
                    format!("dir/file-{idx}.txt"),
                    format!("payload case {case} file {idx} common words"),
                )
            })
            .collect::<Vec<_>>();
        let files = contents
            .iter()
            .map(|(path, data)| RegularFile::new(path, data.as_bytes()))
            .collect::<Vec<_>>();
        let mut options = deterministic_options(0x70 + case);
        options.stripe_width = stripe_width;
        options.volume_loss_tolerance = if stripe_width > 1 { 1 } else { 0 };

        let archive = match dictionary {
            Some(dict) => write_archive_with_dictionary(&files, &master_key(), options, dict),
            None => write_archive(&files, &master_key(), options),
        }
        .unwrap();

        let opened = if stripe_width > 1 {
            let refs = archive
                .volumes
                .iter()
                .map(Vec::as_slice)
                .collect::<Vec<_>>();
            open_archive_volumes(&refs, &master_key()).unwrap()
        } else {
            open_archive(&archive.bytes, &master_key()).unwrap()
        };
        opened.verify().unwrap();
        assert_eq!(opened.list_files().unwrap().len(), file_count);
        for (path, data) in contents {
            assert_eq!(
                opened.extract_file(&path).unwrap(),
                Some(data.into_bytes()),
                "{path}"
            );
        }
    }
}

#[test]
fn reconstructed_tar_stream_fixture_matches_member_bindings() {
    let archive = write_archive(
        &[RegularFile::new("tar/member.txt", b"tar corpus")],
        &master_key(),
        deterministic_options(0x44),
    )
    .unwrap();
    let tar_stream =
        tzap_core::sequential_extract_tar_stream(&archive.bytes, &master_key()).unwrap();
    let member = parse_tar_member_group(&tar_stream, 4096).unwrap();

    assert_eq!(member.path, b"tar/member.txt");
    assert_eq!(member.data, b"tar corpus");
    assert_eq!(member.logical_size, 10);
    assert_eq!(tar_stream.len(), 2048);
}

fn index_root_with_shard_hashes(hashes: Vec<(u64, [u8; 8], [u8; 8])>) -> IndexRoot {
    IndexRoot {
        header: IndexRootHeader {
            file_count: hashes.len() as u64,
            ..IndexRootHeader::empty()
        },
        shards: hashes
            .into_iter()
            .map(|(idx, first, last)| ShardEntry {
                shard_index: idx,
                first_block_index: idx * 2,
                data_block_count: 1,
                parity_block_count: 1,
                encrypted_size: 4096,
                decompressed_size: 256,
                file_count: 1,
                first_path_hash: first,
                last_path_hash: last,
            })
            .collect(),
        directory_hint_shards: Vec::new(),
    }
}

fn locating_shard(
    shard_index: u64,
    file_count: u32,
    first_hash: [u8; 8],
    last_hash: [u8; 8],
    decompressed_size: usize,
) -> ShardEntry {
    ShardEntry {
        shard_index,
        first_block_index: 10,
        data_block_count: 1,
        parity_block_count: 1,
        encrypted_size: 4096,
        decompressed_size: decompressed_size as u32,
        file_count,
        first_path_hash: first_hash,
        last_path_hash: last_hash,
    }
}

fn index_shard_bytes(
    shard_index: u64,
    files: Vec<FileEntry>,
    frames: Vec<FrameEntry>,
    envelopes: Vec<EnvelopeEntry>,
    string_pool: Vec<u8>,
) -> Vec<u8> {
    let header_len = IndexShardHeader {
        version: 1,
        shard_index,
        file_count: 0,
        frame_count: 0,
        envelope_count: 0,
        file_table_offset: 0,
        frame_table_offset: 0,
        envelope_table_offset: 0,
        string_pool_offset: 0,
        string_pool_size: 0,
    }
    .to_bytes()
    .len();
    let file_len = files[0].to_bytes().len();
    let frame_len = frames[0].to_bytes().len();
    let envelope_len = envelopes[0].to_bytes().len();
    let frame_table_offset = header_len + files.len() * file_len;
    let envelope_table_offset = frame_table_offset + frames.len() * frame_len;
    let string_pool_offset = envelope_table_offset + envelopes.len() * envelope_len;

    let header = IndexShardHeader {
        version: 1,
        shard_index,
        file_count: files.len() as u32,
        frame_count: frames.len() as u32,
        envelope_count: envelopes.len() as u32,
        file_table_offset: header_len as u32,
        frame_table_offset: frame_table_offset as u32,
        envelope_table_offset: envelope_table_offset as u32,
        string_pool_offset: string_pool_offset as u32,
        string_pool_size: string_pool.len() as u32,
    };

    let mut out = Vec::new();
    out.extend_from_slice(&header.to_bytes());
    for file in files {
        out.extend_from_slice(&file.to_bytes());
    }
    for frame in frames {
        out.extend_from_slice(&frame.to_bytes());
    }
    for envelope in envelopes {
        out.extend_from_slice(&envelope.to_bytes());
    }
    out.extend_from_slice(&string_pool);
    out
}

fn directory_hint_table_bytes(
    hint_shard_index: u64,
    entries: Vec<DirectoryHintEntry>,
    shard_row_indexes: Vec<u32>,
    string_pool: Vec<u8>,
) -> Vec<u8> {
    let header_len = DirectoryHintTableHeader {
        version: 1,
        hint_shard_index,
        entry_count: 0,
        entry_table_offset: 0,
        shard_list_offset: 0,
        string_pool_offset: 0,
        string_pool_size: 0,
    }
    .to_bytes()
    .len();
    let entry_len = entries
        .first()
        .map(|entry| entry.to_bytes().len())
        .unwrap_or(0);
    let shard_list_offset = if entries.is_empty() {
        0
    } else {
        header_len + entries.len() * entry_len
    };
    let string_pool_offset = if string_pool.is_empty() {
        0
    } else {
        shard_list_offset + shard_row_indexes.len() * 4
    };

    let header = DirectoryHintTableHeader {
        version: 1,
        hint_shard_index,
        entry_count: entries.len() as u64,
        entry_table_offset: if entries.is_empty() {
            0
        } else {
            header_len as u64
        },
        shard_list_offset: shard_list_offset as u64,
        string_pool_offset: string_pool_offset as u64,
        string_pool_size: string_pool.len() as u64,
    };

    let mut out = Vec::new();
    out.extend_from_slice(&header.to_bytes());
    for entry in entries {
        out.extend_from_slice(&entry.to_bytes());
    }
    for row in shard_row_indexes {
        out.extend_from_slice(&row.to_le_bytes());
    }
    out.extend_from_slice(&string_pool);
    out
}

fn file_entry(
    path: &[u8],
    path_offset: u32,
    first_frame_index: u64,
    frame_count: u32,
    offset_in_first_frame_plaintext: u32,
    tar_member_group_size: u64,
    file_data_size: u64,
) -> FileEntry {
    FileEntry {
        path_hash: hash_prefix(path),
        path_offset,
        path_length: path.len() as u32,
        first_frame_index,
        frame_count,
        offset_in_first_frame_plaintext,
        tar_member_group_size,
        file_data_size,
        flags: EXTENDED_METADATA_V1,
    }
}

fn frame_entry(
    frame_index: u64,
    envelope_index: u64,
    offset_in_envelope: u32,
    compressed_size: u32,
    decompressed_size: u32,
    tar_stream_offset: u64,
) -> FrameEntry {
    FrameEntry {
        frame_index,
        envelope_index,
        offset_in_envelope,
        compressed_size,
        decompressed_size,
        flags: 0,
        tar_stream_offset,
    }
}

fn envelope_entry(
    envelope_index: u64,
    first_block_index: u64,
    plaintext_size: u32,
    first_frame_index: u64,
    frame_count: u32,
) -> EnvelopeEntry {
    EnvelopeEntry {
        envelope_index,
        first_block_index,
        data_block_count: 1,
        parity_block_count: 0,
        encrypted_size: 4096,
        plaintext_size,
        first_frame_index,
        frame_count,
    }
}
