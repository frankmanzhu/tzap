use super::envelope::{build_crypto_header, MIN_BLOCK_SIZE, TAR_BLOCK_LEN};
use super::*;
use crate::crypto::*;
use crate::entry_metadata::*;
use crate::format::*;
use crate::metadata::*;
use crate::reader::{
    add_expected_directory_hint_rows, open_archive, open_archive_with_recipient_wrap_resolver, validate_directory_hint_tables_against_expected,
};
use crate::tar_model::{parse_tar_member_group, TarEntryKind};
use crate::wire::*;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read};
use std::rc::Rc;

#[test]
fn writer_defaults_use_v45_sizing_and_parallel_mode() {
    let options = WriterOptions::default();

    assert_eq!(options.chunk_size, 256 * 1024);
    assert_eq!(options.envelope_target_size, 1024 * 1024);
    assert_eq!(options.block_size, 64 * 1024);
    assert_eq!(options.stripe_width, 8);
    assert_eq!(options.volume_loss_tolerance, 1);
    assert_eq!(options.fec_data_shards, 224);
    assert_eq!(options.index_fec_data_shards, 16);
    assert_eq!(options.index_root_fec_data_shards, MIN_INDEX_ROOT_FEC_DATA_SHARDS);
    assert_eq!(options.bit_rot_buffer_pct, 5);
    assert_eq!(options.jobs, default_jobs());
    assert!(options.jobs >= 1);
}

#[test]
fn emission_state_collects_data_leaf_hashes_only_for_root_auth() {
    let options = single_volume_metadata_test_options();
    let archive_uuid = [1u8; 16];
    let session_id = [2u8; 16];
    let crypto_header = b"test crypto header";

    let mut unsigned_sink = MemoryArchiveSink::default();
    let volume_format_rev = volume_format_revision_for_options(&options, &KdfParams::None);
    let unsigned = begin_writer_emission_state(&mut unsigned_sink, options, crypto_header, None, archive_uuid, session_id, volume_format_rev, false).unwrap();
    assert!(unsigned.data_leaf_hashes.is_none());

    let mut signed_sink = MemoryArchiveSink::default();
    let volume_format_rev = volume_format_revision_for_options(&options, &KdfParams::None);
    let signed = begin_writer_emission_state(&mut signed_sink, options, crypto_header, None, archive_uuid, session_id, volume_format_rev, true).unwrap();
    assert_eq!(signed.data_leaf_hashes.as_deref(), Some([].as_slice()));
}

#[test]
fn ordered_envelope_serializes_zero_parity_without_root_auth_leaf_collection() {
    let options = plan_writer_options(WriterOptions {
        stripe_width: 1,
        volume_loss_tolerance: 0,
        bit_rot_buffer_pct: 0,
        aead_algo: AeadAlgo::None,
        ..WriterOptions::default()
    })
    .unwrap();
    let payload = deterministic_bytes(options.block_size as usize * 2 + 17);
    let extent = ObjectExtent::new(11, plan_encrypted_object(payload.len(), options.fec_data_shards, options.fec_parity_shards, options).unwrap()).unwrap();
    assert_eq!(extent.parity_block_count, 0);
    assert_eq!(extent.data_block_count, 3);
    let subkeys = Subkeys::unencrypted_placeholder();

    let result = build_ordered_envelope_result(
        OrderedEnvelopeJob { envelope_index: 3, plaintext: payload.clone(), extent, collect_data_leaf_hashes: false },
        &subkeys,
        options,
        [1u8; 16],
        [2u8; 16],
    )
    .unwrap();

    match result.records {
        OrderedEnvelopeRecords::Serialized(records) => {
            assert_eq!(records.len(), extent.data_block_count as usize);
            let parsed = BlockRecord::parse(&records[0].bytes, options.block_size as usize).unwrap();
            assert_eq!(parsed.block_index, extent.first_block_index);
            assert_eq!(parsed.kind, BlockKind::PayloadData);
            assert!(!parsed.is_last_data());
            let last = BlockRecord::parse(&records[2].bytes, options.block_size as usize).unwrap();
            assert_eq!(last.block_index, extent.first_block_index + 2);
            assert_eq!(last.kind, BlockKind::PayloadData);
            assert!(last.is_last_data());
        }
        OrderedEnvelopeRecords::Materialized(_) => {
            panic!("zero-parity unsigned envelope should use serialized records")
        }
    }

    let result = build_ordered_envelope_result(
        OrderedEnvelopeJob { envelope_index: 3, plaintext: payload, extent, collect_data_leaf_hashes: true },
        &subkeys,
        options,
        [1u8; 16],
        [2u8; 16],
    )
    .unwrap();

    match result.records {
        OrderedEnvelopeRecords::Materialized(records) => {
            assert_eq!(records.len(), extent.data_block_count as usize);
        }
        OrderedEnvelopeRecords::Serialized(_) => {
            panic!("root-auth leaf collection requires materialized records")
        }
    }
}

#[test]
fn ordered_envelope_serializes_encrypted_zero_parity_like_materialized_path() {
    let options = plan_writer_options(WriterOptions {
        stripe_width: 1,
        volume_loss_tolerance: 0,
        bit_rot_buffer_pct: 0,
        aead_algo: AeadAlgo::AesGcmSiv256,
        ..WriterOptions::default()
    })
    .unwrap();
    let payload = deterministic_bytes(options.block_size as usize * 2 + 17);
    let extent = ObjectExtent::new(29, plan_encrypted_object(payload.len(), options.fec_data_shards, options.fec_parity_shards, options).unwrap()).unwrap();
    assert_eq!(extent.parity_block_count, 0);
    assert_eq!(extent.data_block_count, 3);
    let archive_uuid = [3u8; 16];
    let session_id = [4u8; 16];
    let master_key = MasterKey::from_raw_key(&[0x5a; 32]).unwrap();
    let subkeys = Subkeys::derive(&master_key, &archive_uuid, &session_id).unwrap();

    let serialized = build_ordered_envelope_result(
        OrderedEnvelopeJob { envelope_index: 7, plaintext: payload.clone(), extent, collect_data_leaf_hashes: false },
        &subkeys,
        options,
        archive_uuid,
        session_id,
    )
    .unwrap();
    let serialized_bytes = match serialized.records {
        OrderedEnvelopeRecords::Serialized(records) => records.into_iter().map(|record| record.bytes).collect::<Vec<_>>(),
        OrderedEnvelopeRecords::Materialized(_) => {
            panic!("zero-parity encrypted envelope should use serialized records")
        }
    };

    let materialized = build_ordered_envelope_result(
        OrderedEnvelopeJob { envelope_index: 7, plaintext: payload, extent, collect_data_leaf_hashes: true },
        &subkeys,
        options,
        archive_uuid,
        session_id,
    )
    .unwrap();
    let materialized_bytes = match materialized.records {
        OrderedEnvelopeRecords::Materialized(records) => records.iter().map(BlockRecord::to_bytes).collect::<Vec<_>>(),
        OrderedEnvelopeRecords::Serialized(_) => {
            panic!("root-auth leaf collection requires materialized records")
        }
    };

    assert_eq!(serialized_bytes, materialized_bytes);
}

#[test]
fn writer_options_reject_zero_jobs() {
    let err = plan_writer_options(WriterOptions { jobs: 0, ..WriterOptions::default() }).unwrap_err();

    assert_eq!(err, FormatError::WriterUnsupported("jobs must be at least 1"));
}

#[test]
fn production_writer_defaults_generate_distinct_v4_identities() {
    let master_key = MasterKey::from_raw_key(&[9u8; 32]).unwrap();
    let first = write_archive(&[], &master_key, WriterOptions::default()).unwrap();
    let second = write_archive(&[], &master_key, WriterOptions::default()).unwrap();

    assert_ne!(first.archive_uuid, [0u8; 16]);
    assert_ne!(first.session_id, [0u8; 16]);
    assert_ne!(second.archive_uuid, [0u8; 16]);
    assert_ne!(second.session_id, [0u8; 16]);
    assert_ne!(first.archive_uuid, first.session_id);
    assert_ne!(first.archive_uuid, second.archive_uuid);
    assert_ne!(first.session_id, second.session_id);

    for raw in [first.archive_uuid, first.session_id, second.archive_uuid, second.session_id] {
        let id = Uuid::from_bytes(raw);
        assert_eq!(id.get_version_num(), 4);
    }

    let deterministic = WriterOptions { archive_uuid: Some([0x44; 16]), session_id: Some([0x55; 16]), ..WriterOptions::default() };
    let fixture = write_archive(&[], &master_key, deterministic).unwrap();
    assert_eq!(fixture.archive_uuid, [0x44; 16]);
    assert_eq!(fixture.session_id, [0x55; 16]);
}

#[test]
fn writer_partitions_multiple_default_sized_index_shards() {
    let members = (0..=DEFAULT_FILES_PER_INDEX_SHARD)
        .map(|idx| TarMember {
            path: format!("file-{idx:05}.txt").into_bytes(),
            entry_kind: SourceEntryKind::Regular,
            link_target: None,
            tar_member_group_start: idx as u64 * 512,
            tar_member_group_size: 512,
            file_data_size: 0,
            sparse_extents: None,
            mode: 0o644,
            mtime: ArchiveTimestamp::UNIX_EPOCH,
            portable_metadata: PortableFileMetadata::default(),
        })
        .collect::<Vec<_>>();

    let shards = partition_file_rows(sorted_file_rows(&members)).unwrap();

    assert_eq!(shards.len(), 2);
    assert_eq!(shards[0].len(), DEFAULT_FILES_PER_INDEX_SHARD);
    assert_eq!(shards[1].len(), 1);
}

#[test]
fn writer_extends_shard_for_bounded_hash_prefix_run() {
    let mut rows = Vec::new();
    rows.extend((0..9_000).map(|idx| test_file_row(idx, [0u8; 8])));
    rows.extend((9_000..54_000).map(|idx| test_file_row(idx, [1u8; 8])));
    rows.push(test_file_row(54_000, [2u8; 8]));

    let shards = partition_file_rows(rows).unwrap();

    assert_eq!(shards.len(), 2);
    assert_eq!(shards[0].len(), 54_000);
    assert!(shards[0].iter().skip(9_000).all(|row| row.path_hash == [1u8; 8]));
    assert_eq!(shards[1][0].path_hash, [2u8; 8]);
}

#[test]
fn writer_splits_oversized_hash_prefix_run_at_writer_ceiling() {
    let rows = (0..MAX_HASH_PREFIX_RUN_FILES + 1).map(|idx| test_file_row(idx, [7u8; 8])).collect::<Vec<_>>();

    let shards = partition_file_rows(rows).unwrap();

    assert_eq!(shards.len(), 2);
    assert_eq!(shards[0].len(), MAX_HASH_PREFIX_RUN_FILES);
    assert_eq!(shards[1].len(), 1);
}

#[test]
fn writer_builds_directory_hint_rows_for_ancestor_directories() {
    let shard_rows = vec![
        vec![FileRow {
            path_hash: hash_prefix(b"a/b/one.txt"),
            path: b"a/b/one.txt".to_vec(),
            member_index: 0,
            member: TarMember {
                path: b"a/b/one.txt".to_vec(),
                entry_kind: SourceEntryKind::Regular,
                link_target: None,
                tar_member_group_start: 0,
                tar_member_group_size: 512,
                file_data_size: 0,
                sparse_extents: None,
                mode: 0o644,
                mtime: ArchiveTimestamp::UNIX_EPOCH,
                portable_metadata: PortableFileMetadata::default(),
            },
        }],
        vec![FileRow {
            path_hash: hash_prefix(b"a/c/two.txt"),
            path: b"a/c/two.txt".to_vec(),
            member_index: 1,
            member: TarMember {
                path: b"a/c/two.txt".to_vec(),
                entry_kind: SourceEntryKind::Regular,
                link_target: None,
                tar_member_group_start: 512,
                tar_member_group_size: 512,
                file_data_size: 0,
                sparse_extents: None,
                mode: 0o644,
                mtime: ArchiveTimestamp::UNIX_EPOCH,
                portable_metadata: PortableFileMetadata::default(),
            },
        }],
    ];

    let options = plan_writer_options(WriterOptions::default()).unwrap();
    let planned = build_directory_hint_plaintexts(&shard_rows, options).unwrap();
    assert_eq!(planned.len(), 1);
    let locating = DirectoryHintShardEntry {
        hint_shard_index: planned[0].hint_shard_index,
        first_dir_hash: planned[0].first_dir_hash,
        last_dir_hash: planned[0].last_dir_hash,
        first_block_index: 0,
        data_block_count: 1,
        parity_block_count: 0,
        encrypted_size: 4096,
        decompressed_size: planned[0].plaintext.len() as u32,
        entry_count: planned[0].entry_count,
    };
    let table = DirectoryHintTable::parse(&planned[0].plaintext, &locating, 2, MetadataLimits::default()).unwrap();

    let root = table.lookup_directory_index(b"").unwrap();
    assert_eq!(table.shard_rows_for_entry(root).unwrap(), &[0, 1]);
    let a = table.lookup_directory_index(b"a").unwrap();
    assert_eq!(table.shard_rows_for_entry(a).unwrap(), &[0, 1]);
    let ab = table.lookup_directory_index(b"a/b").unwrap();
    assert_eq!(table.shard_rows_for_entry(ab).unwrap(), &[0]);
}

#[test]
fn directory_hint_rows_include_directory_members_own_paths() {
    // §29 writer rule 14: hints include every FileEntry path whose decoded
    // primary entry is itself a directory. Leaf/empty directories are not
    // covered by any descendant's ancestor prefixes, so the writer must insert
    // their own paths. Regression for the reader rejecting the writer's own
    // output when hints are emitted (file_count > DIRECTORY_HINT_REQUIRED_FILE_COUNT).
    let shard_rows = vec![
        vec![
            FileRow {
                path_hash: hash_prefix(b"top.txt"),
                path: b"top.txt".to_vec(),
                member_index: 0,
                member: TarMember {
                    path: b"top.txt".to_vec(),
                    entry_kind: SourceEntryKind::Regular,
                    link_target: None,
                    tar_member_group_start: 0,
                    tar_member_group_size: 512,
                    file_data_size: 0,
                    sparse_extents: None,
                    mode: 0o644,
                    mtime: ArchiveTimestamp::UNIX_EPOCH,
                    portable_metadata: PortableFileMetadata::default(),
                },
            },
            // Leaf empty directory: its own path is not an ancestor of any member.
            FileRow {
                path_hash: hash_prefix(b"a/empty"),
                path: b"a/empty".to_vec(),
                member_index: 1,
                member: TarMember {
                    path: b"a/empty".to_vec(),
                    entry_kind: SourceEntryKind::Directory,
                    link_target: None,
                    tar_member_group_start: 512,
                    tar_member_group_size: 512,
                    file_data_size: 0,
                    sparse_extents: None,
                    mode: 0o755,
                    mtime: ArchiveTimestamp::UNIX_EPOCH,
                    portable_metadata: PortableFileMetadata::default(),
                },
            },
        ],
        vec![
            // Ancestor directory, covered incidentally by its descendant file.
            FileRow {
                path_hash: hash_prefix(b"a/b"),
                path: b"a/b".to_vec(),
                member_index: 2,
                member: TarMember {
                    path: b"a/b".to_vec(),
                    entry_kind: SourceEntryKind::Directory,
                    link_target: None,
                    tar_member_group_start: 1024,
                    tar_member_group_size: 512,
                    file_data_size: 0,
                    sparse_extents: None,
                    mode: 0o755,
                    mtime: ArchiveTimestamp::UNIX_EPOCH,
                    portable_metadata: PortableFileMetadata::default(),
                },
            },
            FileRow {
                path_hash: hash_prefix(b"a/b/one.txt"),
                path: b"a/b/one.txt".to_vec(),
                member_index: 3,
                member: TarMember {
                    path: b"a/b/one.txt".to_vec(),
                    entry_kind: SourceEntryKind::Regular,
                    link_target: None,
                    tar_member_group_start: 1536,
                    tar_member_group_size: 512,
                    file_data_size: 0,
                    sparse_extents: None,
                    mode: 0o644,
                    mtime: ArchiveTimestamp::UNIX_EPOCH,
                    portable_metadata: PortableFileMetadata::default(),
                },
            },
            // Deepest member of a directory-only chain: also a leaf directory.
            FileRow {
                path_hash: hash_prefix(b"x/y/z"),
                path: b"x/y/z".to_vec(),
                member_index: 4,
                member: TarMember {
                    path: b"x/y/z".to_vec(),
                    entry_kind: SourceEntryKind::Directory,
                    link_target: None,
                    tar_member_group_start: 2048,
                    tar_member_group_size: 512,
                    file_data_size: 0,
                    sparse_extents: None,
                    mode: 0o755,
                    mtime: ArchiveTimestamp::UNIX_EPOCH,
                    portable_metadata: PortableFileMetadata::default(),
                },
            },
        ],
    ];

    let options = plan_writer_options(WriterOptions::default()).unwrap();
    let planned = build_directory_hint_plaintexts(&shard_rows, options).unwrap();
    let locating = DirectoryHintShardEntry {
        hint_shard_index: planned[0].hint_shard_index,
        first_dir_hash: planned[0].first_dir_hash,
        last_dir_hash: planned[0].last_dir_hash,
        first_block_index: 0,
        data_block_count: 1,
        parity_block_count: 0,
        encrypted_size: 4096,
        decompressed_size: planned[0].plaintext.len() as u32,
        entry_count: planned[0].entry_count,
    };
    let table = DirectoryHintTable::parse(&planned[0].plaintext, &locating, 2, MetadataLimits::default()).unwrap();

    // Leaf directory paths must be locatable rows in the emitted table.
    let empty = table.lookup_directory_index(b"a/empty").unwrap();
    assert_eq!(table.shard_rows_for_entry(empty).unwrap(), &[0]);
    let xyz = table.lookup_directory_index(b"x/y/z").unwrap();
    assert_eq!(table.shard_rows_for_entry(xyz).unwrap(), &[1]);
    let top = table.lookup_directory_index(b"").unwrap();
    assert_eq!(table.shard_rows_for_entry(top).unwrap(), &[0, 1]);

    // The table must satisfy the reader's exact-equality expectation built
    // from the same members (validate_streamed_payload_summary contract).
    let mut expected = BTreeMap::<Vec<u8>, BTreeSet<u32>>::new();
    for (shard_row_index, rows) in shard_rows.iter().enumerate() {
        for row in rows {
            let kind = match row.member.entry_kind {
                SourceEntryKind::Directory | SourceEntryKind::ReparseDirectory => TarEntryKind::Directory,
                _ => TarEntryKind::Regular,
            };
            add_expected_directory_hint_rows(&mut expected, shard_row_index as u32, &row.path, kind);
        }
    }
    validate_directory_hint_tables_against_expected(&[table], &expected).unwrap();
}

#[test]
fn directory_hints_are_required_only_above_v45_threshold() {
    assert!(!should_emit_directory_hints(0));
    assert!(!should_emit_directory_hints(DIRECTORY_HINT_REQUIRED_FILE_COUNT));
    assert!(should_emit_directory_hints(DIRECTORY_HINT_REQUIRED_FILE_COUNT + 1));
}

#[test]
fn regular_file_writer_uses_local_pax_path_for_long_and_non_ascii_paths() {
    let long_path = format!("dir/{}.txt", "a".repeat(120));
    let unicode_path = "unicode/e\u{301}.txt";
    let files = [RegularFile::new(&long_path, b"long path"), RegularFile::new(unicode_path, b"unicode path")];

    let (tar_stream, members) = build_tar_stream(&files, 4096).unwrap();

    for (member, expected_path, expected_data) in
        [(&members[0], long_path.as_bytes(), b"long path".as_slice()), (&members[1], "unicode/\u{e9}.txt".as_bytes(), b"unicode path".as_slice())]
    {
        let start = member.tar_member_group_start as usize;
        let end = start + member.tar_member_group_size as usize;
        let group = &tar_stream[start..end];
        assert_eq!(group[156], b'x');
        let parsed = parse_tar_member_group(group, 4096).unwrap();
        assert_eq!(parsed.path, expected_path);
        assert_eq!(parsed.data, expected_data);
    }
}

#[test]
fn regular_file_writer_emits_no_global_metadata_or_tar_eof() {
    let long_path = format!("dir/{}.txt", "a".repeat(120));
    let files = [RegularFile::new("plain.txt", b"plain contents"), RegularFile::new(&long_path, b"long path contents")];

    let (tar_stream, members) = build_tar_stream(&files, 4096).unwrap();

    let member_bytes = members.iter().map(|member| member.tar_member_group_size).sum::<u64>();
    assert_eq!(tar_stream.len() as u64, member_bytes);
    assert!(!tar_stream[tar_stream.len() - TAR_BLOCK_LEN * 2..].chunks(TAR_BLOCK_LEN).all(|block| block.iter().all(|byte| *byte == 0)));

    for member in members {
        let start = member.tar_member_group_start as usize;
        let end = start + member.tar_member_group_size as usize;
        assert_path_specific_member_group(&tar_stream[start..end]);
    }
}

struct SparseTestSource {
    logical_size: u64,
    extents: Vec<SparseExtent>,
    extent_bytes: Vec<u8>,
}

impl RegularFileSource for SparseTestSource {
    fn archive_path(&self) -> &str {
        "sparse.bin"
    }

    fn file_data_size(&self) -> u64 {
        self.logical_size
    }

    fn sparse_extents(&self) -> Option<&[SparseExtent]> {
        Some(&self.extents)
    }

    fn mode(&self) -> u32 {
        0o644
    }

    fn mtime(&self) -> ArchiveTimestamp {
        ArchiveTimestamp::UNIX_EPOCH
    }

    fn open(&self) -> Result<Box<dyn Read + '_>, ArchiveWriteError> {
        Ok(Box::new(Cursor::new(self.extent_bytes.as_slice())))
    }
}

#[test]
fn sparse_writer_emits_canonical_gnu_sparse_primary_and_all_hole_file() {
    for source in [
        SparseTestSource {
            logical_size: 32,
            extents: vec![SparseExtent { offset: 4, length: 3 }, SparseExtent { offset: 16, length: 2 }, SparseExtent { offset: 30, length: 2 }],
            extent_bytes: b"abcdeyz".to_vec(),
        },
        SparseTestSource { logical_size: 1 << 20, extents: Vec::new(), extent_bytes: Vec::new() },
    ] {
        let expected_map_prefix = format!("{}\n", source.extents.len());
        let (tar_stream, members) = build_tar_stream(&[source], 4096).unwrap();
        let parsed = parse_tar_member_group(&tar_stream, 4096).unwrap();
        assert_eq!(parsed.path, b"sparse.bin");
        assert_eq!(parsed.logical_size, members[0].file_data_size);
        let layout = parsed.v45_metadata.sparse_layout.unwrap();
        assert_eq!(layout.logical_size, members[0].file_data_size);
        assert_eq!(layout.extents, members[0].sparse_extents.clone().unwrap());
        assert!(parsed.data.starts_with(expected_map_prefix.as_bytes()));
    }
}

#[test]
fn sparse_writer_rejects_noncanonical_extent_maps() {
    for extents in [
        vec![SparseExtent { offset: 0, length: 0 }],
        vec![SparseExtent { offset: 0, length: 2 }, SparseExtent { offset: 2, length: 2 }],
        vec![SparseExtent { offset: 9, length: 2 }],
    ] {
        let source = SparseTestSource { logical_size: 10, extents, extent_bytes: Vec::new() };
        assert!(build_tar_stream(&[source], 4096).is_err());
    }
}

#[test]
fn sparse_writer_indexes_logical_size_and_streams_expanded_content() {
    let source = SparseTestSource {
        logical_size: 12,
        extents: vec![SparseExtent { offset: 2, length: 3 }, SparseExtent { offset: 9, length: 2 }],
        extent_bytes: b"abcxy".to_vec(),
    };
    let master_key = MasterKey::from_raw_key(&[7u8; 32]).unwrap();
    let mut sink = MemoryArchiveSink::default();
    write_archive_sources_to_sink(&[source], &master_key, single_volume_metadata_test_options(), None, &KdfParams::Raw, None, None, &mut sink).unwrap();

    let opened = open_archive(&sink.volumes[0], &master_key).unwrap();
    opened.verify().unwrap();
    let entry = opened.lookup_index_entry("sparse.bin").unwrap().unwrap();
    assert_eq!(entry.file_data_size, 12);
    assert_ne!(entry.flags & HAS_SPARSE_EXTENTS, 0);
    assert_eq!(opened.extract_file("sparse.bin").unwrap().unwrap(), b"\0\0abc\0\0\0\0xy\0");
}

#[test]
fn regular_file_writer_round_trips_mode_and_mtime() {
    let group =
        build_regular_file_member_group(b"script.sh", b"#!/bin/sh\n", 0o755, ArchiveTimestamp::from_seconds(1_700_000_000), &PortableFileMetadata::default())
            .unwrap();

    let parsed = parse_tar_member_group(&group, 4096).unwrap();

    assert_eq!(parsed.mode, 0o755);
    assert_eq!(parsed.mtime, ArchiveTimestamp::from_seconds(1_700_000_000));
}

#[test]
fn regular_file_writer_round_trips_nanosecond_and_pre_epoch_mtimes() {
    for expected in [ArchiveTimestamp::new(1_700_000_000, 123_456_789), ArchiveTimestamp::new(-1, 500_000_000)] {
        let group = build_regular_file_member_group(b"dated.txt", b"dated", 0o644, expected, &PortableFileMetadata::default()).unwrap();
        let parsed = parse_tar_member_group(&group, 4096).unwrap();
        assert_eq!(parsed.mtime, expected);
        assert_eq!(parsed.v45_metadata.portable_mirror.mtime, (expected.seconds, expected.nanoseconds));
    }
}

#[test]
fn regular_file_writer_rejects_invalid_timestamp_nanoseconds() {
    assert!(matches!(
        build_regular_file_member_group(b"dated.txt", b"dated", 0o644, ArchiveTimestamp::new(0, 1_000_000_000), &PortableFileMetadata::default(),),
        Err(FormatError::WriterUnsupported("timestamp nanoseconds must be less than one billion"))
    ));
}

#[test]
fn macos_entitlement_and_superuser_flags_require_system_restore() {
    for flags in [0x0000_0080u64, 0x0008_0000, 0x0010_0000, 0x0080_0000] {
        let mut native = NativeFileMetadata::default();
        native.primary_pax_records.insert("TZAP.macos.st-flags".into(), format!("{flags:016x}").into_bytes());
        assert!(native_metadata_requires_system_restore(&native, "macos"));
    }
}

#[test]
fn linux_bsd_macos_immutable_flags_require_system_restore() {
    let mut native = NativeFileMetadata::default();
    native.primary_pax_records.insert(
        "TZAP.linux.fsflags".into(),
        "0000000000000030".into(), // append and immutable
    );
    assert!(native_metadata_requires_system_restore(&native, "linux"));

    let mut native = NativeFileMetadata::default();
    native.primary_pax_records.insert(
        "TZAP.bsd.st-flags".into(),
        "0000000000060006".into(), // append and immutable
    );
    assert!(native_metadata_requires_system_restore(&native, "freebsd"));

    let mut native = NativeFileMetadata::default();
    native.primary_pax_records.insert(
        "TZAP.macos.st-flags".into(),
        "0000000000040000".into(), // SF_IMMUTABLE
    );
    assert!(native_metadata_requires_system_restore(&native, "macos"));

    let mut native = NativeFileMetadata::default();
    native.primary_pax_records.insert("SCHILY.fflags".into(), "uchg,uappnd".into());
    assert!(native_metadata_requires_system_restore(&native, "linux"));
}

#[test]
fn windows_reparse_and_attributes_require_system_restore() {
    let mut native = NativeFileMetadata::default();
    native.primary_pax_records.insert("TZAP.windows.reparse-placeholder".into(), "1".into());
    assert!(native_metadata_requires_system_restore(&native, "windows"));

    let mut native = NativeFileMetadata::default();
    native.primary_pax_records.insert(
        "TZAP.windows.data-stream-attributes".into(),
        "00000002".into(), // stream contains security
    );
    assert!(native_metadata_requires_system_restore(&native, "windows"));
}

#[test]
fn regular_file_writer_round_trips_portable_owner_origin_and_attributes() {
    let portable_metadata = PortableFileMetadata {
        source_os: "other-unix".into(),
        source_filesystem: "ext4".into(),
        mode_origin: PortableModeOrigin::Native,
        posix_owner: Some(PortablePosixOwner { uid: 9_000_000, gid: 42, uname: Some("tést-user".into()), gname: Some("archive".into()) }),
        attributes: Some(1),
        created: None,
        accessed: None,
        native: NativeFileMetadata::default(),
    };
    let group = build_regular_file_member_group(b"owned.txt", b"owned", 0o640, ArchiveTimestamp::UNIX_EPOCH, &portable_metadata).unwrap();
    let parsed = parse_tar_member_group(&group, 4096).unwrap();

    assert!(parsed.v45_metadata.declaration.owner_kind_posix);
    assert!(parsed.v45_metadata.declaration.mode_origin_native);
    assert_eq!(parsed.v45_metadata.declaration.source_os, "other-unix");
    assert_eq!(parsed.v45_metadata.declaration.source_filesystem, "ext4");
    assert_eq!(parsed.v45_metadata.portable_mirror.uid, Some(9_000_000));
    assert_eq!(parsed.v45_metadata.portable_mirror.gid, Some(42));
    assert_eq!(parsed.v45_metadata.portable_mirror.uname.as_deref(), Some("tést-user".as_bytes()));
    assert_eq!(parsed.v45_metadata.portable_mirror.attributes, Some(1));
    assert_ne!(parsed.v45_metadata.file_entry_flags & REQUIRES_SYSTEM_RESTORE, 0);
}

#[test]
fn regular_file_writer_serializes_portable_creation_and_access_times() {
    let created = ArchiveTimestamp::new(1_600_000_000, 123_456_789);
    let accessed = ArchiveTimestamp::new(1_700_000_000, 987_654_321);
    let portable_metadata = PortableFileMetadata { created: Some(created), accessed: Some(accessed), ..PortableFileMetadata::default() };

    let group = build_regular_file_member_group(b"timestamps.txt", b"timestamps", 0o644, ArchiveTimestamp::UNIX_EPOCH, &portable_metadata).unwrap();
    let parsed = parse_tar_member_group(&group, 4096).unwrap();

    assert_eq!(parsed.v45_metadata.primary_records.get("LIBARCHIVE.creationtime").map(Vec::as_slice), Some(b"1600000000.123456789".as_slice()));
    assert_eq!(parsed.v45_metadata.primary_records.get("atime").map(Vec::as_slice), Some(b"1700000000.987654321".as_slice()));
}

#[test]
fn directory_writer_emits_type_and_portable_ownership_metadata() {
    let portable_metadata = PortableFileMetadata {
        source_os: "other-unix".into(),
        source_filesystem: "unknown".into(),
        mode_origin: PortableModeOrigin::Native,
        posix_owner: Some(PortablePosixOwner { uid: 9_000_000, gid: 42, uname: Some("directory-owner".into()), gname: Some("archive".into()) }),
        attributes: None,
        created: None,
        accessed: None,
        native: NativeFileMetadata::default(),
    };
    let bytes = build_primary_member_prefix(
        b"empty-dir",
        SourceEntryKind::Directory,
        None,
        0,
        None,
        0o2750,
        ArchiveTimestamp::new(1_700_000_000, 123_456_789),
        &portable_metadata,
    )
    .unwrap();
    let parsed = parse_tar_member_group(&bytes, 4096).unwrap();

    assert_eq!(parsed.kind, crate::tar_model::TarEntryKind::Directory);
    assert_eq!(parsed.logical_size, 0);
    assert_eq!(parsed.v45_metadata.portable_mirror.mode, 0o2750);
    assert_eq!(parsed.v45_metadata.portable_mirror.uid, Some(9_000_000));
    assert_eq!(parsed.v45_metadata.portable_mirror.gid, Some(42));
    assert_eq!(parsed.v45_metadata.portable_mirror.mtime, (1_700_000_000, 123_456_789));
}

#[test]
fn posix_special_writer_emits_fifo_and_device_primaries() {
    let mut portable = PortableFileMetadata {
        source_os: "linux".into(),
        mode_origin: PortableModeOrigin::Native,
        native: NativeFileMetadata { required_profiles: vec!["posix-backup-v1".into(), "linux-backup-v1".into()], ..NativeFileMetadata::default() },
        ..PortableFileMetadata::default()
    };
    let fifo = build_primary_member_prefix(b"pipe", SourceEntryKind::Fifo, None, 0, None, 0o640, ArchiveTimestamp::UNIX_EPOCH, &portable).unwrap();
    assert_eq!(parse_tar_member_group(&fifo, 4096).unwrap().kind, crate::tar_model::TarEntryKind::Fifo);

    portable.native.primary_pax_records.insert("TZAP.posix.device-major".into(), b"1".to_vec());
    portable.native.primary_pax_records.insert("TZAP.posix.device-minor".into(), b"3".to_vec());
    let device = build_primary_member_prefix(b"null", SourceEntryKind::CharacterDevice, None, 0, None, 0o666, ArchiveTimestamp::UNIX_EPOCH, &portable).unwrap();
    assert_eq!(parse_tar_member_group(&device, 4096).unwrap().kind, crate::tar_model::TarEntryKind::CharacterDevice);
}

#[test]
fn symlink_writer_emits_target_and_fractional_mtime() {
    let mtime = ArchiveTimestamp::new(1_700_000_321, 654_321_000);
    let bytes = build_primary_member_prefix(
        b"links/current",
        SourceEntryKind::Symlink,
        Some(b"../target.txt"),
        0,
        None,
        0o777,
        mtime,
        &PortableFileMetadata::default(),
    )
    .unwrap();
    let parsed = parse_tar_member_group(&bytes, 4096).unwrap();

    assert_eq!(parsed.kind, crate::tar_model::TarEntryKind::Symlink);
    assert_eq!(parsed.link_target.as_deref(), Some(b"../target.txt".as_slice()));
    assert_eq!(parsed.mtime, mtime);
    assert_eq!(parsed.v45_metadata.portable_mirror.mtime, (mtime.seconds, mtime.nanoseconds));
}

#[test]
fn hardlink_writer_emits_zero_data_alias_with_portable_mirror_only() {
    let portable = PortableFileMetadata {
        source_os: "other-unix".into(),
        source_filesystem: "ext4".into(),
        mode_origin: PortableModeOrigin::Native,
        posix_owner: Some(PortablePosixOwner { uid: 1000, gid: 100, uname: Some("owner".into()), gname: Some("group".into()) }),
        attributes: Some(1),
        created: None,
        accessed: None,
        native: NativeFileMetadata::default(),
    };
    let bytes = build_primary_member_prefix(
        b"aliases/beta",
        SourceEntryKind::Hardlink,
        Some(b"aliases/alpha"),
        0,
        None,
        0o640,
        ArchiveTimestamp::new(1_700_000_000, 123_456_700),
        &portable,
    )
    .unwrap();
    let parsed = parse_tar_member_group(&bytes, 4096).unwrap();
    assert_eq!(parsed.kind, crate::tar_model::TarEntryKind::Hardlink);
    assert_eq!(parsed.logical_size, 0);
    assert_eq!(parsed.link_target.as_deref(), Some(b"aliases/alpha".as_slice()));
    assert_eq!(parsed.v45_metadata.declaration.required_profiles, ["portable-v1"]);
    assert!(parsed.v45_metadata.auxiliary.is_empty());
    assert_eq!(parsed.v45_metadata.portable_mirror.mode, 0o640);
    assert_eq!(parsed.v45_metadata.portable_mirror.uid, Some(1000));
    assert_eq!(parsed.v45_metadata.portable_mirror.attributes, Some(1));
}

#[test]
fn hardlink_writer_rejects_native_file_object_metadata() {
    let mut portable = PortableFileMetadata::default();
    portable.native.primary_pax_records.insert("TZAP.unix.ctime-observed".into(), b"1".to_vec());
    assert!(matches!(
        build_primary_member_prefix(b"beta", SourceEntryKind::Hardlink, Some(b"alpha"), 0, None, 0o644, ArchiveTimestamp::UNIX_EPOCH, &portable,),
        Err(FormatError::WriterInvariant("hardlink alias carries native file-object metadata"))
    ));
}

#[test]
fn regular_file_writer_rejects_reserved_portable_attribute_bits() {
    let portable_metadata = PortableFileMetadata { attributes: Some(1 << 4), ..PortableFileMetadata::default() };
    assert_eq!(
        build_regular_file_member_group(b"attributes.txt", b"data", 0o644, ArchiveTimestamp::UNIX_EPOCH, &portable_metadata,).unwrap_err(),
        FormatError::WriterUnsupported("portable attributes contain reserved bits")
    );
}

#[test]
fn regular_file_writer_emits_and_flags_valid_native_primary_metadata() {
    let mut native = NativeFileMetadata { required_profiles: vec!["posix-backup-v1".into()], ..NativeFileMetadata::default() };
    native.primary_pax_records.insert("LIBARCHIVE.xattr.user.comment".into(), crate::entry_metadata::canonical_base64_encode(b"preserved"));
    let metadata = PortableFileMetadata { source_os: "linux".into(), source_filesystem: "ext4".into(), native, ..PortableFileMetadata::default() };
    let group = build_regular_file_member_group(b"native.txt", b"data", 0o640, ArchiveTimestamp::UNIX_EPOCH, &metadata).unwrap();
    let parsed = parse_tar_member_group(&group, 4096).unwrap();

    assert_eq!(parsed.v45_metadata.declaration.required_profiles, vec!["portable-v1", "posix-backup-v1"]);
    assert_eq!(parsed.v45_metadata.primary_records.get("LIBARCHIVE.xattr.user.comment").map(Vec::as_slice), Some(b"cHJlc2VydmVk".as_slice()));
    assert_ne!(parsed.v45_metadata.file_entry_flags & HAS_NATIVE_METADATA, 0);
}

#[test]
fn regular_file_writer_emits_valid_native_auxiliary_metadata() {
    let mut native = NativeFileMetadata { required_profiles: vec!["posix-backup-v1".into()], ..NativeFileMetadata::default() };
    let mut auxiliary = NativeAuxiliaryMetadata::new("generic.xattr", "posix-backup-v1", RestoreClass::SameOs, b"large xattr value".to_vec());
    auxiliary.name_encoding = NativeAuxiliaryNameEncoding::Bytes;
    auxiliary.name = b"user.large".to_vec();
    native.auxiliary_records.push(auxiliary);
    let metadata = PortableFileMetadata { source_os: "linux".into(), native, ..PortableFileMetadata::default() };

    let group = build_regular_file_member_group(b"native-aux.txt", b"contents", 0o640, ArchiveTimestamp::from_seconds(12), &metadata).unwrap();
    let parsed = parse_tar_member_group(&group, 4096).unwrap();

    assert_eq!(parsed.v45_metadata.auxiliary.len(), 1);
    assert_eq!(parsed.v45_metadata.auxiliary[0].kind, "generic.xattr");
    assert_eq!(parsed.v45_metadata.auxiliary[0].decoded_name, b"user.large");
    assert_ne!(parsed.v45_metadata.file_entry_flags & HAS_AUXILIARY_STREAMS, 0);
}

#[test]
fn regular_file_writer_emits_capture_partial_flag_when_capture_report_present() {
    let mut native = NativeFileMetadata::default();
    let mut auxiliary = NativeAuxiliaryMetadata::new(
        "tzap.capture-report",
        "tzap-core-v1",
        RestoreClass::None,
        b"tzap-capture-report-v1\nportable-v1\ttzap-core-v1\texcluded-policy\tdetail\n".to_vec(),
    );
    auxiliary.native = false;
    auxiliary.name_encoding = NativeAuxiliaryNameEncoding::None;
    auxiliary.name = vec![];
    native.auxiliary_records.push(auxiliary);
    let metadata = PortableFileMetadata { source_os: "linux".into(), native, ..PortableFileMetadata::default() };

    let group = build_regular_file_member_group(b"capture-report.txt", b"contents", 0o640, ArchiveTimestamp::from_seconds(12), &metadata).unwrap();
    let parsed = parse_tar_member_group(&group, 4096).unwrap();

    assert_eq!(parsed.v45_metadata.auxiliary.len(), 1);
    assert_eq!(parsed.v45_metadata.auxiliary[0].kind, "tzap.capture-report");
    assert_ne!(parsed.v45_metadata.file_entry_flags & CAPTURE_PARTIAL, 0);
}

#[test]
fn streamed_auxiliary_sources_work_across_writer_modes_and_verify_digest() {
    struct StreamedSource {
        metadata: PortableFileMetadata,
        payload: Vec<u8>,
    }

    impl RegularFileSource for StreamedSource {
        fn archive_path(&self) -> &str {
            "streamed-aux.txt"
        }

        fn file_data_size(&self) -> u64 {
            8
        }

        fn mode(&self) -> u32 {
            0o640
        }

        fn mtime(&self) -> ArchiveTimestamp {
            ArchiveTimestamp::from_seconds(12)
        }

        fn portable_metadata(&self) -> PortableFileMetadata {
            self.metadata.clone()
        }

        fn open(&self) -> Result<Box<dyn Read + '_>, ArchiveWriteError> {
            Ok(Box::new(Cursor::new(b"contents".as_slice())))
        }

        fn open_auxiliary(&self, ordinal: usize) -> Result<Box<dyn Read + '_>, ArchiveWriteError> {
            assert_eq!(ordinal, 0);
            Ok(Box::new(Cursor::new(self.payload.as_slice())))
        }
    }

    let payload = deterministic_bytes(1024 * 1024 + 17);
    let digest: [u8; 32] = Sha256::digest(&payload).into();
    let mut auxiliary = NativeAuxiliaryMetadata::new_streamed("generic.xattr", "posix-backup-v1", RestoreClass::SameOs, payload.len() as u64, digest);
    auxiliary.name_encoding = NativeAuxiliaryNameEncoding::Bytes;
    auxiliary.name = b"user.large".to_vec();
    let mut source = StreamedSource {
        metadata: PortableFileMetadata {
            source_os: "linux".into(),
            native: NativeFileMetadata {
                required_profiles: vec!["posix-backup-v1".into()],
                auxiliary_records: vec![auxiliary],
                ..NativeFileMetadata::default()
            },
            ..PortableFileMetadata::default()
        },
        payload,
    };
    let key = MasterKey::from_raw_key(&[17u8; 32]).unwrap();
    let options = WriterOptions { stripe_width: 1, volume_loss_tolerance: 0, bit_rot_buffer_pct: 0, ..WriterOptions::default() };

    let mut two_pass = MemoryArchiveSink::default();
    write_archive_sources_to_sink(std::slice::from_ref(&source), &key, options, None, &KdfParams::Raw, None, None, &mut two_pass).unwrap();
    open_archive(&two_pass.volumes[0], &key).unwrap().verify_content().unwrap();

    let mut single_pass = MemoryArchiveSink::default();
    write_archive_sources_to_sink_single_pass(std::slice::from_ref(&source), &key, options, &KdfParams::Raw, None, None, &mut single_pass).unwrap();
    open_archive(&single_pass.volumes[0], &key).unwrap().verify_content().unwrap();

    let mut ordered = MemoryArchiveSink::default();
    write_archive_sources_to_sink_ordered_parallel(std::slice::from_ref(&source), &key, options, &KdfParams::Raw, None, None, &mut ordered).unwrap();
    open_archive(&ordered.volumes[0], &key).unwrap().verify_content().unwrap();

    let mut progress_sink = MemoryArchiveSink::default();
    let mut progress = RecordingWriteProgress::default();
    write_archive_sources_to_sink_single_pass_with_progress(
        std::slice::from_ref(&source),
        &key,
        options,
        &KdfParams::Raw,
        None,
        None,
        &mut progress_sink,
        &mut progress,
    )
    .unwrap();
    assert_eq!(progress.bytes_for(ArchiveWritePhase::EmittingPayload), 8 + source.payload.len() as u64);

    source.metadata.native.auxiliary_records[0].streamed_payload.as_mut().unwrap().sha256[0] ^= 1;
    let mut rejected = MemoryArchiveSink::default();
    assert!(write_archive_sources_to_sink(std::slice::from_ref(&source), &key, options, None, &KdfParams::Raw, None, None, &mut rejected,).is_err());
}

#[test]
fn writer_splits_large_payload_across_seekable_envelopes() {
    let master_key = MasterKey::from_raw_key(&[8u8; 32]).unwrap();
    let data = deterministic_bytes(2 * 1024 * 1024);
    let archive = write_archive(
        &[RegularFile::new("large.bin", &data)],
        &master_key,
        WriterOptions { stripe_width: 1, volume_loss_tolerance: 0, bit_rot_buffer_pct: 0, ..WriterOptions::default() },
    )
    .unwrap();
    let opened = open_archive(&archive.bytes, &master_key).unwrap();

    assert_eq!(opened.list_files().unwrap()[0].path, "large.bin");
    assert_eq!(opened.extract_file("large.bin").unwrap(), Some(data));
    opened.verify().unwrap();
    assert!(opened.index_root.header.envelope_count > 1);
}

#[test]
fn split_member_frames_carry_exact_boundary_flags() {
    let data = deterministic_bytes(12 * 1024);
    let files = [RegularFile::new("large.bin", &data)];
    let options = WriterOptions {
        chunk_size: 1024,
        envelope_target_size: 64 * 1024,
        stripe_width: 1,
        volume_loss_tolerance: 0,
        bit_rot_buffer_pct: 0,
        ..WriterOptions::default()
    };
    let (tar_stream, members) = build_tar_stream(&files, options.max_path_length).unwrap();
    let (_, frames) = build_payload_envelopes(&tar_stream, &members, options, None).unwrap();

    assert!(frames.len() > 2);
    assert_eq!(frames.first().unwrap().flags, 0x0000_0001);
    assert_eq!(frames.last().unwrap().flags, 0x0000_0002);
    assert!(frames[1..frames.len() - 1].iter().all(|frame| frame.flags == 0));
}

#[test]
fn spanning_payload_derives_exact_multi_frame_multi_envelope_stats() {
    let data = deterministic_bytes(13 * 1024);
    let files = [RegularFile::new("spanning.bin", &data)];
    let options = plan_writer_options(WriterOptions {
        block_size: MIN_BLOCK_SIZE,
        chunk_size: 1024,
        envelope_target_size: 2500,
        stripe_width: 1,
        volume_loss_tolerance: 0,
        bit_rot_buffer_pct: 0,
        fec_parity_shards: 0,
        index_fec_parity_shards: 0,
        index_root_fec_parity_shards: 0,
        ..WriterOptions::default()
    })
    .unwrap();
    let mut next_block_index = 0u64;

    let payload = plan_payload_stream(&files, options, None, &mut next_block_index).unwrap();
    let expected_tar_total_size = 3 * TAR_BLOCK_LEN as u64 + data.len() as u64 + padding_to_512(data.len()) as u64;
    let (tar_stream, _) = build_tar_stream(&files, options.max_path_length).unwrap();

    assert_eq!(payload.tar_members.len(), 1);
    assert_eq!(payload.tar_members[0].tar_member_group_start, 0);
    assert_eq!(payload.tar_members[0].tar_member_group_size, expected_tar_total_size);
    assert_eq!(payload.tar_total_size, expected_tar_total_size);
    assert_eq!(payload.content_sha256, sha256_bytes(&tar_stream));
    assert_eq!(payload.frames.len(), 15);
    assert_eq!(payload.payload_objects.len(), 7);
    assert_eq!(payload.payload_block_count, 7);
    assert_eq!(next_block_index, 7);

    for (idx, frame) in payload.frames.iter().enumerate() {
        let expected_decompressed_size = if idx == 14 { 512 } else { 1024 };
        let expected_flags = match idx {
            0 => 0x0000_0001,
            14 => 0x0000_0002,
            _ => 0,
        };
        let expected_offset =
            payload.frames[..idx].iter().filter(|prior| prior.envelope_index == frame.envelope_index).map(|prior| prior.compressed_size).sum::<u32>();

        assert_eq!(frame.frame_index, idx as u64);
        assert_eq!(frame.member_index, 0);
        assert!((frame.envelope_index as usize) < payload.payload_objects.len());
        assert_eq!(frame.offset_in_envelope, expected_offset);
        assert_eq!(frame.decompressed_size, expected_decompressed_size);
        assert_eq!(frame.flags, expected_flags);
        assert_eq!(frame.tar_stream_offset, idx as u64 * 1024);
    }

    for (idx, object) in payload.payload_objects.iter().enumerate() {
        let expected_plaintext_size = payload.frames.iter().filter(|frame| frame.envelope_index == idx as u64).map(|frame| frame.compressed_size).sum::<u32>();

        assert_eq!(object.envelope_index, idx as u64);
        assert_eq!(object.plaintext_size, expected_plaintext_size);
        assert_eq!(object.object.first_block_index, idx as u64);
        assert_eq!(object.object.data_block_count, 1);
        assert_eq!(object.object.parity_block_count, 0);
        assert_eq!(object.object.encrypted_size, options.block_size);
    }

    let shard_rows = partition_file_rows(sorted_file_rows(&payload.tar_members)).unwrap();
    let planned_shards = build_index_shard_plaintexts(&shard_rows, &payload.frames, &payload.payload_objects, options).unwrap();
    assert_eq!(planned_shards.len(), 1);
    let locating_shard = ShardEntry {
        shard_index: planned_shards[0].shard_index,
        first_block_index: 0,
        data_block_count: 1,
        parity_block_count: 0,
        encrypted_size: options.block_size,
        decompressed_size: planned_shards[0].plaintext.len() as u32,
        file_count: planned_shards[0].file_count,
        first_path_hash: planned_shards[0].first_path_hash,
        last_path_hash: planned_shards[0].last_path_hash,
    };
    let shard = IndexShard::parse(&planned_shards[0].plaintext, &locating_shard, MetadataLimits::default()).unwrap();
    assert_eq!(shard.header.file_count, 1);
    assert_eq!(shard.header.frame_count, 15);
    assert_eq!(shard.header.envelope_count, 7);
    assert_eq!(shard.files[0].first_frame_index, 0);
    assert_eq!(shard.files[0].frame_count, 15);
    assert_eq!(shard.files[0].tar_member_group_size, expected_tar_total_size);
    assert_eq!(shard.files[0].file_data_size, data.len() as u64);

    for (idx, frame) in shard.frames.iter().enumerate() {
        assert_eq!(frame.frame_index, idx as u64);
        assert_eq!(frame.envelope_index, payload.frames[idx].envelope_index);
        assert_eq!(frame.offset_in_envelope, payload.frames[idx].offset_in_envelope);
        assert_eq!(frame.compressed_size, payload.frames[idx].compressed_size);
        assert_eq!(frame.decompressed_size, payload.frames[idx].decompressed_size);
        assert_eq!(frame.flags, payload.frames[idx].flags);
        assert_eq!(frame.tar_stream_offset, payload.frames[idx].tar_stream_offset);
    }

    for (idx, envelope) in shard.envelopes.iter().enumerate() {
        assert_eq!(envelope.envelope_index, idx as u64);
        assert_eq!(envelope.first_block_index, idx as u64);
        assert_eq!(envelope.data_block_count, 1);
        assert_eq!(envelope.parity_block_count, 0);
        assert_eq!(envelope.encrypted_size, options.block_size);
        assert_eq!(envelope.plaintext_size, payload.payload_objects[idx].plaintext_size);
        let envelope_frames: Vec<_> = payload.frames.iter().filter(|frame| frame.envelope_index == idx as u64).collect();
        assert_eq!(envelope.first_frame_index, envelope_frames.first().unwrap().frame_index);
        assert_eq!(envelope.frame_count, envelope_frames.len() as u32);
    }

    let master_key = MasterKey::from_raw_key(&[6u8; 32]).unwrap();
    let plan =
        build_writer_plan_from_payload(payload, next_block_index, &master_key, options, None, &KdfParams::Raw, None, [0x44; 16], [0x55; 16], None).unwrap();
    let index_root = IndexRoot::parse(&plan.index_root_plaintext, false, MetadataLimits::default()).unwrap();

    assert_eq!(index_root.header.frame_count, 15);
    assert_eq!(index_root.header.envelope_count, 7);
    assert_eq!(index_root.header.file_count, 1);
    assert_eq!(index_root.header.payload_block_count, 7);
    assert_eq!(index_root.header.tar_total_size, expected_tar_total_size);
    assert_eq!(index_root.header.content_sha256, sha256_bytes(&tar_stream));
}

#[test]
fn writes_empty_archive_with_authentic_bootstrap_structures() {
    let master_key = MasterKey::from_raw_key(&[7u8; 32]).unwrap();
    let archive = write_empty_archive(&master_key).unwrap();
    let bytes = archive.bytes;

    let volume_header = VolumeHeader::parse(&bytes[..VOLUME_HEADER_LEN]).unwrap();
    assert_eq!(volume_header.archive_uuid, archive.archive_uuid);
    assert_eq!(volume_header.session_id, archive.session_id);

    let crypto_start = VOLUME_HEADER_LEN;
    let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
    let crypto_header = CryptoHeader::parse(&bytes[crypto_start..crypto_end], volume_header.crypto_header_length).unwrap();
    let subkeys = Subkeys::derive(&master_key, &archive.archive_uuid, &archive.session_id).unwrap();
    verify_hmac(
        HmacDomain::CryptoHeader,
        &subkeys.mac_key,
        &archive.archive_uuid,
        &archive.session_id,
        crypto_header.hmac_covered_bytes,
        &crypto_header.header_hmac,
    )
    .unwrap();

    let locator = CriticalRecoveryLocator::parse(&bytes[bytes.len() - CRITICAL_RECOVERY_LOCATOR_LEN..]).unwrap();
    let trailer_offset = locator.volume_trailer_offset as usize;
    let trailer = VolumeTrailer::parse(&bytes[trailer_offset..trailer_offset + VOLUME_TRAILER_LEN]).unwrap();
    assert_eq!(trailer.bytes_written, trailer_offset as u64);
    verify_hmac(
        HmacDomain::VolumeTrailer,
        &subkeys.mac_key,
        &archive.archive_uuid,
        &archive.session_id,
        &bytes[trailer_offset..trailer_offset + 96],
        &trailer.trailer_hmac,
    )
    .unwrap();

    let manifest_offset = trailer.manifest_footer_offset as usize;
    let manifest_end = manifest_offset + MANIFEST_FOOTER_LEN;
    let manifest = ManifestFooter::parse(&bytes[manifest_offset..manifest_end]).unwrap();
    assert_eq!(manifest.is_authoritative, 1);
    assert_eq!(manifest.total_volumes, DEFAULT_STRIPE_WIDTH);
    verify_hmac(
        HmacDomain::ManifestFooter,
        &subkeys.mac_key,
        &archive.archive_uuid,
        &archive.session_id,
        &bytes[manifest_offset..manifest_offset + 104],
        &manifest.manifest_hmac,
    )
    .unwrap();
}

#[test]
fn parity_auto_scaling_matches_v45_examples() {
    let options = WriterOptions { fec_data_shards: 224, stripe_width: 8, volume_loss_tolerance: 1, bit_rot_buffer_pct: 5, ..WriterOptions::default() };

    assert_eq!(compute_parity(224, options).unwrap(), 48);
    assert_eq!(compute_parity(17, options).unwrap(), 5);
}

#[test]
fn parity_auto_scaling_rejects_non_convergent_budget() {
    let err = compute_parity(1, WriterOptions { stripe_width: 2, volume_loss_tolerance: 1, bit_rot_buffer_pct: 50, ..WriterOptions::default() }).unwrap_err();

    assert_eq!(err, FormatError::WriterUnsupported("parity calculation did not converge"));
}

#[test]
fn zero_parity_is_allowed_when_no_recovery_margin_is_requested() {
    let planned = plan_writer_options(WriterOptions {
        bit_rot_buffer_pct: 0,
        stripe_width: 1,
        volume_loss_tolerance: 0,
        fec_parity_shards: 0,
        index_fec_parity_shards: 0,
        index_root_fec_parity_shards: 0,
        ..WriterOptions::default()
    })
    .unwrap();

    assert_eq!(planned.fec_parity_shards, 0);
    assert_eq!(planned.index_fec_parity_shards, 0);
    assert_eq!(planned.index_root_fec_parity_shards, 0);
    assert_eq!(compute_parity(1, planned).unwrap(), 0);
}

#[test]
fn index_root_data_shard_maximum_obeys_v45_minimum() {
    let planned = plan_writer_options(WriterOptions { index_root_fec_data_shards: 1, ..WriterOptions::default() }).unwrap();

    assert_eq!(planned.index_root_fec_data_shards, MIN_INDEX_ROOT_FEC_DATA_SHARDS);
}

#[test]
fn metadata_class_planning_raises_index_root_class_above_default() {
    let options =
        plan_writer_options(WriterOptions { block_size: MIN_BLOCK_SIZE, index_root_fec_parity_shards: 0, bit_rot_buffer_pct: 0, ..WriterOptions::default() })
            .unwrap();
    let index_root_payload_len = payload_len_for_encrypted_data_blocks(64, options);

    let planned = plan_index_root_metadata_class(options, index_root_payload_len, None).unwrap();

    assert_eq!(planned.index_root.data_block_count, 64);
    assert_eq!(planned.options.index_root_fec_data_shards, 64);
    assert_eq!(
        planned.options.index_root_fec_parity_shards,
        compute_parity_u16(planned.options.index_root_fec_data_shards as u64, planned.options, "index_root_fec_parity_shards",).unwrap()
    );
}

#[test]
fn single_pass_writer_predeclares_metadata_class_before_payload_streaming() {
    let planned = plan_single_pass_writer_options(WriterOptions {
        block_size: MIN_BLOCK_SIZE,
        stripe_width: 1,
        volume_loss_tolerance: 0,
        bit_rot_buffer_pct: 0,
        index_root_fec_parity_shards: 0,
        ..WriterOptions::default()
    })
    .unwrap();

    assert!(planned.index_root_fec_data_shards > DEFAULT_INDEX_ROOT_FEC_DATA_SHARDS);
    let index_root_payload_len = payload_len_for_encrypted_data_blocks(u32::from(planned.index_root_fec_data_shards - 1), planned);
    let metadata_class = plan_index_root_metadata_class(planned, index_root_payload_len, None).unwrap();

    assert_eq!(metadata_class.options, planned);
}

#[test]
fn metadata_class_planning_rejects_oversized_index_root() {
    let options = single_volume_metadata_test_options();
    let index_root_payload_len = payload_len_for_encrypted_data_blocks(u16::MAX as u32 + 1, options);

    let err = plan_index_root_metadata_class(options, index_root_payload_len, None).unwrap_err();

    assert_eq!(err, FormatError::WriterUnsupported("IndexRoot too large"));
}

#[test]
fn metadata_class_planning_rejects_index_root_u32_encrypted_size_overflow() {
    let options = single_volume_metadata_test_options();
    let index_root_payload_len = u32::MAX as usize - options.aead_algo.tag_len() + 1;

    let err = plan_index_root_metadata_class(options, index_root_payload_len, None).unwrap_err();

    assert_eq!(err, FormatError::WriterUnsupported("IndexRoot too large"));
}

#[test]
fn metadata_class_planning_rejects_oversized_dictionary() {
    let options = single_volume_metadata_test_options();
    let dictionary_payload_len = payload_len_for_encrypted_data_blocks(u16::MAX as u32 + 1, options);

    let err = plan_index_root_metadata_class(options, 1, Some(dictionary_payload_len)).unwrap_err();

    assert_eq!(err, FormatError::WriterUnsupported("dictionary object too large"));
}

#[test]
fn metadata_class_planning_rejects_gf16_total_overflow_for_dictionary() {
    let options = plan_writer_options(WriterOptions {
        block_size: MIN_BLOCK_SIZE,
        stripe_width: 8,
        volume_loss_tolerance: 1,
        bit_rot_buffer_pct: 5,
        ..WriterOptions::default()
    })
    .unwrap();
    let dictionary_payload_len = payload_len_for_encrypted_data_blocks(60_000, options);

    let err = plan_index_root_metadata_class(options, 1, Some(dictionary_payload_len)).unwrap_err();

    assert_eq!(err, FormatError::WriterUnsupported("dictionary object too large"));
}

#[test]
fn written_archive_authenticates_final_index_root_fec_class() {
    let master_key = MasterKey::from_raw_key(&[9u8; 32]).unwrap();
    let dictionary = deterministic_bytes(80 * 1024);
    let file = RegularFile::new("uses-dictionary.txt", b"payload");
    let archive = write_archive_with_dictionary(
        &[file],
        &master_key,
        WriterOptions {
            block_size: MIN_BLOCK_SIZE,
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            index_root_fec_parity_shards: 0,
            ..WriterOptions::default()
        },
        &dictionary,
    )
    .unwrap();

    let volume_header = VolumeHeader::parse(&archive.bytes[..VOLUME_HEADER_LEN]).unwrap();
    let crypto_start = VOLUME_HEADER_LEN;
    let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
    let crypto_header = CryptoHeader::parse(&archive.bytes[crypto_start..crypto_end], volume_header.crypto_header_length).unwrap();
    let subkeys = Subkeys::derive(&master_key, &archive.archive_uuid, &archive.session_id).unwrap();
    verify_hmac(
        HmacDomain::CryptoHeader,
        &subkeys.mac_key,
        &archive.archive_uuid,
        &archive.session_id,
        crypto_header.hmac_covered_bytes,
        &crypto_header.header_hmac,
    )
    .unwrap();

    assert!(crypto_header.fixed.index_root_fec_data_shards > MIN_INDEX_ROOT_FEC_DATA_SHARDS);
    assert_eq!(crypto_header.fixed.index_root_fec_parity_shards, 0);
    let opened = open_archive(&archive.bytes, &master_key).unwrap();
    assert_eq!(opened.extract_file("uses-dictionary.txt").unwrap(), Some(b"payload".to_vec()));
    opened.verify().unwrap();
}

#[test]
fn object_parity_uses_per_object_recurrence_even_with_larger_class_max() {
    let options = WriterOptions { bit_rot_buffer_pct: 0, stripe_width: 1, volume_loss_tolerance: 0, fec_parity_shards: 1, ..WriterOptions::default() };

    assert_eq!(compute_object_parity(1, options, 1).unwrap(), 0);
}

#[test]
fn object_total_shards_obeys_reed_solomon_limit() {
    assert!(validate_object_shard_total(65_535, 0).is_ok());
    assert_eq!(validate_object_shard_total(65_535, 1).unwrap_err(), FormatError::WriterUnsupported("encrypted object exceeds ReedSolomonGF16 shard limit"));
}

#[test]
fn argon2id_kdf_serialization_rejects_memory_requirement_overflow() {
    assert_eq!(
        serialize_kdf_params(&KdfParams::Argon2id { t_cost: 1, m_cost_kib: u32::MAX, parallelism: u32::MAX, salt: b"12345678".to_vec() }).unwrap_err(),
        FormatError::InvalidKdfParams("m_cost_kib requirement overflow")
    );
}

#[test]
fn recipient_wrap_kdf_serialization() {
    let params =
        KdfParams::RecipientWrap { key_wrap_table_length: 16, key_wrap_table_record_count: 4, key_wrap_table_version: 1, key_wrap_table_digest: [0xaau8; 32] };
    let serialized = serialize_kdf_params(&params).unwrap();
    let mut expected = Vec::new();
    expected.extend_from_slice(&(KdfAlgo::RecipientWrap as u16).to_le_bytes());
    expected.extend_from_slice(&16u32.to_le_bytes());
    expected.extend_from_slice(&4u32.to_le_bytes());
    expected.extend_from_slice(&1u16.to_le_bytes());
    expected.extend_from_slice(&0u16.to_le_bytes());
    expected.extend_from_slice(&[0xaau8; 32]);
    assert_eq!(serialized, expected);
}

fn recipient_wrap_test_record() -> RecipientRecordV1 {
    RecipientRecordV1 {
        record_length: 0,
        profile_id: 1,
        recipient_identity_type: 2,
        flags: 0,
        recipient_identity_length: 0,
        profile_payload_length: 0,
        recipient_identity_digest: [0u8; 32],
        recipient_identity_bytes: b"recipient-a".to_vec(),
        profile_payload_bytes: b"profile-payload".to_vec(),
    }
}

#[test]
fn writer_options_reject_reader_resource_cap_excesses() {
    assert_eq!(
        plan_writer_options(WriterOptions { stripe_width: crate::format::READER_MAX_STRIPE_WIDTH + 1, volume_loss_tolerance: 0, ..WriterOptions::default() })
            .unwrap_err(),
        FormatError::ReaderResourceLimitExceeded {
            field: "stripe_width",
            cap: crate::format::READER_MAX_STRIPE_WIDTH as u64,
            actual: crate::format::READER_MAX_STRIPE_WIDTH as u64 + 1,
        }
    );
    assert_eq!(
        plan_writer_options(WriterOptions { block_size: crate::format::READER_MAX_BLOCK_SIZE + 2, ..WriterOptions::default() }).unwrap_err(),
        FormatError::ReaderResourceLimitExceeded {
            field: "block_size",
            cap: crate::format::READER_MAX_BLOCK_SIZE as u64,
            actual: crate::format::READER_MAX_BLOCK_SIZE as u64 + 2,
        }
    );
    assert_eq!(
        plan_writer_options(WriterOptions {
            chunk_size: crate::format::READER_MAX_CHUNK_SIZE + 1,
            envelope_target_size: crate::format::READER_MAX_CHUNK_SIZE + 1,
            ..WriterOptions::default()
        })
        .unwrap_err(),
        FormatError::ReaderResourceLimitExceeded {
            field: "chunk_size",
            cap: crate::format::READER_MAX_CHUNK_SIZE as u64,
            actual: crate::format::READER_MAX_CHUNK_SIZE as u64 + 1,
        }
    );
    assert_eq!(
        plan_writer_options(WriterOptions { max_path_length: crate::format::READER_MAX_PATH_LENGTH + 1, ..WriterOptions::default() }).unwrap_err(),
        FormatError::ReaderResourceLimitExceeded {
            field: "max_path_length",
            cap: crate::format::READER_MAX_PATH_LENGTH as u64,
            actual: crate::format::READER_MAX_PATH_LENGTH as u64 + 1,
        }
    );
    assert_eq!(
        plan_writer_options(WriterOptions {
            bit_rot_buffer_pct: 0,
            stripe_width: 1,
            volume_loss_tolerance: 0,
            fec_data_shards: crate::format::READER_MAX_FEC_CLASS_SHARDS as u16 + 1,
            ..WriterOptions::default()
        })
        .unwrap_err(),
        FormatError::ReaderResourceLimitExceeded {
            field: "fec_data_shards + fec_parity_shards",
            cap: crate::format::READER_MAX_FEC_CLASS_SHARDS as u64,
            actual: crate::format::READER_MAX_FEC_CLASS_SHARDS as u64 + 1,
        }
    );
}

#[test]
fn root_auth_writer_config_rejects_reader_cap_excess_before_authenticator() {
    let master_key = MasterKey::from_raw_key(&[7u8; 32]).unwrap();
    let mut authenticator_called = false;
    let err = write_archive_with_root_auth(
        &[RegularFile::new("signed.txt", b"payload")],
        &master_key,
        single_volume_metadata_test_options(),
        RootAuthWriterConfig {
            authenticator_id: 1,
            signer_identity_type: 1,
            signer_identity: b"signer",
            authenticator_value_length: READER_MAX_ROOT_AUTH_AUTHENTICATOR_VALUE_LEN + 1,
        },
        |_| {
            authenticator_called = true;
            Ok(Vec::new())
        },
    )
    .unwrap_err();

    assert!(!authenticator_called);
    assert_eq!(
        err,
        FormatError::ReaderResourceLimitExceeded {
            field: "RootAuthFooterV1 authenticator value length",
            cap: READER_MAX_ROOT_AUTH_AUTHENTICATOR_VALUE_LEN as u64,
            actual: READER_MAX_ROOT_AUTH_AUTHENTICATOR_VALUE_LEN as u64 + 1,
        }
    );
}

#[test]
fn root_auth_writer_accepts_128_kib_authenticator_value() {
    let master_key = MasterKey::from_raw_key(&[8u8; 32]).unwrap();
    let authenticator_value = vec![0x5a; READER_MAX_ROOT_AUTH_AUTHENTICATOR_VALUE_LEN as usize];
    let expected_value = authenticator_value.clone();
    let archive = write_archive_with_root_auth(
        &[RegularFile::new("signed.txt", b"payload")],
        &master_key,
        single_volume_metadata_test_options(),
        RootAuthWriterConfig {
            authenticator_id: 0xcafe,
            signer_identity_type: 1,
            signer_identity: b"certificate-profile-signer",
            authenticator_value_length: READER_MAX_ROOT_AUTH_AUTHENTICATOR_VALUE_LEN,
        },
        |_| Ok(authenticator_value.clone()),
    )
    .unwrap();

    let opened = open_archive(&archive.bytes, &master_key).unwrap();
    let footer = opened.root_auth_footer.as_ref().unwrap();
    assert_eq!(footer.authenticator_id, 0xcafe);
    assert_eq!(footer.authenticator_value.as_slice(), expected_value.as_slice());

    let verification = opened
        .verify_root_auth_with(|footer, _| Ok(footer.authenticator_id == 0xcafe && footer.authenticator_value.as_slice() == expected_value.as_slice()))
        .unwrap();
    assert_eq!(verification.authenticator_id, 0xcafe);
}

#[test]
fn streaming_writer_sink_round_trips_archive() {
    let files = [RegularFile::new("alpha.txt", b"alpha"), RegularFile::new("nested/beta.txt", b"beta payload")];
    let master_key = MasterKey::from_raw_key(&[7u8; 32]).unwrap();
    let mut sink = MemoryArchiveSink::default();

    let summary =
        write_archive_sources_to_sink(&files, &master_key, single_volume_metadata_test_options(), None, &KdfParams::Raw, None, None, &mut sink).unwrap();

    assert_eq!(summary.volume_count, 1);
    let opened = crate::reader::open_archive(&sink.volumes[0], &master_key).unwrap();
    assert_eq!(opened.extract_file("nested/beta.txt").unwrap(), Some(b"beta payload".to_vec()));
}

#[test]
fn ordered_sink_writer_round_trips_recipientwrap_records() {
    let files = [RegularFile::new("wrapped.txt", b"recipient sink payload")];
    let master_key = MasterKey::from_raw_key(&[9u8; 32]).unwrap();
    let mut sink = MemoryArchiveSink::default();

    let summary = write_archive_sources_to_sink_ordered_parallel_with_recipient_wrap_records(
        &files,
        &master_key,
        single_volume_metadata_test_options(),
        vec![recipient_wrap_test_record()],
        None,
        None,
        &mut sink,
    )
    .unwrap();

    assert_eq!(summary.volume_count, 1);
    let opened = open_archive_with_recipient_wrap_resolver(&sink.volumes[0], |_| Ok(vec![master_key.0])).unwrap();
    assert_eq!(opened.extract_file("wrapped.txt").unwrap(), Some(b"recipient sink payload".to_vec()));
}

#[test]
fn ordered_sink_writer_indexes_v45_metadata_flags_from_member_semantics() {
    let mut sparse_payload = vec![0u8; TAR_BLOCK_LEN];
    sparse_payload[..2].copy_from_slice(b"0\n");
    let mut sparse_fork = NativeAuxiliaryMetadata::new("macos.resource-fork", "macos-backup-v1", RestoreClass::SameOs, sparse_payload);
    sparse_fork.flags = 1;
    sparse_fork.logical_size = 4096;

    let sparse_metadata = PortableFileMetadata {
        source_os: "macos".into(),
        native: NativeFileMetadata {
            required_profiles: vec!["macos-backup-v1".into(), "posix-backup-v1".into()],
            auxiliary_records: vec![sparse_fork],
            ..NativeFileMetadata::default()
        },
        ..PortableFileMetadata::default()
    };
    let portable_only_metadata = PortableFileMetadata {
        native: NativeFileMetadata { required_profiles: vec![PORTABLE_PROFILE.into()], ..NativeFileMetadata::default() },
        ..PortableFileMetadata::default()
    };
    let files = [
        RegularFile { path: "sparse-fork.bin", contents: b"primary", mode: 0o644, mtime: ArchiveTimestamp::UNIX_EPOCH, portable_metadata: sparse_metadata },
        RegularFile {
            path: "portable-only.bin",
            contents: b"portable",
            mode: 0o644,
            mtime: ArchiveTimestamp::UNIX_EPOCH,
            portable_metadata: portable_only_metadata,
        },
    ];
    let master_key = MasterKey::from_raw_key(&[0x45; 32]).unwrap();
    let mut sink = MemoryArchiveSink::default();

    write_archive_sources_to_sink_ordered_parallel(&files, &master_key, single_volume_metadata_test_options(), &KdfParams::Raw, None, None, &mut sink).unwrap();

    let opened = open_archive(&sink.volumes[0], &master_key).unwrap();
    opened.verify().unwrap();
    let entries = opened.list_index_entries().unwrap();
    let sparse = entries.iter().find(|entry| entry.path == "sparse-fork.bin").unwrap();
    assert_ne!(sparse.flags & HAS_SPARSE_EXTENTS, 0);
    let portable_only = entries.iter().find(|entry| entry.path == "portable-only.bin").unwrap();
    assert_eq!(portable_only.flags & HAS_NATIVE_METADATA, 0);
}

#[test]
fn single_pass_sink_writer_round_trips_recipientwrap_records() {
    let files = [RegularFile::new("wrapped.txt", b"recipient single-pass sink payload")];
    let master_key = MasterKey::from_raw_key(&[9u8; 32]).unwrap();
    let mut sink = MemoryArchiveSink::default();

    let summary = write_archive_sources_to_sink_single_pass_with_recipient_wrap_records(
        &files,
        &master_key,
        single_volume_metadata_test_options(),
        vec![recipient_wrap_test_record()],
        None,
        None,
        &mut sink,
    )
    .unwrap();

    assert_eq!(summary.volume_count, 1);
    let opened = open_archive_with_recipient_wrap_resolver(&sink.volumes[0], |_| Ok(vec![master_key.0])).unwrap();
    assert_eq!(opened.extract_file("wrapped.txt").unwrap(), Some(b"recipient single-pass sink payload".to_vec()));
    opened.verify().unwrap();
}

#[test]
fn single_pass_sink_writer_round_trips_recipientwrap_root_auth() {
    let files = [RegularFile::new("wrapped.txt", b"recipient single-pass signed payload")];
    let master_key = MasterKey::from_raw_key(&[9u8; 32]).unwrap();
    let mut sink = MemoryArchiveSink::default();

    let summary = write_archive_sources_to_sink_single_pass_with_recipient_wrap_records(
        &files,
        &master_key,
        single_volume_metadata_test_options(),
        vec![recipient_wrap_test_record()],
        Some(RootAuthWriterConfig {
            authenticator_id: 0x44,
            signer_identity_type: 1,
            signer_identity: b"recipient-wrap-single-pass",
            authenticator_value_length: 32,
        }),
        Some(&mut |request| Ok(request.archive_root.to_vec())),
        &mut sink,
    )
    .unwrap();

    assert_eq!(summary.volume_count, 1);
    let opened = open_archive_with_recipient_wrap_resolver(&sink.volumes[0], |_| Ok(vec![master_key.0])).unwrap();
    let verification = opened
        .verify_root_auth_with(|footer, archive_root| Ok(footer.authenticator_id == 0x44 && footer.authenticator_value.as_slice() == archive_root))
        .unwrap();
    assert_eq!(verification.volume_format_rev, VOLUME_FORMAT_REV_45);
}

#[test]
fn single_pass_writer_rejects_recipientwrap_kdf_without_records_before_writing() {
    let files = [RegularFile::new("wrapped.txt", b"recipient sink payload")];
    let master_key = MasterKey::from_raw_key(&[9u8; 32]).unwrap();
    let mut sink = MemoryArchiveSink::default();
    let kdf_params =
        KdfParams::RecipientWrap { key_wrap_table_length: 0, key_wrap_table_record_count: 1, key_wrap_table_version: 1, key_wrap_table_digest: [0u8; 32] };

    let err =
        write_archive_sources_to_sink_single_pass(&files, &master_key, single_volume_metadata_test_options(), &kdf_params, None, None, &mut sink).unwrap_err();

    match err {
        ArchiveWriteError::Format(FormatError::WriterUnsupported(message)) => {
            assert_eq!(message, "RecipientWrap requires key-wrap records");
        }
        other => panic!("unexpected error: {other:?}"),
    }
    assert!(sink.volumes.is_empty());
}

#[test]
fn ordered_sink_writer_rejects_recipientwrap_kdf_without_records_before_writing() {
    let files = [RegularFile::new("wrapped.txt", b"recipient sink payload")];
    let master_key = MasterKey::from_raw_key(&[9u8; 32]).unwrap();
    let mut sink = MemoryArchiveSink::default();
    let kdf_params =
        KdfParams::RecipientWrap { key_wrap_table_length: 0, key_wrap_table_record_count: 1, key_wrap_table_version: 1, key_wrap_table_digest: [0u8; 32] };

    let err = write_archive_sources_to_sink_ordered_parallel(&files, &master_key, single_volume_metadata_test_options(), &kdf_params, None, None, &mut sink)
        .unwrap_err();

    match err {
        ArchiveWriteError::Format(FormatError::WriterUnsupported(message)) => {
            assert_eq!(message, "RecipientWrap requires key-wrap records");
        }
        other => panic!("unexpected error: {other:?}"),
    }
    assert!(sink.volumes.is_empty());
}

#[test]
fn streaming_writer_bounds_source_reads_and_sink_writes_for_large_file() {
    let file_size = 3 * 1024 * 1024;
    let stats = Rc::new(RefCell::new(GeneratedSourceStats::default()));
    let file = GeneratedFileSource { path: "large/generated.bin", len: file_size, stats: Rc::clone(&stats) };
    let master_key = MasterKey::from_raw_key(&[3u8; 32]).unwrap();
    let options = plan_writer_options(WriterOptions {
        block_size: MIN_BLOCK_SIZE,
        chunk_size: 16 * 1024,
        envelope_target_size: 64 * 1024,
        stripe_width: 1,
        volume_loss_tolerance: 0,
        bit_rot_buffer_pct: 0,
        fec_parity_shards: 0,
        index_fec_parity_shards: 0,
        index_root_fec_parity_shards: 0,
        ..WriterOptions::default()
    })
    .unwrap();
    let mut sink = TrackingArchiveSink::default();

    let summary = write_archive_sources_to_sink_single_pass(&[file], &master_key, options, &KdfParams::Raw, None, None, &mut sink).unwrap();

    let stats = stats.borrow();
    assert_eq!(stats.open_count, 1);
    assert_eq!(stats.total_read, file_size as u64);
    assert!(stats.max_read_request <= options.chunk_size as usize);
    assert_eq!(summary.volume_count, 1);
    assert_eq!(summary.archive_bytes, sink.volume_bytes.iter().sum());
    assert_eq!(summary.bootstrap_sidecar_bytes, sink.bootstrap_sidecar_bytes);
    assert!(sink.max_write_len <= 128 * 1024);
}

#[test]
fn sink_writer_progress_reports_source_bytes_for_each_multi_pass_phase() {
    let file_size = 512 * 1024;
    let stats = Rc::new(RefCell::new(GeneratedSourceStats::default()));
    let file = GeneratedFileSource { path: "large/generated.bin", len: file_size, stats: Rc::clone(&stats) };
    let master_key = MasterKey::from_raw_key(&[4u8; 32]).unwrap();
    let options = WriterOptions {
        block_size: MIN_BLOCK_SIZE,
        chunk_size: 16 * 1024,
        envelope_target_size: 64 * 1024,
        stripe_width: 1,
        volume_loss_tolerance: 0,
        bit_rot_buffer_pct: 0,
        fec_parity_shards: 0,
        index_fec_parity_shards: 0,
        index_root_fec_parity_shards: 0,
        ..WriterOptions::default()
    };
    let mut sink = MemoryArchiveSink::default();
    let mut progress = RecordingWriteProgress::default();

    let summary =
        write_archive_sources_to_sink_with_progress(&[file], &master_key, options, None, &KdfParams::Raw, None, None, &mut sink, &mut progress).unwrap();

    let stats = stats.borrow();
    assert!(stats.open_count > 1);
    assert_eq!(progress.bytes_for(ArchiveWritePhase::PlanningPayload), file_size as u64);
    assert_eq!(progress.bytes_for(ArchiveWritePhase::EmittingPayload), file_size as u64);
    assert_eq!(summary.volume_count, 1);
    assert!(!sink.volumes.is_empty());
}

#[test]
fn sink_writer_progress_reports_multi_pass_phases_and_phase_bytes() {
    let file_size = 512 * 1024;
    let stats = Rc::new(RefCell::new(GeneratedSourceStats::default()));
    let file = GeneratedFileSource { path: "large/generated.bin", len: file_size, stats: Rc::clone(&stats) };
    let master_key = MasterKey::from_raw_key(&[4u8; 32]).unwrap();
    let options = WriterOptions {
        block_size: MIN_BLOCK_SIZE,
        chunk_size: 16 * 1024,
        envelope_target_size: 64 * 1024,
        stripe_width: 1,
        volume_loss_tolerance: 0,
        bit_rot_buffer_pct: 0,
        fec_parity_shards: 0,
        index_fec_parity_shards: 0,
        index_root_fec_parity_shards: 0,
        ..WriterOptions::default()
    };
    let mut sink = MemoryArchiveSink::default();
    let mut progress = RecordingWriteProgress::default();

    write_archive_sources_to_sink_with_progress(&[file], &master_key, options, None, &KdfParams::Raw, None, None, &mut sink, &mut progress).unwrap();

    assert_eq!(
        progress.phases,
        vec![ArchiveWritePhase::PlanningPayload, ArchiveWritePhase::PlanningMetadata, ArchiveWritePhase::EmittingPayload, ArchiveWritePhase::EmittingMetadata,]
    );
    assert_eq!(progress.bytes_for(ArchiveWritePhase::PlanningPayload), file_size as u64);
    assert_eq!(progress.bytes_for(ArchiveWritePhase::EmittingPayload), file_size as u64);
}

#[test]
fn sink_writer_progress_reports_each_volume_size_replanning_attempt() {
    let file_size = 64 * 1024;
    let mut contents = Vec::with_capacity(file_size);
    let mut random = 0x1234_5678u32;
    for _ in 0..file_size {
        random = random.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        contents.push((random >> 24) as u8);
    }
    let file = RegularFile::new("sized.bin", &contents);
    let master_key = MasterKey::from_raw_key(&[9u8; 32]).unwrap();
    let options = WriterOptions {
        block_size: 4 * 1024,
        chunk_size: 4 * 1024,
        envelope_target_size: 128 * 1024,
        stripe_width: 1,
        volume_loss_tolerance: 1,
        target_volume_size: Some(8 * 1024),
        ..WriterOptions::default()
    };
    let mut sink = MemoryArchiveSink::default();
    let mut progress = RecordingWriteProgress::default();

    write_archive_sources_to_sink_with_progress(&[file], &master_key, options, None, &KdfParams::Raw, None, None, &mut sink, &mut progress).unwrap();

    let planning_attempts = progress.phases.iter().filter(|phase| **phase == ArchiveWritePhase::PlanningPayload).count();
    assert!(planning_attempts > 1);
    assert_eq!(progress.phases.len(), planning_attempts * 2 + 2, "each planning attempt has payload and metadata phases before emission",);
    for phases in progress.phases[..planning_attempts * 2].chunks_exact(2) {
        assert_eq!(phases, [ArchiveWritePhase::PlanningPayload, ArchiveWritePhase::PlanningMetadata,]);
    }
    assert_eq!(&progress.phases[planning_attempts * 2..], [ArchiveWritePhase::EmittingPayload, ArchiveWritePhase::EmittingMetadata,]);
    assert_eq!(progress.bytes_for(ArchiveWritePhase::PlanningPayload), file_size as u64 * planning_attempts as u64,);
    assert_eq!(progress.bytes_for(ArchiveWritePhase::EmittingPayload), file_size as u64,);
}

#[test]
fn single_pass_progress_reports_emission_phases() {
    let file_size = 128 * 1024;
    let stats = Rc::new(RefCell::new(GeneratedSourceStats::default()));
    let file = GeneratedFileSource { path: "single/generated.bin", len: file_size, stats };
    let master_key = MasterKey::from_raw_key(&[5u8; 32]).unwrap();
    let options = progress_test_writer_options();
    let mut sink = MemoryArchiveSink::default();
    let mut progress = RecordingWriteProgress::default();

    write_archive_sources_to_sink_single_pass_with_progress(&[file], &master_key, options, &KdfParams::Raw, None, None, &mut sink, &mut progress).unwrap();

    assert_eq!(progress.phases, vec![ArchiveWritePhase::EmittingPayload, ArchiveWritePhase::EmittingMetadata,]);
    assert_eq!(progress.bytes_for(ArchiveWritePhase::EmittingPayload), file_size as u64);
}

#[test]
fn ordered_parallel_progress_reports_emission_phases() {
    let file_size = 128 * 1024;
    let stats = Rc::new(RefCell::new(GeneratedSourceStats::default()));
    let file = GeneratedFileSource { path: "parallel/generated.bin", len: file_size, stats };
    let master_key = MasterKey::from_raw_key(&[6u8; 32]).unwrap();
    let options = progress_test_writer_options();
    let mut sink = MemoryArchiveSink::default();
    let mut progress = RecordingWriteProgress::default();

    write_archive_sources_to_sink_ordered_parallel_with_progress(&[file], &master_key, options, &KdfParams::Raw, None, None, &mut sink, &mut progress).unwrap();

    assert_eq!(progress.phases, vec![ArchiveWritePhase::EmittingPayload, ArchiveWritePhase::EmittingMetadata,]);
    assert_eq!(progress.bytes_for(ArchiveWritePhase::EmittingPayload), file_size as u64);
}

fn progress_test_writer_options() -> WriterOptions {
    WriterOptions {
        block_size: MIN_BLOCK_SIZE,
        chunk_size: 16 * 1024,
        envelope_target_size: 64 * 1024,
        stripe_width: 1,
        volume_loss_tolerance: 0,
        bit_rot_buffer_pct: 0,
        fec_parity_shards: 0,
        index_fec_parity_shards: 0,
        index_root_fec_parity_shards: 0,
        ..WriterOptions::default()
    }
}

#[derive(Default)]
struct RecordingWriteProgress {
    phases: Vec<ArchiveWritePhase>,
    phase_bytes: BTreeMap<ArchiveWritePhase, u64>,
}

impl RecordingWriteProgress {
    fn bytes_for(&self, phase: ArchiveWritePhase) -> u64 {
        self.phase_bytes.get(&phase).copied().unwrap_or_default()
    }
}

impl ArchiveWriteProgressSink for RecordingWriteProgress {
    fn phase_started(&mut self, phase: ArchiveWritePhase) {
        self.phases.push(phase);
    }

    fn source_bytes_read(&mut self, phase: ArchiveWritePhase, _archive_path: &str, bytes: u64) {
        let total = self.phase_bytes.entry(phase).or_default();
        *total = total.saturating_add(bytes);
    }
}

#[derive(Default)]
struct GeneratedSourceStats {
    open_count: usize,
    total_read: u64,
    max_read_request: usize,
}

struct GeneratedFileSource {
    path: &'static str,
    len: usize,
    stats: Rc<RefCell<GeneratedSourceStats>>,
}

impl RegularFileSource for GeneratedFileSource {
    fn archive_path(&self) -> &str {
        self.path
    }

    fn file_data_size(&self) -> u64 {
        self.len as u64
    }

    fn mode(&self) -> u32 {
        0o644
    }

    fn mtime(&self) -> ArchiveTimestamp {
        ArchiveTimestamp::UNIX_EPOCH
    }

    fn open(&self) -> Result<Box<dyn Read + '_>, ArchiveWriteError> {
        self.stats.borrow_mut().open_count += 1;
        Ok(Box::new(GeneratedReader { remaining: self.len, position: 0, stats: Rc::clone(&self.stats) }))
    }
}

struct GeneratedReader {
    remaining: usize,
    position: usize,
    stats: Rc<RefCell<GeneratedSourceStats>>,
}

impl Read for GeneratedReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }
        let count = out.len().min(self.remaining);
        for (offset, byte) in out[..count].iter_mut().enumerate() {
            let position = self.position + offset;
            *byte = position.wrapping_mul(31).wrapping_add(17) as u8;
        }
        self.position += count;
        self.remaining -= count;
        let mut stats = self.stats.borrow_mut();
        stats.total_read += count as u64;
        stats.max_read_request = stats.max_read_request.max(out.len());
        Ok(count)
    }
}

#[derive(Default)]
struct TrackingArchiveSink {
    volume_bytes: Vec<u64>,
    bootstrap_sidecar_bytes: u64,
    max_write_len: usize,
}

impl ArchiveWriteSink for TrackingArchiveSink {
    fn begin_archive(&mut self, volume_count: usize) -> Result<(), ArchiveWriteError> {
        self.volume_bytes = vec![0; volume_count];
        self.bootstrap_sidecar_bytes = 0;
        self.max_write_len = 0;
        Ok(())
    }

    fn write_volume(&mut self, volume_index: usize, bytes: &[u8]) -> Result<(), ArchiveWriteError> {
        let volume = self.volume_bytes.get_mut(volume_index).ok_or(FormatError::WriterInvariant("tracking sink volume index is out of bounds"))?;
        *volume += bytes.len() as u64;
        self.max_write_len = self.max_write_len.max(bytes.len());
        Ok(())
    }

    fn write_bootstrap_sidecar(&mut self, bytes: &[u8]) -> Result<(), ArchiveWriteError> {
        self.bootstrap_sidecar_bytes += bytes.len() as u64;
        self.max_write_len = self.max_write_len.max(bytes.len());
        Ok(())
    }
}

fn deterministic_bytes(len: usize) -> Vec<u8> {
    let mut state = 0x4d41_4d45u32;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        out.push((state >> 24) as u8);
    }
    out
}

fn single_volume_metadata_test_options() -> WriterOptions {
    plan_writer_options(WriterOptions {
        block_size: MIN_BLOCK_SIZE,
        stripe_width: 1,
        volume_loss_tolerance: 0,
        bit_rot_buffer_pct: 0,
        index_root_fec_parity_shards: 0,
        ..WriterOptions::default()
    })
    .unwrap()
}

fn payload_len_for_encrypted_data_blocks(data_block_count: u32, options: WriterOptions) -> usize {
    assert!(data_block_count > 0);
    if data_block_count == 1 {
        return 1;
    }
    let block_size = options.block_size as usize;
    (data_block_count as usize - 1) * block_size - options.aead_algo.tag_len() + 1
}

fn assert_path_specific_member_group(group: &[u8]) {
    let mut cursor = 0usize;
    let mut saw_main = false;
    while cursor < group.len() {
        let header = &group[cursor..cursor + TAR_BLOCK_LEN];
        assert!(header.iter().any(|byte| *byte != 0), "writer emitted tar zero block inside member group");
        let typeflag = header[156];
        assert_ne!(typeflag, b'g', "writer emitted global PAX metadata");
        assert!(!matches!(typeflag, b'V' | b'M' | b'N'), "writer emitted global GNU metadata");
        assert!(matches!(typeflag, b'x' | b'0'), "writer emitted unexpected tar record type {typeflag:?}");
        if typeflag == b'0' {
            saw_main = true;
        }
        let size = read_test_tar_octal(&header[124..136]);
        cursor += TAR_BLOCK_LEN + size + padding_to_512(size);
    }
    assert_eq!(cursor, group.len());
    assert!(saw_main);
}

fn read_test_tar_octal(field: &[u8]) -> usize {
    let mut value = 0usize;
    for byte in field {
        match *byte {
            0 | b' ' => break,
            b'0'..=b'7' => {
                value = value * 8 + usize::from(*byte - b'0');
            }
            other => panic!("malformed test tar octal byte {other:?}"),
        }
    }
    value
}

fn test_file_row(idx: usize, path_hash: [u8; 8]) -> FileRow {
    let path = format!("file-{idx:05}.txt").into_bytes();
    FileRow {
        path_hash,
        path: path.clone(),
        member_index: idx,
        member: TarMember {
            path,
            entry_kind: SourceEntryKind::Regular,
            link_target: None,
            tar_member_group_start: idx as u64 * 512,
            tar_member_group_size: 512,
            file_data_size: 0,
            sparse_extents: None,
            mode: 0o644,
            mtime: ArchiveTimestamp::UNIX_EPOCH,
            portable_metadata: PortableFileMetadata::default(),
        },
    }
}

#[test]
fn crypto_header_extension_area_emits_only_terminator() {
    // F10: the writer must never emit extension TLVs; the extension area is
    // exactly the 6-byte terminator (tag 0x0000, length 0x00000000).
    let options = plan_writer_options(WriterOptions {
        aead_algo: AeadAlgo::None,
        block_size: MIN_BLOCK_SIZE,
        stripe_width: 1,
        volume_loss_tolerance: 0,
        bit_rot_buffer_pct: 0,
        index_root_fec_parity_shards: 0,
        ..WriterOptions::default()
    })
    .unwrap();
    let subkeys = Subkeys::unencrypted_placeholder();
    let archive_uuid = [1u8; 16];
    let session_id = [2u8; 16];
    let volume_format_rev = volume_format_revision_for_options(&options, &KdfParams::None);
    let header = build_crypto_header(options, volume_format_rev, false, &subkeys, &archive_uuid, &session_id, &KdfParams::None).unwrap();

    let kdf_payload = serialize_kdf_params(&KdfParams::None).unwrap();
    let extension_start = CRYPTO_HEADER_FIXED_LEN + kdf_payload.len();
    let extension = &header[extension_start..extension_start + CRYPTO_EXTENSION_HEADER_LEN];
    assert_eq!(extension, &[0u8; CRYPTO_EXTENSION_HEADER_LEN]);
    assert_eq!(header.len(), extension_start + CRYPTO_EXTENSION_HEADER_LEN + CRYPTO_HEADER_HMAC_LEN);

    let extensions = scan_crypto_extension_tlvs(extension).unwrap();
    assert!(extensions.is_empty());
}

#[test]
fn writer_rejects_loss_tolerance_at_or_above_stripe_width() {
    // F10: N >= V must be rejected at option-planning time.
    for stripe_width in [2u32, 8] {
        for volume_loss_tolerance in [stripe_width as u8, stripe_width as u8 + 1] {
            let err =
                plan_writer_options(WriterOptions { block_size: MIN_BLOCK_SIZE, stripe_width, volume_loss_tolerance, ..WriterOptions::default() }).unwrap_err();
            assert!(
                matches!(err, FormatError::WriterUnsupported(message) if message == "volume_loss_tolerance must be less than stripe_width"),
                "expected rejection for stripe_width={stripe_width} volume_loss_tolerance={volume_loss_tolerance}"
            );
        }
    }
}

#[test]
fn seekable_dictionary_extent_requires_non_zero_extent_fields() {
    // F10: core-side pin of the seekable dictionary-extent error message; the
    // CLI verify path already pins the same message.
    let index_root = IndexRoot {
        header: IndexRootHeader {
            version: 1,
            shard_count: 1,
            directory_hint_shard_count: 0,
            frame_count: 0,
            envelope_count: 0,
            file_count: 0,
            payload_block_count: 0,
            tar_total_size: 0,
            content_sha256: [0u8; 32],
            shard_table_offset: 0,
            directory_hint_shard_table_offset: 0,
            dictionary_first_block: 0,
            dictionary_data_block_count: 0,
            dictionary_parity_block_count: 0,
            dictionary_encrypted_size: 0,
            dictionary_decompressed_size: 0,
        },
        shards: Vec::new(),
        directory_hint_shards: Vec::new(),
    };
    let err = crate::reader::validation::dictionary_extent_from_index_root(&index_root).unwrap_err();
    assert!(matches!(err, FormatError::InvalidArchive(message) if message == "dictionary extent missing from IndexRoot"));
}

#[test]
fn native_auxiliary_metadata_streamed_sparse_and_open_auxiliary() {
    use crate::entry_metadata::{RestoreClass, SparseExtent};
    use crate::writer::{NativeAuxiliaryMetadata, RegularFileSource};

    let extents = vec![SparseExtent { offset: 0, length: 100 }, SparseExtent { offset: 200, length: 300 }];
    let aux = NativeAuxiliaryMetadata::new_streamed_sparse("x.custom-streamed", "portable-v1", RestoreClass::Portable, 500, extents, [0x55; 32]).unwrap();

    assert!(aux.is_streamed());
    assert_eq!(aux.flags, 1);
    assert_eq!(aux.logical_size, 500);

    // Test open_auxiliary default method on RegularFileSource
    struct DummySourceWithAux {
        aux: NativeAuxiliaryMetadata,
    }
    impl RegularFileSource for DummySourceWithAux {
        fn archive_path(&self) -> &str {
            "dummy.txt"
        }
        fn file_data_size(&self) -> u64 {
            0
        }
        fn mode(&self) -> u32 {
            0o644
        }
        fn mtime(&self) -> ArchiveTimestamp {
            ArchiveTimestamp::UNIX_EPOCH
        }
        fn portable_metadata(&self) -> PortableFileMetadata {
            PortableFileMetadata {
                source_os: "linux".into(),
                source_filesystem: "ext4".into(),
                mode_origin: PortableModeOrigin::Projected,
                posix_owner: None,
                attributes: None,
                created: None,
                accessed: None,
                native: NativeFileMetadata {
                    required_profiles: vec!["portable-v1".into()],
                    optional_profiles: Vec::new(),
                    primary_pax_records: crate::entry_metadata::PaxRecords::new(),
                    auxiliary_records: vec![self.aux.clone()],
                },
            }
        }
        fn open(&self) -> Result<Box<dyn Read + '_>, ArchiveWriteError> {
            Ok(Box::new(std::io::Cursor::new(b"")))
        }
    }

    let source = DummySourceWithAux { aux };
    // Should fail with WriterUnsupported because streamed auxiliary didn't override open_auxiliary
    assert!(source.open_auxiliary(0).is_err());
    // Missing ordinal
    assert!(source.open_auxiliary(99).is_err());

    // Inline aux record should succeed
    let inline_aux = NativeAuxiliaryMetadata::new("generic.xattr", "posix-backup-v1", RestoreClass::SameOs, b"test value".to_vec());
    let inline_source = DummySourceWithAux { aux: inline_aux };
    let mut reader = inline_source.open_auxiliary(0).unwrap();
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"test value");
}

#[test]
fn writer_options_validation_edges() {
    let master = MasterKey::from_raw_key(&[1u8; 32]).unwrap();
    let files = [RegularFile::new("file.txt", b"data")];

    // Odd or < 4096 block size
    let mut bad_opt = WriterOptions { stripe_width: 1, volume_loss_tolerance: 0, ..WriterOptions::default() };
    bad_opt.block_size = 4095;
    assert!(write_archive(&files, &master, bad_opt).is_err());
    bad_opt.block_size = 2048;
    assert!(write_archive(&files, &master, bad_opt).is_err());

    // stripe_width = 0
    let mut bad_stripe = WriterOptions { stripe_width: 1, volume_loss_tolerance: 0, ..WriterOptions::default() };
    bad_stripe.stripe_width = 0;
    assert!(write_archive(&files, &master, bad_stripe).is_err());

    // bit_rot_buffer_pct > 100
    let mut bad_rot = WriterOptions { stripe_width: 1, volume_loss_tolerance: 0, ..WriterOptions::default() };
    bad_rot.bit_rot_buffer_pct = 101;
    assert!(write_archive(&files, &master, bad_rot).is_err());

    // chunk_size = 0 or chunk_size > envelope_target_size
    let mut bad_chunk = WriterOptions { stripe_width: 1, volume_loss_tolerance: 0, ..WriterOptions::default() };
    bad_chunk.chunk_size = 0;
    assert!(write_archive(&files, &master, bad_chunk).is_err());
    bad_chunk.chunk_size = bad_chunk.envelope_target_size + 1;
    assert!(write_archive(&files, &master, bad_chunk).is_err());

    // target_volume_size = Some(0)
    let mut bad_target = WriterOptions { stripe_width: 1, volume_loss_tolerance: 0, ..WriterOptions::default() };
    bad_target.target_volume_size = Some(0);
    assert!(write_archive(&files, &master, bad_target).is_err());
}
