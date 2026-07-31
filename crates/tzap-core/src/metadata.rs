use std::collections::{BTreeSet, HashMap, HashSet};

use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::entry_metadata::{EXTENDED_METADATA_V1, FILE_ENTRY_KNOWN_FLAGS};
use crate::format::FormatError;

const TZIR_MAGIC: [u8; 4] = *b"TZIR";
const TZIS_MAGIC: [u8; 4] = *b"TZIS";
const TZDH_MAGIC: [u8; 4] = *b"TZDH";

pub const INDEX_ROOT_LEN: usize = 160;
pub const SHARD_ENTRY_LEN: usize = 52;
pub const DIRECTORY_HINT_SHARD_ENTRY_LEN: usize = 56;
pub const ENVELOPE_ENTRY_LEN: usize = 48;
pub const FRAME_ENTRY_LEN: usize = 44;
pub const INDEX_SHARD_HEADER_LEN: usize = 64;
pub const FILE_ENTRY_LEN: usize = 144;
pub const DIRECTORY_HINT_TABLE_LEN: usize = 72;
pub const DIRECTORY_HINT_ENTRY_LEN: usize = 40;

const INDEX_SHARD_VERSION: u32 = 1;
const FRAME_KNOWN_FLAGS: u32 = 0x0000_0003;
const DEFAULT_MAX_HASH_COLLISION_SHARD_SCAN: usize = 16;
const REED_SOLOMON_GF16_MAX_TOTAL_SHARDS: u64 = 65_535;
const SHA256_EMPTY: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetadataLimits {
    pub block_size: u32,
    pub max_path_length: u32,
    pub max_hash_collision_shard_scan: usize,
    pub max_shard_count: u32,
    pub max_directory_hint_shards: u32,
    pub max_files_per_index_shard: u32,
    pub max_entries_per_directory_hint_shard: u64,
    pub max_payload_data_shards: u16,
    pub max_payload_parity_shards: u16,
    pub max_index_data_shards: u16,
    pub max_index_parity_shards: u16,
    pub max_index_root_data_shards: u16,
    pub max_index_root_parity_shards: u16,
}

impl Default for MetadataLimits {
    fn default() -> Self {
        Self {
            block_size: 4096,
            max_path_length: 4096,
            max_hash_collision_shard_scan: DEFAULT_MAX_HASH_COLLISION_SHARD_SCAN,
            max_shard_count: 1_000_000,
            max_directory_hint_shards: 1_000_000,
            max_files_per_index_shard: 1_000_000,
            max_entries_per_directory_hint_shard: 1_000_000,
            max_payload_data_shards: u16::MAX,
            max_payload_parity_shards: u16::MAX,
            max_index_data_shards: u16::MAX,
            max_index_parity_shards: u16::MAX,
            max_index_root_data_shards: u16::MAX,
            max_index_root_parity_shards: u16::MAX,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexRootHeader {
    pub version: u32,
    pub shard_count: u32,
    pub directory_hint_shard_count: u32,
    pub frame_count: u64,
    pub envelope_count: u64,
    pub file_count: u64,
    pub payload_block_count: u64,
    pub tar_total_size: u64,
    pub content_sha256: [u8; 32],
    pub shard_table_offset: u64,
    pub directory_hint_shard_table_offset: u64,
    pub dictionary_first_block: u64,
    pub dictionary_data_block_count: u32,
    pub dictionary_parity_block_count: u32,
    pub dictionary_encrypted_size: u32,
    pub dictionary_decompressed_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexRoot {
    pub header: IndexRootHeader,
    pub shards: Vec<ShardEntry>,
    pub directory_hint_shards: Vec<DirectoryHintShardEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardEntry {
    pub shard_index: u64,
    pub first_block_index: u64,
    pub data_block_count: u32,
    pub parity_block_count: u32,
    pub encrypted_size: u32,
    pub decompressed_size: u32,
    pub file_count: u32,
    pub first_path_hash: [u8; 8],
    pub last_path_hash: [u8; 8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryHintShardEntry {
    pub hint_shard_index: u64,
    pub first_dir_hash: [u8; 8],
    pub last_dir_hash: [u8; 8],
    pub first_block_index: u64,
    pub data_block_count: u32,
    pub parity_block_count: u32,
    pub encrypted_size: u32,
    pub decompressed_size: u32,
    pub entry_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeEntry {
    pub envelope_index: u64,
    pub first_block_index: u64,
    pub data_block_count: u32,
    pub parity_block_count: u32,
    pub encrypted_size: u32,
    pub plaintext_size: u32,
    pub first_frame_index: u64,
    pub frame_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameEntry {
    pub frame_index: u64,
    pub envelope_index: u64,
    pub offset_in_envelope: u32,
    pub compressed_size: u32,
    pub decompressed_size: u32,
    pub flags: u32,
    pub tar_stream_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexShardHeader {
    pub version: u32,
    pub shard_index: u64,
    pub file_count: u32,
    pub frame_count: u32,
    pub envelope_count: u32,
    pub file_table_offset: u32,
    pub frame_table_offset: u32,
    pub envelope_table_offset: u32,
    pub string_pool_offset: u32,
    pub string_pool_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexShard {
    pub header: IndexShardHeader,
    pub files: Vec<FileEntry>,
    pub frames: Vec<FrameEntry>,
    pub envelopes: Vec<EnvelopeEntry>,
    pub string_pool: Vec<u8>,
    file_paths: Vec<Vec<u8>>,
    file_tar_member_group_starts: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub path_hash: [u8; 8],
    pub path_offset: u32,
    pub path_length: u32,
    pub first_frame_index: u64,
    pub frame_count: u32,
    pub offset_in_first_frame_plaintext: u32,
    pub tar_member_group_size: u64,
    pub file_data_size: u64,
    pub flags: u32,
    pub mtime_nsec: u32,
    pub mtime_sec: i64,
    pub created_nsec: u32,
    pub accessed_nsec: u32,
    pub created_sec: i64,
    pub accessed_sec: i64,
    pub uid: u64,
    pub gid: u64,
    pub mode: u32,
    pub attributes: u32,
    pub uname_offset: u32,
    pub uname_length: u32,
    pub gname_offset: u32,
    pub gname_length: u32,
    pub link_target_offset: u32,
    pub link_target_length: u32,
    pub kind: u8,
    pub metadata_flags: u8,
    pub _reserved1: u16,
    pub _reserved2: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryHintTable {
    pub header: DirectoryHintTableHeader,
    pub entries: Vec<DirectoryHintEntry>,
    pub shard_row_indexes: Vec<u32>,
    pub string_pool: Vec<u8>,
    entry_paths: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryHintTableHeader {
    pub version: u32,
    pub hint_shard_index: u64,
    pub entry_count: u64,
    pub entry_table_offset: u64,
    pub shard_list_offset: u64,
    pub string_pool_offset: u64,
    pub string_pool_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryHintEntry {
    pub dir_hash: [u8; 8],
    pub path_offset: u64,
    pub path_length: u32,
    pub shard_list_start_index: u32,
    pub shard_count: u32,
}

impl IndexRoot {
    pub fn parse(
        bytes: &[u8],
        has_dictionary: bool,
        limits: MetadataLimits,
    ) -> Result<Self, FormatError> {
        let structure = "IndexRoot";
        if bytes.len() < INDEX_ROOT_LEN {
            return invalid(structure, "plaintext is shorter than fixed header");
        }
        expect_magic(structure, TZIR_MAGIC, read_array::<4>(bytes, 0, structure)?)?;
        expect_zero(structure, slice(bytes, 128, 32, structure)?)?;

        let header = IndexRootHeader {
            version: read_u32(bytes, 4, structure)?,
            shard_count: read_u32(bytes, 8, structure)?,
            directory_hint_shard_count: read_u32(bytes, 12, structure)?,
            frame_count: read_u64(bytes, 16, structure)?,
            envelope_count: read_u64(bytes, 24, structure)?,
            file_count: read_u64(bytes, 32, structure)?,
            payload_block_count: read_u64(bytes, 40, structure)?,
            tar_total_size: read_u64(bytes, 48, structure)?,
            content_sha256: read_array::<32>(bytes, 56, structure)?,
            shard_table_offset: read_u64(bytes, 88, structure)?,
            directory_hint_shard_table_offset: read_u64(bytes, 96, structure)?,
            dictionary_first_block: read_u64(bytes, 104, structure)?,
            dictionary_data_block_count: read_u32(bytes, 112, structure)?,
            dictionary_parity_block_count: read_u32(bytes, 116, structure)?,
            dictionary_encrypted_size: read_u32(bytes, 120, structure)?,
            dictionary_decompressed_size: read_u32(bytes, 124, structure)?,
        };

        if header.version != 1 {
            return invalid(structure, "unsupported version");
        }
        if header.shard_count > limits.max_shard_count {
            return invalid(structure, "shard count exceeds resource cap");
        }
        if header.directory_hint_shard_count > limits.max_directory_hint_shards {
            return invalid(structure, "directory hint shard count exceeds resource cap");
        }
        validate_dictionary_fields(&header, has_dictionary, limits)?;

        let mut cursor = INDEX_ROOT_LEN;
        let shards = if header.shard_count == 0 {
            if header.shard_table_offset != 0 {
                return invalid(structure, "absent shard table has non-zero offset");
            }
            Vec::new()
        } else {
            expect_offset(structure, "shard table", header.shard_table_offset, cursor)?;
            let count = to_usize(header.shard_count as u64, structure)?;
            let bytes_len = checked_mul(count, SHARD_ENTRY_LEN, structure)?;
            let table = slice(bytes, cursor, bytes_len, structure)?;
            cursor = checked_add(cursor, bytes_len, structure)?;
            parse_shard_entries(table, limits)?
        };

        let directory_hint_shards = if header.directory_hint_shard_count == 0 {
            if header.directory_hint_shard_table_offset != 0 {
                return invalid(
                    structure,
                    "absent directory hint shard table has non-zero offset",
                );
            }
            Vec::new()
        } else {
            if header.shard_count == 0 {
                return invalid(structure, "directory hints require at least one shard");
            }
            expect_offset(
                structure,
                "directory hint shard table",
                header.directory_hint_shard_table_offset,
                cursor,
            )?;
            let count = to_usize(header.directory_hint_shard_count as u64, structure)?;
            let bytes_len = checked_mul(count, DIRECTORY_HINT_SHARD_ENTRY_LEN, structure)?;
            let table = slice(bytes, cursor, bytes_len, structure)?;
            cursor = checked_add(cursor, bytes_len, structure)?;
            parse_directory_hint_shard_entries(table, limits)?
        };

        if bytes.len() != cursor {
            return invalid(
                structure,
                "plaintext length does not match canonical cursor",
            );
        }
        validate_index_root_totals(&header, &shards, has_dictionary)?;

        Ok(Self {
            header,
            shards,
            directory_hint_shards,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut header = self.header.clone();
        header.shard_count = self.shards.len() as u32;
        header.directory_hint_shard_count = self.directory_hint_shards.len() as u32;
        header.shard_table_offset = if self.shards.is_empty() {
            0
        } else {
            INDEX_ROOT_LEN as u64
        };
        header.directory_hint_shard_table_offset = if self.directory_hint_shards.is_empty() {
            0
        } else {
            (INDEX_ROOT_LEN + self.shards.len() * SHARD_ENTRY_LEN) as u64
        };

        let mut bytes = Vec::with_capacity(
            INDEX_ROOT_LEN
                + self.shards.len() * SHARD_ENTRY_LEN
                + self.directory_hint_shards.len() * DIRECTORY_HINT_SHARD_ENTRY_LEN,
        );
        bytes.extend_from_slice(&header.to_bytes());
        for entry in &self.shards {
            bytes.extend_from_slice(&entry.to_bytes());
        }
        for entry in &self.directory_hint_shards {
            bytes.extend_from_slice(&entry.to_bytes());
        }
        bytes
    }

    pub fn candidate_shard_indexes_for_hash(
        &self,
        target_hash: [u8; 8],
        scan_cap_per_direction: usize,
    ) -> Result<Vec<usize>, FormatError> {
        candidate_interval_indexes(
            &self.shards,
            target_hash,
            scan_cap_per_direction,
            |entry| entry.first_path_hash,
            |entry| entry.last_path_hash,
        )
    }

    pub fn candidate_shards_for_path(
        &self,
        normalized_path: &[u8],
        limits: MetadataLimits,
    ) -> Result<Vec<usize>, FormatError> {
        self.candidate_shard_indexes_for_hash(
            hash_prefix(normalized_path),
            limits.max_hash_collision_shard_scan,
        )
    }
}

impl IndexRootHeader {
    pub fn empty() -> Self {
        Self {
            version: 1,
            shard_count: 0,
            directory_hint_shard_count: 0,
            frame_count: 0,
            envelope_count: 0,
            file_count: 0,
            payload_block_count: 0,
            tar_total_size: 0,
            content_sha256: SHA256_EMPTY,
            shard_table_offset: 0,
            directory_hint_shard_table_offset: 0,
            dictionary_first_block: 0,
            dictionary_data_block_count: 0,
            dictionary_parity_block_count: 0,
            dictionary_encrypted_size: 0,
            dictionary_decompressed_size: 0,
        }
    }

    pub fn to_bytes(&self) -> [u8; INDEX_ROOT_LEN] {
        let mut bytes = [0u8; INDEX_ROOT_LEN];
        bytes[0..4].copy_from_slice(&TZIR_MAGIC);
        write_u32(&mut bytes, 4, self.version);
        write_u32(&mut bytes, 8, self.shard_count);
        write_u32(&mut bytes, 12, self.directory_hint_shard_count);
        write_u64(&mut bytes, 16, self.frame_count);
        write_u64(&mut bytes, 24, self.envelope_count);
        write_u64(&mut bytes, 32, self.file_count);
        write_u64(&mut bytes, 40, self.payload_block_count);
        write_u64(&mut bytes, 48, self.tar_total_size);
        bytes[56..88].copy_from_slice(&self.content_sha256);
        write_u64(&mut bytes, 88, self.shard_table_offset);
        write_u64(&mut bytes, 96, self.directory_hint_shard_table_offset);
        write_u64(&mut bytes, 104, self.dictionary_first_block);
        write_u32(&mut bytes, 112, self.dictionary_data_block_count);
        write_u32(&mut bytes, 116, self.dictionary_parity_block_count);
        write_u32(&mut bytes, 120, self.dictionary_encrypted_size);
        write_u32(&mut bytes, 124, self.dictionary_decompressed_size);
        bytes
    }
}

impl ShardEntry {
    pub fn to_bytes(&self) -> [u8; SHARD_ENTRY_LEN] {
        let mut bytes = [0u8; SHARD_ENTRY_LEN];
        write_u64(&mut bytes, 0, self.shard_index);
        write_u64(&mut bytes, 8, self.first_block_index);
        write_u32(&mut bytes, 16, self.data_block_count);
        write_u32(&mut bytes, 20, self.parity_block_count);
        write_u32(&mut bytes, 24, self.encrypted_size);
        write_u32(&mut bytes, 28, self.decompressed_size);
        write_u32(&mut bytes, 32, self.file_count);
        bytes[36..44].copy_from_slice(&self.first_path_hash);
        bytes[44..52].copy_from_slice(&self.last_path_hash);
        bytes
    }
}

impl DirectoryHintShardEntry {
    pub fn to_bytes(&self) -> [u8; DIRECTORY_HINT_SHARD_ENTRY_LEN] {
        let mut bytes = [0u8; DIRECTORY_HINT_SHARD_ENTRY_LEN];
        write_u64(&mut bytes, 0, self.hint_shard_index);
        bytes[8..16].copy_from_slice(&self.first_dir_hash);
        bytes[16..24].copy_from_slice(&self.last_dir_hash);
        write_u64(&mut bytes, 24, self.first_block_index);
        write_u32(&mut bytes, 32, self.data_block_count);
        write_u32(&mut bytes, 36, self.parity_block_count);
        write_u32(&mut bytes, 40, self.encrypted_size);
        write_u32(&mut bytes, 44, self.decompressed_size);
        write_u64(&mut bytes, 48, self.entry_count);
        bytes
    }
}

impl IndexShard {
    pub fn parse(
        bytes: &[u8],
        locating_shard: &ShardEntry,
        limits: MetadataLimits,
    ) -> Result<Self, FormatError> {
        let structure = "IndexShard";
        if bytes.len() < INDEX_SHARD_HEADER_LEN {
            return invalid(structure, "plaintext is shorter than fixed header");
        }
        expect_magic(structure, TZIS_MAGIC, read_array::<4>(bytes, 0, structure)?)?;
        expect_zero(structure, slice(bytes, 48, 16, structure)?)?;

        let header = IndexShardHeader {
            version: read_u32(bytes, 4, structure)?,
            shard_index: read_u64(bytes, 8, structure)?,
            file_count: read_u32(bytes, 16, structure)?,
            frame_count: read_u32(bytes, 20, structure)?,
            envelope_count: read_u32(bytes, 24, structure)?,
            file_table_offset: read_u32(bytes, 28, structure)?,
            frame_table_offset: read_u32(bytes, 32, structure)?,
            envelope_table_offset: read_u32(bytes, 36, structure)?,
            string_pool_offset: read_u32(bytes, 40, structure)?,
            string_pool_size: read_u32(bytes, 44, structure)?,
        };

        if header.version != INDEX_SHARD_VERSION {
            return invalid(structure, "unsupported version");
        }
        if header.file_count == 0 {
            return invalid(structure, "index shard must contain at least one file");
        }
        if header.file_count > limits.max_files_per_index_shard {
            return invalid(structure, "file count exceeds resource cap");
        }
        if header.shard_index != locating_shard.shard_index {
            return invalid(structure, "shard index does not match locating ShardEntry");
        }
        if header.file_count != locating_shard.file_count {
            return invalid(structure, "file count does not match locating ShardEntry");
        }

        let mut cursor = INDEX_SHARD_HEADER_LEN;
        let files = parse_counted_table(
            bytes,
            CountedTableSpec {
                structure,
                name: "file table",
                count: header.file_count as u64,
                offset: header.file_table_offset as u64,
                entry_len: FILE_ENTRY_LEN,
                parse: parse_file_entry,
            },
            &mut cursor,
        )?;
        let frames = parse_counted_table(
            bytes,
            CountedTableSpec {
                structure,
                name: "frame table",
                count: header.frame_count as u64,
                offset: header.frame_table_offset as u64,
                entry_len: FRAME_ENTRY_LEN,
                parse: parse_frame_entry,
            },
            &mut cursor,
        )?;
        let envelopes = parse_counted_table(
            bytes,
            CountedTableSpec {
                structure,
                name: "envelope table",
                count: header.envelope_count as u64,
                offset: header.envelope_table_offset as u64,
                entry_len: ENVELOPE_ENTRY_LEN,
                parse: parse_envelope_entry,
            },
            &mut cursor,
        )?;
        let string_pool = if header.string_pool_size == 0 {
            if header.string_pool_offset != 0 {
                return invalid(structure, "absent string pool has non-zero offset");
            }
            Vec::new()
        } else {
            expect_offset(
                structure,
                "string pool",
                header.string_pool_offset as u64,
                cursor,
            )?;
            let len = header.string_pool_size as usize;
            let pool = slice(bytes, cursor, len, structure)?.to_vec();
            cursor = checked_add(cursor, len, structure)?;
            pool
        };
        if bytes.len() != cursor {
            return invalid(
                structure,
                "plaintext length does not match canonical cursor",
            );
        }

        let (file_paths, file_tar_member_group_starts) = validate_index_shard_tables(
            &files,
            &frames,
            &envelopes,
            &string_pool,
            locating_shard,
            limits,
        )?;

        Ok(Self {
            header,
            files,
            frames,
            envelopes,
            string_pool,
            file_paths,
            file_tar_member_group_starts,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut header = self.header.clone();
        header.file_count = self.files.len() as u32;
        header.frame_count = self.frames.len() as u32;
        header.envelope_count = self.envelopes.len() as u32;

        let mut cursor = INDEX_SHARD_HEADER_LEN;
        header.file_table_offset = table_offset(self.files.len(), cursor);
        cursor += self.files.len() * FILE_ENTRY_LEN;
        header.frame_table_offset = table_offset(self.frames.len(), cursor);
        cursor += self.frames.len() * FRAME_ENTRY_LEN;
        header.envelope_table_offset = table_offset(self.envelopes.len(), cursor);
        cursor += self.envelopes.len() * ENVELOPE_ENTRY_LEN;
        header.string_pool_size = self.string_pool.len() as u32;
        header.string_pool_offset = table_offset(self.string_pool.len(), cursor);

        let mut bytes = Vec::with_capacity(cursor + self.string_pool.len());
        bytes.extend_from_slice(&header.to_bytes());
        for entry in &self.files {
            bytes.extend_from_slice(&entry.to_bytes());
        }
        for entry in &self.frames {
            bytes.extend_from_slice(&entry.to_bytes());
        }
        for entry in &self.envelopes {
            bytes.extend_from_slice(&entry.to_bytes());
        }
        bytes.extend_from_slice(&self.string_pool);
        bytes
    }

    pub fn file_path(&self, file_index: usize) -> Option<&[u8]> {
        self.file_paths.get(file_index).map(Vec::as_slice)
    }

    pub fn tar_member_group_start(&self, file_index: usize) -> Option<u64> {
        self.file_tar_member_group_starts.get(file_index).copied()
    }

    pub fn lookup_file_index(&self, normalized_path: &[u8]) -> Option<usize> {
        let target_hash = hash_prefix(normalized_path);
        let lower = self.lower_bound_file_key(target_hash, normalized_path);

        let mut best = None;
        for idx in lower..self.files.len() {
            let file = &self.files[idx];
            if file.path_hash != target_hash || self.file_paths[idx].as_slice() != normalized_path {
                break;
            }
            best = Some(idx);
        }
        best
    }

    fn lower_bound_file_key(&self, target_hash: [u8; 8], target_path: &[u8]) -> usize {
        let mut low = 0usize;
        let mut high = self.files.len();
        while low < high {
            let mid = low + (high - low) / 2;
            let key_is_less = self.files[mid].path_hash < target_hash
                || (self.files[mid].path_hash == target_hash
                    && self.file_paths[mid].as_slice() < target_path);
            if key_is_less {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        low
    }
}

impl IndexShardHeader {
    pub fn to_bytes(&self) -> [u8; INDEX_SHARD_HEADER_LEN] {
        let mut bytes = [0u8; INDEX_SHARD_HEADER_LEN];
        bytes[0..4].copy_from_slice(&TZIS_MAGIC);
        write_u32(&mut bytes, 4, self.version);
        write_u64(&mut bytes, 8, self.shard_index);
        write_u32(&mut bytes, 16, self.file_count);
        write_u32(&mut bytes, 20, self.frame_count);
        write_u32(&mut bytes, 24, self.envelope_count);
        write_u32(&mut bytes, 28, self.file_table_offset);
        write_u32(&mut bytes, 32, self.frame_table_offset);
        write_u32(&mut bytes, 36, self.envelope_table_offset);
        write_u32(&mut bytes, 40, self.string_pool_offset);
        write_u32(&mut bytes, 44, self.string_pool_size);
        bytes
    }
}

impl FileEntry {
    pub fn to_bytes(&self) -> [u8; FILE_ENTRY_LEN] {
        let mut bytes = [0u8; FILE_ENTRY_LEN];
        bytes[0..8].copy_from_slice(&self.path_hash);
        write_u32(&mut bytes, 8, self.path_offset);
        write_u32(&mut bytes, 12, self.path_length);
        write_u64(&mut bytes, 16, self.first_frame_index);
        write_u32(&mut bytes, 24, self.frame_count);
        write_u32(&mut bytes, 28, self.offset_in_first_frame_plaintext);
        write_u64(&mut bytes, 32, self.tar_member_group_size);
        write_u64(&mut bytes, 40, self.file_data_size);
        write_u32(&mut bytes, 48, self.flags);
        write_u32(&mut bytes, 52, self.mtime_nsec);
        write_i64(&mut bytes, 56, self.mtime_sec);
        write_u32(&mut bytes, 64, self.created_nsec);
        write_u32(&mut bytes, 68, self.accessed_nsec);
        write_i64(&mut bytes, 72, self.created_sec);
        write_i64(&mut bytes, 80, self.accessed_sec);
        write_u64(&mut bytes, 88, self.uid);
        write_u64(&mut bytes, 96, self.gid);
        write_u32(&mut bytes, 104, self.mode);
        write_u32(&mut bytes, 108, self.attributes);
        write_u32(&mut bytes, 112, self.uname_offset);
        write_u32(&mut bytes, 116, self.uname_length);
        write_u32(&mut bytes, 120, self.gname_offset);
        write_u32(&mut bytes, 124, self.gname_length);
        write_u32(&mut bytes, 128, self.link_target_offset);
        write_u32(&mut bytes, 132, self.link_target_length);
        write_u8(&mut bytes, 136, self.kind);
        write_u8(&mut bytes, 137, self.metadata_flags);
        write_u16(&mut bytes, 138, self._reserved1);
        write_u32(&mut bytes, 140, self._reserved2);
        bytes
    }
}

impl FrameEntry {
    pub fn to_bytes(&self) -> [u8; FRAME_ENTRY_LEN] {
        let mut bytes = [0u8; FRAME_ENTRY_LEN];
        write_u64(&mut bytes, 0, self.frame_index);
        write_u64(&mut bytes, 8, self.envelope_index);
        write_u32(&mut bytes, 16, self.offset_in_envelope);
        write_u32(&mut bytes, 20, self.compressed_size);
        write_u32(&mut bytes, 24, self.decompressed_size);
        write_u32(&mut bytes, 28, self.flags);
        write_u64(&mut bytes, 32, self.tar_stream_offset);
        bytes
    }
}

impl EnvelopeEntry {
    pub fn to_bytes(&self) -> [u8; ENVELOPE_ENTRY_LEN] {
        let mut bytes = [0u8; ENVELOPE_ENTRY_LEN];
        write_u64(&mut bytes, 0, self.envelope_index);
        write_u64(&mut bytes, 8, self.first_block_index);
        write_u32(&mut bytes, 16, self.data_block_count);
        write_u32(&mut bytes, 20, self.parity_block_count);
        write_u32(&mut bytes, 24, self.encrypted_size);
        write_u32(&mut bytes, 28, self.plaintext_size);
        write_u64(&mut bytes, 32, self.first_frame_index);
        write_u32(&mut bytes, 40, self.frame_count);
        bytes
    }
}

impl DirectoryHintTable {
    pub fn parse(
        bytes: &[u8],
        locating_shard: &DirectoryHintShardEntry,
        index_root_shard_count: u32,
        limits: MetadataLimits,
    ) -> Result<Self, FormatError> {
        let structure = "DirectoryHintTable";
        if bytes.len() < DIRECTORY_HINT_TABLE_LEN {
            return invalid(structure, "plaintext is shorter than fixed header");
        }
        expect_magic(structure, TZDH_MAGIC, read_array::<4>(bytes, 0, structure)?)?;
        expect_zero(structure, slice(bytes, 56, 16, structure)?)?;

        let header = DirectoryHintTableHeader {
            version: read_u32(bytes, 4, structure)?,
            hint_shard_index: read_u64(bytes, 8, structure)?,
            entry_count: read_u64(bytes, 16, structure)?,
            entry_table_offset: read_u64(bytes, 24, structure)?,
            shard_list_offset: read_u64(bytes, 32, structure)?,
            string_pool_offset: read_u64(bytes, 40, structure)?,
            string_pool_size: read_u64(bytes, 48, structure)?,
        };
        if header.version != 1 {
            return invalid(structure, "unsupported version");
        }
        if header.hint_shard_index != locating_shard.hint_shard_index {
            return invalid(
                structure,
                "hint shard index does not match locating DirectoryHintShardEntry",
            );
        }
        if header.entry_count != locating_shard.entry_count {
            return invalid(
                structure,
                "entry count does not match locating DirectoryHintShardEntry",
            );
        }
        if header.entry_count == 0 {
            return invalid(structure, "located directory hint shard is empty");
        }
        if header.entry_count > limits.max_entries_per_directory_hint_shard {
            return invalid(structure, "entry count exceeds resource cap");
        }

        let entry_count = to_usize(header.entry_count, structure)?;
        expect_offset(
            structure,
            "entry table",
            header.entry_table_offset,
            DIRECTORY_HINT_TABLE_LEN,
        )?;
        let entry_bytes_len = checked_mul(entry_count, DIRECTORY_HINT_ENTRY_LEN, structure)?;
        let entries_end = checked_add(DIRECTORY_HINT_TABLE_LEN, entry_bytes_len, structure)?;
        expect_offset(
            structure,
            "shard list",
            header.shard_list_offset,
            entries_end,
        )?;
        if header.shard_list_offset % 4 != 0 {
            return invalid(structure, "shard list is not 4-byte aligned");
        }

        let entry_bytes = slice(bytes, DIRECTORY_HINT_TABLE_LEN, entry_bytes_len, structure)?;
        let entries = parse_directory_hint_entries(entry_bytes)?;
        let shard_list_len = validate_directory_hint_entries(
            &entries,
            bytes,
            &header,
            locating_shard,
            index_root_shard_count,
        )?;
        let shard_list_offset = to_usize(header.shard_list_offset, structure)?;
        let shard_list_bytes_len = checked_mul(shard_list_len, 4, structure)?;
        let shard_list_end = checked_add(shard_list_offset, shard_list_bytes_len, structure)?;
        let shard_list_bytes = slice(bytes, shard_list_offset, shard_list_bytes_len, structure)?;
        let shard_row_indexes = parse_u32_array(shard_list_bytes, structure)?;

        let string_pool = if header.string_pool_size == 0 {
            if header.string_pool_offset != 0 {
                return invalid(structure, "absent string pool has non-zero offset");
            }
            Vec::new()
        } else {
            expect_offset(
                structure,
                "string pool",
                header.string_pool_offset,
                shard_list_end,
            )?;
            let offset = to_usize(header.string_pool_offset, structure)?;
            let size = to_usize(header.string_pool_size, structure)?;
            slice(bytes, offset, size, structure)?.to_vec()
        };
        let final_cursor = if header.string_pool_size == 0 {
            shard_list_end
        } else {
            checked_add(
                to_usize(header.string_pool_offset, structure)?,
                to_usize(header.string_pool_size, structure)?,
                structure,
            )?
        };
        if bytes.len() != final_cursor {
            return invalid(
                structure,
                "plaintext length does not match canonical cursor",
            );
        }

        let entry_paths = validate_directory_hint_paths_and_lists(
            &entries,
            &shard_row_indexes,
            &string_pool,
            locating_shard,
            index_root_shard_count,
            limits.max_path_length,
        )?;

        Ok(Self {
            header,
            entries,
            shard_row_indexes,
            string_pool,
            entry_paths,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut header = self.header.clone();
        header.entry_count = self.entries.len() as u64;
        header.entry_table_offset = if self.entries.is_empty() {
            0
        } else {
            DIRECTORY_HINT_TABLE_LEN as u64
        };
        header.shard_list_offset = if self.entries.is_empty() {
            0
        } else {
            (DIRECTORY_HINT_TABLE_LEN + self.entries.len() * DIRECTORY_HINT_ENTRY_LEN) as u64
        };
        header.string_pool_size = self.string_pool.len() as u64;
        header.string_pool_offset = if self.string_pool.is_empty() {
            0
        } else {
            header.shard_list_offset + (self.shard_row_indexes.len() as u64) * 4
        };

        let mut bytes = Vec::with_capacity(
            DIRECTORY_HINT_TABLE_LEN
                + self.entries.len() * DIRECTORY_HINT_ENTRY_LEN
                + self.shard_row_indexes.len() * 4
                + self.string_pool.len(),
        );
        bytes.extend_from_slice(&header.to_bytes());
        for entry in &self.entries {
            bytes.extend_from_slice(&entry.to_bytes());
        }
        if !self.entries.is_empty() {
            for row in &self.shard_row_indexes {
                let mut raw = [0u8; 4];
                write_u32(&mut raw, 0, *row);
                bytes.extend_from_slice(&raw);
            }
        }
        bytes.extend_from_slice(&self.string_pool);
        bytes
    }

    pub fn entry_path(&self, entry_index: usize) -> Option<&[u8]> {
        self.entry_paths.get(entry_index).map(Vec::as_slice)
    }

    pub fn lookup_directory_index(&self, normalized_dir_path: &[u8]) -> Option<usize> {
        let target_hash = hash_prefix(normalized_dir_path);
        let lower = self.lower_bound_directory_key(target_hash, normalized_dir_path);
        let entry = self.entries.get(lower)?;
        if entry.dir_hash == target_hash
            && self.entry_paths[lower].as_slice() == normalized_dir_path
        {
            Some(lower)
        } else {
            None
        }
    }

    fn lower_bound_directory_key(&self, target_hash: [u8; 8], target_path: &[u8]) -> usize {
        let mut low = 0usize;
        let mut high = self.entries.len();
        while low < high {
            let mid = low + (high - low) / 2;
            let key_is_less = self.entries[mid].dir_hash < target_hash
                || (self.entries[mid].dir_hash == target_hash
                    && self.entry_paths[mid].as_slice() < target_path);
            if key_is_less {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        low
    }

    pub fn shard_rows_for_entry(&self, entry_index: usize) -> Option<&[u32]> {
        let entry = self.entries.get(entry_index)?;
        let start = entry.shard_list_start_index as usize;
        let end = start.checked_add(entry.shard_count as usize)?;
        self.shard_row_indexes.get(start..end)
    }
}

impl DirectoryHintTableHeader {
    pub fn to_bytes(&self) -> [u8; DIRECTORY_HINT_TABLE_LEN] {
        let mut bytes = [0u8; DIRECTORY_HINT_TABLE_LEN];
        bytes[0..4].copy_from_slice(&TZDH_MAGIC);
        write_u32(&mut bytes, 4, self.version);
        write_u64(&mut bytes, 8, self.hint_shard_index);
        write_u64(&mut bytes, 16, self.entry_count);
        write_u64(&mut bytes, 24, self.entry_table_offset);
        write_u64(&mut bytes, 32, self.shard_list_offset);
        write_u64(&mut bytes, 40, self.string_pool_offset);
        write_u64(&mut bytes, 48, self.string_pool_size);
        bytes
    }
}

impl DirectoryHintEntry {
    pub fn to_bytes(&self) -> [u8; DIRECTORY_HINT_ENTRY_LEN] {
        let mut bytes = [0u8; DIRECTORY_HINT_ENTRY_LEN];
        bytes[0..8].copy_from_slice(&self.dir_hash);
        write_u64(&mut bytes, 8, self.path_offset);
        write_u32(&mut bytes, 16, self.path_length);
        write_u32(&mut bytes, 24, self.shard_list_start_index);
        write_u32(&mut bytes, 28, self.shard_count);
        bytes
    }
}

pub fn hash_prefix(bytes: &[u8]) -> [u8; 8] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

pub fn normalize_lookup_file_path(
    path: &str,
    max_path_length: u32,
) -> Result<Vec<u8>, FormatError> {
    let normalized = path.nfc().collect::<String>();
    validate_file_path_bytes(normalized.as_bytes(), max_path_length)?;
    Ok(normalized.into_bytes())
}

pub fn normalize_lookup_directory_path(
    path: &str,
    max_path_length: u32,
) -> Result<Vec<u8>, FormatError> {
    let trimmed = path.strip_suffix('/').unwrap_or(path);
    let normalized = trimmed.nfc().collect::<String>();
    validate_directory_path_bytes(normalized.as_bytes(), max_path_length)?;
    Ok(normalized.into_bytes())
}

pub fn is_directory_ancestor(directory_path: &[u8], file_path: &[u8]) -> bool {
    if directory_path.is_empty() {
        return true;
    }
    file_path.len() > directory_path.len()
        && file_path.starts_with(directory_path)
        && file_path[directory_path.len()] == b'/'
}

fn parse_shard_entries(
    bytes: &[u8],
    limits: MetadataLimits,
) -> Result<Vec<ShardEntry>, FormatError> {
    let mut entries = Vec::with_capacity(bytes.len() / SHARD_ENTRY_LEN);
    let mut seen_indexes = HashSet::new();
    for chunk in bytes.chunks_exact(SHARD_ENTRY_LEN) {
        let entry = ShardEntry {
            shard_index: read_u64(chunk, 0, "ShardEntry")?,
            first_block_index: read_u64(chunk, 8, "ShardEntry")?,
            data_block_count: read_u32(chunk, 16, "ShardEntry")?,
            parity_block_count: read_u32(chunk, 20, "ShardEntry")?,
            encrypted_size: read_u32(chunk, 24, "ShardEntry")?,
            decompressed_size: read_u32(chunk, 28, "ShardEntry")?,
            file_count: read_u32(chunk, 32, "ShardEntry")?,
            first_path_hash: read_array::<8>(chunk, 36, "ShardEntry")?,
            last_path_hash: read_array::<8>(chunk, 44, "ShardEntry")?,
        };
        if entry.file_count == 0 {
            return invalid("ShardEntry", "file count is zero");
        }
        if entry.decompressed_size == 0 {
            return invalid("ShardEntry", "decompressed size is zero");
        }
        validate_encrypted_extent(
            "ShardEntry",
            entry.data_block_count,
            entry.encrypted_size,
            limits.block_size,
        )?;
        validate_fec_class_extent(
            "ShardEntry",
            entry.data_block_count,
            entry.parity_block_count,
            limits.max_index_data_shards,
            limits.max_index_parity_shards,
        )?;
        if entry.first_path_hash > entry.last_path_hash {
            return invalid("ShardEntry", "first hash is greater than last hash");
        }
        if !seen_indexes.insert(entry.shard_index) {
            return invalid("ShardEntry", "duplicate shard index");
        }
        if let Some(previous) = entries.last() {
            let previous: &ShardEntry = previous;
            if shard_entry_sort_key(previous) >= shard_entry_sort_key(&entry) {
                return invalid("IndexRoot", "ShardEntry rows are not sorted");
            }
            if previous.last_path_hash > entry.first_path_hash {
                return invalid("IndexRoot", "ShardEntry hash ranges overlap out of order");
            }
        }
        entries.push(entry);
    }
    Ok(entries)
}

fn parse_directory_hint_shard_entries(
    bytes: &[u8],
    limits: MetadataLimits,
) -> Result<Vec<DirectoryHintShardEntry>, FormatError> {
    let mut entries = Vec::with_capacity(bytes.len() / DIRECTORY_HINT_SHARD_ENTRY_LEN);
    let mut seen_indexes = HashSet::new();
    for chunk in bytes.chunks_exact(DIRECTORY_HINT_SHARD_ENTRY_LEN) {
        let entry = DirectoryHintShardEntry {
            hint_shard_index: read_u64(chunk, 0, "DirectoryHintShardEntry")?,
            first_dir_hash: read_array::<8>(chunk, 8, "DirectoryHintShardEntry")?,
            last_dir_hash: read_array::<8>(chunk, 16, "DirectoryHintShardEntry")?,
            first_block_index: read_u64(chunk, 24, "DirectoryHintShardEntry")?,
            data_block_count: read_u32(chunk, 32, "DirectoryHintShardEntry")?,
            parity_block_count: read_u32(chunk, 36, "DirectoryHintShardEntry")?,
            encrypted_size: read_u32(chunk, 40, "DirectoryHintShardEntry")?,
            decompressed_size: read_u32(chunk, 44, "DirectoryHintShardEntry")?,
            entry_count: read_u64(chunk, 48, "DirectoryHintShardEntry")?,
        };
        if entry.entry_count == 0 {
            return invalid("DirectoryHintShardEntry", "entry count is zero");
        }
        if entry.decompressed_size == 0 {
            return invalid("DirectoryHintShardEntry", "decompressed size is zero");
        }
        validate_encrypted_extent(
            "DirectoryHintShardEntry",
            entry.data_block_count,
            entry.encrypted_size,
            limits.block_size,
        )?;
        validate_fec_class_extent(
            "DirectoryHintShardEntry",
            entry.data_block_count,
            entry.parity_block_count,
            limits.max_index_data_shards,
            limits.max_index_parity_shards,
        )?;
        if entry.first_dir_hash > entry.last_dir_hash {
            return invalid(
                "DirectoryHintShardEntry",
                "first hash is greater than last hash",
            );
        }
        if !seen_indexes.insert(entry.hint_shard_index) {
            return invalid("DirectoryHintShardEntry", "duplicate hint shard index");
        }
        if let Some(previous) = entries.last() {
            let previous: &DirectoryHintShardEntry = previous;
            if directory_hint_shard_sort_key(previous) >= directory_hint_shard_sort_key(&entry) {
                return invalid("IndexRoot", "DirectoryHintShardEntry rows are not sorted");
            }
            if previous.last_dir_hash > entry.first_dir_hash {
                return invalid(
                    "IndexRoot",
                    "DirectoryHintShardEntry hash ranges overlap out of order",
                );
            }
        }
        entries.push(entry);
    }
    Ok(entries)
}

fn parse_file_entry(bytes: &[u8]) -> Result<FileEntry, FormatError> {
    Ok(FileEntry {
        path_hash: read_array::<8>(bytes, 0, "FileEntry")?,
        path_offset: read_u32(bytes, 8, "FileEntry")?,
        path_length: read_u32(bytes, 12, "FileEntry")?,
        first_frame_index: read_u64(bytes, 16, "FileEntry")?,
        frame_count: read_u32(bytes, 24, "FileEntry")?,
        offset_in_first_frame_plaintext: read_u32(bytes, 28, "FileEntry")?,
        tar_member_group_size: read_u64(bytes, 32, "FileEntry")?,
        file_data_size: read_u64(bytes, 40, "FileEntry")?,
        flags: read_u32(bytes, 48, "FileEntry")?,
        mtime_nsec: read_u32(bytes, 52, "FileEntry")?,
        mtime_sec: read_i64(bytes, 56, "FileEntry")?,
        created_nsec: read_u32(bytes, 64, "FileEntry")?,
        accessed_nsec: read_u32(bytes, 68, "FileEntry")?,
        created_sec: read_i64(bytes, 72, "FileEntry")?,
        accessed_sec: read_i64(bytes, 80, "FileEntry")?,
        uid: read_u64(bytes, 88, "FileEntry")?,
        gid: read_u64(bytes, 96, "FileEntry")?,
        mode: read_u32(bytes, 104, "FileEntry")?,
        attributes: read_u32(bytes, 108, "FileEntry")?,
        uname_offset: read_u32(bytes, 112, "FileEntry")?,
        uname_length: read_u32(bytes, 116, "FileEntry")?,
        gname_offset: read_u32(bytes, 120, "FileEntry")?,
        gname_length: read_u32(bytes, 124, "FileEntry")?,
        link_target_offset: read_u32(bytes, 128, "FileEntry")?,
        link_target_length: read_u32(bytes, 132, "FileEntry")?,
        kind: read_u8(bytes, 136, "FileEntry")?,
        metadata_flags: read_u8(bytes, 137, "FileEntry")?,
        _reserved1: read_u16(bytes, 138, "FileEntry")?,
        _reserved2: read_u32(bytes, 140, "FileEntry")?,
    })
}

fn parse_frame_entry(bytes: &[u8]) -> Result<FrameEntry, FormatError> {
    expect_zero("FrameEntry", slice(bytes, 40, 4, "FrameEntry")?)?;
    Ok(FrameEntry {
        frame_index: read_u64(bytes, 0, "FrameEntry")?,
        envelope_index: read_u64(bytes, 8, "FrameEntry")?,
        offset_in_envelope: read_u32(bytes, 16, "FrameEntry")?,
        compressed_size: read_u32(bytes, 20, "FrameEntry")?,
        decompressed_size: read_u32(bytes, 24, "FrameEntry")?,
        flags: read_u32(bytes, 28, "FrameEntry")?,
        tar_stream_offset: read_u64(bytes, 32, "FrameEntry")?,
    })
}

fn parse_envelope_entry(bytes: &[u8]) -> Result<EnvelopeEntry, FormatError> {
    expect_zero("EnvelopeEntry", slice(bytes, 44, 4, "EnvelopeEntry")?)?;
    Ok(EnvelopeEntry {
        envelope_index: read_u64(bytes, 0, "EnvelopeEntry")?,
        first_block_index: read_u64(bytes, 8, "EnvelopeEntry")?,
        data_block_count: read_u32(bytes, 16, "EnvelopeEntry")?,
        parity_block_count: read_u32(bytes, 20, "EnvelopeEntry")?,
        encrypted_size: read_u32(bytes, 24, "EnvelopeEntry")?,
        plaintext_size: read_u32(bytes, 28, "EnvelopeEntry")?,
        first_frame_index: read_u64(bytes, 32, "EnvelopeEntry")?,
        frame_count: read_u32(bytes, 40, "EnvelopeEntry")?,
    })
}

fn parse_directory_hint_entries(bytes: &[u8]) -> Result<Vec<DirectoryHintEntry>, FormatError> {
    let mut entries = Vec::with_capacity(bytes.len() / DIRECTORY_HINT_ENTRY_LEN);
    for chunk in bytes.chunks_exact(DIRECTORY_HINT_ENTRY_LEN) {
        expect_zero(
            "DirectoryHintEntry",
            slice(chunk, 20, 4, "DirectoryHintEntry")?,
        )?;
        expect_zero(
            "DirectoryHintEntry",
            slice(chunk, 32, 8, "DirectoryHintEntry")?,
        )?;
        entries.push(DirectoryHintEntry {
            dir_hash: read_array::<8>(chunk, 0, "DirectoryHintEntry")?,
            path_offset: read_u64(chunk, 8, "DirectoryHintEntry")?,
            path_length: read_u32(chunk, 16, "DirectoryHintEntry")?,
            shard_list_start_index: read_u32(chunk, 24, "DirectoryHintEntry")?,
            shard_count: read_u32(chunk, 28, "DirectoryHintEntry")?,
        });
    }
    Ok(entries)
}

fn validate_index_root_totals(
    header: &IndexRootHeader,
    shards: &[ShardEntry],
    has_dictionary: bool,
) -> Result<(), FormatError> {
    if shards.is_empty() {
        if header.file_count != 0
            || header.frame_count != 0
            || header.envelope_count != 0
            || header.payload_block_count != 0
            || header.tar_total_size != 0
        {
            return invalid(
                "IndexRoot",
                "empty shard table has non-empty archive totals",
            );
        }
        if header.content_sha256 != SHA256_EMPTY {
            return invalid(
                "IndexRoot",
                "empty archive content hash is not SHA-256(empty)",
            );
        }
        if has_dictionary || !index_root_dictionary_fields_are_zero(header) {
            return invalid("IndexRoot", "empty archive cannot use dictionary");
        }
        return Ok(());
    }

    let mut sum = 0u64;
    for shard in shards {
        sum = sum.checked_add(shard.file_count as u64).ok_or(
            FormatError::MetadataArithmeticOverflow {
                structure: "IndexRoot",
            },
        )?;
    }
    if sum != header.file_count {
        return invalid(
            "IndexRoot",
            "file_count does not equal sum of ShardEntry rows",
        );
    }
    Ok(())
}

fn validate_dictionary_fields(
    header: &IndexRootHeader,
    has_dictionary: bool,
    limits: MetadataLimits,
) -> Result<(), FormatError> {
    if !has_dictionary {
        if !index_root_dictionary_fields_are_zero(header) {
            return invalid(
                "IndexRoot",
                "dictionary fields are non-zero while has_dictionary is false",
            );
        }
        return Ok(());
    }

    if header.dictionary_data_block_count == 0 {
        return invalid(
            "IndexRoot",
            "dictionary data block count is zero while has_dictionary is true",
        );
    }
    if header.dictionary_first_block == 0
        || header.dictionary_encrypted_size == 0
        || header.dictionary_decompressed_size == 0
    {
        return invalid("IndexRoot", "required dictionary field is zero");
    }
    validate_encrypted_extent(
        "IndexRoot.dictionary",
        header.dictionary_data_block_count,
        header.dictionary_encrypted_size,
        limits.block_size,
    )?;
    validate_fec_class_extent(
        "IndexRoot.dictionary",
        header.dictionary_data_block_count,
        header.dictionary_parity_block_count,
        limits.max_index_root_data_shards,
        limits.max_index_root_parity_shards,
    )
}

fn index_root_dictionary_fields_are_zero(header: &IndexRootHeader) -> bool {
    header.dictionary_first_block == 0
        && header.dictionary_data_block_count == 0
        && header.dictionary_parity_block_count == 0
        && header.dictionary_encrypted_size == 0
        && header.dictionary_decompressed_size == 0
}

fn validate_index_shard_tables(
    files: &[FileEntry],
    frames: &[FrameEntry],
    envelopes: &[EnvelopeEntry],
    string_pool: &[u8],
    locating_shard: &ShardEntry,
    limits: MetadataLimits,
) -> Result<(Vec<Vec<u8>>, Vec<u64>), FormatError> {
    validate_frame_table(frames)?;
    validate_envelope_table(envelopes, limits)?;

    let frame_by_index = frames
        .iter()
        .enumerate()
        .map(|(idx, frame)| (frame.frame_index, idx))
        .collect::<HashMap<_, _>>();
    let envelope_by_index = envelopes
        .iter()
        .enumerate()
        .map(|(idx, envelope)| (envelope.envelope_index, idx))
        .collect::<HashMap<_, _>>();

    let mut paths = Vec::with_capacity(files.len());
    let mut starts = Vec::with_capacity(files.len());
    let mut required_frames = BTreeSet::new();

    for file in files {
        if file.flags & !FILE_ENTRY_KNOWN_FLAGS != 0 {
            return invalid("FileEntry", "unknown revision-45 flags are non-zero");
        }
        if file.flags & EXTENDED_METADATA_V1 == 0 {
            return invalid("FileEntry", "EXTENDED_METADATA_V1 flag is not set");
        }
        if file.path_length == 0 {
            return invalid("FileEntry", "path length is zero");
        }
        if file.path_length > limits.max_path_length {
            return invalid("FileEntry", "path length exceeds configured maximum");
        }
        if file.frame_count == 0 {
            return invalid("FileEntry", "frame count is zero");
        }
        if file.tar_member_group_size < 1536 {
            return invalid(
                "FileEntry",
                "tar member group is smaller than the revision-45 minimum",
            );
        }
        if file.path_hash < locating_shard.first_path_hash
            || file.path_hash > locating_shard.last_path_hash
        {
            return invalid(
                "FileEntry",
                "path hash is outside locating ShardEntry bounds",
            );
        }

        let path = string_slice(
            string_pool,
            file.path_offset as u64,
            file.path_length as u64,
            "FileEntry",
        )?;
        validate_file_path_bytes(path, limits.max_path_length)?;
        if hash_prefix(path) != file.path_hash {
            return invalid("FileEntry", "path hash does not match string-pool path");
        }

        let first_frame = frame_for_file(file, &frame_by_index, frames, file.first_frame_index)?;
        let tar_member_group_start = first_frame
            .tar_stream_offset
            .checked_add(file.offset_in_first_frame_plaintext as u64)
            .ok_or(FormatError::MetadataArithmeticOverflow {
                structure: "FileEntry",
            })?;
        validate_file_frame_range(file, frames, &frame_by_index)?;
        for offset in 0..file.frame_count as u64 {
            let index = file.first_frame_index.checked_add(offset).ok_or(
                FormatError::MetadataArithmeticOverflow {
                    structure: "FileEntry",
                },
            )?;
            required_frames.insert(index);
        }
        paths.push(path.to_vec());
        starts.push(tar_member_group_start);
    }

    validate_file_order(files, &paths, &starts)?;
    if required_frames.len() != frames.len()
        || frames
            .iter()
            .any(|frame| !required_frames.contains(&frame.frame_index))
    {
        return invalid(
            "IndexShard",
            "FrameEntry table is not the exact set referenced by FileEntry rows",
        );
    }

    let mut required_envelopes = BTreeSet::new();
    for frame in frames {
        let envelope = envelope_by_index
            .get(&frame.envelope_index)
            .and_then(|idx| envelopes.get(*idx))
            .ok_or(FormatError::InvalidMetadata {
                structure: "FrameEntry",
                reason: "referenced EnvelopeEntry is missing",
            })?;
        validate_frame_envelope_binding(frame, envelope)?;
        required_envelopes.insert(frame.envelope_index);
    }
    if required_envelopes.len() != envelopes.len()
        || envelopes
            .iter()
            .any(|entry| !required_envelopes.contains(&entry.envelope_index))
    {
        return invalid(
            "IndexShard",
            "EnvelopeEntry table is not the exact set referenced by FrameEntry rows",
        );
    }
    validate_frame_slices_by_envelope(frames, envelopes)?;

    if let Some(first) = files.first() {
        if first.path_hash != locating_shard.first_path_hash {
            return invalid(
                "IndexShard",
                "first FileEntry hash does not match ShardEntry",
            );
        }
    }
    if let Some(last) = files.last() {
        if last.path_hash != locating_shard.last_path_hash {
            return invalid(
                "IndexShard",
                "last FileEntry hash does not match ShardEntry",
            );
        }
    }

    Ok((paths, starts))
}

fn validate_frame_table(frames: &[FrameEntry]) -> Result<(), FormatError> {
    for frame in frames {
        if frame.compressed_size == 0 || frame.decompressed_size == 0 {
            return invalid("FrameEntry", "frame sizes must be non-zero");
        }
        if frame.flags & !FRAME_KNOWN_FLAGS != 0 {
            return invalid("FrameEntry", "reserved flag bits are non-zero");
        }
    }
    for pair in frames.windows(2) {
        let previous = &pair[0];
        let next = &pair[1];
        if previous.frame_index >= next.frame_index {
            return invalid("IndexShard", "FrameEntry rows are not sorted and unique");
        }
        let previous_end = previous
            .tar_stream_offset
            .checked_add(previous.decompressed_size as u64)
            .ok_or(FormatError::MetadataArithmeticOverflow {
                structure: "FrameEntry",
            })?;
        if next.frame_index == previous.frame_index + 1 {
            if next.tar_stream_offset != previous_end {
                return invalid(
                    "FrameEntry",
                    "consecutive tar stream offsets are not packed",
                );
            }
        } else if next.tar_stream_offset <= previous_end {
            return invalid("FrameEntry", "non-consecutive tar stream offsets overlap");
        }
    }
    Ok(())
}

fn validate_envelope_table(
    envelopes: &[EnvelopeEntry],
    limits: MetadataLimits,
) -> Result<(), FormatError> {
    for envelope in envelopes {
        if envelope.frame_count == 0 || envelope.plaintext_size == 0 {
            return invalid("EnvelopeEntry", "payload envelope has no frame plaintext");
        }
        validate_encrypted_extent(
            "EnvelopeEntry",
            envelope.data_block_count,
            envelope.encrypted_size,
            limits.block_size,
        )?;
        validate_fec_class_extent(
            "EnvelopeEntry",
            envelope.data_block_count,
            envelope.parity_block_count,
            limits.max_payload_data_shards,
            limits.max_payload_parity_shards,
        )?;
    }
    for pair in envelopes.windows(2) {
        if pair[0].envelope_index >= pair[1].envelope_index {
            return invalid("IndexShard", "EnvelopeEntry rows are not sorted and unique");
        }
    }
    Ok(())
}

fn validate_file_order(
    files: &[FileEntry],
    paths: &[Vec<u8>],
    starts: &[u64],
) -> Result<(), FormatError> {
    for idx in 1..files.len() {
        let previous_key = (
            &files[idx - 1].path_hash,
            paths[idx - 1].as_slice(),
            starts[idx - 1],
        );
        let current_key = (&files[idx].path_hash, paths[idx].as_slice(), starts[idx]);
        if previous_key >= current_key {
            return invalid("IndexShard", "FileEntry rows are not sorted and unique");
        }
    }
    Ok(())
}

fn validate_file_frame_range(
    file: &FileEntry,
    frames: &[FrameEntry],
    frame_by_index: &HashMap<u64, usize>,
) -> Result<(), FormatError> {
    let first = frame_for_file(file, frame_by_index, frames, file.first_frame_index)?;
    if file.offset_in_first_frame_plaintext >= first.decompressed_size {
        return invalid(
            "FileEntry",
            "offset in first frame is outside the first referenced frame",
        );
    }

    let mut bytes_before_last =
        first.decompressed_size as u64 - file.offset_in_first_frame_plaintext as u64;
    if file.frame_count == 1 {
        if file.tar_member_group_size > bytes_before_last {
            return invalid(
                "FileEntry",
                "tar member group exceeds the single referenced frame",
            );
        }
        return Ok(());
    }

    for offset in 1..(file.frame_count as u64 - 1) {
        let frame_index = file.first_frame_index.checked_add(offset).ok_or(
            FormatError::MetadataArithmeticOverflow {
                structure: "FileEntry",
            },
        )?;
        let frame = frame_for_file(file, frame_by_index, frames, frame_index)?;
        bytes_before_last = bytes_before_last
            .checked_add(frame.decompressed_size as u64)
            .ok_or(FormatError::MetadataArithmeticOverflow {
                structure: "FileEntry",
            })?;
    }

    let last_index = file
        .first_frame_index
        .checked_add(file.frame_count as u64 - 1)
        .ok_or(FormatError::MetadataArithmeticOverflow {
            structure: "FileEntry",
        })?;
    let last = frame_for_file(file, frame_by_index, frames, last_index)?;
    let max_size = bytes_before_last
        .checked_add(last.decompressed_size as u64)
        .ok_or(FormatError::MetadataArithmeticOverflow {
            structure: "FileEntry",
        })?;
    if file.tar_member_group_size <= bytes_before_last || file.tar_member_group_size > max_size {
        return invalid("FileEntry", "frame range is not minimal");
    }
    Ok(())
}

fn validate_frame_envelope_binding(
    frame: &FrameEntry,
    envelope: &EnvelopeEntry,
) -> Result<(), FormatError> {
    let envelope_frame_end = envelope
        .first_frame_index
        .checked_add(envelope.frame_count as u64)
        .ok_or(FormatError::MetadataArithmeticOverflow {
            structure: "EnvelopeEntry",
        })?;
    if frame.frame_index < envelope.first_frame_index || frame.frame_index >= envelope_frame_end {
        return invalid("FrameEntry", "frame index is outside envelope frame range");
    }
    let end = frame
        .offset_in_envelope
        .checked_add(frame.compressed_size)
        .ok_or(FormatError::MetadataArithmeticOverflow {
            structure: "FrameEntry",
        })?;
    if end > envelope.plaintext_size {
        return invalid("FrameEntry", "frame slice exceeds envelope plaintext");
    }
    Ok(())
}

fn validate_frame_slices_by_envelope(
    frames: &[FrameEntry],
    envelopes: &[EnvelopeEntry],
) -> Result<(), FormatError> {
    for envelope in envelopes {
        let mut slices = frames
            .iter()
            .filter(|frame| frame.envelope_index == envelope.envelope_index)
            .map(|frame| {
                let end = frame
                    .offset_in_envelope
                    .checked_add(frame.compressed_size)
                    .ok_or(FormatError::MetadataArithmeticOverflow {
                        structure: "FrameEntry",
                    })?;
                Ok((frame.offset_in_envelope, end, frame.frame_index))
            })
            .collect::<Result<Vec<_>, FormatError>>()?;
        slices.sort_unstable_by_key(|slice| (slice.0, slice.2));
        for pair in slices.windows(2) {
            if pair[0].1 > pair[1].0 {
                return invalid("FrameEntry", "frame slices overlap inside an envelope");
            }
        }

        let contains_complete_global_range = (0..envelope.frame_count as u64).all(|offset| {
            envelope
                .first_frame_index
                .checked_add(offset)
                .map(|index| slices.iter().any(|slice| slice.2 == index))
                .unwrap_or(false)
        });
        if contains_complete_global_range {
            let mut cursor = 0u32;
            for (start, end, _) in slices {
                if start != cursor {
                    return invalid("EnvelopeEntry", "complete local envelope has frame gap");
                }
                cursor = end;
            }
            if cursor != envelope.plaintext_size {
                return invalid(
                    "EnvelopeEntry",
                    "complete local envelope does not cover plaintext",
                );
            }
        }
    }
    Ok(())
}

fn validate_directory_hint_entries(
    entries: &[DirectoryHintEntry],
    bytes: &[u8],
    header: &DirectoryHintTableHeader,
    locating_shard: &DirectoryHintShardEntry,
    index_root_shard_count: u32,
) -> Result<usize, FormatError> {
    let structure = "DirectoryHintTable";
    if index_root_shard_count == 0 {
        return invalid(structure, "directory hints require IndexRoot shard rows");
    }
    if entries.is_empty() {
        return invalid(structure, "located directory hint table is empty");
    }
    if entries[0].dir_hash != locating_shard.first_dir_hash {
        return invalid(
            structure,
            "first DirectoryHintEntry hash does not match locating row",
        );
    }
    if entries[entries.len() - 1].dir_hash != locating_shard.last_dir_hash {
        return invalid(
            structure,
            "last DirectoryHintEntry hash does not match locating row",
        );
    }

    let mut max_shard_list_end = 0usize;
    for entry in entries {
        if entry.shard_count == 0 {
            return invalid("DirectoryHintEntry", "shard count is zero");
        }
        let start = entry.shard_list_start_index as usize;
        let end = start.checked_add(entry.shard_count as usize).ok_or(
            FormatError::MetadataArithmeticOverflow {
                structure: "DirectoryHintEntry",
            },
        )?;
        max_shard_list_end = max_shard_list_end.max(end);
    }
    let byte_len = checked_mul(max_shard_list_end, 4, structure)?;
    let shard_list_offset = to_usize(header.shard_list_offset, structure)?;
    let shard_list_end = checked_add(shard_list_offset, byte_len, structure)?;
    if shard_list_end > bytes.len() {
        return invalid(structure, "shard list exceeds plaintext");
    }
    Ok(max_shard_list_end)
}

fn validate_directory_hint_paths_and_lists(
    entries: &[DirectoryHintEntry],
    shard_row_indexes: &[u32],
    string_pool: &[u8],
    locating_shard: &DirectoryHintShardEntry,
    index_root_shard_count: u32,
    max_path_length: u32,
) -> Result<Vec<Vec<u8>>, FormatError> {
    let mut paths = Vec::with_capacity(entries.len());
    let mut seen_paths = HashSet::new();
    for entry in entries {
        let path = if entry.path_length == 0 {
            if entry.path_offset != 0 || entry.dir_hash != hash_prefix(b"") {
                return invalid(
                    "DirectoryHintEntry",
                    "root directory entry is not canonical",
                );
            }
            &[][..]
        } else {
            let path = string_slice(
                string_pool,
                entry.path_offset,
                entry.path_length as u64,
                "DirectoryHintEntry",
            )?;
            validate_directory_path_bytes(path, max_path_length)?;
            path
        };
        if hash_prefix(path) != entry.dir_hash {
            return invalid(
                "DirectoryHintEntry",
                "dir_hash does not match string-pool path",
            );
        }
        if !seen_paths.insert(path.to_vec()) {
            return invalid("DirectoryHintEntry", "duplicate directory path");
        }

        let start = entry.shard_list_start_index as usize;
        let end = start.checked_add(entry.shard_count as usize).ok_or(
            FormatError::MetadataArithmeticOverflow {
                structure: "DirectoryHintEntry",
            },
        )?;
        let rows = shard_row_indexes
            .get(start..end)
            .ok_or(FormatError::InvalidMetadata {
                structure: "DirectoryHintEntry",
                reason: "shard-row-index range is out of bounds",
            })?;
        for pair in rows.windows(2) {
            if pair[0] >= pair[1] {
                return invalid(
                    "DirectoryHintEntry",
                    "shard-row-index list is not sorted and unique",
                );
            }
        }
        if rows.iter().any(|row| *row >= index_root_shard_count) {
            return invalid(
                "DirectoryHintEntry",
                "shard-row-index is outside IndexRoot shard table",
            );
        }
        paths.push(path.to_vec());
    }

    for idx in 1..entries.len() {
        let previous_key = (&entries[idx - 1].dir_hash, paths[idx - 1].as_slice());
        let current_key = (&entries[idx].dir_hash, paths[idx].as_slice());
        if previous_key >= current_key {
            return invalid(
                "DirectoryHintTable",
                "DirectoryHintEntry rows are not sorted and unique",
            );
        }
    }
    if entries[0].dir_hash != locating_shard.first_dir_hash
        || entries[entries.len() - 1].dir_hash != locating_shard.last_dir_hash
    {
        return invalid(
            "DirectoryHintTable",
            "entry hash bounds do not match locating shard",
        );
    }

    Ok(paths)
}

fn candidate_interval_indexes<T>(
    entries: &[T],
    target_hash: [u8; 8],
    scan_cap_per_direction: usize,
    first_hash: impl Fn(&T) -> [u8; 8],
    last_hash: impl Fn(&T) -> [u8; 8],
) -> Result<Vec<usize>, FormatError> {
    if entries.is_empty() {
        return Ok(Vec::new());
    }
    let upper = entries.partition_point(|entry| first_hash(entry) <= target_hash);
    if upper == 0 {
        return Ok(Vec::new());
    }
    let landing = upper - 1;
    if last_hash(&entries[landing]) < target_hash {
        return Ok(Vec::new());
    }

    let mut start = landing;
    let mut left_scanned = 0usize;
    while start > 0
        && first_hash(&entries[start - 1]) <= target_hash
        && last_hash(&entries[start - 1]) >= target_hash
    {
        left_scanned += 1;
        if left_scanned > scan_cap_per_direction {
            return Err(FormatError::HashPrefixCollisionRunExceeded);
        }
        start -= 1;
    }

    let mut end = landing + 1;
    let mut right_scanned = 0usize;
    while end < entries.len()
        && first_hash(&entries[end]) <= target_hash
        && last_hash(&entries[end]) >= target_hash
    {
        right_scanned += 1;
        if right_scanned > scan_cap_per_direction {
            return Err(FormatError::HashPrefixCollisionRunExceeded);
        }
        end += 1;
    }

    Ok((start..end).collect())
}

pub fn validate_file_path_bytes(path: &[u8], max_path_length: u32) -> Result<(), FormatError> {
    if path.is_empty() || path.len() > max_path_length as usize {
        return Err(FormatError::UnsafeArchivePath);
    }
    validate_relative_path(path, false)
}

pub fn validate_directory_path_bytes(path: &[u8], max_path_length: u32) -> Result<(), FormatError> {
    if path.len() > max_path_length as usize {
        return Err(FormatError::UnsafeArchivePath);
    }
    validate_relative_path(path, true)
}

fn validate_relative_path(path: &[u8], allow_empty_root: bool) -> Result<(), FormatError> {
    if path.is_empty() {
        return if allow_empty_root {
            Ok(())
        } else {
            Err(FormatError::UnsafeArchivePath)
        };
    }
    if path.contains(&0) || path.contains(&b'\\') || path.contains(&b':') || path[0] == b'/' {
        return Err(FormatError::UnsafeArchivePath);
    }
    let path_str = std::str::from_utf8(path).map_err(|_| FormatError::UnsafeArchivePath)?;
    if !path_str.nfc().eq(path_str.chars()) {
        return Err(FormatError::UnsafeArchivePath);
    }
    for component in path_str.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(FormatError::UnsafeArchivePath);
        }
        if is_windows_device_component(component) {
            return Err(FormatError::UnsafeArchivePath);
        }
    }
    Ok(())
}

fn is_windows_device_component(component: &str) -> bool {
    let stem = component
        .split('.')
        .next()
        .unwrap_or(component)
        .trim_end_matches([' ', '.']);
    let upper = stem.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "CLOCK$"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "COM\u{00b9}"
            | "COM\u{00b2}"
            | "COM\u{00b3}"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
            | "LPT\u{00b9}"
            | "LPT\u{00b2}"
            | "LPT\u{00b3}"
    )
}

fn validate_encrypted_extent(
    structure: &'static str,
    data_block_count: u32,
    encrypted_size: u32,
    block_size: u32,
) -> Result<(), FormatError> {
    if data_block_count == 0 || encrypted_size == 0 {
        return invalid(structure, "encrypted object has zero data blocks or size");
    }
    let expected = (data_block_count as u64)
        .checked_mul(block_size as u64)
        .ok_or(FormatError::MetadataArithmeticOverflow { structure })?;
    if expected > u32::MAX as u64 || expected != encrypted_size as u64 {
        return invalid(
            structure,
            "encrypted_size is not data_block_count * block_size",
        );
    }
    Ok(())
}

fn validate_fec_class_extent(
    structure: &'static str,
    data_block_count: u32,
    parity_block_count: u32,
    data_shard_max: u16,
    parity_shard_max: u16,
) -> Result<(), FormatError> {
    if data_block_count > data_shard_max as u32 {
        return invalid(structure, "data_block_count exceeds class maximum");
    }
    if parity_block_count > parity_shard_max as u32 {
        return invalid(structure, "parity_block_count exceeds class maximum");
    }
    let total = data_block_count as u64 + parity_block_count as u64;
    if total > REED_SOLOMON_GF16_MAX_TOTAL_SHARDS {
        return invalid(
            structure,
            "data_block_count + parity_block_count exceeds ReedSolomonGF16 limit",
        );
    }
    Ok(())
}

fn frame_for_file<'a>(
    _file: &FileEntry,
    frame_by_index: &HashMap<u64, usize>,
    frames: &'a [FrameEntry],
    frame_index: u64,
) -> Result<&'a FrameEntry, FormatError> {
    frame_by_index
        .get(&frame_index)
        .and_then(|idx| frames.get(*idx))
        .ok_or(FormatError::InvalidMetadata {
            structure: "FileEntry",
            reason: "referenced FrameEntry is missing",
        })
}

struct CountedTableSpec<T> {
    structure: &'static str,
    name: &'static str,
    count: u64,
    offset: u64,
    entry_len: usize,
    parse: fn(&[u8]) -> Result<T, FormatError>,
}

fn parse_counted_table<T>(
    bytes: &[u8],
    spec: CountedTableSpec<T>,
    cursor: &mut usize,
) -> Result<Vec<T>, FormatError> {
    if spec.count == 0 {
        if spec.offset != 0 {
            return invalid(spec.structure, "absent counted table has non-zero offset");
        }
        return Ok(Vec::new());
    }
    expect_offset(spec.structure, spec.name, spec.offset, *cursor)?;
    let count = to_usize(spec.count, spec.structure)?;
    let bytes_len = checked_mul(count, spec.entry_len, spec.structure)?;
    let table = slice(bytes, *cursor, bytes_len, spec.structure)?;
    *cursor = checked_add(*cursor, bytes_len, spec.structure)?;
    table.chunks_exact(spec.entry_len).map(spec.parse).collect()
}

fn parse_u32_array(bytes: &[u8], structure: &'static str) -> Result<Vec<u32>, FormatError> {
    let mut out = Vec::with_capacity(bytes.len() / 4);
    for chunk in bytes.chunks_exact(4) {
        out.push(read_u32(chunk, 0, structure)?);
    }
    Ok(out)
}

fn string_slice<'a>(
    string_pool: &'a [u8],
    offset: u64,
    length: u64,
    structure: &'static str,
) -> Result<&'a [u8], FormatError> {
    let start = to_usize(offset, structure)?;
    let len = to_usize(length, structure)?;
    slice(string_pool, start, len, structure)
}

fn shard_entry_sort_key(entry: &ShardEntry) -> ([u8; 8], [u8; 8], u64) {
    (
        entry.first_path_hash,
        entry.last_path_hash,
        entry.shard_index,
    )
}

fn directory_hint_shard_sort_key(entry: &DirectoryHintShardEntry) -> ([u8; 8], [u8; 8], u64) {
    (
        entry.first_dir_hash,
        entry.last_dir_hash,
        entry.hint_shard_index,
    )
}

fn table_offset(len: usize, cursor: usize) -> u32 {
    if len == 0 {
        0
    } else {
        cursor as u32
    }
}

fn expect_magic(
    structure: &'static str,
    expected: [u8; 4],
    actual: [u8; 4],
) -> Result<(), FormatError> {
    if actual != expected {
        return Err(FormatError::BadMagic { structure });
    }
    Ok(())
}

fn expect_zero(structure: &'static str, bytes: &[u8]) -> Result<(), FormatError> {
    if bytes.iter().any(|byte| *byte != 0) {
        return Err(FormatError::NonZeroReserved { structure });
    }
    Ok(())
}

fn expect_offset(
    structure: &'static str,
    name: &'static str,
    actual: u64,
    expected: usize,
) -> Result<(), FormatError> {
    if actual != expected as u64 {
        return Err(FormatError::InvalidMetadata {
            structure,
            reason: name,
        });
    }
    Ok(())
}

fn slice<'a>(
    bytes: &'a [u8],
    offset: usize,
    len: usize,
    structure: &'static str,
) -> Result<&'a [u8], FormatError> {
    let end = checked_add(offset, len, structure)?;
    bytes.get(offset..end).ok_or(FormatError::InvalidMetadata {
        structure,
        reason: "range is out of bounds",
    })
}

fn read_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
    structure: &'static str,
) -> Result<[u8; N], FormatError> {
    let mut out = [0u8; N];
    out.copy_from_slice(slice(bytes, offset, N, structure)?);
    Ok(out)
}

fn read_u32(bytes: &[u8], offset: usize, structure: &'static str) -> Result<u32, FormatError> {
    let raw = read_array::<4>(bytes, offset, structure)?;
    Ok(u32::from_le_bytes(raw))
}

fn read_u64(bytes: &[u8], offset: usize, structure: &'static str) -> Result<u64, FormatError> {
    let raw = read_array::<8>(bytes, offset, structure)?;
    Ok(u64::from_le_bytes(raw))
}

fn read_i64(bytes: &[u8], offset: usize, structure: &'static str) -> Result<i64, FormatError> {
    let raw = read_array::<8>(bytes, offset, structure)?;
    Ok(i64::from_le_bytes(raw))
}

fn read_u16(bytes: &[u8], offset: usize, structure: &'static str) -> Result<u16, FormatError> {
    let raw = read_array::<2>(bytes, offset, structure)?;
    Ok(u16::from_le_bytes(raw))
}

fn read_u8(bytes: &[u8], offset: usize, structure: &'static str) -> Result<u8, FormatError> {
    let raw = read_array::<1>(bytes, offset, structure)?;
    Ok(u8::from_le_bytes(raw))
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn write_i64(bytes: &mut [u8], offset: usize, value: i64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u8(bytes: &mut [u8], offset: usize, value: u8) {
    bytes[offset..offset + 1].copy_from_slice(&value.to_le_bytes());
}

fn checked_add(lhs: usize, rhs: usize, structure: &'static str) -> Result<usize, FormatError> {
    lhs.checked_add(rhs)
        .ok_or(FormatError::MetadataArithmeticOverflow { structure })
}

fn checked_mul(lhs: usize, rhs: usize, structure: &'static str) -> Result<usize, FormatError> {
    lhs.checked_mul(rhs)
        .ok_or(FormatError::MetadataArithmeticOverflow { structure })
}

fn to_usize(value: u64, structure: &'static str) -> Result<usize, FormatError> {
    usize::try_from(value).map_err(|_| FormatError::MetadataArithmeticOverflow { structure })
}

fn invalid<T>(structure: &'static str, reason: &'static str) -> Result<T, FormatError> {
    Err(FormatError::InvalidMetadata { structure, reason })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_reader_caps_match_v41() {
        let limits = MetadataLimits::default();
        assert_eq!(limits.max_shard_count, 1_000_000);
        assert_eq!(limits.max_directory_hint_shards, 1_000_000);
        assert_eq!(limits.max_files_per_index_shard, 1_000_000);
        assert_eq!(limits.max_entries_per_directory_hint_shard, 1_000_000);
        assert_eq!(limits.max_hash_collision_shard_scan, 16);
    }

    #[test]
    fn index_root_rejects_shard_extent_above_crypto_header_class_limits() {
        let path_hash = hash_prefix(b"a.txt");
        let root = IndexRoot {
            header: IndexRootHeader {
                file_count: 1,
                ..IndexRootHeader::empty()
            },
            shards: vec![ShardEntry {
                shard_index: 0,
                first_block_index: 1,
                data_block_count: 1,
                parity_block_count: 2,
                encrypted_size: 4096,
                decompressed_size: 64,
                file_count: 1,
                first_path_hash: path_hash,
                last_path_hash: path_hash,
            }],
            directory_hint_shards: Vec::new(),
        };
        let limits = MetadataLimits {
            max_index_parity_shards: 1,
            ..MetadataLimits::default()
        };

        assert_eq!(
            IndexRoot::parse(&root.to_bytes(), false, limits).unwrap_err(),
            FormatError::InvalidMetadata {
                structure: "ShardEntry",
                reason: "parity_block_count exceeds class maximum",
            }
        );
    }

    #[test]
    fn metadata_fec_extent_rejects_reed_solomon_total_overflow() {
        assert_eq!(
            validate_fec_class_extent("EnvelopeEntry", 65_535, 1, u16::MAX, u16::MAX).unwrap_err(),
            FormatError::InvalidMetadata {
                structure: "EnvelopeEntry",
                reason: "data_block_count + parity_block_count exceeds ReedSolomonGF16 limit",
            }
        );
    }

    #[test]
    fn parses_valid_empty_index_root() {
        let root = IndexRoot {
            header: IndexRootHeader::empty(),
            shards: Vec::new(),
            directory_hint_shards: Vec::new(),
        };

        let bytes = root.to_bytes();
        let parsed = IndexRoot::parse(&bytes, false, MetadataLimits::default()).unwrap();

        assert_eq!(parsed.header.file_count, 0);
        assert!(parsed.shards.is_empty());
        assert!(parsed.directory_hint_shards.is_empty());
    }

    #[test]
    fn index_root_rejects_nonzero_offsets_for_absent_counted_tables() {
        let mut root = IndexRoot {
            header: IndexRootHeader::empty(),
            shards: Vec::new(),
            directory_hint_shards: Vec::new(),
        };

        let mut bytes = root.to_bytes();
        write_u64(&mut bytes, 88, INDEX_ROOT_LEN as u64);
        assert_eq!(
            IndexRoot::parse(&bytes, false, MetadataLimits::default()).unwrap_err(),
            FormatError::InvalidMetadata {
                structure: "IndexRoot",
                reason: "absent shard table has non-zero offset",
            }
        );

        root.header.file_count = 1;
        root.shards.push(ShardEntry {
            shard_index: 0,
            first_block_index: 1,
            data_block_count: 1,
            parity_block_count: 0,
            encrypted_size: 4096,
            decompressed_size: 128,
            file_count: 1,
            first_path_hash: hash_prefix(b"a.txt"),
            last_path_hash: hash_prefix(b"a.txt"),
        });
        let mut bytes = root.to_bytes();
        write_u64(&mut bytes, 96, (INDEX_ROOT_LEN + SHARD_ENTRY_LEN) as u64);
        assert_eq!(
            IndexRoot::parse(&bytes, false, MetadataLimits::default()).unwrap_err(),
            FormatError::InvalidMetadata {
                structure: "IndexRoot",
                reason: "absent directory hint shard table has non-zero offset",
            }
        );
    }

    #[test]
    fn index_root_rejects_has_dictionary_with_zero_dictionary_fields() {
        let root = IndexRoot {
            header: IndexRootHeader::empty(),
            shards: Vec::new(),
            directory_hint_shards: Vec::new(),
        };

        assert_eq!(
            IndexRoot::parse(&root.to_bytes(), true, MetadataLimits::default()).unwrap_err(),
            FormatError::InvalidMetadata {
                structure: "IndexRoot",
                reason: "dictionary data block count is zero while has_dictionary is true",
            }
        );
    }

    #[test]
    fn index_root_rejects_empty_archive_with_dictionary_extent() {
        let root = IndexRoot {
            header: IndexRootHeader {
                dictionary_first_block: 1,
                dictionary_data_block_count: 1,
                dictionary_encrypted_size: 4096,
                dictionary_decompressed_size: 16,
                ..IndexRootHeader::empty()
            },
            shards: Vec::new(),
            directory_hint_shards: Vec::new(),
        };

        assert_eq!(
            IndexRoot::parse(&root.to_bytes(), true, MetadataLimits::default()).unwrap_err(),
            FormatError::InvalidMetadata {
                structure: "IndexRoot",
                reason: "empty archive cannot use dictionary",
            }
        );
    }

    #[test]
    fn encrypted_object_extents_reject_zero_data_or_size_for_all_metadata_rows() {
        assert_eq!(
            validate_encrypted_extent("ManifestFooter.IndexRoot", 0, 4096, 4096).unwrap_err(),
            FormatError::InvalidMetadata {
                structure: "ManifestFooter.IndexRoot",
                reason: "encrypted object has zero data blocks or size",
            }
        );
        assert_eq!(
            validate_encrypted_extent("EnvelopeEntry", 1, 0, 4096).unwrap_err(),
            FormatError::InvalidMetadata {
                structure: "EnvelopeEntry",
                reason: "encrypted object has zero data blocks or size",
            }
        );

        let path_hash = hash_prefix(b"a.txt");
        let mut root = IndexRoot {
            header: IndexRootHeader {
                file_count: 1,
                ..IndexRootHeader::empty()
            },
            shards: vec![ShardEntry {
                shard_index: 0,
                first_block_index: 1,
                data_block_count: 0,
                parity_block_count: 0,
                encrypted_size: 4096,
                decompressed_size: 128,
                file_count: 1,
                first_path_hash: path_hash,
                last_path_hash: path_hash,
            }],
            directory_hint_shards: Vec::new(),
        };
        assert_eq!(
            IndexRoot::parse(&root.to_bytes(), false, MetadataLimits::default()).unwrap_err(),
            FormatError::InvalidMetadata {
                structure: "ShardEntry",
                reason: "encrypted object has zero data blocks or size",
            }
        );

        root.shards[0].data_block_count = 1;
        root.shards[0].encrypted_size = 4096;
        root.directory_hint_shards.push(DirectoryHintShardEntry {
            hint_shard_index: 0,
            first_dir_hash: hash_prefix(b""),
            last_dir_hash: hash_prefix(b""),
            first_block_index: 2,
            data_block_count: 1,
            parity_block_count: 0,
            encrypted_size: 0,
            decompressed_size: 72,
            entry_count: 1,
        });
        assert_eq!(
            IndexRoot::parse(&root.to_bytes(), false, MetadataLimits::default()).unwrap_err(),
            FormatError::InvalidMetadata {
                structure: "DirectoryHintShardEntry",
                reason: "encrypted object has zero data blocks or size",
            }
        );

        let mut dict_root = IndexRoot {
            header: IndexRootHeader {
                file_count: 1,
                dictionary_first_block: 10,
                dictionary_data_block_count: 0,
                dictionary_parity_block_count: 0,
                dictionary_encrypted_size: 4096,
                dictionary_decompressed_size: 32,
                ..IndexRootHeader::empty()
            },
            shards: vec![ShardEntry {
                shard_index: 0,
                first_block_index: 1,
                data_block_count: 1,
                parity_block_count: 0,
                encrypted_size: 4096,
                decompressed_size: 128,
                file_count: 1,
                first_path_hash: path_hash,
                last_path_hash: path_hash,
            }],
            directory_hint_shards: Vec::new(),
        };
        assert_eq!(
            IndexRoot::parse(&dict_root.to_bytes(), true, MetadataLimits::default()).unwrap_err(),
            FormatError::InvalidMetadata {
                structure: "IndexRoot",
                reason: "dictionary data block count is zero while has_dictionary is true",
            }
        );
        dict_root.header.dictionary_data_block_count = 1;
        dict_root.header.dictionary_encrypted_size = 0;
        assert_eq!(
            IndexRoot::parse(&dict_root.to_bytes(), true, MetadataLimits::default()).unwrap_err(),
            FormatError::InvalidMetadata {
                structure: "IndexRoot",
                reason: "required dictionary field is zero",
            }
        );
    }

    #[test]
    fn index_root_rejects_dictionary_fields_when_crypto_header_has_no_dictionary() {
        let mut root = IndexRoot {
            header: IndexRootHeader::empty(),
            shards: Vec::new(),
            directory_hint_shards: Vec::new(),
        };
        root.header.dictionary_first_block = 1;
        root.header.dictionary_data_block_count = 1;
        root.header.dictionary_encrypted_size = 4096;
        root.header.dictionary_decompressed_size = 16;

        assert_eq!(
            IndexRoot::parse(&root.to_bytes(), false, MetadataLimits::default()).unwrap_err(),
            FormatError::InvalidMetadata {
                structure: "IndexRoot",
                reason: "dictionary fields are non-zero while has_dictionary is false",
            }
        );
    }

    #[test]
    fn rejects_directory_hint_rows_sorted_by_old_v36_key_only() {
        let h = [0x10; 8];
        let z = [0x20; 8];
        let root = IndexRoot {
            header: IndexRootHeader {
                file_count: 1,
                ..IndexRootHeader::empty()
            },
            shards: vec![ShardEntry {
                shard_index: 0,
                first_block_index: 0,
                data_block_count: 1,
                parity_block_count: 1,
                encrypted_size: 4096,
                decompressed_size: 64,
                file_count: 1,
                first_path_hash: h,
                last_path_hash: z,
            }],
            directory_hint_shards: vec![
                DirectoryHintShardEntry {
                    hint_shard_index: 0,
                    first_dir_hash: h,
                    last_dir_hash: z,
                    first_block_index: 10,
                    data_block_count: 1,
                    parity_block_count: 1,
                    encrypted_size: 4096,
                    decompressed_size: 72,
                    entry_count: 1,
                },
                DirectoryHintShardEntry {
                    hint_shard_index: 1,
                    first_dir_hash: h,
                    last_dir_hash: h,
                    first_block_index: 12,
                    data_block_count: 1,
                    parity_block_count: 1,
                    encrypted_size: 4096,
                    decompressed_size: 72,
                    entry_count: 1,
                },
            ],
        };

        assert_eq!(
            IndexRoot::parse(&root.to_bytes(), false, MetadataLimits::default()).unwrap_err(),
            FormatError::InvalidMetadata {
                structure: "IndexRoot",
                reason: "DirectoryHintShardEntry rows are not sorted"
            }
        );
    }

    #[test]
    fn directory_hint_shard_count_cap_is_independent_from_index_shard_cap() {
        let path_hash = hash_prefix(b"a.txt");
        let dir_hash = hash_prefix(b"");
        let root = IndexRoot {
            header: IndexRootHeader {
                file_count: 1,
                ..IndexRootHeader::empty()
            },
            shards: vec![ShardEntry {
                shard_index: 0,
                first_block_index: 1,
                data_block_count: 1,
                parity_block_count: 0,
                encrypted_size: 4096,
                decompressed_size: 128,
                file_count: 1,
                first_path_hash: path_hash,
                last_path_hash: path_hash,
            }],
            directory_hint_shards: vec![DirectoryHintShardEntry {
                hint_shard_index: 0,
                first_dir_hash: dir_hash,
                last_dir_hash: dir_hash,
                first_block_index: 2,
                data_block_count: 1,
                parity_block_count: 0,
                encrypted_size: 4096,
                decompressed_size: 72,
                entry_count: 1,
            }],
        };
        let limits = MetadataLimits {
            max_shard_count: 1,
            max_directory_hint_shards: 1,
            ..MetadataLimits::default()
        };
        IndexRoot::parse(&root.to_bytes(), false, limits).unwrap();

        let rejecting_limits = MetadataLimits {
            max_directory_hint_shards: 0,
            ..limits
        };
        assert_eq!(
            IndexRoot::parse(&root.to_bytes(), false, rejecting_limits).unwrap_err(),
            FormatError::InvalidMetadata {
                structure: "IndexRoot",
                reason: "directory hint shard count exceeds resource cap",
            }
        );
    }

    #[test]
    fn directory_hint_paths_obey_configured_max_path_length() {
        let path = b"toolong".to_vec();
        let table = DirectoryHintTable {
            header: DirectoryHintTableHeader {
                version: 1,
                hint_shard_index: 0,
                entry_count: 0,
                entry_table_offset: 0,
                shard_list_offset: 0,
                string_pool_offset: 0,
                string_pool_size: 0,
            },
            entries: vec![DirectoryHintEntry {
                dir_hash: hash_prefix(&path),
                path_offset: 0,
                path_length: path.len() as u32,
                shard_list_start_index: 0,
                shard_count: 1,
            }],
            shard_row_indexes: vec![0],
            string_pool: path.clone(),
            entry_paths: vec![path.clone()],
        };
        let bytes = table.to_bytes();
        let locating = DirectoryHintShardEntry {
            hint_shard_index: 0,
            first_dir_hash: hash_prefix(&path),
            last_dir_hash: hash_prefix(&path),
            first_block_index: 0,
            data_block_count: 1,
            parity_block_count: 0,
            encrypted_size: 4096,
            decompressed_size: bytes.len() as u32,
            entry_count: 1,
        };
        let limits = MetadataLimits {
            max_path_length: 3,
            ..MetadataLimits::default()
        };

        assert_eq!(
            DirectoryHintTable::parse(&bytes, &locating, 1, limits).unwrap_err(),
            FormatError::UnsafeArchivePath
        );
    }

    #[test]
    fn directory_hint_table_rejects_wrong_hint_shard_identity() {
        let path = b"dir".to_vec();
        let table = DirectoryHintTable {
            header: DirectoryHintTableHeader {
                version: 1,
                hint_shard_index: 5,
                entry_count: 0,
                entry_table_offset: 0,
                shard_list_offset: 0,
                string_pool_offset: 0,
                string_pool_size: 0,
            },
            entries: vec![DirectoryHintEntry {
                dir_hash: hash_prefix(&path),
                path_offset: 0,
                path_length: path.len() as u32,
                shard_list_start_index: 0,
                shard_count: 1,
            }],
            shard_row_indexes: vec![0],
            string_pool: path.clone(),
            entry_paths: vec![path.clone()],
        };
        let bytes = table.to_bytes();
        let locating = DirectoryHintShardEntry {
            hint_shard_index: 6,
            first_dir_hash: hash_prefix(&path),
            last_dir_hash: hash_prefix(&path),
            first_block_index: 0,
            data_block_count: 1,
            parity_block_count: 0,
            encrypted_size: 4096,
            decompressed_size: bytes.len() as u32,
            entry_count: 1,
        };

        assert_eq!(
            DirectoryHintTable::parse(&bytes, &locating, 1, MetadataLimits::default()).unwrap_err(),
            FormatError::InvalidMetadata {
                structure: "DirectoryHintTable",
                reason: "hint shard index does not match locating DirectoryHintShardEntry",
            }
        );
    }

    #[test]
    fn directory_hint_table_rejects_empty_shard_lists() {
        let path = b"dir".to_vec();
        let table = DirectoryHintTable {
            header: DirectoryHintTableHeader {
                version: 1,
                hint_shard_index: 0,
                entry_count: 0,
                entry_table_offset: 0,
                shard_list_offset: 0,
                string_pool_offset: 0,
                string_pool_size: 0,
            },
            entries: vec![DirectoryHintEntry {
                dir_hash: hash_prefix(&path),
                path_offset: 0,
                path_length: path.len() as u32,
                shard_list_start_index: 0,
                shard_count: 0,
            }],
            shard_row_indexes: Vec::new(),
            string_pool: path.clone(),
            entry_paths: vec![path.clone()],
        };
        let bytes = table.to_bytes();
        let locating = DirectoryHintShardEntry {
            hint_shard_index: 0,
            first_dir_hash: hash_prefix(&path),
            last_dir_hash: hash_prefix(&path),
            first_block_index: 0,
            data_block_count: 1,
            parity_block_count: 0,
            encrypted_size: 4096,
            decompressed_size: bytes.len() as u32,
            entry_count: 1,
        };

        assert_eq!(
            DirectoryHintTable::parse(&bytes, &locating, 1, MetadataLimits::default()).unwrap_err(),
            FormatError::InvalidMetadata {
                structure: "DirectoryHintEntry",
                reason: "shard count is zero",
            }
        );
    }

    #[test]
    fn index_shard_rejects_unsupported_version_and_zero_count_pointer_offsets() {
        let path = b"file.txt";
        let path_hash = hash_prefix(path);
        let file = FileEntry {
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
        };
        let frame = FrameEntry {
            frame_index: 0,
            envelope_index: 0,
            offset_in_envelope: 0,
            compressed_size: 128,
            decompressed_size: 1536,
            flags: 0,
            tar_stream_offset: 0,
        };
        let envelope = EnvelopeEntry {
            envelope_index: 0,
            first_block_index: 0,
            data_block_count: 1,
            parity_block_count: 0,
            encrypted_size: 4096,
            plaintext_size: 128,
            first_frame_index: 0,
            frame_count: 1,
        };
        let shard = IndexShard {
            header: IndexShardHeader {
                version: 1,
                shard_index: 7,
                file_count: 0,
                frame_count: 0,
                envelope_count: 0,
                file_table_offset: 0,
                frame_table_offset: 0,
                envelope_table_offset: 0,
                string_pool_offset: 0,
                string_pool_size: 0,
            },
            files: vec![file],
            frames: vec![frame],
            envelopes: vec![envelope],
            string_pool: path.to_vec(),
            file_paths: Vec::new(),
            file_tar_member_group_starts: Vec::new(),
        };
        let locating = ShardEntry {
            shard_index: 7,
            first_block_index: 10,
            data_block_count: 1,
            parity_block_count: 0,
            encrypted_size: 4096,
            decompressed_size: shard.to_bytes().len() as u32,
            file_count: 1,
            first_path_hash: path_hash,
            last_path_hash: path_hash,
        };

        let mut unsupported_version = shard.to_bytes();
        write_u32(&mut unsupported_version, 4, 3);
        assert_eq!(
            IndexShard::parse(&unsupported_version, &locating, MetadataLimits::default())
                .unwrap_err(),
            FormatError::InvalidMetadata {
                structure: "IndexShard",
                reason: "unsupported version",
            }
        );

        let mut nonzero_zero_frame_table = shard.to_bytes();
        write_u32(&mut nonzero_zero_frame_table, 20, 0);
        write_u32(
            &mut nonzero_zero_frame_table,
            32,
            INDEX_SHARD_HEADER_LEN as u32,
        );
        assert_eq!(
            IndexShard::parse(
                &nonzero_zero_frame_table,
                &locating,
                MetadataLimits::default()
            )
            .unwrap_err(),
            FormatError::InvalidMetadata {
                structure: "IndexShard",
                reason: "absent counted table has non-zero offset",
            }
        );

        let mut nonzero_zero_envelope_table = shard.to_bytes();
        write_u32(&mut nonzero_zero_envelope_table, 24, 0);
        write_u32(
            &mut nonzero_zero_envelope_table,
            36,
            (INDEX_SHARD_HEADER_LEN + FILE_ENTRY_LEN + FRAME_ENTRY_LEN) as u32,
        );
        assert_eq!(
            IndexShard::parse(
                &nonzero_zero_envelope_table,
                &locating,
                MetadataLimits::default()
            )
            .unwrap_err(),
            FormatError::InvalidMetadata {
                structure: "IndexShard",
                reason: "absent counted table has non-zero offset",
            }
        );
    }

    #[test]
    fn directory_hint_table_rejects_zero_count_nonzero_offsets() {
        let path = b"dir".to_vec();
        let table = DirectoryHintTable {
            header: DirectoryHintTableHeader {
                version: 1,
                hint_shard_index: 5,
                entry_count: 0,
                entry_table_offset: 0,
                shard_list_offset: 0,
                string_pool_offset: 0,
                string_pool_size: 0,
            },
            entries: vec![DirectoryHintEntry {
                dir_hash: hash_prefix(&path),
                path_offset: 0,
                path_length: path.len() as u32,
                shard_list_start_index: 0,
                shard_count: 1,
            }],
            shard_row_indexes: vec![0],
            string_pool: path.clone(),
            entry_paths: vec![path.clone()],
        };
        let locating = DirectoryHintShardEntry {
            hint_shard_index: 5,
            first_dir_hash: hash_prefix(&path),
            last_dir_hash: hash_prefix(&path),
            first_block_index: 0,
            data_block_count: 1,
            parity_block_count: 0,
            encrypted_size: 4096,
            decompressed_size: table.to_bytes().len() as u32,
            entry_count: 1,
        };
        let mut bytes = table.to_bytes();
        let bytes_len = bytes.len() as u64;
        write_u64(&mut bytes, 48, 0);
        write_u64(&mut bytes, 40, bytes_len);

        assert_eq!(
            DirectoryHintTable::parse(&bytes, &locating, 1, MetadataLimits::default()).unwrap_err(),
            FormatError::InvalidMetadata {
                structure: "DirectoryHintTable",
                reason: "absent string pool has non-zero offset",
            }
        );
    }

    #[test]
    fn index_shard_rejects_non_exact_local_frame_and_envelope_tables() {
        let path = b"exact-local.txt";
        let path_hash = hash_prefix(path);
        let file = FileEntry {
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
        };
        let frame = FrameEntry {
            frame_index: 0,
            envelope_index: 0,
            offset_in_envelope: 0,
            compressed_size: 128,
            decompressed_size: 1536,
            flags: 0,
            tar_stream_offset: 0,
        };
        let envelope = EnvelopeEntry {
            envelope_index: 0,
            first_block_index: 10,
            data_block_count: 1,
            parity_block_count: 0,
            encrypted_size: 4096,
            plaintext_size: 128,
            first_frame_index: 0,
            frame_count: 1,
        };
        let shard = IndexShard {
            header: IndexShardHeader {
                version: 1,
                shard_index: 3,
                file_count: 0,
                frame_count: 0,
                envelope_count: 0,
                file_table_offset: 0,
                frame_table_offset: 0,
                envelope_table_offset: 0,
                string_pool_offset: 0,
                string_pool_size: 0,
            },
            files: vec![file.clone()],
            frames: vec![frame.clone()],
            envelopes: vec![envelope.clone()],
            string_pool: path.to_vec(),
            file_paths: Vec::new(),
            file_tar_member_group_starts: Vec::new(),
        };
        let locating = ShardEntry {
            shard_index: 3,
            first_block_index: 20,
            data_block_count: 1,
            parity_block_count: 0,
            encrypted_size: 4096,
            decompressed_size: shard.to_bytes().len() as u32,
            file_count: 1,
            first_path_hash: path_hash,
            last_path_hash: path_hash,
        };
        IndexShard::parse(&shard.to_bytes(), &locating, MetadataLimits::default()).unwrap();

        let parse_with = |frames: Vec<FrameEntry>, envelopes: Vec<EnvelopeEntry>| {
            let mut mutated = shard.clone();
            mutated.frames = frames;
            mutated.envelopes = envelopes;
            let bytes = mutated.to_bytes();
            let locating = ShardEntry {
                decompressed_size: bytes.len() as u32,
                ..locating.clone()
            };
            IndexShard::parse(&bytes, &locating, MetadataLimits::default()).unwrap_err()
        };

        let mut missing_frame = frame.clone();
        missing_frame.frame_index = 1;
        assert_eq!(
            parse_with(vec![missing_frame], vec![envelope.clone()]),
            FormatError::InvalidMetadata {
                structure: "FileEntry",
                reason: "referenced FrameEntry is missing",
            }
        );

        let mut unreferenced_frame = frame.clone();
        unreferenced_frame.frame_index = 9;
        unreferenced_frame.tar_stream_offset = 3072;
        assert_eq!(
            parse_with(
                vec![frame.clone(), unreferenced_frame],
                vec![envelope.clone()]
            ),
            FormatError::InvalidMetadata {
                structure: "IndexShard",
                reason: "FrameEntry table is not the exact set referenced by FileEntry rows",
            }
        );

        assert_eq!(
            parse_with(vec![frame.clone(), frame.clone()], vec![envelope.clone()]),
            FormatError::InvalidMetadata {
                structure: "IndexShard",
                reason: "FrameEntry rows are not sorted and unique",
            }
        );

        let mut missing_envelope = envelope.clone();
        missing_envelope.envelope_index = 1;
        assert_eq!(
            parse_with(vec![frame.clone()], vec![missing_envelope]),
            FormatError::InvalidMetadata {
                structure: "FrameEntry",
                reason: "referenced EnvelopeEntry is missing",
            }
        );

        let mut unreferenced_envelope = envelope.clone();
        unreferenced_envelope.envelope_index = 9;
        unreferenced_envelope.first_block_index = 11;
        unreferenced_envelope.first_frame_index = 9;
        assert_eq!(
            parse_with(
                vec![frame.clone()],
                vec![envelope.clone(), unreferenced_envelope]
            ),
            FormatError::InvalidMetadata {
                structure: "IndexShard",
                reason: "EnvelopeEntry table is not the exact set referenced by FrameEntry rows",
            }
        );

        assert_eq!(
            parse_with(vec![frame], vec![envelope.clone(), envelope]),
            FormatError::InvalidMetadata {
                structure: "IndexShard",
                reason: "EnvelopeEntry rows are not sorted and unique",
            }
        );
    }

    #[test]
    fn metadata_parsers_reject_malformed_buffer_corpus() {
        let limits = MetadataLimits::default();
        let path = b"file.txt";
        let path_hash = hash_prefix(path);
        let shard_entry = ShardEntry {
            shard_index: 0,
            first_block_index: 1,
            data_block_count: 1,
            parity_block_count: 0,
            encrypted_size: 4096,
            decompressed_size: 0,
            file_count: 1,
            first_path_hash: path_hash,
            last_path_hash: path_hash,
        };

        let root = IndexRoot {
            header: IndexRootHeader {
                file_count: 1,
                frame_count: 1,
                envelope_count: 1,
                payload_block_count: 1,
                tar_total_size: 512,
                ..IndexRootHeader::empty()
            },
            shards: vec![ShardEntry {
                decompressed_size: 256,
                ..shard_entry.clone()
            }],
            directory_hint_shards: Vec::new(),
        };
        let root_bytes = root.to_bytes();
        IndexRoot::parse(&root_bytes, false, limits).unwrap();

        assert_eq!(
            IndexRoot::parse(&root_bytes[..INDEX_ROOT_LEN - 1], false, limits).unwrap_err(),
            FormatError::InvalidMetadata {
                structure: "IndexRoot",
                reason: "plaintext is shorter than fixed header",
            }
        );
        let mut bad_root = root_bytes.clone();
        bad_root[0] ^= 1;
        assert_eq!(
            IndexRoot::parse(&bad_root, false, limits).unwrap_err(),
            FormatError::BadMagic {
                structure: "IndexRoot"
            }
        );
        let mut bad_root = root_bytes.clone();
        write_u32(&mut bad_root, 4, 2);
        assert_eq!(
            IndexRoot::parse(&bad_root, false, limits).unwrap_err(),
            FormatError::InvalidMetadata {
                structure: "IndexRoot",
                reason: "unsupported version",
            }
        );
        let mut bad_root = root_bytes.clone();
        bad_root[128] = 1;
        assert_eq!(
            IndexRoot::parse(&bad_root, false, limits).unwrap_err(),
            FormatError::NonZeroReserved {
                structure: "IndexRoot"
            }
        );
        let mut bad_root = root_bytes.clone();
        write_u64(&mut bad_root, 88, (INDEX_ROOT_LEN + 1) as u64);
        assert_eq!(
            IndexRoot::parse(&bad_root, false, limits).unwrap_err(),
            FormatError::InvalidMetadata {
                structure: "IndexRoot",
                reason: "shard table",
            }
        );
        assert_eq!(
            IndexRoot::parse(&root_bytes[..root_bytes.len() - 1], false, limits).unwrap_err(),
            FormatError::InvalidMetadata {
                structure: "IndexRoot",
                reason: "range is out of bounds",
            }
        );
        let mut bad_root = root_bytes.clone();
        bad_root.push(0);
        assert_eq!(
            IndexRoot::parse(&bad_root, false, limits).unwrap_err(),
            FormatError::InvalidMetadata {
                structure: "IndexRoot",
                reason: "plaintext length does not match canonical cursor",
            }
        );

        let file = FileEntry {
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
        };
        let frame = FrameEntry {
            frame_index: 0,
            envelope_index: 0,
            offset_in_envelope: 0,
            compressed_size: 128,
            decompressed_size: 1536,
            flags: 0x0000_0003,
            tar_stream_offset: 0,
        };
        let envelope = EnvelopeEntry {
            envelope_index: 0,
            first_block_index: 1,
            data_block_count: 1,
            parity_block_count: 0,
            encrypted_size: 4096,
            plaintext_size: 128,
            first_frame_index: 0,
            frame_count: 1,
        };
        let shard = IndexShard {
            header: IndexShardHeader {
                version: 1,
                shard_index: 0,
                file_count: 0,
                frame_count: 0,
                envelope_count: 0,
                file_table_offset: 0,
                frame_table_offset: 0,
                envelope_table_offset: 0,
                string_pool_offset: 0,
                string_pool_size: 0,
            },
            files: vec![file],
            frames: vec![frame],
            envelopes: vec![envelope],
            string_pool: path.to_vec(),
            file_paths: Vec::new(),
            file_tar_member_group_starts: Vec::new(),
        };
        let shard_bytes = shard.to_bytes();
        let locating = ShardEntry {
            decompressed_size: shard_bytes.len() as u32,
            ..shard_entry
        };
        IndexShard::parse(&shard_bytes, &locating, limits).unwrap();

        assert_eq!(
            IndexShard::parse(
                &shard_bytes[..INDEX_SHARD_HEADER_LEN - 1],
                &locating,
                limits
            )
            .unwrap_err(),
            FormatError::InvalidMetadata {
                structure: "IndexShard",
                reason: "plaintext is shorter than fixed header",
            }
        );
        let mut bad_shard = shard_bytes.clone();
        bad_shard[0] ^= 1;
        assert_eq!(
            IndexShard::parse(&bad_shard, &locating, limits).unwrap_err(),
            FormatError::BadMagic {
                structure: "IndexShard"
            }
        );
        let mut bad_shard = shard_bytes.clone();
        bad_shard[48] = 1;
        assert_eq!(
            IndexShard::parse(&bad_shard, &locating, limits).unwrap_err(),
            FormatError::NonZeroReserved {
                structure: "IndexShard"
            }
        );
        let mut bad_shard = shard_bytes.clone();
        write_u32(&mut bad_shard, 28, INDEX_SHARD_HEADER_LEN as u32 + 1);
        assert_eq!(
            IndexShard::parse(&bad_shard, &locating, limits).unwrap_err(),
            FormatError::InvalidMetadata {
                structure: "IndexShard",
                reason: "file table",
            }
        );
        assert_eq!(
            IndexShard::parse(&shard_bytes[..shard_bytes.len() - 1], &locating, limits)
                .unwrap_err(),
            FormatError::InvalidMetadata {
                structure: "IndexShard",
                reason: "range is out of bounds",
            }
        );
        let mut bad_shard = shard_bytes.clone();
        bad_shard.push(0);
        assert_eq!(
            IndexShard::parse(&bad_shard, &locating, limits).unwrap_err(),
            FormatError::InvalidMetadata {
                structure: "IndexShard",
                reason: "plaintext length does not match canonical cursor",
            }
        );

        let dir_path = b"dir".to_vec();
        let dir_hash = hash_prefix(&dir_path);
        let table = DirectoryHintTable {
            header: DirectoryHintTableHeader {
                version: 1,
                hint_shard_index: 0,
                entry_count: 0,
                entry_table_offset: 0,
                shard_list_offset: 0,
                string_pool_offset: 0,
                string_pool_size: 0,
            },
            entries: vec![DirectoryHintEntry {
                dir_hash,
                path_offset: 0,
                path_length: dir_path.len() as u32,
                shard_list_start_index: 0,
                shard_count: 1,
            }],
            shard_row_indexes: vec![0],
            string_pool: dir_path.clone(),
            entry_paths: Vec::new(),
        };
        let table_bytes = table.to_bytes();
        let locating_hint = DirectoryHintShardEntry {
            hint_shard_index: 0,
            first_dir_hash: dir_hash,
            last_dir_hash: dir_hash,
            first_block_index: 2,
            data_block_count: 1,
            parity_block_count: 0,
            encrypted_size: 4096,
            decompressed_size: table_bytes.len() as u32,
            entry_count: 1,
        };
        DirectoryHintTable::parse(&table_bytes, &locating_hint, 1, limits).unwrap();

        assert_eq!(
            DirectoryHintTable::parse(
                &table_bytes[..DIRECTORY_HINT_TABLE_LEN - 1],
                &locating_hint,
                1,
                limits,
            )
            .unwrap_err(),
            FormatError::InvalidMetadata {
                structure: "DirectoryHintTable",
                reason: "plaintext is shorter than fixed header",
            }
        );
        let mut bad_table = table_bytes.clone();
        bad_table[0] ^= 1;
        assert_eq!(
            DirectoryHintTable::parse(&bad_table, &locating_hint, 1, limits).unwrap_err(),
            FormatError::BadMagic {
                structure: "DirectoryHintTable"
            }
        );
        let mut bad_table = table_bytes.clone();
        bad_table[56] = 1;
        assert_eq!(
            DirectoryHintTable::parse(&bad_table, &locating_hint, 1, limits).unwrap_err(),
            FormatError::NonZeroReserved {
                structure: "DirectoryHintTable"
            }
        );
        let mut bad_table = table_bytes.clone();
        write_u64(&mut bad_table, 24, DIRECTORY_HINT_TABLE_LEN as u64 + 1);
        assert_eq!(
            DirectoryHintTable::parse(&bad_table, &locating_hint, 1, limits).unwrap_err(),
            FormatError::InvalidMetadata {
                structure: "DirectoryHintTable",
                reason: "entry table",
            }
        );
        assert_eq!(
            DirectoryHintTable::parse(
                &table_bytes[..table_bytes.len() - 1],
                &locating_hint,
                1,
                limits
            )
            .unwrap_err(),
            FormatError::InvalidMetadata {
                structure: "DirectoryHintTable",
                reason: "range is out of bounds",
            }
        );
        let mut bad_table = table_bytes.clone();
        bad_table.push(0);
        assert_eq!(
            DirectoryHintTable::parse(&bad_table, &locating_hint, 1, limits).unwrap_err(),
            FormatError::InvalidMetadata {
                structure: "DirectoryHintTable",
                reason: "plaintext length does not match canonical cursor",
            }
        );
    }

    #[test]
    fn candidate_path_lookup_uses_supplied_collision_cap() {
        let path = b"same-prefix.txt";
        let hash = hash_prefix(path);
        let root = IndexRoot {
            header: IndexRootHeader::empty(),
            shards: (0..3)
                .map(|idx| ShardEntry {
                    shard_index: idx,
                    first_block_index: idx,
                    data_block_count: 1,
                    parity_block_count: 1,
                    encrypted_size: 4096,
                    decompressed_size: 256,
                    file_count: 1,
                    first_path_hash: hash,
                    last_path_hash: hash,
                })
                .collect(),
            directory_hint_shards: Vec::new(),
        };

        let mut limits = MetadataLimits {
            max_hash_collision_shard_scan: 0,
            ..MetadataLimits::default()
        };
        assert_eq!(
            root.candidate_shards_for_path(path, limits).unwrap_err(),
            FormatError::HashPrefixCollisionRunExceeded
        );

        limits.max_hash_collision_shard_scan = 2;
        assert_eq!(
            root.candidate_shards_for_path(path, limits).unwrap(),
            vec![0, 1, 2]
        );
    }

    #[test]
    fn parses_single_shard_and_finds_final_file_entry() {
        let path = b"file.txt";
        let path_hash = hash_prefix(path);
        let file = FileEntry {
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
        };
        let frame = FrameEntry {
            frame_index: 0,
            envelope_index: 0,
            offset_in_envelope: 0,
            compressed_size: 128,
            decompressed_size: 1536,
            flags: 0,
            tar_stream_offset: 0,
        };
        let envelope = EnvelopeEntry {
            envelope_index: 0,
            first_block_index: 0,
            data_block_count: 1,
            parity_block_count: 1,
            encrypted_size: 4096,
            plaintext_size: 128,
            first_frame_index: 0,
            frame_count: 1,
        };
        let shard = IndexShard {
            header: IndexShardHeader {
                version: 1,
                shard_index: 7,
                file_count: 0,
                frame_count: 0,
                envelope_count: 0,
                file_table_offset: 0,
                frame_table_offset: 0,
                envelope_table_offset: 0,
                string_pool_offset: 0,
                string_pool_size: 0,
            },
            files: vec![file],
            frames: vec![frame],
            envelopes: vec![envelope],
            string_pool: path.to_vec(),
            file_paths: Vec::new(),
            file_tar_member_group_starts: Vec::new(),
        };
        let locating = ShardEntry {
            shard_index: 7,
            first_block_index: 10,
            data_block_count: 1,
            parity_block_count: 1,
            encrypted_size: 4096,
            decompressed_size: shard.to_bytes().len() as u32,
            file_count: 1,
            first_path_hash: path_hash,
            last_path_hash: path_hash,
        };

        let parsed =
            IndexShard::parse(&shard.to_bytes(), &locating, MetadataLimits::default()).unwrap();

        assert_eq!(parsed.lookup_file_index(path), Some(0));
        assert_eq!(parsed.file_path(0), Some(path.as_slice()));
    }
}
