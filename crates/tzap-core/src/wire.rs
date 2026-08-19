use crc32c::crc32c;
use sha2::{Digest, Sha256};

use crate::crypto::KdfParams;
use crate::format::{
    root_auth_spec_id_for_revision, AeadAlgo, BlockKind, CompressionAlgo, FecAlgo, FormatError, KdfAlgo, VolumeFormatRevision, BLOCK_RECORD_FRAMING_LEN,
    BOOTSTRAP_SIDECAR_HEADER_LEN, CRITICAL_METADATA_IMAGE_FIXED_LEN, CRITICAL_METADATA_RECOVERY_HEADER_LEN, CRITICAL_METADATA_RECOVERY_SHARD_HEADER_LEN,
    CRITICAL_RECOVERY_LOCATOR_LEN, CRYPTO_EXTENSION_HEADER_LEN, CRYPTO_EXTENSION_MAX_VALUE_LEN, CRYPTO_HEADER_FIXED_LEN, CRYPTO_HEADER_HMAC_LEN,
    FORMAT_VERSION, IMAGE_CRC_LEN, MANIFEST_FOOTER_LEN, READER_MAX_BLOCK_SIZE, READER_MAX_CHUNK_SIZE, READER_MAX_CRYPTO_HEADER_LEN,
    READER_MAX_ENVELOPE_TARGET_SIZE, READER_MAX_FEC_CLASS_SHARDS, READER_MAX_INDEX_FEC_CLASS_SHARDS, READER_MAX_INDEX_ROOT_FEC_CLASS_SHARDS,
    READER_MAX_KEY_WRAP_TABLE_LEN, READER_MAX_KEY_WRAP_TABLE_RECIPIENT_RECORDS, READER_MAX_PATH_LENGTH, READER_MAX_ROOT_AUTH_AUTHENTICATOR_VALUE_LEN,
    READER_MAX_ROOT_AUTH_FOOTER_LEN, READER_MAX_ROOT_AUTH_SIGNER_IDENTITY_LEN, READER_MAX_STRIPE_WIDTH, READER_MAX_SUPPORTED_VOLUME_FORMAT_REV,
    ROOT_AUTH_FOOTER_FIXED_LEN, SERIALIZED_REGION_HEADER_LEN, VOLUME_FORMAT_REV_45, VOLUME_HEADER_LEN, VOLUME_TRAILER_LEN,
};
use crate::raw_stream_profile::{validate_raw_stream_content_model_extension, RAW_STREAM_CONTENT_MODEL_EXTENSION_TAG};

const TZAP_MAGIC: [u8; 4] = *b"TZAP";
const TZCH_MAGIC: [u8; 4] = *b"TZCH";
const TZBK_MAGIC: [u8; 4] = *b"TZBK";
const TZMF_MAGIC: [u8; 4] = *b"TZMF";
const TZVT_MAGIC: [u8; 4] = *b"TZVT";
const TZRA_MAGIC: [u8; 4] = *b"TZRA";
const TZBS_MAGIC: [u8; 4] = *b"TZBS";
const TZMI_MAGIC: [u8; 4] = *b"TZMI";
const TZCR_MAGIC: [u8; 4] = *b"TZCR";
const TZCS_MAGIC: [u8; 4] = *b"TZCS";
const TZCL_MAGIC: [u8; 4] = *b"TZCL";
const TZKW_MAGIC: [u8; 4] = *b"TZKW";

const BLOCK_LAST_DATA_FLAG: u8 = 0x01;
const BLOCK_RESERVED_FLAGS: u8 = !BLOCK_LAST_DATA_FLAG;

const SIDECAR_MANIFEST_PRESENT: u32 = 0x01;
const SIDECAR_INDEX_ROOT_PRESENT: u32 = 0x02;
const SIDECAR_DICTIONARY_PRESENT: u32 = 0x04;
const SIDECAR_KNOWN_FLAGS: u32 = SIDECAR_MANIFEST_PRESENT | SIDECAR_INDEX_ROOT_PRESENT | SIDECAR_DICTIONARY_PRESENT;

const KEY_WRAP_TABLE_DIGEST_DOMAIN_V45: &[u8] = b"tzap-key-wrap-table-v45\0";
const KEY_WRAP_TABLE_VERSION: u16 = 1;
const KEY_WRAP_TABLE_HEADER_LEN: usize = 96;
const KEY_WRAP_RECORD_HEADER_LEN: usize = 68;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeHeader {
    pub format_version: u16,
    pub volume_format_rev: u16,
    pub volume_index: u32,
    pub stripe_width: u32,
    pub archive_uuid: [u8; 16],
    pub session_id: [u8; 16],
    pub crypto_header_offset: u32,
    pub crypto_header_length: u32,
    pub header_crc32c: u32,
}

impl VolumeHeader {
    pub fn parse(bytes: &[u8]) -> Result<Self, FormatError> {
        expect_len("VolumeHeader", VOLUME_HEADER_LEN, bytes.len())?;
        expect_magic("VolumeHeader", TZAP_MAGIC, &bytes[0..4])?;
        expect_crc("VolumeHeader", &bytes[..124], read_u32(bytes, 124)?)?;
        expect_zero("VolumeHeader", &bytes[56..124])?;

        let header = Self {
            format_version: read_u16(bytes, 4)?,
            volume_format_rev: read_u16(bytes, 6)?,
            volume_index: read_u32(bytes, 8)?,
            stripe_width: read_u32(bytes, 12)?,
            archive_uuid: read_array_16(bytes, 16)?,
            session_id: read_array_16(bytes, 32)?,
            crypto_header_offset: read_u32(bytes, 48)?,
            crypto_header_length: read_u32(bytes, 52)?,
            header_crc32c: read_u32(bytes, 124)?,
        };
        header.validate()?;
        Ok(header)
    }

    pub fn parse_volume_format_revision(&self) -> Result<VolumeFormatRevision, FormatError> {
        VolumeFormatRevision::from_u16(self.volume_format_rev).ok_or({
            FormatError::UnsupportedVolumeFormatRevision {
                format_version: self.format_version,
                volume_format_rev: self.volume_format_rev,
                reader_max_supported_revision: READER_MAX_SUPPORTED_VOLUME_FORMAT_REV,
            }
        })
    }

    pub fn validate(&self) -> Result<(), FormatError> {
        if self.format_version != FORMAT_VERSION {
            return Err(FormatError::UnsupportedFormatVersion(self.format_version));
        }
        if self.stripe_width == 0 {
            return Err(FormatError::ZeroStripeWidth);
        }
        if self.volume_index >= self.stripe_width {
            return Err(FormatError::VolumeIndexOutOfRange { volume_index: self.volume_index, stripe_width: self.stripe_width });
        }
        if self.crypto_header_offset != VOLUME_HEADER_LEN as u32 {
            return Err(FormatError::NonCanonicalCryptoHeaderOffset(self.crypto_header_offset));
        }
        if self.crypto_header_length > READER_MAX_CRYPTO_HEADER_LEN {
            return Err(FormatError::ReaderResourceLimitExceeded {
                field: "CryptoHeader length",
                cap: READER_MAX_CRYPTO_HEADER_LEN as u64,
                actual: self.crypto_header_length as u64,
            });
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> [u8; VOLUME_HEADER_LEN] {
        let mut bytes = [0u8; VOLUME_HEADER_LEN];
        bytes[0..4].copy_from_slice(&TZAP_MAGIC);
        write_u16(&mut bytes, 4, self.format_version);
        write_u16(&mut bytes, 6, self.volume_format_rev);
        write_u32(&mut bytes, 8, self.volume_index);
        write_u32(&mut bytes, 12, self.stripe_width);
        bytes[16..32].copy_from_slice(&self.archive_uuid);
        bytes[32..48].copy_from_slice(&self.session_id);
        write_u32(&mut bytes, 48, self.crypto_header_offset);
        write_u32(&mut bytes, 52, self.crypto_header_length);
        let crc = crc32c(&bytes[..124]);
        write_u32(&mut bytes, 124, crc);
        bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoHeaderFixed {
    pub length: u32,
    pub compression_algo: CompressionAlgo,
    pub aead_algo: AeadAlgo,
    pub fec_algo: FecAlgo,
    pub kdf_algo: KdfAlgo,
    pub chunk_size: u32,
    pub envelope_target_size: u32,
    pub block_size: u32,
    pub fec_data_shards: u16,
    pub fec_parity_shards: u16,
    pub index_fec_data_shards: u16,
    pub index_fec_parity_shards: u16,
    pub index_root_fec_data_shards: u16,
    pub index_root_fec_parity_shards: u16,
    pub stripe_width: u32,
    pub volume_loss_tolerance: u8,
    pub bit_rot_buffer_pct: u8,
    pub has_dictionary: u8,
    pub max_path_length: u32,
    pub expected_volume_size: u64,
}

impl CryptoHeaderFixed {
    pub fn parse(bytes: &[u8], volume_crypto_header_length: u32) -> Result<Self, FormatError> {
        expect_len("CryptoHeaderFixed", CRYPTO_HEADER_FIXED_LEN, bytes.len())?;
        expect_magic("CryptoHeaderFixed", TZCH_MAGIC, &bytes[0..4])?;
        expect_zero("CryptoHeaderFixed", &bytes[47..48])?;
        expect_zero("CryptoHeaderFixed", &bytes[60..76])?;

        let length = read_u32(bytes, 4)?;
        if length != volume_crypto_header_length {
            return Err(FormatError::CryptoHeaderLengthMismatch { fixed: length, volume: volume_crypto_header_length });
        }
        if length > READER_MAX_CRYPTO_HEADER_LEN {
            return Err(FormatError::ReaderResourceLimitExceeded {
                field: "CryptoHeader length",
                cap: READER_MAX_CRYPTO_HEADER_LEN as u64,
                actual: length as u64,
            });
        }

        let header = Self {
            length,
            compression_algo: CompressionAlgo::try_from(read_u16(bytes, 8)?)?,
            aead_algo: AeadAlgo::try_from(read_u16(bytes, 10)?)?,
            fec_algo: FecAlgo::try_from(read_u16(bytes, 12)?)?,
            kdf_algo: KdfAlgo::try_from(read_u16(bytes, 14)?)?,
            chunk_size: read_u32(bytes, 16)?,
            envelope_target_size: read_u32(bytes, 20)?,
            block_size: read_u32(bytes, 24)?,
            fec_data_shards: read_u16(bytes, 28)?,
            fec_parity_shards: read_u16(bytes, 30)?,
            index_fec_data_shards: read_u16(bytes, 32)?,
            index_fec_parity_shards: read_u16(bytes, 34)?,
            index_root_fec_data_shards: read_u16(bytes, 36)?,
            index_root_fec_parity_shards: read_u16(bytes, 38)?,
            stripe_width: read_u32(bytes, 40)?,
            volume_loss_tolerance: bytes[44],
            bit_rot_buffer_pct: bytes[45],
            has_dictionary: bytes[46],
            max_path_length: read_u32(bytes, 48)?,
            expected_volume_size: read_u64(bytes, 52)?,
        };
        header.validate_supported_profile()?;
        Ok(header)
    }

    pub fn validate_supported_profile(&self) -> Result<(), FormatError> {
        if self.compression_algo != CompressionAlgo::ZstdFramed {
            return Err(FormatError::UnsupportedCompression(self.compression_algo));
        }
        if self.fec_algo != FecAlgo::ReedSolomonGF16 {
            return Err(FormatError::UnsupportedFec(self.fec_algo));
        }
        match (self.aead_algo, self.kdf_algo) {
            (AeadAlgo::None, KdfAlgo::None) => {}
            (aead_algo, KdfAlgo::Raw | KdfAlgo::Argon2id | KdfAlgo::RecipientWrap) if aead_algo.is_encrypted() => {}
            _ => {
                return Err(FormatError::InvalidProtectionMode { aead_algo: self.aead_algo, kdf_algo: self.kdf_algo });
            }
        }
        if self.has_dictionary > 1 {
            return Err(FormatError::InvalidBoolean { field: "has_dictionary", value: self.has_dictionary });
        }
        if self.stripe_width == 0 {
            return Err(FormatError::ZeroStripeWidth);
        }
        if self.stripe_width > READER_MAX_STRIPE_WIDTH {
            return Err(FormatError::ReaderResourceLimitExceeded {
                field: "stripe_width",
                cap: READER_MAX_STRIPE_WIDTH as u64,
                actual: self.stripe_width as u64,
            });
        }
        if self.volume_loss_tolerance as u32 >= self.stripe_width {
            return Err(FormatError::VolumeLossToleranceOutOfRange { volume_loss_tolerance: self.volume_loss_tolerance, stripe_width: self.stripe_width });
        }
        if self.bit_rot_buffer_pct > 100 {
            return Err(FormatError::BitRotBufferPctTooLarge(self.bit_rot_buffer_pct));
        }
        if self.fec_data_shards == 0 {
            return Err(FormatError::ZeroDataShardMaximum { field: "fec_data_shards" });
        }
        if self.index_fec_data_shards == 0 {
            return Err(FormatError::ZeroDataShardMaximum { field: "index_fec_data_shards" });
        }
        if self.index_root_fec_data_shards == 0 {
            return Err(FormatError::ZeroDataShardMaximum { field: "index_root_fec_data_shards" });
        }
        validate_fec_class_shards("fec_data_shards + fec_parity_shards", self.fec_data_shards, self.fec_parity_shards, READER_MAX_FEC_CLASS_SHARDS)?;
        validate_fec_class_shards(
            "index_fec_data_shards + index_fec_parity_shards",
            self.index_fec_data_shards,
            self.index_fec_parity_shards,
            READER_MAX_INDEX_FEC_CLASS_SHARDS,
        )?;
        validate_fec_class_shards(
            "index_root_fec_data_shards + index_root_fec_parity_shards",
            self.index_root_fec_data_shards,
            self.index_root_fec_parity_shards,
            READER_MAX_INDEX_ROOT_FEC_CLASS_SHARDS,
        )?;
        if self.chunk_size == 0 {
            return Err(FormatError::ZeroChunkSize);
        }
        if self.envelope_target_size == 0 {
            return Err(FormatError::ZeroEnvelopeTargetSize);
        }
        if self.chunk_size > self.envelope_target_size {
            return Err(FormatError::ChunkSizeExceedsEnvelopeTarget { chunk_size: self.chunk_size, envelope_target_size: self.envelope_target_size });
        }
        if self.chunk_size > READER_MAX_CHUNK_SIZE {
            return Err(FormatError::ReaderResourceLimitExceeded { field: "chunk_size", cap: READER_MAX_CHUNK_SIZE as u64, actual: self.chunk_size as u64 });
        }
        if self.envelope_target_size > READER_MAX_ENVELOPE_TARGET_SIZE {
            return Err(FormatError::ReaderResourceLimitExceeded {
                field: "envelope_target_size",
                cap: READER_MAX_ENVELOPE_TARGET_SIZE as u64,
                actual: self.envelope_target_size as u64,
            });
        }
        if self.block_size < 4096 {
            return Err(FormatError::BlockSizeTooSmall(self.block_size));
        }
        if self.block_size % 2 != 0 {
            return Err(FormatError::OddBlockSize(self.block_size));
        }
        validate_fec_class_data_shards("fec_data_shards", self.fec_data_shards, self.block_size)?;
        validate_fec_class_data_shards("index_fec_data_shards", self.index_fec_data_shards, self.block_size)?;
        validate_fec_class_data_shards("index_root_fec_data_shards", self.index_root_fec_data_shards, self.block_size)?;
        if self.block_size > READER_MAX_BLOCK_SIZE {
            return Err(FormatError::ReaderResourceLimitExceeded { field: "block_size", cap: READER_MAX_BLOCK_SIZE as u64, actual: self.block_size as u64 });
        }
        if self.max_path_length > READER_MAX_PATH_LENGTH {
            return Err(FormatError::ReaderResourceLimitExceeded {
                field: "max_path_length",
                cap: READER_MAX_PATH_LENGTH as u64,
                actual: self.max_path_length as u64,
            });
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> [u8; CRYPTO_HEADER_FIXED_LEN] {
        let mut bytes = [0u8; CRYPTO_HEADER_FIXED_LEN];
        bytes[0..4].copy_from_slice(&TZCH_MAGIC);
        write_u32(&mut bytes, 4, self.length);
        write_u16(&mut bytes, 8, self.compression_algo as u16);
        write_u16(&mut bytes, 10, self.aead_algo as u16);
        write_u16(&mut bytes, 12, self.fec_algo as u16);
        write_u16(&mut bytes, 14, self.kdf_algo as u16);
        write_u32(&mut bytes, 16, self.chunk_size);
        write_u32(&mut bytes, 20, self.envelope_target_size);
        write_u32(&mut bytes, 24, self.block_size);
        write_u16(&mut bytes, 28, self.fec_data_shards);
        write_u16(&mut bytes, 30, self.fec_parity_shards);
        write_u16(&mut bytes, 32, self.index_fec_data_shards);
        write_u16(&mut bytes, 34, self.index_fec_parity_shards);
        write_u16(&mut bytes, 36, self.index_root_fec_data_shards);
        write_u16(&mut bytes, 38, self.index_root_fec_parity_shards);
        write_u32(&mut bytes, 40, self.stripe_width);
        bytes[44] = self.volume_loss_tolerance;
        bytes[45] = self.bit_rot_buffer_pct;
        bytes[46] = self.has_dictionary;
        write_u32(&mut bytes, 48, self.max_path_length);
        write_u64(&mut bytes, 52, self.expected_volume_size);
        bytes
    }
}

fn validate_fec_class_shards(field: &'static str, data_shards: u16, parity_shards: u16, cap: u32) -> Result<(), FormatError> {
    let total = data_shards as u32 + parity_shards as u32;
    if total > cap {
        return Err(FormatError::ReaderResourceLimitExceeded { field, cap: cap as u64, actual: total as u64 });
    }
    Ok(())
}

fn validate_fec_class_data_shards(field: &'static str, data_shards: u16, block_size: u32) -> Result<(), FormatError> {
    let max_data_shards = u32::MAX as u64 / block_size as u64;
    if (data_shards as u64) > max_data_shards {
        return Err(FormatError::ReaderResourceLimitExceeded { field, cap: max_data_shards, actual: data_shards as u64 });
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionTlv<'a> {
    pub tag: u16,
    pub value: &'a [u8],
}

pub fn scan_crypto_extension_tlvs(bytes: &[u8]) -> Result<Vec<ExtensionTlv<'_>>, FormatError> {
    let mut offset = 0usize;
    let mut extensions = Vec::new();
    loop {
        if offset == bytes.len() {
            return Err(FormatError::MissingExtensionTerminator);
        }
        if bytes.len() - offset < CRYPTO_EXTENSION_HEADER_LEN {
            return Err(FormatError::TruncatedExtensionHeader);
        }
        let tag = read_u16(bytes, offset)?;
        let length = read_u32(bytes, offset + 2)?;
        offset += CRYPTO_EXTENSION_HEADER_LEN;
        if tag == 0 {
            if length != 0 {
                return Err(FormatError::MalformedExtensionTerminator);
            }
            if offset != bytes.len() {
                return Err(FormatError::BytesAfterExtensionTerminator);
            }
            return Ok(extensions);
        }
        if length > CRYPTO_EXTENSION_MAX_VALUE_LEN {
            return Err(FormatError::ExtensionPayloadTooLarge(length));
        }
        let length = length as usize;
        if bytes.len() - offset < length {
            return Err(FormatError::TruncatedExtensionPayload);
        }
        extensions.push(ExtensionTlv { tag, value: &bytes[offset..offset + length] });
        offset += length;
    }
}

pub fn validate_crypto_extension_semantics(extensions: &[ExtensionTlv<'_>]) -> Result<(), FormatError> {
    let mut seen_known = Vec::new();
    for extension in extensions {
        let ext_tag = extension.tag & 0x7fff;
        let is_critical = extension.tag & 0x8000 != 0;
        if matches!(ext_tag, 0x0004 | 0x0006) {
            return Err(FormatError::ForbiddenExtensionTag(ext_tag));
        }
        if ext_tag == RAW_STREAM_CONTENT_MODEL_EXTENSION_TAG {
            if is_critical {
                if seen_known.contains(&ext_tag) {
                    return Err(FormatError::DuplicateKnownExtension(ext_tag));
                }
                validate_raw_stream_content_model_extension(is_critical, extension.value)?;
                seen_known.push(ext_tag);
            }
            continue;
        }
        if is_known_extension(ext_tag) {
            if seen_known.contains(&ext_tag) {
                return Err(FormatError::DuplicateKnownExtension(ext_tag));
            }
            validate_known_extension(ext_tag, extension.value)?;
            seen_known.push(ext_tag);
        } else if is_critical {
            return Err(FormatError::UnknownCriticalExtension(ext_tag));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoHeader<'a> {
    pub fixed: CryptoHeaderFixed,
    pub kdf_params: KdfParams,
    pub extensions: Vec<ExtensionTlv<'a>>,
    pub header_hmac: [u8; 32],
    pub hmac_covered_bytes: &'a [u8],
}

pub fn compute_key_wrap_table_digest(key_wrap_table_length: u32, key_wrap_table_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(KEY_WRAP_TABLE_DIGEST_DOMAIN_V45);
    hasher.update(key_wrap_table_length.to_le_bytes());
    hasher.update(key_wrap_table_bytes);
    let digest = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    output
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyWrapTableV1 {
    pub version: u16,
    pub volume_format_rev: u16,
    pub table_length: u32,
    pub flags: u32,
    pub archive_uuid: [u8; 16],
    pub session_id: [u8; 16],
    pub recipient_record_count: u32,
    pub records_offset: u32,
    pub records_length: u32,
    pub recipient_records: Vec<RecipientRecordV1>,
}

impl KeyWrapTableV1 {
    pub fn to_bytes(&self) -> Result<Vec<u8>, FormatError> {
        if self.version != KEY_WRAP_TABLE_VERSION {
            return Err(FormatError::InvalidArchive("KeyWrapTableV1 version must be 1"));
        }
        if self.volume_format_rev != VOLUME_FORMAT_REV_45 {
            return Err(FormatError::InvalidArchive("KeyWrapTableV1 volume_format_rev must be 45"));
        }
        if self.flags != 0 {
            return Err(FormatError::NonZeroReserved { structure: "KeyWrapTableV1" });
        }
        if self.records_offset != KEY_WRAP_TABLE_HEADER_LEN as u32 {
            return Err(FormatError::InvalidArchive("KeyWrapTableV1 records_offset must be 96"));
        }
        if !self.recipient_records.is_empty() {
            let mut recipients = Vec::with_capacity(self.recipient_records.len());
            for record in &self.recipient_records {
                recipients.extend_from_slice(&record.to_bytes()?);
            }
            let recipient_record_count = u32_len(self.recipient_records.len(), "KeyWrapTableV1 recipient_record_count")?;
            if self.recipient_record_count != 0 && self.recipient_record_count != recipient_record_count {
                return Err(FormatError::InvalidArchive("KeyWrapTableV1 recipient_record_count does not match fields"));
            }
            let records_length = u32_len(recipients.len(), "KeyWrapTableV1 records_length")?;
            if self.records_length != 0 && self.records_length != records_length {
                return Err(FormatError::InvalidArchive("KeyWrapTableV1 records_length does not match fields"));
            }

            let table_length = u32_len(
                KEY_WRAP_TABLE_HEADER_LEN.checked_add(recipients.len()).ok_or(FormatError::WriterUnsupported("key-wrap table length overflow"))?,
                "KeyWrapTableV1 table_length",
            )?;
            if self.table_length != 0 && self.table_length != table_length {
                return Err(FormatError::InvalidArchive("KeyWrapTableV1 table_length does not match fields"));
            }

            let mut bytes = vec![0u8; KEY_WRAP_TABLE_HEADER_LEN];
            bytes[0..4].copy_from_slice(&TZKW_MAGIC);
            write_u16(&mut bytes, 4, self.version);
            write_u16(&mut bytes, 6, self.volume_format_rev);
            write_u32(&mut bytes, 8, table_length);
            write_u32(&mut bytes, 12, KEY_WRAP_TABLE_HEADER_LEN as u32);
            bytes[20..36].copy_from_slice(&self.archive_uuid);
            bytes[36..52].copy_from_slice(&self.session_id);
            write_u32(&mut bytes, 52, recipient_record_count);
            write_u32(&mut bytes, 56, KEY_WRAP_TABLE_HEADER_LEN as u32);
            write_u32(&mut bytes, 60, records_length);
            bytes.extend(recipients);
            Ok(bytes)
        } else {
            Err(FormatError::WriterUnsupported("KeyWrapTableV1 must include at least one recipient record"))
        }
    }

    pub fn parse(
        bytes: &[u8],
        archive_uuid: &[u8; 16],
        session_id: &[u8; 16],
        key_wrap_table_length: u32,
        key_wrap_table_record_count: u32,
    ) -> Result<Self, FormatError> {
        if bytes.len() > READER_MAX_KEY_WRAP_TABLE_LEN as usize {
            return Err(FormatError::ReaderResourceLimitExceeded {
                field: "KeyWrapTableV1 length",
                cap: READER_MAX_KEY_WRAP_TABLE_LEN as u64,
                actual: bytes.len() as u64,
            });
        }
        if bytes.len() < KEY_WRAP_TABLE_HEADER_LEN {
            return Err(FormatError::InvalidLength { structure: "KeyWrapTableV1", expected: KEY_WRAP_TABLE_HEADER_LEN, actual: bytes.len() });
        }
        expect_magic("KeyWrapTableV1", TZKW_MAGIC, &bytes[0..4])?;

        let header_length = read_u32(bytes, 12)?;
        if header_length != KEY_WRAP_TABLE_HEADER_LEN as u32 {
            return Err(FormatError::InvalidArchive("KeyWrapTableV1 header_length must be 96"));
        }
        let version = read_u16(bytes, 4)?;
        if version != KEY_WRAP_TABLE_VERSION {
            return Err(FormatError::InvalidArchive("KeyWrapTableV1 version must be 1"));
        }
        let volume_format_rev = read_u16(bytes, 6)?;
        if volume_format_rev != VOLUME_FORMAT_REV_45 {
            return Err(FormatError::InvalidArchive("KeyWrapTableV1 volume_format_rev must be 45"));
        }

        let declared_length = read_u32(bytes, 8)?;
        if declared_length != key_wrap_table_length {
            return Err(FormatError::InvalidArchive("KeyWrapTableV1 length does not match KdfParams"));
        }
        if declared_length as usize != bytes.len() {
            return Err(FormatError::InvalidLength { structure: "KeyWrapTableV1", expected: declared_length as usize, actual: bytes.len() });
        }

        let flags = read_u32(bytes, 16)?;
        if flags != 0 {
            return Err(FormatError::NonZeroReserved { structure: "KeyWrapTableV1" });
        }

        let table_archive_uuid = read_array_16(bytes, 20)?;
        if table_archive_uuid != *archive_uuid {
            return Err(FormatError::InvalidArchive("KeyWrapTableV1 archive_uuid does not match CryptoHeader"));
        }
        let table_session_id = read_array_16(bytes, 36)?;
        if table_session_id != *session_id {
            return Err(FormatError::InvalidArchive("KeyWrapTableV1 session_id does not match CryptoHeader"));
        }

        let recipient_record_count = read_u32(bytes, 52)?;
        if recipient_record_count > READER_MAX_KEY_WRAP_TABLE_RECIPIENT_RECORDS {
            return Err(FormatError::ReaderResourceLimitExceeded {
                field: "KeyWrapTableV1 recipient_record_count",
                cap: READER_MAX_KEY_WRAP_TABLE_RECIPIENT_RECORDS as u64,
                actual: recipient_record_count as u64,
            });
        }
        if recipient_record_count != key_wrap_table_record_count {
            return Err(FormatError::InvalidArchive("KeyWrapTableV1 recipient_record_count does not match KdfParams"));
        }

        let records_offset = read_u32(bytes, 56)?;
        let records_length = read_u32(bytes, 60)?;
        if records_offset != KEY_WRAP_TABLE_HEADER_LEN as u32 {
            return Err(FormatError::InvalidArchive("KeyWrapTableV1 records_offset must be 96"));
        }
        let records_end =
            records_offset.checked_add(records_length).ok_or(FormatError::InvalidArchive("KeyWrapTableV1 records_offset + records_length overflow"))?;
        if records_end != declared_length {
            return Err(FormatError::InvalidArchive("KeyWrapTableV1 records_offset and records_length are inconsistent"));
        }
        expect_zero("KeyWrapTableV1", &bytes[64..96])?;

        let mut recipient_records = Vec::with_capacity(recipient_record_count as usize);
        let mut cursor = records_offset as usize;
        for _ in 0..recipient_record_count {
            let (record, consumed) = RecipientRecordV1::parse(&bytes[cursor..])?;
            cursor += consumed;
            recipient_records.push(record);
        }
        if cursor != declared_length as usize {
            return Err(FormatError::InvalidArchive("KeyWrapTableV1 has trailing record bytes"));
        }

        Ok(Self {
            version,
            volume_format_rev,
            table_length: declared_length,
            flags,
            archive_uuid: table_archive_uuid,
            session_id: table_session_id,
            recipient_record_count,
            records_offset,
            records_length,
            recipient_records,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientRecordV1 {
    pub record_length: u32,
    pub profile_id: u16,
    pub recipient_identity_type: u16,
    pub flags: u32,
    pub recipient_identity_length: u32,
    pub profile_payload_length: u32,
    pub recipient_identity_digest: [u8; 32],
    pub recipient_identity_bytes: Vec<u8>,
    pub profile_payload_bytes: Vec<u8>,
}

impl RecipientRecordV1 {
    pub fn with_record_length(mut self, record_length: u32) -> Self {
        self.record_length = record_length;
        self
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, FormatError> {
        let mut bytes = vec![0u8; KEY_WRAP_RECORD_HEADER_LEN];
        let computed_identity_length = u32_len(self.recipient_identity_bytes.len(), "RecipientRecordV1 identity length")?;
        let computed_profile_payload_length = u32_len(self.profile_payload_bytes.len(), "RecipientRecordV1 profile payload length")?;
        let computed_record_length = u32_len(
            KEY_WRAP_RECORD_HEADER_LEN
                .checked_add(self.recipient_identity_bytes.len())
                .and_then(|value| value.checked_add(self.profile_payload_bytes.len()))
                .ok_or(FormatError::WriterUnsupported("RecipientRecordV1 length overflow"))?,
            "RecipientRecordV1 record length",
        )?;

        let record_length = if self.record_length == 0 {
            computed_record_length
        } else {
            if self.record_length != computed_record_length {
                return Err(FormatError::InvalidArchive("RecipientRecordV1 length is inconsistent with payload sizes"));
            }
            self.record_length
        };
        if self.recipient_identity_length != 0 && self.recipient_identity_length != computed_identity_length {
            return Err(FormatError::InvalidArchive("RecipientRecordV1 identity length is inconsistent with payload size"));
        }
        if self.profile_payload_length != 0 && self.profile_payload_length != computed_profile_payload_length {
            return Err(FormatError::InvalidArchive("RecipientRecordV1 payload length is inconsistent with payload size"));
        }

        let mut digest = Sha256::new();
        digest.update(&self.recipient_identity_bytes);
        let mut expected_digest = [0u8; 32];
        expected_digest.copy_from_slice(&digest.finalize());
        if self.recipient_identity_digest != [0u8; 32] && self.recipient_identity_digest != expected_digest {
            return Err(FormatError::InvalidArchive("RecipientRecordV1 recipient_identity_digest mismatch"));
        }

        write_u32(&mut bytes, 0, record_length);
        write_u16(&mut bytes, 4, self.profile_id);
        write_u16(&mut bytes, 6, self.recipient_identity_type);
        write_u32(&mut bytes, 8, 0);
        write_u32(&mut bytes, 12, computed_identity_length);
        write_u32(&mut bytes, 16, computed_profile_payload_length);
        bytes[20..52].copy_from_slice(&expected_digest);
        bytes.extend_from_slice(&self.recipient_identity_bytes);
        bytes.extend_from_slice(&self.profile_payload_bytes);
        Ok(bytes)
    }

    pub fn parse(bytes: &[u8]) -> Result<(Self, usize), FormatError> {
        if bytes.len() < KEY_WRAP_RECORD_HEADER_LEN {
            return Err(FormatError::InvalidLength { structure: "RecipientRecordV1", expected: KEY_WRAP_RECORD_HEADER_LEN, actual: bytes.len() });
        }

        let record_length = read_u32(bytes, 0)?;
        let record_length = usize::try_from(record_length).map_err(|_| FormatError::InvalidArchive("RecipientRecordV1 record_length overflows memory"))?;
        if record_length < KEY_WRAP_RECORD_HEADER_LEN {
            return Err(FormatError::InvalidArchive("RecipientRecordV1 record_length is too small"));
        }
        if record_length > bytes.len() {
            return Err(FormatError::InvalidLength { structure: "RecipientRecordV1", expected: record_length, actual: bytes.len() });
        }

        let profile_id = read_u16(bytes, 4)?;
        let recipient_identity_type = read_u16(bytes, 6)?;
        let flags = read_u32(bytes, 8)?;
        if flags != 0 {
            return Err(FormatError::NonZeroReserved { structure: "RecipientRecordV1" });
        }
        let recipient_identity_length = read_u32(bytes, 12)?;
        let profile_payload_length = read_u32(bytes, 16)?;
        let recipient_identity_length =
            usize::try_from(recipient_identity_length).map_err(|_| FormatError::InvalidArchive("RecipientRecordV1 identity length"))?;
        let profile_payload_length = usize::try_from(profile_payload_length).map_err(|_| FormatError::InvalidArchive("RecipientRecordV1 payload length"))?;
        let expected_length = KEY_WRAP_RECORD_HEADER_LEN
            .checked_add(recipient_identity_length)
            .and_then(|value| value.checked_add(profile_payload_length))
            .ok_or(FormatError::InvalidArchive("RecipientRecordV1 length arithmetic overflow"))?;
        if record_length != expected_length {
            return Err(FormatError::InvalidArchive("RecipientRecordV1 length is inconsistent with payload sizes"));
        }

        let mut recipient_identity_digest = [0u8; 32];
        recipient_identity_digest.copy_from_slice(&bytes[20..52]);
        expect_zero("RecipientRecordV1", &bytes[52..68])?;

        let identity_start = KEY_WRAP_RECORD_HEADER_LEN;
        let identity_end = identity_start + recipient_identity_length;
        let payload_end = identity_end + profile_payload_length;
        let recipient_identity_bytes = bytes[identity_start..identity_end].to_vec();
        let profile_payload_bytes = bytes[identity_end..payload_end].to_vec();

        let mut digest = Sha256::new();
        digest.update(&recipient_identity_bytes);
        let mut expected_digest = [0u8; 32];
        expected_digest.copy_from_slice(&digest.finalize());
        if recipient_identity_digest != expected_digest {
            return Err(FormatError::InvalidArchive("RecipientRecordV1 recipient_identity_digest mismatch"));
        }

        Ok((
            Self {
                record_length: expected_length as u32,
                profile_id,
                recipient_identity_type,
                flags,
                recipient_identity_length: recipient_identity_length as u32,
                profile_payload_length: profile_payload_length as u32,
                recipient_identity_digest,
                recipient_identity_bytes,
                profile_payload_bytes,
            },
            record_length,
        ))
    }
}

impl<'a> CryptoHeader<'a> {
    pub fn parse(bytes: &'a [u8], volume_crypto_header_length: u32) -> Result<Self, FormatError> {
        let declared_len = volume_crypto_header_length as usize;
        if volume_crypto_header_length > READER_MAX_CRYPTO_HEADER_LEN {
            return Err(FormatError::ReaderResourceLimitExceeded {
                field: "CryptoHeader length",
                cap: READER_MAX_CRYPTO_HEADER_LEN as u64,
                actual: volume_crypto_header_length as u64,
            });
        }
        if bytes.len() != declared_len {
            return Err(FormatError::InvalidLength { structure: "CryptoHeader", expected: declared_len, actual: bytes.len() });
        }
        let min_len = CRYPTO_HEADER_FIXED_LEN + 2 + CRYPTO_EXTENSION_HEADER_LEN + CRYPTO_HEADER_HMAC_LEN;
        if bytes.len() < min_len {
            return Err(FormatError::CryptoHeaderTooShort { min: min_len, actual: bytes.len() });
        }

        let fixed = CryptoHeaderFixed::parse(&bytes[..CRYPTO_HEADER_FIXED_LEN], volume_crypto_header_length)?;
        let hmac_offset = bytes.len() - CRYPTO_HEADER_HMAC_LEN;
        let (kdf_params, kdf_len) = KdfParams::parse(fixed.kdf_algo, &bytes[CRYPTO_HEADER_FIXED_LEN..hmac_offset])?;
        let extension_bytes = &bytes[CRYPTO_HEADER_FIXED_LEN + kdf_len..hmac_offset];
        let extensions = scan_crypto_extension_tlvs(extension_bytes)?;
        let header_hmac = read_array_32(bytes, hmac_offset)?;

        Ok(Self { fixed, kdf_params, extensions, header_hmac, hmac_covered_bytes: &bytes[..hmac_offset] })
    }

    pub fn validate_extension_semantics(&self) -> Result<(), FormatError> {
        validate_crypto_extension_semantics(&self.extensions)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockRecord {
    pub block_index: u64,
    pub kind: BlockKind,
    pub flags: u8,
    pub payload: Vec<u8>,
    pub record_crc32c: u32,
}

impl BlockRecord {
    pub fn parse(bytes: &[u8], block_size: usize) -> Result<Self, FormatError> {
        let expected = block_size + BLOCK_RECORD_FRAMING_LEN;
        expect_len("BlockRecord", expected, bytes.len())?;
        expect_magic("BlockRecord", TZBK_MAGIC, &bytes[0..4])?;
        expect_zero("BlockRecord", &bytes[14..16])?;
        expect_crc("BlockRecord", &bytes[..16 + block_size], read_u32(bytes, 16 + block_size)?)?;

        let kind = BlockKind::try_from(bytes[12])?;
        let flags = bytes[13];
        if flags & BLOCK_RESERVED_FLAGS != 0 {
            return Err(FormatError::InvalidBlockFlags(flags));
        }
        if kind.is_parity() && flags & BLOCK_LAST_DATA_FLAG != 0 {
            return Err(FormatError::ParityBlockHasLastDataFlag);
        }

        Ok(Self {
            block_index: read_u64(bytes, 4)?,
            kind,
            flags,
            payload: bytes[16..16 + block_size].to_vec(),
            record_crc32c: read_u32(bytes, 16 + block_size)?,
        })
    }

    pub fn is_last_data(&self) -> bool {
        self.flags & BLOCK_LAST_DATA_FLAG != 0
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        Self::to_bytes_from_parts(self.block_index, self.kind, self.flags, &self.payload)
    }

    pub(crate) fn to_bytes_from_parts(block_index: u64, kind: BlockKind, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; payload.len() + BLOCK_RECORD_FRAMING_LEN];
        bytes[0..4].copy_from_slice(&TZBK_MAGIC);
        write_u64(&mut bytes, 4, block_index);
        bytes[12] = kind as u8;
        bytes[13] = flags;
        bytes[16..16 + payload.len()].copy_from_slice(payload);
        let crc = crc32c(&bytes[..16 + payload.len()]);
        let crc_offset = 16 + payload.len();
        write_u32(&mut bytes, crc_offset, crc);
        bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestFooter {
    pub archive_uuid: [u8; 16],
    pub session_id: [u8; 16],
    pub volume_index: u32,
    pub is_authoritative: u8,
    pub total_volumes: u32,
    pub index_root_first_block: u64,
    pub index_root_data_block_count: u32,
    pub index_root_parity_block_count: u32,
    pub index_root_encrypted_size: u32,
    pub index_root_decompressed_size: u32,
    pub manifest_hmac: [u8; 32],
}

impl ManifestFooter {
    pub fn parse(bytes: &[u8]) -> Result<Self, FormatError> {
        expect_len("ManifestFooter", MANIFEST_FOOTER_LEN, bytes.len())?;
        expect_magic("ManifestFooter", TZMF_MAGIC, &bytes[0..4])?;
        expect_zero("ManifestFooter", &bytes[41..44])?;
        expect_zero("ManifestFooter", &bytes[72..104])?;
        let is_authoritative = bytes[40];
        if is_authoritative > 1 {
            return Err(FormatError::InvalidAuthoritativeFlag(is_authoritative));
        }

        Ok(Self {
            archive_uuid: read_array_16(bytes, 4)?,
            session_id: read_array_16(bytes, 20)?,
            volume_index: read_u32(bytes, 36)?,
            is_authoritative,
            total_volumes: read_u32(bytes, 44)?,
            index_root_first_block: read_u64(bytes, 48)?,
            index_root_data_block_count: read_u32(bytes, 56)?,
            index_root_parity_block_count: read_u32(bytes, 60)?,
            index_root_encrypted_size: read_u32(bytes, 64)?,
            index_root_decompressed_size: read_u32(bytes, 68)?,
            manifest_hmac: read_array_32(bytes, 104)?,
        })
    }

    pub fn validate_index_root_extent(&self, block_size: u32) -> Result<(), FormatError> {
        if self.index_root_data_block_count == 0 || self.index_root_encrypted_size == 0 {
            return Err(FormatError::EmptyIndexRootExtent);
        }
        let expected = self.index_root_data_block_count.checked_mul(block_size).ok_or(FormatError::IndexRootSizeMismatch)?;
        if expected != self.index_root_encrypted_size {
            return Err(FormatError::IndexRootSizeMismatch);
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> [u8; MANIFEST_FOOTER_LEN] {
        let mut bytes = [0u8; MANIFEST_FOOTER_LEN];
        bytes[0..4].copy_from_slice(&TZMF_MAGIC);
        bytes[4..20].copy_from_slice(&self.archive_uuid);
        bytes[20..36].copy_from_slice(&self.session_id);
        write_u32(&mut bytes, 36, self.volume_index);
        bytes[40] = self.is_authoritative;
        write_u32(&mut bytes, 44, self.total_volumes);
        write_u64(&mut bytes, 48, self.index_root_first_block);
        write_u32(&mut bytes, 56, self.index_root_data_block_count);
        write_u32(&mut bytes, 60, self.index_root_parity_block_count);
        write_u32(&mut bytes, 64, self.index_root_encrypted_size);
        write_u32(&mut bytes, 68, self.index_root_decompressed_size);
        bytes[104..136].copy_from_slice(&self.manifest_hmac);
        bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeTrailer {
    pub archive_uuid: [u8; 16],
    pub session_id: [u8; 16],
    pub volume_index: u32,
    pub block_count: u64,
    pub bytes_written: u64,
    pub manifest_footer_offset: u64,
    pub manifest_footer_length: u32,
    pub closed_at_ns: i64,
    pub root_auth_footer_offset: u64,
    pub root_auth_footer_length: u32,
    pub root_auth_flags: u32,
    pub trailer_hmac: [u8; 32],
}

impl VolumeTrailer {
    pub fn parse(bytes: &[u8]) -> Result<Self, FormatError> {
        expect_len("VolumeTrailer", VOLUME_TRAILER_LEN, bytes.len())?;
        expect_magic("VolumeTrailer", TZVT_MAGIC, &bytes[0..4])?;
        expect_zero("VolumeTrailer", &bytes[92..96])?;
        let manifest_footer_length = read_u32(bytes, 64)?;
        if manifest_footer_length != MANIFEST_FOOTER_LEN as u32 {
            return Err(FormatError::InvalidManifestFooterLength(manifest_footer_length));
        }
        let root_auth_flags = read_u32(bytes, 88)?;
        if root_auth_flags & !0x0000_0001 != 0 {
            return Err(FormatError::InvalidArchive("VolumeTrailer root_auth_flags has unknown bits"));
        }

        Ok(Self {
            archive_uuid: read_array_16(bytes, 4)?,
            session_id: read_array_16(bytes, 20)?,
            volume_index: read_u32(bytes, 36)?,
            block_count: read_u64(bytes, 40)?,
            bytes_written: read_u64(bytes, 48)?,
            manifest_footer_offset: read_u64(bytes, 56)?,
            manifest_footer_length,
            closed_at_ns: read_i64(bytes, 68)?,
            root_auth_footer_offset: read_u64(bytes, 76)?,
            root_auth_footer_length: read_u32(bytes, 84)?,
            root_auth_flags,
            trailer_hmac: read_array_32(bytes, 96)?,
        })
    }

    pub fn to_bytes(&self) -> [u8; VOLUME_TRAILER_LEN] {
        let mut bytes = [0u8; VOLUME_TRAILER_LEN];
        bytes[0..4].copy_from_slice(&TZVT_MAGIC);
        bytes[4..20].copy_from_slice(&self.archive_uuid);
        bytes[20..36].copy_from_slice(&self.session_id);
        write_u32(&mut bytes, 36, self.volume_index);
        write_u64(&mut bytes, 40, self.block_count);
        write_u64(&mut bytes, 48, self.bytes_written);
        write_u64(&mut bytes, 56, self.manifest_footer_offset);
        write_u32(&mut bytes, 64, self.manifest_footer_length);
        write_i64(&mut bytes, 68, self.closed_at_ns);
        write_u64(&mut bytes, 76, self.root_auth_footer_offset);
        write_u32(&mut bytes, 84, self.root_auth_footer_length);
        write_u32(&mut bytes, 88, self.root_auth_flags);
        bytes[96..128].copy_from_slice(&self.trailer_hmac);
        bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootAuthFooterV1 {
    pub archive_uuid: [u8; 16],
    pub session_id: [u8; 16],
    pub format_version: u16,
    pub volume_format_rev: u16,
    pub authenticator_id: u16,
    pub signer_identity_type: u16,
    pub signer_identity_bytes: Vec<u8>,
    pub authenticator_value: Vec<u8>,
    pub total_data_block_count: u64,
    pub critical_metadata_digest: [u8; 32],
    pub index_digest: [u8; 32],
    pub fec_layout_digest: [u8; 32],
    pub data_block_merkle_root: [u8; 32],
    pub signer_identity_digest: [u8; 32],
    pub archive_root: [u8; 32],
    pub footer_crc32c: u32,
}

impl RootAuthFooterV1 {
    pub fn footer_length(&self) -> Result<u32, FormatError> {
        root_auth_footer_length(self.signer_identity_bytes.len(), self.authenticator_value.len())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, FormatError> {
        validate_root_auth_variable_lengths(self.signer_identity_bytes.len(), self.authenticator_value.len())?;
        let footer_length = self.footer_length()?;
        let root_auth_spec_id = root_auth_spec_id_for_revision(self.format_version, self.volume_format_rev)?;
        let mut bytes = vec![0u8; footer_length as usize];
        bytes[0..4].copy_from_slice(&TZRA_MAGIC);
        write_u16(&mut bytes, 4, 1);
        bytes[6..30].copy_from_slice(&root_auth_spec_id);
        write_u32(&mut bytes, 30, footer_length);
        write_u32(&mut bytes, 34, 0);
        bytes[38..54].copy_from_slice(&self.archive_uuid);
        bytes[54..70].copy_from_slice(&self.session_id);
        write_u16(&mut bytes, 70, self.format_version);
        write_u16(&mut bytes, 72, self.volume_format_rev);
        write_u16(&mut bytes, 74, self.authenticator_id);
        write_u16(&mut bytes, 76, self.signer_identity_type);
        write_u32(
            &mut bytes,
            78,
            u32::try_from(self.signer_identity_bytes.len()).map_err(|_| FormatError::InvalidArchive("RootAuthFooterV1 signer identity length overflow"))?,
        );
        write_u32(
            &mut bytes,
            82,
            u32::try_from(self.authenticator_value.len()).map_err(|_| FormatError::InvalidArchive("RootAuthFooterV1 authenticator length overflow"))?,
        );
        write_u64(&mut bytes, 86, self.total_data_block_count);
        bytes[94..126].copy_from_slice(&self.critical_metadata_digest);
        bytes[126..158].copy_from_slice(&self.index_digest);
        bytes[158..190].copy_from_slice(&self.fec_layout_digest);
        bytes[190..222].copy_from_slice(&self.data_block_merkle_root);
        bytes[222..254].copy_from_slice(&self.signer_identity_digest);
        bytes[254..286].copy_from_slice(&self.archive_root);
        let signer_start = ROOT_AUTH_FOOTER_FIXED_LEN;
        let signer_end = signer_start + self.signer_identity_bytes.len();
        bytes[signer_start..signer_end].copy_from_slice(&self.signer_identity_bytes);
        let auth_end = signer_end + self.authenticator_value.len();
        bytes[signer_end..auth_end].copy_from_slice(&self.authenticator_value);
        let crc = crc32c(&bytes[..auth_end]);
        write_u32(&mut bytes, auth_end, crc);
        Ok(bytes)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() > READER_MAX_ROOT_AUTH_FOOTER_LEN as usize {
            return Err(FormatError::ReaderResourceLimitExceeded {
                field: "RootAuthFooterV1 length",
                cap: READER_MAX_ROOT_AUTH_FOOTER_LEN as u64,
                actual: bytes.len() as u64,
            });
        }
        let min_len = ROOT_AUTH_FOOTER_FIXED_LEN + 4;
        if bytes.len() < min_len {
            return Err(FormatError::InvalidLength { structure: "RootAuthFooterV1", expected: min_len, actual: bytes.len() });
        }
        expect_magic("RootAuthFooterV1", TZRA_MAGIC, &bytes[0..4])?;
        let version = read_u16(bytes, 4)?;
        if version != 1 {
            return Err(FormatError::UnsupportedFormatVersion(version));
        }
        let root_auth_spec_id = read_array_24(bytes, 6)?;
        let footer_length = read_u32(bytes, 30)?;
        if footer_length as usize != bytes.len() {
            return Err(FormatError::InvalidLength { structure: "RootAuthFooterV1", expected: footer_length as usize, actual: bytes.len() });
        }
        if read_u32(bytes, 34)? != 0 {
            return Err(FormatError::InvalidArchive("RootAuthFooterV1 flags must be zero"));
        }
        let format_version = read_u16(bytes, 70)?;
        if format_version != FORMAT_VERSION {
            return Err(FormatError::UnsupportedFormatVersion(format_version));
        }
        let volume_format_rev = read_u16(bytes, 72)?;
        if root_auth_spec_id != root_auth_spec_id_for_revision(format_version, volume_format_rev)? {
            return Err(FormatError::InvalidArchive("RootAuthFooterV1 root_auth_spec_id does not match volume_format_rev"));
        }
        let signer_identity_length = read_u32(bytes, 78)?;
        let authenticator_value_length = read_u32(bytes, 82)?;
        validate_root_auth_variable_lengths(signer_identity_length as usize, authenticator_value_length as usize)?;
        let expected = root_auth_footer_length(signer_identity_length as usize, authenticator_value_length as usize)?;
        if expected != footer_length {
            return Err(FormatError::InvalidLength { structure: "RootAuthFooterV1", expected: expected as usize, actual: footer_length as usize });
        }
        expect_zero("RootAuthFooterV1", &bytes[286..318])?;
        let crc_offset = bytes.len() - 4;
        expect_crc("RootAuthFooterV1", &bytes[..crc_offset], read_u32(bytes, crc_offset)?)?;

        let signer_start = ROOT_AUTH_FOOTER_FIXED_LEN;
        let signer_end = signer_start + signer_identity_length as usize;
        let auth_end = signer_end + authenticator_value_length as usize;
        Ok(Self {
            archive_uuid: read_array_16(bytes, 38)?,
            session_id: read_array_16(bytes, 54)?,
            format_version,
            volume_format_rev,
            authenticator_id: read_u16(bytes, 74)?,
            signer_identity_type: read_u16(bytes, 76)?,
            signer_identity_bytes: bytes[signer_start..signer_end].to_vec(),
            authenticator_value: bytes[signer_end..auth_end].to_vec(),
            total_data_block_count: read_u64(bytes, 86)?,
            critical_metadata_digest: read_array_32(bytes, 94)?,
            index_digest: read_array_32(bytes, 126)?,
            fec_layout_digest: read_array_32(bytes, 158)?,
            data_block_merkle_root: read_array_32(bytes, 190)?,
            signer_identity_digest: read_array_32(bytes, 222)?,
            archive_root: read_array_32(bytes, 254)?,
            footer_crc32c: read_u32(bytes, crc_offset)?,
        })
    }
}

fn root_auth_footer_length(signer_identity_len: usize, authenticator_value_len: usize) -> Result<u32, FormatError> {
    let len = ROOT_AUTH_FOOTER_FIXED_LEN
        .checked_add(signer_identity_len)
        .and_then(|value| value.checked_add(authenticator_value_len))
        .and_then(|value| value.checked_add(4))
        .ok_or(FormatError::InvalidArchive("RootAuthFooterV1 length overflow"))?;
    if len > READER_MAX_ROOT_AUTH_FOOTER_LEN as usize {
        return Err(FormatError::ReaderResourceLimitExceeded {
            field: "RootAuthFooterV1 length",
            cap: READER_MAX_ROOT_AUTH_FOOTER_LEN as u64,
            actual: len as u64,
        });
    }
    u32::try_from(len).map_err(|_| FormatError::InvalidArchive("RootAuthFooterV1 length overflow"))
}

fn validate_root_auth_variable_lengths(signer_identity_len: usize, authenticator_value_len: usize) -> Result<(), FormatError> {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerializedRegion {
    pub region_type: u16,
    pub offset: u64,
    pub bytes: Vec<u8>,
}

impl SerializedRegion {
    pub fn encoded_len(&self) -> usize {
        SERIALIZED_REGION_HEADER_LEN + self.bytes.len()
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, FormatError> {
        let length = u32::try_from(self.bytes.len()).map_err(|_| FormatError::InvalidArchive("SerializedRegion length exceeds u32"))?;
        let mut bytes = vec![0u8; self.encoded_len()];
        write_u16(&mut bytes, 0, self.region_type);
        write_u64(&mut bytes, 4, self.offset);
        write_u32(&mut bytes, 12, length);
        bytes[SERIALIZED_REGION_HEADER_LEN..].copy_from_slice(&self.bytes);
        Ok(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CriticalMetadataImage {
    pub volume_format_rev: u16,
    pub archive_uuid: [u8; 16],
    pub session_id: [u8; 16],
    pub volume_index: u32,
    pub stripe_width: u32,
    pub layout_flags: u32,
    pub volume_header_offset: u64,
    pub volume_header_length: u32,
    pub crypto_header_offset: u64,
    pub crypto_header_length: u32,
    pub key_wrap_table_offset: u64,
    pub key_wrap_table_length: u32,
    pub block_records_offset: u64,
    pub block_records_length: u64,
    pub block_count: u64,
    pub manifest_footer_offset: u64,
    pub manifest_footer_length: u32,
    pub root_auth_footer_offset: u64,
    pub root_auth_footer_length: u32,
    pub volume_trailer_offset: u64,
    pub volume_trailer_length: u32,
    pub body_bytes_before_cmra: u64,
    pub volume_header_sha256: [u8; 32],
    pub crypto_header_sha256: [u8; 32],
    pub key_wrap_table_sha256: [u8; 32],
    pub manifest_footer_sha256: [u8; 32],
    pub root_auth_footer_sha256: [u8; 32],
    pub volume_trailer_sha256: [u8; 32],
    pub regions: Vec<SerializedRegion>,
}

fn critical_metadata_image_fixed_len(volume_format_rev: u16) -> Result<usize, FormatError> {
    if volume_format_rev == VOLUME_FORMAT_REV_45 {
        Ok(CRITICAL_METADATA_IMAGE_FIXED_LEN)
    } else {
        Err(FormatError::UnsupportedVolumeFormatRevision {
            format_version: FORMAT_VERSION,
            volume_format_rev,
            reader_max_supported_revision: READER_MAX_SUPPORTED_VOLUME_FORMAT_REV,
        })
    }
}

impl CriticalMetadataImage {
    pub fn to_bytes(&self) -> Result<Vec<u8>, FormatError> {
        let fixed_len = critical_metadata_image_fixed_len(self.volume_format_rev)?;
        let region_count = u16::try_from(self.regions.len()).map_err(|_| FormatError::InvalidArchive("CriticalMetadataImage has too many regions"))?;
        let variable_len = self.regions.iter().try_fold(0usize, |total, region| {
            total.checked_add(region.encoded_len()).ok_or(FormatError::InvalidArchive("CriticalMetadataImage length overflow"))
        })?;
        let mut bytes = vec![
            0u8;
            fixed_len
                .checked_add(variable_len)
                .and_then(|value| value.checked_add(IMAGE_CRC_LEN))
                .ok_or(FormatError::InvalidArchive("CriticalMetadataImage length overflow",))?
        ];
        bytes[0..4].copy_from_slice(&TZMI_MAGIC);
        write_u16(&mut bytes, 4, 1);
        write_u16(&mut bytes, 6, self.volume_format_rev);
        bytes[8..24].copy_from_slice(&self.archive_uuid);
        bytes[24..40].copy_from_slice(&self.session_id);
        write_u32(&mut bytes, 40, self.volume_index);
        write_u32(&mut bytes, 44, self.stripe_width);
        write_u32(&mut bytes, 48, self.layout_flags);
        write_u64(&mut bytes, 52, self.volume_header_offset);
        write_u32(&mut bytes, 60, self.volume_header_length);
        write_u64(&mut bytes, 64, self.crypto_header_offset);
        write_u32(&mut bytes, 72, self.crypto_header_length);
        write_u64(&mut bytes, 76, self.key_wrap_table_offset);
        write_u32(&mut bytes, 84, self.key_wrap_table_length);
        write_u64(&mut bytes, 88, self.block_records_offset);
        write_u64(&mut bytes, 96, self.block_records_length);
        write_u64(&mut bytes, 104, self.block_count);
        write_u64(&mut bytes, 112, self.manifest_footer_offset);
        write_u32(&mut bytes, 120, self.manifest_footer_length);
        write_u64(&mut bytes, 124, self.root_auth_footer_offset);
        write_u32(&mut bytes, 132, self.root_auth_footer_length);
        write_u64(&mut bytes, 136, self.volume_trailer_offset);
        write_u32(&mut bytes, 144, self.volume_trailer_length);
        write_u64(&mut bytes, 148, self.body_bytes_before_cmra);
        bytes[156..188].copy_from_slice(&self.volume_header_sha256);
        bytes[188..220].copy_from_slice(&self.crypto_header_sha256);
        bytes[220..252].copy_from_slice(&self.key_wrap_table_sha256);
        bytes[252..284].copy_from_slice(&self.manifest_footer_sha256);
        bytes[284..316].copy_from_slice(&self.root_auth_footer_sha256);
        bytes[316..348].copy_from_slice(&self.volume_trailer_sha256);
        write_u16(&mut bytes, 348, region_count);

        let mut cursor = fixed_len;
        for region in &self.regions {
            let region_bytes = region.to_bytes()?;
            let end = cursor + region_bytes.len();
            bytes[cursor..end].copy_from_slice(&region_bytes);
            cursor = end;
        }
        let crc = crc32c(&bytes[..cursor]);
        write_u32(&mut bytes, cursor, crc);
        Ok(bytes)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() < 8 + IMAGE_CRC_LEN {
            return Err(FormatError::InvalidLength { structure: "CriticalMetadataImageV1", expected: 8 + IMAGE_CRC_LEN, actual: bytes.len() });
        }
        expect_magic("CriticalMetadataImageV1", TZMI_MAGIC, &bytes[0..4])?;
        let version = read_u16(bytes, 4)?;
        if version != 1 {
            return Err(FormatError::UnsupportedFormatVersion(version));
        }
        let volume_format_rev = read_u16(bytes, 6)?;
        let fixed_len = critical_metadata_image_fixed_len(volume_format_rev)?;
        if bytes.len() < fixed_len + IMAGE_CRC_LEN {
            return Err(FormatError::InvalidLength { structure: "CriticalMetadataImageV1", expected: fixed_len + IMAGE_CRC_LEN, actual: bytes.len() });
        }
        let layout_flags = read_u32(bytes, 48)?;
        if layout_flags & !0x0000_0003 != 0 {
            return Err(FormatError::InvalidArchive("CriticalMetadataImage layout_flags has unknown bits"));
        }
        expect_zero("CriticalMetadataImageV1", &bytes[350..364])?;
        let expected_crc_offset = bytes.len().checked_sub(IMAGE_CRC_LEN).ok_or(FormatError::InvalidArchive("CriticalMetadataImage length underflow"))?;
        expect_crc("CriticalMetadataImageV1", &bytes[..expected_crc_offset], read_u32(bytes, expected_crc_offset)?)?;

        let serialized_region_count = read_u16(bytes, 348)? as usize;
        let mut cursor = fixed_len;
        let mut regions = Vec::with_capacity(serialized_region_count);
        for _ in 0..serialized_region_count {
            if cursor + SERIALIZED_REGION_HEADER_LEN > expected_crc_offset {
                return Err(FormatError::InvalidLength { structure: "SerializedRegion", expected: cursor + SERIALIZED_REGION_HEADER_LEN, actual: bytes.len() });
            }
            let region_type = read_u16(bytes, cursor)?;
            if read_u16(bytes, cursor + 2)? != 0 {
                return Err(FormatError::NonZeroReserved { structure: "SerializedRegion" });
            }
            let offset = read_u64(bytes, cursor + 4)?;
            let length = read_u32(bytes, cursor + 12)? as usize;
            cursor += SERIALIZED_REGION_HEADER_LEN;
            let end = cursor.checked_add(length).ok_or(FormatError::InvalidArchive("SerializedRegion length overflow"))?;
            if end > expected_crc_offset {
                return Err(FormatError::InvalidLength { structure: "SerializedRegion", expected: end, actual: bytes.len() });
            }
            regions.push(SerializedRegion { region_type, offset, bytes: bytes[cursor..end].to_vec() });
            cursor = end;
        }
        if cursor != expected_crc_offset {
            return Err(FormatError::InvalidArchive("CriticalMetadataImage has trailing region bytes"));
        }

        Ok(Self {
            volume_format_rev,
            archive_uuid: read_array_16(bytes, 8)?,
            session_id: read_array_16(bytes, 24)?,
            volume_index: read_u32(bytes, 40)?,
            stripe_width: read_u32(bytes, 44)?,
            layout_flags,
            volume_header_offset: read_u64(bytes, 52)?,
            volume_header_length: read_u32(bytes, 60)?,
            crypto_header_offset: read_u64(bytes, 64)?,
            crypto_header_length: read_u32(bytes, 72)?,
            key_wrap_table_offset: read_u64(bytes, 76)?,
            key_wrap_table_length: read_u32(bytes, 84)?,
            block_records_offset: read_u64(bytes, 88)?,
            block_records_length: read_u64(bytes, 96)?,
            block_count: read_u64(bytes, 104)?,
            manifest_footer_offset: read_u64(bytes, 112)?,
            manifest_footer_length: read_u32(bytes, 120)?,
            root_auth_footer_offset: read_u64(bytes, 124)?,
            root_auth_footer_length: read_u32(bytes, 132)?,
            volume_trailer_offset: read_u64(bytes, 136)?,
            volume_trailer_length: read_u32(bytes, 144)?,
            body_bytes_before_cmra: read_u64(bytes, 148)?,
            volume_header_sha256: read_array_32(bytes, 156)?,
            crypto_header_sha256: read_array_32(bytes, 188)?,
            key_wrap_table_sha256: read_array_32(bytes, 220)?,
            manifest_footer_sha256: read_array_32(bytes, 252)?,
            root_auth_footer_sha256: read_array_32(bytes, 284)?,
            volume_trailer_sha256: read_array_32(bytes, 316)?,
            regions,
        })
    }

    pub fn region(&self, region_type: u16) -> Option<&SerializedRegion> {
        self.regions.iter().find(|region| region.region_type == region_type)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CriticalMetadataRecoveryHeader {
    pub shard_size: u32,
    pub data_shard_count: u16,
    pub parity_shard_count: u16,
    pub image_length: u32,
    pub archive_uuid_hint: [u8; 16],
    pub session_id_hint: [u8; 16],
    pub volume_index_hint: u32,
    pub image_sha256: [u8; 32],
    pub header_crc32c: u32,
}

impl CriticalMetadataRecoveryHeader {
    pub fn parse(bytes: &[u8]) -> Result<Self, FormatError> {
        expect_len("CriticalMetadataRecoveryHeader", CRITICAL_METADATA_RECOVERY_HEADER_LEN, bytes.len())?;
        expect_magic("CriticalMetadataRecoveryHeader", TZCR_MAGIC, &bytes[0..4])?;
        let version = read_u16(bytes, 4)?;
        if version != 1 {
            return Err(FormatError::UnsupportedFormatVersion(version));
        }
        let fec_algo = read_u16(bytes, 6)?;
        if fec_algo != FecAlgo::ReedSolomonGF16 as u16 {
            return Err(FormatError::UnknownFecAlgo(fec_algo));
        }
        expect_zero("CriticalMetadataRecoveryHeader", &bytes[88..112])?;
        expect_crc("CriticalMetadataRecoveryHeader", &bytes[..112], read_u32(bytes, 112)?)?;
        Ok(Self {
            shard_size: read_u32(bytes, 8)?,
            data_shard_count: read_u16(bytes, 12)?,
            parity_shard_count: read_u16(bytes, 14)?,
            image_length: read_u32(bytes, 16)?,
            archive_uuid_hint: read_array_16(bytes, 20)?,
            session_id_hint: read_array_16(bytes, 36)?,
            volume_index_hint: read_u32(bytes, 52)?,
            image_sha256: read_array_32(bytes, 56)?,
            header_crc32c: read_u32(bytes, 112)?,
        })
    }

    pub fn to_bytes(&self) -> [u8; CRITICAL_METADATA_RECOVERY_HEADER_LEN] {
        let mut bytes = [0u8; CRITICAL_METADATA_RECOVERY_HEADER_LEN];
        bytes[0..4].copy_from_slice(&TZCR_MAGIC);
        write_u16(&mut bytes, 4, 1);
        write_u16(&mut bytes, 6, FecAlgo::ReedSolomonGF16 as u16);
        write_u32(&mut bytes, 8, self.shard_size);
        write_u16(&mut bytes, 12, self.data_shard_count);
        write_u16(&mut bytes, 14, self.parity_shard_count);
        write_u32(&mut bytes, 16, self.image_length);
        bytes[20..36].copy_from_slice(&self.archive_uuid_hint);
        bytes[36..52].copy_from_slice(&self.session_id_hint);
        write_u32(&mut bytes, 52, self.volume_index_hint);
        bytes[56..88].copy_from_slice(&self.image_sha256);
        let crc = crc32c(&bytes[..112]);
        write_u32(&mut bytes, 112, crc);
        bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CriticalMetadataRecoveryShard {
    pub shard_index: u16,
    pub shard_role: u8,
    pub shard_payload_length: u32,
    pub payload: Vec<u8>,
    pub shard_crc32c: u32,
}

impl CriticalMetadataRecoveryShard {
    pub fn parse(bytes: &[u8], shard_size: usize) -> Result<Self, FormatError> {
        let expected = CRITICAL_METADATA_RECOVERY_SHARD_HEADER_LEN.checked_add(shard_size).ok_or(FormatError::InvalidArchive("CMRA shard length overflow"))?;
        expect_len("CriticalMetadataRecoveryShard", expected, bytes.len())?;
        expect_magic("CriticalMetadataRecoveryShard", TZCS_MAGIC, &bytes[0..4])?;
        if bytes[7] != 0 {
            return Err(FormatError::NonZeroReserved { structure: "CriticalMetadataRecoveryShard" });
        }
        let shard_role = bytes[6];
        if shard_role > 1 {
            return Err(FormatError::InvalidArchive("CriticalMetadataRecoveryShard has unknown role"));
        }
        expect_crc("CriticalMetadataRecoveryShard", &[&bytes[..12], &bytes[CRITICAL_METADATA_RECOVERY_SHARD_HEADER_LEN..]].concat(), read_u32(bytes, 12)?)?;
        let shard_payload_length = read_u32(bytes, 8)?;
        if shard_payload_length as usize > shard_size {
            return Err(FormatError::InvalidArchive("CriticalMetadataRecoveryShard payload length exceeds shard size"));
        }
        Ok(Self {
            shard_index: read_u16(bytes, 4)?,
            shard_role,
            shard_payload_length,
            payload: bytes[CRITICAL_METADATA_RECOVERY_SHARD_HEADER_LEN..].to_vec(),
            shard_crc32c: read_u32(bytes, 12)?,
        })
    }

    pub fn to_bytes(&self, shard_size: usize) -> Result<Vec<u8>, FormatError> {
        if self.payload.len() != shard_size {
            return Err(FormatError::InvalidArchive("CriticalMetadataRecoveryShard payload length mismatch"));
        }
        let mut bytes = vec![0u8; CRITICAL_METADATA_RECOVERY_SHARD_HEADER_LEN + shard_size];
        bytes[0..4].copy_from_slice(&TZCS_MAGIC);
        write_u16(&mut bytes, 4, self.shard_index);
        bytes[6] = self.shard_role;
        write_u32(&mut bytes, 8, self.shard_payload_length);
        bytes[CRITICAL_METADATA_RECOVERY_SHARD_HEADER_LEN..].copy_from_slice(&self.payload);
        let mut covered = Vec::with_capacity(12 + shard_size);
        covered.extend_from_slice(&bytes[..12]);
        covered.extend_from_slice(&bytes[CRITICAL_METADATA_RECOVERY_SHARD_HEADER_LEN..]);
        let crc = crc32c(&covered);
        write_u32(&mut bytes, 12, crc);
        Ok(bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CriticalRecoveryLocator {
    pub volume_format_rev: u16,
    pub cmra_offset: u64,
    pub cmra_length: u32,
    pub volume_trailer_offset: u64,
    pub body_bytes_before_cmra: u64,
    pub archive_uuid_hint: [u8; 16],
    pub session_id_hint: [u8; 16],
    pub volume_index_hint: u32,
    pub locator_sequence: u32,
    pub cmra_shard_size: u32,
    pub cmra_data_shard_count: u16,
    pub cmra_parity_shard_count: u16,
    pub cmra_image_length: u32,
    pub cmra_image_sha256: [u8; 32],
    pub locator_crc32c: u32,
}

impl CriticalRecoveryLocator {
    pub fn parse(bytes: &[u8]) -> Result<Self, FormatError> {
        expect_len("CriticalRecoveryLocator", CRITICAL_RECOVERY_LOCATOR_LEN, bytes.len())?;
        expect_magic("CriticalRecoveryLocator", TZCL_MAGIC, &bytes[0..4])?;
        let version = read_u16(bytes, 4)?;
        if version != 1 {
            return Err(FormatError::UnsupportedFormatVersion(version));
        }
        let volume_format_rev = read_u16(bytes, 6)?;
        if volume_format_rev != VOLUME_FORMAT_REV_45 {
            return Err(FormatError::UnsupportedVolumeFormatRevision {
                format_version: FORMAT_VERSION,
                volume_format_rev,
                reader_max_supported_revision: READER_MAX_SUPPORTED_VOLUME_FORMAT_REV,
            });
        }
        if read_u16(bytes, 20)? != CRITICAL_METADATA_RECOVERY_HEADER_LEN as u16 {
            return Err(FormatError::InvalidArchive("CriticalRecoveryLocator CMRA header length is invalid"));
        }
        let fec_algo = read_u16(bytes, 22)?;
        if fec_algo != FecAlgo::ReedSolomonGF16 as u16 {
            return Err(FormatError::UnknownFecAlgo(fec_algo));
        }
        let locator_sequence = read_u32(bytes, 76)?;
        if locator_sequence > 1 {
            return Err(FormatError::InvalidArchive("CriticalRecoveryLocator has invalid sequence"));
        }
        expect_crc("CriticalRecoveryLocator", &bytes[..124], read_u32(bytes, 124)?)?;

        Ok(Self {
            volume_format_rev,
            cmra_offset: read_u64(bytes, 8)?,
            cmra_length: read_u32(bytes, 16)?,
            volume_trailer_offset: read_u64(bytes, 24)?,
            body_bytes_before_cmra: read_u64(bytes, 32)?,
            archive_uuid_hint: read_array_16(bytes, 40)?,
            session_id_hint: read_array_16(bytes, 56)?,
            volume_index_hint: read_u32(bytes, 72)?,
            locator_sequence,
            cmra_shard_size: read_u32(bytes, 80)?,
            cmra_data_shard_count: read_u16(bytes, 84)?,
            cmra_parity_shard_count: read_u16(bytes, 86)?,
            cmra_image_length: read_u32(bytes, 88)?,
            cmra_image_sha256: read_array_32(bytes, 92)?,
            locator_crc32c: read_u32(bytes, 124)?,
        })
    }

    pub fn to_bytes(&self) -> [u8; CRITICAL_RECOVERY_LOCATOR_LEN] {
        let mut bytes = [0u8; CRITICAL_RECOVERY_LOCATOR_LEN];
        bytes[0..4].copy_from_slice(&TZCL_MAGIC);
        write_u16(&mut bytes, 4, 1);
        write_u16(&mut bytes, 6, self.volume_format_rev);
        write_u64(&mut bytes, 8, self.cmra_offset);
        write_u32(&mut bytes, 16, self.cmra_length);
        write_u16(&mut bytes, 20, CRITICAL_METADATA_RECOVERY_HEADER_LEN as u16);
        write_u16(&mut bytes, 22, FecAlgo::ReedSolomonGF16 as u16);
        write_u64(&mut bytes, 24, self.volume_trailer_offset);
        write_u64(&mut bytes, 32, self.body_bytes_before_cmra);
        bytes[40..56].copy_from_slice(&self.archive_uuid_hint);
        bytes[56..72].copy_from_slice(&self.session_id_hint);
        write_u32(&mut bytes, 72, self.volume_index_hint);
        write_u32(&mut bytes, 76, self.locator_sequence);
        write_u32(&mut bytes, 80, self.cmra_shard_size);
        write_u16(&mut bytes, 84, self.cmra_data_shard_count);
        write_u16(&mut bytes, 86, self.cmra_parity_shard_count);
        write_u32(&mut bytes, 88, self.cmra_image_length);
        bytes[92..124].copy_from_slice(&self.cmra_image_sha256);
        let crc = crc32c(&bytes[..124]);
        write_u32(&mut bytes, 124, crc);
        bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapSidecarHeader {
    pub archive_uuid: [u8; 16],
    pub session_id: [u8; 16],
    pub flags: u32,
    pub manifest_footer_offset: u64,
    pub manifest_footer_length: u32,
    pub index_root_records_offset: u64,
    pub index_root_records_length: u64,
    pub dictionary_records_offset: u64,
    pub dictionary_records_length: u64,
    pub sidecar_hmac: [u8; 32],
    pub header_crc32c: u32,
}

impl BootstrapSidecarHeader {
    pub fn parse(bytes: &[u8]) -> Result<Self, FormatError> {
        expect_len("BootstrapSidecarHeader", BOOTSTRAP_SIDECAR_HEADER_LEN, bytes.len())?;
        expect_magic("BootstrapSidecarHeader", TZBS_MAGIC, &bytes[0..4])?;
        let version = read_u32(bytes, 4)?;
        if version != 1 {
            return Err(FormatError::UnsupportedBootstrapSidecarVersion(version));
        }
        expect_zero("BootstrapSidecarHeader", &bytes[88..92])?;
        expect_crc("BootstrapSidecarHeader", &bytes[..124], read_u32(bytes, 124)?)?;

        let header = Self {
            archive_uuid: read_array_16(bytes, 8)?,
            session_id: read_array_16(bytes, 24)?,
            flags: read_u32(bytes, 40)?,
            manifest_footer_offset: read_u64(bytes, 44)?,
            manifest_footer_length: read_u32(bytes, 52)?,
            index_root_records_offset: read_u64(bytes, 56)?,
            index_root_records_length: read_u64(bytes, 64)?,
            dictionary_records_offset: read_u64(bytes, 72)?,
            dictionary_records_length: read_u64(bytes, 80)?,
            sidecar_hmac: read_array_32(bytes, 92)?,
            header_crc32c: read_u32(bytes, 124)?,
        };
        header.validate_sections()?;
        Ok(header)
    }

    pub fn validate_packed_layout(&self, file_size: u64) -> Result<(), FormatError> {
        let mut cursor = BOOTSTRAP_SIDECAR_HEADER_LEN as u64;
        cursor = self.validate_section_cursor(self.has_manifest_footer(), self.manifest_footer_offset, self.manifest_footer_length as u64, cursor)?;
        cursor = self.validate_section_cursor(self.has_index_root_records(), self.index_root_records_offset, self.index_root_records_length, cursor)?;
        cursor = self.validate_section_cursor(self.has_dictionary_records(), self.dictionary_records_offset, self.dictionary_records_length, cursor)?;
        if cursor != file_size {
            return Err(FormatError::NonCanonicalBootstrapSidecarLayout);
        }
        Ok(())
    }

    pub fn has_manifest_footer(&self) -> bool {
        self.flags & SIDECAR_MANIFEST_PRESENT != 0
    }

    pub fn has_index_root_records(&self) -> bool {
        self.flags & SIDECAR_INDEX_ROOT_PRESENT != 0
    }

    pub fn has_dictionary_records(&self) -> bool {
        self.flags & SIDECAR_DICTIONARY_PRESENT != 0
    }

    pub fn to_bytes(&self) -> [u8; BOOTSTRAP_SIDECAR_HEADER_LEN] {
        let mut bytes = [0u8; BOOTSTRAP_SIDECAR_HEADER_LEN];
        bytes[0..4].copy_from_slice(&TZBS_MAGIC);
        write_u32(&mut bytes, 4, 1);
        bytes[8..24].copy_from_slice(&self.archive_uuid);
        bytes[24..40].copy_from_slice(&self.session_id);
        write_u32(&mut bytes, 40, self.flags);
        write_u64(&mut bytes, 44, self.manifest_footer_offset);
        write_u32(&mut bytes, 52, self.manifest_footer_length);
        write_u64(&mut bytes, 56, self.index_root_records_offset);
        write_u64(&mut bytes, 64, self.index_root_records_length);
        write_u64(&mut bytes, 72, self.dictionary_records_offset);
        write_u64(&mut bytes, 80, self.dictionary_records_length);
        bytes[92..124].copy_from_slice(&self.sidecar_hmac);
        let crc = crc32c(&bytes[..124]);
        write_u32(&mut bytes, 124, crc);
        bytes
    }

    fn validate_sections(&self) -> Result<(), FormatError> {
        if self.flags & !SIDECAR_KNOWN_FLAGS != 0 {
            return Err(FormatError::UnknownBootstrapSidecarFlags(self.flags));
        }
        self.validate_presence_fields(self.has_manifest_footer(), self.manifest_footer_offset, self.manifest_footer_length as u64)?;
        if self.has_manifest_footer() && self.manifest_footer_length != MANIFEST_FOOTER_LEN as u32 {
            return Err(FormatError::InvalidManifestFooterLength(self.manifest_footer_length));
        }
        self.validate_presence_fields(self.has_index_root_records(), self.index_root_records_offset, self.index_root_records_length)?;
        self.validate_presence_fields(self.has_dictionary_records(), self.dictionary_records_offset, self.dictionary_records_length)?;
        Ok(())
    }

    fn validate_presence_fields(&self, present: bool, offset: u64, length: u64) -> Result<(), FormatError> {
        match (present, offset, length) {
            (true, 0, _) | (true, _, 0) => Err(FormatError::EmptyBootstrapSidecarSection),
            (false, 0, 0) => Ok(()),
            (false, _, _) => Err(FormatError::NonZeroAbsentBootstrapSidecarSection),
            (true, _, _) => Ok(()),
        }
    }

    fn validate_section_cursor(&self, present: bool, offset: u64, length: u64, cursor: u64) -> Result<u64, FormatError> {
        if present {
            if offset != cursor {
                return Err(FormatError::NonCanonicalBootstrapSidecarLayout);
            }
            cursor.checked_add(length).ok_or(FormatError::NonCanonicalBootstrapSidecarLayout)
        } else {
            Ok(cursor)
        }
    }
}

fn is_known_extension(ext_tag: u16) -> bool {
    matches!(ext_tag, 0x0001 | 0x0002 | 0x0003 | 0x0005)
}

fn validate_known_extension(ext_tag: u16, value: &[u8]) -> Result<(), FormatError> {
    match ext_tag {
        0x0001 | 0x0002 | 0x0005 => std::str::from_utf8(value).map(|_| ()).map_err(|_| FormatError::MalformedKnownExtension(ext_tag)),
        0x0003 => {
            if value.len() == 8 {
                Ok(())
            } else {
                Err(FormatError::MalformedKnownExtension(ext_tag))
            }
        }
        _ => Ok(()),
    }
}

fn expect_len(structure: &'static str, expected: usize, actual: usize) -> Result<(), FormatError> {
    if actual != expected {
        return Err(FormatError::InvalidLength { structure, expected, actual });
    }
    Ok(())
}

fn u32_len(value: usize, field: &'static str) -> Result<u32, FormatError> {
    u32::try_from(value).map_err(|_| FormatError::WriterUnsupported(field))
}

fn expect_magic(structure: &'static str, expected: [u8; 4], actual: &[u8]) -> Result<(), FormatError> {
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

fn expect_crc(structure: &'static str, covered: &[u8], expected: u32) -> Result<(), FormatError> {
    if crc32c(covered) != expected {
        return Err(FormatError::BadCrc { structure });
    }
    Ok(())
}

fn read_array_16(bytes: &[u8], offset: usize) -> Result<[u8; 16], FormatError> {
    let mut value = [0u8; 16];
    value.copy_from_slice(bytes.get(offset..offset + 16).ok_or(FormatError::InvalidLength {
        structure: "array16",
        expected: offset + 16,
        actual: bytes.len(),
    })?);
    Ok(value)
}

fn read_array_24(bytes: &[u8], offset: usize) -> Result<[u8; 24], FormatError> {
    let mut value = [0u8; 24];
    value.copy_from_slice(bytes.get(offset..offset + 24).ok_or(FormatError::InvalidLength {
        structure: "array24",
        expected: offset + 24,
        actual: bytes.len(),
    })?);
    Ok(value)
}

fn read_array_32(bytes: &[u8], offset: usize) -> Result<[u8; 32], FormatError> {
    let mut value = [0u8; 32];
    value.copy_from_slice(bytes.get(offset..offset + 32).ok_or(FormatError::InvalidLength {
        structure: "array32",
        expected: offset + 32,
        actual: bytes.len(),
    })?);
    Ok(value)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, FormatError> {
    let array: [u8; 2] = bytes
        .get(offset..offset + 2)
        .ok_or(FormatError::InvalidLength { structure: "u16", expected: offset + 2, actual: bytes.len() })?
        .try_into()
        .expect("slice length checked");
    Ok(u16::from_le_bytes(array))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, FormatError> {
    let array: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or(FormatError::InvalidLength { structure: "u32", expected: offset + 4, actual: bytes.len() })?
        .try_into()
        .expect("slice length checked");
    Ok(u32::from_le_bytes(array))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, FormatError> {
    let array: [u8; 8] = bytes
        .get(offset..offset + 8)
        .ok_or(FormatError::InvalidLength { structure: "u64", expected: offset + 8, actual: bytes.len() })?
        .try_into()
        .expect("slice length checked");
    Ok(u64::from_le_bytes(array))
}

fn read_i64(bytes: &[u8], offset: usize) -> Result<i64, FormatError> {
    let array: [u8; 8] = bytes
        .get(offset..offset + 8)
        .ok_or(FormatError::InvalidLength { structure: "i64", expected: offset + 8, actual: bytes.len() })?
        .try_into()
        .expect("slice length checked");
    Ok(i64::from_le_bytes(array))
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{CRYPTO_HEADER_HMAC_LEN, VOLUME_FORMAT_REV};
    use sha2::{Digest, Sha256};

    fn uuid() -> [u8; 16] {
        [0x11; 16]
    }

    fn session() -> [u8; 16] {
        [0x22; 16]
    }

    fn volume_header() -> VolumeHeader {
        VolumeHeader {
            format_version: FORMAT_VERSION,
            volume_format_rev: VOLUME_FORMAT_REV,
            volume_index: 0,
            stripe_width: 1,
            archive_uuid: uuid(),
            session_id: session(),
            crypto_header_offset: VOLUME_HEADER_LEN as u32,
            crypto_header_length: 128,
            header_crc32c: 0,
        }
    }

    fn crypto_fixed() -> CryptoHeaderFixed {
        CryptoHeaderFixed {
            length: (CRYPTO_HEADER_FIXED_LEN + 2 + 6 + CRYPTO_HEADER_HMAC_LEN) as u32,
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
        }
    }

    fn recipient_record_bytes() -> Vec<u8> {
        recipient_record_bytes_with_profile_and_payload(1, b"alice", b"profile")
    }

    fn recipient_record_bytes_with_profile_and_payload(profile_id: u16, identity: &[u8], profile_payload: &[u8]) -> Vec<u8> {
        let mut digest = Sha256::new();
        digest.update(identity);
        let identity_digest = digest.finalize();

        let mut bytes = vec![0u8; KEY_WRAP_RECORD_HEADER_LEN];
        let record_length = KEY_WRAP_RECORD_HEADER_LEN.checked_add(identity.len()).and_then(|value| value.checked_add(profile_payload.len())).unwrap() as u32;
        write_u16(&mut bytes, 4, profile_id);
        write_u16(&mut bytes, 6, 2);
        write_u32(&mut bytes, 12, identity.len() as u32);
        write_u32(&mut bytes, 16, profile_payload.len() as u32);
        bytes[20..52].copy_from_slice(&identity_digest);
        bytes.extend_from_slice(identity);
        bytes.extend_from_slice(profile_payload);
        write_u32(&mut bytes, 0, record_length);
        bytes
    }

    fn key_wrap_table_bytes() -> (Vec<u8>, u32) {
        let records = recipient_record_bytes();
        let record_count = 1u32;
        let records_length = records.len() as u32;
        let table_length = KEY_WRAP_TABLE_HEADER_LEN as u32 + records_length;

        let mut bytes = vec![0u8; KEY_WRAP_TABLE_HEADER_LEN];
        bytes[0..4].copy_from_slice(&TZKW_MAGIC);
        write_u16(&mut bytes, 4, KEY_WRAP_TABLE_VERSION);
        write_u16(&mut bytes, 6, VOLUME_FORMAT_REV_45);
        write_u32(&mut bytes, 8, table_length);
        write_u32(&mut bytes, 12, KEY_WRAP_TABLE_HEADER_LEN as u32);
        bytes[20..36].copy_from_slice(&uuid());
        bytes[36..52].copy_from_slice(&session());
        write_u32(&mut bytes, 52, record_count);
        write_u32(&mut bytes, 56, KEY_WRAP_TABLE_HEADER_LEN as u32);
        write_u32(&mut bytes, 60, records_length);
        bytes.extend(records);
        (bytes, table_length)
    }

    fn raw_crypto_header_bytes() -> Vec<u8> {
        let fixed = crypto_fixed();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&fixed.to_bytes());
        bytes.extend_from_slice(&(KdfAlgo::Raw as u16).to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&[0xab; CRYPTO_HEADER_HMAC_LEN]);
        bytes
    }

    #[test]
    fn volume_header_round_trips_and_validates() {
        let bytes = volume_header().to_bytes();
        let parsed = VolumeHeader::parse(&bytes).unwrap();
        assert_eq!(parsed.format_version, FORMAT_VERSION);
        assert_eq!(parsed.volume_format_rev, VOLUME_FORMAT_REV);
        assert_eq!(parsed.crypto_header_offset, VOLUME_HEADER_LEN as u32);
    }

    #[test]
    fn volume_header_rejects_mutations() {
        let mut bytes = volume_header().to_bytes();
        bytes[0] = b'X';
        assert_eq!(VolumeHeader::parse(&bytes).unwrap_err(), FormatError::BadMagic { structure: "VolumeHeader" });

        let mut bytes = volume_header().to_bytes();
        write_u16(&mut bytes, 6, 35);
        let crc = crc32c(&bytes[..124]);
        write_u32(&mut bytes, 124, crc);
        assert_eq!(
            VolumeHeader::parse(&bytes).unwrap().parse_volume_format_revision().unwrap_err(),
            FormatError::UnsupportedVolumeFormatRevision {
                format_version: FORMAT_VERSION,
                volume_format_rev: 35,
                reader_max_supported_revision: READER_MAX_SUPPORTED_VOLUME_FORMAT_REV,
            }
        );

        let mut bytes = volume_header().to_bytes();
        bytes[124] ^= 1;
        assert_eq!(VolumeHeader::parse(&bytes).unwrap_err(), FormatError::BadCrc { structure: "VolumeHeader" });

        let mut bytes = volume_header().to_bytes();
        write_u32(&mut bytes, 48, 129);
        let crc = crc32c(&bytes[..124]);
        write_u32(&mut bytes, 124, crc);
        assert_eq!(VolumeHeader::parse(&bytes).unwrap_err(), FormatError::NonCanonicalCryptoHeaderOffset(129));

        let mut bytes = volume_header().to_bytes();
        write_u32(&mut bytes, 52, READER_MAX_CRYPTO_HEADER_LEN + 1);
        let crc = crc32c(&bytes[..124]);
        write_u32(&mut bytes, 124, crc);
        assert_eq!(
            VolumeHeader::parse(&bytes).unwrap_err(),
            FormatError::ReaderResourceLimitExceeded {
                field: "CryptoHeader length",
                cap: READER_MAX_CRYPTO_HEADER_LEN as u64,
                actual: (READER_MAX_CRYPTO_HEADER_LEN + 1) as u64,
            }
        );
    }

    #[test]
    fn volume_header_revision_dispatch_is_versioned() {
        let bytes = volume_header().to_bytes();
        let parsed = VolumeHeader::parse(&bytes).unwrap();
        assert_eq!(parsed.parse_volume_format_revision().unwrap(), VolumeFormatRevision::V45);

        let mut legacy = volume_header().to_bytes();
        write_u16(&mut legacy, 6, 43);
        let legacy_crc = crc32c(&legacy[..124]);
        write_u32(&mut legacy, 124, legacy_crc);
        assert_eq!(
            VolumeHeader::parse(&legacy).unwrap().parse_volume_format_revision(),
            Err(FormatError::UnsupportedVolumeFormatRevision {
                format_version: FORMAT_VERSION,
                volume_format_rev: 43,
                reader_max_supported_revision: READER_MAX_SUPPORTED_VOLUME_FORMAT_REV,
            })
        );

        let mut v45 = volume_header().to_bytes();
        write_u16(&mut v45, 6, VOLUME_FORMAT_REV_45 + 1);
        let v45_crc = crc32c(&v45[..124]);
        write_u32(&mut v45, 124, v45_crc);
        assert_eq!(
            VolumeHeader::parse(&v45).unwrap().parse_volume_format_revision(),
            Err(FormatError::UnsupportedVolumeFormatRevision {
                format_version: FORMAT_VERSION,
                volume_format_rev: VOLUME_FORMAT_REV_45 + 1,
                reader_max_supported_revision: READER_MAX_SUPPORTED_VOLUME_FORMAT_REV,
            })
        );
    }

    #[test]
    fn fixed_structure_magic_matrix_rejects_all_magic_fields() {
        let mut volume = volume_header().to_bytes();
        volume[0] ^= 0x01;
        assert_eq!(VolumeHeader::parse(&volume).unwrap_err(), FormatError::BadMagic { structure: "VolumeHeader" });

        let mut crypto = crypto_fixed().to_bytes();
        crypto[0] ^= 0x01;
        assert_eq!(CryptoHeaderFixed::parse(&crypto, crypto_fixed().length).unwrap_err(), FormatError::BadMagic { structure: "CryptoHeaderFixed" });

        let record = BlockRecord { block_index: 0, kind: BlockKind::PayloadData, flags: BLOCK_LAST_DATA_FLAG, payload: vec![7; 4096], record_crc32c: 0 };
        let mut block = record.to_bytes();
        block[0] ^= 0x01;
        assert_eq!(BlockRecord::parse(&block, 4096).unwrap_err(), FormatError::BadMagic { structure: "BlockRecord" });

        let footer = ManifestFooter {
            archive_uuid: uuid(),
            session_id: session(),
            volume_index: 0,
            is_authoritative: 1,
            total_volumes: 1,
            index_root_first_block: 0,
            index_root_data_block_count: 1,
            index_root_parity_block_count: 0,
            index_root_encrypted_size: 4096,
            index_root_decompressed_size: 120,
            manifest_hmac: [0xaa; 32],
        };
        let mut manifest = footer.to_bytes();
        manifest[0] ^= 0x01;
        assert_eq!(ManifestFooter::parse(&manifest).unwrap_err(), FormatError::BadMagic { structure: "ManifestFooter" });

        let trailer = VolumeTrailer {
            archive_uuid: uuid(),
            session_id: session(),
            volume_index: 0,
            block_count: 3,
            bytes_written: 10_000,
            manifest_footer_offset: 9_864,
            manifest_footer_length: MANIFEST_FOOTER_LEN as u32,
            closed_at_ns: 123,
            root_auth_footer_offset: 0,
            root_auth_footer_length: 0,
            root_auth_flags: 0,
            trailer_hmac: [0xbb; 32],
        };
        let mut trailer_bytes = trailer.to_bytes();
        trailer_bytes[0] ^= 0x01;
        assert_eq!(VolumeTrailer::parse(&trailer_bytes).unwrap_err(), FormatError::BadMagic { structure: "VolumeTrailer" });

        let sidecar = BootstrapSidecarHeader {
            archive_uuid: uuid(),
            session_id: session(),
            flags: SIDECAR_MANIFEST_PRESENT,
            manifest_footer_offset: BOOTSTRAP_SIDECAR_HEADER_LEN as u64,
            manifest_footer_length: MANIFEST_FOOTER_LEN as u32,
            index_root_records_offset: 0,
            index_root_records_length: 0,
            dictionary_records_offset: 0,
            dictionary_records_length: 0,
            sidecar_hmac: [0xcc; 32],
            header_crc32c: 0,
        };
        let mut sidecar_bytes = sidecar.to_bytes();
        sidecar_bytes[0] ^= 0x01;
        assert_eq!(BootstrapSidecarHeader::parse(&sidecar_bytes).unwrap_err(), FormatError::BadMagic { structure: "BootstrapSidecarHeader" });
    }

    #[test]
    fn crypto_header_fixed_round_trips_and_validates() {
        let header = crypto_fixed();
        let bytes = header.to_bytes();
        let parsed = CryptoHeaderFixed::parse(&bytes, header.length).unwrap();
        assert_eq!(parsed.compression_algo, CompressionAlgo::ZstdFramed);
        assert_eq!(parsed.fec_algo, FecAlgo::ReedSolomonGF16);
    }

    #[test]
    fn crypto_header_fixed_rejects_unsupported_profile_values() {
        let mut header = crypto_fixed();
        header.compression_algo = CompressionAlgo::None;
        assert_eq!(CryptoHeaderFixed::parse(&header.to_bytes(), header.length).unwrap_err(), FormatError::UnsupportedCompression(CompressionAlgo::None));

        let mut header = crypto_fixed();
        header.block_size = 4097;
        assert_eq!(CryptoHeaderFixed::parse(&header.to_bytes(), header.length).unwrap_err(), FormatError::OddBlockSize(4097));

        let mut bytes = crypto_fixed().to_bytes();
        bytes[47] = 1;
        assert_eq!(CryptoHeaderFixed::parse(&bytes, crypto_fixed().length).unwrap_err(), FormatError::NonZeroReserved { structure: "CryptoHeaderFixed" });
    }

    #[test]
    fn key_wrap_table_round_trips_with_record_digest_checks() {
        let (table_bytes, table_length) = key_wrap_table_bytes();
        let parsed = KeyWrapTableV1::parse(&table_bytes, &uuid(), &session(), table_length, 1).unwrap();
        assert_eq!(parsed.table_length, table_length);
        assert_eq!(parsed.recipient_records.len(), 1);
        assert_eq!(parsed.recipient_records[0].recipient_identity_bytes, b"alice");

        let (record, consumed) = RecipientRecordV1::parse(&table_bytes[96..]).unwrap();
        assert_eq!(record.profile_id, 1);
        assert_eq!(record.recipient_identity_type, 2);
        assert_eq!(record.profile_payload_bytes, b"profile");
        assert_eq!(record.recipient_identity_length as usize, b"alice".len());
        assert_eq!(record.profile_payload_length as usize, b"profile".len());
        assert_eq!(consumed, table_bytes.len() - 96);

        let digest = compute_key_wrap_table_digest(table_length, &table_bytes);
        let mut expected = Sha256::new();
        expected.update(KEY_WRAP_TABLE_DIGEST_DOMAIN_V45);
        expected.update(table_length.to_le_bytes());
        expected.update(&table_bytes);
        let expected = expected.finalize();
        let expected_digest: [u8; 32] = expected[..].try_into().unwrap();
        assert_eq!(digest, expected_digest);
    }

    #[test]
    fn key_wrap_table_parse_rejects_table_record_count_and_length_mismatch() {
        let (table_bytes, table_length) = key_wrap_table_bytes();
        let parsed = KeyWrapTableV1::parse(&table_bytes, &uuid(), &session(), table_length, 2);
        assert_eq!(parsed.unwrap_err(), FormatError::InvalidArchive("KeyWrapTableV1 recipient_record_count does not match KdfParams"));

        let mut bad = table_bytes.clone();
        write_u32(&mut bad, 8, table_length + 1);
        assert_eq!(
            KeyWrapTableV1::parse(&bad, &uuid(), &session(), table_length, 1),
            Err(FormatError::InvalidArchive("KeyWrapTableV1 length does not match KdfParams"))
        );
    }

    #[test]
    fn key_wrap_table_parse_rejects_short_table_without_panic() {
        assert_eq!(
            KeyWrapTableV1::parse(&[0u8; 3], &uuid(), &session(), 3, 0),
            Err(FormatError::InvalidLength { structure: "KeyWrapTableV1", expected: KEY_WRAP_TABLE_HEADER_LEN, actual: 3 })
        );
    }

    #[test]
    fn key_wrap_table_parse_rejects_magic_version_revision_and_reserved_fields() {
        let (table_bytes, table_length) = key_wrap_table_bytes();

        let mut bad_magic = table_bytes.clone();
        bad_magic[0] = b'X';
        assert_eq!(KeyWrapTableV1::parse(&bad_magic, &uuid(), &session(), table_length, 1), Err(FormatError::BadMagic { structure: "KeyWrapTableV1" }));

        let mut bad_version = table_bytes.clone();
        write_u16(&mut bad_version, 4, 2);
        assert_eq!(
            KeyWrapTableV1::parse(&bad_version, &uuid(), &session(), table_length, 1),
            Err(FormatError::InvalidArchive("KeyWrapTableV1 version must be 1"))
        );

        let mut bad_revision = table_bytes.clone();
        write_u16(&mut bad_revision, 6, 43);
        assert_eq!(
            KeyWrapTableV1::parse(&bad_revision, &uuid(), &session(), table_length, 1),
            Err(FormatError::InvalidArchive("KeyWrapTableV1 volume_format_rev must be 45"))
        );

        let mut bad_reserved = table_bytes.clone();
        bad_reserved[64] = 1;
        assert_eq!(
            KeyWrapTableV1::parse(&bad_reserved, &uuid(), &session(), table_length, 1),
            Err(FormatError::NonZeroReserved { structure: "KeyWrapTableV1" })
        );

        let mut bad_header_length = table_bytes.clone();
        write_u32(&mut bad_header_length, 12, 97);
        assert_eq!(
            KeyWrapTableV1::parse(&bad_header_length, &uuid(), &session(), table_length, 1),
            Err(FormatError::InvalidArchive("KeyWrapTableV1 header_length must be 96"))
        );
    }

    #[test]
    fn key_wrap_records_reject_invalid_digest_and_record_length() {
        let table = recipient_record_bytes();
        let (record, _) = RecipientRecordV1::parse(&table).unwrap();
        assert_eq!(record.recipient_identity_length as usize, b"alice".len());

        let mut bad_digest = table.clone();
        bad_digest[20] ^= 1;
        assert_eq!(RecipientRecordV1::parse(&bad_digest).unwrap_err(), FormatError::InvalidArchive("RecipientRecordV1 recipient_identity_digest mismatch"));

        let mut bad_len = table.clone();
        write_u32(&mut bad_len, 0, 12);
        assert_eq!(RecipientRecordV1::parse(&bad_len).unwrap_err(), FormatError::InvalidArchive("RecipientRecordV1 record_length is too small"));
    }

    #[test]
    fn key_wrap_records_parse_unknown_profile_id() {
        let table = recipient_record_bytes_with_profile_and_payload(0xBEEF, b"charlie", b"payload");
        let (record, consumed) = RecipientRecordV1::parse(&table).unwrap();
        assert_eq!(record.profile_id, 0xBEEF);
        assert_eq!(record.recipient_identity_bytes, b"charlie");
        assert_eq!(record.profile_payload_bytes, b"payload");
        assert_eq!(consumed, table.len());
    }

    #[test]
    fn crypto_header_fixed_validates_v45_protection_mode_pairs() {
        let mut header = crypto_fixed();
        header.aead_algo = AeadAlgo::None;
        header.kdf_algo = KdfAlgo::None;
        header.validate_supported_profile().unwrap();

        let mut header = crypto_fixed();
        header.aead_algo = AeadAlgo::None;
        header.kdf_algo = KdfAlgo::Raw;
        assert_eq!(header.validate_supported_profile().unwrap_err(), FormatError::InvalidProtectionMode { aead_algo: AeadAlgo::None, kdf_algo: KdfAlgo::Raw });

        let mut header = crypto_fixed();
        header.aead_algo = AeadAlgo::AesGcmSiv256;
        header.kdf_algo = KdfAlgo::None;
        assert_eq!(
            header.validate_supported_profile().unwrap_err(),
            FormatError::InvalidProtectionMode { aead_algo: AeadAlgo::AesGcmSiv256, kdf_algo: KdfAlgo::None }
        );

        let mut header = crypto_fixed();
        header.aead_algo = AeadAlgo::None;
        header.kdf_algo = KdfAlgo::RecipientWrap;
        assert_eq!(
            header.validate_supported_profile().unwrap_err(),
            FormatError::InvalidProtectionMode { aead_algo: AeadAlgo::None, kdf_algo: KdfAlgo::RecipientWrap }
        );

        let mut header = crypto_fixed();
        header.aead_algo = AeadAlgo::AesGcmSiv256;
        header.kdf_algo = KdfAlgo::RecipientWrap;
        header.validate_supported_profile().unwrap();
    }

    #[test]
    fn crypto_header_fixed_rejects_parameter_mutation_matrix() {
        let mut bytes = crypto_fixed().to_bytes();
        write_u16(&mut bytes, 8, 99);
        assert_eq!(CryptoHeaderFixed::parse(&bytes, crypto_fixed().length).unwrap_err(), FormatError::UnknownCompressionAlgo(99));

        let mut bytes = crypto_fixed().to_bytes();
        write_u16(&mut bytes, 10, 99);
        assert_eq!(CryptoHeaderFixed::parse(&bytes, crypto_fixed().length).unwrap_err(), FormatError::UnknownAeadAlgo(99));

        let mut bytes = crypto_fixed().to_bytes();
        write_u16(&mut bytes, 12, 99);
        assert_eq!(CryptoHeaderFixed::parse(&bytes, crypto_fixed().length).unwrap_err(), FormatError::UnknownFecAlgo(99));

        let mut bytes = crypto_fixed().to_bytes();
        write_u16(&mut bytes, 14, 99);
        assert_eq!(CryptoHeaderFixed::parse(&bytes, crypto_fixed().length).unwrap_err(), FormatError::UnknownKdfAlgo(99));

        let cases: Vec<(&'static str, CryptoHeaderFixed, FormatError)> = vec![
            ("unsupported FEC None", CryptoHeaderFixed { fec_algo: FecAlgo::None, ..crypto_fixed() }, FormatError::UnsupportedFec(FecAlgo::None)),
            ("unsupported FEC Wirehair", CryptoHeaderFixed { fec_algo: FecAlgo::Wirehair, ..crypto_fixed() }, FormatError::UnsupportedFec(FecAlgo::Wirehair)),
            (
                "invalid dictionary flag",
                CryptoHeaderFixed { has_dictionary: 2, ..crypto_fixed() },
                FormatError::InvalidBoolean { field: "has_dictionary", value: 2 },
            ),
            ("zero stripe width", CryptoHeaderFixed { stripe_width: 0, ..crypto_fixed() }, FormatError::ZeroStripeWidth),
            (
                "stripe width cap",
                CryptoHeaderFixed { stripe_width: READER_MAX_STRIPE_WIDTH + 1, ..crypto_fixed() },
                FormatError::ReaderResourceLimitExceeded {
                    field: "stripe_width",
                    cap: READER_MAX_STRIPE_WIDTH as u64,
                    actual: (READER_MAX_STRIPE_WIDTH + 1) as u64,
                },
            ),
            (
                "loss tolerance must be below stripe width",
                CryptoHeaderFixed { stripe_width: 2, volume_loss_tolerance: 2, ..crypto_fixed() },
                FormatError::VolumeLossToleranceOutOfRange { volume_loss_tolerance: 2, stripe_width: 2 },
            ),
            ("bit rot pct cap", CryptoHeaderFixed { bit_rot_buffer_pct: 101, ..crypto_fixed() }, FormatError::BitRotBufferPctTooLarge(101)),
            (
                "zero payload data shards",
                CryptoHeaderFixed { fec_data_shards: 0, ..crypto_fixed() },
                FormatError::ZeroDataShardMaximum { field: "fec_data_shards" },
            ),
            (
                "zero index data shards",
                CryptoHeaderFixed { index_fec_data_shards: 0, ..crypto_fixed() },
                FormatError::ZeroDataShardMaximum { field: "index_fec_data_shards" },
            ),
            (
                "zero index root data shards",
                CryptoHeaderFixed { index_root_fec_data_shards: 0, ..crypto_fixed() },
                FormatError::ZeroDataShardMaximum { field: "index_root_fec_data_shards" },
            ),
            ("zero chunk size", CryptoHeaderFixed { chunk_size: 0, ..crypto_fixed() }, FormatError::ZeroChunkSize),
            ("zero envelope target size", CryptoHeaderFixed { envelope_target_size: 0, ..crypto_fixed() }, FormatError::ZeroEnvelopeTargetSize),
            (
                "chunk exceeds envelope",
                CryptoHeaderFixed { chunk_size: 4096, envelope_target_size: 2048, ..crypto_fixed() },
                FormatError::ChunkSizeExceedsEnvelopeTarget { chunk_size: 4096, envelope_target_size: 2048 },
            ),
            ("block size too small", CryptoHeaderFixed { block_size: 2048, ..crypto_fixed() }, FormatError::BlockSizeTooSmall(2048)),
        ];

        for (name, header, expected) in cases {
            assert_eq!(CryptoHeaderFixed::parse(&header.to_bytes(), header.length).unwrap_err(), expected, "{name}");
        }
    }

    #[test]
    fn crypto_header_fixed_treats_expected_volume_size_as_advisory_not_reserved() {
        let mut header = crypto_fixed();
        header.expected_volume_size = 1u64 << 56;

        let parsed = CryptoHeaderFixed::parse(&header.to_bytes(), header.length).unwrap();

        assert_eq!(parsed.expected_volume_size, 1u64 << 56);
    }

    #[test]
    fn crypto_header_fixed_rejects_reader_cap_excesses() {
        let mut header = crypto_fixed();
        header.chunk_size = READER_MAX_CHUNK_SIZE + 1;
        header.envelope_target_size = header.chunk_size;
        assert_eq!(
            CryptoHeaderFixed::parse(&header.to_bytes(), header.length).unwrap_err(),
            FormatError::ReaderResourceLimitExceeded { field: "chunk_size", cap: READER_MAX_CHUNK_SIZE as u64, actual: (READER_MAX_CHUNK_SIZE + 1) as u64 }
        );

        let mut header = crypto_fixed();
        header.block_size = READER_MAX_BLOCK_SIZE + 2;
        assert_eq!(
            CryptoHeaderFixed::parse(&header.to_bytes(), header.length).unwrap_err(),
            FormatError::ReaderResourceLimitExceeded { field: "block_size", cap: READER_MAX_BLOCK_SIZE as u64, actual: (READER_MAX_BLOCK_SIZE + 2) as u64 }
        );

        let mut header = crypto_fixed();
        header.max_path_length = READER_MAX_PATH_LENGTH + 1;
        assert_eq!(
            CryptoHeaderFixed::parse(&header.to_bytes(), header.length).unwrap_err(),
            FormatError::ReaderResourceLimitExceeded {
                field: "max_path_length",
                cap: READER_MAX_PATH_LENGTH as u64,
                actual: (READER_MAX_PATH_LENGTH + 1) as u64,
            }
        );

        let mut header = crypto_fixed();
        header.fec_data_shards = READER_MAX_FEC_CLASS_SHARDS as u16;
        header.fec_parity_shards = 1;
        assert_eq!(
            CryptoHeaderFixed::parse(&header.to_bytes(), header.length).unwrap_err(),
            FormatError::ReaderResourceLimitExceeded {
                field: "fec_data_shards + fec_parity_shards",
                cap: READER_MAX_FEC_CLASS_SHARDS as u64,
                actual: (READER_MAX_FEC_CLASS_SHARDS + 1) as u64,
            }
        );

        let mut header = crypto_fixed();
        header.index_fec_data_shards = READER_MAX_INDEX_FEC_CLASS_SHARDS as u16;
        header.index_fec_parity_shards = 1;
        assert_eq!(
            CryptoHeaderFixed::parse(&header.to_bytes(), header.length).unwrap_err(),
            FormatError::ReaderResourceLimitExceeded {
                field: "index_fec_data_shards + index_fec_parity_shards",
                cap: READER_MAX_INDEX_FEC_CLASS_SHARDS as u64,
                actual: (READER_MAX_INDEX_FEC_CLASS_SHARDS + 1) as u64,
            }
        );

        let mut header = crypto_fixed();
        header.block_size = 1_048_576;
        header.fec_data_shards = 4_096;
        header.fec_parity_shards = 0;
        let max_data_shards = u32::MAX as u64 / header.block_size as u64;
        assert_eq!(
            CryptoHeaderFixed::parse(&header.to_bytes(), header.length).unwrap_err(),
            FormatError::ReaderResourceLimitExceeded { field: "fec_data_shards", cap: max_data_shards, actual: 4_096 }
        );

        let mut header = crypto_fixed();
        header.block_size = 1_048_576;
        header.index_fec_data_shards = 4_096;
        header.index_fec_parity_shards = 0;
        let max_data_shards = u32::MAX as u64 / header.block_size as u64;
        assert_eq!(
            CryptoHeaderFixed::parse(&header.to_bytes(), header.length).unwrap_err(),
            FormatError::ReaderResourceLimitExceeded { field: "index_fec_data_shards", cap: max_data_shards, actual: 4_096 }
        );

        let mut header = crypto_fixed();
        header.block_size = 1_048_576;
        header.index_root_fec_data_shards = 4_096;
        let max_data_shards = u32::MAX as u64 / header.block_size as u64;
        assert_eq!(
            CryptoHeaderFixed::parse(&header.to_bytes(), header.length).unwrap_err(),
            FormatError::ReaderResourceLimitExceeded { field: "index_root_fec_data_shards", cap: max_data_shards, actual: 4_096 }
        );
    }

    #[test]
    fn crypto_extension_scanner_enforces_terminator_and_caps() {
        let bytes = [0u8; CRYPTO_EXTENSION_HEADER_LEN];
        assert!(scan_crypto_extension_tlvs(&bytes).unwrap().is_empty());

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x0001u16.to_le_bytes());
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(b"hey");
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        let tlvs = scan_crypto_extension_tlvs(&bytes).unwrap();
        assert_eq!(tlvs[0].tag, 1);
        assert_eq!(tlvs[0].value, b"hey");

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x0001u16.to_le_bytes());
        bytes.extend_from_slice(&257u32.to_le_bytes());
        assert_eq!(scan_crypto_extension_tlvs(&bytes).unwrap_err(), FormatError::ExtensionPayloadTooLarge(257));

        assert_eq!(scan_crypto_extension_tlvs(&[]).unwrap_err(), FormatError::MissingExtensionTerminator);
    }

    #[test]
    fn crypto_header_parse_splits_fixed_kdf_extensions_and_hmac() {
        let bytes = raw_crypto_header_bytes();
        let header = CryptoHeader::parse(&bytes, bytes.len() as u32).unwrap();
        assert_eq!(header.fixed.kdf_algo, KdfAlgo::Raw);
        assert_eq!(header.kdf_params, KdfParams::Raw);
        assert!(header.extensions.is_empty());
        assert_eq!(header.header_hmac, [0xab; CRYPTO_HEADER_HMAC_LEN]);
        assert_eq!(header.hmac_covered_bytes.len(), bytes.len() - CRYPTO_HEADER_HMAC_LEN);
    }

    #[test]
    fn crypto_header_parse_rejects_truncated_and_bad_kdf_params() {
        let mut bytes = raw_crypto_header_bytes();
        bytes.truncate(CRYPTO_HEADER_FIXED_LEN + 1);
        assert_eq!(
            CryptoHeader::parse(&bytes, bytes.len() as u32).unwrap_err(),
            FormatError::CryptoHeaderTooShort {
                min: CRYPTO_HEADER_FIXED_LEN + 2 + CRYPTO_EXTENSION_HEADER_LEN + CRYPTO_HEADER_HMAC_LEN,
                actual: CRYPTO_HEADER_FIXED_LEN + 1
            }
        );

        let mut bytes = raw_crypto_header_bytes();
        write_u16(&mut bytes, CRYPTO_HEADER_FIXED_LEN, KdfAlgo::Argon2id as u16);
        assert_eq!(CryptoHeader::parse(&bytes, bytes.len() as u32).unwrap_err(), FormatError::KdfAlgoTagMismatch { expected: 0, actual: 1 });
    }

    #[test]
    fn crypto_header_length_mismatch_matrix_rejects_independent_declared_lengths() {
        let canonical = raw_crypto_header_bytes();
        CryptoHeader::parse(&canonical, canonical.len() as u32).unwrap();

        let mut fixed_longer = canonical.clone();
        write_u32(&mut fixed_longer, 4, (canonical.len() + 1) as u32);
        assert_eq!(
            CryptoHeader::parse(&fixed_longer, fixed_longer.len() as u32).unwrap_err(),
            FormatError::CryptoHeaderLengthMismatch { fixed: (canonical.len() + 1) as u32, volume: canonical.len() as u32 }
        );

        let longer_volume_len = (canonical.len() + 1) as u32;
        let mut padded = canonical.clone();
        padded.insert(canonical.len() - CRYPTO_HEADER_HMAC_LEN, 0);
        assert_eq!(
            CryptoHeader::parse(&padded, longer_volume_len).unwrap_err(),
            FormatError::CryptoHeaderLengthMismatch { fixed: canonical.len() as u32, volume: longer_volume_len }
        );

        let mut fixed_shorter = canonical.clone();
        write_u32(&mut fixed_shorter, 4, (canonical.len() - 1) as u32);
        assert_eq!(
            CryptoHeader::parse(&fixed_shorter, fixed_shorter.len() as u32).unwrap_err(),
            FormatError::CryptoHeaderLengthMismatch { fixed: (canonical.len() - 1) as u32, volume: canonical.len() as u32 }
        );
    }

    #[test]
    fn crypto_extension_semantics_reject_forbidden_duplicate_and_critical() {
        let duplicate = vec![ExtensionTlv { tag: 0x0001, value: b"one" }, ExtensionTlv { tag: 0x0001, value: b"two" }];
        assert_eq!(validate_crypto_extension_semantics(&duplicate).unwrap_err(), FormatError::DuplicateKnownExtension(0x0001));

        let forbidden = vec![ExtensionTlv { tag: 0x8004, value: b"" }];
        assert_eq!(validate_crypto_extension_semantics(&forbidden).unwrap_err(), FormatError::ForbiddenExtensionTag(0x0004));

        let unknown_critical = vec![ExtensionTlv { tag: 0x8123, value: b"" }];
        assert_eq!(validate_crypto_extension_semantics(&unknown_critical).unwrap_err(), FormatError::UnknownCriticalExtension(0x0123));

        let malformed_known = vec![ExtensionTlv { tag: 0x0003, value: b"short" }];
        assert_eq!(validate_crypto_extension_semantics(&malformed_known).unwrap_err(), FormatError::MalformedKnownExtension(0x0003));
    }

    #[test]
    fn block_record_round_trips_and_validates_crc() {
        let record = BlockRecord { block_index: 0, kind: BlockKind::PayloadData, flags: BLOCK_LAST_DATA_FLAG, payload: vec![7; 4096], record_crc32c: 0 };
        let bytes = record.to_bytes();
        let parsed = BlockRecord::parse(&bytes, 4096).unwrap();
        assert_eq!(parsed.kind, BlockKind::PayloadData);
        assert!(parsed.is_last_data());

        let mut corrupted = bytes;
        corrupted[20] ^= 1;
        assert_eq!(BlockRecord::parse(&corrupted, 4096).unwrap_err(), FormatError::BadCrc { structure: "BlockRecord" });
    }

    #[test]
    fn block_record_crc_covers_every_record_header_and_payload_byte() {
        let record = BlockRecord {
            block_index: 0x0102_0304_0506_0708,
            kind: BlockKind::PayloadData,
            flags: BLOCK_LAST_DATA_FLAG,
            payload: (0..4096).map(|idx| (idx & 0xff) as u8).collect(),
            record_crc32c: 0,
        };
        let bytes = record.to_bytes();
        let covered_len = 16 + record.payload.len();

        for offset in 0..covered_len {
            let mut corrupted = bytes.clone();
            corrupted[offset] ^= 0x80;
            let err = BlockRecord::parse(&corrupted, record.payload.len()).unwrap_err();
            if offset < 4 {
                assert_eq!(err, FormatError::BadMagic { structure: "BlockRecord" }, "magic byte {offset}");
            } else if (14..16).contains(&offset) {
                assert_eq!(err, FormatError::NonZeroReserved { structure: "BlockRecord" }, "reserved byte {offset}");
            } else {
                assert_eq!(err, FormatError::BadCrc { structure: "BlockRecord" }, "CRC-covered byte {offset}");
            }
        }

        let mut corrupted_crc = bytes;
        corrupted_crc[covered_len] ^= 0x80;
        assert_eq!(BlockRecord::parse(&corrupted_crc, record.payload.len()).unwrap_err(), FormatError::BadCrc { structure: "BlockRecord" });
    }

    #[test]
    fn block_record_rejects_reserved_kind_flags_and_parity_last_flag() {
        let mut record = BlockRecord { block_index: 0, kind: BlockKind::PayloadData, flags: 0x02, payload: vec![0; 4096], record_crc32c: 0 };
        assert_eq!(BlockRecord::parse(&record.to_bytes(), 4096).unwrap_err(), FormatError::InvalidBlockFlags(0x02));

        record.kind = BlockKind::PayloadParity;
        record.flags = BLOCK_LAST_DATA_FLAG;
        assert_eq!(BlockRecord::parse(&record.to_bytes(), 4096).unwrap_err(), FormatError::ParityBlockHasLastDataFlag);

        let mut bytes = record.to_bytes();
        bytes[12] = 10;
        let crc = crc32c(&bytes[..4112]);
        write_u32(&mut bytes, 4112, crc);
        assert_eq!(BlockRecord::parse(&bytes, 4096).unwrap_err(), FormatError::UnknownBlockKind(10));

        for unknown_kind in 10..=u8::MAX {
            let mut bytes = record.to_bytes();
            bytes[12] = unknown_kind;
            let crc = crc32c(&bytes[..4112]);
            write_u32(&mut bytes, 4112, crc);
            assert_eq!(BlockRecord::parse(&bytes, 4096).unwrap_err(), FormatError::UnknownBlockKind(unknown_kind));
        }
    }

    #[test]
    fn manifest_footer_round_trips_and_validates_index_extent() {
        let footer = ManifestFooter {
            archive_uuid: uuid(),
            session_id: session(),
            volume_index: 0,
            is_authoritative: 1,
            total_volumes: 1,
            index_root_first_block: 0,
            index_root_data_block_count: 2,
            index_root_parity_block_count: 1,
            index_root_encrypted_size: 8192,
            index_root_decompressed_size: 120,
            manifest_hmac: [0xaa; 32],
        };
        let parsed = ManifestFooter::parse(&footer.to_bytes()).unwrap();
        parsed.validate_index_root_extent(4096).unwrap();

        let mut bad = footer.clone();
        bad.index_root_encrypted_size = 4096;
        assert_eq!(ManifestFooter::parse(&bad.to_bytes()).unwrap().validate_index_root_extent(4096).unwrap_err(), FormatError::IndexRootSizeMismatch);
    }

    #[test]
    fn volume_trailer_round_trips_and_requires_manifest_length() {
        let trailer = VolumeTrailer {
            archive_uuid: uuid(),
            session_id: session(),
            volume_index: 0,
            block_count: 3,
            bytes_written: 10_000,
            manifest_footer_offset: 9_864,
            manifest_footer_length: MANIFEST_FOOTER_LEN as u32,
            closed_at_ns: 123,
            root_auth_footer_offset: 0,
            root_auth_footer_length: 0,
            root_auth_flags: 0,
            trailer_hmac: [0xbb; 32],
        };
        let parsed = VolumeTrailer::parse(&trailer.to_bytes()).unwrap();
        assert_eq!(parsed.block_count, 3);

        let mut bad = trailer;
        bad.manifest_footer_length = 100;
        assert_eq!(VolumeTrailer::parse(&bad.to_bytes()).unwrap_err(), FormatError::InvalidManifestFooterLength(100));
    }

    #[test]
    fn root_auth_footer_round_trips_and_validates_crc_and_lengths() {
        let footer = RootAuthFooterV1 {
            archive_uuid: uuid(),
            session_id: session(),
            format_version: FORMAT_VERSION,
            volume_format_rev: VOLUME_FORMAT_REV,
            authenticator_id: 2,
            signer_identity_type: 1,
            signer_identity_bytes: b"public-key".to_vec(),
            authenticator_value: vec![0x5a; 68],
            total_data_block_count: 7,
            critical_metadata_digest: [1; 32],
            index_digest: [2; 32],
            fec_layout_digest: [3; 32],
            data_block_merkle_root: [4; 32],
            signer_identity_digest: [5; 32],
            archive_root: [6; 32],
            footer_crc32c: 0,
        };
        let bytes = footer.to_bytes().unwrap();
        let parsed = RootAuthFooterV1::parse(&bytes).unwrap();
        assert_eq!(parsed.archive_uuid, uuid());
        assert_eq!(parsed.signer_identity_bytes, b"public-key");
        assert_eq!(parsed.authenticator_value, vec![0x5a; 68]);
        assert_eq!(parsed.footer_length().unwrap() as usize, bytes.len());

        let mut bad_crc = bytes.clone();
        bad_crc[100] ^= 0x40;
        assert_eq!(RootAuthFooterV1::parse(&bad_crc).unwrap_err(), FormatError::BadCrc { structure: "RootAuthFooterV1" });

        let mut bad_len = bytes;
        write_u32(&mut bad_len, 30, 1);
        let crc_offset = bad_len.len() - 4;
        let crc = crc32c(&bad_len[..crc_offset]);
        write_u32(&mut bad_len, crc_offset, crc);
        assert!(matches!(RootAuthFooterV1::parse(&bad_len).unwrap_err(), FormatError::InvalidLength { structure: "RootAuthFooterV1", .. }));

        let mut legacy_revision = footer.to_bytes().unwrap();
        write_u16(&mut legacy_revision, 72, 43);
        let mismatch_crc_offset = legacy_revision.len() - 4;
        let mismatch_crc = crc32c(&legacy_revision[..mismatch_crc_offset]);
        write_u32(&mut legacy_revision, mismatch_crc_offset, mismatch_crc);
        assert_eq!(
            RootAuthFooterV1::parse(&legacy_revision).unwrap_err(),
            FormatError::UnsupportedVolumeFormatRevision {
                format_version: FORMAT_VERSION,
                volume_format_rev: 43,
                reader_max_supported_revision: READER_MAX_SUPPORTED_VOLUME_FORMAT_REV,
            }
        );

        let mut mismatched = footer.to_bytes().unwrap();
        write_u16(&mut mismatched, 72, VOLUME_FORMAT_REV_45 + 1);
        let mismatch_crc_offset = mismatched.len() - 4;
        let mismatch_crc = crc32c(&mismatched[..mismatch_crc_offset]);
        write_u32(&mut mismatched, mismatch_crc_offset, mismatch_crc);
        assert_eq!(
            RootAuthFooterV1::parse(&mismatched).unwrap_err(),
            FormatError::UnsupportedVolumeFormatRevision {
                format_version: FORMAT_VERSION,
                volume_format_rev: VOLUME_FORMAT_REV_45 + 1,
                reader_max_supported_revision: READER_MAX_SUPPORTED_VOLUME_FORMAT_REV,
            }
        );
    }

    #[test]
    fn bootstrap_sidecar_header_validates_presence_and_layout() {
        let header = BootstrapSidecarHeader {
            archive_uuid: uuid(),
            session_id: session(),
            flags: SIDECAR_MANIFEST_PRESENT | SIDECAR_INDEX_ROOT_PRESENT,
            manifest_footer_offset: BOOTSTRAP_SIDECAR_HEADER_LEN as u64,
            manifest_footer_length: MANIFEST_FOOTER_LEN as u32,
            index_root_records_offset: (BOOTSTRAP_SIDECAR_HEADER_LEN + MANIFEST_FOOTER_LEN) as u64,
            index_root_records_length: 40,
            dictionary_records_offset: 0,
            dictionary_records_length: 0,
            sidecar_hmac: [0xcc; 32],
            header_crc32c: 0,
        };
        let parsed = BootstrapSidecarHeader::parse(&header.to_bytes()).unwrap();
        parsed.validate_packed_layout(BOOTSTRAP_SIDECAR_HEADER_LEN as u64 + MANIFEST_FOOTER_LEN as u64 + 40).unwrap();

        let mut bad = header.clone();
        bad.flags |= 0x08;
        assert_eq!(BootstrapSidecarHeader::parse(&bad.to_bytes()).unwrap_err(), FormatError::UnknownBootstrapSidecarFlags(0x0b));

        let mut bad = header;
        bad.index_root_records_offset += 1;
        let parsed = BootstrapSidecarHeader::parse(&bad.to_bytes()).unwrap();
        assert_eq!(
            parsed.validate_packed_layout(BOOTSTRAP_SIDECAR_HEADER_LEN as u64 + MANIFEST_FOOTER_LEN as u64 + 40).unwrap_err(),
            FormatError::NonCanonicalBootstrapSidecarLayout
        );
    }

    #[test]
    fn critical_metadata_image_rejects_unsupported_volume_format_revision() {
        let image = CriticalMetadataImage {
            volume_format_rev: VOLUME_FORMAT_REV_45,
            archive_uuid: uuid(),
            session_id: session(),
            volume_index: 0,
            stripe_width: 1,
            layout_flags: 1,
            volume_header_offset: 0,
            volume_header_length: VOLUME_HEADER_LEN as u32,
            crypto_header_offset: 0,
            crypto_header_length: 0,
            key_wrap_table_offset: 0,
            key_wrap_table_length: 0,
            block_records_offset: 0,
            block_records_length: 0,
            block_count: 0,
            manifest_footer_offset: 0,
            manifest_footer_length: 0,
            root_auth_footer_offset: 0,
            root_auth_footer_length: 0,
            volume_trailer_offset: 0,
            volume_trailer_length: 0,
            body_bytes_before_cmra: 0,
            volume_header_sha256: [0u8; 32],
            crypto_header_sha256: [0u8; 32],
            key_wrap_table_sha256: [0u8; 32],
            manifest_footer_sha256: [0u8; 32],
            root_auth_footer_sha256: [0u8; 32],
            volume_trailer_sha256: [0u8; 32],
            regions: vec![],
        };
        for revision in [43, VOLUME_FORMAT_REV_45 + 1] {
            let mut bytes = image.to_bytes().unwrap();
            write_u16(&mut bytes, 6, revision);
            let crc_offset = bytes.len() - 4;
            let crc = crc32c(&bytes[..crc_offset]);
            write_u32(&mut bytes, crc_offset, crc);
            assert_eq!(
                CriticalMetadataImage::parse(&bytes).unwrap_err(),
                FormatError::UnsupportedVolumeFormatRevision {
                    format_version: FORMAT_VERSION,
                    volume_format_rev: revision,
                    reader_max_supported_revision: READER_MAX_SUPPORTED_VOLUME_FORMAT_REV,
                }
            );
        }
    }
}
