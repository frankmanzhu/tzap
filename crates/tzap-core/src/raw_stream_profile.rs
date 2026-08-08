use crate::format::FormatError;
use crate::wire::ExtensionTlv;

pub const RAW_STREAM_CONTENT_MODEL_EXTENSION_TAG: u16 = 0x0007;
#[cfg(test)]
pub const RAW_STREAM_CONTENT_MODEL_EXTENSION_CRITICAL_TAG: u16 =
    0x8000 | RAW_STREAM_CONTENT_MODEL_EXTENSION_TAG;
pub const RAW_STREAM_CONTENT_MODEL_VALUE: &[u8] = b"raw_stream_v1";
pub const RAW_STREAM_UNSUPPORTED_MESSAGE: &str =
    "raw-stream content profile is not supported by the revision-45 tar reader";

#[cfg(test)]
pub const RAW_STREAM_INDEX_ROOT_V1_MAGIC: [u8; 8] = *b"TZRSIDX1";
#[cfg(test)]
pub const RAW_STREAM_INDEX_ROOT_V1_VERSION: u16 = 1;
#[cfg(test)]
pub const RAW_STREAM_INDEX_ROOT_V1_LEN: usize = 112;
#[cfg(test)]
pub const RAW_FILE_ENTRY_V1_LEN: usize = 88;
#[cfg(test)]
pub const RAW_FRAME_ENTRY_V1_LEN: usize = 48;
#[cfg(test)]
pub const RAW_ENVELOPE_ENTRY_V1_LEN: usize = 56;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentProfile {
    TarMember,
    RawStreamV1,
}

#[cfg(test)]
pub fn serialize_raw_stream_content_model_extension() -> Vec<u8> {
    let mut bytes = Vec::with_capacity(6 + RAW_STREAM_CONTENT_MODEL_VALUE.len());
    bytes.extend_from_slice(&RAW_STREAM_CONTENT_MODEL_EXTENSION_CRITICAL_TAG.to_le_bytes());
    bytes.extend_from_slice(&(RAW_STREAM_CONTENT_MODEL_VALUE.len() as u32).to_le_bytes());
    bytes.extend_from_slice(RAW_STREAM_CONTENT_MODEL_VALUE);
    bytes
}

pub fn validate_raw_stream_content_model_extension(
    is_critical: bool,
    value: &[u8],
) -> Result<(), FormatError> {
    if !is_critical || value != RAW_STREAM_CONTENT_MODEL_VALUE {
        return Err(FormatError::MalformedKnownExtension(
            RAW_STREAM_CONTENT_MODEL_EXTENSION_TAG,
        ));
    }
    Ok(())
}

pub fn content_profile_from_extensions(
    extensions: &[ExtensionTlv<'_>],
) -> Result<ContentProfile, FormatError> {
    let mut profile = ContentProfile::TarMember;
    for extension in extensions {
        let ext_tag = extension.tag & 0x7fff;
        let is_critical = extension.tag & 0x8000 != 0;
        if ext_tag == RAW_STREAM_CONTENT_MODEL_EXTENSION_TAG && is_critical {
            validate_raw_stream_content_model_extension(is_critical, extension.value)?;
            profile = ContentProfile::RawStreamV1;
        }
    }
    Ok(profile)
}

pub fn reject_unsupported_raw_stream_profile(
    extensions: &[ExtensionTlv<'_>],
) -> Result<(), FormatError> {
    match content_profile_from_extensions(extensions)? {
        ContentProfile::TarMember => Ok(()),
        ContentProfile::RawStreamV1 => Err(FormatError::ReaderUnsupported(
            RAW_STREAM_UNSUPPORTED_MESSAGE,
        )),
    }
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawStreamIndexRootV1 {
    pub file_count: u32,
    pub frame_count: u64,
    pub envelope_count: u64,
    pub payload_block_count: u64,
    pub raw_total_size: u64,
    pub raw_content_sha256: [u8; 32],
    pub raw_file_entry_offset: u32,
    pub raw_frame_table_offset: u32,
    pub raw_envelope_table_offset: u32,
    pub string_pool_offset: u32,
    pub string_pool_size: u32,
}

#[cfg(test)]
impl RawStreamIndexRootV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self, FormatError> {
        expect_len(
            "RawStreamIndexRootV1",
            RAW_STREAM_INDEX_ROOT_V1_LEN,
            bytes.len(),
        )?;
        expect_magic(
            "RawStreamIndexRootV1",
            RAW_STREAM_INDEX_ROOT_V1_MAGIC,
            &bytes[0..8],
        )?;
        let version = read_u16(bytes, 8, "RawStreamIndexRootV1")?;
        if version != RAW_STREAM_INDEX_ROOT_V1_VERSION {
            return Err(FormatError::InvalidMetadata {
                structure: "RawStreamIndexRootV1",
                reason: "unsupported version",
            });
        }
        expect_zero("RawStreamIndexRootV1", &bytes[10..16])?;
        expect_zero("RawStreamIndexRootV1", &bytes[20..24])?;
        expect_zero("RawStreamIndexRootV1", &bytes[108..112])?;
        Ok(Self {
            file_count: read_u32(bytes, 16, "RawStreamIndexRootV1")?,
            frame_count: read_u64(bytes, 24, "RawStreamIndexRootV1")?,
            envelope_count: read_u64(bytes, 32, "RawStreamIndexRootV1")?,
            payload_block_count: read_u64(bytes, 40, "RawStreamIndexRootV1")?,
            raw_total_size: read_u64(bytes, 48, "RawStreamIndexRootV1")?,
            raw_content_sha256: read_array_32(bytes, 56, "RawStreamIndexRootV1")?,
            raw_file_entry_offset: read_u32(bytes, 88, "RawStreamIndexRootV1")?,
            raw_frame_table_offset: read_u32(bytes, 92, "RawStreamIndexRootV1")?,
            raw_envelope_table_offset: read_u32(bytes, 96, "RawStreamIndexRootV1")?,
            string_pool_offset: read_u32(bytes, 100, "RawStreamIndexRootV1")?,
            string_pool_size: read_u32(bytes, 104, "RawStreamIndexRootV1")?,
        })
    }

    pub fn to_bytes(&self) -> [u8; RAW_STREAM_INDEX_ROOT_V1_LEN] {
        let mut bytes = [0u8; RAW_STREAM_INDEX_ROOT_V1_LEN];
        bytes[0..8].copy_from_slice(&RAW_STREAM_INDEX_ROOT_V1_MAGIC);
        write_u16(&mut bytes, 8, RAW_STREAM_INDEX_ROOT_V1_VERSION);
        write_u32(&mut bytes, 16, self.file_count);
        write_u64(&mut bytes, 24, self.frame_count);
        write_u64(&mut bytes, 32, self.envelope_count);
        write_u64(&mut bytes, 40, self.payload_block_count);
        write_u64(&mut bytes, 48, self.raw_total_size);
        bytes[56..88].copy_from_slice(&self.raw_content_sha256);
        write_u32(&mut bytes, 88, self.raw_file_entry_offset);
        write_u32(&mut bytes, 92, self.raw_frame_table_offset);
        write_u32(&mut bytes, 96, self.raw_envelope_table_offset);
        write_u32(&mut bytes, 100, self.string_pool_offset);
        write_u32(&mut bytes, 104, self.string_pool_size);
        bytes
    }
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawFileEntryV1 {
    pub path_hash: [u8; 8],
    pub path_offset: u32,
    pub path_length: u32,
    pub file_data_size: u64,
    pub first_frame_index: u64,
    pub frame_count: u64,
    pub mode: u32,
    pub mtime: u64,
    pub content_sha256: [u8; 32],
}

#[cfg(test)]
impl RawFileEntryV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self, FormatError> {
        expect_len("RawFileEntryV1", RAW_FILE_ENTRY_V1_LEN, bytes.len())?;
        expect_zero("RawFileEntryV1", &bytes[44..48])?;
        Ok(Self {
            path_hash: read_array_8(bytes, 0, "RawFileEntryV1")?,
            path_offset: read_u32(bytes, 8, "RawFileEntryV1")?,
            path_length: read_u32(bytes, 12, "RawFileEntryV1")?,
            file_data_size: read_u64(bytes, 16, "RawFileEntryV1")?,
            first_frame_index: read_u64(bytes, 24, "RawFileEntryV1")?,
            frame_count: read_u64(bytes, 32, "RawFileEntryV1")?,
            mode: read_u32(bytes, 40, "RawFileEntryV1")?,
            mtime: read_u64(bytes, 48, "RawFileEntryV1")?,
            content_sha256: read_array_32(bytes, 56, "RawFileEntryV1")?,
        })
    }

    pub fn to_bytes(&self) -> [u8; RAW_FILE_ENTRY_V1_LEN] {
        let mut bytes = [0u8; RAW_FILE_ENTRY_V1_LEN];
        bytes[0..8].copy_from_slice(&self.path_hash);
        write_u32(&mut bytes, 8, self.path_offset);
        write_u32(&mut bytes, 12, self.path_length);
        write_u64(&mut bytes, 16, self.file_data_size);
        write_u64(&mut bytes, 24, self.first_frame_index);
        write_u64(&mut bytes, 32, self.frame_count);
        write_u32(&mut bytes, 40, self.mode);
        write_u64(&mut bytes, 48, self.mtime);
        bytes[56..88].copy_from_slice(&self.content_sha256);
        bytes
    }
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawFrameEntryV1 {
    pub frame_index: u64,
    pub envelope_index: u64,
    pub offset_in_envelope: u32,
    pub compressed_size: u32,
    pub decompressed_size: u32,
    pub raw_stream_offset: u64,
}

#[cfg(test)]
impl RawFrameEntryV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self, FormatError> {
        expect_len("RawFrameEntryV1", RAW_FRAME_ENTRY_V1_LEN, bytes.len())?;
        expect_zero("RawFrameEntryV1", &bytes[28..32])?;
        expect_zero("RawFrameEntryV1", &bytes[40..48])?;
        Ok(Self {
            frame_index: read_u64(bytes, 0, "RawFrameEntryV1")?,
            envelope_index: read_u64(bytes, 8, "RawFrameEntryV1")?,
            offset_in_envelope: read_u32(bytes, 16, "RawFrameEntryV1")?,
            compressed_size: read_u32(bytes, 20, "RawFrameEntryV1")?,
            decompressed_size: read_u32(bytes, 24, "RawFrameEntryV1")?,
            raw_stream_offset: read_u64(bytes, 32, "RawFrameEntryV1")?,
        })
    }

    pub fn to_bytes(&self) -> [u8; RAW_FRAME_ENTRY_V1_LEN] {
        let mut bytes = [0u8; RAW_FRAME_ENTRY_V1_LEN];
        write_u64(&mut bytes, 0, self.frame_index);
        write_u64(&mut bytes, 8, self.envelope_index);
        write_u32(&mut bytes, 16, self.offset_in_envelope);
        write_u32(&mut bytes, 20, self.compressed_size);
        write_u32(&mut bytes, 24, self.decompressed_size);
        write_u64(&mut bytes, 32, self.raw_stream_offset);
        bytes
    }
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawEnvelopeEntryV1 {
    pub envelope_index: u64,
    pub first_block_index: u64,
    pub data_block_count: u32,
    pub parity_block_count: u32,
    pub encrypted_size: u32,
    pub plaintext_size: u32,
    pub first_frame_index: u64,
    pub frame_count: u64,
}

#[cfg(test)]
impl RawEnvelopeEntryV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self, FormatError> {
        expect_len("RawEnvelopeEntryV1", RAW_ENVELOPE_ENTRY_V1_LEN, bytes.len())?;
        expect_zero("RawEnvelopeEntryV1", &bytes[48..56])?;
        Ok(Self {
            envelope_index: read_u64(bytes, 0, "RawEnvelopeEntryV1")?,
            first_block_index: read_u64(bytes, 8, "RawEnvelopeEntryV1")?,
            data_block_count: read_u32(bytes, 16, "RawEnvelopeEntryV1")?,
            parity_block_count: read_u32(bytes, 20, "RawEnvelopeEntryV1")?,
            encrypted_size: read_u32(bytes, 24, "RawEnvelopeEntryV1")?,
            plaintext_size: read_u32(bytes, 28, "RawEnvelopeEntryV1")?,
            first_frame_index: read_u64(bytes, 32, "RawEnvelopeEntryV1")?,
            frame_count: read_u64(bytes, 40, "RawEnvelopeEntryV1")?,
        })
    }

    pub fn to_bytes(&self) -> [u8; RAW_ENVELOPE_ENTRY_V1_LEN] {
        let mut bytes = [0u8; RAW_ENVELOPE_ENTRY_V1_LEN];
        write_u64(&mut bytes, 0, self.envelope_index);
        write_u64(&mut bytes, 8, self.first_block_index);
        write_u32(&mut bytes, 16, self.data_block_count);
        write_u32(&mut bytes, 20, self.parity_block_count);
        write_u32(&mut bytes, 24, self.encrypted_size);
        write_u32(&mut bytes, 28, self.plaintext_size);
        write_u64(&mut bytes, 32, self.first_frame_index);
        write_u64(&mut bytes, 40, self.frame_count);
        bytes
    }
}

#[cfg(test)]
fn expect_len(structure: &'static str, expected: usize, actual: usize) -> Result<(), FormatError> {
    if actual != expected {
        return Err(FormatError::InvalidLength {
            structure,
            expected,
            actual,
        });
    }
    Ok(())
}

#[cfg(test)]
fn expect_magic(
    structure: &'static str,
    expected: [u8; 8],
    actual: &[u8],
) -> Result<(), FormatError> {
    if actual != expected {
        return Err(FormatError::BadMagic { structure });
    }
    Ok(())
}

#[cfg(test)]
fn expect_zero(structure: &'static str, bytes: &[u8]) -> Result<(), FormatError> {
    if bytes.iter().any(|byte| *byte != 0) {
        return Err(FormatError::NonZeroReserved { structure });
    }
    Ok(())
}

#[cfg(test)]
fn read_array_8(
    bytes: &[u8],
    offset: usize,
    structure: &'static str,
) -> Result<[u8; 8], FormatError> {
    bytes
        .get(offset..offset + 8)
        .ok_or(FormatError::InvalidLength {
            structure,
            expected: offset + 8,
            actual: bytes.len(),
        })?
        .try_into()
        .map_err(|_| FormatError::InvalidLength {
            structure,
            expected: offset + 8,
            actual: bytes.len(),
        })
}

#[cfg(test)]
fn read_array_32(
    bytes: &[u8],
    offset: usize,
    structure: &'static str,
) -> Result<[u8; 32], FormatError> {
    bytes
        .get(offset..offset + 32)
        .ok_or(FormatError::InvalidLength {
            structure,
            expected: offset + 32,
            actual: bytes.len(),
        })?
        .try_into()
        .map_err(|_| FormatError::InvalidLength {
            structure,
            expected: offset + 32,
            actual: bytes.len(),
        })
}

#[cfg(test)]
fn read_u16(bytes: &[u8], offset: usize, structure: &'static str) -> Result<u16, FormatError> {
    let raw = bytes
        .get(offset..offset + 2)
        .ok_or(FormatError::InvalidLength {
            structure,
            expected: offset + 2,
            actual: bytes.len(),
        })?;
    Ok(u16::from_le_bytes(raw.try_into().map_err(|_| {
        FormatError::InvalidLength {
            structure,
            expected: offset + 2,
            actual: bytes.len(),
        }
    })?))
}

#[cfg(test)]
fn read_u32(bytes: &[u8], offset: usize, structure: &'static str) -> Result<u32, FormatError> {
    let raw = bytes
        .get(offset..offset + 4)
        .ok_or(FormatError::InvalidLength {
            structure,
            expected: offset + 4,
            actual: bytes.len(),
        })?;
    Ok(u32::from_le_bytes(raw.try_into().map_err(|_| {
        FormatError::InvalidLength {
            structure,
            expected: offset + 4,
            actual: bytes.len(),
        }
    })?))
}

#[cfg(test)]
fn read_u64(bytes: &[u8], offset: usize, structure: &'static str) -> Result<u64, FormatError> {
    let raw = bytes
        .get(offset..offset + 8)
        .ok_or(FormatError::InvalidLength {
            structure,
            expected: offset + 8,
            actual: bytes.len(),
        })?;
    Ok(u64::from_le_bytes(raw.try_into().map_err(|_| {
        FormatError::InvalidLength {
            structure,
            expected: offset + 8,
            actual: bytes.len(),
        }
    })?))
}

#[cfg(test)]
fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::crypto::{compute_hmac, HmacDomain, MasterKey, Subkeys};
    use crate::format::{
        AeadAlgo, CompressionAlgo, FecAlgo, KdfAlgo, CRYPTO_EXTENSION_HEADER_LEN,
        CRYPTO_HEADER_FIXED_LEN, CRYPTO_HEADER_HMAC_LEN, FORMAT_VERSION, VOLUME_FORMAT_REV,
        VOLUME_HEADER_LEN, VOLUME_TRAILER_LEN,
    };
    use crate::non_seekable_reader::{
        verify_non_seekable_stream, verify_non_seekable_stream_with_bootstrap_sidecar,
        NonSeekableReaderOptions,
    };
    use crate::reader::{
        open_archive, open_archive_with_bootstrap_sidecar, open_non_seekable_archive,
        public_no_key_verify_archive_with, sequential_extract_tar_stream,
    };
    use crate::tar_model::parse_tar_member_group;
    use crate::wire::{
        validate_crypto_extension_semantics, CryptoHeaderFixed, ExtensionTlv, VolumeHeader,
    };

    use super::*;

    #[test]
    fn raw_stream_index_rows_round_trip() {
        let root = RawStreamIndexRootV1 {
            file_count: 1,
            frame_count: 2,
            envelope_count: 3,
            payload_block_count: 4,
            raw_total_size: 5,
            raw_content_sha256: [6; 32],
            raw_file_entry_offset: RAW_STREAM_INDEX_ROOT_V1_LEN as u32,
            raw_frame_table_offset: 200,
            raw_envelope_table_offset: 300,
            string_pool_offset: 400,
            string_pool_size: 12,
        };
        assert_eq!(RawStreamIndexRootV1::parse(&root.to_bytes()).unwrap(), root);

        let file = RawFileEntryV1 {
            path_hash: [1; 8],
            path_offset: 400,
            path_length: 15,
            file_data_size: 1234,
            first_frame_index: 0,
            frame_count: 2,
            mode: 0o644,
            mtime: 1_700_000_000,
            content_sha256: [2; 32],
        };
        assert_eq!(RawFileEntryV1::parse(&file.to_bytes()).unwrap(), file);

        let frame = RawFrameEntryV1 {
            frame_index: 7,
            envelope_index: 8,
            offset_in_envelope: 9,
            compressed_size: 10,
            decompressed_size: 11,
            raw_stream_offset: 12,
        };
        assert_eq!(RawFrameEntryV1::parse(&frame.to_bytes()).unwrap(), frame);

        let envelope = RawEnvelopeEntryV1 {
            envelope_index: 13,
            first_block_index: 14,
            data_block_count: 15,
            parity_block_count: 16,
            encrypted_size: 17,
            plaintext_size: 18,
            first_frame_index: 19,
            frame_count: 20,
        };
        assert_eq!(
            RawEnvelopeEntryV1::parse(&envelope.to_bytes()).unwrap(),
            envelope
        );
    }

    #[test]
    fn raw_content_model_extension_is_critical_and_exact() {
        let tlv = serialize_raw_stream_content_model_extension();
        assert_eq!(
            u16::from_le_bytes(tlv[0..2].try_into().unwrap()),
            RAW_STREAM_CONTENT_MODEL_EXTENSION_CRITICAL_TAG
        );
        assert_eq!(
            u32::from_le_bytes(tlv[2..6].try_into().unwrap()),
            RAW_STREAM_CONTENT_MODEL_VALUE.len() as u32
        );
        assert_eq!(&tlv[6..], RAW_STREAM_CONTENT_MODEL_VALUE);

        assert_eq!(
            validate_raw_stream_content_model_extension(false, RAW_STREAM_CONTENT_MODEL_VALUE)
                .unwrap_err(),
            FormatError::MalformedKnownExtension(RAW_STREAM_CONTENT_MODEL_EXTENSION_TAG)
        );
        assert_eq!(
            validate_raw_stream_content_model_extension(true, b"tar_member").unwrap_err(),
            FormatError::MalformedKnownExtension(RAW_STREAM_CONTENT_MODEL_EXTENSION_TAG)
        );
    }

    #[test]
    fn base_readers_reject_raw_stream_profile_before_tar_metadata() {
        let master_key = MasterKey::from_raw_key(&[9; 32]).unwrap();
        let archive = minimal_raw_profile_archive(&master_key);
        let expected = FormatError::ReaderUnsupported(RAW_STREAM_UNSUPPORTED_MESSAGE);

        assert_eq!(open_archive(&archive, &master_key).unwrap_err(), expected);
        assert_eq!(
            sequential_extract_tar_stream(&archive, &master_key).unwrap_err(),
            expected
        );
        assert_eq!(
            verify_non_seekable_stream(Cursor::new(&archive), &master_key).unwrap_err(),
            expected
        );
        assert_eq!(
            open_archive_with_bootstrap_sidecar(&archive, b"not a sidecar", &master_key)
                .unwrap_err(),
            expected
        );
        assert_eq!(
            open_non_seekable_archive(&archive, &master_key, Some(b"not a sidecar")).unwrap_err(),
            expected
        );
        assert_eq!(
            verify_non_seekable_stream_with_bootstrap_sidecar(
                Cursor::new(&archive),
                b"not a sidecar",
                &master_key,
                NonSeekableReaderOptions::default(),
            )
            .unwrap_err(),
            expected
        );
        assert_eq!(
            public_no_key_verify_archive_with(&archive, |_, _| Ok(true)).unwrap_err(),
            expected
        );
    }

    #[test]
    fn raw_stream_profile_rejects_before_tar_metadata_poison_corpus() {
        let master_key = MasterKey::from_raw_key(&[9; 32]).unwrap();
        let expected = FormatError::ReaderUnsupported(RAW_STREAM_UNSUPPORTED_MESSAGE);

        let mut bad_checksum = tar_member(b"file.txt", b'0', b"abc", b"");
        bad_checksum[0] = b'F';

        let mut nonzero_padding = tar_member(b"file.txt", b'0', b"a", b"");
        nonzero_padding[513] = 1;

        let mut pax_size_exceeds_group =
            tar_member(b"PaxHeaders/file", b'x', &pax_record("size", b"4096"), b"");
        pax_size_exceeds_group.extend_from_slice(&tar_member_with_declared_size(
            b"file", b'0', 0, b"short", b"",
        ));

        let metadata_only = tar_member(
            b"PaxHeaders/file",
            b'x',
            &pax_record("path", b"safe.txt"),
            b"",
        );

        let poison_cases = vec![
            (
                "global pax",
                tar_member(b"global", b'g', &pax_record("path", b"poisoned.txt"), b""),
                FormatError::InvalidArchive("global PAX headers are not allowed"),
            ),
            (
                "gnu sparse entry",
                tar_member(b"sparse.bin", b'S', b"", b""),
                FormatError::ReaderUnsupported("unsupported GNU sparse tar entry"),
            ),
            (
                "unsupported typeflag",
                tar_member(b"fifo", b'6', b"", b""),
                FormatError::ReaderUnsupported("unsupported tar entry type"),
            ),
            (
                "unsafe absolute path",
                tar_member(b"/absolute", b'0', b"abc", b""),
                FormatError::UnsafeArchivePath,
            ),
            (
                "bad checksum",
                bad_checksum,
                FormatError::InvalidArchive("tar header checksum mismatch"),
            ),
            (
                "nonzero padding",
                nonzero_padding,
                FormatError::InvalidArchive("tar member padding is non-zero"),
            ),
            (
                "pax size exceeds group",
                pax_size_exceeds_group,
                FormatError::InvalidLength {
                    structure: "tar member",
                    expected: 5632,
                    actual: 2048,
                },
            ),
            (
                "metadata without main entry",
                metadata_only,
                FormatError::InvalidArchive(
                    "tar member group has metadata records but no main entry",
                ),
            ),
        ];

        for (name, tar_body, tar_error) in poison_cases {
            let _ = tar_error;
            assert!(parse_tar_member_group(&tar_body, 4096).is_err(), "{name}");

            let archive = minimal_raw_profile_archive_with_body(&master_key, &tar_body);
            assert_eq!(
                open_archive(&archive, &master_key).unwrap_err(),
                expected,
                "{name}: seekable open"
            );
            assert_eq!(
                sequential_extract_tar_stream(&archive, &master_key).unwrap_err(),
                expected,
                "{name}: sequential extraction"
            );
            assert_eq!(
                verify_non_seekable_stream(Cursor::new(&archive), &master_key).unwrap_err(),
                expected,
                "{name}: non-seekable verify"
            );
            assert_eq!(
                public_no_key_verify_archive_with(&archive, |_, _| Ok(true)).unwrap_err(),
                expected,
                "{name}: public no-key verify"
            );
        }
    }

    #[test]
    fn non_critical_raw_stream_tag_is_forward_compatible_unknown_extension() {
        let extension = ExtensionTlv {
            tag: RAW_STREAM_CONTENT_MODEL_EXTENSION_TAG,
            value: b"ignored by base reader",
        };

        validate_crypto_extension_semantics(std::slice::from_ref(&extension)).unwrap();
        assert_eq!(
            content_profile_from_extensions(&[extension]).unwrap(),
            ContentProfile::TarMember
        );
    }

    fn minimal_raw_profile_archive(master_key: &MasterKey) -> Vec<u8> {
        minimal_raw_profile_archive_with_body(master_key, &[])
    }

    fn minimal_raw_profile_archive_with_body(master_key: &MasterKey, body: &[u8]) -> Vec<u8> {
        let archive_uuid = [1; 16];
        let session_id = [2; 16];
        let subkeys = Subkeys::derive(master_key, &archive_uuid, &session_id).unwrap();
        let extension = serialize_raw_stream_content_model_extension();
        let crypto_len = CRYPTO_HEADER_FIXED_LEN
            + 2
            + extension.len()
            + CRYPTO_EXTENSION_HEADER_LEN
            + CRYPTO_HEADER_HMAC_LEN;
        let fixed = CryptoHeaderFixed {
            length: crypto_len as u32,
            compression_algo: CompressionAlgo::ZstdFramed,
            aead_algo: AeadAlgo::AesGcmSiv256,
            fec_algo: FecAlgo::ReedSolomonGF16,
            kdf_algo: KdfAlgo::Raw,
            chunk_size: 4096,
            envelope_target_size: 4096,
            block_size: 4096,
            fec_data_shards: 1,
            fec_parity_shards: 0,
            index_fec_data_shards: 1,
            index_fec_parity_shards: 0,
            index_root_fec_data_shards: 1,
            index_root_fec_parity_shards: 0,
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            has_dictionary: 0,
            max_path_length: 4096,
            expected_volume_size: 0,
        };
        let mut crypto = fixed.to_bytes().to_vec();
        crypto.extend_from_slice(&(KdfAlgo::Raw as u16).to_le_bytes());
        crypto.extend_from_slice(&extension);
        crypto.extend_from_slice(&0u16.to_le_bytes());
        crypto.extend_from_slice(&0u32.to_le_bytes());
        let hmac = compute_hmac(
            HmacDomain::CryptoHeader,
            &subkeys.mac_key,
            &archive_uuid,
            &session_id,
            &crypto,
        );
        crypto.extend_from_slice(&hmac);

        let header = VolumeHeader {
            format_version: FORMAT_VERSION,
            volume_format_rev: VOLUME_FORMAT_REV,
            volume_index: 0,
            stripe_width: 1,
            archive_uuid,
            session_id,
            crypto_header_offset: VOLUME_HEADER_LEN as u32,
            crypto_header_length: crypto.len() as u32,
            header_crc32c: 0,
        };
        let mut archive = header.to_bytes().to_vec();
        archive.extend_from_slice(&crypto);
        archive.extend_from_slice(body);
        archive.resize(
            VOLUME_HEADER_LEN + crypto.len() + body.len() + VOLUME_TRAILER_LEN,
            0,
        );
        archive
    }

    fn tar_header(path: &[u8], kind: u8, size: usize, link: &[u8]) -> [u8; 512] {
        let mut header = [0u8; 512];
        header[..path.len()].copy_from_slice(path);
        write_octal(&mut header[100..108], 0o644);
        write_octal(&mut header[108..116], 0);
        write_octal(&mut header[116..124], 0);
        write_octal(&mut header[124..136], size as u64);
        write_octal(&mut header[136..148], 0);
        header[148..156].fill(b' ');
        header[156] = kind;
        header[157..157 + link.len()].copy_from_slice(link);
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum = header.iter().map(|byte| *byte as u64).sum::<u64>();
        write_checksum(&mut header[148..156], checksum);
        header
    }

    fn tar_member(path: &[u8], kind: u8, data: &[u8], link: &[u8]) -> Vec<u8> {
        tar_member_with_declared_size(path, kind, data.len(), data, link)
    }

    fn tar_member_with_declared_size(
        path: &[u8],
        kind: u8,
        declared_size: usize,
        data: &[u8],
        link: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&tar_header(path, kind, declared_size, link));
        out.extend_from_slice(data);
        out.resize(out.len() + tar_padding_to_512(data.len()), 0);
        out
    }

    fn pax_record(key: &str, value: &[u8]) -> Vec<u8> {
        let mut len = key.len() + value.len() + 4;
        loop {
            let candidate = len.to_string().len() + 1 + key.len() + 1 + value.len() + 1;
            if candidate == len {
                break;
            }
            len = candidate;
        }
        let mut out = Vec::new();
        out.extend_from_slice(len.to_string().as_bytes());
        out.push(b' ');
        out.extend_from_slice(key.as_bytes());
        out.push(b'=');
        out.extend_from_slice(value);
        out.push(b'\n');
        out
    }

    fn write_octal(field: &mut [u8], value: u64) {
        let digits = format!("{value:o}");
        field.fill(0);
        let start = field.len() - 1 - digits.len();
        field[..start].fill(b'0');
        field[start..start + digits.len()].copy_from_slice(digits.as_bytes());
    }

    fn write_checksum(field: &mut [u8], value: u64) {
        let digits = format!("{value:06o}");
        field[0..6].copy_from_slice(digits.as_bytes());
        field[6] = 0;
        field[7] = b' ';
    }

    fn tar_padding_to_512(len: usize) -> usize {
        let remainder = len % 512;
        if remainder == 0 {
            0
        } else {
            512 - remainder
        }
    }
}
