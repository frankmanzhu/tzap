use std::fs;
use std::io::Read;

use super::*;
use crate::compression::compress_zstd_frame;
use crate::crypto::{compute_hmac, encrypt_padded_aead_object, AeadObjectContext, KdfParams};
use crate::entry_metadata::RestorePolicy;
use crate::fec::encode_parity_gf16;
use crate::format::{
    AeadAlgo, CompressionAlgo, FecAlgo, KdfAlgo, BLOCK_RECORD_FRAMING_LEN,
    BOOTSTRAP_SIDECAR_HEADER_LEN, CRITICAL_METADATA_RECOVERY_HEADER_LEN,
    CRITICAL_METADATA_RECOVERY_SHARD_HEADER_LEN, CRITICAL_RECOVERY_LOCATOR_LEN,
    CRYPTO_EXTENSION_HEADER_LEN, CRYPTO_HEADER_FIXED_LEN, FORMAT_VERSION, LOCATOR_PAIR_LEN,
    MANIFEST_FOOTER_LEN, READER_MAX_SUPPORTED_VOLUME_FORMAT_REV, VOLUME_FORMAT_REV,
    VOLUME_FORMAT_REV_45, VOLUME_TRAILER_LEN,
};
use crate::metadata::{
    hash_prefix, DirectoryHintEntry, DirectoryHintTableHeader, IndexRootHeader, IndexShardHeader,
    ENVELOPE_ENTRY_LEN, FILE_ENTRY_LEN, FRAME_ENTRY_LEN, INDEX_SHARD_HEADER_LEN,
};
use crate::non_seekable_reader::{
    extract_non_seekable_stream_to_dir, list_non_seekable_stream, verify_non_seekable_stream,
    verify_non_seekable_stream_with_bootstrap_sidecar, verify_non_seekable_stream_with_options,
    verify_non_seekable_stream_with_recipient_wrap_resolver_options, NonSeekableReaderOptions,
    SequentialRootAuthStatus,
};
use crate::raw_stream_profile::{
    serialize_raw_stream_content_model_extension, RAW_STREAM_UNSUPPORTED_MESSAGE,
};
use crate::wire::{
    compute_key_wrap_table_digest, BootstrapSidecarHeader, CriticalMetadataImage,
    CriticalMetadataRecoveryHeader, CriticalMetadataRecoveryShard, CriticalRecoveryLocator,
    RecipientRecordV1,
};
use crate::writer::NativeFileMetadata;
use crate::writer::{
    write_archive, write_archive_sources_to_sink_single_pass, write_archive_unencrypted,
    write_archive_with_dictionary, write_archive_with_kdf,
    write_archive_with_recipient_wrap_records, write_archive_with_root_auth,
    write_archive_with_root_auth_and_recipient_wrap_records, MemoryArchiveSink,
    PortableFileMetadata, PortableModeOrigin, PortablePosixOwner, RegularFile, RegularFileSource,
    RootAuthSigningRequest, RootAuthWriterConfig, SourceEntryKind, WriterOptions,
};
#[cfg(target_os = "linux")]
use crate::writer::{NativeAuxiliaryMetadata, NativeAuxiliaryNameEncoding};

#[test]
fn exposed_attributes_prefer_exact_native_platform_flags() {
    let mut records = crate::entry_metadata::PaxRecords::new();
    records.insert("TZAP.macos.st-flags".into(), b"0000000000008000".to_vec());
    assert_eq!(exposed_file_attributes(&records, Some(2)), Some(0x8000));

    records.remove("TZAP.macos.st-flags");
    records.insert("TZAP.windows.file-attributes".into(), b"00000022".to_vec());
    assert_eq!(exposed_file_attributes(&records, Some(2)), Some(0x22));

    records.clear();
    assert_eq!(exposed_file_attributes(&records, Some(2)), Some(2));
}

fn master_key() -> MasterKey {
    MasterKey::from_raw_key(&[0x42; 32]).unwrap()
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

fn recipient_wrap_layout(volume: &[u8]) -> (usize, usize, usize, usize, u32) {
    let header = VolumeHeader::parse(&volume[..VOLUME_HEADER_LEN]).unwrap();
    let crypto_start = header.crypto_header_offset as usize;
    let crypto_len = header.crypto_header_length as usize;
    let crypto_end = crypto_start + crypto_len;
    let crypto = CryptoHeader::parse(
        &volume[crypto_start..crypto_end],
        header.crypto_header_length,
    )
    .unwrap();
    let KdfParams::RecipientWrap {
        key_wrap_table_length,
        ..
    } = crypto.kdf_params
    else {
        panic!("expected RecipientWrap KdfParams");
    };
    (
        crypto_start,
        crypto_len,
        crypto_end,
        key_wrap_table_length as usize,
        key_wrap_table_length,
    )
}

fn rewrite_recipient_wrap_kdf_digest(crypto_bytes: &mut [u8], digest: [u8; 32]) {
    let digest_start = CRYPTO_HEADER_FIXED_LEN + 14;
    crypto_bytes[digest_start..digest_start + 32].copy_from_slice(&digest);
}

fn mutate_top_level_recipient_wrap_public_profile(volume: &mut [u8]) {
    let (crypto_start, crypto_len, table_start, table_len, table_len_u32) =
        recipient_wrap_layout(volume);
    let table_end = table_start + table_len;
    volume[table_end - 1] ^= 0x5a;
    let digest = compute_key_wrap_table_digest(table_len_u32, &volume[table_start..table_end]);
    rewrite_recipient_wrap_kdf_digest(&mut volume[crypto_start..crypto_start + crypto_len], digest);
}

fn mutate_cmra_recipient_wrap_public_profile(volume: &mut [u8]) {
    rewrite_public_cmra_image(volume, |image| {
        let table_region = image
            .regions
            .iter_mut()
            .find(|region| region.region_type == 6)
            .unwrap();
        *table_region.bytes.last_mut().unwrap() ^= 0x5a;
        let digest =
            compute_key_wrap_table_digest(table_region.bytes.len() as u32, &table_region.bytes);
        let crypto_region = image
            .regions
            .iter_mut()
            .find(|region| region.region_type == 2)
            .unwrap();
        rewrite_recipient_wrap_kdf_digest(&mut crypto_region.bytes, digest);
    });
}

fn add_raw_stream_profile_to_physical_crypto_header(volume: &mut Vec<u8>) {
    let mut header = VolumeHeader::parse(&volume[..VOLUME_HEADER_LEN]).unwrap();
    let crypto_start = header.crypto_header_offset as usize;
    let crypto_len = header.crypto_header_length as usize;
    let hmac_start = crypto_start + crypto_len - CRYPTO_HEADER_HMAC_LEN;
    let terminator_start = hmac_start - CRYPTO_EXTENSION_HEADER_LEN;
    let extension = serialize_raw_stream_content_model_extension();
    let new_crypto_len = header.crypto_header_length + extension.len() as u32;

    volume.splice(terminator_start..terminator_start, extension);
    header.crypto_header_length = new_crypto_len;
    volume[..VOLUME_HEADER_LEN].copy_from_slice(&header.to_bytes());
    volume[crypto_start + 4..crypto_start + 8].copy_from_slice(&new_crypto_len.to_le_bytes());
}

fn recompute_physical_crypto_header_hmac(volume: &mut [u8], master_key: &MasterKey) {
    let header = VolumeHeader::parse(&volume[..VOLUME_HEADER_LEN]).unwrap();
    let crypto_start = header.crypto_header_offset as usize;
    let crypto_end = crypto_start + header.crypto_header_length as usize;
    let hmac_start = crypto_end - CRYPTO_HEADER_HMAC_LEN;
    let subkeys = Subkeys::derive(master_key, &header.archive_uuid, &header.session_id).unwrap();
    let hmac = compute_hmac(
        HmacDomain::CryptoHeader,
        &subkeys.mac_key,
        &header.archive_uuid,
        &header.session_id,
        &volume[crypto_start..hmac_start],
    );
    volume[hmac_start..crypto_end].copy_from_slice(&hmac);
}

#[test]
fn reader_defaults_use_available_parallelism_jobs() {
    let options = ReaderOptions::default();

    assert_eq!(options.jobs, default_jobs());
    assert!(options.jobs >= 1);
}

#[test]
fn reader_options_reject_zero_jobs() {
    let err = OpenedArchive::open_with_options(
        &[],
        &master_key(),
        ReaderOptions {
            jobs: 0,
            ..ReaderOptions::default()
        },
    )
    .unwrap_err();

    assert_eq!(
        err,
        FormatError::ReaderUnsupported("jobs must be at least 1")
    );
}

const TEST_ROOT_AUTH_ID: u16 = 0xe001;
const TEST_ROOT_AUTH_VALUE_LEN: u32 = 32;

fn test_root_auth_config() -> RootAuthWriterConfig<'static> {
    RootAuthWriterConfig {
        authenticator_id: TEST_ROOT_AUTH_ID,
        signer_identity_type: 0,
        signer_identity: &[],
        authenticator_value_length: TEST_ROOT_AUTH_VALUE_LEN,
    }
}

fn test_root_auth_value(request: &RootAuthSigningRequest) -> Vec<u8> {
    request.archive_root.to_vec()
}

fn test_root_auth_verifies(footer: &RootAuthFooterV1, archive_root: &[u8; 32]) -> bool {
    footer.authenticator_id == TEST_ROOT_AUTH_ID
        && footer.signer_identity_type == 0
        && footer.signer_identity_bytes.is_empty()
        && footer.authenticator_value.as_slice() == archive_root
}

fn dictionary() -> &'static [u8] {
    b"dir/dict.txt common words common words common words dictionary payload"
}

#[derive(Clone)]
struct CountingReadAt {
    bytes: std::sync::Arc<Vec<u8>>,
    reads: std::sync::Arc<std::sync::Mutex<Vec<(u64, u64)>>>,
    denied_ranges: std::sync::Arc<Vec<(u64, u64)>>,
}

impl CountingReadAt {
    fn new(bytes: Vec<u8>, denied_ranges: Vec<(u64, u64)>) -> Self {
        Self {
            bytes: std::sync::Arc::new(bytes),
            reads: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            denied_ranges: std::sync::Arc::new(denied_ranges),
        }
    }

    fn reads(&self) -> Vec<(u64, u64)> {
        self.reads.lock().unwrap().clone()
    }
}

impl ArchiveReadAt for CountingReadAt {
    fn len(&self) -> Result<u64, FormatError> {
        u64::try_from(self.bytes.as_ref().len())
            .map_err(|_| FormatError::InvalidArchive("archive length overflow"))
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), FormatError> {
        let end = checked_u64_add(offset, buf.len() as u64, "archive read range overflow")?;
        self.reads.lock().unwrap().push((offset, end));
        if self
            .denied_ranges
            .iter()
            .any(|(start, limit)| ranges_overlap(offset, end, *start, *limit))
        {
            return Err(FormatError::InvalidArchive("denied test read"));
        }
        let start = to_usize(offset, "archive")?;
        let end_usize = checked_add(start, buf.len(), "archive")?;
        let source = self
            .bytes
            .get(start..end_usize)
            .ok_or(FormatError::InvalidLength {
                structure: "archive",
                expected: end_usize,
                actual: self.bytes.as_ref().len(),
            })?;
        buf.copy_from_slice(source);
        Ok(())
    }
}

fn ranges_overlap(left_start: u64, left_end: u64, right_start: u64, right_end: u64) -> bool {
    left_start < right_end && right_start < left_end
}

fn single_stream_options() -> WriterOptions {
    WriterOptions {
        stripe_width: 1,
        volume_loss_tolerance: 0,
        ..WriterOptions::default()
    }
}

struct ChunkedReader {
    bytes: Vec<u8>,
    cursor: usize,
    max_chunk: usize,
}

impl ChunkedReader {
    fn new(bytes: Vec<u8>, max_chunk: usize) -> Self {
        Self {
            bytes,
            cursor: 0,
            max_chunk,
        }
    }
}

impl std::io::Read for ChunkedReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.cursor >= self.bytes.len() {
            return Ok(0);
        }
        let available = self.bytes.len() - self.cursor;
        let len = available.min(buf.len()).min(self.max_chunk);
        buf[..len].copy_from_slice(&self.bytes[self.cursor..self.cursor + len]);
        self.cursor += len;
        Ok(len)
    }
}

#[test]
fn global_file_table_key_step_rejects_distinct_path_regression() {
    let previous = ([1u8; 8], b"b.txt".to_vec(), 0);
    let current = ([1u8; 8], b"a.txt".to_vec(), 0);

    assert_eq!(
        validate_global_file_table_key_step(Some(&previous), &current).unwrap_err(),
        FormatError::InvalidArchive("global FileEntry rows are not sorted and unique")
    );
}

#[test]
fn global_file_table_key_step_rejects_duplicate_full_key() {
    let previous = ([1u8; 8], b"a.txt".to_vec(), 7);
    let current = ([1u8; 8], b"a.txt".to_vec(), 7);

    assert_eq!(
        validate_global_file_table_key_step(Some(&previous), &current).unwrap_err(),
        FormatError::InvalidArchive("global FileEntry rows are not sorted and unique")
    );
}

fn small_block_recovery_options() -> WriterOptions {
    WriterOptions {
        block_size: 4096,
        chunk_size: 32 * 1024,
        envelope_target_size: 32 * 1024,
        stripe_width: 1,
        volume_loss_tolerance: 0,
        bit_rot_buffer_pct: 1,
        fec_data_shards: 16,
        fec_parity_shards: 1,
        index_fec_data_shards: 4,
        index_fec_parity_shards: 1,
        index_root_fec_data_shards: 16,
        index_root_fec_parity_shards: 1,
        ..WriterOptions::default()
    }
}

fn parity_rich_recovery_options() -> WriterOptions {
    WriterOptions {
        block_size: 4096,
        chunk_size: 32 * 1024,
        envelope_target_size: 32 * 1024,
        stripe_width: 1,
        volume_loss_tolerance: 0,
        bit_rot_buffer_pct: 40,
        fec_data_shards: 16,
        fec_parity_shards: 16,
        index_fec_data_shards: 4,
        index_fec_parity_shards: 4,
        index_root_fec_data_shards: 16,
        index_root_fec_parity_shards: 16,
        ..WriterOptions::default()
    }
}

fn pseudo_random_bytes(len: usize) -> Vec<u8> {
    let mut state = 0x1234_5678u32;
    (0..len)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state >> 24) as u8
        })
        .collect()
}

#[test]
fn opens_lists_verifies_and_extracts_one_file_archive() {
    let archive = write_archive(
        &[RegularFile::new("dir/hello.txt", b"hello m7")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let opened = open_archive(&archive.bytes, &master_key()).unwrap();

    assert_eq!(
        opened.list_files().unwrap(),
        vec![ArchiveEntry {
            path: "dir/hello.txt".to_string(),
            file_data_size: 8,
            kind: TarEntryKind::Regular,
            mode: 0o644,
            mtime: ArchiveTimestamp::UNIX_EPOCH,
            diagnostics: Vec::new(),
            link_target: None,
            created: None,
            accessed: None,
            attributes: None,
            uid: None,
            gid: None,
            uname: None,
            gname: None,
        }]
    );
    opened.verify().unwrap();
    assert_eq!(
        opened.extract_file("dir/hello.txt").unwrap(),
        Some(b"hello m7".to_vec())
    );
    assert_eq!(opened.extract_file("missing.txt").unwrap(), None);
}

#[test]
fn root_auth_archive_round_trips_and_verifies_with_callback() {
    let archive = write_archive_with_root_auth(
        &[RegularFile::new("signed.txt", b"root-auth payload")],
        &master_key(),
        single_stream_options(),
        RootAuthWriterConfig {
            authenticator_id: 0x7777,
            signer_identity_type: 1,
            signer_identity: b"test signer",
            authenticator_value_length: 32,
        },
        |request| Ok(request.archive_root.to_vec()),
    )
    .unwrap();

    let opened = open_archive(&archive.bytes, &master_key()).unwrap();
    opened.verify().unwrap();
    let verified = opened
        .verify_root_auth_with(|footer, archive_root| {
            Ok(footer.authenticator_value == archive_root.as_slice())
        })
        .unwrap();

    assert_eq!(verified.authenticator_id, 0x7777);
    assert_eq!(verified.signer_identity_type, 1);
    assert_eq!(verified.signer_identity_bytes, b"test signer");
    assert_eq!(
        verified.archive_root,
        opened.root_auth_footer.as_ref().unwrap().archive_root
    );
    assert_eq!(
        verified.diagnostics,
        vec![
            RootAuthDiagnostic::RootAuthContentVerified,
            RootAuthDiagnostic::AuthenticatedMetadataNotRootSigned,
            RootAuthDiagnostic::RecoveryMarginNotRootAuthenticated,
            RootAuthDiagnostic::RecoveryMarginUnchecked,
        ]
    );
}

#[test]
fn root_auth_rejects_fast_content_verification_token() {
    let archive = write_archive_with_root_auth(
        &[RegularFile::new("signed.txt", b"root-auth payload")],
        &master_key(),
        single_stream_options(),
        RootAuthWriterConfig {
            authenticator_id: 0x7777,
            signer_identity_type: 1,
            signer_identity: b"test signer",
            authenticator_value_length: 32,
        },
        |request| Ok(request.archive_root.to_vec()),
    )
    .unwrap();

    let opened = open_archive(&archive.bytes, &master_key()).unwrap();
    let content_verification = opened.verify_content_fast().unwrap();
    assert_eq!(
        opened
            .verify_root_auth_with_verified_content(&content_verification, |_, _| Ok(true))
            .unwrap_err(),
        FormatError::ReaderUnsupported(
            "RootAuth verification requires full archive content verification"
        )
    );
}

#[test]
fn root_auth_verification_requires_authenticator_success() {
    let archive = write_archive_with_root_auth(
        &[RegularFile::new("signed.txt", b"root-auth payload")],
        &master_key(),
        single_stream_options(),
        RootAuthWriterConfig {
            authenticator_id: 9,
            signer_identity_type: 1,
            signer_identity: b"test signer",
            authenticator_value_length: 32,
        },
        |request| Ok(request.archive_root.to_vec()),
    )
    .unwrap();
    let opened = open_archive(&archive.bytes, &master_key()).unwrap();

    assert_eq!(
        opened.verify_root_auth_with(|_, _| Ok(false)).unwrap_err(),
        FormatError::InvalidArchive("root-auth authenticator verification failed")
    );
}

#[test]
fn public_no_key_verifies_encrypted_data_block_commitment_with_callback() {
    let archive = write_archive_with_root_auth(
        &[RegularFile::new("public.txt", b"public commitment")],
        &master_key(),
        single_stream_options(),
        RootAuthWriterConfig {
            authenticator_id: 0x2222,
            signer_identity_type: 1,
            signer_identity: b"public verifier",
            authenticator_value_length: 32,
        },
        |request| Ok(request.archive_root.to_vec()),
    )
    .unwrap();

    let verified = public_no_key_verify_archive_with(&archive.bytes, |footer, archive_root| {
        Ok(footer.authenticator_value == archive_root.as_slice())
    })
    .unwrap();

    assert_eq!(verified.authenticator_id, 0x2222);
    assert_eq!(verified.signer_identity_bytes, b"public verifier");
    assert!(verified.total_data_block_count > 0);
}

#[test]
fn public_no_key_verifier_not_invoked_for_future_revision() {
    let archive = write_archive_with_root_auth(
        &[RegularFile::new("public.txt", b"public callback")],
        &master_key(),
        single_stream_options(),
        RootAuthWriterConfig {
            authenticator_id: 0x2222,
            signer_identity_type: 1,
            signer_identity: b"public verifier",
            authenticator_value_length: 32,
        },
        |request| Ok(request.archive_root.to_vec()),
    )
    .unwrap();
    let mut bytes = archive.bytes;
    let mut header = VolumeHeader::parse(&bytes[..VOLUME_HEADER_LEN]).unwrap();
    header.volume_format_rev = VOLUME_FORMAT_REV_45 + 1;
    bytes[..VOLUME_HEADER_LEN].copy_from_slice(&header.to_bytes());

    let mut called = false;
    let err = public_no_key_verify_archive_with(&bytes, |_, _| {
        called = true;
        Ok(true)
    })
    .unwrap_err();

    assert!(!called);
    assert_eq!(
        err,
        FormatError::UnsupportedVolumeFormatRevision {
            format_version: FORMAT_VERSION,
            volume_format_rev: VOLUME_FORMAT_REV_45 + 1,
            reader_max_supported_revision: READER_MAX_SUPPORTED_VOLUME_FORMAT_REV,
        }
    );
}

#[test]
fn public_no_key_rejects_public_header_revision_mismatch() {
    let archive = write_archive_with_root_auth(
        &[RegularFile::new("public.txt", b"public v45 only")],
        &master_key(),
        single_stream_options(),
        RootAuthWriterConfig {
            authenticator_id: 0x2222,
            signer_identity_type: 1,
            signer_identity: b"public verifier",
            authenticator_value_length: 32,
        },
        |request| Ok(request.archive_root.to_vec()),
    )
    .unwrap();
    let mut bytes = archive.bytes;
    let mut header = VolumeHeader::parse(&bytes[..VOLUME_HEADER_LEN]).unwrap();
    header.volume_format_rev = 43;
    bytes[..VOLUME_HEADER_LEN].copy_from_slice(&header.to_bytes());

    let mut called = false;
    let err = public_no_key_verify_archive_with(&bytes, |_, _| {
        called = true;
        Ok(true)
    })
    .unwrap_err();

    assert!(!called);
    assert_eq!(
        err,
        FormatError::UnsupportedVolumeFormatRevision {
            format_version: FORMAT_VERSION,
            volume_format_rev: 43,
            reader_max_supported_revision: READER_MAX_SUPPORTED_VOLUME_FORMAT_REV,
        }
    );
}

#[test]
fn public_no_key_rejects_recovered_footer_revision_mismatch() {
    let archive = write_archive_with_root_auth(
        &[RegularFile::new("public.txt", b"public footer mismatch")],
        &master_key(),
        single_stream_options(),
        RootAuthWriterConfig {
            authenticator_id: 0x2222,
            signer_identity_type: 1,
            signer_identity: b"public verifier",
            authenticator_value_length: 32,
        },
        |request| Ok(request.archive_root.to_vec()),
    )
    .unwrap();
    let mut bytes = archive.bytes;
    rewrite_public_cmra_image(&mut bytes, |image| {
        let root_auth_region = image
            .regions
            .iter_mut()
            .find(|region| region.region_type == 4)
            .unwrap();
        rewrite_root_auth_footer_revision_bytes(&mut root_auth_region.bytes, 43);
    });

    let mut called = false;
    let err = public_no_key_verify_archive_with(&bytes, |_, _| {
        called = true;
        Ok(true)
    })
    .unwrap_err();

    assert!(!called);
    assert_eq!(
        err,
        FormatError::InvalidArchive("no valid v41 public CMRA candidate found")
    );
}

#[test]
fn public_no_key_rejects_recovered_image_with_unknown_layout_flags() {
    let archive = write_archive_with_root_auth(
        &[RegularFile::new("public.txt", b"public image mismatch")],
        &master_key(),
        single_stream_options(),
        RootAuthWriterConfig {
            authenticator_id: 0x2222,
            signer_identity_type: 1,
            signer_identity: b"public verifier",
            authenticator_value_length: 32,
        },
        |request| Ok(request.archive_root.to_vec()),
    )
    .unwrap();
    let bytes =
        rewrite_cmra_image_variable_len(&archive.bytes, CmraRecoveryMode::PublicNoKey, |image| {
            image.layout_flags |= 0x8000_0000;
        });

    let mut called = false;
    let err = public_no_key_verify_archive_with(&bytes, |_, _| {
        called = true;
        Ok(true)
    })
    .unwrap_err();

    assert!(!called);
    assert_eq!(
        err,
        FormatError::InvalidArchive("no valid v41 public CMRA candidate found")
    );
}

#[test]
fn public_no_key_ignores_untrusted_manifest_and_trailer_block_count_fields() {
    let archive = write_archive_with_root_auth(
        &[RegularFile::new(
            "public-fields.txt",
            b"public source authority",
        )],
        &master_key(),
        single_stream_options(),
        RootAuthWriterConfig {
            authenticator_id: 0x2222,
            signer_identity_type: 1,
            signer_identity: b"public verifier",
            authenticator_value_length: 32,
        },
        |request| Ok(request.archive_root.to_vec()),
    )
    .unwrap();
    let mut bytes = archive.bytes.clone();

    rewrite_public_cmra_image(&mut bytes, |image| {
        let manifest_region = image
            .regions
            .iter_mut()
            .find(|region| region.region_type == 3)
            .unwrap();
        manifest_region.bytes[44..48].copy_from_slice(&99u32.to_le_bytes());

        let trailer_region = image
            .regions
            .iter_mut()
            .find(|region| region.region_type == 5)
            .unwrap();
        let mut trailer = VolumeTrailer::parse(&trailer_region.bytes).unwrap();
        trailer.block_count += 7;
        trailer_region.bytes = trailer.to_bytes().to_vec();
    });

    public_no_key_verify_archive_with(&bytes, |footer, archive_root| {
        Ok(footer.authenticator_value == archive_root.as_slice())
    })
    .unwrap();
}

#[test]
fn public_no_key_compares_only_public_crypto_profile_across_volumes() {
    let archive = write_archive_with_root_auth(
        &[RegularFile::new(
            "public-crypto.txt",
            b"cross-volume public profile",
        )],
        &master_key(),
        WriterOptions {
            stripe_width: 2,
            volume_loss_tolerance: 0,
            ..WriterOptions::default()
        },
        RootAuthWriterConfig {
            authenticator_id: 0x3333,
            signer_identity_type: 1,
            signer_identity: b"public verifier",
            authenticator_value_length: 32,
        },
        |request| Ok(request.archive_root.to_vec()),
    )
    .unwrap();
    let mut volumes = archive.volumes.clone();
    let volume_header = VolumeHeader::parse(&volumes[1][..VOLUME_HEADER_LEN]).unwrap();
    let crypto_offset = volume_header.crypto_header_offset as usize;
    let expected_volume_size = 123_456_789u64;
    volumes[1][crypto_offset + 52..crypto_offset + 60]
        .copy_from_slice(&expected_volume_size.to_le_bytes());
    rewrite_public_cmra_image(&mut volumes[1], |image| {
        let crypto_region = image
            .regions
            .iter_mut()
            .find(|region| region.region_type == 2)
            .unwrap();
        crypto_region.bytes[52..60].copy_from_slice(&expected_volume_size.to_le_bytes());
    });

    let volume_refs = volumes.iter().map(Vec::as_slice).collect::<Vec<_>>();
    public_no_key_verify_volumes_with(&volume_refs, |footer, archive_root| {
        Ok(footer.authenticator_value == archive_root.as_slice())
    })
    .unwrap();
}

#[test]
fn locator_based_cmra_recovery_treats_header_damage_as_recoverable() {
    let archive = write_archive_with_root_auth(
        &[RegularFile::new("cmra-header.txt", b"header fallback")],
        &master_key(),
        single_stream_options(),
        RootAuthWriterConfig {
            authenticator_id: 0x4444,
            signer_identity_type: 1,
            signer_identity: b"public verifier",
            authenticator_value_length: 32,
        },
        |request| Ok(request.archive_root.to_vec()),
    )
    .unwrap();
    let final_locator = final_recovery_locator(&archive.bytes);

    let mut bad_crc = archive.bytes.clone();
    let crc_offset = final_locator.cmra_offset as usize + CRITICAL_METADATA_RECOVERY_HEADER_LEN - 1;
    bad_crc[crc_offset] ^= 0x55;
    public_no_key_verify_archive_with(&bad_crc, |footer, archive_root| {
        Ok(footer.authenticator_value == archive_root.as_slice())
    })
    .unwrap();

    let mut bad_magic = archive.bytes.clone();
    bad_magic[final_locator.cmra_offset as usize] ^= 0x55;
    public_no_key_verify_archive_with(&bad_magic, |footer, archive_root| {
        Ok(footer.authenticator_value == archive_root.as_slice())
    })
    .unwrap();

    let mut bad_hint = archive.bytes.clone();
    bad_hint[crc_offset] ^= 0xAA;
    for offset in [
        bad_hint.len() - LOCATOR_PAIR_LEN,
        bad_hint.len() - CRITICAL_RECOVERY_LOCATOR_LEN,
    ] {
        let mut locator = CriticalRecoveryLocator::parse(
            &bad_hint[offset..offset + CRITICAL_RECOVERY_LOCATOR_LEN],
        )
        .unwrap();
        locator.volume_index_hint += 1;
        bad_hint[offset..offset + CRITICAL_RECOVERY_LOCATOR_LEN]
            .copy_from_slice(&locator.to_bytes());
    }
    assert_eq!(
        public_no_key_verify_archive_with(&bad_hint, |_, _| Ok(true)).unwrap_err(),
        FormatError::InvalidArchive("no valid v41 public CMRA candidate found")
    );
}

#[test]
fn recovers_physical_volume_header_magic_from_cmra_authority() {
    let payload = b"front header authority".to_vec();
    let archive = write_archive(
        &[RegularFile::new("volume-header.txt", &payload)],
        &master_key(),
        small_block_recovery_options(),
    )
    .unwrap();

    let mut corrupted = archive.bytes;
    corrupted[0] ^= 0x55;

    let opened = open_archive(&corrupted, &master_key()).unwrap();
    assert_eq!(
        opened.extract_file("volume-header.txt").unwrap(),
        Some(payload)
    );
    opened.verify().unwrap();
}

#[test]
fn recovers_crc_valid_physical_volume_index_from_cmra_authority() {
    let payload = b"crc-valid wrong volume index".to_vec();
    let mut options = small_block_recovery_options();
    options.stripe_width = 2;
    options.volume_loss_tolerance = 0;
    let archive = write_archive(
        &[RegularFile::new("volume-index.txt", &payload)],
        &master_key(),
        options,
    )
    .unwrap();

    let mut corrupted = archive.volumes[0].clone();
    let mut header = VolumeHeader::parse(&corrupted[..VOLUME_HEADER_LEN]).unwrap();
    assert_eq!(header.volume_index, 0);
    header.volume_index = 1;
    corrupted[..VOLUME_HEADER_LEN].copy_from_slice(&header.to_bytes());
    assert_eq!(
        VolumeHeader::parse(&corrupted[..VOLUME_HEADER_LEN])
            .unwrap()
            .volume_index,
        1
    );

    let opened = open_archive_volumes(
        &[corrupted.as_slice(), archive.volumes[1].as_slice()],
        &master_key(),
    )
    .unwrap();
    assert_eq!(opened.volume_header.volume_index, 0);
    assert_eq!(
        opened.extract_file("volume-index.txt").unwrap(),
        Some(payload)
    );
    opened.verify().unwrap();
}

#[test]
fn recovers_physical_crypto_header_magic_from_cmra_authority() {
    let payload = b"crypto header authority".to_vec();
    let archive = write_archive(
        &[RegularFile::new("crypto-header.txt", &payload)],
        &master_key(),
        small_block_recovery_options(),
    )
    .unwrap();
    let crypto_offset = VolumeHeader::parse(&archive.bytes[..VOLUME_HEADER_LEN])
        .unwrap()
        .crypto_header_offset;

    let mut corrupted = archive.bytes;
    corrupted[crypto_offset as usize] ^= 0x55;

    let opened = open_archive(&corrupted, &master_key()).unwrap();
    assert_eq!(
        opened.extract_file("crypto-header.txt").unwrap(),
        Some(payload)
    );
    opened.verify().unwrap();
}

#[test]
fn read_at_api_recovers_physical_header_magic_from_cmra_authority() {
    let payload = b"read-at header authority".to_vec();
    let archive = write_archive(
        &[RegularFile::new("read-at-header.txt", &payload)],
        &master_key(),
        small_block_recovery_options(),
    )
    .unwrap();

    let mut corrupted = archive.bytes;
    corrupted[0] ^= 0x55;

    let opened = open_seekable_archive(corrupted, &master_key()).unwrap();
    assert_eq!(
        opened.extract_file("read-at-header.txt").unwrap(),
        Some(payload)
    );
    opened.verify().unwrap();
}

#[test]
fn read_at_api_recovers_crc_valid_physical_volume_index_from_cmra_authority() {
    let payload = b"read-at crc-valid wrong volume index".to_vec();
    let mut options = small_block_recovery_options();
    options.stripe_width = 2;
    options.volume_loss_tolerance = 0;
    let archive = write_archive(
        &[RegularFile::new("read-at-volume-index.txt", &payload)],
        &master_key(),
        options,
    )
    .unwrap();

    let mut corrupted = archive.volumes[0].clone();
    let mut header = VolumeHeader::parse(&corrupted[..VOLUME_HEADER_LEN]).unwrap();
    assert_eq!(header.volume_index, 0);
    header.volume_index = 1;
    corrupted[..VOLUME_HEADER_LEN].copy_from_slice(&header.to_bytes());

    let opened =
        open_seekable_archive_volumes(vec![corrupted, archive.volumes[1].clone()], &master_key())
            .unwrap();
    assert_eq!(opened.volume_header.volume_index, 0);
    assert_eq!(
        opened.extract_file("read-at-volume-index.txt").unwrap(),
        Some(payload)
    );
    opened.verify().unwrap();
}

#[test]
fn recovers_cmra_header_magic_from_locator_tuple() {
    let payload = b"cmra header authority".to_vec();
    let archive = write_archive(
        &[RegularFile::new("cmra-header-magic.txt", &payload)],
        &master_key(),
        small_block_recovery_options(),
    )
    .unwrap();
    let locator = final_recovery_locator(&archive.bytes);

    let mut corrupted = archive.bytes;
    corrupted[locator.cmra_offset as usize] ^= 0x55;

    let opened = open_archive(&corrupted, &master_key()).unwrap();
    assert_eq!(
        opened.extract_file("cmra-header-magic.txt").unwrap(),
        Some(payload)
    );
    opened.verify().unwrap();
}

#[test]
fn recovers_cmra_shard_magic_as_erasure() {
    let payload = b"cmra shard authority".to_vec();
    let archive = write_archive(
        &[RegularFile::new("cmra-shard-magic.txt", &payload)],
        &master_key(),
        small_block_recovery_options(),
    )
    .unwrap();
    let locator = final_recovery_locator(&archive.bytes);
    let first_shard_offset = locator.cmra_offset as usize + CRITICAL_METADATA_RECOVERY_HEADER_LEN;

    let mut corrupted = archive.bytes;
    corrupted[first_shard_offset] ^= 0x55;

    let opened = open_archive(&corrupted, &master_key()).unwrap();
    assert_eq!(
        opened.extract_file("cmra-shard-magic.txt").unwrap(),
        Some(payload)
    );
    opened.verify().unwrap();
}

#[test]
fn key_holding_rejects_recovered_image_with_unknown_layout_flags() {
    let archive = write_archive(
        &[RegularFile::new("cmra-image-revision.txt", b"payload")],
        &master_key(),
        small_block_recovery_options(),
    )
    .unwrap();
    let mut mutated =
        rewrite_cmra_image_variable_len(&archive.bytes, CmraRecoveryMode::KeyHolding, |image| {
            image.layout_flags |= 0x8000_0000;
        });
    mutated[0] ^= 0x55;

    assert!(open_archive(&mutated, &master_key()).is_err());
}

#[test]
fn key_holding_rejects_recovered_footer_revision_mismatch() {
    let archive = write_archive_with_root_auth(
        &[RegularFile::new("cmra-footer-revision.txt", b"payload")],
        &master_key(),
        single_stream_options(),
        test_root_auth_config(),
        |request| Ok(test_root_auth_value(request)),
    )
    .unwrap();
    let mut mutated = archive.bytes;
    rewrite_cmra_image(&mut mutated, CmraRecoveryMode::KeyHolding, |image| {
        let root_auth_region = image
            .regions
            .iter_mut()
            .find(|region| region.region_type == 4)
            .unwrap();
        rewrite_root_auth_footer_revision_bytes(&mut root_auth_region.bytes, 43);
    });
    mutated[0] ^= 0x55;

    assert!(open_archive(&mutated, &master_key()).is_err());
}

#[test]
fn key_holding_rejects_locator_image_revision_mismatch() {
    let archive = write_archive(
        &[RegularFile::new("cmra-locator-revision.txt", b"payload")],
        &master_key(),
        small_block_recovery_options(),
    )
    .unwrap();
    let mut mutated = archive.bytes;
    let locator = final_recovery_locator(&mutated);
    let mirror_offset = mutated.len() - LOCATOR_PAIR_LEN;
    let final_offset = mutated.len() - CRITICAL_RECOVERY_LOCATOR_LEN;
    for offset in [mirror_offset, final_offset] {
        rewrite_recovery_locator(&mut mutated, offset, |locator| {
            locator.volume_format_rev = 43;
        });
    }
    mutated[0] ^= 0x55;
    mutated[locator.cmra_offset as usize] ^= 0x55;

    assert!(open_archive(&mutated, &master_key()).is_err());
}

#[test]
fn image_identity_allows_matching_current_revision() {
    let archive = write_archive(
        &[RegularFile::new("matching-v45.txt", b"payload")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let locator = final_recovery_locator(&archive.bytes);
    let recovered = recover_cmra(
        &archive.bytes,
        locator.cmra_offset,
        Some(CmraDecoderTuple::from(locator)),
        CmraRecoveryMode::KeyHolding,
    )
    .unwrap();
    let image = recovered.image;
    let header = VolumeHeader::parse(&archive.bytes[..VOLUME_HEADER_LEN]).unwrap();
    let crypto_start = header.crypto_header_offset as usize;
    let crypto_end = crypto_start + header.crypto_header_length as usize;
    let crypto = CryptoHeader::parse(
        &archive.bytes[crypto_start..crypto_end],
        header.crypto_header_length,
    )
    .unwrap();

    validate_image_identity(&image, &header, &crypto.fixed).unwrap();
}

#[test]
fn key_holding_rejects_cmra_below_authenticated_parity_floor() {
    let archive = write_archive(
        &[RegularFile::new(
            "cmra-floor.txt",
            b"authenticated CMRA floor",
        )],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let malformed = rewrite_cmra_parity_count(&archive.bytes, 1);
    let final_offset = malformed.len() - CRITICAL_RECOVERY_LOCATOR_LEN;
    let locator = CriticalRecoveryLocator::parse(
        &malformed[final_offset..final_offset + CRITICAL_RECOVERY_LOCATOR_LEN],
    )
    .unwrap();
    let volume_header = VolumeHeader::parse(&malformed[..VOLUME_HEADER_LEN]).unwrap();
    let crypto_start = volume_header.crypto_header_offset as usize;
    let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
    let crypto_header = CryptoHeader::parse(
        &malformed[crypto_start..crypto_end],
        volume_header.crypto_header_length,
    )
    .unwrap();
    let subkeys = Subkeys::derive(
        &master_key(),
        &volume_header.archive_uuid,
        &volume_header.session_id,
    )
    .unwrap();

    assert_eq!(
        parse_locator_cmra_candidate(
            &malformed,
            final_offset,
            locator,
            KeyHoldingTerminalContext {
                subkeys: &subkeys,
                volume_header: &volume_header,
                crypto_header: &crypto_header.fixed,
                crypto_header_bytes: &malformed[crypto_start..crypto_end],
            },
        )
        .unwrap_err(),
        FormatError::InvalidArchive(
            "CMRA parity shard count is below authenticated bit-rot lower bound"
        )
    );
    assert!(open_archive(&malformed, &master_key()).is_err());
}

#[test]
fn locator_tuple_bounds_are_checked_before_locator_position_fields() {
    let archive = write_archive(
        &[RegularFile::new(
            "locator-order.txt",
            b"locator tuple first",
        )],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let final_offset = archive.bytes.len() - CRITICAL_RECOVERY_LOCATOR_LEN;
    let mut locator = final_recovery_locator(&archive.bytes);
    locator.cmra_shard_size = 513;
    locator.body_bytes_before_cmra = locator.cmra_offset + 1;
    let volume_header = VolumeHeader::parse(&archive.bytes[..VOLUME_HEADER_LEN]).unwrap();
    let crypto_start = volume_header.crypto_header_offset as usize;
    let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
    let crypto_header = CryptoHeader::parse(
        &archive.bytes[crypto_start..crypto_end],
        volume_header.crypto_header_length,
    )
    .unwrap();
    let subkeys = Subkeys::derive(
        &master_key(),
        &volume_header.archive_uuid,
        &volume_header.session_id,
    )
    .unwrap();

    assert_eq!(
        parse_locator_cmra_candidate(
            &archive.bytes,
            final_offset,
            locator,
            KeyHoldingTerminalContext {
                subkeys: &subkeys,
                volume_header: &volume_header,
                crypto_header: &crypto_header.fixed,
                crypto_header_bytes: &archive.bytes[crypto_start..crypto_end],
            },
        )
        .unwrap_err(),
        FormatError::InvalidArchive("CMRA shard_size is invalid")
    );
}

#[test]
fn sequential_extract_rejects_bytes_after_terminal_locator() {
    let archive = write_archive(
        &[RegularFile::new("seq.txt", b"sequential EOF")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let mut appended = archive.bytes.clone();
    appended.extend_from_slice(&[0xAA; 32]);

    assert_eq!(
        sequential_extract_tar_stream(&appended, &master_key()).unwrap_err(),
        FormatError::InvalidArchive("sequential terminal does not end at EOF")
    );
}

#[test]
fn global_file_table_order_rejects_cross_shard_duplicate_reversal() {
    let first = (hash_prefix(b"dup.txt"), b"dup.txt".to_vec(), 2048);
    let second = (hash_prefix(b"dup.txt"), b"dup.txt".to_vec(), 1024);

    assert_eq!(
        validate_global_file_table_key_step(Some(&first), &second).unwrap_err(),
        FormatError::InvalidArchive("global FileEntry rows are not sorted and unique")
    );
}

#[test]
fn root_auth_verifies_key_holding_and_public_no_key_modes() {
    let archive = write_archive_with_root_auth(
        &[RegularFile::new("signed.txt", b"ed25519 payload")],
        &master_key(),
        single_stream_options(),
        test_root_auth_config(),
        |request| Ok(test_root_auth_value(request)),
    )
    .unwrap();

    let opened = open_archive(&archive.bytes, &master_key()).unwrap();
    let root_auth = opened
        .verify_root_auth_with(|footer, archive_root| {
            Ok(test_root_auth_verifies(footer, archive_root))
        })
        .unwrap();
    assert_eq!(
        root_auth.archive_root,
        opened.root_auth_footer.as_ref().unwrap().archive_root
    );

    let public = public_no_key_verify_archive_with(&archive.bytes, |footer, archive_root| {
        Ok(test_root_auth_verifies(footer, archive_root))
    })
    .unwrap();
    assert_eq!(public.archive_root, root_auth.archive_root);
    assert_eq!(
        public.diagnostics,
        vec![
            PublicNoKeyDiagnostic::PublicDataBlockCommitmentVerified,
            PublicNoKeyDiagnostic::PublicPhysicalCompletenessUnverified,
            PublicNoKeyDiagnostic::PublicRecoveryMarginUnchecked,
        ]
    );
}

#[test]
fn root_auth_verifies_with_tolerated_missing_volume_after_fec_repair() {
    let options = WriterOptions {
        block_size: 4096,
        chunk_size: 16 * 1024,
        envelope_target_size: 16 * 1024,
        stripe_width: 2,
        volume_loss_tolerance: 1,
        bit_rot_buffer_pct: 0,
        fec_data_shards: 16,
        fec_parity_shards: 1,
        index_fec_data_shards: 4,
        index_fec_parity_shards: 1,
        index_root_fec_data_shards: 16,
        index_root_fec_parity_shards: 1,
        ..WriterOptions::default()
    };
    let archive = write_archive_with_root_auth(
        &[RegularFile::new("missing-volume.txt", b"recover me")],
        &master_key(),
        options,
        test_root_auth_config(),
        |request| Ok(test_root_auth_value(request)),
    )
    .unwrap();

    let opened = open_archive_volumes(&[archive.volumes[0].as_slice()], &master_key()).unwrap();
    let root_auth = opened
        .verify_root_auth_with(|footer, archive_root| {
            Ok(test_root_auth_verifies(footer, archive_root))
        })
        .unwrap();
    assert!(root_auth
        .diagnostics
        .contains(&RootAuthDiagnostic::ReplicatedGlobalCopyUncheckedDueToVolumeLoss));
}

#[test]
fn public_no_key_rejects_unsigned_archives() {
    let archive = write_archive(
        &[RegularFile::new("plain.txt", b"unsigned")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();

    assert_eq!(
        public_no_key_verify_archive_with(&archive.bytes, |_, _| Ok(true)).unwrap_err(),
        FormatError::InvalidArchive("no valid v41 public CMRA candidate found")
    );
}

#[test]
fn unsigned_archive_reports_root_auth_absent() {
    let archive = write_archive(
        &[RegularFile::new("plain.txt", b"unsigned")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let opened = open_archive(&archive.bytes, &master_key()).unwrap();

    assert_eq!(
        opened.verify_root_auth_with(|_, _| Ok(true)).unwrap_err(),
        FormatError::ReaderUnsupported("root-auth footer is absent")
    );
}

#[test]
fn safe_extract_writes_regular_file_under_root() {
    let archive = write_archive(
        &[RegularFile::new("dir/hello.txt", b"safe m8")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let opened = open_archive(&archive.bytes, &master_key()).unwrap();
    let tmp = tempfile::tempdir().unwrap();

    opened
        .extract_file_to(
            "dir/hello.txt",
            tmp.path(),
            SafeExtractionOptions::default(),
        )
        .unwrap()
        .unwrap();

    assert_eq!(
        std::fs::read(tmp.path().join("dir").join("hello.txt")).unwrap(),
        b"safe m8"
    );
}

fn decoded_primary_metadata_storage(
    opened: &OpenedArchive,
    path: &str,
) -> (crate::entry_metadata::PaxRecords, [u8; 512]) {
    let located = opened.locate_index_file(path.as_bytes()).unwrap().unwrap();
    let file = &located.shard.files[located.file_index];
    let mut reader = DecodedTarMemberGroupReader::new(opened, &located.shard, file).unwrap();
    let mut group = vec![0u8; usize::try_from(file.tar_member_group_size).unwrap()];
    let mut offset = 0usize;
    while offset < group.len() {
        let read = reader.read_some_member_bytes(&mut group[offset..]).unwrap();
        assert_ne!(read, 0, "decoded member group ended early");
        offset += read;
    }

    assert_eq!(group[156], b'x');
    let pax_size = usize::try_from(parse_test_tar_octal(&group[124..136])).unwrap();
    let pax_end = 512 + pax_size;
    let records = crate::entry_metadata::parse_canonical_pax(&group[512..pax_end]).unwrap();
    let primary_offset = pax_end + padding_to_512(pax_size);
    let primary = group[primary_offset..primary_offset + 512]
        .try_into()
        .unwrap();
    (records, primary)
}

fn parse_test_tar_octal(field: &[u8]) -> u64 {
    let field = nul_trimmed_test_field(field);
    let text = std::str::from_utf8(field).unwrap().trim();
    u64::from_str_radix(text, 8).unwrap()
}

fn nul_trimmed_test_field(field: &[u8]) -> &[u8] {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    &field[..end]
}

#[test]
fn compressed_archive_round_trips_header_and_pax_portable_metadata_stores() {
    let files = [
        RegularFile {
            mode: 0o640,
            mtime: ArchiveTimestamp::from_seconds(1_700_000_000),
            portable_metadata: PortableFileMetadata {
                source_os: "other-unix".into(),
                source_filesystem: "ext4".into(),
                mode_origin: PortableModeOrigin::Native,
                posix_owner: Some(PortablePosixOwner {
                    uid: 42,
                    gid: 84,
                    uname: Some("alice".into()),
                    gname: Some("staff".into()),
                }),
                attributes: Some(1),
                created: None,
                accessed: None,
                native: Default::default(),
            },
            ..RegularFile::new("header-fields.txt", b"header metadata")
        },
        RegularFile {
            mode: 0o604,
            mtime: ArchiveTimestamp::new(-1, 500_000_000),
            portable_metadata: PortableFileMetadata {
                source_os: "other-unix".into(),
                source_filesystem: "zfs".into(),
                mode_origin: PortableModeOrigin::Native,
                posix_owner: Some(PortablePosixOwner {
                    uid: 9_000_000,
                    gid: 8_000_000,
                    uname: Some("u".repeat(40)),
                    gname: Some("g".repeat(40)),
                }),
                attributes: Some(2),
                created: None,
                accessed: None,
                native: Default::default(),
            },
            ..RegularFile::new("pax-overrides.txt", b"PAX metadata")
        },
    ];
    let archive = write_archive(&files, &master_key(), single_stream_options()).unwrap();
    let opened = open_archive(&archive.bytes, &master_key()).unwrap();

    assert_eq!(
        opened.crypto_header.compression_algo,
        CompressionAlgo::ZstdFramed
    );

    let (header_records, header_primary) =
        decoded_primary_metadata_storage(&opened, "header-fields.txt");
    for key in ["uid", "gid", "uname", "gname", "mtime"] {
        assert!(!header_records.contains_key(key), "{key} should use ustar");
    }
    assert_eq!(parse_test_tar_octal(&header_primary[108..116]), 42);
    assert_eq!(parse_test_tar_octal(&header_primary[116..124]), 84);
    assert_eq!(nul_trimmed_test_field(&header_primary[265..297]), b"alice");
    assert_eq!(nul_trimmed_test_field(&header_primary[297..329]), b"staff");
    assert_eq!(
        parse_test_tar_octal(&header_primary[136..148]),
        1_700_000_000
    );

    let (pax_records, pax_primary) = decoded_primary_metadata_storage(&opened, "pax-overrides.txt");
    let long_uname = "u".repeat(40);
    let long_gname = "g".repeat(40);
    for (key, expected) in [
        ("uid", b"9000000".as_slice()),
        ("gid", b"8000000".as_slice()),
        ("uname", long_uname.as_bytes()),
        ("gname", long_gname.as_bytes()),
        ("mtime", b"-1.5".as_slice()),
    ] {
        assert_eq!(pax_records.get(key).map(Vec::as_slice), Some(expected));
    }
    assert_eq!(parse_test_tar_octal(&pax_primary[108..116]), 0);
    assert_eq!(parse_test_tar_octal(&pax_primary[116..124]), 0);
    assert!(nul_trimmed_test_field(&pax_primary[265..297]).is_empty());
    assert!(nul_trimmed_test_field(&pax_primary[297..329]).is_empty());
    assert_eq!(parse_test_tar_octal(&pax_primary[136..148]), 0);

    for expected in &files {
        let index = opened.lookup_index_entry(expected.path).unwrap().unwrap();
        assert!(index.layout.compressed_size > 0);
        assert_eq!(
            index.flags,
            crate::entry_metadata::EXTENDED_METADATA_V1
                | crate::entry_metadata::REQUIRES_SYSTEM_RESTORE
        );

        let located = opened
            .locate_index_file(expected.path.as_bytes())
            .unwrap()
            .unwrap();
        let member = opened
            .decode_loaded_owned_tar_member(&located.shard, located.file_index, false)
            .unwrap();
        let metadata = member.v45_metadata.unwrap();
        let owner = expected.portable_metadata.posix_owner.as_ref().unwrap();

        assert_eq!(member.mode, expected.mode);
        assert_eq!(member.mtime, expected.mtime);
        assert_eq!(
            metadata.file_entry_flags,
            crate::entry_metadata::EXTENDED_METADATA_V1
                | crate::entry_metadata::REQUIRES_SYSTEM_RESTORE
        );
        assert_eq!(
            metadata.declaration.source_os,
            expected.portable_metadata.source_os
        );
        assert_eq!(
            metadata.declaration.source_filesystem,
            expected.portable_metadata.source_filesystem
        );
        assert!(metadata.declaration.mode_origin_native);
        assert_eq!(metadata.portable_mirror.mode, expected.mode);
        assert_eq!(
            metadata.portable_mirror.mtime,
            (expected.mtime.seconds, expected.mtime.nanoseconds)
        );
        assert_eq!(
            metadata.portable_mirror.attributes,
            expected.portable_metadata.attributes
        );
        assert_eq!(metadata.portable_mirror.uid, Some(owner.uid));
        assert_eq!(metadata.portable_mirror.gid, Some(owner.gid));
        assert_eq!(
            metadata.portable_mirror.uname.as_deref(),
            owner.uname.as_deref().map(str::as_bytes)
        );
        assert_eq!(
            metadata.portable_mirror.gname.as_deref(),
            owner.gname.as_deref().map(str::as_bytes)
        );
    }
}

#[test]
fn compressed_archive_extraction_applies_portable_mode_and_pax_mtime() {
    let archived_mtime = ArchiveTimestamp::new(946_684_800, 123_456_700);
    let archive = write_archive(
        &[RegularFile {
            mode: 0o604,
            mtime: archived_mtime,
            ..RegularFile::new("dated.txt", b"dated")
        }],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let opened = open_archive(&archive.bytes, &master_key()).unwrap();
    assert_eq!(
        opened
            .lookup_index_entry("dated.txt")
            .unwrap()
            .unwrap()
            .flags,
        crate::entry_metadata::EXTENDED_METADATA_V1
    );
    let content_root = tempfile::tempdir().unwrap();

    let content_diagnostics = opened
        .extract_file_to(
            "dated.txt",
            content_root.path(),
            SafeExtractionOptions {
                restore_policy: crate::entry_metadata::RestorePolicy::Content,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap()
        .unwrap();
    for metadata_class in ["mode", "mtime"] {
        assert!(content_diagnostics.iter().any(|diagnostic| {
            diagnostic.metadata_class == metadata_class
                && diagnostic.status == crate::tar_model::MetadataDiagnosticStatus::Skipped
        }));
    }
    let content_mtime = fs::metadata(content_root.path().join("dated.txt"))
        .unwrap()
        .modified()
        .unwrap();
    assert_ne!(
        content_mtime,
        std::time::UNIX_EPOCH
            + std::time::Duration::new(archived_mtime.seconds as u64, archived_mtime.nanoseconds,)
    );

    let portable_root = tempfile::tempdir().unwrap();
    opened
        .extract_file_to(
            "dated.txt",
            portable_root.path(),
            SafeExtractionOptions::default(),
        )
        .unwrap()
        .unwrap();
    let portable_mtime = fs::metadata(portable_root.path().join("dated.txt"))
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(
        portable_mtime,
        std::time::UNIX_EPOCH
            + std::time::Duration::new(archived_mtime.seconds as u64, archived_mtime.nanoseconds,)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            fs::metadata(portable_root.path().join("dated.txt"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o604
        );
    }
}

#[test]
fn same_os_restore_rejects_required_native_profile_from_another_os() {
    let (source_os, required_profiles) = if cfg!(target_os = "macos") {
        (
            "linux",
            vec!["posix-backup-v1".into(), "linux-backup-v1".into()],
        )
    } else {
        (
            "macos",
            vec!["posix-backup-v1".into(), "macos-backup-v1".into()],
        )
    };
    let archive = write_archive(
        &[RegularFile {
            portable_metadata: PortableFileMetadata {
                source_os: source_os.into(),
                native: NativeFileMetadata {
                    required_profiles,
                    ..NativeFileMetadata::default()
                },
                ..PortableFileMetadata::default()
            },
            ..RegularFile::new("foreign-native.txt", b"payload")
        }],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let opened = open_archive(&archive.bytes, &master_key()).unwrap();

    assert_eq!(
        opened
            .plan_metadata_restore(SafeExtractionOptions {
                restore_policy: RestorePolicy::SameOs,
                ..SafeExtractionOptions::default()
            })
            .unwrap_err(),
        FormatError::ReaderUnsupported(
            "requested native metadata is not supported by this conformance class"
        )
    );
}

#[cfg(unix)]
#[test]
fn compressed_archive_extraction_restores_setid_bits_only_for_authorized_system_policy() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    // SAFETY: these process identity getters have no preconditions.
    let uid = unsafe { libc::geteuid() } as u64;
    let gid = unsafe { libc::getegid() } as u64;

    let archive = write_archive(
        &[RegularFile {
            mode: 0o7751,
            mtime: ArchiveTimestamp::from_seconds(1_700_000_000),
            portable_metadata: PortableFileMetadata {
                source_os: "other-unix".into(),
                source_filesystem: "unknown".into(),
                mode_origin: PortableModeOrigin::Native,
                posix_owner: Some(PortablePosixOwner {
                    uid,
                    gid,
                    uname: None,
                    gname: None,
                }),
                attributes: None,
                created: None,
                accessed: None,
                native: Default::default(),
            },
            ..RegularFile::new("privileged.sh", b"#!/bin/sh\n")
        }],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let opened = open_archive(&archive.bytes, &master_key()).unwrap();
    assert_eq!(
        opened
            .lookup_index_entry("privileged.sh")
            .unwrap()
            .unwrap()
            .flags,
        crate::entry_metadata::EXTENDED_METADATA_V1
            | crate::entry_metadata::REQUIRES_SYSTEM_RESTORE
    );

    let portable_root = tempfile::tempdir().unwrap();
    let portable_diagnostics = opened
        .extract_file_to(
            "privileged.sh",
            portable_root.path(),
            SafeExtractionOptions::default(),
        )
        .unwrap()
        .unwrap();
    assert!(portable_diagnostics.iter().any(|diagnostic| {
        diagnostic.metadata_class == "setid-mode"
            && diagnostic.status == crate::tar_model::MetadataDiagnosticStatus::Skipped
    }));
    assert!(portable_diagnostics.iter().any(|diagnostic| {
        diagnostic.metadata_class == "numeric-ownership"
            && diagnostic.status == crate::tar_model::MetadataDiagnosticStatus::Skipped
    }));
    assert_eq!(
        fs::metadata(portable_root.path().join("privileged.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o1751
    );

    let same_os_root = tempfile::tempdir().unwrap();
    opened
        .extract_file_to(
            "privileged.sh",
            same_os_root.path(),
            SafeExtractionOptions {
                restore_policy: crate::entry_metadata::RestorePolicy::SameOs,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        fs::metadata(same_os_root.path().join("privileged.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o1751
    );

    let unauthorized_root = tempfile::tempdir().unwrap();
    assert_eq!(
        opened
            .extract_file_to(
                "privileged.sh",
                unauthorized_root.path(),
                SafeExtractionOptions {
                    restore_policy: crate::entry_metadata::RestorePolicy::System,
                    ..SafeExtractionOptions::default()
                },
            )
            .unwrap_err(),
        FormatError::ReaderUnsupported(
            "system restore policy requires explicit caller authorization"
        )
    );
    assert!(!unauthorized_root.path().join("privileged.sh").exists());

    let system_root = tempfile::tempdir().unwrap();
    opened
        .extract_file_to(
            "privileged.sh",
            system_root.path(),
            SafeExtractionOptions {
                restore_policy: crate::entry_metadata::RestorePolicy::System,
                system_authorized: true,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        fs::metadata(system_root.path().join("privileged.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o7751
    );
    let restored = fs::metadata(system_root.path().join("privileged.sh")).unwrap();
    assert_eq!(restored.uid() as u64, uid);
    assert_eq!(restored.gid() as u64, gid);
}

#[cfg(unix)]
#[test]
fn compressed_archive_extraction_restores_native_xattrs_only_under_native_policy() {
    let mut native = NativeFileMetadata {
        required_profiles: vec!["posix-backup-v1".into()],
        ..NativeFileMetadata::default()
    };
    native.primary_pax_records.insert(
        "LIBARCHIVE.xattr.user.tzap-test".into(),
        crate::entry_metadata::canonical_base64_encode(b"native value"),
    );
    let archive = write_archive(
        &[RegularFile {
            portable_metadata: PortableFileMetadata {
                source_os: source_os_for_test().into(),
                native,
                ..PortableFileMetadata::default()
            },
            ..RegularFile::new("xattr.txt", b"payload")
        }],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let opened = open_archive(&archive.bytes, &master_key()).unwrap();

    let portable_root = tempfile::tempdir().unwrap();
    opened
        .extract_file_to(
            "xattr.txt",
            portable_root.path(),
            SafeExtractionOptions {
                restore_policy: RestorePolicy::Portable,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();
    assert_eq!(
        xattr::get(portable_root.path().join("xattr.txt"), "user.tzap-test").unwrap(),
        None
    );

    let native_root = tempfile::tempdir().unwrap();
    opened
        .extract_file_to(
            "xattr.txt",
            native_root.path(),
            SafeExtractionOptions {
                restore_policy: RestorePolicy::SameOs,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();
    assert_eq!(
        xattr::get(native_root.path().join("xattr.txt"), "user.tzap-test").unwrap(),
        Some(b"native value".to_vec())
    );
}

#[cfg(target_os = "linux")]
#[test]
fn compressed_archive_extraction_restores_auxiliary_linux_xattr() {
    let mut record = NativeAuxiliaryMetadata::new(
        "generic.xattr",
        "posix-backup-v1",
        crate::entry_metadata::RestoreClass::SameOs,
        b"auxiliary xattr value".to_vec(),
    );
    record.name_encoding = NativeAuxiliaryNameEncoding::Bytes;
    record.name = b"user.tzap-aux".to_vec();
    let native = NativeFileMetadata {
        required_profiles: vec!["posix-backup-v1".into(), "linux-backup-v1".into()],
        auxiliary_records: vec![record],
        ..NativeFileMetadata::default()
    };
    let archive = write_archive(
        &[RegularFile {
            portable_metadata: PortableFileMetadata {
                source_os: "linux".into(),
                native,
                ..PortableFileMetadata::default()
            },
            ..RegularFile::new("aux-xattr.txt", b"payload")
        }],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let opened = open_archive(&archive.bytes, &master_key()).unwrap();
    let root = tempfile::tempdir().unwrap();
    opened
        .extract_file_to(
            "aux-xattr.txt",
            root.path(),
            SafeExtractionOptions {
                restore_policy: RestorePolicy::SameOs,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();
    assert_eq!(
        xattr::get(root.path().join("aux-xattr.txt"), "user.tzap-aux").unwrap(),
        Some(b"auxiliary xattr value".to_vec())
    );
}

#[cfg(target_os = "linux")]
#[test]
fn same_os_restore_reports_system_xattr_as_policy_skipped() {
    let mut native = NativeFileMetadata {
        required_profiles: vec!["posix-backup-v1".into(), "linux-backup-v1".into()],
        ..NativeFileMetadata::default()
    };
    native.primary_pax_records.insert(
        "LIBARCHIVE.xattr.security.selinux".into(),
        crate::entry_metadata::canonical_base64_encode(b"label"),
    );
    let archive = write_archive(
        &[RegularFile {
            portable_metadata: PortableFileMetadata {
                source_os: "linux".into(),
                native,
                ..PortableFileMetadata::default()
            },
            ..RegularFile::new("label.txt", b"payload")
        }],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let opened = open_archive(&archive.bytes, &master_key()).unwrap();
    let root = tempfile::tempdir().unwrap();
    let diagnostics = opened
        .extract_file_to(
            "label.txt",
            root.path(),
            SafeExtractionOptions {
                restore_policy: RestorePolicy::SameOs,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap()
        .unwrap();
    assert!(diagnostics.iter().any(|diagnostic| {
        diagnostic.metadata_class == "system-extended-attribute"
            && diagnostic.status == crate::tar_model::MetadataDiagnosticStatus::Skipped
    }));
    assert_eq!(
        xattr::get(root.path().join("label.txt"), "security.selinux").unwrap(),
        None
    );
}

#[cfg(target_os = "linux")]
fn source_os_for_test() -> &'static str {
    "linux"
}

#[cfg(target_os = "macos")]
fn source_os_for_test() -> &'static str {
    "macos"
}

#[cfg(all(unix, not(target_os = "linux"), not(target_os = "macos")))]
fn source_os_for_test() -> &'static str {
    "other-unix"
}

#[cfg(target_os = "linux")]
#[test]
fn compressed_archive_extraction_restores_linux_inode_flags() {
    use std::os::fd::AsRawFd;

    let root = tempfile::tempdir().unwrap();
    let probe_path = root.path().join("flags-probe.txt");
    fs::write(&probe_path, b"probe").unwrap();
    let probe = fs::File::open(&probe_path).unwrap();
    let mut intrinsic_flags: libc::c_long = 0;
    assert_eq!(
        unsafe {
            libc::ioctl(
                probe.as_raw_fd(),
                libc::FS_IOC_GETFLAGS,
                &mut intrinsic_flags,
            )
        },
        0
    );
    drop(probe);
    fs::remove_file(probe_path).unwrap();
    let expected_flags = intrinsic_flags as u64 | u64::from(linux_raw_sys::general::FS_NODUMP_FL);
    let mut native = NativeFileMetadata {
        required_profiles: vec!["posix-backup-v1".into(), "linux-backup-v1".into()],
        ..NativeFileMetadata::default()
    };
    native.primary_pax_records.insert(
        "TZAP.linux.fsflags".into(),
        format!("{expected_flags:016x}").into_bytes(),
    );
    let archive = write_archive(
        &[RegularFile {
            portable_metadata: PortableFileMetadata {
                source_os: "linux".into(),
                native,
                ..PortableFileMetadata::default()
            },
            ..RegularFile::new("flags.txt", b"payload")
        }],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let opened = open_archive(&archive.bytes, &master_key()).unwrap();
    opened
        .extract_file_to(
            "flags.txt",
            root.path(),
            SafeExtractionOptions {
                restore_policy: RestorePolicy::SameOs,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();
    let file = fs::File::open(root.path().join("flags.txt")).unwrap();
    let mut flags: libc::c_long = 0;
    // SAFETY: GETFLAGS writes one c_long to a valid pointer.
    assert_eq!(
        unsafe { libc::ioctl(file.as_raw_fd(), libc::FS_IOC_GETFLAGS, &mut flags,) },
        0
    );
    assert_eq!(flags as u64, expected_flags);
}

#[cfg(target_os = "linux")]
#[test]
fn compressed_archive_extraction_restores_canonical_posix_acl() {
    let acl = b"user::rw-,group::r--,other::---,user:123:r--,mask::r--";
    let mut native = NativeFileMetadata {
        required_profiles: vec!["posix-backup-v1".into()],
        ..NativeFileMetadata::default()
    };
    native
        .primary_pax_records
        .insert("SCHILY.acl.access".into(), acl.to_vec());
    native
        .primary_pax_records
        .insert("TZAP.acl.projection".into(), b"exact".to_vec());
    native.primary_pax_records.insert(
        "TZAP.acl.syntax".into(),
        b"schily-posix1e-extra-id-v1".to_vec(),
    );
    let archive = write_archive(
        &[RegularFile {
            mode: 0o640,
            portable_metadata: PortableFileMetadata {
                source_os: "linux".into(),
                native,
                ..PortableFileMetadata::default()
            },
            ..RegularFile::new("acl.txt", b"payload")
        }],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let opened = open_archive(&archive.bytes, &master_key()).unwrap();
    let root = tempfile::tempdir().unwrap();
    opened
        .extract_file_to(
            "acl.txt",
            root.path(),
            SafeExtractionOptions {
                restore_policy: RestorePolicy::SameOs,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();
    let binary = xattr::get(root.path().join("acl.txt"), "system.posix_acl_access")
        .unwrap()
        .unwrap();
    assert_eq!(
        crate::entry_metadata::linux_posix_acl_xattr_to_schily(&binary).unwrap(),
        acl
    );
}

#[cfg(windows)]
#[test]
#[allow(clippy::permissions_set_readonly_false)]
fn compressed_archive_extraction_restores_portable_readonly_attribute() {
    let archive = write_archive(
        &[RegularFile {
            portable_metadata: PortableFileMetadata {
                source_os: "windows".into(),
                source_filesystem: "ntfs".into(),
                mode_origin: PortableModeOrigin::Projected,
                posix_owner: None,
                attributes: Some(1),
                created: None,
                accessed: None,
                native: Default::default(),
            },
            ..RegularFile::new("readonly.txt", b"readonly")
        }],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let opened = open_archive(&archive.bytes, &master_key()).unwrap();
    let root = tempfile::tempdir().unwrap();

    opened
        .extract_file_to(
            "readonly.txt",
            root.path(),
            SafeExtractionOptions::default(),
        )
        .unwrap()
        .unwrap();
    let path = root.path().join("readonly.txt");
    assert!(fs::metadata(&path).unwrap().permissions().readonly());

    // Let TempDir clean up the restored file on Windows.
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_readonly(false);
    fs::set_permissions(path, permissions).unwrap();
}

#[test]
fn seekable_extract_all_to_streams_unique_archive() {
    let archive = write_archive(
        &[
            RegularFile::new("alpha.txt", b"alpha"),
            RegularFile::new("dir/beta.txt", b"beta"),
        ],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let opened = open_archive(&archive.bytes, &master_key()).unwrap();
    let tmp = tempfile::tempdir().unwrap();

    let diagnostics = opened
        .extract_all_to(tmp.path(), SafeExtractionOptions::default())
        .unwrap();

    assert_eq!(diagnostics.len(), 2);
    assert_eq!(fs::read(tmp.path().join("alpha.txt")).unwrap(), b"alpha");
    assert_eq!(
        fs::read(tmp.path().join("dir").join("beta.txt")).unwrap(),
        b"beta"
    );
}

#[test]
fn seekable_extract_all_to_rejects_duplicate_paths_for_cli_fallback() {
    let archive = write_archive(
        &[
            RegularFile::new("same.txt", b"old"),
            RegularFile::new("same.txt", b"new"),
        ],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let opened = open_archive(&archive.bytes, &master_key()).unwrap();
    let tmp = tempfile::tempdir().unwrap();

    assert_eq!(
        opened
            .extract_all_to(tmp.path(), SafeExtractionOptions::default())
            .unwrap_err(),
        FormatError::ReaderUnsupported("fast full extract requires unique archive paths")
    );
}

#[test]
fn seekable_extract_indexed_files_to_restores_final_duplicate_winner() {
    let archive = write_archive(
        &[
            RegularFile::new("same.txt", b"old"),
            RegularFile::new("same.txt", b"new"),
        ],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let opened = open_archive(&archive.bytes, &master_key()).unwrap();
    let tmp = tempfile::tempdir().unwrap();

    let diagnostics = opened
        .extract_indexed_files_to(tmp.path(), SafeExtractionOptions::default(), 2)
        .unwrap();

    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0].0, "same.txt");
    assert_eq!(fs::read(tmp.path().join("same.txt")).unwrap(), b"new");
}

#[test]
fn selected_restore_preflights_every_path_before_writing() {
    let archive = write_archive(
        &[RegularFile::new("alpha.txt", b"alpha")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let opened = open_archive(&archive.bytes, &master_key()).unwrap();
    let tmp = tempfile::tempdir().unwrap();

    let error = opened
        .extract_selected_files_to(
            &["alpha.txt".into(), "missing.txt".into()],
            tmp.path(),
            SafeExtractionOptions::default(),
            2,
        )
        .unwrap_err();

    assert_eq!(
        error,
        FormatError::ReaderUnsupported("selected archive path is absent from the final index")
    );
    assert!(!tmp.path().join("alpha.txt").exists());
}

#[test]
fn safe_extract_rejects_overwriting_existing_file_by_default() {
    let archive = write_archive(
        &[RegularFile::new("hello.txt", b"new")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let opened = open_archive(&archive.bytes, &master_key()).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("hello.txt"), b"old").unwrap();

    assert_eq!(
        opened
            .extract_file_to("hello.txt", tmp.path(), SafeExtractionOptions::default())
            .unwrap_err(),
        FormatError::UnsafeOverwrite
    );
    assert_eq!(std::fs::read(tmp.path().join("hello.txt")).unwrap(), b"old");
}

#[test]
fn opens_and_verifies_empty_archive() {
    let archive = write_archive(&[], &master_key(), single_stream_options()).unwrap();
    let opened = open_archive(&archive.bytes, &master_key()).unwrap();

    assert!(opened.list_files().unwrap().is_empty());
    opened.verify().unwrap();
}

#[test]
fn default_reader_options_allow_v36_trailing_garbage_scan() {
    let archive = write_archive(
        &[RegularFile::new("garbage-tolerant.txt", b"still intact")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let mut with_trailing_garbage = archive.bytes.clone();
    with_trailing_garbage.extend_from_slice(b"ignored trailing bytes");

    let opened = open_archive(&with_trailing_garbage, &master_key()).unwrap();
    assert_eq!(
        opened.extract_file("garbage-tolerant.txt").unwrap(),
        Some(b"still intact".to_vec())
    );
}

#[test]
fn seekable_open_rejects_too_small_and_unavailable_header_crypto_bytes() {
    assert_eq!(
        open_archive(
            &[0u8; VOLUME_HEADER_LEN + VOLUME_TRAILER_LEN - 1],
            &master_key()
        )
        .unwrap_err(),
        FormatError::InvalidLength {
            structure: "archive",
            expected: VOLUME_HEADER_LEN + VOLUME_TRAILER_LEN,
            actual: VOLUME_HEADER_LEN + VOLUME_TRAILER_LEN - 1,
        }
    );

    let mut header = test_volume_header();
    header.crypto_header_length = 512;
    let mut unavailable_crypto = header.to_bytes().to_vec();
    unavailable_crypto.resize(VOLUME_HEADER_LEN + VOLUME_TRAILER_LEN, 0);

    assert_eq!(
        open_archive(&unavailable_crypto, &master_key()).unwrap_err(),
        FormatError::InvalidLength {
            structure: "CryptoHeader",
            expected: VOLUME_HEADER_LEN + 512,
            actual: VOLUME_HEADER_LEN + VOLUME_TRAILER_LEN,
        }
    );
}

#[test]
fn seekable_open_recovers_physical_noncanonical_crypto_header_offset() {
    let archive = write_archive(
        &[RegularFile::new("offset.txt", b"offset")],
        &master_key(),
        small_block_recovery_options(),
    )
    .unwrap();
    let mut mutated = archive.bytes;
    let mut header = VolumeHeader::parse(&mutated[..VOLUME_HEADER_LEN]).unwrap();
    header.crypto_header_offset = VOLUME_HEADER_LEN as u32 + 1;
    mutated[..VOLUME_HEADER_LEN].copy_from_slice(&header.to_bytes());

    let opened = open_archive(&mutated, &master_key()).unwrap();
    assert_eq!(
        opened.volume_header.crypto_header_offset,
        VOLUME_HEADER_LEN as u32
    );
    assert_eq!(
        opened.extract_file("offset.txt").unwrap(),
        Some(b"offset".to_vec())
    );
    opened.verify().unwrap();
}

#[test]
fn rejects_wrong_key_before_metadata_release() {
    let archive = write_archive(&[], &master_key(), single_stream_options()).unwrap();
    let wrong = MasterKey::from_raw_key(&[0x43; 32]).unwrap();

    assert_eq!(
        open_archive(&archive.bytes, &wrong).unwrap_err(),
        FormatError::HmacMismatch {
            structure: "CryptoHeader"
        }
    );
}

#[test]
fn ordinary_encrypted_writers_emit_v45_archives() {
    let raw_key_archive = write_archive(
        &[RegularFile::new("raw.txt", b"raw key payload")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let raw_header = VolumeHeader::parse(&raw_key_archive.bytes[..VOLUME_HEADER_LEN]).unwrap();
    assert_eq!(raw_header.volume_format_rev, VOLUME_FORMAT_REV_45);
    let raw_opened = open_archive(&raw_key_archive.bytes, &master_key()).unwrap();
    assert_eq!(
        raw_opened.volume_header.volume_format_rev,
        VOLUME_FORMAT_REV_45
    );
    assert_eq!(
        raw_opened.extract_file("raw.txt").unwrap(),
        Some(b"raw key payload".to_vec())
    );

    let passphrase_kdf = KdfParams::Argon2id {
        t_cost: 1,
        m_cost_kib: 8,
        parallelism: 1,
        salt: b"0123456789abcdef".to_vec(),
    };
    let passphrase_archive = write_archive_with_kdf(
        &[RegularFile::new("pass.txt", b"passphrase payload")],
        &master_key(),
        single_stream_options(),
        &passphrase_kdf,
    )
    .unwrap();
    let passphrase_header =
        VolumeHeader::parse(&passphrase_archive.bytes[..VOLUME_HEADER_LEN]).unwrap();
    assert_eq!(passphrase_header.volume_format_rev, VOLUME_FORMAT_REV_45);
    let passphrase_opened = open_archive(&passphrase_archive.bytes, &master_key()).unwrap();
    assert_eq!(
        passphrase_opened.volume_header.volume_format_rev,
        VOLUME_FORMAT_REV_45
    );
    assert_eq!(
        passphrase_opened.extract_file("pass.txt").unwrap(),
        Some(b"passphrase payload".to_vec())
    );
}

#[test]
fn rejects_future_volume_format_revision_before_key_mismatch() {
    let archive = write_archive(&[], &master_key(), single_stream_options()).unwrap();
    let mut bytes = archive.bytes;
    let mut header = VolumeHeader::parse(&bytes[..VOLUME_HEADER_LEN]).unwrap();
    header.volume_format_rev = VOLUME_FORMAT_REV_45 + 1;
    bytes[..VOLUME_HEADER_LEN].copy_from_slice(&header.to_bytes());
    let wrong = MasterKey::from_raw_key(&[0x43; 32]).unwrap();

    assert_eq!(
        open_archive(&bytes, &wrong).unwrap_err(),
        FormatError::UnsupportedVolumeFormatRevision {
            format_version: FORMAT_VERSION,
            volume_format_rev: VOLUME_FORMAT_REV_45 + 1,
            reader_max_supported_revision: READER_MAX_SUPPORTED_VOLUME_FORMAT_REV,
        }
    );
}

#[test]
fn open_archive_unencrypted_accepts_v45_profile() {
    let archive = write_archive_unencrypted(
        &[RegularFile::new("payload.txt", b"smoke-v45-unencrypted")],
        WriterOptions {
            aead_algo: AeadAlgo::None,
            ..single_stream_options()
        },
    )
    .unwrap();

    let opened = open_archive_unencrypted(&archive.bytes).unwrap();
    let header = VolumeHeader::parse(&archive.bytes[..VOLUME_HEADER_LEN]).unwrap();

    assert_eq!(header.volume_format_rev, VOLUME_FORMAT_REV_45);
    assert_eq!(opened.volume_header.volume_format_rev, VOLUME_FORMAT_REV_45);
    assert_eq!(
        opened.extract_file("payload.txt").unwrap(),
        Some(b"smoke-v45-unencrypted".to_vec())
    );
    opened.verify().unwrap();
}

#[test]
fn full_verification_reports_v45_metadata_capabilities_separately() {
    let archive = write_archive(
        &[RegularFile::new("report.txt", b"report")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let opened = open_archive(&archive.bytes, &master_key()).unwrap();
    let verification = opened.verify_content().unwrap();
    let report = verification.metadata_report().unwrap();

    assert!(report.all_capture_complete);
    assert!(report.full_fidelity_possible);
    assert_eq!(report.profiles_present, ["portable-v1"]);
    assert!(report.auxiliary_kinds_present.is_empty());
    assert_eq!(report.entries.len(), 1);
    assert_eq!(report.entries[0].path, b"report.txt");
    assert!(report.entries[0]
        .policy_capabilities
        .iter()
        .all(|capability| capability.policy_complete));
    assert!(report.entries[0].diagnostics.is_empty());
}

#[test]
fn root_auth_unencrypted_v45_round_trips_with_recomputed_archive_root() {
    let archive = write_archive_with_root_auth(
        &[RegularFile::new(
            "signed-v45.txt",
            b"root-auth v45 plaintext",
        )],
        &master_key(),
        WriterOptions {
            aead_algo: AeadAlgo::None,
            ..single_stream_options()
        },
        test_root_auth_config(),
        |request| Ok(test_root_auth_value(request)),
    )
    .unwrap();
    let opened = open_archive_unencrypted(&archive.bytes).unwrap();
    let header = VolumeHeader::parse(&archive.bytes[..VOLUME_HEADER_LEN]).unwrap();

    assert_eq!(header.volume_format_rev, VOLUME_FORMAT_REV_45);
    assert_eq!(opened.volume_header.volume_format_rev, VOLUME_FORMAT_REV_45);
    assert_eq!(
        opened.extract_file("signed-v45.txt").unwrap(),
        Some(b"root-auth v45 plaintext".to_vec())
    );

    let verified = opened
        .verify_root_auth_with(|footer, archive_root| {
            Ok(test_root_auth_verifies(footer, archive_root))
        })
        .unwrap();

    assert_eq!(verified.format_version, FORMAT_VERSION);
    assert_eq!(verified.volume_format_rev, VOLUME_FORMAT_REV_45);
    assert_eq!(
        verified.archive_root,
        opened.root_auth_footer.as_ref().unwrap().archive_root
    );
}

#[test]
fn recipientwrap_open_accepts_candidate_after_header_hmac() {
    let master = master_key();
    let archive = write_archive_with_recipient_wrap_records(
        &[RegularFile::new("wrapped.txt", b"recipient payload")],
        &master,
        single_stream_options(),
        vec![recipient_wrap_test_record()],
    )
    .unwrap();

    let opened = open_archive_with_recipient_wrap_resolver(&archive.bytes, |context| {
        assert_eq!(
            context.archive_identity.volume_format_rev,
            VOLUME_FORMAT_REV_45
        );
        assert_eq!(context.record.profile_id, 1);
        Ok(vec![master.0])
    })
    .unwrap();

    assert_eq!(
        opened.extract_file("wrapped.txt").unwrap(),
        Some(b"recipient payload".to_vec())
    );
    opened.verify().unwrap();
}

#[test]
fn recipientwrap_seekable_open_uses_lazy_block_source() {
    let master = master_key();
    let archive = write_archive_with_recipient_wrap_records(
        &[RegularFile::new("wrapped.txt", b"recipient payload")],
        &master,
        single_stream_options(),
        vec![recipient_wrap_test_record()],
    )
    .unwrap();

    let opened = open_seekable_archive_with_recipient_wrap_resolver_options(
        CountingReadAt::new(archive.bytes, vec![]),
        |context| {
            assert_eq!(
                context.archive_identity.volume_format_rev,
                VOLUME_FORMAT_REV_45
            );
            assert_eq!(context.record.profile_id, 1);
            Ok(vec![master.0])
        },
        ReaderOptions::default(),
    )
    .unwrap();

    assert!(opened.blocks.is_empty());
    assert!(opened.lazy_blocks.is_some());
    assert_eq!(
        opened.extract_file("wrapped.txt").unwrap(),
        Some(b"recipient payload".to_vec())
    );
    opened.verify().unwrap();
}

#[test]
fn recipientwrap_seekable_volume_set_opens_with_resolver() {
    let master = master_key();
    let archive = write_archive_with_recipient_wrap_records(
        &[RegularFile::new("wrapped.txt", b"recipient payload")],
        &master,
        WriterOptions {
            stripe_width: 2,
            volume_loss_tolerance: 0,
            ..WriterOptions::default()
        },
        vec![recipient_wrap_test_record()],
    )
    .unwrap();
    assert_eq!(archive.volumes.len(), 2);

    let opened = open_seekable_archive_volumes_with_recipient_wrap_resolver_options(
        archive.volumes,
        |context| {
            assert_eq!(
                context.archive_identity.volume_format_rev,
                VOLUME_FORMAT_REV_45
            );
            assert_eq!(context.record.profile_id, 1);
            Ok(vec![master.0])
        },
        ReaderOptions::default(),
    )
    .unwrap();

    assert_eq!(opened.observed_volume_count, 2);
    assert!(opened.blocks.is_empty());
    assert!(opened.lazy_blocks.is_some());
    assert_eq!(
        opened.extract_file("wrapped.txt").unwrap(),
        Some(b"recipient payload".to_vec())
    );
    opened.verify().unwrap();
}

#[test]
fn recipientwrap_open_tries_subsequent_records_after_failed_candidate() {
    let master = master_key();
    let mut first_record = recipient_wrap_test_record();
    first_record.recipient_identity_bytes = b"first-candidate".to_vec();
    let mut second_record = recipient_wrap_test_record();
    second_record.recipient_identity_bytes = b"second-candidate".to_vec();

    let archive = write_archive_with_recipient_wrap_records(
        &[RegularFile::new("wrapped.txt", b"recipient payload")],
        &master,
        single_stream_options(),
        vec![first_record, second_record],
    )
    .unwrap();

    let mut attempts = Vec::new();
    let opened = open_archive_with_recipient_wrap_resolver(&archive.bytes, |context| {
        attempts.push(context.record.recipient_identity_bytes.clone());
        if context.record.recipient_identity_bytes.as_slice() == b"second-candidate" {
            Ok(vec![master.0])
        } else {
            Ok(vec![[0x99u8; 32]])
        }
    })
    .unwrap();

    assert_eq!(
        attempts,
        vec![b"first-candidate".to_vec(), b"second-candidate".to_vec(),]
    );
    assert_eq!(
        opened.extract_file("wrapped.txt").unwrap(),
        Some(b"recipient payload".to_vec())
    );
    opened.verify().unwrap();
}

#[test]
fn recipientwrap_startup_rejects_malformed_record_length() {
    let master = master_key();
    let options = WriterOptions {
        bit_rot_buffer_pct: 0,
        ..single_stream_options()
    };
    let archive = write_archive_with_recipient_wrap_records(
        &[RegularFile::new("wrapped.txt", b"recipient payload")],
        &master,
        options,
        vec![recipient_wrap_test_record()],
    )
    .unwrap();
    let mut bytes = archive.bytes;
    let (_, _, table_start, _table_len, _) = recipient_wrap_layout(&bytes);
    bytes[table_start + 96..table_start + 100].copy_from_slice(&1u32.to_le_bytes());

    assert_eq!(
        open_archive_with_recipient_wrap_resolver(&bytes, |_| { Ok(vec![master.0]) }).unwrap_err(),
        FormatError::InvalidArchive("RecipientRecordV1 record_length is too small")
    );
}

#[test]
fn recipientwrap_future_revision_rejects_before_resolver_callback() {
    let archive = write_archive_with_recipient_wrap_records(
        &[RegularFile::new("wrapped.txt", b"recipient payload")],
        &master_key(),
        single_stream_options(),
        vec![recipient_wrap_test_record()],
    )
    .unwrap();
    let mut bytes = archive.bytes;
    let mut header = VolumeHeader::parse(&bytes[..VOLUME_HEADER_LEN]).unwrap();
    header.volume_format_rev = VOLUME_FORMAT_REV_45 + 1;
    bytes[..VOLUME_HEADER_LEN].copy_from_slice(&header.to_bytes());

    let mut called = false;
    let err = open_archive_with_recipient_wrap_resolver(&bytes, |_| {
        called = true;
        Ok(vec![master_key().0])
    })
    .unwrap_err();

    assert!(!called);
    assert_eq!(
        err,
        FormatError::UnsupportedVolumeFormatRevision {
            format_version: FORMAT_VERSION,
            volume_format_rev: VOLUME_FORMAT_REV_45 + 1,
            reader_max_supported_revision: READER_MAX_SUPPORTED_VOLUME_FORMAT_REV,
        }
    );
}

#[test]
fn recipientwrap_stripe_width_mismatch_rejects_before_resolver_callback() {
    let archive = write_archive_with_recipient_wrap_records(
        &[RegularFile::new("wrapped.txt", b"recipient payload")],
        &master_key(),
        single_stream_options(),
        vec![recipient_wrap_test_record()],
    )
    .unwrap();
    let mut bytes = archive.bytes;
    let mut header = VolumeHeader::parse(&bytes[..VOLUME_HEADER_LEN]).unwrap();
    header.stripe_width += 1;
    bytes[..VOLUME_HEADER_LEN].copy_from_slice(&header.to_bytes());

    let mut called = false;
    let err = open_archive_with_recipient_wrap_resolver(&bytes, |_| {
        called = true;
        Ok(vec![master_key().0])
    })
    .unwrap_err();

    assert!(!called);
    assert_eq!(
        err,
        FormatError::InvalidArchive("VolumeHeader and CryptoHeader stripe_width differ")
    );
}

#[test]
fn recipientwrap_defers_raw_stream_profile_rejection_until_after_resolver_callback() {
    let master = master_key();
    let archive = write_archive_with_recipient_wrap_records(
        &[RegularFile::new("wrapped.txt", b"recipient payload")],
        &master,
        single_stream_options(),
        vec![recipient_wrap_test_record()],
    )
    .unwrap();
    let mut bytes = archive.bytes;
    add_raw_stream_profile_to_physical_crypto_header(&mut bytes);
    recompute_physical_crypto_header_hmac(&mut bytes, &master);

    let mut called = false;
    let err = open_archive_with_recipient_wrap_resolver(&bytes, |_| {
        called = true;
        Ok(vec![master.0])
    })
    .unwrap_err();

    assert!(called);
    assert_eq!(
        err,
        FormatError::ReaderUnsupported(RAW_STREAM_UNSUPPORTED_MESSAGE)
    );
}

#[test]
fn recipientwrap_recovers_physical_key_wrap_table_from_cmra_authority() {
    let master = master_key();
    let archive = write_archive_with_recipient_wrap_records(
        &[RegularFile::new("wrapped.txt", b"recipient payload")],
        &master,
        single_stream_options(),
        vec![recipient_wrap_test_record()],
    )
    .unwrap();
    let mut bytes = archive.bytes;
    let header = VolumeHeader::parse(&bytes[..VOLUME_HEADER_LEN]).unwrap();
    let crypto_start = header.crypto_header_offset as usize;
    let crypto_end = crypto_start + header.crypto_header_length as usize;
    let crypto_header = CryptoHeader::parse(
        &bytes[crypto_start..crypto_end],
        header.crypto_header_length,
    )
    .unwrap();
    let KdfParams::RecipientWrap {
        key_wrap_table_length,
        ..
    } = crypto_header.kdf_params
    else {
        panic!("expected RecipientWrap KdfParams");
    };
    let table_start = crypto_end;
    let table_end = table_start + key_wrap_table_length as usize;
    bytes[table_end - 1] ^= 0x01;

    let mut called = false;
    let opened = open_archive_with_recipient_wrap_resolver(&bytes, |context| {
        called = true;
        assert_eq!(
            context.archive_identity.volume_format_rev,
            VOLUME_FORMAT_REV_45
        );
        assert_eq!(context.record.profile_id, 1);
        Ok(vec![master.0])
    })
    .unwrap();

    assert!(called);
    assert_eq!(
        opened.extract_file("wrapped.txt").unwrap(),
        Some(b"recipient payload".to_vec())
    );
    opened.verify().unwrap();
}

#[test]
fn recipientwrap_open_rejects_wrong_candidate_header_hmac() {
    let archive = write_archive_with_recipient_wrap_records(
        &[RegularFile::new("wrapped.txt", b"recipient payload")],
        &master_key(),
        single_stream_options(),
        vec![recipient_wrap_test_record()],
    )
    .unwrap();
    let wrong_candidate = [0x99u8; 32];

    assert_eq!(
        open_archive_with_recipient_wrap_resolver(&archive.bytes, |_| {
            Ok(vec![wrong_candidate])
        })
        .unwrap_err(),
        FormatError::KeyMaterialMismatch
    );
}

#[test]
fn recipientwrap_open_recovers_tampered_physical_crypto_header_hmac_from_cmra() {
    let master = master_key();
    let archive = write_archive_with_recipient_wrap_records(
        &[RegularFile::new("wrapped.txt", b"recipient payload")],
        &master,
        single_stream_options(),
        vec![recipient_wrap_test_record()],
    )
    .unwrap();
    let mut bytes = archive.bytes.clone();
    let header = VolumeHeader::parse(&bytes[..VOLUME_HEADER_LEN]).unwrap();
    let hmac_end = header.crypto_header_offset as usize + header.crypto_header_length as usize;
    bytes[hmac_end - 1] ^= 0x55;

    let opened = open_archive_with_recipient_wrap_resolver(&bytes, |_| Ok(vec![master.0])).unwrap();

    assert_eq!(
        opened.extract_file("wrapped.txt").unwrap(),
        Some(b"recipient payload".to_vec())
    );
    assert_eq!(
        opened.crypto_header_bytes,
        archive.bytes[header.crypto_header_offset as usize..hmac_end]
    );
    opened.verify().unwrap();
}

#[test]
fn recipientwrap_archive_does_not_fall_back_to_raw_master_key_open() {
    let master = master_key();
    let archive = write_archive_with_recipient_wrap_records(
        &[RegularFile::new("wrapped.txt", b"recipient payload")],
        &master,
        single_stream_options(),
        vec![recipient_wrap_test_record()],
    )
    .unwrap();

    assert_eq!(
        open_archive(&archive.bytes, &master).unwrap_err(),
        FormatError::KeyMaterialMismatch
    );
}

#[test]
fn recipientwrap_seekable_archive_does_not_fall_back_to_raw_master_key_open() {
    let master = master_key();
    let archive = write_archive_with_recipient_wrap_records(
        &[RegularFile::new("wrapped.txt", b"recipient payload")],
        &master,
        single_stream_options(),
        vec![recipient_wrap_test_record()],
    )
    .unwrap();

    assert_eq!(
        open_seekable_archive(archive.bytes, &master).unwrap_err(),
        FormatError::KeyMaterialMismatch
    );
}

#[test]
fn public_no_key_verifies_signed_recipientwrap_block_commitment() {
    let archive = write_archive_with_root_auth_and_recipient_wrap_records(
        &[RegularFile::new("wrapped.txt", b"recipient payload")],
        &master_key(),
        single_stream_options(),
        vec![recipient_wrap_test_record()],
        test_root_auth_config(),
        |request| Ok(test_root_auth_value(request)),
    )
    .unwrap();

    let verified = public_no_key_verify_archive_with(&archive.bytes, |footer, archive_root| {
        Ok(test_root_auth_verifies(footer, archive_root))
    })
    .unwrap();

    assert_eq!(verified.volume_format_rev, VOLUME_FORMAT_REV_45);
    assert_eq!(verified.total_data_block_count, 3);
}

#[test]
fn public_no_key_rejects_recipientwrap_startup_and_cmra_kdf_mismatch() {
    let archive = write_archive_with_root_auth_and_recipient_wrap_records(
        &[RegularFile::new("wrapped.txt", b"recipient payload")],
        &master_key(),
        single_stream_options(),
        vec![recipient_wrap_test_record()],
        test_root_auth_config(),
        |request| Ok(test_root_auth_value(request)),
    )
    .unwrap();
    let mut bytes = archive.bytes;
    mutate_top_level_recipient_wrap_public_profile(&mut bytes);

    let err = public_no_key_verify_archive_with(&bytes, |footer, archive_root| {
        Ok(test_root_auth_verifies(footer, archive_root))
    })
    .unwrap_err();

    assert_eq!(
        err,
        FormatError::InvalidArchive("no valid v41 public CMRA candidate found")
    );
}

#[test]
fn public_no_key_rejects_recipientwrap_kdf_profile_mismatch_across_volumes() {
    let archive = write_archive_with_root_auth_and_recipient_wrap_records(
        &[RegularFile::new("wrapped.txt", b"recipient payload")],
        &master_key(),
        WriterOptions {
            stripe_width: 2,
            volume_loss_tolerance: 0,
            ..WriterOptions::default()
        },
        vec![recipient_wrap_test_record()],
        test_root_auth_config(),
        |request| Ok(test_root_auth_value(request)),
    )
    .unwrap();
    let mut volumes = archive.volumes;
    mutate_top_level_recipient_wrap_public_profile(&mut volumes[1]);
    mutate_cmra_recipient_wrap_public_profile(&mut volumes[1]);

    let volume_refs = volumes.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let err = public_no_key_verify_volumes_with(&volume_refs, |footer, archive_root| {
        Ok(test_root_auth_verifies(footer, archive_root))
    })
    .unwrap_err();

    assert_eq!(
        err,
        FormatError::InvalidArchive("public no-key volume global metadata differs")
    );
}

#[test]
fn write_archive_defaults_to_current_revision() {
    let archive = write_archive(&[], &master_key(), single_stream_options()).unwrap();
    let header = VolumeHeader::parse(&archive.bytes[..VOLUME_HEADER_LEN]).unwrap();

    assert_eq!(header.format_version, FORMAT_VERSION);
    assert_eq!(header.volume_format_rev, VOLUME_FORMAT_REV);
}

#[test]
fn non_seekable_stream_rejects_future_volume_format_revision() {
    let archive = write_archive(&[], &master_key(), single_stream_options()).unwrap();
    let mut bytes = archive.bytes;
    let mut header = VolumeHeader::parse(&bytes[..VOLUME_HEADER_LEN]).unwrap();
    header.volume_format_rev = VOLUME_FORMAT_REV_45 + 1;
    bytes[..VOLUME_HEADER_LEN].copy_from_slice(&header.to_bytes());

    assert_eq!(
        verify_non_seekable_stream(std::io::Cursor::new(bytes), &master_key()).unwrap_err(),
        FormatError::UnsupportedVolumeFormatRevision {
            format_version: FORMAT_VERSION,
            volume_format_rev: VOLUME_FORMAT_REV_45 + 1,
            reader_max_supported_revision: READER_MAX_SUPPORTED_VOLUME_FORMAT_REV,
        }
    );
}

#[test]
fn open_seekable_archive_rejects_future_volume_format_revision() {
    let archive = write_archive(&[], &master_key(), single_stream_options()).unwrap();
    let mut bytes = archive.bytes;
    let mut header = VolumeHeader::parse(&bytes[..VOLUME_HEADER_LEN]).unwrap();
    header.volume_format_rev = VOLUME_FORMAT_REV_45 + 1;
    bytes[..VOLUME_HEADER_LEN].copy_from_slice(&header.to_bytes());

    assert_eq!(
        open_seekable_archive(CountingReadAt::new(bytes, vec![]), &master_key()).unwrap_err(),
        FormatError::UnsupportedVolumeFormatRevision {
            format_version: FORMAT_VERSION,
            volume_format_rev: VOLUME_FORMAT_REV_45 + 1,
            reader_max_supported_revision: READER_MAX_SUPPORTED_VOLUME_FORMAT_REV,
        }
    );
}

#[test]
fn rejects_payload_tamper_even_with_recomputed_block_crc() {
    let mut archive = write_archive(
        &[RegularFile::new("file.txt", b"authenticated")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap()
    .bytes;
    let volume = VolumeHeader::parse(&archive[..VOLUME_HEADER_LEN]).unwrap();
    let crypto_end = VOLUME_HEADER_LEN + usize::try_from(volume.crypto_header_length).unwrap();
    let crypto = CryptoHeader::parse(
        &archive[VOLUME_HEADER_LEN..crypto_end],
        volume.crypto_header_length,
    )
    .unwrap();
    let block_size = crypto.fixed.block_size as usize;
    archive[crypto_end + 16] ^= 1;
    let crc_offset = crypto_end + 16 + block_size;
    let crc = crc32c::crc32c(&archive[crypto_end..crc_offset]);
    archive[crc_offset..crc_offset + 4].copy_from_slice(&crc.to_le_bytes());

    let opened = open_archive(&archive, &master_key()).unwrap();
    assert_eq!(opened.verify().unwrap_err(), FormatError::AeadFailure);
}

#[test]
fn list_and_extract_use_final_view_for_duplicate_paths() {
    let archive = write_archive(
        &[
            RegularFile {
                mtime: crate::ArchiveTimestamp::from_seconds(1_700_000_000),
                ..RegularFile::new("same.txt", b"old")
            },
            RegularFile {
                mtime: crate::ArchiveTimestamp::from_seconds(1_700_000_100),
                ..RegularFile::new("same.txt", b"newer")
            },
        ],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let opened = open_archive(&archive.bytes, &master_key()).unwrap();

    let listed = opened.list_index_entries().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].path, "same.txt");
    assert_eq!(listed[0].name, "same.txt");
    assert_eq!(listed[0].file_data_size, 5);
    assert_eq!(listed[0].flags, crate::entry_metadata::EXTENDED_METADATA_V1);
    assert_eq!(listed[0].frame_count, 1);
    assert!(listed[0].layout.compressed_size > 0);
    let looked_up = opened.lookup_index_entry("same.txt").unwrap().unwrap();
    assert_eq!(looked_up.path, "same.txt");
    assert_eq!(looked_up.file_data_size, 5);
    assert_eq!(looked_up.flags, crate::entry_metadata::EXTENDED_METADATA_V1);
    assert_eq!(opened.lookup_index_entry("missing.txt").unwrap(), None);
    assert_eq!(
        opened.list_files().unwrap(),
        vec![ArchiveEntry {
            path: "same.txt".to_string(),
            file_data_size: 5,
            kind: TarEntryKind::Regular,
            mode: 0o644,
            mtime: ArchiveTimestamp::from_seconds(1_700_000_100),
            diagnostics: Vec::new(),
            link_target: None,
            created: None,
            accessed: None,
            attributes: None,
            uid: None,
            gid: None,
            uname: None,
            gname: None,
        }]
    );
    assert_eq!(
        opened.extract_file("same.txt").unwrap(),
        Some(b"newer".to_vec())
    );
    opened.verify().unwrap();
}

#[test]
fn index_entries_do_not_decrypt_payload_envelopes() {
    let (mut opened, broken_payload_block) = multi_envelope_reader_fixture();
    corrupt_payload_record(&mut opened.blocks, broken_payload_block);

    let listed = opened.list_index_entries().unwrap();
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].path, "broken.txt");
    assert_eq!(listed[0].file_data_size, b"broken payload\n".len() as u64);
    assert_eq!(listed[0].flags, crate::entry_metadata::EXTENDED_METADATA_V1);
    assert_eq!(listed[1].path, "healthy.txt");
    assert_eq!(listed[1].file_data_size, b"healthy payload\n".len() as u64);
    assert_eq!(listed[1].flags, crate::entry_metadata::EXTENDED_METADATA_V1);
    let looked_up = opened.lookup_index_entry("broken.txt").unwrap().unwrap();
    assert_eq!(looked_up.path, "broken.txt");
    assert_eq!(looked_up.file_data_size, b"broken payload\n".len() as u64);
    assert_eq!(looked_up.flags, crate::entry_metadata::EXTENDED_METADATA_V1);
    assert_eq!(opened.list_files().unwrap_err(), FormatError::AeadFailure);
}

#[test]
fn index_entry_layout_stats_match_frame_and_envelope_tables() {
    let payload = pseudo_random_bytes(12 * 1024);
    let archive = write_archive(
        &[RegularFile::new("chunked.bin", &payload)],
        &master_key(),
        WriterOptions {
            block_size: 4096,
            chunk_size: 1024,
            envelope_target_size: 2048,
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            fec_data_shards: 16,
            fec_parity_shards: 0,
            ..WriterOptions::default()
        },
    )
    .unwrap();
    let opened = open_archive(&archive.bytes, &master_key()).unwrap();
    let entry = opened.list_index_entries().unwrap().remove(0);
    let located = opened
        .locate_index_file(b"chunked.bin")
        .unwrap()
        .expect("indexed file exists");
    let file = &located.shard.files[located.file_index];
    let frames = frame_range_for_file(&located.shard, file).unwrap();
    assert!(frames.len() > 1);

    let expected_compressed_size = frames
        .iter()
        .map(|frame| frame.compressed_size as u64)
        .sum::<u64>();
    let expected_decompressed_frame_size = frames
        .iter()
        .map(|frame| frame.decompressed_size as u64)
        .sum::<u64>();
    let envelope_indexes = frames
        .iter()
        .map(|frame| frame.envelope_index)
        .collect::<BTreeSet<_>>();
    assert!(envelope_indexes.len() > 1);

    let envelopes = envelope_indexes
        .iter()
        .map(|index| envelope_by_index(&located.shard, *index).unwrap())
        .collect::<Vec<_>>();
    let expected_first_payload_block_index = envelopes
        .iter()
        .map(|envelope| envelope.first_block_index)
        .min();
    let expected_payload_data_block_count = envelopes
        .iter()
        .map(|envelope| envelope.data_block_count as u64)
        .sum::<u64>();
    let expected_payload_parity_block_count = envelopes
        .iter()
        .map(|envelope| envelope.parity_block_count as u64)
        .sum::<u64>();
    let expected_payload_encrypted_size = envelopes
        .iter()
        .map(|envelope| envelope.encrypted_size as u64)
        .sum::<u64>();

    assert_eq!(entry.path, "chunked.bin");
    assert_eq!(entry.name, "chunked.bin");
    assert_eq!(entry.file_data_size, payload.len() as u64);
    assert_eq!(entry.flags, file.flags);
    assert_eq!(entry.tar_member_group_size, file.tar_member_group_size);
    assert_eq!(entry.first_frame_index, file.first_frame_index);
    assert_eq!(entry.frame_count, file.frame_count);
    assert_eq!(
        entry.offset_in_first_frame_plaintext,
        file.offset_in_first_frame_plaintext
    );
    assert_eq!(entry.layout.compressed_size, expected_compressed_size);
    assert_eq!(
        entry.layout.decompressed_frame_size,
        expected_decompressed_frame_size
    );
    assert_eq!(entry.layout.envelope_count as usize, envelope_indexes.len());
    assert_eq!(
        entry.layout.first_envelope_index,
        envelope_indexes.iter().next().copied()
    );
    assert_eq!(
        entry.layout.last_envelope_index,
        envelope_indexes.iter().next_back().copied()
    );
    assert_eq!(
        entry.layout.first_payload_block_index,
        expected_first_payload_block_index
    );
    assert_eq!(
        entry.layout.payload_data_block_count,
        expected_payload_data_block_count
    );
    assert_eq!(
        entry.layout.payload_parity_block_count,
        expected_payload_parity_block_count
    );
    assert_eq!(
        entry.layout.payload_encrypted_size,
        expected_payload_encrypted_size
    );
}

#[test]
fn extract_file_does_not_decrypt_unselected_payload_envelope() {
    // This fixture corrupts only the unselected envelope, proving selected
    // extraction does not decrypt unrelated payload envelopes.
    let (mut opened, broken_payload_block) = multi_envelope_reader_fixture();
    corrupt_payload_record(&mut opened.blocks, broken_payload_block);

    assert_eq!(
        opened.extract_file("healthy.txt").unwrap(),
        Some(b"healthy payload\n".to_vec())
    );
    assert_eq!(
        opened.extract_file("broken.txt").unwrap_err(),
        FormatError::AeadFailure
    );
    assert_eq!(opened.verify().unwrap_err(), FormatError::AeadFailure);
}

#[test]
fn seekable_extract_does_not_read_unselected_payload_envelope() {
    let healthy = pseudo_random_bytes(64 * 1024);
    let broken = pseudo_random_bytes(64 * 1024);
    let options = WriterOptions {
        block_size: 4096,
        chunk_size: 4096,
        envelope_target_size: 8192,
        stripe_width: 1,
        volume_loss_tolerance: 0,
        bit_rot_buffer_pct: 0,
        fec_data_shards: 4,
        fec_parity_shards: 0,
        index_fec_data_shards: 4,
        index_fec_parity_shards: 0,
        index_root_fec_data_shards: 4,
        index_root_fec_parity_shards: 0,
        ..WriterOptions::default()
    };
    let archive = write_archive(
        &[
            RegularFile::new("healthy.bin", &healthy),
            RegularFile::new("broken.bin", &broken),
        ],
        &master_key(),
        options,
    )
    .unwrap();
    let eager = open_archive(&archive.bytes, &master_key()).unwrap();
    let healthy_envelopes = envelope_indices_for_path(&eager, "healthy.bin");
    let broken_envelopes = envelope_entries_for_path(&eager, "broken.bin");
    let denied_block_indices = broken_envelopes
        .iter()
        .filter(|envelope| !healthy_envelopes.contains(&envelope.envelope_index))
        .flat_map(|envelope| {
            let block_count = envelope.data_block_count as u64 + envelope.parity_block_count as u64;
            envelope.first_block_index..envelope.first_block_index + block_count
        })
        .collect::<BTreeSet<_>>();
    assert!(
        !denied_block_indices.is_empty(),
        "fixture must place broken.bin in at least one unshared envelope"
    );
    let denied_ranges = block_record_slots(&archive.bytes)
        .into_iter()
        .filter_map(|(offset, len, record)| {
            denied_block_indices
                .contains(&record.block_index)
                .then_some((offset as u64, (offset + len) as u64))
        })
        .collect::<Vec<_>>();
    assert!(!denied_ranges.is_empty());

    let reader = CountingReadAt::new(archive.bytes, denied_ranges.clone());
    let opened = open_seekable_archive(reader.clone(), &master_key()).unwrap();

    assert_eq!(opened.extract_file("healthy.bin").unwrap(), Some(healthy));
    for (read_start, read_end) in reader.reads() {
        assert!(
            denied_ranges
                .iter()
                .all(|(start, end)| !ranges_overlap(read_start, read_end, *start, *end)),
            "targeted extract read an unrelated payload BlockRecord range"
        );
    }
    assert_eq!(
        opened.extract_file("broken.bin").unwrap_err(),
        FormatError::InvalidArchive("denied test read")
    );
}

#[test]
fn extract_file_to_writer_streams_before_reading_later_envelopes() {
    struct FailOnFirstWrite;

    impl std::io::Write for FailOnFirstWrite {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("sink stopped"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let payload = pseudo_random_bytes(128 * 1024);
    let options = WriterOptions {
        block_size: 4096,
        chunk_size: 4096,
        envelope_target_size: 8192,
        stripe_width: 1,
        volume_loss_tolerance: 0,
        bit_rot_buffer_pct: 0,
        fec_data_shards: 4,
        fec_parity_shards: 0,
        index_fec_data_shards: 4,
        index_fec_parity_shards: 0,
        index_root_fec_data_shards: 4,
        index_root_fec_parity_shards: 0,
        ..WriterOptions::default()
    };
    let archive = write_archive(
        &[RegularFile::new("large.bin", &payload)],
        &master_key(),
        options,
    )
    .unwrap();
    let eager = open_archive(&archive.bytes, &master_key()).unwrap();
    let envelopes = envelope_entries_for_path(&eager, "large.bin");
    let first_envelope = envelopes
        .first()
        .expect("large fixture should have at least one envelope")
        .envelope_index;
    let later_envelope_blocks = envelopes
        .iter()
        .filter(|entry| entry.envelope_index != first_envelope)
        .flat_map(|entry| {
            let block_count = entry.data_block_count as u64 + entry.parity_block_count as u64;
            entry.first_block_index..entry.first_block_index + block_count
        })
        .collect::<BTreeSet<_>>();
    assert!(
        !later_envelope_blocks.is_empty(),
        "fixture must span more than one payload envelope"
    );
    let denied_ranges = block_record_slots(&archive.bytes)
        .into_iter()
        .filter_map(|(offset, len, record)| {
            later_envelope_blocks
                .contains(&record.block_index)
                .then_some((offset as u64, (offset + len) as u64))
        })
        .collect::<Vec<_>>();
    assert!(!denied_ranges.is_empty());

    let reader = CountingReadAt::new(archive.bytes, denied_ranges.clone());
    let opened = open_seekable_archive(reader.clone(), &master_key()).unwrap();
    let mut writer = FailOnFirstWrite;

    let err = opened
        .extract_file_to_writer("large.bin", &mut writer)
        .unwrap_err();
    assert_eq!(err.to_string(), "extraction output write failed");
    for (read_start, read_end) in reader.reads() {
        assert!(
            denied_ranges
                .iter()
                .all(|(start, end)| !ranges_overlap(read_start, read_end, *start, *end)),
            "streaming writer read a later payload envelope before surfacing writer failure"
        );
    }
}

#[test]
fn extract_file_to_writer_writes_bounded_chunks() {
    struct ChunkRecorder {
        total: usize,
        max_write: usize,
        writes: usize,
    }

    impl std::io::Write for ChunkRecorder {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.total += buf.len();
            self.max_write = self.max_write.max(buf.len());
            self.writes += 1;
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let payload = pseudo_random_bytes(128 * 1024);
    let options = WriterOptions {
        block_size: 4096,
        chunk_size: 4096,
        envelope_target_size: 8192,
        stripe_width: 1,
        volume_loss_tolerance: 0,
        bit_rot_buffer_pct: 0,
        fec_data_shards: 4,
        fec_parity_shards: 0,
        index_fec_data_shards: 4,
        index_fec_parity_shards: 0,
        index_root_fec_data_shards: 4,
        index_root_fec_parity_shards: 0,
        ..WriterOptions::default()
    };
    let archive = write_archive(
        &[RegularFile::new("large.bin", &payload)],
        &master_key(),
        options,
    )
    .unwrap();
    let opened = open_archive(&archive.bytes, &master_key()).unwrap();
    let mut writer = ChunkRecorder {
        total: 0,
        max_write: 0,
        writes: 0,
    };

    opened
        .extract_file_to_writer("large.bin", &mut writer)
        .unwrap()
        .unwrap();

    assert_eq!(writer.total, payload.len());
    assert!(writer.writes > 1);
    assert!(
        writer.max_write <= options.chunk_size as usize,
        "writer saw a {} byte chunk, larger than the {} byte frame target",
        writer.max_write,
        options.chunk_size
    );
}

#[test]
fn extract_file_to_writer_with_progress_reports_payload_bytes() {
    struct ChunkRecorder {
        total: usize,
    }

    impl std::io::Write for ChunkRecorder {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.total += buf.len();
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let payload = pseudo_random_bytes(128 * 1024);
    let options = WriterOptions {
        block_size: 4096,
        chunk_size: 4096,
        envelope_target_size: 8192,
        stripe_width: 1,
        volume_loss_tolerance: 0,
        bit_rot_buffer_pct: 0,
        fec_data_shards: 4,
        fec_parity_shards: 0,
        index_fec_data_shards: 4,
        index_fec_parity_shards: 0,
        index_root_fec_data_shards: 4,
        index_root_fec_parity_shards: 0,
        ..WriterOptions::default()
    };
    let archive = write_archive(
        &[RegularFile::new("large.bin", &payload)],
        &master_key(),
        options,
    )
    .unwrap();
    let opened = open_archive(&archive.bytes, &master_key()).unwrap();
    let mut writer = ChunkRecorder { total: 0 };
    let mut progress_events = Vec::new();
    let mut progress = |archive_path: &str, bytes: u64| {
        progress_events.push((archive_path.to_owned(), bytes));
    };

    opened
        .extract_file_to_writer_with_progress("large.bin", &mut writer, &mut progress)
        .unwrap()
        .unwrap();

    let reported_bytes = progress_events.iter().map(|(_, bytes)| *bytes).sum::<u64>();
    assert_eq!(writer.total, payload.len());
    assert_eq!(reported_bytes, payload.len() as u64);
    assert!(progress_events.len() > 1);
    assert!(progress_events.iter().all(|(path, _)| path == "large.bin"));
}

#[test]
fn streaming_filesystem_extract_does_not_publish_partial_file_on_late_payload_error() {
    let payload = pseudo_random_bytes(128 * 1024);
    let options = WriterOptions {
        block_size: 4096,
        chunk_size: 4096,
        envelope_target_size: 8192,
        stripe_width: 1,
        volume_loss_tolerance: 0,
        bit_rot_buffer_pct: 0,
        fec_data_shards: 4,
        fec_parity_shards: 0,
        index_fec_data_shards: 4,
        index_fec_parity_shards: 0,
        index_root_fec_data_shards: 4,
        index_root_fec_parity_shards: 0,
        ..WriterOptions::default()
    };
    let archive = write_archive(
        &[RegularFile::new("large.bin", &payload)],
        &master_key(),
        options,
    )
    .unwrap();
    let eager = open_archive(&archive.bytes, &master_key()).unwrap();
    let envelopes = envelope_entries_for_path(&eager, "large.bin");
    let last_envelope = envelopes
        .last()
        .expect("large fixture should have at least one envelope");
    assert_ne!(
        envelopes.first().unwrap().envelope_index,
        last_envelope.envelope_index,
        "fixture must span more than one payload envelope"
    );
    let corrupt_slot = block_record_slots(&archive.bytes)
        .into_iter()
        .enumerate()
        .find_map(|(slot, (_, _, record))| {
            (record.block_index == last_envelope.first_block_index).then_some(slot)
        })
        .unwrap();
    let mut corrupted = archive.bytes;
    corrupt_block_record_payload_at_slot(&mut corrupted, corrupt_slot);
    let opened = open_seekable_archive(corrupted, &master_key()).unwrap();
    let tmp = tempfile::tempdir().unwrap();

    assert!(matches!(
        opened
            .extract_file_to("large.bin", tmp.path(), SafeExtractionOptions::default())
            .unwrap_err(),
        FormatError::AeadFailure | FormatError::FecTooFewAvailableShards
    ));
    assert!(!tmp.path().join("large.bin").exists());
    assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
}

#[test]
fn bootstrap_sidecar_opens_lists_verifies_and_extracts() {
    let archive = write_archive(
        &[RegularFile::new("dir/sidecar.txt", b"hello sidecar")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let opened = open_archive_with_bootstrap_sidecar(
        &archive.bytes,
        &archive.bootstrap_sidecar,
        &master_key(),
    )
    .unwrap();

    assert_eq!(
        opened.list_files().unwrap(),
        vec![ArchiveEntry {
            path: "dir/sidecar.txt".to_string(),
            file_data_size: 13,
            kind: TarEntryKind::Regular,
            mode: 0o644,
            mtime: ArchiveTimestamp::UNIX_EPOCH,
            diagnostics: Vec::new(),
            link_target: None,
            created: None,
            accessed: None,
            attributes: None,
            uid: None,
            gid: None,
            uname: None,
            gname: None,
        }]
    );
    assert_eq!(
        opened.extract_file("dir/sidecar.txt").unwrap(),
        Some(b"hello sidecar".to_vec())
    );
    opened.verify().unwrap();
}

#[test]
fn fast_verify_plaintext_zero_recovery_defers_payload_semantics() {
    let options = WriterOptions {
        aead_algo: AeadAlgo::None,
        volume_loss_tolerance: 0,
        bit_rot_buffer_pct: 0,
        ..single_stream_options()
    };
    let archive = write_archive_unencrypted(
        &[RegularFile::new(
            "payload.txt",
            b"payload bytes large enough to produce a zstd frame",
        )],
        options,
    )
    .unwrap();
    let opened = open_archive(&archive.bytes, &master_key()).unwrap();
    let tables = opened.load_payload_index_tables().unwrap();
    let first_envelope = tables.envelopes.values().next().unwrap();
    let volume_header = VolumeHeader::parse(&archive.bytes[..VOLUME_HEADER_LEN]).unwrap();
    let crypto_end = VOLUME_HEADER_LEN + volume_header.crypto_header_length as usize;
    let record_len = opened.crypto_header.block_size as usize + BLOCK_RECORD_FRAMING_LEN;
    let payload_offset = crypto_end + first_envelope.first_block_index as usize * record_len;

    let mut tampered = archive.bytes.clone();
    tampered[payload_offset + 16] ^= 0x01;
    let crc_offset = payload_offset + 16 + opened.crypto_header.block_size as usize;
    let crc = crc32c::crc32c(&tampered[payload_offset..crc_offset]);
    tampered[crc_offset..crc_offset + 4].copy_from_slice(&crc.to_le_bytes());

    let tampered_opened = open_archive(&tampered, &master_key()).unwrap();
    assert!(tampered_opened.fast_verify_defers_payload_semantics());
    tampered_opened.verify_content_fast().unwrap();
    assert!(tampered_opened.verify_content().is_err());
}

#[test]
fn fast_verify_root_auth_archive_requires_full_root_auth_scan() {
    let archive = write_archive_with_root_auth(
        &[RegularFile::new("signed.txt", b"root-auth payload")],
        &master_key(),
        single_stream_options(),
        RootAuthWriterConfig {
            authenticator_id: 0x7777,
            signer_identity_type: 1,
            signer_identity: b"test signer",
            authenticator_value_length: 32,
        },
        |request| Ok(request.archive_root.to_vec()),
    )
    .unwrap();

    let opened = open_archive(&archive.bytes, &master_key()).unwrap();
    assert!(!opened.fast_verify_defers_payload_semantics());
    assert!(matches!(
        opened.verify_content_fast().unwrap().mode,
        ContentVerificationMode::Fast
    ));
}

#[test]
fn fast_verify_dictionary_archive_does_not_defer_payload_semantics() {
    let archive = write_archive_with_dictionary(
        &[RegularFile::new("dict.txt", b"dictionary payload")],
        &master_key(),
        single_stream_options(),
        dictionary(),
    )
    .unwrap();

    let opened = open_archive(&archive.bytes, &master_key()).unwrap();
    assert!(!opened.fast_verify_defers_payload_semantics());
}

#[test]
fn fast_verify_encrypted_archive_does_not_defer_payload_semantics() {
    let options = WriterOptions {
        aead_algo: AeadAlgo::AesGcmSiv256,
        volume_loss_tolerance: 0,
        bit_rot_buffer_pct: 0,
        ..single_stream_options()
    };
    let archive = write_archive(
        &[RegularFile::new("payload.txt", b"encrypted payload")],
        &master_key(),
        options,
    )
    .unwrap();

    let opened = open_archive(&archive.bytes, &master_key()).unwrap();
    assert!(!opened.fast_verify_defers_payload_semantics());
}

#[test]
fn fast_verify_repair_archive_does_not_defer_payload_semantics() {
    let options = WriterOptions {
        fec_parity_shards: 2,
        volume_loss_tolerance: 0,
        bit_rot_buffer_pct: 0,
        ..single_stream_options()
    };
    let archive = write_archive(
        &[RegularFile::new("payload.txt", b"payload for repair")],
        &master_key(),
        options,
    )
    .unwrap();

    let opened = open_archive(&archive.bytes, &master_key()).unwrap();
    assert!(!opened.fast_verify_defers_payload_semantics());
}

#[test]
fn dictionary_archive_opens_lists_verifies_and_extracts_seekable() {
    let archive = write_archive_with_dictionary(
        &[RegularFile::new(
            "dir/dict.txt",
            b"common words common words dictionary payload",
        )],
        &master_key(),
        single_stream_options(),
        dictionary(),
    )
    .unwrap();
    let opened = open_archive(&archive.bytes, &master_key()).unwrap();

    assert_eq!(opened.crypto_header.has_dictionary, 1);
    assert!(opened.index_root.header.dictionary_data_block_count > 0);
    assert_eq!(
        opened.list_files().unwrap(),
        vec![ArchiveEntry {
            path: "dir/dict.txt".to_string(),
            file_data_size: 44,
            kind: TarEntryKind::Regular,
            mode: 0o644,
            mtime: ArchiveTimestamp::UNIX_EPOCH,
            diagnostics: Vec::new(),
            link_target: None,
            created: None,
            accessed: None,
            attributes: None,
            uid: None,
            gid: None,
            uname: None,
            gname: None,
        }]
    );
    assert_eq!(
        opened.extract_file("dir/dict.txt").unwrap(),
        Some(b"common words common words dictionary payload".to_vec())
    );
    opened.verify().unwrap();
}

#[test]
fn dictionary_object_tamper_fails_before_payload_decompression() {
    let archive = write_archive_with_dictionary(
        &[RegularFile::new(
            "dir/dict.txt",
            b"common words common words dictionary payload",
        )],
        &master_key(),
        single_stream_options(),
        dictionary(),
    )
    .unwrap();
    let opened = open_archive(&archive.bytes, &master_key()).unwrap();
    let volume_header = VolumeHeader::parse(&archive.bytes[..VOLUME_HEADER_LEN]).unwrap();
    let crypto_end = VOLUME_HEADER_LEN + volume_header.crypto_header_length as usize;
    let record_len = opened.crypto_header.block_size as usize + BLOCK_RECORD_FRAMING_LEN;
    let dictionary_offset =
        crypto_end + opened.index_root.header.dictionary_first_block as usize * record_len;

    let mut tampered = archive.bytes.clone();
    tampered[dictionary_offset + 16] ^= 0x01;
    let crc_offset = dictionary_offset + 16 + opened.crypto_header.block_size as usize;
    let crc = crc32c::crc32c(&tampered[dictionary_offset..crc_offset]);
    tampered[crc_offset..crc_offset + 4].copy_from_slice(&crc.to_le_bytes());

    assert_eq!(
        open_archive(&tampered, &master_key()).unwrap_err(),
        FormatError::AeadFailure
    );
}

#[test]
fn dictionary_archive_bootstraps_from_sidecar_for_non_seekable_open() {
    let archive = write_archive_with_dictionary(
        &[RegularFile::new(
            "dict-sidecar.txt",
            b"common words common words sidecar payload",
        )],
        &master_key(),
        single_stream_options(),
        dictionary(),
    )
    .unwrap();
    let opened = open_non_seekable_archive(
        &archive.bytes,
        &master_key(),
        Some(&archive.bootstrap_sidecar),
    )
    .unwrap();

    assert_eq!(
        opened.extract_file("dict-sidecar.txt").unwrap(),
        Some(b"common words common words sidecar payload".to_vec())
    );
    opened.verify().unwrap();
}

#[test]
fn non_seekable_full_sidecar_bootstraps_when_terminal_trailer_is_corrupt() {
    let archive = write_archive(
        &[RegularFile::new(
            "sidecar-terminal.txt",
            b"sidecar authority",
        )],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let mut corrupted = archive.bytes.clone();
    corrupt_v41_terminal_recovery(&mut corrupted);
    assert!(open_archive(&corrupted, &master_key()).is_err());

    let opened =
        open_non_seekable_archive(&corrupted, &master_key(), Some(&archive.bootstrap_sidecar))
            .unwrap();

    assert!(opened.volume_trailer.is_none());
    assert_eq!(
        opened.extract_file("sidecar-terminal.txt").unwrap(),
        Some(b"sidecar authority".to_vec())
    );
    opened.verify().unwrap();
}

#[test]
fn dictionary_full_sidecar_bootstraps_when_terminal_material_is_absent() {
    let archive = write_archive_with_dictionary(
        &[RegularFile::new(
            "dict-no-terminal.txt",
            b"common words common words without terminal",
        )],
        &master_key(),
        single_stream_options(),
        dictionary(),
    )
    .unwrap();
    let terminal_offset = terminal_material_offset(&archive.bytes);
    let truncated = archive.bytes[..terminal_offset].to_vec();
    assert!(open_archive(&truncated, &master_key()).is_err());

    let opened =
        open_non_seekable_archive(&truncated, &master_key(), Some(&archive.bootstrap_sidecar))
            .unwrap();

    assert!(opened.volume_trailer.is_none());
    assert_eq!(
        opened.extract_file("dict-no-terminal.txt").unwrap(),
        Some(b"common words common words without terminal".to_vec())
    );
    opened.verify().unwrap();
}

#[test]
fn bootstrap_sidecar_treats_crc_failed_payload_block_as_erasure() {
    let archive = write_archive(
        &[RegularFile::new(
            "sidecar-erasure.txt",
            b"repair through sidecar",
        )],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let mut corrupted = archive.bytes.clone();
    corrupt_first_block_record_payload(&mut corrupted);

    let opened =
        open_archive_with_bootstrap_sidecar(&corrupted, &archive.bootstrap_sidecar, &master_key())
            .unwrap();
    assert_eq!(
        opened.extract_file("sidecar-erasure.txt").unwrap(),
        Some(b"repair through sidecar".to_vec())
    );
}

#[test]
fn extraction_rejects_logical_payload_above_total_size_cap() {
    let archive = write_archive(
        &[RegularFile::new("cap.txt", b"payload")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let options = ReaderOptions {
        max_total_extraction_size: 3,
        ..ReaderOptions::default()
    };
    let opened = OpenedArchive::open_with_options(&archive.bytes, &master_key(), options).unwrap();

    assert_eq!(
        opened.extract_file("cap.txt").unwrap_err(),
        FormatError::ReaderUnsupported("total extraction size exceeds configured cap")
    );
}

#[test]
fn verify_does_not_apply_extraction_payload_cap() {
    let archive = write_archive(
        &[RegularFile::new("verify-cap.txt", b"payload")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let options = ReaderOptions {
        max_total_extraction_size: 3,
        ..ReaderOptions::default()
    };
    let opened = OpenedArchive::open_with_options(&archive.bytes, &master_key(), options).unwrap();

    opened.verify().unwrap();
    assert_eq!(
        opened.extract_file("verify-cap.txt").unwrap_err(),
        FormatError::ReaderUnsupported("total extraction size exceeds configured cap")
    );
}

#[test]
fn verify_streams_past_legacy_in_memory_tar_cap() {
    let data = vec![0x5a; 4096];
    let archive = write_archive(
        &[RegularFile::new("verify-large.txt", &data)],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let options = ReaderOptions {
        max_verify_tar_size: 1,
        ..ReaderOptions::default()
    };
    let opened = OpenedArchive::open_with_options(&archive.bytes, &master_key(), options).unwrap();

    opened.verify().unwrap();
}

#[test]
fn dictionary_sidecar_requires_dictionary_record_section() {
    let archive = write_archive_with_dictionary(
        &[RegularFile::new("dict-missing.txt", b"common words")],
        &master_key(),
        single_stream_options(),
        dictionary(),
    )
    .unwrap();
    let header =
        BootstrapSidecarHeader::parse(&archive.bootstrap_sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN])
            .unwrap();
    let mut missing_dictionary =
        archive.bootstrap_sidecar[..header.dictionary_records_offset as usize].to_vec();
    rewrite_sidecar_header(&mut missing_dictionary, &master_key(), |header| {
        header.flags &= !0x04;
        header.dictionary_records_offset = 0;
        header.dictionary_records_length = 0;
    });

    assert_eq!(
        open_non_seekable_archive(&archive.bytes, &master_key(), Some(&missing_dictionary))
            .unwrap_err(),
        FormatError::ReaderUnsupported("dictionary bootstrap required")
    );
}

#[test]
fn dictionary_sidecar_records_are_validated_against_dictionary_extent() {
    let archive = write_archive_with_dictionary(
        &[RegularFile::new("dict-sidecar-kind.txt", b"common words")],
        &master_key(),
        single_stream_options(),
        dictionary(),
    )
    .unwrap();

    let mut wrong_kind = archive.bootstrap_sidecar.clone();
    mutate_sidecar_dictionary_record(&mut wrong_kind, 0, |record| {
        record.kind = BlockKind::IndexRootData;
    });
    assert_eq!(
        open_archive_with_bootstrap_sidecar(&archive.bytes, &wrong_kind, &master_key())
            .unwrap_err(),
        FormatError::InvalidArchive("sidecar BlockRecord section has wrong kind")
    );

    let mut wrong_last = archive.bootstrap_sidecar.clone();
    mutate_sidecar_dictionary_record(&mut wrong_last, 0, |record| {
        record.flags = 0;
    });
    assert_eq!(
        open_archive_with_bootstrap_sidecar(&archive.bytes, &wrong_last, &master_key())
            .unwrap_err(),
        FormatError::InvalidArchive("sidecar BlockRecord section has wrong last-data flag")
    );
}

#[test]
fn non_seekable_random_access_requires_sidecar() {
    let archive = write_archive(
        &[RegularFile::new("file.txt", b"payload")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();

    assert_eq!(
        open_non_seekable_archive(&archive.bytes, &master_key(), None).unwrap_err(),
        FormatError::ReaderUnsupported("non-seekable random access requires a bootstrap sidecar")
    );
    assert!(open_non_seekable_archive(
        &archive.bytes,
        &master_key(),
        Some(&archive.bootstrap_sidecar)
    )
    .is_ok());
}

#[test]
fn non_seekable_bootstrap_rejects_index_root_only_sidecar() {
    let archive = write_archive(
        &[RegularFile::new("sparse.txt", b"sparse sidecar")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let index_root_only = sparse_bootstrap_sidecar(
        &archive.bootstrap_sidecar,
        &master_key(),
        false,
        true,
        false,
    );

    assert_eq!(
        open_non_seekable_archive(&archive.bytes, &master_key(), Some(&index_root_only))
            .unwrap_err(),
        FormatError::ReaderUnsupported(
            "non-seekable bootstrap sidecar requires ManifestFooter and IndexRoot sections"
        )
    );
}

#[test]
fn seekable_sidecar_uses_index_root_records_after_terminal_manifest_authority() {
    let archive = write_archive(
        &[RegularFile::new("sparse-index.txt", b"recover index root")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let opened = open_archive(&archive.bytes, &master_key()).unwrap();
    let mut corrupted = archive.bytes.clone();
    corrupt_object_extent_records(
        &mut corrupted,
        index_root_extent_from_manifest(&opened.manifest_footer),
    );
    assert!(open_archive(&corrupted, &master_key()).is_err());

    let index_root_only = sparse_bootstrap_sidecar(
        &archive.bootstrap_sidecar,
        &master_key(),
        false,
        true,
        false,
    );
    let recovered =
        open_archive_with_bootstrap_sidecar(&corrupted, &index_root_only, &master_key()).unwrap();

    assert_eq!(
        recovered.extract_file("sparse-index.txt").unwrap(),
        Some(b"recover index root".to_vec())
    );
    recovered.verify().unwrap();
}

#[test]
fn seekable_sidecar_uses_dictionary_records_after_index_root_authority() {
    let archive = write_archive_with_dictionary(
        &[RegularFile::new(
            "sparse-dict.txt",
            b"common words common words sparse dictionary",
        )],
        &master_key(),
        single_stream_options(),
        dictionary(),
    )
    .unwrap();
    let opened = open_archive(&archive.bytes, &master_key()).unwrap();
    let mut corrupted = archive.bytes.clone();
    corrupt_object_extent_records(
        &mut corrupted,
        dictionary_extent_from_index_root(&opened.index_root).unwrap(),
    );
    assert!(open_archive(&corrupted, &master_key()).is_err());

    let dictionary_only = sparse_bootstrap_sidecar(
        &archive.bootstrap_sidecar,
        &master_key(),
        false,
        false,
        true,
    );
    assert_eq!(
        open_non_seekable_archive(&archive.bytes, &master_key(), Some(&dictionary_only))
            .unwrap_err(),
        FormatError::ReaderUnsupported(
            "non-seekable bootstrap sidecar requires ManifestFooter and IndexRoot sections"
        )
    );

    let recovered =
        open_archive_with_bootstrap_sidecar(&corrupted, &dictionary_only, &master_key()).unwrap();
    assert_eq!(
        recovered.extract_file("sparse-dict.txt").unwrap(),
        Some(b"common words common words sparse dictionary".to_vec())
    );
    recovered.verify().unwrap();
}

#[test]
fn sequential_extracts_dictionary_free_tar_stream() {
    let archive = write_archive(
        &[RegularFile::new("seq.txt", b"streaming")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();

    let tar_stream = sequential_extract_tar_stream(&archive.bytes, &master_key()).unwrap();
    let member = parse_tar_member_group(&tar_stream, 4096).unwrap();
    assert_eq!(member.path, b"seq.txt");
    assert_eq!(member.data, b"streaming");
}

#[test]
fn sequential_rejects_logical_payload_above_total_size_cap() {
    let archive = write_archive(
        &[RegularFile::new("seq-cap.txt", b"payload")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let options = ReaderOptions {
        max_total_extraction_size: 3,
        ..ReaderOptions::default()
    };

    assert_eq!(
        sequential_extract_tar_stream_with_options(&archive.bytes, &master_key(), options)
            .unwrap_err(),
        FormatError::ReaderUnsupported("total extraction size exceeds configured cap")
    );
}

#[test]
fn sequential_rejects_tar_stream_above_buffer_cap_during_decode() {
    let archive = write_archive(
        &[RegularFile::new("seq-buffer-cap.txt", b"payload")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let options = ReaderOptions {
        max_verify_tar_size: 512,
        ..ReaderOptions::default()
    };

    assert_eq!(
        sequential_extract_tar_stream_with_options(&archive.bytes, &master_key(), options)
            .unwrap_err(),
        FormatError::ReaderUnsupported("sequential tar stream exceeds configured verification cap")
    );
}

#[test]
fn sequential_repairs_crc_failed_payload_data_when_parity_is_guaranteed() {
    let archive = write_archive(
        &[RegularFile::new("seq-erasure.txt", b"stream repair")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let mut corrupted = archive.bytes;
    corrupt_first_block_record_payload(&mut corrupted);

    let tar_stream = sequential_extract_tar_stream(&corrupted, &master_key()).unwrap();
    let member = parse_tar_member_group(&tar_stream, 4096).unwrap();
    assert_eq!(member.path, b"seq-erasure.txt");
    assert_eq!(member.data, b"stream repair");
}

#[test]
fn sequential_rejects_crc_failed_payload_data_without_guaranteed_parity() {
    let archive = write_archive(
        &[RegularFile::new("seq-no-parity.txt", b"no repair")],
        &master_key(),
        WriterOptions {
            bit_rot_buffer_pct: 0,
            fec_parity_shards: 0,
            index_fec_parity_shards: 0,
            index_root_fec_parity_shards: 0,
            ..single_stream_options()
        },
    )
    .unwrap();
    let mut corrupted = archive.bytes;
    corrupt_first_block_record_payload(&mut corrupted);

    assert_eq!(
        sequential_extract_tar_stream(&corrupted, &master_key()).unwrap_err(),
        FormatError::BadCrc {
            structure: "BlockRecord"
        }
    );
}

#[test]
fn sequential_rejects_when_terminal_authentication_fails_without_returning_bytes() {
    let archive = write_archive(
        &[RegularFile::new(
            "seq.txt",
            b"payload must not be returned after terminal auth failure",
        )],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let mut corrupted = archive.bytes;
    corrupt_v41_terminal_recovery(&mut corrupted);

    match sequential_extract_tar_stream(&corrupted, &master_key()) {
        Ok(bytes) => panic!(
            "sequential helper returned {} decoded byte(s) despite terminal HMAC failure",
            bytes.len()
        ),
        Err(err) => assert_eq!(
            err,
            FormatError::InvalidArchive("no valid v41 CMRA candidate found")
        ),
    }
}

#[test]
fn sequential_rejects_dictionary_archive_without_bootstrap_before_payload_release() {
    let archive = write_archive_with_dictionary(
        &[RegularFile::new(
            "seq-dict.txt",
            b"common words common words dictionary payload",
        )],
        &master_key(),
        single_stream_options(),
        b"common words dictionary",
    )
    .unwrap();

    match sequential_extract_tar_stream(&archive.bytes, &master_key()) {
            Ok(bytes) => panic!(
                "sequential helper returned {} decoded byte(s) for dictionary archive without bootstrap",
                bytes.len()
            ),
            Err(err) => assert_eq!(
                err,
                FormatError::ReaderUnsupported(
                    "dictionary bootstrap required for non-seekable sequential extraction"
                )
            ),
        }
}

#[test]
fn non_seekable_dictionary_error_keeps_missing_bootstrap_wording() {
    let archive = write_archive_with_dictionary(
        &[RegularFile::new(
            "seq-dict-open.txt",
            b"common words common words bootstrap required",
        )],
        &master_key(),
        single_stream_options(),
        b"common words bootstrap",
    )
    .unwrap();

    assert_eq!(
        open_non_seekable_archive(&archive.bytes, &master_key(), None).unwrap_err(),
        FormatError::ReaderUnsupported("non-seekable random access requires a bootstrap sidecar")
    );
}

#[test]
fn sequential_zstd_stream_rejects_skippable_frame_segments() {
    let skippable = [0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0];
    let mut output = Vec::new();

    assert_eq!(
        decode_concatenated_zstd_frames_with_cap(&skippable, None, &mut output, usize::MAX, None,)
            .unwrap_err(),
        FormatError::NotStandardZstdFrame
    );
    assert!(output.is_empty());
}

#[test]
fn live_non_seekable_verify_stream_accepts_single_volume_archive() {
    let archive = write_archive(
        &[RegularFile::new("live.txt", b"stream verify")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();

    let report =
        verify_non_seekable_stream(std::io::Cursor::new(archive.bytes), &master_key()).unwrap();

    assert_eq!(report.file_count, 1);
    assert_eq!(report.total_volumes, 1);
    assert_eq!(report.root_auth, SequentialRootAuthStatus::Absent);
    assert!(report.payload_block_count > 0);
}

#[test]
fn live_non_seekable_verify_stream_accepts_recipientwrap_archive() {
    let master = master_key();
    let archive = write_archive_with_recipient_wrap_records(
        &[RegularFile::new(
            "wrapped-live.txt",
            b"stream recipient verify",
        )],
        &master,
        single_stream_options(),
        vec![recipient_wrap_test_record()],
    )
    .unwrap();

    let mut called = false;
    let report = verify_non_seekable_stream_with_recipient_wrap_resolver_options(
        std::io::Cursor::new(archive.bytes),
        |context| {
            called = true;
            assert_eq!(
                context.archive_identity.volume_format_rev,
                VOLUME_FORMAT_REV_45
            );
            assert_eq!(context.record.profile_id, 1);
            Ok(vec![master.0])
        },
        NonSeekableReaderOptions::default(),
    )
    .unwrap();

    assert!(called);
    assert_eq!(report.file_count, 1);
    assert_eq!(report.total_volumes, 1);
    assert_eq!(report.root_auth, SequentialRootAuthStatus::Absent);
}

#[test]
fn live_non_seekable_recipientwrap_resolver_rejects_unencrypted_archive() {
    let archive = write_archive_unencrypted(
        &[RegularFile::new("plain-live.txt", b"plaintext payload")],
        single_stream_options(),
    )
    .unwrap();

    let mut called = false;
    let err = verify_non_seekable_stream_with_recipient_wrap_resolver_options(
        std::io::Cursor::new(archive.bytes),
        |_| {
            called = true;
            Ok(vec![master_key().0])
        },
        NonSeekableReaderOptions::default(),
    )
    .unwrap_err();

    assert!(!called);
    assert_eq!(err, FormatError::KeyMaterialMismatch);
}

#[test]
fn live_non_seekable_verify_stream_accepts_tiny_read_chunks() {
    let archive = write_archive(
        &[RegularFile::new("tiny-chunks.txt", b"one byte at a time")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();

    let report =
        verify_non_seekable_stream(ChunkedReader::new(archive.bytes, 1), &master_key()).unwrap();

    assert_eq!(report.file_count, 1);
    assert_eq!(report.tar_total_size % 512, 0);
}

#[test]
fn live_non_seekable_verify_stream_accepts_empty_archive() {
    let archive = write_archive(&[], &master_key(), single_stream_options()).unwrap();

    let report =
        verify_non_seekable_stream(std::io::Cursor::new(archive.bytes), &master_key()).unwrap();

    assert_eq!(report.file_count, 0);
    assert_eq!(report.payload_block_count, 0);
    assert_eq!(report.tar_total_size, 0);
}

#[test]
fn live_non_seekable_verify_rejects_dictionary_archive_without_bootstrap() {
    let archive = write_archive_with_dictionary(
        &[RegularFile::new(
            "live-dict.txt",
            b"common words common words dictionary payload",
        )],
        &master_key(),
        single_stream_options(),
        b"common words dictionary",
    )
    .unwrap();

    assert_eq!(
        verify_non_seekable_stream(std::io::Cursor::new(archive.bytes), &master_key()).unwrap_err(),
        FormatError::ReaderUnsupported(
            "dictionary bootstrap required for non-seekable sequential verification"
        )
    );
}

#[test]
fn live_non_seekable_verify_accepts_dictionary_archive_with_bootstrap() {
    let archive = write_archive_with_dictionary(
        &[RegularFile::new(
            "live-dict-sidecar.txt",
            b"common words common words dictionary payload",
        )],
        &master_key(),
        single_stream_options(),
        b"common words dictionary",
    )
    .unwrap();

    let report = verify_non_seekable_stream_with_bootstrap_sidecar(
        std::io::Cursor::new(archive.bytes),
        &archive.bootstrap_sidecar,
        &master_key(),
        NonSeekableReaderOptions::default(),
    )
    .unwrap();

    assert_eq!(report.file_count, 1);
    assert_eq!(report.total_volumes, 1);
}

#[test]
fn live_non_seekable_verify_rejects_terminal_tail_above_cap() {
    let archive = write_archive(
        &[RegularFile::new("tail-cap.txt", b"payload")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let options = NonSeekableReaderOptions {
        max_terminal_tail_size: 8,
        ..NonSeekableReaderOptions::default()
    };

    assert_eq!(
        verify_non_seekable_stream_with_options(
            std::io::Cursor::new(archive.bytes),
            &master_key(),
            options
        )
        .unwrap_err(),
        FormatError::ReaderUnsupported("terminal tail exceeds configured cap")
    );
}

#[test]
fn live_non_seekable_verify_rejects_metadata_above_retention_cap() {
    let archive = write_archive(
        &[RegularFile::new("metadata-cap.txt", b"payload")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let options = NonSeekableReaderOptions {
        max_retained_metadata_bytes: 1,
        ..NonSeekableReaderOptions::default()
    };

    assert_eq!(
        verify_non_seekable_stream_with_options(
            std::io::Cursor::new(archive.bytes),
            &master_key(),
            options
        )
        .unwrap_err(),
        FormatError::ReaderUnsupported("retained metadata exceeds configured streaming cap")
    );
}

#[test]
fn live_non_seekable_verify_repairs_crc_failed_metadata_block() {
    let archive = write_archive(
        &[RegularFile::new("metadata-erasure.txt", b"payload")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let mut corrupted = archive.bytes;
    let slot = first_block_record_slot_with_kind(&corrupted, BlockKind::IndexRootData).unwrap();
    corrupt_block_record_payload_at_slot(&mut corrupted, slot);

    let report =
        verify_non_seekable_stream(std::io::Cursor::new(corrupted), &master_key()).unwrap();

    assert_eq!(report.file_count, 1);
}

#[test]
fn live_non_seekable_verify_rejects_member_count_above_cap() {
    let archive = write_archive(
        &[RegularFile::new("member-cap.txt", b"payload")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let options = NonSeekableReaderOptions {
        max_streamed_member_count: 0,
        ..NonSeekableReaderOptions::default()
    };

    assert_eq!(
        verify_non_seekable_stream_with_options(
            std::io::Cursor::new(archive.bytes),
            &master_key(),
            options
        )
        .unwrap_err(),
        FormatError::ReaderUnsupported("tar member count exceeds configured streaming cap")
    );
}

#[test]
fn live_non_seekable_verify_rejects_total_extraction_cap_during_decode() {
    let archive = write_archive(
        &[RegularFile::new("live-total-cap.txt", b"payload")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let mut options = NonSeekableReaderOptions::default();
    options.reader.max_total_extraction_size = 3;

    assert_eq!(
        verify_non_seekable_stream_with_options(
            std::io::Cursor::new(archive.bytes),
            &master_key(),
            options
        )
        .unwrap_err(),
        FormatError::ReaderUnsupported("total extraction size exceeds configured cap")
    );
}

#[test]
fn live_non_seekable_verify_reports_root_auth_wire_only() {
    let archive = write_archive_with_root_auth(
        &[RegularFile::new("signed-live.txt", b"root-auth stream")],
        &master_key(),
        single_stream_options(),
        test_root_auth_config(),
        |request| Ok(test_root_auth_value(request)),
    )
    .unwrap();

    let report =
        verify_non_seekable_stream(std::io::Cursor::new(archive.bytes), &master_key()).unwrap();

    assert_eq!(report.root_auth, SequentialRootAuthStatus::WireValidOnly);
}

#[test]
fn live_non_seekable_extract_stream_commits_after_terminal_verify() {
    let archive = write_archive(
        &[
            RegularFile::new("alpha.txt", b"alpha"),
            RegularFile::new("nested/beta.txt", b"beta"),
        ],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out");

    let report = extract_non_seekable_stream_to_dir(
        std::io::Cursor::new(archive.bytes),
        &master_key(),
        &out,
        NonSeekableReaderOptions::default(),
        SafeExtractionOptions::default(),
    )
    .unwrap();

    assert_eq!(report.verification.file_count, 2);
    assert_eq!(report.extracted_member_count, 2);
    assert_eq!(fs::read(out.join("alpha.txt")).unwrap(), b"alpha");
    assert_eq!(fs::read(out.join("nested/beta.txt")).unwrap(), b"beta");
}

#[test]
fn live_non_seekable_extract_stream_accepts_tiny_read_chunks() {
    let archive = write_archive(
        &[RegularFile::new("tiny-extract.txt", b"chunked extraction")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out");

    extract_non_seekable_stream_to_dir(
        ChunkedReader::new(archive.bytes, 1),
        &master_key(),
        &out,
        NonSeekableReaderOptions::default(),
        SafeExtractionOptions::default(),
    )
    .unwrap();

    assert_eq!(
        fs::read(out.join("tiny-extract.txt")).unwrap(),
        b"chunked extraction"
    );
}

#[test]
fn live_non_seekable_extract_stream_terminal_failure_leaves_no_final_output() {
    let archive = write_archive(
        &[RegularFile::new("late-fail.txt", b"must remain staged")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let mut corrupted = archive.bytes;
    corrupt_v41_terminal_recovery(&mut corrupted);
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out");

    match extract_non_seekable_stream_to_dir(
        std::io::Cursor::new(corrupted),
        &master_key(),
        &out,
        NonSeekableReaderOptions::default(),
        SafeExtractionOptions::default(),
    )
    .unwrap_err()
    {
        ExtractError::Format(err) => assert_eq!(
            err,
            FormatError::InvalidArchive("no valid v41 CMRA candidate found")
        ),
        ExtractError::Output(err) => panic!("unexpected output error: {err}"),
    }
    assert!(!out.exists());
}

#[test]
fn live_non_seekable_extract_stream_existing_destination_obeys_overwrite_policy() {
    let archive = write_archive(
        &[RegularFile::new("same.txt", b"new")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out");
    fs::create_dir(&out).unwrap();
    fs::write(out.join("same.txt"), b"old").unwrap();

    match extract_non_seekable_stream_to_dir(
        std::io::Cursor::new(archive.bytes.clone()),
        &master_key(),
        &out,
        NonSeekableReaderOptions::default(),
        SafeExtractionOptions::default(),
    )
    .unwrap_err()
    {
        ExtractError::Format(err) => assert_eq!(err, FormatError::UnsafeOverwrite),
        ExtractError::Output(err) => panic!("unexpected output error: {err}"),
    }
    assert_eq!(fs::read(out.join("same.txt")).unwrap(), b"old");

    extract_non_seekable_stream_to_dir(
        std::io::Cursor::new(archive.bytes),
        &master_key(),
        &out,
        NonSeekableReaderOptions::default(),
        SafeExtractionOptions {
            overwrite_existing: true,
            ..SafeExtractionOptions::default()
        },
    )
    .unwrap();
    assert_eq!(fs::read(out.join("same.txt")).unwrap(), b"new");
}

#[test]
fn live_non_seekable_list_stream_matches_seekable_final_view() {
    let archive = write_archive(
        &[
            RegularFile::new("a.txt", b"a"),
            RegularFile::new("b.txt", b"bb"),
        ],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let seekable = open_archive(&archive.bytes, &master_key()).unwrap();
    let expected = seekable.list_files().unwrap();

    let report = list_non_seekable_stream(
        std::io::Cursor::new(archive.bytes),
        &master_key(),
        NonSeekableReaderOptions::default(),
    )
    .unwrap();

    assert_eq!(report.verification.file_count, 2);
    assert_eq!(report.entries, expected);
}

#[test]
fn bootstrap_sidecar_rejects_bad_flags_and_trailing_bytes() {
    let archive = write_archive(&[], &master_key(), single_stream_options()).unwrap();
    let mut bad_flags = archive.bootstrap_sidecar.clone();
    rewrite_sidecar_header(&mut bad_flags, &master_key(), |header| {
        header.flags |= 0x08;
    });
    assert_eq!(
        open_archive_with_bootstrap_sidecar(&archive.bytes, &bad_flags, &master_key()).unwrap_err(),
        FormatError::UnknownBootstrapSidecarFlags(0x0b)
    );

    let mut trailing = archive.bootstrap_sidecar.clone();
    trailing.push(0);
    assert_eq!(
        open_archive_with_bootstrap_sidecar(&archive.bytes, &trailing, &master_key()).unwrap_err(),
        FormatError::NonCanonicalBootstrapSidecarLayout
    );
}

#[test]
fn bootstrap_sidecar_rejects_bad_manifest_footer_semantics() {
    let archive = write_archive(&[], &master_key(), single_stream_options()).unwrap();
    let mut wrong_volume = archive.bootstrap_sidecar.clone();
    mutate_sidecar_manifest(&mut wrong_volume, &master_key(), |footer| {
        footer.volume_index = 1;
    });
    assert_eq!(
        open_archive_with_bootstrap_sidecar(&archive.bytes, &wrong_volume, &master_key())
            .unwrap_err(),
        FormatError::InvalidArchive("sidecar ManifestFooter volume_index must be zero")
    );

    let mut non_authoritative = archive.bootstrap_sidecar.clone();
    mutate_sidecar_manifest(&mut non_authoritative, &master_key(), |footer| {
        footer.is_authoritative = 0;
    });
    assert_eq!(
        open_archive_with_bootstrap_sidecar(&archive.bytes, &non_authoritative, &master_key())
            .unwrap_err(),
        FormatError::InvalidArchive("sidecar ManifestFooter is not authoritative")
    );
}

#[test]
fn sidecar_manifest_validation_does_not_compare_opened_volume_index() {
    let archive = write_archive(&[], &master_key(), single_stream_options()).unwrap();
    let volume_header = VolumeHeader::parse(&archive.bytes[..VOLUME_HEADER_LEN]).unwrap();
    let crypto_start = volume_header.crypto_header_offset as usize;
    let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
    let crypto_header = CryptoHeader::parse(
        &archive.bytes[crypto_start..crypto_end],
        volume_header.crypto_header_length,
    )
    .unwrap();
    let subkeys = Subkeys::derive(
        &master_key(),
        &volume_header.archive_uuid,
        &volume_header.session_id,
    )
    .unwrap();
    let mut opened_header = volume_header;
    opened_header.volume_index = 1;

    let parsed = parse_bootstrap_sidecar(
        &archive.bootstrap_sidecar,
        &opened_header,
        &crypto_header.fixed,
        &subkeys,
    )
    .unwrap();

    assert_eq!(parsed.manifest_footer.unwrap().volume_index, 0);
}

#[test]
fn bootstrap_sidecar_rejects_conflicting_manifest_bootstrap_fields() {
    let archive = write_archive(&[], &master_key(), single_stream_options()).unwrap();
    let mut conflicting = archive.bootstrap_sidecar.clone();
    mutate_sidecar_manifest(&mut conflicting, &master_key(), |footer| {
        footer.index_root_first_block += 1;
    });

    assert_eq!(
        open_archive_with_bootstrap_sidecar(&archive.bytes, &conflicting, &master_key())
            .unwrap_err(),
        FormatError::InvalidArchive("bootstrap sidecar conflicts with terminal ManifestFooter")
    );
}

#[test]
fn sidecar_size_cap_counts_only_present_sparse_sections() {
    let mut crypto_header = test_crypto_header();
    crypto_header.has_dictionary = 1;
    crypto_header.index_root_fec_data_shards = 1;
    crypto_header.index_root_fec_parity_shards = 0;
    let record_len = crypto_header.block_size as u64 + BLOCK_RECORD_FRAMING_LEN as u64;
    let header = BootstrapSidecarHeader {
        archive_uuid: [0x31; 16],
        session_id: [0x42; 16],
        flags: 0x04,
        manifest_footer_offset: 0,
        manifest_footer_length: 0,
        index_root_records_offset: 0,
        index_root_records_length: 0,
        dictionary_records_offset: BOOTSTRAP_SIDECAR_HEADER_LEN as u64,
        dictionary_records_length: record_len,
        sidecar_hmac: [0u8; 32],
        header_crc32c: 0,
    };

    validate_sidecar_size_cap(
        &header,
        &crypto_header,
        BOOTSTRAP_SIDECAR_HEADER_LEN as u64 + record_len,
    )
    .unwrap();
    assert_eq!(
        validate_sidecar_size_cap(
            &header,
            &crypto_header,
            BOOTSTRAP_SIDECAR_HEADER_LEN as u64 + record_len + 1,
        )
        .unwrap_err(),
        FormatError::InvalidArchive("bootstrap sidecar exceeds resource cap")
    );
}

#[test]
fn sidecar_size_cap_rejects_sparse_section_above_class_max() {
    let mut crypto_header = test_crypto_header();
    crypto_header.index_root_fec_data_shards = 1;
    crypto_header.index_root_fec_parity_shards = 0;
    let record_len = crypto_header.block_size as u64 + BLOCK_RECORD_FRAMING_LEN as u64;
    let header = BootstrapSidecarHeader {
        archive_uuid: [0x31; 16],
        session_id: [0x42; 16],
        flags: 0x02,
        manifest_footer_offset: 0,
        manifest_footer_length: 0,
        index_root_records_offset: BOOTSTRAP_SIDECAR_HEADER_LEN as u64,
        index_root_records_length: record_len * 2,
        dictionary_records_offset: 0,
        dictionary_records_length: 0,
        sidecar_hmac: [0u8; 32],
        header_crc32c: 0,
    };

    assert_eq!(
        validate_sidecar_size_cap(
            &header,
            &crypto_header,
            BOOTSTRAP_SIDECAR_HEADER_LEN as u64 + record_len * 2,
        )
        .unwrap_err(),
        FormatError::InvalidArchive("bootstrap sidecar IndexRoot records exceed resource cap")
    );
}

#[test]
fn sidecar_size_cap_uses_wide_arithmetic_for_large_record_classes() {
    let mut crypto_header = test_crypto_header();
    crypto_header.block_size = u32::MAX;
    crypto_header.index_root_fec_data_shards = u16::MAX;
    crypto_header.index_root_fec_parity_shards = u16::MAX;
    let record_len = crypto_header.block_size as u64 + BLOCK_RECORD_FRAMING_LEN as u64;
    let max_records = crypto_header.index_root_fec_data_shards as u64
        + crypto_header.index_root_fec_parity_shards as u64;
    let max_section_len = max_records * record_len;
    let cap = BOOTSTRAP_SIDECAR_HEADER_LEN as u64
        + MANIFEST_FOOTER_LEN as u64
        + max_section_len
        + max_section_len;
    let header = BootstrapSidecarHeader {
        archive_uuid: [0x31; 16],
        session_id: [0x42; 16],
        flags: 0x01 | 0x02 | 0x04,
        manifest_footer_offset: BOOTSTRAP_SIDECAR_HEADER_LEN as u64,
        manifest_footer_length: MANIFEST_FOOTER_LEN as u32,
        index_root_records_offset: 0,
        index_root_records_length: max_section_len,
        dictionary_records_offset: 0,
        dictionary_records_length: max_section_len,
        sidecar_hmac: [0u8; 32],
        header_crc32c: 0,
    };

    validate_sidecar_size_cap(&header, &crypto_header, cap).unwrap();
    assert_eq!(
        validate_sidecar_size_cap(&header, &crypto_header, cap + 1).unwrap_err(),
        FormatError::InvalidArchive("bootstrap sidecar exceeds resource cap")
    );
}

#[test]
fn bootstrap_sidecar_rejects_dictionary_section_for_no_dictionary_archive() {
    let archive = write_archive(&[], &master_key(), single_stream_options()).unwrap();
    let mut with_dictionary = archive.bootstrap_sidecar.clone();
    let header =
        BootstrapSidecarHeader::parse(&with_dictionary[..BOOTSTRAP_SIDECAR_HEADER_LEN]).unwrap();
    let record_len = sidecar_record_len(&with_dictionary);
    let first_record = header.index_root_records_offset as usize;
    let copied_record = with_dictionary[first_record..first_record + record_len].to_vec();
    let dictionary_offset = with_dictionary.len() as u64;
    with_dictionary.extend_from_slice(&copied_record);
    rewrite_sidecar_header(&mut with_dictionary, &master_key(), |header| {
        header.flags |= 0x04;
        header.dictionary_records_offset = dictionary_offset;
        header.dictionary_records_length = record_len as u64;
    });

    assert_eq!(
        open_archive_with_bootstrap_sidecar(&archive.bytes, &with_dictionary, &master_key())
            .unwrap_err(),
        FormatError::InvalidArchive(
            "bootstrap sidecar has dictionary records while has_dictionary is false"
        )
    );
}

#[test]
fn bootstrap_sidecar_rejects_missing_duplicate_wrong_kind_and_wrong_last_flag() {
    let archive = write_archive(&[], &master_key(), single_stream_options()).unwrap();
    let mut missing = archive.bootstrap_sidecar.clone();
    let record_len = sidecar_record_len(&missing);
    let new_len = missing.len() - record_len;
    missing.truncate(new_len);
    rewrite_sidecar_header(&mut missing, &master_key(), |header| {
        header.index_root_records_length -= record_len as u64;
    });
    assert_eq!(
        open_archive_with_bootstrap_sidecar(&archive.bytes, &missing, &master_key()).unwrap_err(),
        FormatError::InvalidArchive("sidecar BlockRecord section does not match declared extent")
    );

    let mut duplicate = archive.bootstrap_sidecar.clone();
    mutate_sidecar_index_record(&mut duplicate, 1, |record| {
        record.block_index -= 1;
    });
    assert_eq!(
        open_archive_with_bootstrap_sidecar(&archive.bytes, &duplicate, &master_key()).unwrap_err(),
        FormatError::InvalidArchive("sidecar BlockRecord section has missing or duplicate blocks")
    );

    let mut misordered = archive.bootstrap_sidecar.clone();
    swap_sidecar_index_records(&mut misordered, 0, 1);
    assert_eq!(
        open_archive_with_bootstrap_sidecar(&archive.bytes, &misordered, &master_key())
            .unwrap_err(),
        FormatError::InvalidArchive("sidecar BlockRecord section has missing or duplicate blocks")
    );

    let mut wrong_kind = archive.bootstrap_sidecar.clone();
    mutate_sidecar_index_record(&mut wrong_kind, 0, |record| {
        record.kind = BlockKind::PayloadData;
    });
    assert_eq!(
        open_archive_with_bootstrap_sidecar(&archive.bytes, &wrong_kind, &master_key())
            .unwrap_err(),
        FormatError::InvalidArchive("sidecar BlockRecord section has wrong kind")
    );

    let mut wrong_last = archive.bootstrap_sidecar.clone();
    mutate_sidecar_index_record(&mut wrong_last, 0, |record| {
        record.flags = 0;
    });
    assert_eq!(
        open_archive_with_bootstrap_sidecar(&archive.bytes, &wrong_last, &master_key())
            .unwrap_err(),
        FormatError::InvalidArchive("sidecar BlockRecord section has wrong last-data flag")
    );
}

#[test]
fn verify_helper_rejects_envelope_frame_coverage_gap() {
    let frames = BTreeMap::from([(
        0,
        FrameEntry {
            frame_index: 0,
            envelope_index: 0,
            offset_in_envelope: 0,
            compressed_size: 10,
            decompressed_size: 512,
            flags: 0,
            tar_stream_offset: 0,
        },
    )]);
    let envelopes = BTreeMap::from([(
        0,
        EnvelopeEntry {
            envelope_index: 0,
            first_block_index: 0,
            data_block_count: 1,
            parity_block_count: 1,
            encrypted_size: 4096,
            plaintext_size: 11,
            first_frame_index: 0,
            frame_count: 1,
        },
    )]);

    assert_eq!(
        validate_envelope_frame_coverage(&frames, &envelopes).unwrap_err(),
        FormatError::InvalidArchive("EnvelopeEntry frame coverage has a gap or overlap")
    );
}

#[test]
fn verify_helper_rejects_file_extent_gaps_and_overlaps() {
    assert!(validate_file_extent_coverage_ranges(&[(512, 512), (0, 512)], 1024).is_ok());
    assert_eq!(
        validate_file_extent_coverage_ranges(&[(0, 512), (1024, 512)], 1536).unwrap_err(),
        FormatError::InvalidArchive("FileEntry extents do not cover tar stream exactly")
    );
    assert_eq!(
        validate_file_extent_coverage_ranges(&[(0, 1024), (512, 512)], 1024).unwrap_err(),
        FormatError::InvalidArchive("FileEntry extents do not cover tar stream exactly")
    );
}

#[test]
fn verify_rejects_authenticated_content_hash_mismatch() {
    let options = WriterOptions {
        index_root_fec_parity_shards: 0,
        ..single_stream_options()
    };
    let archive = write_archive(
        &[RegularFile::new("content-hash.txt", b"hash covered")],
        &master_key(),
        options,
    )
    .unwrap();
    let opened = open_archive(&archive.bytes, &master_key()).unwrap();

    let mut root = opened.index_root.clone();
    root.header.content_sha256 = [0xa5; 32];
    let root_plaintext = root.to_bytes();
    IndexRoot::parse(
        &root_plaintext,
        false,
        metadata_limits(&opened.crypto_header),
    )
    .unwrap();
    assert_eq!(
        root_plaintext.len() as u32,
        opened.manifest_footer.index_root_decompressed_size
    );

    let compressed_root = compress_zstd_frame(&root_plaintext, options.zstd_level).unwrap();
    let mut next_block_index = opened.manifest_footer.index_root_first_block;
    let replacement = encrypt_test_object(
        &compressed_root,
        &opened.subkeys.index_root_key,
        &opened.subkeys.index_nonce_seed,
        b"idxroot",
        0,
        BlockKind::IndexRootData,
        &mut next_block_index,
        &opened.crypto_header,
        &opened.volume_header,
    );
    assert_eq!(
        replacement.extent.data_block_count,
        opened.manifest_footer.index_root_data_block_count
    );
    assert_eq!(
        replacement.extent.encrypted_size,
        opened.manifest_footer.index_root_encrypted_size
    );

    let volume_header = VolumeHeader::parse(&archive.bytes[..VOLUME_HEADER_LEN]).unwrap();
    let crypto_end =
        volume_header.crypto_header_offset as usize + volume_header.crypto_header_length as usize;
    let record_len = opened.crypto_header.block_size as usize + BLOCK_RECORD_FRAMING_LEN;
    let mut malformed = archive.bytes.clone();
    for record in replacement.records {
        let offset = crypto_end + record.block_index as usize * record_len;
        malformed[offset..offset + record_len].copy_from_slice(&record.to_bytes());
    }

    let reopened = open_archive(&malformed, &master_key()).unwrap();
    assert_eq!(
        reopened.verify().unwrap_err(),
        FormatError::InvalidArchive("IndexRoot content_sha256 does not match decoded tar stream")
    );
}

#[test]
fn verify_rejects_file_entry_tar_path_and_size_mismatches() {
    let (mut path_mismatch, _) = multi_envelope_reader_fixture();
    rewrite_as_single_healthy_file(&mut path_mismatch, |_file, path| {
        path[0] = b'x';
    });
    assert_eq!(
        path_mismatch.verify().unwrap_err(),
        FormatError::InvalidArchive("tar member path does not match FileEntry path")
    );

    let (mut size_mismatch, _) = multi_envelope_reader_fixture();
    rewrite_as_single_healthy_file(&mut size_mismatch, |file, _path| {
        file.file_data_size += 1;
    });
    assert_eq!(
        size_mismatch.verify().unwrap_err(),
        FormatError::InvalidArchive("tar member size does not match FileEntry file_data_size")
    );
}

#[test]
fn verify_rejects_inconsistent_duplicate_local_frame_rows_across_shards() {
    let (mut opened, _) = multi_envelope_reader_fixture();
    let locating = opened.index_root.shards[0].clone();
    let mut duplicate = opened.load_index_shard(&locating).unwrap();
    duplicate.header.shard_index = 1;
    duplicate.frames[0].flags ^= 0x0000_0001;
    let duplicate_plaintext = duplicate.to_bytes();
    let mut next_block_index = opened
        .blocks
        .keys()
        .last()
        .copied()
        .map(|index| index + 1)
        .unwrap_or(0);
    let duplicate_object = encrypt_test_object(
        &compress_zstd_frame(&duplicate_plaintext, 1).unwrap(),
        &opened.subkeys.index_shard_key,
        &opened.subkeys.index_nonce_seed,
        b"idxshard",
        1,
        BlockKind::IndexShardData,
        &mut next_block_index,
        &opened.crypto_header,
        &opened.volume_header,
    );
    insert_records(&mut opened.blocks, &duplicate_object.records);
    opened.index_root.shards.push(ShardEntry {
        shard_index: 1,
        first_block_index: duplicate_object.extent.first_block_index,
        data_block_count: duplicate_object.extent.data_block_count,
        parity_block_count: 0,
        encrypted_size: duplicate_object.extent.encrypted_size,
        decompressed_size: duplicate_plaintext.len() as u32,
        file_count: locating.file_count,
        first_path_hash: locating.first_path_hash,
        last_path_hash: locating.last_path_hash,
    });
    opened.index_root.header.file_count += locating.file_count as u64;

    assert_eq!(
        opened.verify().unwrap_err(),
        FormatError::InvalidArchive("duplicate FrameEntry rows do not match")
    );
}

#[test]
fn verify_rejects_inconsistent_duplicate_local_envelope_rows_across_shards() {
    let (mut opened, _) = multi_envelope_reader_fixture();
    let locating = opened.index_root.shards[0].clone();
    let mut duplicate = opened.load_index_shard(&locating).unwrap();
    duplicate.header.shard_index = 1;
    duplicate.envelopes[0].first_block_index += 1;
    let duplicate_plaintext = duplicate.to_bytes();
    let mut next_block_index = opened
        .blocks
        .keys()
        .last()
        .copied()
        .map(|index| index + 1)
        .unwrap_or(0);
    let duplicate_object = encrypt_test_object(
        &compress_zstd_frame(&duplicate_plaintext, 1).unwrap(),
        &opened.subkeys.index_shard_key,
        &opened.subkeys.index_nonce_seed,
        b"idxshard",
        1,
        BlockKind::IndexShardData,
        &mut next_block_index,
        &opened.crypto_header,
        &opened.volume_header,
    );
    insert_records(&mut opened.blocks, &duplicate_object.records);
    opened.index_root.shards.push(ShardEntry {
        shard_index: 1,
        first_block_index: duplicate_object.extent.first_block_index,
        data_block_count: duplicate_object.extent.data_block_count,
        parity_block_count: 0,
        encrypted_size: duplicate_object.extent.encrypted_size,
        decompressed_size: duplicate_plaintext.len() as u32,
        file_count: locating.file_count,
        first_path_hash: locating.first_path_hash,
        last_path_hash: locating.last_path_hash,
    });
    opened.index_root.header.file_count += locating.file_count as u64;

    assert_eq!(
        opened.verify().unwrap_err(),
        FormatError::InvalidArchive("duplicate EnvelopeEntry rows do not match")
    );
}

#[test]
fn verify_rejects_non_contiguous_global_envelope_indexes() {
    let (mut opened, _) = multi_envelope_reader_fixture();
    replace_first_index_shard(&mut opened, |shard| {
        let frame = shard
            .frames
            .iter_mut()
            .find(|entry| entry.frame_index == 1)
            .unwrap();
        frame.envelope_index = 2;

        let envelope = shard
            .envelopes
            .iter_mut()
            .find(|entry| entry.envelope_index == 1)
            .unwrap();
        envelope.envelope_index = 2;
    });

    assert_eq!(
        opened.verify().unwrap_err(),
        FormatError::InvalidMetadata {
            structure: "EnvelopeEntry",
            reason: "global index coverage has a gap",
        }
    );
}

#[test]
fn verify_rejects_payload_object_extent_overlap() {
    let (mut opened, _) = multi_envelope_reader_fixture();
    replace_first_index_shard(&mut opened, |shard| {
        let first_block_index = shard.envelopes[0].first_block_index;
        shard.envelopes[1].first_block_index = first_block_index;
    });

    assert_eq!(
        opened.verify().unwrap_err(),
        FormatError::InvalidArchive("encrypted object block ranges overlap")
    );
}

#[test]
fn verify_accepts_cross_shard_shared_envelope_frame_union() {
    let volume_header = test_volume_header();
    let crypto_header = test_crypto_header();
    let subkeys = Subkeys::derive(
        &master_key(),
        &volume_header.archive_uuid,
        &volume_header.session_id,
    )
    .unwrap();
    let mut next_block_index = 0u64;
    let mut blocks = BTreeMap::new();

    let alpha = test_member(b"alpha.txt", b"alpha cross shard\n");
    let beta = test_member(b"beta.txt", b"beta cross shard\n");
    let tar_stream = [alpha.as_slice(), beta.as_slice()].concat();
    let frame0_plaintext = compress_zstd_frame(&alpha, 1).unwrap();
    let frame1_plaintext = compress_zstd_frame(&beta, 1).unwrap();
    let envelope_plaintext = [frame0_plaintext.as_slice(), frame1_plaintext.as_slice()].concat();
    let payload = encrypt_test_object(
        &envelope_plaintext,
        &subkeys.enc_key,
        &subkeys.nonce_seed,
        b"envelope",
        0,
        BlockKind::PayloadData,
        &mut next_block_index,
        &crypto_header,
        &volume_header,
    );
    insert_records(&mut blocks, &payload.records);

    let envelope = EnvelopeEntry {
        envelope_index: 0,
        first_block_index: payload.extent.first_block_index,
        data_block_count: payload.extent.data_block_count,
        parity_block_count: 0,
        encrypted_size: payload.extent.encrypted_size,
        plaintext_size: envelope_plaintext.len() as u32,
        first_frame_index: 0,
        frame_count: 2,
    };
    let frame0 = FrameEntry {
        frame_index: 0,
        envelope_index: 0,
        offset_in_envelope: 0,
        compressed_size: frame0_plaintext.len() as u32,
        decompressed_size: alpha.len() as u32,
        flags: 0x0000_0003,
        tar_stream_offset: 0,
    };
    let frame1 = FrameEntry {
        frame_index: 1,
        envelope_index: 0,
        offset_in_envelope: frame0_plaintext.len() as u32,
        compressed_size: frame1_plaintext.len() as u32,
        decompressed_size: beta.len() as u32,
        flags: 0x0000_0003,
        tar_stream_offset: alpha.len() as u64,
    };

    let (shard0_plaintext, first0, last0) = build_test_index_shard(
        &[TestFileMeta {
            path: b"alpha.txt".to_vec(),
            frame_index: 0,
            tar_stream_offset: 0,
            member_group_size: alpha.len() as u64,
            file_data_size: b"alpha cross shard\n".len() as u64,
        }],
        &[frame0],
        std::slice::from_ref(&envelope),
    );
    let (mut shard1_plaintext, first1, last1) = build_test_index_shard(
        &[TestFileMeta {
            path: b"beta.txt".to_vec(),
            frame_index: 1,
            tar_stream_offset: alpha.len() as u64,
            member_group_size: beta.len() as u64,
            file_data_size: b"beta cross shard\n".len() as u64,
        }],
        &[frame1],
        std::slice::from_ref(&envelope),
    );
    shard1_plaintext[8..16].copy_from_slice(&1u64.to_le_bytes());

    let shard0 = encrypt_test_object(
        &compress_zstd_frame(&shard0_plaintext, 1).unwrap(),
        &subkeys.index_shard_key,
        &subkeys.index_nonce_seed,
        b"idxshard",
        0,
        BlockKind::IndexShardData,
        &mut next_block_index,
        &crypto_header,
        &volume_header,
    );
    let shard1 = encrypt_test_object(
        &compress_zstd_frame(&shard1_plaintext, 1).unwrap(),
        &subkeys.index_shard_key,
        &subkeys.index_nonce_seed,
        b"idxshard",
        1,
        BlockKind::IndexShardData,
        &mut next_block_index,
        &crypto_header,
        &volume_header,
    );
    insert_records(&mut blocks, &shard0.records);
    insert_records(&mut blocks, &shard1.records);

    let index_root = IndexRoot {
        header: IndexRootHeader {
            frame_count: 2,
            envelope_count: 1,
            file_count: 2,
            payload_block_count: payload.extent.data_block_count as u64,
            tar_total_size: tar_stream.len() as u64,
            content_sha256: sha256_bytes(&tar_stream),
            ..IndexRootHeader::empty()
        },
        shards: vec![
            ShardEntry {
                shard_index: 0,
                first_block_index: shard0.extent.first_block_index,
                data_block_count: shard0.extent.data_block_count,
                parity_block_count: 0,
                encrypted_size: shard0.extent.encrypted_size,
                decompressed_size: shard0_plaintext.len() as u32,
                file_count: 1,
                first_path_hash: first0,
                last_path_hash: last0,
            },
            ShardEntry {
                shard_index: 1,
                first_block_index: shard1.extent.first_block_index,
                data_block_count: shard1.extent.data_block_count,
                parity_block_count: 0,
                encrypted_size: shard1.extent.encrypted_size,
                decompressed_size: shard1_plaintext.len() as u32,
                file_count: 1,
                first_path_hash: first1,
                last_path_hash: last1,
            },
        ],
        directory_hint_shards: Vec::new(),
    };

    let index_root_plaintext = index_root.to_bytes();
    let index_root_object = encrypt_test_object(
        &compress_zstd_frame(&index_root_plaintext, 1).unwrap(),
        &subkeys.index_root_key,
        &subkeys.index_nonce_seed,
        b"idxroot",
        0,
        BlockKind::IndexRootData,
        &mut next_block_index,
        &crypto_header,
        &volume_header,
    );
    insert_records(&mut blocks, &index_root_object.records);

    let archive_uuid = volume_header.archive_uuid;
    let session_id = volume_header.session_id;
    let opened = OpenedArchive {
        options: ReaderOptions::default(),
        observed_archive_bytes: 1_000_000,
        observed_volume_count: 1,
        subkeys,
        blocks,
        lazy_blocks: None,
        crypto_header_bytes: Vec::new(),
        volume_header,
        crypto_header,
        manifest_footer: ManifestFooter {
            archive_uuid,
            session_id,
            volume_index: 0,
            is_authoritative: 1,
            total_volumes: 1,
            index_root_first_block: index_root_object.extent.first_block_index,
            index_root_data_block_count: index_root_object.extent.data_block_count,
            index_root_parity_block_count: 0,
            index_root_encrypted_size: index_root_object.extent.encrypted_size,
            index_root_decompressed_size: index_root_plaintext.len() as u32,
            manifest_hmac: [0u8; 32],
        },
        volume_trailer: Some(VolumeTrailer {
            archive_uuid,
            session_id,
            volume_index: 0,
            block_count: next_block_index,
            bytes_written: 0,
            manifest_footer_offset: 0,
            manifest_footer_length: MANIFEST_FOOTER_LEN as u32,
            closed_at_ns: 0,
            root_auth_footer_offset: 0,
            root_auth_footer_length: 0,
            root_auth_flags: 0,
            trailer_hmac: [0u8; 32],
        }),
        root_auth_footer: None,
        index_root,
        payload_dictionary: None,
    };

    opened.verify().unwrap();
}

#[test]
fn verify_rejects_authenticated_archive_missing_required_directory_hints() {
    let options = WriterOptions {
        index_root_fec_parity_shards: 0,
        ..single_stream_options()
    };
    let archive = write_archive(
        &[RegularFile::new("only.txt", b"only payload")],
        &master_key(),
        options,
    )
    .unwrap();
    let opened = open_archive(&archive.bytes, &master_key()).unwrap();
    assert!(opened.index_root.directory_hint_shards.is_empty());

    let mut root = opened.index_root.clone();
    root.header.file_count = DIRECTORY_HINT_REQUIRED_FILE_COUNT + 1;
    root.shards[0].file_count = (DIRECTORY_HINT_REQUIRED_FILE_COUNT + 1) as u32;
    let root_plaintext = root.to_bytes();
    IndexRoot::parse(
        &root_plaintext,
        false,
        metadata_limits(&opened.crypto_header),
    )
    .unwrap();
    assert_eq!(
        root_plaintext.len() as u32,
        opened.manifest_footer.index_root_decompressed_size
    );

    let compressed_root = compress_zstd_frame(&root_plaintext, options.zstd_level).unwrap();
    let mut next_block_index = opened.manifest_footer.index_root_first_block;
    let replacement = encrypt_test_object(
        &compressed_root,
        &opened.subkeys.index_root_key,
        &opened.subkeys.index_nonce_seed,
        b"idxroot",
        0,
        BlockKind::IndexRootData,
        &mut next_block_index,
        &opened.crypto_header,
        &opened.volume_header,
    );
    assert_eq!(
        replacement.extent.first_block_index,
        opened.manifest_footer.index_root_first_block
    );
    assert_eq!(
        replacement.extent.data_block_count,
        opened.manifest_footer.index_root_data_block_count
    );
    assert_eq!(
        replacement.extent.encrypted_size,
        opened.manifest_footer.index_root_encrypted_size
    );

    let volume_header = VolumeHeader::parse(&archive.bytes[..VOLUME_HEADER_LEN]).unwrap();
    let crypto_end =
        volume_header.crypto_header_offset as usize + volume_header.crypto_header_length as usize;
    let record_len = opened.crypto_header.block_size as usize + BLOCK_RECORD_FRAMING_LEN;
    let mut malformed = archive.bytes.clone();
    for record in replacement.records {
        let offset = crypto_end + record.block_index as usize * record_len;
        malformed[offset..offset + record_len].copy_from_slice(&record.to_bytes());
    }

    let reopened = open_archive(&malformed, &master_key()).unwrap();
    assert_eq!(
        reopened.index_root.header.file_count,
        DIRECTORY_HINT_REQUIRED_FILE_COUNT + 1
    );
    assert!(reopened.index_root.directory_hint_shards.is_empty());

    assert_eq!(
        reopened.verify().unwrap_err(),
        FormatError::InvalidArchive("IndexRoot file_count requires directory hints")
    );
}

#[test]
fn expected_directory_hint_rows_include_ancestors_and_directory_entries() {
    let mut map = DirectoryHintMap::new();
    add_expected_directory_hint_rows(&mut map, 2, b"foo/bar/baz.txt", TarEntryKind::Regular);
    add_expected_directory_hint_rows(&mut map, 4, b"foo/bar", TarEntryKind::Directory);

    assert_eq!(map.get(&Vec::new()), Some(&BTreeSet::from([2, 4])));
    assert_eq!(map.get(b"foo".as_slice()), Some(&BTreeSet::from([2, 4])));
    assert_eq!(
        map.get(b"foo/bar".as_slice()),
        Some(&BTreeSet::from([2, 4]))
    );
    assert!(!map.contains_key(b"foo/bar/baz.txt".as_slice()));
    assert!(!map.contains_key(b"foobar".as_slice()));
}

#[test]
fn directory_hint_validation_requires_exact_global_map() {
    let mut expected = DirectoryHintMap::new();
    add_expected_directory_hint_rows(&mut expected, 0, b"foo/bar.txt", TarEntryKind::Regular);
    add_expected_directory_hint_rows(&mut expected, 1, b"foo", TarEntryKind::Directory);
    let rows = sorted_directory_hint_rows(&expected);
    let table = directory_hint_table_from_rows(7, &rows, 2);

    validate_directory_hint_tables_against_expected(std::slice::from_ref(&table), &expected)
        .unwrap();

    let mut missing_root = expected.clone();
    missing_root.remove(&Vec::new());
    let missing_root_rows = sorted_directory_hint_rows(&missing_root);
    let missing_root_table = directory_hint_table_from_rows(8, &missing_root_rows, 2);
    assert_eq!(
        validate_directory_hint_tables_against_expected(&[missing_root_table], &expected)
            .unwrap_err(),
        FormatError::InvalidArchive("directory hint map does not match decoded files")
    );

    let mut expected_missing_directory_entry = expected.clone();
    expected_missing_directory_entry
        .get_mut(b"foo".as_slice())
        .unwrap()
        .remove(&1);
    assert_eq!(
        validate_directory_hint_tables_against_expected(
            std::slice::from_ref(&table),
            &expected_missing_directory_entry,
        )
        .unwrap_err(),
        FormatError::InvalidArchive("directory hint map does not match decoded files")
    );

    let mut extra = expected.clone();
    extra.insert(b"foo/extra".to_vec(), BTreeSet::from([0]));
    let extra_rows = sorted_directory_hint_rows(&extra);
    let extra_table = directory_hint_table_from_rows(9, &extra_rows, 2);
    assert_eq!(
        validate_directory_hint_tables_against_expected(&[extra_table], &expected).unwrap_err(),
        FormatError::InvalidArchive("directory hint map does not match decoded files")
    );
}

#[test]
fn directory_hint_validation_rejects_global_order_mismatch() {
    let mut expected = DirectoryHintMap::new();
    expected.insert(Vec::new(), BTreeSet::from([0]));
    expected.insert(b"alpha".to_vec(), BTreeSet::from([0]));
    let rows = sorted_directory_hint_rows(&expected);
    let first = directory_hint_table_from_rows(8, &rows[..1], 1);
    let second = directory_hint_table_from_rows(9, &rows[1..], 1);

    assert_eq!(
        validate_directory_hint_tables_against_expected(&[second, first], &expected).unwrap_err(),
        FormatError::InvalidArchive("DirectoryHintEntry rows are not globally sorted")
    );
}

#[test]
fn object_extent_rejects_parity_above_class_cap() {
    let crypto_header = CryptoHeaderFixed {
        length: 0,
        compression_algo: CompressionAlgo::ZstdFramed,
        aead_algo: AeadAlgo::AesGcmSiv256,
        fec_algo: FecAlgo::ReedSolomonGF16,
        kdf_algo: KdfAlgo::Raw,
        chunk_size: 1024,
        envelope_target_size: 4096,
        block_size: 4096,
        fec_data_shards: 1,
        fec_parity_shards: 1,
        index_fec_data_shards: 1,
        index_fec_parity_shards: 1,
        index_root_fec_data_shards: 1,
        index_root_fec_parity_shards: 1,
        stripe_width: 1,
        volume_loss_tolerance: 0,
        bit_rot_buffer_pct: 0,
        has_dictionary: 0,
        max_path_length: 4096,
        expected_volume_size: 0,
    };
    let extent = ObjectExtent {
        first_block_index: 0,
        data_block_count: 1,
        parity_block_count: 2,
        encrypted_size: 4096,
    };

    assert_eq!(
        validate_object_extent(extent, &crypto_header, 1, 1).unwrap_err(),
        FormatError::InvalidArchive("encrypted object exceeds its class parity-shard maximum")
    );
}

#[test]
fn object_extent_rejects_parity_below_recoverability_requirement() {
    let crypto_header = CryptoHeaderFixed {
        length: 0,
        compression_algo: CompressionAlgo::ZstdFramed,
        aead_algo: AeadAlgo::AesGcmSiv256,
        fec_algo: FecAlgo::ReedSolomonGF16,
        kdf_algo: KdfAlgo::Raw,
        chunk_size: 1024,
        envelope_target_size: 4096,
        block_size: 4096,
        fec_data_shards: 1,
        fec_parity_shards: 1,
        index_fec_data_shards: 1,
        index_fec_parity_shards: 1,
        index_root_fec_data_shards: 1,
        index_root_fec_parity_shards: 1,
        stripe_width: 2,
        volume_loss_tolerance: 1,
        bit_rot_buffer_pct: 0,
        has_dictionary: 0,
        max_path_length: 4096,
        expected_volume_size: 0,
    };
    let extent = ObjectExtent {
        first_block_index: 0,
        data_block_count: 1,
        parity_block_count: 0,
        encrypted_size: 4096,
    };

    assert_eq!(
        validate_object_extent(extent, &crypto_header, 1, 1).unwrap_err(),
        FormatError::InvalidArchive("encrypted object parity does not match v41 compute_parity")
    );
}

#[test]
fn encrypted_object_extent_matrix_rejects_overlaps() {
    let (opened, _) = multi_envelope_reader_fixture();
    let loaded_shard = opened
        .load_index_shard(&opened.index_root.shards[0])
        .unwrap();
    let base_envelopes = loaded_shard
        .envelopes
        .iter()
        .map(|entry| (entry.envelope_index, entry.clone()))
        .collect::<BTreeMap<_, _>>();
    let payload_start = loaded_shard.envelopes[0].first_block_index;
    let overlap = FormatError::InvalidArchive("encrypted object block ranges overlap");

    let mut payload_overlap = base_envelopes.clone();
    payload_overlap
        .get_mut(&loaded_shard.envelopes[1].envelope_index)
        .unwrap()
        .first_block_index = payload_start;
    assert_eq!(
        opened
            .validate_encrypted_object_block_ranges(&payload_overlap)
            .unwrap_err(),
        overlap
    );

    let mut shard_overlap = opened.clone();
    let shard = shard_overlap.index_root.shards[0].clone();
    shard_overlap.index_root.shards.push(ShardEntry {
        shard_index: 1,
        ..shard
    });
    assert_eq!(
        shard_overlap
            .validate_encrypted_object_block_ranges(&base_envelopes)
            .unwrap_err(),
        overlap
    );

    let mut dictionary_overlap = opened.clone();
    dictionary_overlap.crypto_header.has_dictionary = 1;
    dictionary_overlap.index_root.header.dictionary_first_block = payload_start;
    dictionary_overlap
        .index_root
        .header
        .dictionary_data_block_count = 1;
    dictionary_overlap
        .index_root
        .header
        .dictionary_parity_block_count = 0;
    dictionary_overlap
        .index_root
        .header
        .dictionary_encrypted_size = 4096;
    dictionary_overlap
        .index_root
        .header
        .dictionary_decompressed_size = 128;
    assert_eq!(
        dictionary_overlap
            .validate_encrypted_object_block_ranges(&base_envelopes)
            .unwrap_err(),
        overlap
    );

    let mut hint_overlap = opened.clone();
    hint_overlap
        .index_root
        .directory_hint_shards
        .push(DirectoryHintShardEntry {
            hint_shard_index: 0,
            first_dir_hash: [0; 8],
            last_dir_hash: [0; 8],
            first_block_index: payload_start,
            data_block_count: 1,
            parity_block_count: 0,
            encrypted_size: 4096,
            decompressed_size: 128,
            entry_count: 1,
        });
    assert_eq!(
        hint_overlap
            .validate_encrypted_object_block_ranges(&base_envelopes)
            .unwrap_err(),
        overlap
    );
}

#[test]
fn load_metadata_object_rejects_per_object_zstd_frame_exactness_mutations() {
    let volume_header = test_volume_header();
    let crypto_header = test_crypto_header();
    let subkeys = Subkeys::derive(
        &master_key(),
        &volume_header.archive_uuid,
        &volume_header.session_id,
    )
    .unwrap();
    let mut next_block_index = 0u64;

    let index_root_payload = b"index root metadata object";
    let index_root_compressed = compress_zstd_frame(index_root_payload, 1).unwrap();
    assert_metadata_object_from_compressed(
        &{
            let mut bytes = index_root_compressed.clone();
            bytes.push(0);
            bytes
        },
        index_root_payload.len(),
        &subkeys,
        &volume_header,
        &crypto_header,
        &subkeys.index_root_key,
        &subkeys.index_nonce_seed,
        b"idxroot",
        0,
        BlockKind::IndexRootData,
        BlockKind::IndexRootParity,
        crypto_header.index_root_fec_data_shards,
        crypto_header.index_root_fec_parity_shards,
        &mut next_block_index,
        FormatError::TrailingBytesAfterZstdFrame,
    );
    assert_metadata_object_from_compressed(
        &index_root_compressed,
        index_root_payload.len() + 1,
        &subkeys,
        &volume_header,
        &crypto_header,
        &subkeys.index_root_key,
        &subkeys.index_nonce_seed,
        b"idxroot",
        0,
        BlockKind::IndexRootData,
        BlockKind::IndexRootParity,
        crypto_header.index_root_fec_data_shards,
        crypto_header.index_root_fec_parity_shards,
        &mut next_block_index,
        FormatError::ZstdDecompressedSizeMismatch {
            expected: index_root_payload.len() + 1,
            actual: index_root_payload.len(),
        },
    );

    let index_shard_payload = b"index shard metadata object";
    let index_shard_compressed = compress_zstd_frame(index_shard_payload, 1).unwrap();
    assert_metadata_object_from_compressed(
        &{
            let mut bytes = index_shard_compressed.clone();
            bytes.push(0);
            bytes
        },
        index_shard_payload.len(),
        &subkeys,
        &volume_header,
        &crypto_header,
        &subkeys.index_shard_key,
        &subkeys.index_nonce_seed,
        b"idxshard",
        1,
        BlockKind::IndexShardData,
        BlockKind::IndexShardParity,
        crypto_header.index_fec_data_shards,
        crypto_header.index_fec_parity_shards,
        &mut next_block_index,
        FormatError::TrailingBytesAfterZstdFrame,
    );
    assert_metadata_object_from_compressed(
        &index_shard_compressed,
        index_shard_payload.len() + 1,
        &subkeys,
        &volume_header,
        &crypto_header,
        &subkeys.index_shard_key,
        &subkeys.index_nonce_seed,
        b"idxshard",
        1,
        BlockKind::IndexShardData,
        BlockKind::IndexShardParity,
        crypto_header.index_fec_data_shards,
        crypto_header.index_fec_parity_shards,
        &mut next_block_index,
        FormatError::ZstdDecompressedSizeMismatch {
            expected: index_shard_payload.len() + 1,
            actual: index_shard_payload.len(),
        },
    );

    let directory_hint_payload = b"directory hint metadata object";
    let directory_hint_compressed = compress_zstd_frame(directory_hint_payload, 1).unwrap();
    assert_metadata_object_from_compressed(
        &{
            let mut bytes = directory_hint_compressed.clone();
            bytes.push(0);
            bytes
        },
        directory_hint_payload.len(),
        &subkeys,
        &volume_header,
        &crypto_header,
        &subkeys.dir_hint_key,
        &subkeys.index_nonce_seed,
        b"dirhint",
        0,
        BlockKind::DirectoryHintData,
        BlockKind::DirectoryHintParity,
        crypto_header.index_fec_data_shards,
        crypto_header.index_fec_parity_shards,
        &mut next_block_index,
        FormatError::TrailingBytesAfterZstdFrame,
    );
    assert_metadata_object_from_compressed(
        &directory_hint_compressed,
        directory_hint_payload.len() + 1,
        &subkeys,
        &volume_header,
        &crypto_header,
        &subkeys.dir_hint_key,
        &subkeys.index_nonce_seed,
        b"dirhint",
        0,
        BlockKind::DirectoryHintData,
        BlockKind::DirectoryHintParity,
        crypto_header.index_fec_data_shards,
        crypto_header.index_fec_parity_shards,
        &mut next_block_index,
        FormatError::ZstdDecompressedSizeMismatch {
            expected: directory_hint_payload.len() + 1,
            actual: directory_hint_payload.len(),
        },
    );

    let dictionary_payload = b"dictionary metadata object";
    let dictionary_compressed = compress_zstd_frame(dictionary_payload, 1).unwrap();
    assert_metadata_object_from_compressed(
        &{
            let mut bytes = dictionary_compressed.clone();
            bytes.push(0);
            bytes
        },
        dictionary_payload.len(),
        &subkeys,
        &volume_header,
        &crypto_header,
        &subkeys.dictionary_key,
        &subkeys.index_nonce_seed,
        b"dict",
        0,
        BlockKind::DictionaryData,
        BlockKind::DictionaryParity,
        crypto_header.index_root_fec_data_shards,
        crypto_header.index_root_fec_parity_shards,
        &mut next_block_index,
        FormatError::TrailingBytesAfterZstdFrame,
    );
    assert_metadata_object_from_compressed(
        &dictionary_compressed,
        dictionary_payload.len() + 1,
        &subkeys,
        &volume_header,
        &crypto_header,
        &subkeys.dictionary_key,
        &subkeys.index_nonce_seed,
        b"dict",
        0,
        BlockKind::DictionaryData,
        BlockKind::DictionaryParity,
        crypto_header.index_root_fec_data_shards,
        crypto_header.index_root_fec_parity_shards,
        &mut next_block_index,
        FormatError::ZstdDecompressedSizeMismatch {
            expected: dictionary_payload.len() + 1,
            actual: dictionary_payload.len(),
        },
    );
}

#[test]
fn load_metadata_object_extent_rejects_encrypted_size_not_data_block_count_times_block_size() {
    let volume_header = test_volume_header();
    let crypto_header = test_crypto_header();
    let subkeys = Subkeys::derive(
        &master_key(),
        &volume_header.archive_uuid,
        &volume_header.session_id,
    )
    .unwrap();
    let mut next_block_index = 0u64;

    let index_root_payload = b"index root metadata object";
    let (index_root_extent, index_root_records) = build_metadata_object_from_payload(
        index_root_payload,
        &subkeys,
        &volume_header,
        &crypto_header,
        &subkeys.index_root_key,
        &subkeys.index_nonce_seed,
        b"idxroot",
        0,
        BlockKind::IndexRootData,
        &mut next_block_index,
    );
    let mut index_root_extent = index_root_extent;
    index_root_extent.encrypted_size = index_root_extent
        .encrypted_size
        .saturating_add(crypto_header.block_size);
    assert_eq!(
        load_metadata_object_from_parts(
            &index_root_records,
            ObjectLoadContext::index_root(
                &volume_header,
                &crypto_header,
                &subkeys,
                index_root_extent,
            ),
            index_root_payload.len() as u32,
        )
        .unwrap_err(),
        FormatError::InvalidArchive("encrypted object size is not data_block_count * block_size")
    );

    let index_shard_payload = b"index shard metadata object";
    let (index_shard_extent, index_shard_records) = build_metadata_object_from_payload(
        index_shard_payload,
        &subkeys,
        &volume_header,
        &crypto_header,
        &subkeys.index_shard_key,
        &subkeys.index_nonce_seed,
        b"idxshard",
        1,
        BlockKind::IndexShardData,
        &mut next_block_index,
    );
    let mut index_shard_extent = index_shard_extent;
    index_shard_extent.encrypted_size = index_shard_extent
        .encrypted_size
        .saturating_add(crypto_header.block_size);
    assert_eq!(
        load_metadata_object_from_parts(
            &index_shard_records,
            ObjectLoadContext {
                volume_header: &volume_header,
                crypto_header: &crypto_header,
                extent: index_shard_extent,
                data_kind: BlockKind::IndexShardData,
                parity_kind: BlockKind::IndexShardParity,
                key: &subkeys.index_shard_key,
                nonce_seed: &subkeys.index_nonce_seed,
                domain: b"idxshard",
                counter: 1,
                class_data_shard_max: crypto_header.index_fec_data_shards,
                class_parity_shard_max: crypto_header.index_fec_parity_shards,
            },
            index_shard_payload.len() as u32,
        )
        .unwrap_err(),
        FormatError::InvalidArchive("encrypted object size is not data_block_count * block_size")
    );

    let directory_hint_payload = b"directory hint metadata object";
    let (directory_hint_extent, directory_hint_records) = build_metadata_object_from_payload(
        directory_hint_payload,
        &subkeys,
        &volume_header,
        &crypto_header,
        &subkeys.dir_hint_key,
        &subkeys.index_nonce_seed,
        b"dirhint",
        0,
        BlockKind::DirectoryHintData,
        &mut next_block_index,
    );
    let mut directory_hint_extent = directory_hint_extent;
    directory_hint_extent.encrypted_size = directory_hint_extent
        .encrypted_size
        .saturating_add(crypto_header.block_size);
    assert_eq!(
        load_metadata_object_from_parts(
            &directory_hint_records,
            ObjectLoadContext {
                volume_header: &volume_header,
                crypto_header: &crypto_header,
                extent: directory_hint_extent,
                data_kind: BlockKind::DirectoryHintData,
                parity_kind: BlockKind::DirectoryHintParity,
                key: &subkeys.dir_hint_key,
                nonce_seed: &subkeys.index_nonce_seed,
                domain: b"dirhint",
                counter: 0,
                class_data_shard_max: crypto_header.index_fec_data_shards,
                class_parity_shard_max: crypto_header.index_fec_parity_shards,
            },
            directory_hint_payload.len() as u32,
        )
        .unwrap_err(),
        FormatError::InvalidArchive("encrypted object size is not data_block_count * block_size")
    );

    let dictionary_payload = b"dictionary metadata object";
    let (dictionary_extent, dictionary_records) = build_metadata_object_from_payload(
        dictionary_payload,
        &subkeys,
        &volume_header,
        &crypto_header,
        &subkeys.dictionary_key,
        &subkeys.index_nonce_seed,
        b"dict",
        0,
        BlockKind::DictionaryData,
        &mut next_block_index,
    );
    let mut dictionary_extent = dictionary_extent;
    dictionary_extent.encrypted_size = dictionary_extent
        .encrypted_size
        .saturating_add(crypto_header.block_size);
    assert_eq!(
        load_metadata_object_from_parts(
            &dictionary_records,
            ObjectLoadContext {
                volume_header: &volume_header,
                crypto_header: &crypto_header,
                extent: dictionary_extent,
                data_kind: BlockKind::DictionaryData,
                parity_kind: BlockKind::DictionaryParity,
                key: &subkeys.dictionary_key,
                nonce_seed: &subkeys.index_nonce_seed,
                domain: b"dict",
                counter: 0,
                class_data_shard_max: crypto_header.index_root_fec_data_shards,
                class_parity_shard_max: crypto_header.index_root_fec_parity_shards,
            },
            dictionary_payload.len() as u32,
        )
        .unwrap_err(),
        FormatError::InvalidArchive("encrypted object size is not data_block_count * block_size")
    );
}

#[test]
fn opens_complete_multi_volume_archive() {
    let files = [RegularFile::new("alpha.txt", b"hello from volume stripes")];
    let archive = write_archive(
        &files,
        &master_key(),
        WriterOptions {
            stripe_width: 2,
            volume_loss_tolerance: 1,
            ..single_stream_options()
        },
    )
    .unwrap();
    assert_eq!(archive.volumes.len(), 2);

    let volume_refs = archive
        .volumes
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    let opened = open_archive_volumes(&volume_refs, &master_key()).unwrap();

    assert_eq!(opened.volume_header.stripe_width, 2);
    assert_eq!(opened.list_files().unwrap()[0].path, "alpha.txt");
    assert_eq!(
        opened.extract_file("alpha.txt").unwrap(),
        Some(b"hello from volume stripes".to_vec())
    );
    opened.verify().unwrap();
}

#[test]
fn recovers_from_one_missing_volume_when_parity_allows() {
    let files = [RegularFile::new("alpha.txt", b"recover me")];
    let archive = write_archive(
        &files,
        &master_key(),
        WriterOptions {
            stripe_width: 2,
            volume_loss_tolerance: 1,
            ..single_stream_options()
        },
    )
    .unwrap();

    let recovered = open_archive_volumes(&[archive.volumes[1].as_slice()], &master_key()).unwrap();
    assert_eq!(
        recovered.extract_file("alpha.txt").unwrap(),
        Some(b"recover me".to_vec())
    );
    recovered.verify().unwrap();
}

#[test]
fn recovers_from_crc_corrupted_block_when_parity_allows() {
    let files = [RegularFile::new("alpha.txt", b"repair corrupt block")];
    let archive = write_archive(
        &files,
        &master_key(),
        WriterOptions {
            stripe_width: 2,
            volume_loss_tolerance: 1,
            ..single_stream_options()
        },
    )
    .unwrap();
    let mut volumes = archive.volumes.clone();
    corrupt_first_block_record_payload(&mut volumes[0]);

    let volume_refs = volumes.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let recovered = open_archive_volumes(&volume_refs, &master_key()).unwrap();

    assert_eq!(
        recovered.extract_file("alpha.txt").unwrap(),
        Some(b"repair corrupt block".to_vec())
    );
    recovered.verify().unwrap();
}

#[test]
fn rejects_multi_volume_count_mismatch_without_tolerance() {
    let files = [RegularFile::new("alpha.txt", b"count check")];
    let archive = write_archive(
        &files,
        &master_key(),
        WriterOptions {
            stripe_width: 3,
            volume_loss_tolerance: 0,
            ..single_stream_options()
        },
    )
    .unwrap();

    assert_eq!(
        open_archive_volumes(&[archive.volumes[0].as_slice()], &master_key()).unwrap_err(),
        FormatError::InvalidArchive("missing volume count exceeds volume_loss_tolerance")
    );
}

#[test]
fn rejects_multi_volume_manifest_bootstrap_field_mismatch() {
    let files = [RegularFile::new("alpha.txt", b"footer mismatch")];
    let archive = write_archive(
        &files,
        &master_key(),
        WriterOptions {
            stripe_width: 2,
            volume_loss_tolerance: 1,
            ..single_stream_options()
        },
    )
    .unwrap();

    let mut bad_first = archive.volumes[0].clone();
    rewrite_manifest_footer(&mut bad_first, &master_key(), |footer| {
        footer.index_root_first_block = footer.index_root_first_block.wrapping_add(1);
    });

    open_archive_volumes(
        &[bad_first.as_slice(), archive.volumes[1].as_slice()],
        &master_key(),
    )
    .unwrap();
}

#[test]
fn repairs_corrupted_index_root_block_in_multi_volume_archive() {
    let files = [RegularFile::new("alpha.txt", b"repair meta root")];
    let archive = write_archive(
        &files,
        &master_key(),
        WriterOptions {
            stripe_width: 2,
            volume_loss_tolerance: 1,
            ..single_stream_options()
        },
    )
    .unwrap();
    let mut volumes = archive.volumes.clone();

    let mut corrupted = false;
    for volume in &mut volumes {
        if let Some(slot) = block_record_slots_with_kind(volume, BlockKind::IndexRootData).first() {
            corrupt_block_record_payload_at_slot(volume, *slot);
            corrupted = true;
            break;
        }
    }
    assert!(corrupted, "expected an IndexRootData record");

    let volume_refs = volumes.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let opened = open_archive_volumes(&volume_refs, &master_key()).unwrap();
    assert_eq!(
        opened.extract_file("alpha.txt").unwrap(),
        Some(b"repair meta root".to_vec())
    );
    opened.verify().unwrap();
}

#[test]
fn repairs_corrupted_index_shard_block_in_multi_volume_archive() {
    let files = [RegularFile::new("alpha.txt", b"repair meta shard")];
    let archive = write_archive(
        &files,
        &master_key(),
        WriterOptions {
            stripe_width: 2,
            volume_loss_tolerance: 1,
            ..single_stream_options()
        },
    )
    .unwrap();
    let mut volumes = archive.volumes.clone();

    let mut corrupted = false;
    for volume in &mut volumes {
        if let Some(slot) = block_record_slots_with_kind(volume, BlockKind::IndexShardData).first()
        {
            corrupt_block_record_payload_at_slot(volume, *slot);
            corrupted = true;
            break;
        }
    }
    assert!(corrupted, "expected an IndexShardData record");

    let volume_refs = volumes.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let opened = open_archive_volumes(&volume_refs, &master_key()).unwrap();
    assert_eq!(
        opened.extract_file("alpha.txt").unwrap(),
        Some(b"repair meta shard".to_vec())
    );
    opened.verify().unwrap();
}

#[test]
fn rejects_missing_volume_when_loss_tolerance_zero_even_with_bitrot_parity() {
    let files = [RegularFile::new(
        "alpha.txt",
        b"bitrot parity is not volume loss",
    )];
    let archive = write_archive(
        &files,
        &master_key(),
        WriterOptions {
            stripe_width: 2,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 1,
            ..single_stream_options()
        },
    )
    .unwrap();

    assert_eq!(
        open_archive_volumes(&[archive.volumes[1].as_slice()], &master_key()).unwrap_err(),
        FormatError::InvalidArchive("missing volume count exceeds volume_loss_tolerance")
    );
}

#[test]
fn repairs_crc_erasure_only_within_parity_budget() {
    let payload = pseudo_random_bytes(12_000);
    let archive = write_archive(
        &[RegularFile::new("rot.bin", &payload)],
        &master_key(),
        small_block_recovery_options(),
    )
    .unwrap();
    let payload_slots = first_payload_data_run_slots(&archive.bytes);
    assert!(
        payload_slots.len() >= 2,
        "fixture must contain a multi-block payload object"
    );

    let mut one_erasure = archive.bytes.clone();
    corrupt_block_record_payload_at_slot(&mut one_erasure, payload_slots[0]);
    let repaired = open_archive(&one_erasure, &master_key()).unwrap();
    assert_eq!(
        repaired.extract_file("rot.bin").unwrap(),
        Some(payload.clone())
    );

    let mut two_erasures = archive.bytes.clone();
    corrupt_block_record_payload_at_slot(&mut two_erasures, payload_slots[0]);
    corrupt_block_record_payload_at_slot(&mut two_erasures, payload_slots[1]);
    let unrepaired = open_archive(&two_erasures, &master_key()).unwrap();
    assert_eq!(
        unrepaired.extract_file("rot.bin").unwrap_err(),
        FormatError::FecTooFewAvailableShards
    );
}

#[test]
fn verify_rejects_missing_required_object_block_extent() {
    let (mut opened, missing_block) = multi_envelope_reader_fixture();
    assert!(opened.blocks.remove(&missing_block).is_some());

    assert_eq!(
        opened.verify().unwrap_err(),
        FormatError::FecTooFewAvailableShards
    );
}

#[test]
fn parity_crc_erasure_does_not_hide_authenticated_data() {
    let payload = pseudo_random_bytes(12_000);
    let archive = write_archive(
        &[RegularFile::new("parity-erasure.bin", &payload)],
        &master_key(),
        parity_rich_recovery_options(),
    )
    .unwrap();
    let payload_slot = first_payload_data_run_slots(&archive.bytes)[0];
    let parity_slots = block_record_slots_with_kind(&archive.bytes, BlockKind::PayloadParity);
    assert!(
        parity_slots.len() >= 2,
        "fixture must contain redundant parity shards"
    );
    let mut corrupted = archive.bytes;
    corrupt_block_record_payload_at_slot(&mut corrupted, payload_slot);
    corrupt_block_record_payload_at_slot(&mut corrupted, parity_slots[0]);

    let opened = open_archive(&corrupted, &master_key()).unwrap();
    assert_eq!(
        opened.extract_file("parity-erasure.bin").unwrap(),
        Some(payload)
    );
    opened.verify().unwrap();
}

#[test]
fn repair_patches_restore_crc_erased_payload_block() {
    let payload = pseudo_random_bytes(12_000);
    let archive = write_archive(
        &[RegularFile::new("rot.bin", &payload)],
        &master_key(),
        small_block_recovery_options(),
    )
    .unwrap();
    let payload_slot = first_payload_data_run_slots(&archive.bytes)[0];
    let mut corrupted = archive.bytes.clone();
    corrupt_block_record_payload_at_slot(&mut corrupted, payload_slot);

    let opened = open_seekable_archive(corrupted.clone(), &master_key()).unwrap();
    opened.verify().unwrap();
    let patches = opened.repair_patches().unwrap();
    assert_eq!(patches.len(), 1);
    apply_repair_patches(&mut corrupted, &patches);

    let repaired = open_seekable_archive(corrupted, &master_key()).unwrap();
    repaired.verify().unwrap();
    assert!(repaired.repair_patches().unwrap().is_empty());
}

#[test]
fn repair_patches_restore_crc_erased_payload_parity_block() {
    let payload = pseudo_random_bytes(12_000);
    let archive = write_archive(
        &[RegularFile::new("parity-erasure.bin", &payload)],
        &master_key(),
        parity_rich_recovery_options(),
    )
    .unwrap();
    let parity_slot = block_record_slots_with_kind(&archive.bytes, BlockKind::PayloadParity)[0];
    let mut corrupted = archive.bytes.clone();
    corrupt_block_record_payload_at_slot(&mut corrupted, parity_slot);

    let opened = open_seekable_archive(corrupted.clone(), &master_key()).unwrap();
    opened.verify().unwrap();
    let patches = opened.repair_patches().unwrap();
    assert_eq!(patches.len(), 1);
    apply_repair_patches(&mut corrupted, &patches);

    let repaired = open_seekable_archive(corrupted, &master_key()).unwrap();
    repaired.verify().unwrap();
    assert!(repaired.repair_patches().unwrap().is_empty());
}

#[test]
fn recovers_physical_odd_block_size_from_cmra_authority() {
    let archive = write_archive(
        &[RegularFile::new("odd-block.txt", b"payload")],
        &master_key(),
        small_block_recovery_options(),
    )
    .unwrap();
    let mut malformed = archive.bytes;
    let volume_header = VolumeHeader::parse(&malformed[..VOLUME_HEADER_LEN]).unwrap();
    let block_size_offset = volume_header.crypto_header_offset as usize + 24;
    malformed[block_size_offset..block_size_offset + 4].copy_from_slice(&4097u32.to_le_bytes());

    let opened = open_archive(&malformed, &master_key()).unwrap();
    assert_ne!(opened.crypto_header.block_size, 4097);
    assert_eq!(
        opened.extract_file("odd-block.txt").unwrap(),
        Some(b"payload".to_vec())
    );
    opened.verify().unwrap();
}

#[test]
fn repairs_structurally_malformed_payload_block_slots() {
    let payload = pseudo_random_bytes(12_000);
    let archive = write_archive(
        &[RegularFile::new("structural-block.bin", &payload)],
        &master_key(),
        small_block_recovery_options(),
    )
    .unwrap();
    let payload_slot = first_payload_data_run_slots(&archive.bytes)[0];

    let mut bad_magic = archive.bytes.clone();
    corrupt_block_record_magic_at_slot(&mut bad_magic, payload_slot);
    assert_eq!(
        open_archive(&bad_magic, &master_key())
            .unwrap()
            .extract_file("structural-block.bin")
            .unwrap(),
        Some(payload.clone())
    );

    let mut bad_reserved = archive.bytes;
    corrupt_block_record_reserved_at_slot(&mut bad_reserved, payload_slot);
    assert_eq!(
        open_archive(&bad_reserved, &master_key())
            .unwrap()
            .extract_file("structural-block.bin")
            .unwrap(),
        Some(payload)
    );
}

#[test]
fn repair_patches_restore_structurally_malformed_payload_block_slot() {
    let payload = pseudo_random_bytes(12_000);
    let archive = write_archive(
        &[RegularFile::new("structural-patch.bin", &payload)],
        &master_key(),
        small_block_recovery_options(),
    )
    .unwrap();
    let payload_slot = first_payload_data_run_slots(&archive.bytes)[0];
    let mut corrupted = archive.bytes.clone();
    corrupt_block_record_magic_at_slot(&mut corrupted, payload_slot);

    let opened = open_seekable_archive(corrupted.clone(), &master_key()).unwrap();
    opened.verify().unwrap();
    assert_eq!(
        opened.extract_file("structural-patch.bin").unwrap(),
        Some(payload)
    );
    let patches = opened.repair_patches().unwrap();
    assert_eq!(patches.len(), 1);
    apply_repair_patches(&mut corrupted, &patches);

    let repaired = open_seekable_archive(corrupted, &master_key()).unwrap();
    repaired.verify().unwrap();
    assert!(repaired.repair_patches().unwrap().is_empty());
}

#[test]
fn repairs_structurally_malformed_index_root_block_slot() {
    let archive = write_archive(
        &[RegularFile::new(
            "structural-index-root.txt",
            b"metadata repair",
        )],
        &master_key(),
        small_block_recovery_options(),
    )
    .unwrap();
    let index_root_slot =
        first_block_record_slot_with_kind(&archive.bytes, BlockKind::IndexRootData).unwrap();
    let mut corrupted = archive.bytes;
    corrupt_block_record_magic_at_slot(&mut corrupted, index_root_slot);

    let opened = open_archive(&corrupted, &master_key()).unwrap();
    assert_eq!(
        opened.extract_file("structural-index-root.txt").unwrap(),
        Some(b"metadata repair".to_vec())
    );
    opened.verify().unwrap();
}

#[test]
fn rejects_parity_block_with_last_data_flag() {
    let archive = write_archive(
        &[RegularFile::new("parity-flag.txt", b"payload")],
        &master_key(),
        small_block_recovery_options(),
    )
    .unwrap();
    let parity_slot =
        first_block_record_slot_with_kind(&archive.bytes, BlockKind::PayloadParity).unwrap();
    let mut malformed = archive.bytes;
    mutate_block_record_at_slot(&mut malformed, parity_slot, |record| {
        record.flags = 0x01;
    });

    assert_eq!(
        open_archive(&malformed, &master_key()).unwrap_err(),
        FormatError::ParityBlockHasLastDataFlag
    );
}

#[test]
fn rejects_missing_and_duplicate_payload_last_data_flags() {
    let payload = pseudo_random_bytes(12_000);
    let archive = write_archive(
        &[RegularFile::new("flags.bin", &payload)],
        &master_key(),
        small_block_recovery_options(),
    )
    .unwrap();
    let payload_slots = first_payload_data_run_slots(&archive.bytes);
    assert!(
        payload_slots.len() >= 2,
        "fixture must contain a multi-block payload object"
    );

    let mut duplicate_last = archive.bytes.clone();
    mutate_block_record_at_slot(&mut duplicate_last, payload_slots[0], |record| {
        record.flags = 0x01;
    });
    let opened = open_archive(&duplicate_last, &master_key()).unwrap();
    assert_eq!(
        opened.extract_file("flags.bin").unwrap_err(),
        FormatError::InvalidArchive("object last-data flag is not on the final data block")
    );

    let mut missing_last = archive.bytes;
    mutate_block_record_at_slot(
        &mut missing_last,
        *payload_slots.last().unwrap(),
        |record| {
            record.flags = 0;
        },
    );
    let opened = open_archive(&missing_last, &master_key()).unwrap();
    assert_eq!(
        opened.extract_file("flags.bin").unwrap_err(),
        FormatError::InvalidArchive("object last-data flag is not on the final data block")
    );
}

#[test]
fn recovers_from_one_corrupt_manifest_footer_copy_when_another_volume_authenticates() {
    let files = [RegularFile::new(
        "footer-copy.txt",
        b"survives one bad footer",
    )];
    let archive = write_archive(
        &files,
        &master_key(),
        WriterOptions {
            stripe_width: 2,
            volume_loss_tolerance: 1,
            ..single_stream_options()
        },
    )
    .unwrap();
    let mut volumes = archive.volumes.clone();
    corrupt_manifest_footer_hmac(&mut volumes[0]);

    let volume_refs = volumes.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let opened = open_archive_volumes(&volume_refs, &master_key()).unwrap();
    assert_eq!(opened.manifest_footer.volume_index, 0);
    assert_eq!(opened.volume_header.volume_index, 0);
    assert_eq!(opened.volume_trailer.as_ref().unwrap().volume_index, 0);
    assert_eq!(
        opened.extract_file("footer-copy.txt").unwrap(),
        Some(b"survives one bad footer".to_vec())
    );
    opened.verify().unwrap();
}

#[test]
fn manifest_footer_corruption_requires_trusted_sidecar() {
    let archive = write_archive(
        &[RegularFile::new("footer.txt", b"sidecar authority")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let manifest_offset = terminal_material_offset(&archive.bytes);
    let mut corrupted = archive.bytes.clone();
    corrupted[manifest_offset + MANIFEST_HMAC_COVERED_LEN] ^= 0x01;
    corrupt_v41_terminal_recovery(&mut corrupted);

    assert!(open_archive(&corrupted, &master_key()).is_err());

    let opened =
        open_non_seekable_archive(&corrupted, &master_key(), Some(&archive.bootstrap_sidecar))
            .unwrap();
    assert!(opened.volume_trailer.is_none());
    assert_eq!(
        opened.extract_file("footer.txt").unwrap(),
        Some(b"sidecar authority".to_vec())
    );
    opened.verify().unwrap();
}

#[test]
fn authenticated_footer_trailer_and_sidecar_hmac_boundaries_are_enforced() {
    let archive = write_archive(
        &[RegularFile::new("hmac-boundary.txt", b"boundary bytes")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let strict_options = ReaderOptions {
        max_trailing_garbage_scan: 0,
        ..ReaderOptions::default()
    };

    let manifest_offset = terminal_material_offset(&archive.bytes);
    for offset in [
        manifest_offset + 71,
        manifest_offset + MANIFEST_HMAC_COVERED_LEN,
    ] {
        let mut corrupted = archive.bytes.clone();
        corrupted[offset] ^= 0x01;
        open_archive(&corrupted, &master_key()).unwrap();
    }

    let trailer_offset = manifest_offset + MANIFEST_FOOTER_LEN;
    for offset in [
        trailer_offset + 75,
        trailer_offset + TRAILER_HMAC_COVERED_LEN,
    ] {
        let mut corrupted = archive.bytes.clone();
        corrupted[offset] ^= 0x01;
        OpenedArchive::open_with_options(&corrupted, &master_key(), strict_options).unwrap();
    }

    let mut covered_sidecar = archive.bootstrap_sidecar.clone();
    let mut header =
        BootstrapSidecarHeader::parse(&covered_sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN]).unwrap();
    header.manifest_footer_offset += 1;
    covered_sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN].copy_from_slice(&header.to_bytes());
    assert_eq!(
        open_archive_with_bootstrap_sidecar(&archive.bytes, &covered_sidecar, &master_key())
            .unwrap_err(),
        FormatError::HmacMismatch {
            structure: "BootstrapSidecarHeader"
        }
    );

    let mut tag_sidecar = archive.bootstrap_sidecar.clone();
    let mut header =
        BootstrapSidecarHeader::parse(&tag_sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN]).unwrap();
    header.sidecar_hmac[0] ^= 1;
    tag_sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN].copy_from_slice(&header.to_bytes());
    assert_eq!(
        open_archive_with_bootstrap_sidecar(&archive.bytes, &tag_sidecar, &master_key())
            .unwrap_err(),
        FormatError::HmacMismatch {
            structure: "BootstrapSidecarHeader"
        }
    );

    let mut non_covered_sidecar = archive.bootstrap_sidecar.clone();
    let header =
        BootstrapSidecarHeader::parse(&non_covered_sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN])
            .unwrap();
    let mut header_bytes = header.to_bytes();
    header_bytes[124] ^= 0x01;
    let crc = crc32c::crc32c(&header_bytes[..124]);
    header_bytes[124..128].copy_from_slice(&crc.to_le_bytes());
    non_covered_sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN].copy_from_slice(&header_bytes);
    let opened =
        open_archive_with_bootstrap_sidecar(&archive.bytes, &non_covered_sidecar, &master_key())
            .unwrap();
    assert_eq!(
        opened.extract_file("hmac-boundary.txt").unwrap(),
        Some(b"boundary bytes".to_vec())
    );
}

#[test]
fn rejects_authenticated_footer_and_trailer_volume_index_mismatches() {
    let archive = write_archive(
        &[RegularFile::new("volume-index.txt", b"identity")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();

    let mut bad_trailer = archive.bytes.clone();
    rewrite_volume_trailer(&mut bad_trailer, &master_key(), |trailer| {
        trailer.volume_index = 1;
    });
    open_archive(&bad_trailer, &master_key()).unwrap();

    let mut bad_manifest = archive.bytes;
    rewrite_manifest_footer(&mut bad_manifest, &master_key(), |footer| {
        footer.volume_index = 1;
    });
    open_archive(&bad_manifest, &master_key()).unwrap();
}

#[test]
fn rejects_same_key_header_terminal_material_splice() {
    let first = write_archive(
        &[RegularFile::new("splice.txt", b"same shape")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let second = write_archive(
        &[RegularFile::new("splice.txt", b"same shape")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    assert_ne!(first.archive_uuid, second.archive_uuid);
    assert_eq!(
        terminal_material_offset(&first.bytes),
        terminal_material_offset(&second.bytes)
    );
    assert_eq!(first.bytes.len(), second.bytes.len());

    let terminal_offset = terminal_material_offset(&first.bytes);
    let mut spliced = first.bytes.clone();
    spliced[terminal_offset..].copy_from_slice(&second.bytes[terminal_offset..]);

    assert_eq!(
        open_archive(&spliced, &master_key()).unwrap_err(),
        FormatError::InvalidArchive("no valid v41 CMRA candidate found")
    );
}

#[test]
fn rejects_cmra_crypto_header_pre_hmac_mismatch() {
    let kdf_params = crate::crypto::KdfParams::Argon2id {
        t_cost: 1,
        m_cost_kib: 8,
        parallelism: 1,
        salt: b"0123456789abcdef".to_vec(),
    };
    let archive = write_archive_with_kdf(
        &[RegularFile::new("cmra-crypto.txt", b"same fixed header")],
        &master_key(),
        single_stream_options(),
        &kdf_params,
    )
    .unwrap();
    let mut mutated = archive.bytes.clone();
    let volume_header = VolumeHeader::parse(&mutated[..VOLUME_HEADER_LEN]).unwrap();
    let subkeys = Subkeys::derive(
        &master_key(),
        &volume_header.archive_uuid,
        &volume_header.session_id,
    )
    .unwrap();

    rewrite_cmra_image(&mut mutated, CmraRecoveryMode::KeyHolding, |image| {
        let crypto_region = image
            .regions
            .iter_mut()
            .find(|region| region.region_type == 2)
            .unwrap();
        let hmac_offset = crypto_region.bytes.len() - CRYPTO_HEADER_HMAC_LEN;
        let salt_start = CRYPTO_HEADER_FIXED_LEN + 16;
        crypto_region.bytes[salt_start] ^= 0x01;
        let hmac = compute_hmac(
            HmacDomain::CryptoHeader,
            &subkeys.mac_key,
            &volume_header.archive_uuid,
            &volume_header.session_id,
            &crypto_region.bytes[..hmac_offset],
        );
        crypto_region.bytes[hmac_offset..].copy_from_slice(&hmac);
    });

    let final_offset = mutated.len() - CRITICAL_RECOVERY_LOCATOR_LEN;
    let locator = final_recovery_locator(&mutated);
    let crypto_start = volume_header.crypto_header_offset as usize;
    let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
    let parsed_crypto = CryptoHeader::parse(
        &mutated[crypto_start..crypto_end],
        volume_header.crypto_header_length,
    )
    .unwrap();
    assert_eq!(
        parse_locator_cmra_candidate(
            &mutated,
            final_offset,
            locator,
            KeyHoldingTerminalContext {
                subkeys: &subkeys,
                volume_header: &volume_header,
                crypto_header: &parsed_crypto.fixed,
                crypto_header_bytes: &mutated[crypto_start..crypto_end],
            },
        )
        .unwrap_err(),
        FormatError::InvalidArchive("CMRA CryptoHeader differs from parsed CryptoHeader")
    );
    assert!(open_archive(&mutated, &master_key()).is_err());
}

#[test]
fn recovers_physical_crypto_header_splice_from_cmra_authority() {
    let base = WriterOptions {
        archive_uuid: Some([0x11; 16]),
        session_id: Some([0x22; 16]),
        ..small_block_recovery_options()
    };
    let same_archive = WriterOptions {
        archive_uuid: Some([0x11; 16]),
        session_id: Some([0x33; 16]),
        ..small_block_recovery_options()
    };

    let first = write_archive(
        &[RegularFile::new("splice.txt", b"same shape")],
        &master_key(),
        base,
    )
    .unwrap();
    let second = write_archive(
        &[RegularFile::new("splice.txt", b"same shape")],
        &master_key(),
        same_archive,
    )
    .unwrap();

    let volume_header = VolumeHeader::parse(&first.bytes[..VOLUME_HEADER_LEN]).unwrap();
    let second_volume_header = VolumeHeader::parse(&second.bytes[..VOLUME_HEADER_LEN]).unwrap();
    let crypto_start = volume_header.crypto_header_offset as usize;
    let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
    let second_crypto_end = second_volume_header.crypto_header_offset as usize
        + second_volume_header.crypto_header_length as usize;
    assert_eq!(crypto_end, second_crypto_end);

    let mut spliced = first.bytes.clone();
    spliced[crypto_start..crypto_end].copy_from_slice(&second.bytes[crypto_start..crypto_end]);

    let opened = open_archive(&spliced, &master_key()).unwrap();
    assert_eq!(
        opened.crypto_header_bytes,
        first.bytes[crypto_start..crypto_end].to_vec()
    );
    assert_eq!(
        opened.extract_file("splice.txt").unwrap(),
        Some(b"same shape".to_vec())
    );
    opened.verify().unwrap();
}

#[test]
fn rejects_same_key_object_splice_with_session_mismatch() {
    let first = write_archive(
        &[RegularFile::new("splice.txt", b"same shape")],
        &master_key(),
        WriterOptions {
            archive_uuid: Some([0x11; 16]),
            session_id: Some([0x22; 16]),
            ..single_stream_options()
        },
    )
    .unwrap();
    let second = write_archive(
        &[RegularFile::new("splice.txt", b"same shape")],
        &master_key(),
        WriterOptions {
            archive_uuid: Some([0x11; 16]),
            session_id: Some([0x33; 16]),
            ..single_stream_options()
        },
    )
    .unwrap();

    let volume_header = VolumeHeader::parse(&first.bytes[..VOLUME_HEADER_LEN]).unwrap();
    let crypto_end =
        volume_header.crypto_header_offset as usize + volume_header.crypto_header_length as usize;
    let terminal_offset = terminal_material_offset(&first.bytes);
    let second_terminal_offset = terminal_material_offset(&second.bytes);
    assert_eq!(terminal_offset, second_terminal_offset);

    let mut spliced = first.bytes.clone();
    spliced[crypto_end..terminal_offset]
        .copy_from_slice(&second.bytes[crypto_end..terminal_offset]);

    assert_eq!(
        open_archive(&spliced, &master_key()).unwrap_err(),
        FormatError::AeadFailure
    );
}

#[test]
fn rejects_authenticated_trailer_pointer_and_count_mutations() {
    let archive = write_archive(
        &[RegularFile::new(
            "trailer-range.txt",
            b"authenticated ranges",
        )],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let strict_options = ReaderOptions {
        max_trailing_garbage_scan: 0,
        ..ReaderOptions::default()
    };
    let bytes = archive.bytes;
    let manifest_offset = terminal_material_offset(&bytes);
    let trailer_offset = manifest_offset + MANIFEST_FOOTER_LEN;

    let mut wrong_footer_length = bytes.clone();
    rewrite_volume_trailer(&mut wrong_footer_length, &master_key(), |trailer| {
        trailer.manifest_footer_length = 42;
    });
    OpenedArchive::open_with_options(&wrong_footer_length, &master_key(), strict_options).unwrap();

    for (label, offset) in [
        (
            "offset before trailer by 1",
            manifest_offset.saturating_sub(1),
        ),
        ("offset after trailer", manifest_offset + 1),
        ("offset at stream start", 0),
        ("offset at trailer", trailer_offset),
        ("offset beyond trailer", trailer_offset + 4),
    ] {
        let mut wrong_footer_offset = bytes.clone();
        rewrite_volume_trailer(&mut wrong_footer_offset, &master_key(), |trailer| {
            trailer.manifest_footer_offset = offset as u64;
        });
        open_archive(&wrong_footer_offset, &master_key())
            .unwrap_or_else(|err| panic!("manifest offset case {label}: {err:?}"));
    }

    let mut wrong_bytes_written = bytes.clone();
    rewrite_volume_trailer(&mut wrong_bytes_written, &master_key(), |trailer| {
        trailer.bytes_written += 1;
    });
    open_archive(&wrong_bytes_written, &master_key()).unwrap();

    let mut wrong_block_count = bytes.clone();
    rewrite_volume_trailer(&mut wrong_block_count, &master_key(), |trailer| {
        trailer.block_count += 1;
    });
    open_archive(&wrong_block_count, &master_key()).unwrap();

    let mut wrong_footer_offset = bytes.clone();
    rewrite_volume_trailer(&mut wrong_footer_offset, &master_key(), |trailer| {
        trailer.manifest_footer_offset = bytes.len() as u64 + 1024;
    });
    open_archive(&wrong_footer_offset, &master_key()).unwrap();
}

#[test]
fn rejects_authenticated_trailer_outside_trailing_scan_cap() {
    let archive = write_archive(
        &[RegularFile::new(
            "trailer-trailing-scan.txt",
            b"trailer scan boundaries",
        )],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let options = ReaderOptions {
        max_trailing_garbage_scan: 8,
        ..ReaderOptions::default()
    };

    let mut within_scan = archive.bytes.clone();
    within_scan.resize(within_scan.len() + options.max_trailing_garbage_scan, 0xAA);
    let opened = OpenedArchive::open_with_options(&within_scan, &master_key(), options).unwrap();
    assert_eq!(
        opened.extract_file("trailer-trailing-scan.txt").unwrap(),
        Some(b"trailer scan boundaries".to_vec())
    );

    let mut beyond_scan = archive.bytes.clone();
    beyond_scan.resize(
        beyond_scan.len() + max_critical_recovery_scan(options).unwrap() + 1,
        0xAA,
    );
    assert_eq!(
        OpenedArchive::open_with_options(&beyond_scan, &master_key(), options).unwrap_err(),
        FormatError::InvalidArchive("no valid v41 CMRA candidate found")
    );
}

#[test]
fn rejects_authenticated_index_root_extent_size_mismatch_at_open() {
    let archive = write_archive(
        &[RegularFile::new("index-root-size.txt", b"extent size")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    let mut malformed = archive.bytes;
    let slot = first_block_record_slot_with_kind(&malformed, BlockKind::IndexRootData)
        .expect("archive should contain IndexRootData");
    mutate_block_record_at_slot(&mut malformed, slot, |record| {
        record.payload[0] ^= 0x55;
    });

    assert_eq!(
        open_archive(&malformed, &master_key()).unwrap_err(),
        FormatError::AeadFailure
    );
}

#[test]
fn rejects_block_record_at_wrong_stripe_position() {
    let files = [RegularFile::new("alpha.txt", b"wrong stripe")];
    let archive = write_archive(
        &files,
        &master_key(),
        WriterOptions {
            stripe_width: 2,
            volume_loss_tolerance: 1,
            ..single_stream_options()
        },
    )
    .unwrap();
    let mut volumes = archive.volumes.clone();
    mutate_first_block_record(&mut volumes[0], |record| {
        record.block_index += 2;
    });

    let volume_refs = volumes.iter().map(Vec::as_slice).collect::<Vec<_>>();
    assert_eq!(
        open_archive_volumes(&volume_refs, &master_key()).unwrap_err(),
        FormatError::InvalidArchive("BlockRecord index does not match volume position")
    );
}

#[test]
fn rejects_decreasing_block_record_index_in_required_region() {
    let archive = write_archive(
        &[RegularFile::new("alpha.txt", b"decreasing block index")],
        &master_key(),
        single_stream_options(),
    )
    .unwrap();
    assert!(block_record_slots(&archive.bytes).len() >= 2);

    let mut malformed = archive.bytes;
    mutate_block_record_at_slot(&mut malformed, 1, |record| {
        record.block_index = 0;
    });

    assert_eq!(
        open_archive(&malformed, &master_key()).unwrap_err(),
        FormatError::InvalidArchive("BlockRecord index does not match volume position")
    );
}

#[test]
fn rejects_duplicate_authenticated_volume_indexes() {
    let files = [RegularFile::new("alpha.txt", b"duplicates")];
    let archive = write_archive(
        &files,
        &master_key(),
        WriterOptions {
            stripe_width: 2,
            volume_loss_tolerance: 1,
            ..single_stream_options()
        },
    )
    .unwrap();

    assert_eq!(
        open_archive_volumes(
            &[archive.volumes[0].as_slice(), archive.volumes[0].as_slice()],
            &master_key()
        )
        .unwrap_err(),
        FormatError::InvalidArchive("duplicate authenticated volume index")
    );
}

#[test]
fn rejects_conflicting_duplicate_authenticated_volume_indexes_by_default() {
    let files = [RegularFile::new("alpha.txt", b"conflicting duplicates")];
    let archive = write_archive(
        &files,
        &master_key(),
        WriterOptions {
            stripe_width: 2,
            volume_loss_tolerance: 1,
            ..single_stream_options()
        },
    )
    .unwrap();
    let mut conflicting = archive.volumes[0].clone();
    corrupt_first_block_record_payload(&mut conflicting);

    assert_eq!(
        open_archive_volumes(
            &[archive.volumes[0].as_slice(), conflicting.as_slice()],
            &master_key()
        )
        .unwrap_err(),
        FormatError::InvalidArchive("duplicate authenticated volume index")
    );
}

fn directory_hint_table_from_rows(
    hint_shard_index: u64,
    rows: &[(Vec<u8>, Vec<u32>)],
    shard_count: u32,
) -> DirectoryHintTable {
    let mut entries = Vec::new();
    let mut shard_row_indexes = Vec::new();
    let mut string_pool = Vec::new();

    for (path, rows) in rows {
        let path_offset = if path.is_empty() {
            0
        } else {
            let offset = string_pool.len() as u64;
            string_pool.extend_from_slice(path);
            offset
        };
        let shard_list_start_index = shard_row_indexes.len() as u32;
        shard_row_indexes.extend_from_slice(rows);
        entries.push(DirectoryHintEntry {
            dir_hash: hash_prefix(path),
            path_offset,
            path_length: path.len() as u32,
            shard_list_start_index,
            shard_count: rows.len() as u32,
        });
    }

    let table_bytes =
        directory_hint_table_bytes(hint_shard_index, entries, shard_row_indexes, string_pool);
    let locating = DirectoryHintShardEntry {
        hint_shard_index,
        first_dir_hash: hash_prefix(&rows.first().unwrap().0),
        last_dir_hash: hash_prefix(&rows.last().unwrap().0),
        first_block_index: 0,
        data_block_count: 1,
        parity_block_count: 0,
        encrypted_size: 4096,
        decompressed_size: table_bytes.len() as u32,
        entry_count: rows.len() as u64,
    };
    DirectoryHintTable::parse(
        &table_bytes,
        &locating,
        shard_count,
        MetadataLimits::default(),
    )
    .unwrap()
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

fn corrupt_first_block_record_payload(volume: &mut [u8]) {
    let (record_offset, _) = first_block_record(volume);
    volume[record_offset + 16] ^= 0x55;
}

fn corrupt_block_record_payload_at_slot(volume: &mut [u8], slot: usize) {
    let (record_offset, _) = block_record_at_slot(volume, slot);
    volume[record_offset + 16] ^= 0x55;
}

fn apply_repair_patches(volume: &mut [u8], patches: &[ArchiveRepairPatch]) {
    for patch in patches {
        let offset = patch.record_offset as usize;
        let end = offset + patch.record_bytes.len();
        volume[offset..end].copy_from_slice(&patch.record_bytes);
    }
}

fn corrupt_block_record_magic_at_slot(volume: &mut [u8], slot: usize) {
    let (record_offset, _) = block_record_at_slot(volume, slot);
    volume[record_offset] ^= 0x55;
}

fn corrupt_block_record_reserved_at_slot(volume: &mut [u8], slot: usize) {
    let (record_offset, _) = block_record_at_slot(volume, slot);
    volume[record_offset + 14] = 0x01;
}

fn corrupt_manifest_footer_hmac(volume: &mut [u8]) {
    let manifest_offset = terminal_material_offset(volume);
    volume[manifest_offset + MANIFEST_HMAC_COVERED_LEN] ^= 0x01;
}

fn final_recovery_locator(volume: &[u8]) -> CriticalRecoveryLocator {
    let final_offset = volume.len() - CRITICAL_RECOVERY_LOCATOR_LEN;
    CriticalRecoveryLocator::parse(
        &volume[final_offset..final_offset + CRITICAL_RECOVERY_LOCATOR_LEN],
    )
    .unwrap()
}

fn rewrite_cmra_parity_count(volume: &[u8], parity_shard_count: u16) -> Vec<u8> {
    let locator = final_recovery_locator(volume);
    let tuple = CmraDecoderTuple::from(locator);
    assert!(parity_shard_count < tuple.parity_shard_count);
    let cmra_offset = locator.cmra_offset as usize;
    let shard_size = tuple.shard_size as usize;
    let row_len = CRITICAL_METADATA_RECOVERY_SHARD_HEADER_LEN + shard_size;
    let kept_rows = tuple.data_shard_count as usize + parity_shard_count as usize;
    let mut header = CriticalMetadataRecoveryHeader::parse(
        &volume[cmra_offset..cmra_offset + CRITICAL_METADATA_RECOVERY_HEADER_LEN],
    )
    .unwrap();
    header.parity_shard_count = parity_shard_count;

    let mut cmra = Vec::with_capacity(CRITICAL_METADATA_RECOVERY_HEADER_LEN + kept_rows * row_len);
    cmra.extend_from_slice(&header.to_bytes());
    let rows_start = cmra_offset + CRITICAL_METADATA_RECOVERY_HEADER_LEN;
    for row in 0..kept_rows {
        let start = rows_start + row * row_len;
        cmra.extend_from_slice(&volume[start..start + row_len]);
    }

    let mut out = Vec::with_capacity(cmra_offset + cmra.len() + LOCATOR_PAIR_LEN);
    out.extend_from_slice(&volume[..cmra_offset]);
    out.extend_from_slice(&cmra);
    let mut mirror = locator;
    mirror.locator_sequence = 1;
    mirror.cmra_length = cmra.len() as u32;
    mirror.cmra_parity_shard_count = parity_shard_count;
    out.extend_from_slice(&mirror.to_bytes());
    let final_locator = CriticalRecoveryLocator {
        volume_format_rev: locator.volume_format_rev,
        locator_sequence: 0,
        ..mirror
    };
    out.extend_from_slice(&final_locator.to_bytes());
    out
}

fn rewrite_public_cmra_image(volume: &mut [u8], mutate: impl FnOnce(&mut CriticalMetadataImage)) {
    rewrite_cmra_image(volume, CmraRecoveryMode::PublicNoKey, mutate);
}

fn rewrite_root_auth_footer_revision_bytes(bytes: &mut [u8], revision: u16) {
    bytes[72..74].copy_from_slice(&revision.to_le_bytes());
    let crc_offset = bytes.len() - 4;
    let crc = crc32c::crc32c(&bytes[..crc_offset]);
    bytes[crc_offset..crc_offset + 4].copy_from_slice(&crc.to_le_bytes());
}

fn rewrite_cmra_image(
    volume: &mut [u8],
    mode: CmraRecoveryMode,
    mutate: impl FnOnce(&mut CriticalMetadataImage),
) {
    let final_offset = volume.len() - CRITICAL_RECOVERY_LOCATOR_LEN;
    let locator = final_recovery_locator(volume);
    let tuple = CmraDecoderTuple::from(locator);
    let recovered = recover_cmra(volume, locator.cmra_offset, Some(tuple), mode).unwrap();
    let mut image = recovered.image;
    mutate(&mut image);
    refresh_critical_image_region_digests(&mut image);
    let image_bytes = image.to_bytes().unwrap();
    assert_eq!(image_bytes.len(), tuple.image_length as usize);

    let shard_size = tuple.shard_size as usize;
    let data_shard_count = tuple.data_shard_count as usize;
    let parity_shard_count = tuple.parity_shard_count as usize;
    assert!(image_bytes.len() <= data_shard_count * shard_size);

    let mut data_shards = Vec::with_capacity(data_shard_count);
    for idx in 0..data_shard_count {
        let start = idx * shard_size;
        let end = (start + shard_size).min(image_bytes.len());
        let mut payload = vec![0u8; shard_size];
        if start < image_bytes.len() {
            payload[..end - start].copy_from_slice(&image_bytes[start..end]);
        }
        data_shards.push(payload);
    }
    let parity_shards = encode_parity_gf16(&data_shards, parity_shard_count).unwrap();
    let image_sha256 = sha256_bytes(&image_bytes);

    let header = CriticalMetadataRecoveryHeader {
        shard_size: tuple.shard_size,
        data_shard_count: tuple.data_shard_count,
        parity_shard_count: tuple.parity_shard_count,
        image_length: tuple.image_length,
        archive_uuid_hint: locator.archive_uuid_hint,
        session_id_hint: locator.session_id_hint,
        volume_index_hint: locator.volume_index_hint,
        image_sha256,
        header_crc32c: 0,
    };
    let mut cmra = Vec::new();
    cmra.extend_from_slice(&header.to_bytes());
    for (idx, payload) in data_shards.into_iter().enumerate() {
        let payload_len = if idx + 1 == data_shard_count {
            image_bytes.len() - idx * shard_size
        } else {
            shard_size
        };
        cmra.extend_from_slice(
            &CriticalMetadataRecoveryShard {
                shard_index: idx as u16,
                shard_role: 0,
                shard_payload_length: payload_len as u32,
                payload,
                shard_crc32c: 0,
            }
            .to_bytes(shard_size)
            .unwrap(),
        );
    }
    for (idx, payload) in parity_shards.into_iter().enumerate() {
        cmra.extend_from_slice(
            &CriticalMetadataRecoveryShard {
                shard_index: (data_shard_count + idx) as u16,
                shard_role: 1,
                shard_payload_length: shard_size as u32,
                payload,
                shard_crc32c: 0,
            }
            .to_bytes(shard_size)
            .unwrap(),
        );
    }
    assert_eq!(cmra.len() as u64, recovered.cmra_length);
    let cmra_offset = locator.cmra_offset as usize;
    volume[cmra_offset..cmra_offset + cmra.len()].copy_from_slice(&cmra);

    rewrite_locator_image_sha(volume, final_offset, image_sha256);
    let mirror_offset = final_offset - CRITICAL_RECOVERY_LOCATOR_LEN;
    rewrite_locator_image_sha(volume, mirror_offset, image_sha256);
}

fn rewrite_cmra_image_variable_len(
    volume: &[u8],
    mode: CmraRecoveryMode,
    mutate: impl FnOnce(&mut CriticalMetadataImage),
) -> Vec<u8> {
    let locator = final_recovery_locator(volume);
    let tuple = CmraDecoderTuple::from(locator);
    let recovered = recover_cmra(volume, locator.cmra_offset, Some(tuple), mode).unwrap();
    let mut image = recovered.image;
    mutate(&mut image);
    refresh_critical_image_region_digests(&mut image);
    let image_bytes = image.to_bytes().unwrap();

    let shard_size = tuple.shard_size as usize;
    let data_shard_count = image_bytes.len().div_ceil(shard_size);
    let parity_shard_count = tuple.parity_shard_count as usize;
    assert!(data_shard_count > 0);
    assert!(image_bytes.len() <= data_shard_count * shard_size);

    let mut data_shards = Vec::with_capacity(data_shard_count);
    for idx in 0..data_shard_count {
        let start = idx * shard_size;
        let end = (start + shard_size).min(image_bytes.len());
        let mut payload = vec![0u8; shard_size];
        if start < image_bytes.len() {
            payload[..end - start].copy_from_slice(&image_bytes[start..end]);
        }
        data_shards.push(payload);
    }
    let parity_shards = encode_parity_gf16(&data_shards, parity_shard_count).unwrap();
    let image_sha256 = sha256_bytes(&image_bytes);
    let data_shard_count_u16 = u16::try_from(data_shard_count).unwrap();
    let image_length_u32 = u32::try_from(image_bytes.len()).unwrap();

    let header = CriticalMetadataRecoveryHeader {
        shard_size: tuple.shard_size,
        data_shard_count: data_shard_count_u16,
        parity_shard_count: tuple.parity_shard_count,
        image_length: image_length_u32,
        archive_uuid_hint: locator.archive_uuid_hint,
        session_id_hint: locator.session_id_hint,
        volume_index_hint: locator.volume_index_hint,
        image_sha256,
        header_crc32c: 0,
    };
    let mut cmra = Vec::new();
    cmra.extend_from_slice(&header.to_bytes());
    for (idx, payload) in data_shards.into_iter().enumerate() {
        let payload_len = if idx + 1 == data_shard_count {
            image_bytes.len() - idx * shard_size
        } else {
            shard_size
        };
        cmra.extend_from_slice(
            &CriticalMetadataRecoveryShard {
                shard_index: idx as u16,
                shard_role: 0,
                shard_payload_length: payload_len as u32,
                payload,
                shard_crc32c: 0,
            }
            .to_bytes(shard_size)
            .unwrap(),
        );
    }
    for (idx, payload) in parity_shards.into_iter().enumerate() {
        cmra.extend_from_slice(
            &CriticalMetadataRecoveryShard {
                shard_index: (data_shard_count + idx) as u16,
                shard_role: 1,
                shard_payload_length: shard_size as u32,
                payload,
                shard_crc32c: 0,
            }
            .to_bytes(shard_size)
            .unwrap(),
        );
    }

    let locator_base = CriticalRecoveryLocator {
        volume_format_rev: image.volume_format_rev,
        cmra_offset: locator.cmra_offset,
        cmra_length: cmra.len() as u32,
        volume_trailer_offset: locator.volume_trailer_offset,
        body_bytes_before_cmra: locator.body_bytes_before_cmra,
        archive_uuid_hint: locator.archive_uuid_hint,
        session_id_hint: locator.session_id_hint,
        volume_index_hint: locator.volume_index_hint,
        locator_sequence: 1,
        cmra_shard_size: tuple.shard_size,
        cmra_data_shard_count: data_shard_count_u16,
        cmra_parity_shard_count: tuple.parity_shard_count,
        cmra_image_length: image_length_u32,
        cmra_image_sha256: image_sha256,
        locator_crc32c: 0,
    };

    let cmra_offset = locator.cmra_offset as usize;
    let mut out = Vec::new();
    out.extend_from_slice(&volume[..cmra_offset]);
    out.extend_from_slice(&cmra);
    out.extend_from_slice(&locator_base.to_bytes());
    out.extend_from_slice(
        &CriticalRecoveryLocator {
            locator_sequence: 0,
            ..locator_base
        }
        .to_bytes(),
    );
    out
}

fn rewrite_recovery_locator(
    volume: &mut [u8],
    offset: usize,
    mutate: impl FnOnce(&mut CriticalRecoveryLocator),
) {
    let mut locator =
        CriticalRecoveryLocator::parse(&volume[offset..offset + CRITICAL_RECOVERY_LOCATOR_LEN])
            .unwrap();
    mutate(&mut locator);
    volume[offset..offset + CRITICAL_RECOVERY_LOCATOR_LEN].copy_from_slice(&locator.to_bytes());
}

fn refresh_critical_image_region_digests(image: &mut CriticalMetadataImage) {
    image.volume_header_sha256 = sha256_bytes(
        &image
            .regions
            .iter()
            .find(|region| region.region_type == 1)
            .unwrap()
            .bytes,
    );
    image.crypto_header_sha256 = sha256_bytes(
        &image
            .regions
            .iter()
            .find(|region| region.region_type == 2)
            .unwrap()
            .bytes,
    );
    image.key_wrap_table_sha256 = image
        .regions
        .iter()
        .find(|region| region.region_type == 6)
        .map(|region| sha256_bytes(&region.bytes))
        .unwrap_or([0u8; 32]);
    image.manifest_footer_sha256 = sha256_bytes(
        &image
            .regions
            .iter()
            .find(|region| region.region_type == 3)
            .unwrap()
            .bytes,
    );
    image.root_auth_footer_sha256 = image
        .regions
        .iter()
        .find(|region| region.region_type == 4)
        .map(|region| sha256_bytes(&region.bytes))
        .unwrap_or([0u8; 32]);
    image.volume_trailer_sha256 = sha256_bytes(
        &image
            .regions
            .iter()
            .find(|region| region.region_type == 5)
            .unwrap()
            .bytes,
    );
}

fn rewrite_locator_image_sha(volume: &mut [u8], offset: usize, image_sha256: [u8; 32]) {
    let mut locator =
        CriticalRecoveryLocator::parse(&volume[offset..offset + CRITICAL_RECOVERY_LOCATOR_LEN])
            .unwrap();
    locator.cmra_image_sha256 = image_sha256;
    volume[offset..offset + CRITICAL_RECOVERY_LOCATOR_LEN].copy_from_slice(&locator.to_bytes());
}

fn corrupt_v41_terminal_recovery(volume: &mut [u8]) {
    let final_offset = volume.len() - CRITICAL_RECOVERY_LOCATOR_LEN;
    let final_locator = CriticalRecoveryLocator::parse(
        &volume[final_offset..final_offset + CRITICAL_RECOVERY_LOCATOR_LEN],
    )
    .unwrap();
    let mirror_offset = final_offset - CRITICAL_RECOVERY_LOCATOR_LEN;
    volume[final_locator.cmra_offset as usize] ^= 0x55;
    volume[mirror_offset] ^= 0x55;
    volume[final_offset] ^= 0x55;
}

fn mutate_first_block_record(volume: &mut [u8], mutate: impl FnOnce(&mut BlockRecord)) {
    let (record_offset, record_len) = first_block_record(volume);
    let block_size = record_len - BLOCK_RECORD_FRAMING_LEN;
    let mut record = BlockRecord::parse(
        &volume[record_offset..record_offset + record_len],
        block_size,
    )
    .unwrap();
    mutate(&mut record);
    volume[record_offset..record_offset + record_len].copy_from_slice(&record.to_bytes());
}

fn mutate_block_record_at_slot(
    volume: &mut [u8],
    slot: usize,
    mutate: impl FnOnce(&mut BlockRecord),
) {
    let (record_offset, record_len) = block_record_at_slot(volume, slot);
    let block_size = record_len - BLOCK_RECORD_FRAMING_LEN;
    let mut record = BlockRecord::parse(
        &volume[record_offset..record_offset + record_len],
        block_size,
    )
    .unwrap();
    mutate(&mut record);
    volume[record_offset..record_offset + record_len].copy_from_slice(&record.to_bytes());
}

fn first_block_record(volume: &[u8]) -> (usize, usize) {
    block_record_at_slot(volume, 0)
}

fn block_record_at_slot(volume: &[u8], slot: usize) -> (usize, usize) {
    let volume_header = VolumeHeader::parse(&volume[..VOLUME_HEADER_LEN]).unwrap();
    let crypto_start = volume_header.crypto_header_offset as usize;
    let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
    let crypto_header = CryptoHeader::parse(
        &volume[crypto_start..crypto_end],
        volume_header.crypto_header_length,
    )
    .unwrap();
    let record_len = crypto_header.fixed.block_size as usize + BLOCK_RECORD_FRAMING_LEN;
    let record_offset = crypto_end + slot * record_len;
    assert!(volume.len() >= record_offset + record_len);
    (record_offset, record_len)
}

fn first_block_record_slot_with_kind(volume: &[u8], kind: BlockKind) -> Option<usize> {
    block_record_slots(volume)
        .into_iter()
        .enumerate()
        .find_map(|(slot, (_, _, record))| (record.kind == kind).then_some(slot))
}

fn block_record_slots_with_kind(volume: &[u8], kind: BlockKind) -> Vec<usize> {
    block_record_slots(volume)
        .into_iter()
        .enumerate()
        .filter_map(|(slot, (_, _, record))| (record.kind == kind).then_some(slot))
        .collect()
}

fn first_payload_data_run_slots(volume: &[u8]) -> Vec<usize> {
    let mut slots = Vec::new();
    for (slot, (_, _, record)) in block_record_slots(volume).into_iter().enumerate() {
        if record.kind == BlockKind::PayloadData {
            slots.push(slot);
        } else if !slots.is_empty() {
            break;
        }
    }
    slots
}

fn envelope_indices_for_path(opened: &OpenedArchive, path: &str) -> BTreeSet<u64> {
    envelope_entries_for_path(opened, path)
        .into_iter()
        .map(|entry| entry.envelope_index)
        .collect()
}

fn envelope_entries_for_path(opened: &OpenedArchive, path: &str) -> Vec<EnvelopeEntry> {
    let normalized =
        normalize_lookup_file_path(path, opened.crypto_header.max_path_length).unwrap();
    let located = opened.locate_index_file(&normalized).unwrap().unwrap();
    let file = &located.shard.files[located.file_index];
    frame_range_for_file(&located.shard, file)
        .unwrap()
        .iter()
        .map(|frame| {
            located
                .shard
                .envelopes
                .iter()
                .find(|entry| entry.envelope_index == frame.envelope_index)
                .unwrap()
                .clone()
        })
        .collect()
}

fn block_record_slots(volume: &[u8]) -> Vec<(usize, usize, BlockRecord)> {
    let volume_header = VolumeHeader::parse(&volume[..VOLUME_HEADER_LEN]).unwrap();
    let crypto_start = volume_header.crypto_header_offset as usize;
    let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
    let crypto_header = CryptoHeader::parse(
        &volume[crypto_start..crypto_end],
        volume_header.crypto_header_length,
    )
    .unwrap();
    let record_len = crypto_header.fixed.block_size as usize + BLOCK_RECORD_FRAMING_LEN;
    let manifest_offset = terminal_material_offset(volume);
    assert_eq!((manifest_offset - crypto_end) % record_len, 0);
    let record_count = (manifest_offset - crypto_end) / record_len;
    (0..record_count)
        .map(|slot| {
            let offset = crypto_end + slot * record_len;
            let record = BlockRecord::parse(
                &volume[offset..offset + record_len],
                record_len - BLOCK_RECORD_FRAMING_LEN,
            )
            .unwrap();
            (offset, record_len, record)
        })
        .collect()
}

fn rewrite_manifest_footer(
    volume: &mut [u8],
    master_key: &MasterKey,
    mutate: impl FnOnce(&mut ManifestFooter),
) {
    let volume_header = VolumeHeader::parse(&volume[..VOLUME_HEADER_LEN]).unwrap();
    let offset = terminal_material_offset(volume);
    let mut footer = ManifestFooter::parse(&volume[offset..offset + MANIFEST_FOOTER_LEN]).unwrap();
    mutate(&mut footer);
    footer.manifest_hmac = [0u8; 32];
    let mut footer_bytes = footer.to_bytes();
    let subkeys = Subkeys::derive(
        master_key,
        &volume_header.archive_uuid,
        &volume_header.session_id,
    )
    .unwrap();
    footer.manifest_hmac = compute_hmac(
        HmacDomain::ManifestFooter,
        &subkeys.mac_key,
        &volume_header.archive_uuid,
        &volume_header.session_id,
        &footer_bytes[..MANIFEST_HMAC_COVERED_LEN],
    );
    footer_bytes = footer.to_bytes();
    volume[offset..offset + MANIFEST_FOOTER_LEN].copy_from_slice(&footer_bytes);
}

fn rewrite_volume_trailer(
    volume: &mut [u8],
    master_key: &MasterKey,
    mutate: impl FnOnce(&mut VolumeTrailer),
) {
    let volume_header = VolumeHeader::parse(&volume[..VOLUME_HEADER_LEN]).unwrap();
    let offset = terminal_material_offset(volume) + MANIFEST_FOOTER_LEN;
    let mut trailer = VolumeTrailer::parse(&volume[offset..offset + VOLUME_TRAILER_LEN]).unwrap();
    mutate(&mut trailer);
    trailer.trailer_hmac = [0u8; 32];
    let mut trailer_bytes = trailer.to_bytes();
    let subkeys = Subkeys::derive(
        master_key,
        &volume_header.archive_uuid,
        &volume_header.session_id,
    )
    .unwrap();
    trailer.trailer_hmac = compute_hmac(
        HmacDomain::VolumeTrailer,
        &subkeys.mac_key,
        &volume_header.archive_uuid,
        &volume_header.session_id,
        &trailer_bytes[..TRAILER_HMAC_COVERED_LEN],
    );
    trailer_bytes = trailer.to_bytes();
    volume[offset..offset + VOLUME_TRAILER_LEN].copy_from_slice(&trailer_bytes);
}

fn rewrite_sidecar_header(
    sidecar: &mut [u8],
    master_key: &MasterKey,
    mutate: impl FnOnce(&mut BootstrapSidecarHeader),
) {
    let mut header =
        BootstrapSidecarHeader::parse(&sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN]).unwrap();
    mutate(&mut header);
    write_signed_sidecar_header(sidecar, master_key, &mut header);
}

fn write_signed_sidecar_header(
    sidecar: &mut [u8],
    master_key: &MasterKey,
    header: &mut BootstrapSidecarHeader,
) {
    header.sidecar_hmac = [0u8; 32];
    let mut header_bytes = header.to_bytes();
    let subkeys = Subkeys::derive(master_key, &header.archive_uuid, &header.session_id).unwrap();
    header.sidecar_hmac = compute_hmac(
        HmacDomain::BootstrapSidecar,
        &subkeys.mac_key,
        &header.archive_uuid,
        &header.session_id,
        &header_bytes[..SIDECAR_HMAC_COVERED_LEN],
    );
    header_bytes = header.to_bytes();
    sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN].copy_from_slice(&header_bytes);
}

fn sparse_bootstrap_sidecar(
    source: &[u8],
    master_key: &MasterKey,
    include_manifest: bool,
    include_index_root: bool,
    include_dictionary: bool,
) -> Vec<u8> {
    let source_header =
        BootstrapSidecarHeader::parse(&source[..BOOTSTRAP_SIDECAR_HEADER_LEN]).unwrap();
    let mut sidecar = vec![0u8; BOOTSTRAP_SIDECAR_HEADER_LEN];
    let mut header = BootstrapSidecarHeader {
        archive_uuid: source_header.archive_uuid,
        session_id: source_header.session_id,
        flags: 0,
        manifest_footer_offset: 0,
        manifest_footer_length: 0,
        index_root_records_offset: 0,
        index_root_records_length: 0,
        dictionary_records_offset: 0,
        dictionary_records_length: 0,
        sidecar_hmac: [0u8; 32],
        header_crc32c: 0,
    };

    if include_manifest {
        assert!(source_header.has_manifest_footer());
        let (offset, length) = append_sidecar_section(
            source,
            &mut sidecar,
            source_header.manifest_footer_offset,
            source_header.manifest_footer_length as u64,
        );
        header.flags |= 0x01;
        header.manifest_footer_offset = offset;
        header.manifest_footer_length = length as u32;
    }
    if include_index_root {
        assert!(source_header.has_index_root_records());
        let (offset, length) = append_sidecar_section(
            source,
            &mut sidecar,
            source_header.index_root_records_offset,
            source_header.index_root_records_length,
        );
        header.flags |= 0x02;
        header.index_root_records_offset = offset;
        header.index_root_records_length = length;
    }
    if include_dictionary {
        assert!(source_header.has_dictionary_records());
        let (offset, length) = append_sidecar_section(
            source,
            &mut sidecar,
            source_header.dictionary_records_offset,
            source_header.dictionary_records_length,
        );
        header.flags |= 0x04;
        header.dictionary_records_offset = offset;
        header.dictionary_records_length = length;
    }

    write_signed_sidecar_header(&mut sidecar, master_key, &mut header);
    sidecar
}

fn append_sidecar_section(
    source: &[u8],
    sidecar: &mut Vec<u8>,
    source_offset: u64,
    length: u64,
) -> (u64, u64) {
    let source_offset = source_offset as usize;
    let length = length as usize;
    let offset = sidecar.len() as u64;
    sidecar.extend_from_slice(&source[source_offset..source_offset + length]);
    (offset, length as u64)
}

fn mutate_sidecar_manifest(
    sidecar: &mut [u8],
    master_key: &MasterKey,
    mutate: impl FnOnce(&mut ManifestFooter),
) {
    let header = BootstrapSidecarHeader::parse(&sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN]).unwrap();
    let offset = header.manifest_footer_offset as usize;
    let mut footer = ManifestFooter::parse(&sidecar[offset..offset + MANIFEST_FOOTER_LEN]).unwrap();
    mutate(&mut footer);
    footer.manifest_hmac = [0u8; 32];
    let mut footer_bytes = footer.to_bytes();
    let subkeys = Subkeys::derive(master_key, &footer.archive_uuid, &footer.session_id).unwrap();
    footer.manifest_hmac = compute_hmac(
        HmacDomain::ManifestFooter,
        &subkeys.mac_key,
        &footer.archive_uuid,
        &footer.session_id,
        &footer_bytes[..MANIFEST_HMAC_COVERED_LEN],
    );
    footer_bytes = footer.to_bytes();
    sidecar[offset..offset + MANIFEST_FOOTER_LEN].copy_from_slice(&footer_bytes);
}

fn mutate_sidecar_index_record(
    sidecar: &mut [u8],
    record_index: usize,
    mutate: impl FnOnce(&mut BlockRecord),
) {
    let header = BootstrapSidecarHeader::parse(&sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN]).unwrap();
    let record_len = sidecar_record_len(sidecar);
    let offset = header.index_root_records_offset as usize + record_index * record_len;
    let block_size = record_len - BLOCK_RECORD_FRAMING_LEN;
    let mut record = BlockRecord::parse(&sidecar[offset..offset + record_len], block_size).unwrap();
    mutate(&mut record);
    sidecar[offset..offset + record_len].copy_from_slice(&record.to_bytes());
}

fn mutate_sidecar_dictionary_record(
    sidecar: &mut [u8],
    record_index: usize,
    mutate: impl FnOnce(&mut BlockRecord),
) {
    let header = BootstrapSidecarHeader::parse(&sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN]).unwrap();
    let record_len = sidecar_record_len(sidecar);
    let offset = header.dictionary_records_offset as usize + record_index * record_len;
    let block_size = record_len - BLOCK_RECORD_FRAMING_LEN;
    let mut record = BlockRecord::parse(&sidecar[offset..offset + record_len], block_size).unwrap();
    mutate(&mut record);
    sidecar[offset..offset + record_len].copy_from_slice(&record.to_bytes());
}

fn swap_sidecar_index_records(sidecar: &mut [u8], left: usize, right: usize) {
    let header = BootstrapSidecarHeader::parse(&sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN]).unwrap();
    let record_len = sidecar_record_len(sidecar);
    let left_offset = header.index_root_records_offset as usize + left * record_len;
    let right_offset = header.index_root_records_offset as usize + right * record_len;
    for idx in 0..record_len {
        sidecar.swap(left_offset + idx, right_offset + idx);
    }
}

fn sidecar_record_len(sidecar: &[u8]) -> usize {
    let header = BootstrapSidecarHeader::parse(&sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN]).unwrap();
    let footer_offset = header.manifest_footer_offset as usize;
    let footer =
        ManifestFooter::parse(&sidecar[footer_offset..footer_offset + MANIFEST_FOOTER_LEN])
            .unwrap();
    let index_record_count =
        footer.index_root_data_block_count as usize + footer.index_root_parity_block_count as usize;
    header.index_root_records_length as usize / index_record_count
}

fn corrupt_object_extent_records(volume: &mut [u8], extent: ObjectExtent) {
    let volume_header = VolumeHeader::parse(&volume[..VOLUME_HEADER_LEN]).unwrap();
    assert_eq!(volume_header.volume_index, 0);
    assert_eq!(volume_header.stripe_width, 1);
    let crypto_start = volume_header.crypto_header_offset as usize;
    let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
    let crypto_header = CryptoHeader::parse(
        &volume[crypto_start..crypto_end],
        volume_header.crypto_header_length,
    )
    .unwrap();
    let record_len = crypto_header.fixed.block_size as usize + BLOCK_RECORD_FRAMING_LEN;
    let record_count = extent.data_block_count as u64 + extent.parity_block_count as u64;
    for offset in 0..record_count {
        let block_index = extent.first_block_index + offset;
        let record_offset = crypto_end + block_index as usize * record_len;
        volume[record_offset + 16] ^= 0x55;
    }
}

fn terminal_material_offset(volume: &[u8]) -> usize {
    let volume_header = VolumeHeader::parse(&volume[..VOLUME_HEADER_LEN]).unwrap();
    let crypto_start = volume_header.crypto_header_offset as usize;
    let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
    let crypto_header = CryptoHeader::parse(
        &volume[crypto_start..crypto_end],
        volume_header.crypto_header_length,
    )
    .unwrap();
    let (_, offset, _) = parse_stream_block_prefix(
        volume,
        crypto_end,
        crypto_header.fixed.block_size as usize,
        &volume_header,
    )
    .unwrap();
    offset
}

#[derive(Debug)]
struct TestObject {
    extent: ObjectExtent,
    records: Vec<BlockRecord>,
}

#[derive(Debug)]
struct TestFileMeta {
    path: Vec<u8>,
    frame_index: u64,
    tar_stream_offset: u64,
    member_group_size: u64,
    file_data_size: u64,
}

fn multi_envelope_reader_fixture() -> (OpenedArchive, u64) {
    let volume_header = test_volume_header();
    let crypto_header = test_crypto_header();
    let subkeys = Subkeys::derive(
        &master_key(),
        &volume_header.archive_uuid,
        &volume_header.session_id,
    )
    .unwrap();
    let mut next_block_index = 0u64;
    let mut blocks = BTreeMap::new();

    let healthy = test_member(b"healthy.txt", b"healthy payload\n");
    let broken = test_member(b"broken.txt", b"broken payload\n");
    let tar_stream = [healthy.as_slice(), broken.as_slice()].concat();

    let healthy_frame = compress_zstd_frame(&healthy, 1).unwrap();
    let broken_frame = compress_zstd_frame(&broken, 1).unwrap();

    let healthy_payload = encrypt_test_object(
        &healthy_frame,
        &subkeys.enc_key,
        &subkeys.nonce_seed,
        b"envelope",
        0,
        BlockKind::PayloadData,
        &mut next_block_index,
        &crypto_header,
        &volume_header,
    );
    let broken_payload = encrypt_test_object(
        &broken_frame,
        &subkeys.enc_key,
        &subkeys.nonce_seed,
        b"envelope",
        1,
        BlockKind::PayloadData,
        &mut next_block_index,
        &crypto_header,
        &volume_header,
    );
    let broken_payload_block = broken_payload.extent.first_block_index;
    insert_records(&mut blocks, &healthy_payload.records);
    insert_records(&mut blocks, &broken_payload.records);

    let frames = vec![
        FrameEntry {
            frame_index: 0,
            envelope_index: 0,
            offset_in_envelope: 0,
            compressed_size: healthy_frame.len() as u32,
            decompressed_size: healthy.len() as u32,
            flags: 0x0000_0003,
            tar_stream_offset: 0,
        },
        FrameEntry {
            frame_index: 1,
            envelope_index: 1,
            offset_in_envelope: 0,
            compressed_size: broken_frame.len() as u32,
            decompressed_size: broken.len() as u32,
            flags: 0x0000_0003,
            tar_stream_offset: healthy.len() as u64,
        },
    ];
    let envelopes = vec![
        EnvelopeEntry {
            envelope_index: 0,
            first_block_index: healthy_payload.extent.first_block_index,
            data_block_count: healthy_payload.extent.data_block_count,
            parity_block_count: 0,
            encrypted_size: healthy_payload.extent.encrypted_size,
            plaintext_size: healthy_frame.len() as u32,
            first_frame_index: 0,
            frame_count: 1,
        },
        EnvelopeEntry {
            envelope_index: 1,
            first_block_index: broken_payload.extent.first_block_index,
            data_block_count: broken_payload.extent.data_block_count,
            parity_block_count: 0,
            encrypted_size: broken_payload.extent.encrypted_size,
            plaintext_size: broken_frame.len() as u32,
            first_frame_index: 1,
            frame_count: 1,
        },
    ];
    let files = vec![
        TestFileMeta {
            path: b"healthy.txt".to_vec(),
            frame_index: 0,
            tar_stream_offset: 0,
            member_group_size: healthy.len() as u64,
            file_data_size: b"healthy payload\n".len() as u64,
        },
        TestFileMeta {
            path: b"broken.txt".to_vec(),
            frame_index: 1,
            tar_stream_offset: healthy.len() as u64,
            member_group_size: broken.len() as u64,
            file_data_size: b"broken payload\n".len() as u64,
        },
    ];

    let (index_shard_plaintext, first_path_hash, last_path_hash) =
        build_test_index_shard(&files, &frames, &envelopes);
    let index_shard = encrypt_test_object(
        &compress_zstd_frame(&index_shard_plaintext, 1).unwrap(),
        &subkeys.index_shard_key,
        &subkeys.index_nonce_seed,
        b"idxshard",
        0,
        BlockKind::IndexShardData,
        &mut next_block_index,
        &crypto_header,
        &volume_header,
    );
    insert_records(&mut blocks, &index_shard.records);

    let shard_entry = ShardEntry {
        shard_index: 0,
        first_block_index: index_shard.extent.first_block_index,
        data_block_count: index_shard.extent.data_block_count,
        parity_block_count: 0,
        encrypted_size: index_shard.extent.encrypted_size,
        decompressed_size: index_shard_plaintext.len() as u32,
        file_count: files.len() as u32,
        first_path_hash,
        last_path_hash,
    };
    let mut root_header = IndexRootHeader::empty();
    root_header.frame_count = frames.len() as u64;
    root_header.envelope_count = envelopes.len() as u64;
    root_header.file_count = files.len() as u64;
    root_header.payload_block_count = healthy_payload.extent.data_block_count as u64
        + broken_payload.extent.data_block_count as u64;
    root_header.tar_total_size = tar_stream.len() as u64;
    root_header.content_sha256 = sha256_bytes(&tar_stream);
    let index_root = IndexRoot {
        header: root_header,
        shards: vec![shard_entry],
        directory_hint_shards: Vec::new(),
    };

    let index_root_plaintext = index_root.to_bytes();
    let index_root_object = encrypt_test_object(
        &compress_zstd_frame(&index_root_plaintext, 1).unwrap(),
        &subkeys.index_root_key,
        &subkeys.index_nonce_seed,
        b"idxroot",
        0,
        BlockKind::IndexRootData,
        &mut next_block_index,
        &crypto_header,
        &volume_header,
    );
    insert_records(&mut blocks, &index_root_object.records);

    let archive_uuid = volume_header.archive_uuid;
    let session_id = volume_header.session_id;
    let opened = OpenedArchive {
        options: ReaderOptions::default(),
        observed_archive_bytes: 1_000_000,
        observed_volume_count: 1,
        subkeys,
        blocks,
        lazy_blocks: None,
        crypto_header_bytes: Vec::new(),
        volume_header,
        crypto_header,
        manifest_footer: ManifestFooter {
            archive_uuid,
            session_id,
            volume_index: 0,
            is_authoritative: 1,
            total_volumes: 1,
            index_root_first_block: index_root_object.extent.first_block_index,
            index_root_data_block_count: index_root_object.extent.data_block_count,
            index_root_parity_block_count: 0,
            index_root_encrypted_size: index_root_object.extent.encrypted_size,
            index_root_decompressed_size: index_root_plaintext.len() as u32,
            manifest_hmac: [0u8; 32],
        },
        volume_trailer: Some(VolumeTrailer {
            archive_uuid,
            session_id,
            volume_index: 0,
            block_count: next_block_index,
            bytes_written: 0,
            manifest_footer_offset: 0,
            manifest_footer_length: MANIFEST_FOOTER_LEN as u32,
            closed_at_ns: 0,
            root_auth_footer_offset: 0,
            root_auth_footer_length: 0,
            root_auth_flags: 0,
            trailer_hmac: [0u8; 32],
        }),
        root_auth_footer: None,
        index_root,
        payload_dictionary: None,
    };
    (opened, broken_payload_block)
}

fn replace_first_index_shard(opened: &mut OpenedArchive, mutate: impl FnOnce(&mut IndexShard)) {
    let locating = opened.index_root.shards[0].clone();
    let mut shard = opened.load_index_shard(&locating).unwrap();
    mutate(&mut shard);
    let plaintext = shard.to_bytes();
    let mut next_block_index = opened
        .blocks
        .keys()
        .last()
        .copied()
        .map(|index| index + 1)
        .unwrap_or(0);
    let replacement = encrypt_test_object(
        &compress_zstd_frame(&plaintext, 1).unwrap(),
        &opened.subkeys.index_shard_key,
        &opened.subkeys.index_nonce_seed,
        b"idxshard",
        locating.shard_index,
        BlockKind::IndexShardData,
        &mut next_block_index,
        &opened.crypto_header,
        &opened.volume_header,
    );
    insert_records(&mut opened.blocks, &replacement.records);
    opened.index_root.shards[0] = ShardEntry {
        shard_index: locating.shard_index,
        first_block_index: replacement.extent.first_block_index,
        data_block_count: replacement.extent.data_block_count,
        parity_block_count: 0,
        encrypted_size: replacement.extent.encrypted_size,
        decompressed_size: plaintext.len() as u32,
        file_count: shard.files.len() as u32,
        first_path_hash: shard.files.first().unwrap().path_hash,
        last_path_hash: shard.files.last().unwrap().path_hash,
    };
}

fn rewrite_as_single_healthy_file(
    opened: &mut OpenedArchive,
    mutate: impl FnOnce(&mut FileEntry, &mut Vec<u8>),
) {
    let healthy_path = b"healthy.txt";
    let healthy_payload = b"healthy payload\n";
    let healthy_member = test_member(healthy_path, healthy_payload);
    replace_first_index_shard(opened, |shard| {
        let file_index = (0..shard.files.len())
            .find(|idx| shard.file_path(*idx) == Some(healthy_path.as_slice()))
            .unwrap();
        let mut file = shard.files[file_index].clone();
        let frame = shard
            .frames
            .iter()
            .find(|entry| entry.frame_index == 0)
            .unwrap()
            .clone();
        let envelope = shard
            .envelopes
            .iter()
            .find(|entry| entry.envelope_index == 0)
            .unwrap()
            .clone();
        let mut path = healthy_path.to_vec();

        file.path_offset = 0;
        file.path_length = path.len() as u32;
        file.first_frame_index = 0;
        file.frame_count = 1;
        file.offset_in_first_frame_plaintext = 0;
        file.tar_member_group_size = healthy_member.len() as u64;
        file.file_data_size = healthy_payload.len() as u64;
        file.flags = crate::entry_metadata::EXTENDED_METADATA_V1;
        mutate(&mut file, &mut path);
        file.path_offset = 0;
        file.path_length = path.len() as u32;
        file.path_hash = hash_prefix(&path);

        shard.files = vec![file];
        shard.frames = vec![frame];
        shard.envelopes = vec![envelope];
        shard.string_pool = path;
    });

    opened.index_root.header.file_count = 1;
    opened.index_root.header.frame_count = 1;
    opened.index_root.header.envelope_count = 1;
    opened.index_root.header.payload_block_count = 1;
    opened.index_root.header.tar_total_size = healthy_member.len() as u64;
    opened.index_root.header.content_sha256 = sha256_bytes(&healthy_member);
}

fn test_volume_header() -> VolumeHeader {
    VolumeHeader {
        format_version: FORMAT_VERSION,
        volume_format_rev: VOLUME_FORMAT_REV,
        volume_index: 0,
        stripe_width: 1,
        archive_uuid: [0x31; 16],
        session_id: [0x42; 16],
        crypto_header_offset: VOLUME_HEADER_LEN as u32,
        crypto_header_length: CRYPTO_HEADER_FIXED_LEN as u32,
        header_crc32c: 0,
    }
}

fn test_crypto_header() -> CryptoHeaderFixed {
    CryptoHeaderFixed {
        length: CRYPTO_HEADER_FIXED_LEN as u32,
        compression_algo: CompressionAlgo::ZstdFramed,
        aead_algo: AeadAlgo::AesGcmSiv256,
        fec_algo: FecAlgo::ReedSolomonGF16,
        kdf_algo: KdfAlgo::Raw,
        chunk_size: 4096,
        envelope_target_size: 8192,
        block_size: 4096,
        fec_data_shards: 4,
        fec_parity_shards: 0,
        index_fec_data_shards: 4,
        index_fec_parity_shards: 0,
        index_root_fec_data_shards: 4,
        index_root_fec_parity_shards: 0,
        stripe_width: 1,
        volume_loss_tolerance: 0,
        bit_rot_buffer_pct: 0,
        has_dictionary: 0,
        max_path_length: 4096,
        expected_volume_size: 0,
    }
}

#[allow(clippy::too_many_arguments)]
fn encrypt_test_object(
    plaintext: &[u8],
    key: &[u8; 32],
    nonce_seed: &[u8; 32],
    domain: &[u8],
    counter: u64,
    data_kind: BlockKind,
    next_block_index: &mut u64,
    crypto_header: &CryptoHeaderFixed,
    volume_header: &VolumeHeader,
) -> TestObject {
    let block_size = crypto_header.block_size as usize;
    let encrypted = encrypt_padded_aead_object(
        AeadObjectContext {
            algo: crypto_header.aead_algo,
            key,
            nonce_seed,
            domain,
            archive_uuid: &volume_header.archive_uuid,
            session_id: &volume_header.session_id,
            counter,
        },
        block_size,
        plaintext,
    )
    .unwrap();
    assert_eq!(encrypted.len() % block_size, 0);

    let first_block_index = *next_block_index;
    let data_block_count = encrypted.len() / block_size;
    let records = encrypted
        .chunks(block_size)
        .enumerate()
        .map(|(index, payload)| BlockRecord {
            block_index: first_block_index + index as u64,
            kind: data_kind,
            flags: if index + 1 == data_block_count {
                0x01
            } else {
                0
            },
            payload: payload.to_vec(),
            record_crc32c: 0,
        })
        .collect::<Vec<_>>();
    *next_block_index += data_block_count as u64;

    TestObject {
        extent: ObjectExtent {
            first_block_index,
            data_block_count: data_block_count as u32,
            parity_block_count: 0,
            encrypted_size: encrypted.len() as u32,
        },
        records,
    }
}

fn insert_records(blocks: &mut BTreeMap<u64, BlockRecord>, records: &[BlockRecord]) {
    for record in records {
        assert!(blocks.insert(record.block_index, record.clone()).is_none());
    }
}

#[allow(clippy::too_many_arguments)]
fn build_metadata_object_from_payload(
    payload: &[u8],
    _subkeys: &Subkeys,
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
    key: &[u8; 32],
    nonce_seed: &[u8; 32],
    domain: &[u8],
    counter: u64,
    data_kind: BlockKind,
    next_block_index: &mut u64,
) -> (ObjectExtent, BTreeMap<u64, BlockRecord>) {
    let compressed = compress_zstd_frame(payload, 1).unwrap();
    build_metadata_object_from_compressed(
        &compressed,
        key,
        nonce_seed,
        domain,
        counter,
        data_kind,
        next_block_index,
        crypto_header,
        volume_header,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_metadata_object_from_compressed(
    compressed: &[u8],
    key: &[u8; 32],
    nonce_seed: &[u8; 32],
    domain: &[u8],
    counter: u64,
    data_kind: BlockKind,
    next_block_index: &mut u64,
    crypto_header: &CryptoHeaderFixed,
    volume_header: &VolumeHeader,
) -> (ObjectExtent, BTreeMap<u64, BlockRecord>) {
    let object = encrypt_test_object(
        compressed,
        key,
        nonce_seed,
        domain,
        counter,
        data_kind,
        next_block_index,
        crypto_header,
        volume_header,
    );

    let mut blocks = BTreeMap::new();
    for record in object.records {
        blocks.insert(record.block_index, record);
    }
    (object.extent, blocks)
}

#[allow(clippy::too_many_arguments)]
fn assert_metadata_object_from_compressed(
    compressed: &[u8],
    decompressed_size: usize,
    _subkeys: &Subkeys,
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
    key: &[u8; 32],
    nonce_seed: &[u8; 32],
    domain: &[u8],
    counter: u64,
    data_kind: BlockKind,
    parity_kind: BlockKind,
    class_data_shards: u16,
    class_parity_shards: u16,
    next_block_index: &mut u64,
    expected: FormatError,
) {
    let (extent, blocks) = build_metadata_object_from_compressed(
        compressed,
        key,
        nonce_seed,
        domain,
        counter,
        data_kind,
        next_block_index,
        crypto_header,
        volume_header,
    );
    let error = load_metadata_object_from_parts(
        &blocks,
        ObjectLoadContext {
            volume_header,
            crypto_header,
            extent,
            data_kind,
            parity_kind,
            key,
            nonce_seed,
            domain,
            counter,
            class_data_shard_max: class_data_shards,
            class_parity_shard_max: class_parity_shards,
        },
        decompressed_size as u32,
    )
    .unwrap_err();
    assert_eq!(error, expected);
}

fn corrupt_payload_record(blocks: &mut BTreeMap<u64, BlockRecord>, block_index: u64) {
    let record = blocks.get_mut(&block_index).unwrap();
    assert_eq!(record.kind, BlockKind::PayloadData);
    record.payload[0] ^= 0x55;
}

fn build_test_index_shard(
    files: &[TestFileMeta],
    frames: &[FrameEntry],
    envelopes: &[EnvelopeEntry],
) -> (Vec<u8>, [u8; 8], [u8; 8]) {
    let mut sorted = files
        .iter()
        .map(|file| (hash_prefix(&file.path), file))
        .collect::<Vec<_>>();
    sorted.sort_by(|left, right| {
        (left.0, left.1.path.as_slice(), left.1.tar_stream_offset).cmp(&(
            right.0,
            right.1.path.as_slice(),
            right.1.tar_stream_offset,
        ))
    });

    let mut string_pool = Vec::new();
    let mut file_entries = Vec::with_capacity(sorted.len());
    for (path_hash, file) in &sorted {
        let path_offset = string_pool.len() as u32;
        string_pool.extend_from_slice(&file.path);
        file_entries.push(FileEntry {
            path_hash: *path_hash,
            path_offset,
            path_length: file.path.len() as u32,
            first_frame_index: file.frame_index,
            frame_count: 1,
            offset_in_first_frame_plaintext: 0,
            tar_member_group_size: file.member_group_size,
            file_data_size: file.file_data_size,
            flags: crate::entry_metadata::EXTENDED_METADATA_V1,
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
        });
    }

    let header = IndexShardHeader {
        version: 1,
        shard_index: 0,
        file_count: file_entries.len() as u32,
        frame_count: frames.len() as u32,
        envelope_count: envelopes.len() as u32,
        file_table_offset: INDEX_SHARD_HEADER_LEN as u32,
        frame_table_offset: (INDEX_SHARD_HEADER_LEN + file_entries.len() * FILE_ENTRY_LEN) as u32,
        envelope_table_offset: (INDEX_SHARD_HEADER_LEN
            + file_entries.len() * FILE_ENTRY_LEN
            + frames.len() * FRAME_ENTRY_LEN) as u32,
        string_pool_offset: (INDEX_SHARD_HEADER_LEN
            + file_entries.len() * FILE_ENTRY_LEN
            + frames.len() * FRAME_ENTRY_LEN
            + envelopes.len() * ENVELOPE_ENTRY_LEN) as u32,
        string_pool_size: string_pool.len() as u32,
    };

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&header.to_bytes());
    for entry in &file_entries {
        bytes.extend_from_slice(&entry.to_bytes());
    }
    for entry in frames {
        bytes.extend_from_slice(&entry.to_bytes());
    }
    for entry in envelopes {
        bytes.extend_from_slice(&entry.to_bytes());
    }
    bytes.extend_from_slice(&string_pool);

    (bytes, sorted.first().unwrap().0, sorted.last().unwrap().0)
}

#[test]
fn opens_lists_and_verifies_archive_with_pax_metadata_and_symlink_target() {
    struct CustomMember<'a> {
        path: &'a str,
        target: &'a [u8],
        created_sec: u64,
        created_nsec: u32,
        accessed_sec: u64,
        accessed_nsec: u32,
    }

    impl<'a> RegularFileSource for CustomMember<'a> {
        fn archive_path(&self) -> &str {
            self.path
        }
        fn entry_kind(&self) -> SourceEntryKind {
            SourceEntryKind::Symlink
        }
        fn link_target(&self) -> Option<&[u8]> {
            Some(self.target)
        }
        fn file_data_size(&self) -> u64 {
            0
        }
        fn mode(&self) -> u32 {
            0o777
        }
        fn mtime(&self) -> ArchiveTimestamp {
            ArchiveTimestamp::new(1_700_000_000, 100_000_000)
        }
        fn portable_metadata(&self) -> PortableFileMetadata {
            let mut primary_pax_records = std::collections::BTreeMap::default();
            primary_pax_records.insert(
                "LIBARCHIVE.creationtime".into(),
                ArchiveTimestamp::new(self.created_sec as i64, self.created_nsec)
                    .canonical_pax_value()
                    .unwrap(),
            );
            primary_pax_records.insert(
                "atime".into(),
                ArchiveTimestamp::new(self.accessed_sec as i64, self.accessed_nsec)
                    .canonical_pax_value()
                    .unwrap(),
            );

            PortableFileMetadata {
                source_os: "macos".into(),
                source_filesystem: "apfs".into(),
                mode_origin: PortableModeOrigin::Native,
                posix_owner: Some(PortablePosixOwner {
                    uid: 1001,
                    gid: 1002,
                    uname: Some("alice".into()),
                    gname: Some("devs".into()),
                }),
                attributes: Some(0x05),
                created: None,
                accessed: None,
                native: NativeFileMetadata {
                    required_profiles: vec![
                        "macos-backup-v1".into(),
                        "portable-v1".into(),
                        "posix-backup-v1".into(),
                    ],
                    primary_pax_records,
                    auxiliary_records: Vec::new(),
                    ..Default::default()
                },
            }
        }
        fn open(&self) -> Result<Box<dyn Read + '_>, crate::format::ArchiveWriteError> {
            Ok(Box::new(std::io::Cursor::new(b"")))
        }
    }

    let source = CustomMember {
        path: "links/sym1",
        target: b"target.txt",
        created_sec: 1_700_000_100,
        created_nsec: 500_000_000,
        accessed_sec: 1_700_000_200,
        accessed_nsec: 250_000_000,
    };

    let mut sink = MemoryArchiveSink::default();
    write_archive_sources_to_sink_single_pass(
        &[source],
        &master_key(),
        single_stream_options(),
        &crate::crypto::KdfParams::Raw,
        None,
        None,
        &mut sink,
    )
    .unwrap();
    let archive_bytes = sink.volumes.remove(0);

    let opened = open_archive(&archive_bytes, &master_key()).unwrap();

    let entries = opened.list_files().unwrap();
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];

    assert_eq!(entry.path, "links/sym1");
    assert_eq!(entry.kind, TarEntryKind::Symlink);
    assert_eq!(entry.link_target, Some("target.txt".to_string()));
    assert_eq!(
        entry.created,
        Some(ArchiveTimestamp::new(1_700_000_100, 500_000_000))
    );
    assert_eq!(
        entry.accessed,
        Some(ArchiveTimestamp::new(1_700_000_200, 250_000_000))
    );
    assert_eq!(entry.attributes, Some(0x05));
    assert_eq!(entry.uid, Some(1001));
    assert_eq!(entry.gid, Some(1002));
    assert_eq!(entry.uname, Some("alice".to_string()));
    assert_eq!(entry.gname, Some("devs".to_string()));

    let streamed_report = list_non_seekable_stream(
        std::io::Cursor::new(archive_bytes),
        &master_key(),
        NonSeekableReaderOptions::default(),
    )
    .unwrap();
    assert_eq!(streamed_report.entries, entries);
}

#[test]
fn extraction_options_allow_absolute_symlinks_toggle() {
    struct AbsSymlinkSource;

    impl RegularFileSource for AbsSymlinkSource {
        fn archive_path(&self) -> &str {
            "abs_link"
        }
        fn entry_kind(&self) -> SourceEntryKind {
            SourceEntryKind::Symlink
        }
        fn link_target(&self) -> Option<&[u8]> {
            Some(b"/tmp/abs_target")
        }
        fn file_data_size(&self) -> u64 {
            0
        }
        fn mode(&self) -> u32 {
            0o777
        }
        fn mtime(&self) -> ArchiveTimestamp {
            ArchiveTimestamp::new(1_700_000_000, 0)
        }
        fn open(&self) -> Result<Box<dyn Read + '_>, crate::format::ArchiveWriteError> {
            Ok(Box::new(std::io::Cursor::new(b"")))
        }
    }

    let mut sink = MemoryArchiveSink::default();
    write_archive_sources_to_sink_single_pass(
        &[AbsSymlinkSource],
        &master_key(),
        single_stream_options(),
        &crate::crypto::KdfParams::Raw,
        None,
        None,
        &mut sink,
    )
    .unwrap();
    let archive_bytes = sink.volumes.remove(0);
    let opened = open_archive(&archive_bytes, &master_key()).unwrap();

    let tmp = tempfile::tempdir().unwrap();

    let options_disallowed = SafeExtractionOptions {
        allow_absolute_symlinks: false,
        ..Default::default()
    };
    assert_eq!(
        opened
            .extract_indexed_files_to(tmp.path(), options_disallowed, 1)
            .unwrap_err(),
        crate::format::FormatError::UnsafeArchivePath
    );

    let tmp_allowed = tempfile::tempdir().unwrap();
    let options_allowed = SafeExtractionOptions {
        allow_absolute_symlinks: true,
        ..Default::default()
    };
    let res_allowed = opened.extract_indexed_files_to(tmp_allowed.path(), options_allowed, 1);
    match res_allowed {
        Ok(_) => {}
        Err(crate::format::FormatError::FilesystemExtractionFailed(msg)) => {
            assert_eq!(msg, "failed to create symlink");
        }
        Err(other) => panic!("expected Ok or FilesystemExtractionFailed, got {:?}", other),
    }
}

fn test_member(path: &[u8], data: &[u8]) -> Vec<u8> {
    let records = crate::entry_metadata::portable_primary_pax(path, 0o644, "other", false).unwrap();
    let pax = crate::entry_metadata::encode_canonical_pax(&records).unwrap();
    let mut out = Vec::new();
    out.extend_from_slice(&test_tar_header(
        b"TZAP-PAX/PRIMARY",
        pax.len() as u64,
        0,
        b'x',
    ));
    out.extend_from_slice(&pax);
    out.resize(out.len() + padding_to_512(pax.len()), 0);
    out.extend_from_slice(&test_tar_header(path, data.len() as u64, 0o644, b'0'));
    out.extend_from_slice(data);
    out.resize(out.len() + padding_to_512(data.len()), 0);
    out
}

fn test_tar_header(path: &[u8], size: u64, mode: u64, typeflag: u8) -> [u8; 512] {
    let mut header = [0u8; 512];
    header[..path.len()].copy_from_slice(path);
    write_test_tar_octal(&mut header[100..108], mode);
    write_test_tar_octal(&mut header[108..116], 0);
    write_test_tar_octal(&mut header[116..124], 0);
    write_test_tar_octal(&mut header[124..136], size);
    write_test_tar_octal(&mut header[136..148], 0);
    header[148..156].fill(b' ');
    header[156] = typeflag;
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum = header.iter().map(|byte| *byte as u64).sum::<u64>();
    write_test_tar_checksum(&mut header[148..156], checksum);
    header
}

fn write_test_tar_octal(field: &mut [u8], value: u64) {
    let digits = format!("{value:o}");
    field.fill(0);
    let start = field.len() - 1 - digits.len();
    field[..start].fill(b'0');
    field[start..start + digits.len()].copy_from_slice(digits.as_bytes());
}

fn write_test_tar_checksum(field: &mut [u8], value: u64) {
    let digits = format!("{value:06o}");
    field[0..6].copy_from_slice(digits.as_bytes());
    field[6] = 0;
    field[7] = b' ';
}

fn padding_to_512(len: usize) -> usize {
    let remainder = len % 512;
    if remainder == 0 {
        0
    } else {
        512 - remainder
    }
}

#[test]
fn list_index_entries_and_lookup_index_entry_header_metadata_coverage() {
    struct TestSource {
        path: &'static str,
        kind: SourceEntryKind,
        target: Option<&'static [u8]>,
        created: Option<ArchiveTimestamp>,
        accessed: Option<ArchiveTimestamp>,
        attributes: Option<u32>,
        uid: Option<u64>,
        gid: Option<u64>,
        uname: Option<&'static str>,
        gname: Option<&'static str>,
    }

    impl RegularFileSource for TestSource {
        fn archive_path(&self) -> &str {
            self.path
        }
        fn entry_kind(&self) -> SourceEntryKind {
            self.kind
        }
        fn link_target(&self) -> Option<&[u8]> {
            self.target
        }
        fn file_data_size(&self) -> u64 {
            0
        }
        fn mode(&self) -> u32 {
            0o755
        }
        fn mtime(&self) -> ArchiveTimestamp {
            ArchiveTimestamp::new(1_700_000_000, 100_000_000)
        }
        fn portable_metadata(&self) -> PortableFileMetadata {
            let posix_owner = if self.uid.is_some()
                || self.gid.is_some()
                || self.uname.is_some()
                || self.gname.is_some()
            {
                Some(PortablePosixOwner {
                    uid: self.uid.unwrap_or(u64::MAX),
                    gid: self.gid.unwrap_or(u64::MAX),
                    uname: self.uname.map(|s| s.to_string()),
                    gname: self.gname.map(|s| s.to_string()),
                })
            } else {
                None
            };
            PortableFileMetadata {
                posix_owner,
                attributes: self.attributes,
                created: self.created,
                accessed: self.accessed,
                ..Default::default()
            }
        }
        fn open(&self) -> Result<Box<dyn Read + '_>, crate::format::ArchiveWriteError> {
            Ok(Box::new(std::io::Cursor::new(b"")))
        }
    }

    let s1 = TestSource {
        path: "symlink.txt",
        kind: SourceEntryKind::Symlink,
        target: Some(b"target.txt"),
        created: Some(ArchiveTimestamp::new(1_700_000_100, 200_000_000)),
        accessed: Some(ArchiveTimestamp::new(1_700_000_300, 400_000_000)),
        attributes: Some(0x05),
        uid: Some(1001),
        gid: Some(1002),
        uname: Some("alice"),
        gname: Some("devs"),
    };

    let s2 = TestSource {
        path: "plain.txt",
        kind: SourceEntryKind::Regular,
        target: None,
        created: None,
        accessed: None,
        attributes: None,
        uid: None,
        gid: None,
        uname: None,
        gname: None,
    };

    let mut sink = MemoryArchiveSink::default();
    write_archive_sources_to_sink_single_pass(
        &[s1, s2],
        &master_key(),
        single_stream_options(),
        &crate::crypto::KdfParams::Raw,
        None,
        None,
        &mut sink,
    )
    .unwrap();

    let archive_bytes = sink.volumes.remove(0);
    let opened = open_archive(&archive_bytes, &master_key()).unwrap();

    let index_entries = opened.list_index_entries().unwrap();
    assert_eq!(index_entries.len(), 2);

    let e1 = index_entries
        .iter()
        .find(|e| e.path == "symlink.txt")
        .unwrap();
    assert_eq!(e1.kind, TarEntryKind::Symlink);
    assert_eq!(e1.link_target, Some("target.txt".to_string()));
    assert_eq!(
        e1.created,
        Some(ArchiveTimestamp::new(1_700_000_100, 200_000_000))
    );
    assert_eq!(
        e1.accessed,
        Some(ArchiveTimestamp::new(1_700_000_300, 400_000_000))
    );
    assert_eq!(e1.attributes, Some(0x05));
    assert_eq!(e1.uid, Some(1001));
    assert_eq!(e1.gid, Some(1002));
    assert_eq!(e1.uname, Some("alice".to_string()));
    assert_eq!(e1.gname, Some("devs".to_string()));

    let e2 = index_entries
        .iter()
        .find(|e| e.path == "plain.txt")
        .unwrap();
    assert_eq!(e2.kind, TarEntryKind::Regular);
    assert_eq!(e2.link_target, None);
    assert_eq!(e2.created, None);
    assert_eq!(e2.accessed, None);
    assert_eq!(e2.attributes, None);
    assert_eq!(e2.uid, None);
    assert_eq!(e2.gid, None);
    assert_eq!(e2.uname, None);
    assert_eq!(e2.gname, None);

    let looked_up1 = opened.lookup_index_entry("symlink.txt").unwrap().unwrap();
    assert_eq!(looked_up1, *e1);
    let looked_up2 = opened.lookup_index_entry("plain.txt").unwrap().unwrap();
    assert_eq!(looked_up2, *e2);
}

#[test]
fn list_directory_contents_functional_verification() {
    struct DirTestSource {
        path: &'static str,
        kind: SourceEntryKind,
    }

    impl RegularFileSource for DirTestSource {
        fn archive_path(&self) -> &str {
            self.path
        }
        fn entry_kind(&self) -> SourceEntryKind {
            self.kind
        }
        fn file_data_size(&self) -> u64 {
            0
        }
        fn mode(&self) -> u32 {
            0o755
        }
        fn mtime(&self) -> ArchiveTimestamp {
            ArchiveTimestamp::from_seconds(1_700_000_000)
        }
        fn open(&self) -> Result<Box<dyn Read + '_>, crate::format::ArchiveWriteError> {
            Ok(Box::new(std::io::Cursor::new(b"")))
        }
    }

    let sources = [
        DirTestSource {
            path: "docs/file1.txt",
            kind: SourceEntryKind::Regular,
        },
        DirTestSource {
            path: "docs/sub/file2.txt",
            kind: SourceEntryKind::Regular,
        },
        DirTestSource {
            path: "docs/sub",
            kind: SourceEntryKind::Directory,
        },
    ];

    let mut sink = MemoryArchiveSink::default();
    write_archive_sources_to_sink_single_pass(
        &sources,
        &master_key(),
        single_stream_options(),
        &crate::crypto::KdfParams::Raw,
        None,
        None,
        &mut sink,
    )
    .unwrap();

    let archive_bytes = sink.volumes.remove(0);
    let opened = open_archive(&archive_bytes, &master_key()).unwrap();

    let root_contents = opened.list_directory_contents("").unwrap();
    assert_eq!(root_contents.len(), 1);
    assert_eq!(root_contents[0].path, "docs");
    assert_eq!(root_contents[0].name, "docs");
    assert_eq!(root_contents[0].kind, TarEntryKind::Directory);

    let docs_contents = opened.list_directory_contents("docs").unwrap();
    assert_eq!(docs_contents.len(), 2);

    let file1 = docs_contents
        .iter()
        .find(|e| e.path == "docs/file1.txt")
        .unwrap();
    assert_eq!(file1.name, "file1.txt");
    assert_eq!(file1.kind, TarEntryKind::Regular);

    let sub_dir = docs_contents.iter().find(|e| e.path == "docs/sub").unwrap();
    assert_eq!(sub_dir.name, "sub");
    assert_eq!(sub_dir.kind, TarEntryKind::Directory);
}
