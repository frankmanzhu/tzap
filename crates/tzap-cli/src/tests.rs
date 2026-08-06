use std::fs::{self};
use std::time::{Duration, UNIX_EPOCH};

use anyhow::anyhow;
use openssl::x509::X509;
use tzap_core::entry_metadata::CaptureStatus;
use tzap_core::format::{
    ArchiveWriteError, CompressionAlgo, ExtractError, FecAlgo, FormatError, FORMAT_VERSION,
    READER_MAX_SUPPORTED_VOLUME_FORMAT_REV, VOLUME_FORMAT_REV_45, VOLUME_HEADER_LEN,
};
use tzap_core::reader::ArchiveEntry;
use tzap_core::wire::VolumeHeader;
#[cfg(all(test, target_os = "macos"))]
use tzap_core::write_archive;
#[cfg(target_os = "macos")]
use tzap_core::PortablePosixOwner;
#[cfg(test)]
use tzap_core::{write_archive_with_kdf, RegularFile};
use tzap_core::{
    ArchiveTimestamp, EntryMetadataVerification, KdfParams, MasterKey, MetadataDiagnostic,
    MetadataVerificationReport, PublicNoKeyVerification, RestorePolicy, RestorePolicyCapability,
    RootAuthSigningRequest, RootAuthWriterConfig, SourceEntryKind, TarEntryKind, WriterOptions,
};
#[cfg(test)]
use tzap_core::{MetadataDiagnosticStatus, MetadataOperation};
#[cfg(target_os = "macos")]
use tzap_core::{NativeAuxiliaryMetadata, PortableFileMetadata, PortableModeOrigin, RestoreClass};
use tzap_plugin_signing::ed25519_raw::ED25519_AUTHENTICATOR_ID;
use tzap_plugin_signing::x509_chain::{self};

#[cfg(any(target_os = "linux", windows))]
use std::fs::File;
#[cfg(windows)]
use std::io;
#[cfg(any(target_os = "linux", windows))]
use std::io::{Seek, SeekFrom, Write};
#[cfg(windows)]
use std::path::{Path, PathBuf};
#[cfg(windows)]
use tzap_core::{write_archive_sources_to_sink, RegularFileSource};
#[cfg(any(target_os = "linux", windows))]
use tzap_core::{
    write_archive_sources_to_sink_ordered_parallel, MemoryArchiveSink, SafeExtractionOptions,
};

use super::*;
use crate::commands::*;
use plaintext_spool::ExplicitPlaintextSpool;

use std::io::Cursor;

use tzap_core::format::MASTER_KEY_LEN;

fn test_master_key() -> MasterKey {
    MasterKey::from_raw_key(&[0x42; MASTER_KEY_LEN]).unwrap()
}

#[cfg(windows)]
fn windows_test_tempdir() -> tempfile::TempDir {
    let Some(root) = std::env::var_os("TZAP_WINDOWS_TEST_ROOT") else {
        return tempfile::tempdir().unwrap();
    };
    let root = PathBuf::from(root);
    fs::create_dir_all(&root).unwrap();
    tempfile::Builder::new()
        .prefix("tzap-windows-")
        .tempdir_in(root)
        .unwrap()
}

#[cfg(windows)]
fn create_windows_relative_symlink(path: &Path, target: &str) -> bool {
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::ERROR_PRIVILEGE_NOT_HELD;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    };
    use windows_sys::Win32::System::Ioctl::FSCTL_SET_REPARSE_POINT;
    use windows_sys::Win32::System::IO::DeviceIoControl;

    fs::write(path, []).unwrap();
    let target = target.encode_utf16().collect::<Vec<_>>();
    let target_bytes = target.len() * 2;
    let mut path_units = target.clone();
    path_units.push(0);
    path_units.extend_from_slice(&target);
    path_units.push(0);
    let payload_len = 12 + path_units.len() * 2;
    let mut reparse = Vec::with_capacity(8 + payload_len);
    reparse.extend_from_slice(&0xA000_000Cu32.to_le_bytes());
    reparse.extend_from_slice(&(payload_len as u16).to_le_bytes());
    reparse.extend_from_slice(&0u16.to_le_bytes());
    reparse.extend_from_slice(&0u16.to_le_bytes());
    reparse.extend_from_slice(&(target_bytes as u16).to_le_bytes());
    reparse.extend_from_slice(&((target_bytes + 2) as u16).to_le_bytes());
    reparse.extend_from_slice(&(target_bytes as u16).to_le_bytes());
    reparse.extend_from_slice(&1u32.to_le_bytes());
    for unit in path_units {
        reparse.extend_from_slice(&unit.to_le_bytes());
    }

    let file = fs::OpenOptions::new()
        .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .unwrap();
    let mut returned = 0u32;
    // SAFETY: the handle and complete relative-symlink reparse buffer remain live for the
    // synchronous call. Creating the fixture this way does not require symlink privilege.
    let result = unsafe {
        DeviceIoControl(
            file.as_raw_handle().cast(),
            FSCTL_SET_REPARSE_POINT,
            reparse.as_ptr().cast(),
            reparse.len() as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    let error = std::io::Error::last_os_error();
    if result == 0 && error.raw_os_error().map(|code| code as u32) == Some(ERROR_PRIVILEGE_NOT_HELD)
    {
        return false;
    }
    assert_ne!(result, 0, "{error}");
    true
}

fn test_tar_stream(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (path, data) in entries {
        out.extend_from_slice(&test_tar_header(path.as_bytes(), b'0', data.len() as u64));
        out.extend_from_slice(data);
        out.resize(out.len() + test_tar_padding(data.len()), 0);
    }
    out.extend_from_slice(&[0u8; 1024]);
    out
}

fn test_tar_header(path: &[u8], kind: u8, size: u64) -> [u8; 512] {
    let mut header = [0u8; 512];
    header[..path.len()].copy_from_slice(path);
    test_tar_octal(&mut header[100..108], 0o644);
    test_tar_octal(&mut header[108..116], 0);
    test_tar_octal(&mut header[116..124], 0);
    test_tar_octal(&mut header[124..136], size);
    test_tar_octal(&mut header[136..148], 0);
    header[148..156].fill(b' ');
    header[156] = kind;
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum = header.iter().map(|byte| *byte as u64).sum::<u64>();
    test_tar_checksum(&mut header[148..156], checksum);
    header
}

fn test_tar_octal(field: &mut [u8], value: u64) {
    let digits = format!("{value:o}");
    field.fill(0);
    let start = field.len() - 1 - digits.len();
    field[..start].fill(b'0');
    field[start..start + digits.len()].copy_from_slice(digits.as_bytes());
}

fn test_tar_checksum(field: &mut [u8], value: u64) {
    let digits = format!("{value:06o}");
    field[0..6].copy_from_slice(digits.as_bytes());
    field[6] = 0;
    field[7] = b' ';
}

fn test_tar_padding(len: usize) -> usize {
    let remainder = len % 512;
    if remainder == 0 {
        0
    } else {
        512 - remainder
    }
}

#[test]
fn create_layout_defaults_scale_by_input_size() {
    assert_eq!(
        default_create_layout(Some(LARGE_CREATE_LAYOUT_THRESHOLD)),
        CreateLayout {
            block_size: 64 * 1024,
            chunk_size: 256 * 1024,
            envelope_target_size: 1024 * 1024,
        }
    );
    assert_eq!(
        default_create_layout(Some(LARGE_CREATE_LAYOUT_THRESHOLD + 1)),
        CreateLayout {
            block_size: 1024 * 1024,
            chunk_size: 32 * 1024 * 1024,
            envelope_target_size: 64 * 1024 * 1024,
        }
    );
    assert_eq!(
        default_create_layout(None),
        default_create_layout(Some(LARGE_CREATE_LAYOUT_THRESHOLD + 1))
    );
}

#[test]
fn create_layout_chunk_override_grows_implicit_envelope() {
    let layout = resolve_create_layout(
        CreateLayoutOverrides {
            chunk_size: Some("4M"),
            envelope_size: None,
            block_size: None,
        },
        Some(1024),
    )
    .unwrap();

    assert_eq!(layout.chunk_size, 4 * 1024 * 1024);
    assert_eq!(layout.envelope_target_size, 4 * 1024 * 1024);
    assert_eq!(layout.block_size, 64 * 1024);
}

#[cfg(any(unix, windows))]
#[test]
fn create_groups_selected_hardlinks_under_deterministic_canonical_target() {
    let temp = tempfile::tempdir().unwrap();
    let first = temp.path().join("first.txt");
    let second = temp.path().join("second.txt");
    fs::write(&first, b"shared").unwrap();
    fs::hard_link(&first, &second).unwrap();

    let specs = collect_input_specs(&[
        first.to_string_lossy().into_owned(),
        second.to_string_lossy().into_owned(),
    ])
    .unwrap();

    assert_eq!(specs[0].entry_kind, SourceEntryKind::Regular);
    assert_eq!(specs[1].entry_kind, SourceEntryKind::Hardlink);
    assert_eq!(
        specs[1].link_target.as_deref(),
        Some(b"first.txt".as_slice())
    );
    assert_eq!(specs[1].size, 0);
    assert_eq!(specs[1].portable_metadata.created, None);
    assert_eq!(specs[1].portable_metadata.accessed, None);
    assert!(specs[1]
        .portable_metadata
        .native
        .auxiliary_records
        .is_empty());
}

#[test]
fn tar_stdin_signer_failure_removes_temporary_archive_output() {
    let temp = tempfile::tempdir().unwrap();
    let output = temp.path().join("failed.tzap");
    let key = CreateKey {
        master_key: test_master_key(),
        kdf_params: KdfParams::Raw,
    };
    let root_auth = RootAuthWriterConfig {
        authenticator_id: 0x9001,
        signer_identity_type: 0x9002,
        signer_identity: b"test signer",
        authenticator_value_length: 64,
    };
    let mut authenticator = |_request: &RootAuthSigningRequest| {
        Err(FormatError::WriterUnsupported("test signer failed"))
    };
    let mut input = Cursor::new(test_tar_stream(&[("signed.txt", b"signed")]));

    let error = write_tar_stdin_archive_output_from_reader(
        output.to_str().unwrap(),
        &mut input,
        &key,
        WriterOptions {
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            ..WriterOptions::default()
        },
        Some(root_auth),
        Some(&mut authenticator),
        false,
    )
    .unwrap_err();

    assert!(error.to_string().contains("test signer failed"));
    assert!(!output.exists());
}

#[test]
fn raw_spool_multi_volume_signer_failure_removes_temporary_archive_outputs_and_spool() {
    let temp = tempfile::tempdir().unwrap();
    let output = temp.path().join("failed-raw-spool.tzap");
    let volume_0 = create_output_paths(output.to_str().unwrap(), 3)[0].clone();
    let volume_1 = create_output_paths(output.to_str().unwrap(), 3)[1].clone();
    let volume_2 = create_output_paths(output.to_str().unwrap(), 3)[2].clone();
    let key = CreateKey {
        master_key: test_master_key(),
        kdf_params: KdfParams::Raw,
    };
    let root_auth = RootAuthWriterConfig {
        authenticator_id: 0x9001,
        signer_identity_type: 0x9002,
        signer_identity: b"test signer",
        authenticator_value_length: 64,
    };
    let mut authenticator = |_request: &RootAuthSigningRequest| {
        Err(FormatError::WriterUnsupported("test signer failed"))
    };
    let payload = (0..150_000)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    let spool_path;

    {
        let spool = crate::plaintext_spool::spool_unknown_size_raw_stdin_in(
            Cursor::new(payload),
            temp.path(),
            u64::MAX,
            ExplicitPlaintextSpool::acknowledge_plaintext_spool(),
        )
        .unwrap();
        let known_size_source = spool.known_size_source();
        spool_path = spool.path().to_path_buf();
        let mut spool_reader = spool.reopen().unwrap();

        let error = write_raw_stdin_archive_output_from_reader(
            output.to_str().unwrap(),
            &mut spool_reader,
            "raw/spooled.bin",
            known_size_source.size(),
            &key,
            WriterOptions {
                stripe_width: 3,
                volume_loss_tolerance: 0,
                bit_rot_buffer_pct: 0,
                ..WriterOptions::default()
            },
            Some(root_auth),
            Some(&mut authenticator),
            false,
        )
        .unwrap_err();

        assert!(error.to_string().contains("test signer failed"));
        assert!(spool_path.exists());
    }

    assert!(!spool_path.exists());
    assert!(!output.exists());
    assert!(!volume_0.exists());
    assert!(!volume_1.exists());
    assert!(!volume_2.exists());
}

#[test]
fn read_kdf_params_rejects_stripe_width_mismatch_before_returning_kdf() {
    let archive = write_archive_with_kdf(
        &[RegularFile::new("file.txt", b"contents")],
        &test_master_key(),
        WriterOptions {
            archive_uuid: Some([0x11; 16]),
            session_id: Some([0x22; 16]),
            bit_rot_buffer_pct: 0,
            ..WriterOptions::default()
        },
        &KdfParams::Argon2id {
            t_cost: 1,
            m_cost_kib: 8,
            parallelism: 1,
            salt: vec![0x33; 8],
        },
    )
    .unwrap();
    let mut bytes = archive.bytes;
    let mut volume_header = VolumeHeader::parse(&bytes[..VOLUME_HEADER_LEN]).unwrap();
    volume_header.stripe_width += 1;
    bytes[..VOLUME_HEADER_LEN].copy_from_slice(&volume_header.to_bytes());

    let err = read_kdf_params_from_volume(&bytes).unwrap_err();

    assert_eq!(
        err.downcast_ref::<FormatError>(),
        Some(&FormatError::InvalidArchive(
            "VolumeHeader and CryptoHeader stripe_width differ"
        ))
    );
}

#[test]
fn unsupported_revision_errors_suggest_reader_upgrade() {
    for err in [
        FormatError::UnsupportedFormatVersion(2),
        FormatError::UnsupportedVolumeFormatRevision {
            format_version: 1,
            volume_format_rev: 44,
            reader_max_supported_revision: READER_MAX_SUPPORTED_VOLUME_FORMAT_REV,
        },
    ] {
        let diagnostic = classify_format_error(&err);

        assert_eq!(diagnostic.label, "unsupported-revision");
        assert_eq!(diagnostic.exit_code, EXIT_UNSUPPORTED_REVISION);
        assert_eq!(
            diagnostic.action,
            "upgrade tzap or use a reader that supports this archive revision"
        );
    }
}

#[test]
fn reporting_unsupported_revision_json_has_observed_supported_action_only() {
    let err = anyhow!(FormatError::UnsupportedVolumeFormatRevision {
        format_version: 1,
        volume_format_rev: VOLUME_FORMAT_REV_45 + 1,
        reader_max_supported_revision: VOLUME_FORMAT_REV_45,
    });

    let payload = unsupported_revision_error_json(
        &err,
        "upgrade tzap or use a reader that supports this archive revision",
    );

    assert_eq!(payload["label"], "unsupported-revision");
    assert_eq!(
        payload["observed"]["format_version"],
        serde_json::json!(FORMAT_VERSION)
    );
    assert_eq!(
        payload["observed"]["volume_format_rev"],
        serde_json::json!(VOLUME_FORMAT_REV_45 + 1)
    );
    assert_eq!(
        payload["supported"]["max_volume_format_rev"],
        serde_json::json!(VOLUME_FORMAT_REV_45)
    );
    assert!(payload.get("root_auth").is_none());
    assert!(payload.get("decryption_keywrap").is_none());
}

#[test]
fn reporting_public_no_key_status_is_metadata_only() {
    let root_auth = VerifiedPublicNoKeyRootAuth::Ed25519(PublicNoKeyVerification {
        format_version: FORMAT_VERSION,
        volume_format_rev: VOLUME_FORMAT_REV_45,
        archive_root: [1; 32],
        authenticator_id: ED25519_AUTHENTICATOR_ID,
        signer_identity_type: 1,
        signer_identity_bytes: [2; 32].to_vec(),
        total_data_block_count: 7,
        diagnostics: vec![
            tzap_core::reader::PublicNoKeyDiagnostic::PublicDataBlockCommitmentVerified,
            tzap_core::reader::PublicNoKeyDiagnostic::PublicPhysicalCompletenessUnverified,
        ],
    });

    let status = public_no_key_status_json(&root_auth);

    assert_eq!(status["revision_mode"], serde_json::json!("v45"));
    assert_eq!(status["decryption_keywrap"], serde_json::json!("not_used"));
    assert_eq!(
        status["trust_policy"],
        serde_json::json!("public_trust_matched")
    );
    assert_eq!(
        status["public_no_key_metadata_only"],
        serde_json::json!("metadata_commitments_verified")
    );
}

#[test]
fn embedded_official_root_fingerprint_matches_certificate() {
    let der = x509_chain::certificate_der_from_pem_or_der(OFFICIAL_TZAP_ROOT_CERT_PEM).unwrap();
    let cert = X509::from_der(&der).unwrap();
    let digest = cert.digest(openssl::hash::MessageDigest::sha256()).unwrap();

    assert_eq!(
        OFFICIAL_TZAP_ROOT_CERT_SHA256,
        format!("sha256:{}", encode_hex(&digest))
    );
}

#[test]
fn bootstrap_required_errors_keep_missing_bootstrap_diagnostic() {
    for err in [
        FormatError::ReaderUnsupported("dictionary bootstrap required"),
        FormatError::ReaderUnsupported(
            "dictionary bootstrap required for non-seekable sequential extraction",
        ),
        FormatError::ReaderUnsupported("non-seekable random access requires a bootstrap sidecar"),
        FormatError::WriterUnsupported("bootstrap sidecar required"),
    ] {
        let diagnostic = classify_format_error(&err);

        assert_eq!(diagnostic.label, "missing-bootstrap");
        assert_eq!(diagnostic.exit_code, EXIT_MISSING_BOOTSTRAP);
        assert_eq!(diagnostic.action, "use --bootstrap with a matching sidecar");
    }
}

#[test]
fn missing_volume_errors_keep_stable_diagnostic() {
    let diagnostic = classify_format_error(&FormatError::InvalidArchive(
        "missing volume count exceeds volume_loss_tolerance",
    ));

    assert_eq!(diagnostic.label, "missing-volume");
    assert_eq!(diagnostic.exit_code, EXIT_CORRUPT_ARCHIVE);
    assert_eq!(
        diagnostic.action,
        "add the missing archive volume(s) or confirm volume-loss tolerance"
    );
}

fn assert_format_diagnostic(err: &FormatError, label: &str, exit_code: u8, action: &str) {
    let diagnostic = classify_format_error(err);
    assert_eq!(diagnostic.label, label);
    assert_eq!(diagnostic.exit_code, exit_code);
    assert_eq!(diagnostic.action, action);
}

#[test]
fn classify_format_error_covers_unsupported_revision_group() {
    for err in [
        FormatError::UnsupportedFormatVersion(2),
        FormatError::UnsupportedVolumeFormatRevision {
            format_version: 1,
            volume_format_rev: VOLUME_FORMAT_REV_45 + 1,
            reader_max_supported_revision: READER_MAX_SUPPORTED_VOLUME_FORMAT_REV,
        },
        FormatError::UnknownCompressionAlgo(7),
        FormatError::UnknownAeadAlgo(7),
        FormatError::UnknownFecAlgo(7),
        FormatError::UnknownKdfAlgo(7),
        FormatError::UnsupportedCompression(CompressionAlgo::ZstdFramed),
        FormatError::UnsupportedFec(FecAlgo::Wirehair),
        FormatError::UnsupportedBootstrapSidecarVersion(3),
    ] {
        assert_format_diagnostic(
            &err,
            "unsupported-revision",
            EXIT_UNSUPPORTED_REVISION,
            "upgrade tzap or use a reader that supports this archive revision",
        );
    }
}

#[test]
fn classify_format_error_covers_corrupt_header_structures() {
    for err in [
        FormatError::BadMagic {
            structure: "VolumeTrailer",
        },
        FormatError::BadMagic {
            structure: "ManifestFooter",
        },
    ] {
        assert_format_diagnostic(
            &err,
            "corrupt-header",
            EXIT_CORRUPT_ARCHIVE,
            "verify the archive header/trailer bytes and source file path",
        );
    }
    for err in [
        FormatError::BadCrc {
            structure: "VolumeHeader",
        },
        FormatError::BadCrc {
            structure: "VolumeTrailer",
        },
        FormatError::BadCrc {
            structure: "ManifestFooter",
        },
        FormatError::InvalidMetadata {
            structure: "VolumeHeader",
            reason: "bad field",
        },
        FormatError::InvalidMetadata {
            structure: "ManifestFooter",
            reason: "bad field",
        },
    ] {
        assert_format_diagnostic(
            &err,
            "corrupt-header",
            EXIT_CORRUPT_ARCHIVE,
            "inspect archive metadata and source file path",
        );
    }
}

#[test]
fn classify_format_error_covers_wrong_key_group() {
    for err in [
        FormatError::HmacMismatch {
            structure: "CryptoHeader",
        },
        FormatError::KeyMaterialMismatch,
        FormatError::InvalidRawMasterKeyLength,
    ] {
        assert_format_diagnostic(
            &err,
            "wrong-key",
            EXIT_WRONG_KEY,
            "confirm the archive key source (passphrase/raw key/recipient key)",
        );
    }
}

#[test]
fn classify_format_error_covers_corrupt_archive_and_missing_volume() {
    assert_format_diagnostic(
        &FormatError::IntegrityDigestMismatch {
            structure: "ManifestFooter",
        },
        "corrupt-archive",
        EXIT_CORRUPT_ARCHIVE,
        "verify the archive bytes and source file path",
    );
    for err in [
        FormatError::FecTooFewAvailableShards,
        FormatError::InvalidArchive("complete volume set has missing global blocks"),
        FormatError::InvalidArchive("missing volume count exceeds volume_loss_tolerance"),
    ] {
        assert_format_diagnostic(
            &err,
            "missing-volume",
            EXIT_CORRUPT_ARCHIVE,
            "add the missing archive volume(s) or confirm volume-loss tolerance",
        );
    }
}

#[test]
fn classify_format_error_pins_dictionary_extent_message_as_corrupt_archive() {
    // Spec v0.45 §15.2: has_dictionary = 1 with a zero dictionary extent is
    // non-conformant archive content, so this message must stay in the
    // corrupt-archive family — never missing-bootstrap (which the spec
    // reserves for the non-seekable sidecar path).
    assert_format_diagnostic(
        &FormatError::InvalidArchive("dictionary extent missing from IndexRoot"),
        "corrupt-archive",
        EXIT_CORRUPT_ARCHIVE,
        "verify archive integrity and source",
    );
    // The genuine user-supply case keeps the missing-bootstrap mapping.
    assert_format_diagnostic(
        &FormatError::ReaderUnsupported("dictionary bootstrap required"),
        "missing-bootstrap",
        EXIT_MISSING_BOOTSTRAP,
        "use --bootstrap with a matching sidecar",
    );
}

#[test]
fn classify_format_error_covers_corrupt_payload_group() {
    for err in [
        FormatError::HmacMismatch {
            structure: "PayloadBlock",
        },
        FormatError::AeadFailure,
    ] {
        assert_format_diagnostic(
            &err,
            "corrupt-payload",
            EXIT_CORRUPT_ARCHIVE,
            "verify archive payload integrity",
        );
    }
    assert_format_diagnostic(
        &FormatError::BadCrc {
            structure: "PayloadBlock",
        },
        "corrupt-payload",
        EXIT_CORRUPT_ARCHIVE,
        "verify payload integrity",
    );
    for structure in ["IndexRoot", "FrameEntry", "EnvelopeEntry"] {
        assert_format_diagnostic(
            &FormatError::InvalidMetadata {
                structure,
                reason: "bad table",
            },
            "corrupt-payload",
            EXIT_CORRUPT_ARCHIVE,
            "inspect archive metadata tables and payload",
        );
    }
}

#[test]
fn classify_format_error_covers_invalid_arguments() {
    let message = "argon2 T-cost exceeds reader cap";
    assert_format_diagnostic(
        &FormatError::InvalidKdfParams(message),
        "invalid-arguments",
        EXIT_USAGE,
        message,
    );
    assert_format_diagnostic(
        &FormatError::ReaderResourceLimitExceeded {
            field: "entry-count",
            cap: 100,
            actual: 101,
        },
        "invalid-arguments",
        EXIT_USAGE,
        "archive exceeds reader resource limits (payload/metadata size caps, or argon2 parameters via --argon2-t-cost, --argon2-m-cost-kib, --argon2-parallelism)",
    );
}

#[test]
fn classify_format_error_covers_unsafe_path() {
    assert_format_diagnostic(
        &FormatError::UnsafeArchivePath,
        "unsafe-path",
        EXIT_UNSAFE_PATH,
        "archive contains unsafe paths; extract paths should be reviewed first",
    );
    assert_format_diagnostic(
        &FormatError::UnsafeOverwrite,
        "unsafe-path",
        EXIT_UNSAFE_PATH,
        "add --overwrite if overwriting existing files is intended",
    );
}

#[test]
fn classify_format_error_covers_unsupported_feature_fallback() {
    for err in [
        FormatError::ReaderUnsupported("unrelated reader limitation"),
        FormatError::WriterUnsupported("unrelated writer limitation"),
    ] {
        assert_format_diagnostic(
            &err,
            "unsupported-feature",
            EXIT_UNSUPPORTED_FEATURE,
            "use a supported archive shape or upgrade tzap",
        );
    }
}

#[test]
fn classify_format_error_wildcard_is_corrupt_archive() {
    for err in [
        FormatError::UnknownBlockKind(9),
        FormatError::InvalidArchive("some other archive reason"),
    ] {
        assert_format_diagnostic(
            &err,
            "corrupt-archive",
            EXIT_CORRUPT_ARCHIVE,
            "verify archive integrity and source",
        );
    }
}

#[test]
fn classify_error_maps_wrapped_core_errors_and_fallbacks() {
    let usage = anyhow!(UsageError("bad argument"));
    let diagnostic = classify_error(&usage);
    assert_eq!(diagnostic.label, "invalid-arguments");
    assert_eq!(diagnostic.exit_code, EXIT_USAGE);

    let contextual_usage = anyhow!("invalid size '10Q': unsupported suffix 'Q'")
        .context(UsageError("invalid volume-size"));
    let diagnostic = classify_error(&contextual_usage);
    assert_eq!(diagnostic.label, "invalid-arguments");
    assert_eq!(diagnostic.exit_code, EXIT_USAGE);

    let write_format = anyhow!(ArchiveWriteError::Format(FormatError::UnsafeArchivePath));
    let diagnostic = classify_error(&write_format);
    assert_eq!(diagnostic.label, "unsafe-path");
    assert_eq!(diagnostic.exit_code, EXIT_UNSAFE_PATH);

    let write_io = anyhow!(ArchiveWriteError::Io(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "missing archive"
    )));
    let diagnostic = classify_error(&write_io);
    assert_eq!(diagnostic.label, "io-error");
    assert_eq!(diagnostic.exit_code, EXIT_IO);
    assert_eq!(diagnostic.action, "check file paths and permissions");

    let extract_format = anyhow!(ExtractError::Format(FormatError::UnsupportedFormatVersion(
        2
    )));
    let diagnostic = classify_error(&extract_format);
    assert_eq!(diagnostic.label, "unsupported-revision");
    assert_eq!(diagnostic.exit_code, EXIT_UNSUPPORTED_REVISION);

    let extract_output = anyhow!(ExtractError::Output(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "denied"
    )));
    let diagnostic = classify_error(&extract_output);
    assert_eq!(diagnostic.label, "io-error");
    assert_eq!(diagnostic.exit_code, EXIT_IO);

    let chained_format = anyhow!(FormatError::BadMagic {
        structure: "VolumeHeader",
    })
    .context("reading archive");
    let diagnostic = classify_error(&chained_format);
    assert_eq!(diagnostic.label, "corrupt-header");
    assert_eq!(diagnostic.exit_code, EXIT_CORRUPT_ARCHIVE);

    let generic = anyhow!("boom");
    let diagnostic = classify_error(&generic);
    assert_eq!(diagnostic.label, "error");
    assert_eq!(diagnostic.exit_code, EXIT_GENERIC);
    assert_eq!(diagnostic.action, "");
}

#[test]
fn classify_io_error_covers_kinds_and_actions() {
    for kind in [
        std::io::ErrorKind::PermissionDenied,
        std::io::ErrorKind::NotFound,
        std::io::ErrorKind::AlreadyExists,
    ] {
        let diagnostic = classify_io_error(&std::io::Error::new(kind, "io"));
        assert_eq!(diagnostic.label, "io-error");
        assert_eq!(diagnostic.exit_code, EXIT_IO);
        assert_eq!(diagnostic.action, "check file paths and permissions");
    }
    for kind in [std::io::ErrorKind::Other, std::io::ErrorKind::BrokenPipe] {
        let diagnostic = classify_io_error(&std::io::Error::new(kind, "io"));
        assert_eq!(diagnostic.label, "io-error");
        assert_eq!(diagnostic.exit_code, EXIT_IO);
        assert_eq!(diagnostic.action, "check filesystem state");
    }
}

#[test]
fn unsupported_revision_error_json_covers_all_branches() {
    let version_err = anyhow!(FormatError::UnsupportedFormatVersion(2));
    let payload = unsupported_revision_error_json(
        &version_err,
        "upgrade tzap or use a reader that supports this archive revision",
    );
    assert_eq!(payload["label"], "unsupported-revision");
    assert_eq!(payload["observed"]["format_version"], serde_json::json!(2));
    assert_eq!(
        payload["supported"]["format_version"],
        serde_json::json!(FORMAT_VERSION)
    );
    assert_eq!(
        payload["supported"]["max_volume_format_rev"],
        serde_json::json!(READER_MAX_SUPPORTED_VOLUME_FORMAT_REV)
    );

    let no_format_cause = anyhow!("plain io failure");
    let payload = unsupported_revision_error_json(
        &no_format_cause,
        "upgrade tzap or use a reader that supports this archive revision",
    );
    assert_eq!(payload["label"], "unsupported-revision");
    assert!(payload.get("observed").unwrap().is_null());
    assert_eq!(
        payload["supported"]["format_version"],
        serde_json::json!(FORMAT_VERSION)
    );
    assert_eq!(
        payload["supported"]["max_volume_format_rev"],
        serde_json::json!(READER_MAX_SUPPORTED_VOLUME_FORMAT_REV)
    );
    assert_eq!(
        payload["action"],
        "upgrade tzap or use a reader that supports this archive revision"
    );
}

#[test]
fn metadata_diagnostic_lines_use_stable_cli_warning_prefix() {
    let line = metadata_diagnostic_line(
        "path/in/archive",
        &MetadataDiagnostic {
            path: b"path/in/archive".to_vec(),
            profile: "gnu-sparse".into(),
            metadata_class: "sparse-layout".into(),
            operation: MetadataOperation::Plan,
            status: MetadataDiagnosticStatus::Unsupported,
            message: "unsupported sparse-file PAX metadata was ignored".into(),
            restore_policy: None,
            restore_phase: None,
            native_host_error: None,
            bytes_staged: None,
            bytes_committed: None,
        },
    );

    assert_eq!(
            line,
            "tzap: degraded-metadata: path/in/archive: gnu-sparse: sparse-layout: Plan/Unsupported: unsupported sparse-file PAX metadata was ignored"
        );
}

#[test]
fn selected_metadata_diagnostic_lines_filter_to_requested_paths() {
    let entries = vec![
        ArchiveEntry {
            path: "selected.txt".to_string(),
            file_data_size: 1,
            kind: TarEntryKind::Regular,
            mode: 0o644,
            mtime: ArchiveTimestamp::UNIX_EPOCH,
            diagnostics: vec![MetadataDiagnostic {
                path: b"selected.txt".to_vec(),
                profile: "pax-posix-2001".into(),
                metadata_class: "pax-key".into(),
                operation: MetadataOperation::Plan,
                status: MetadataDiagnosticStatus::Unsupported,
                message: "unsupported PAX key was ignored".into(),
                restore_policy: None,
                restore_phase: None,
                native_host_error: None,
                bytes_staged: None,
                bytes_committed: None,
            }],
            link_target: None,
            created: None,
            accessed: None,
            attributes: None,
            uid: None,
            gid: None,
            uname: None,
            gname: None,
        },
        ArchiveEntry {
            path: "other.txt".to_string(),
            file_data_size: 1,
            kind: TarEntryKind::Regular,
            mode: 0o644,
            mtime: ArchiveTimestamp::UNIX_EPOCH,
            diagnostics: vec![MetadataDiagnostic {
                path: b"other.txt".to_vec(),
                profile: "gnu-sparse".into(),
                metadata_class: "sparse-layout".into(),
                operation: MetadataOperation::Plan,
                status: MetadataDiagnosticStatus::Unsupported,
                message: "unsupported sparse-file PAX metadata was ignored".into(),
                restore_policy: None,
                restore_phase: None,
                native_host_error: None,
                bytes_staged: None,
                bytes_committed: None,
            }],
            link_target: None,
            created: None,
            accessed: None,
            attributes: None,
            uid: None,
            gid: None,
            uname: None,
            gname: None,
        },
    ];

    assert_eq!(
            metadata_diagnostic_lines_for_paths(&entries, &["selected.txt".to_string()]),
            vec![
                "tzap: degraded-metadata: selected.txt: pax-posix-2001: pax-key: Plan/Unsupported: unsupported PAX key was ignored"
                    .to_string()
            ]
        );
    assert_eq!(metadata_diagnostic_lines_for_entries(&entries).len(), 2);
}

#[test]
fn metadata_diagnostic_line_includes_optional_suffixes() {
    // All three optional suffixes present: restore policy/phase, native error, staged/committed.
    let all_some = metadata_diagnostic_line(
        "a/b",
        &MetadataDiagnostic {
            path: b"a/b".to_vec(),
            profile: "pax-posix-2001".into(),
            metadata_class: "acl".into(),
            operation: MetadataOperation::Restore,
            status: MetadataDiagnosticStatus::Failed,
            message: "restore failed".into(),
            restore_policy: Some(RestorePolicy::System),
            restore_phase: Some(2),
            native_host_error: Some("EACCES: permission denied".into()),
            bytes_staged: Some(128),
            bytes_committed: Some(96),
        },
    );
    assert_eq!(
        all_some,
        "tzap: degraded-metadata: a/b: pax-posix-2001: acl: Restore/Failed: restore failed \
         [policy=System phase=2] [native-error=EACCES: permission denied] [staged=128 committed=96]"
    );

    // Suffixes are independent: policy/phase and staged/committed without a native error.
    let no_native_error = metadata_diagnostic_line(
        "c",
        &MetadataDiagnostic {
            path: b"c".to_vec(),
            profile: "gnu-sparse".into(),
            metadata_class: "sparse-layout".into(),
            operation: MetadataOperation::Capture,
            status: MetadataDiagnosticStatus::Partial,
            message: "partial capture".into(),
            restore_policy: Some(RestorePolicy::Portable),
            restore_phase: Some(1),
            native_host_error: None,
            bytes_staged: Some(4),
            bytes_committed: Some(4),
        },
    );
    assert_eq!(
        no_native_error,
        "tzap: degraded-metadata: c: gnu-sparse: sparse-layout: Capture/Partial: partial capture \
         [policy=Portable phase=1] [staged=4 committed=4]"
    );

    // Native error alone, no restore phase (pairs are emitted only when both halves are Some).
    let error_only = metadata_diagnostic_line(
        "d",
        &MetadataDiagnostic {
            path: b"d".to_vec(),
            profile: "pax-posix-2001".into(),
            metadata_class: "xattr".into(),
            operation: MetadataOperation::Verify,
            status: MetadataDiagnosticStatus::Skipped,
            message: "skipped".into(),
            restore_policy: Some(RestorePolicy::SameOs),
            restore_phase: None,
            native_host_error: Some("ENOENT".into()),
            bytes_staged: None,
            bytes_committed: None,
        },
    );
    assert_eq!(
        error_only,
        "tzap: degraded-metadata: d: pax-posix-2001: xattr: Verify/Skipped: skipped \
         [native-error=ENOENT]"
    );
}

fn test_entry_verification(
    path: &str,
    capture_status: CaptureStatus,
    policy_capabilities: Vec<RestorePolicyCapability>,
    diagnostics: Vec<MetadataDiagnostic>,
) -> EntryMetadataVerification {
    EntryMetadataVerification {
        path: path.as_bytes().to_vec(),
        capture_status,
        required_profiles: vec!["pax-posix-2001".to_string()],
        optional_profiles: vec!["gnu-sparse".to_string()],
        auxiliary_kinds: vec!["xattr".to_string()],
        policy_capabilities,
        full_fidelity_possible: false,
        diagnostics,
    }
}

#[test]
fn metadata_verification_json_reports_diagnostics_and_policies() {
    let report = MetadataVerificationReport {
        all_capture_complete: false,
        full_fidelity_possible: false,
        profiles_present: vec!["pax-posix-2001".to_string()],
        auxiliary_kinds_present: vec!["xattr".to_string()],
        entries: vec![test_entry_verification(
            "in/archive",
            CaptureStatus::Partial,
            vec![
                RestorePolicyCapability {
                    policy: RestorePolicy::Content,
                    policy_complete: true,
                    degraded_restore_available: false,
                    reason: Some("no content metadata captured"),
                },
                RestorePolicyCapability {
                    policy: RestorePolicy::System,
                    policy_complete: false,
                    degraded_restore_available: true,
                    reason: Some("native metadata partially restored"),
                },
            ],
            vec![MetadataDiagnostic {
                path: b"in/archive".to_vec(),
                profile: "pax-posix-2001".into(),
                metadata_class: "acl".into(),
                operation: MetadataOperation::Capture,
                status: MetadataDiagnosticStatus::Partial,
                message: "some ACL entries not capturable".into(),
                restore_policy: Some(RestorePolicy::System),
                restore_phase: Some(1),
                native_host_error: Some("EINVAL".into()),
                bytes_staged: Some(16),
                bytes_committed: Some(8),
            }],
        )],
    };

    let payload = metadata_verification_json(&report);

    assert_eq!(payload["capture_complete"], serde_json::json!(false));
    assert_eq!(payload["full_fidelity_possible"], serde_json::json!(false));
    assert_eq!(
        payload["profiles_present"],
        serde_json::json!(["pax-posix-2001"])
    );
    assert_eq!(
        payload["auxiliary_kinds_present"],
        serde_json::json!(["xattr"])
    );

    let entry = &payload["entries"][0];
    assert_eq!(entry["path"], serde_json::json!("in/archive"));
    assert_eq!(entry["capture_status"], serde_json::json!("partial"));
    assert_eq!(
        entry["required_profiles"],
        serde_json::json!(["pax-posix-2001"])
    );
    assert_eq!(
        entry["optional_profiles"],
        serde_json::json!(["gnu-sparse"])
    );
    assert_eq!(entry["auxiliary_kinds"], serde_json::json!(["xattr"]));
    assert_eq!(entry["full_fidelity_possible"], serde_json::json!(false));

    let capabilities = &entry["policy_capabilities"];
    assert_eq!(capabilities[0]["policy"], serde_json::json!("content"));
    assert_eq!(capabilities[0]["policy_complete"], serde_json::json!(true));
    assert_eq!(
        capabilities[0]["degraded_restore_available"],
        serde_json::json!(false)
    );
    assert_eq!(
        capabilities[0]["reason"],
        serde_json::json!("no content metadata captured")
    );
    assert_eq!(capabilities[1]["policy"], serde_json::json!("system"));
    assert_eq!(capabilities[1]["policy_complete"], serde_json::json!(false));
    assert_eq!(
        capabilities[1]["degraded_restore_available"],
        serde_json::json!(true)
    );
    assert_eq!(
        capabilities[1]["reason"],
        serde_json::json!("native metadata partially restored")
    );

    let diagnostic = &entry["diagnostics"][0];
    assert_eq!(diagnostic["path"], serde_json::json!("in/archive"));
    assert_eq!(diagnostic["profile"], serde_json::json!("pax-posix-2001"));
    assert_eq!(diagnostic["metadata_class"], serde_json::json!("acl"));
    assert_eq!(diagnostic["operation"], serde_json::json!("capture"));
    assert_eq!(diagnostic["status"], serde_json::json!("partial"));
    assert_eq!(
        diagnostic["reason"],
        serde_json::json!("some ACL entries not capturable")
    );
    assert_eq!(diagnostic["restore_policy"], serde_json::json!("system"));
    assert_eq!(diagnostic["restore_phase"], serde_json::json!(1));
    assert_eq!(diagnostic["native_host_error"], serde_json::json!("EINVAL"));
    assert_eq!(diagnostic["bytes_staged"], serde_json::json!(16));
    assert_eq!(diagnostic["bytes_committed"], serde_json::json!(8));
}

#[test]
fn metadata_verification_stdout_lines_cover_partial_and_policy_counts() {
    let report = MetadataVerificationReport {
        all_capture_complete: false,
        full_fidelity_possible: false,
        profiles_present: vec!["pax-posix-2001".to_string(), "gnu-sparse".to_string()],
        auxiliary_kinds_present: vec!["xattr".to_string()],
        entries: vec![
            test_entry_verification(
                "a",
                CaptureStatus::Complete,
                vec![
                    RestorePolicyCapability {
                        policy: RestorePolicy::Content,
                        policy_complete: true,
                        degraded_restore_available: false,
                        reason: None,
                    },
                    RestorePolicyCapability {
                        policy: RestorePolicy::Portable,
                        policy_complete: true,
                        degraded_restore_available: false,
                        reason: None,
                    },
                ],
                vec![],
            ),
            test_entry_verification(
                "b",
                CaptureStatus::Partial,
                vec![RestorePolicyCapability {
                    policy: RestorePolicy::System,
                    policy_complete: true,
                    degraded_restore_available: true,
                    reason: Some("degraded"),
                }],
                vec![],
            ),
        ],
    };

    let lines = metadata_verification_stdout_lines(&report);
    assert_eq!(
        lines,
        vec![
            "metadata: capture=partial full-fidelity=not-possible profiles=[pax-posix-2001,gnu-sparse] auxiliary-kinds=[xattr]",
            "metadata-policy content: 1/2 entries policy-complete",
            "metadata-policy portable: 1/2 entries policy-complete",
            "metadata-policy same-os: 0/2 entries policy-complete",
            "metadata-policy system: 1/2 entries policy-complete",
        ]
    );

    // Fully complete report flips the summary flags.
    let complete = MetadataVerificationReport {
        all_capture_complete: true,
        full_fidelity_possible: true,
        profiles_present: vec![],
        auxiliary_kinds_present: vec![],
        entries: vec![test_entry_verification(
            "a",
            CaptureStatus::Complete,
            vec![RestorePolicyCapability {
                policy: RestorePolicy::Portable,
                policy_complete: true,
                degraded_restore_available: false,
                reason: None,
            }],
            vec![],
        )],
    };
    let lines = metadata_verification_stdout_lines(&complete);
    assert_eq!(
        lines[0],
        "metadata: capture=complete full-fidelity=possible profiles=[] auxiliary-kinds=[]"
    );
    assert_eq!(
        lines[1],
        "metadata-policy content: 0/1 entries policy-complete"
    );
    assert_eq!(
        lines[2],
        "metadata-policy portable: 1/1 entries policy-complete"
    );
    assert_eq!(lines.len(), 5);
}

#[test]
fn archive_entry_kind_label_covers_all_kinds() {
    assert_eq!(archive_entry_kind_label(TarEntryKind::Regular), "file");
    assert_eq!(
        archive_entry_kind_label(TarEntryKind::Directory),
        "directory"
    );
    assert_eq!(archive_entry_kind_label(TarEntryKind::Symlink), "symlink");
    assert_eq!(archive_entry_kind_label(TarEntryKind::Hardlink), "hardlink");
    assert_eq!(
        archive_entry_kind_label(TarEntryKind::CharacterDevice),
        "character-device"
    );
    assert_eq!(
        archive_entry_kind_label(TarEntryKind::BlockDevice),
        "block-device"
    );
    assert_eq!(archive_entry_kind_label(TarEntryKind::Fifo), "fifo");
}

#[test]
fn format_duration_three_decimal_seconds() {
    assert_eq!(format_duration(Duration::ZERO), "0.000s");
    assert_eq!(format_duration(Duration::from_secs_f64(1.5)), "1.500s");
    assert_eq!(format_duration(Duration::from_secs_f64(1.23456)), "1.235s");
    assert_eq!(format_duration(Duration::from_nanos(42)), "0.000s");
}

#[cfg(target_os = "linux")]
#[test]
fn filesystem_scan_captures_linux_native_profile_and_user_xattr() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("native.txt");
    fs::write(&path, b"payload").unwrap();
    xattr::set(&path, "user.tzap-test", b"metadata").unwrap();
    let identity = input_identity(&fs::metadata(&path).unwrap()).unwrap();

    let native = capture_native_file_metadata(&path, identity).unwrap();

    assert_eq!(
        native.required_profiles,
        vec!["linux-backup-v1", "posix-backup-v1"]
    );
    assert_eq!(
        native
            .primary_pax_records
            .get("LIBARCHIVE.xattr.user.tzap-test")
            .map(Vec::as_slice),
        Some(b"bWV0YWRhdGE".as_slice())
    );
    assert!(native
        .primary_pax_records
        .contains_key("TZAP.linux.fsflags"));
    assert!(native
        .primary_pax_records
        .contains_key("TZAP.unix.ctime-observed"));
    if identity.creation_time.is_some() {
        assert!(native
            .primary_pax_records
            .contains_key("LIBARCHIVE.creationtime"));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn filesystem_scan_and_restore_preserve_linux_fifo() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::FileTypeExt as _;

    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("events.fifo");
    let source_c = CString::new(source.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(source_c.as_ptr(), 0o640) }, 0);
    let acl = [
        2, 0, 0, 0, // POSIX ACL xattr version
        1, 0, 6, 0, 0xff, 0xff, 0xff, 0xff, // owning user
        2, 0, 6, 0, 0x39, 0x30, 0, 0, // named user 12345
        4, 0, 4, 0, 0xff, 0xff, 0xff, 0xff, // owning group
        0x10, 0, 6, 0, 0xff, 0xff, 0xff, 0xff, // mask
        0x20, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, // other
    ];
    xattr::set(&source, "system.posix_acl_access", &acl).unwrap();
    let expected_acl = xattr::get(&source, "system.posix_acl_access")
        .unwrap()
        .unwrap();

    let specs = collect_input_specs(&[source.to_string_lossy().into_owned()]).unwrap();
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].entry_kind, SourceEntryKind::Fifo);
    assert_eq!(specs[0].size, 0);
    assert!(specs[0]
        .portable_metadata
        .native
        .primary_pax_records
        .contains_key("SCHILY.acl.access"));

    let key = MasterKey::from_raw_key(&[41u8; 32]).unwrap();
    let mut sink = MemoryArchiveSink::default();
    write_archive_sources_to_sink_ordered_parallel(
        &specs,
        &key,
        WriterOptions {
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            ..WriterOptions::default()
        },
        &KdfParams::Raw,
        None,
        None,
        &mut sink,
    )
    .unwrap();
    let opened = tzap_core::open_archive(&sink.volumes[0], &key).unwrap();
    opened.verify().unwrap();
    let output = temp.path().join("fifo-output");
    fs::create_dir(&output).unwrap();
    opened
        .extract_all_to(
            &output,
            SafeExtractionOptions {
                restore_policy: RestorePolicy::System,
                system_authorized: true,
                // Linux exposes birth time on some filesystems but has no general API to
                // restore it, so the unrelated FIFO recreation proceeds explicitly degraded.
                allow_degraded: true,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();
    let restored = fs::symlink_metadata(output.join("events.fifo")).unwrap();
    assert!(restored.file_type().is_fifo());
    assert_eq!(readonly_mode(&restored) & 0o777, 0o660);
    assert_eq!(
        xattr::get(output.join("events.fifo"), "system.posix_acl_access")
            .unwrap()
            .unwrap(),
        expected_acl
    );
}

#[cfg(target_os = "linux")]
#[test]
fn filesystem_scan_discovers_linux_sparse_extents() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("sparse.bin");
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&source)
        .unwrap();
    let logical_size = 512 * 1024u64;
    file.set_len(logical_size).unwrap();
    file.seek(SeekFrom::Start(64 * 1024)).unwrap();
    file.write_all(b"first extent").unwrap();
    file.seek(SeekFrom::Start(384 * 1024)).unwrap();
    file.write_all(b"last extent").unwrap();
    file.flush().unwrap();

    let specs = collect_input_specs(&[source.to_string_lossy().into_owned()]).unwrap();
    let extents = specs[0]
        .sparse_extents
        .as_ref()
        .expect("filesystem should expose SEEK_DATA/SEEK_HOLE");
    assert!(!extents.is_empty());
    assert!(extents.iter().map(|extent| extent.length).sum::<u64>() < logical_size);

    let key = MasterKey::from_raw_key(&[42u8; 32]).unwrap();
    let mut sink = MemoryArchiveSink::default();
    write_archive_sources_to_sink_ordered_parallel(
        &specs,
        &key,
        WriterOptions {
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            ..WriterOptions::default()
        },
        &KdfParams::Raw,
        None,
        None,
        &mut sink,
    )
    .unwrap();
    let opened = tzap_core::open_archive(&sink.volumes[0], &key).unwrap();
    let indexed = opened.lookup_index_entry("sparse.bin").unwrap().unwrap();
    assert_ne!(
        indexed.flags & (1 << 3),
        0,
        "archive index lost sparse metadata"
    );
    let output = temp.path().join("sparse-output");
    fs::create_dir(&output).unwrap();
    opened
        .extract_all_to(
            &output,
            SafeExtractionOptions {
                restore_policy: RestorePolicy::SameOs,
                // Linux exposes birth time but has no general API to assign it.
                allow_degraded: true,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();
    let restored_path = output.join("sparse.bin");
    let restored = File::open(&restored_path).unwrap();
    assert_eq!(restored.metadata().unwrap().len(), logical_size);
    let restored_extents = query_linux_sparse_extents(&restored, logical_size).unwrap();
    use std::os::unix::fs::MetadataExt as _;
    assert!(
        restored_extents.is_some(),
        "restored output should remain sparse; source extents={extents:?}, blocks={}",
        restored.metadata().unwrap().blocks()
    );
    let restored_extents = restored_extents.unwrap();
    assert!(
        restored_extents
            .iter()
            .map(|extent| extent.length)
            .sum::<u64>()
            < logical_size
    );
    let bytes = fs::read(restored_path).unwrap();
    assert_eq!(&bytes[64 * 1024..64 * 1024 + 12], b"first extent");
    assert_eq!(&bytes[384 * 1024..384 * 1024 + 11], b"last extent");
}

#[cfg(target_os = "macos")]
#[test]
fn filesystem_scan_captures_macos_native_metadata_and_writes_valid_archive() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("native.txt");
    fs::write(&path, b"payload").unwrap();
    xattr::set(&path, "com.tzap.test", b"metadata").unwrap();
    xattr::set(&path, "com.apple.FinderInfo", &[0x5a; 32]).unwrap();
    xattr::set(&path, "com.apple.ResourceFork", b"resource fork").unwrap();
    let acl_status = std::process::Command::new("chmod")
        .arg("+a")
        .arg("everyone deny delete")
        .arg(&path)
        .status()
        .unwrap();
    assert!(acl_status.success());
    let identity = input_identity(&fs::metadata(&path).unwrap()).unwrap();

    let native = capture_native_file_metadata(&path, identity).unwrap();
    let shared = tzap_core::macos_metadata::capture_macos_metadata(&path, false).unwrap();
    assert_eq!(
        shared.native, native,
        "CLI and reusable TZAP metadata capture must remain identical"
    );

    assert_eq!(
        native.required_profiles,
        vec!["macos-backup-v1", "posix-backup-v1"]
    );
    assert_eq!(
        native
            .primary_pax_records
            .get("LIBARCHIVE.xattr.com.tzap.test")
            .map(Vec::as_slice),
        Some(b"bWV0YWRhdGE".as_slice())
    );
    for key in [
        "LIBARCHIVE.creationtime",
        "TZAP.unix.ctime-observed",
        "TZAP.macos.st-flags",
        "TZAP.acl.projection",
    ] {
        assert!(native.primary_pax_records.contains_key(key), "{key}");
    }
    let finder_info = native
        .auxiliary_records
        .iter()
        .find(|record| record.kind == "macos.finder-info")
        .unwrap();
    assert_eq!(finder_info.payload, [0x5a; 32]);
    let resource_fork = native
        .auxiliary_records
        .iter()
        .find(|record| record.kind == "macos.resource-fork")
        .unwrap();
    assert!(resource_fork.is_streamed());
    assert!(resource_fork.payload.is_empty());
    assert_eq!(resource_fork.logical_size, b"resource fork".len() as u64);
    let acl = native
        .auxiliary_records
        .iter()
        .find(|record| record.kind == "macos.acl-native")
        .unwrap();
    assert!(!acl.payload.is_empty());
    assert_eq!(
        acl.meta.get("TZAP.aux.meta.acl-format").map(Vec::as_slice),
        Some(b"darwin-acl-external-v1".as_slice())
    );

    // `RegularFile` is the convenience in-memory source and cannot reopen a streamed
    // filesystem fork. Keep this parser/writer assertion independent from the InputSpec
    // streaming integration test by substituting the same bytes as an in-memory record.
    let mut archive_native = native.clone();
    let resource_index = archive_native
        .auxiliary_records
        .iter()
        .position(|record| record.kind == "macos.resource-fork")
        .unwrap();
    archive_native.auxiliary_records[resource_index] = NativeAuxiliaryMetadata::new(
        "macos.resource-fork",
        "macos-backup-v1",
        RestoreClass::SameOs,
        b"resource fork".to_vec(),
    );

    let archive = write_archive(
        &[RegularFile {
            path: "native.txt",
            contents: b"payload",
            mode: identity.mode,
            mtime: identity.mtime,
            portable_metadata: PortableFileMetadata {
                source_os: "macos".into(),
                source_filesystem: "unknown".into(),
                mode_origin: PortableModeOrigin::Native,
                posix_owner: Some(PortablePosixOwner {
                    uid: identity.uid,
                    gid: identity.gid,
                    uname: None,
                    gname: None,
                }),
                attributes: None,
                created: None,
                accessed: None,
                native: archive_native,
            },
        }],
        &MasterKey::from_raw_key(&[7u8; 32]).unwrap(),
        WriterOptions {
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            ..WriterOptions::default()
        },
    )
    .unwrap();
    let opened = tzap_core::open_archive(
        &archive.bytes,
        &MasterKey::from_raw_key(&[7u8; 32]).unwrap(),
    )
    .unwrap();
    opened.verify().unwrap();
    let verification = opened.verify_content().unwrap();
    let report = verification.metadata_report().unwrap();
    assert_eq!(
        report.profiles_present,
        vec!["macos-backup-v1", "portable-v1", "posix-backup-v1"]
    );
    assert!(report
        .auxiliary_kinds_present
        .contains(&"macos.acl-native".to_string()));
    assert!(report
        .auxiliary_kinds_present
        .contains(&"macos.finder-info".to_string()));
    assert!(report
        .auxiliary_kinds_present
        .contains(&"macos.resource-fork".to_string()));
}

#[cfg(target_os = "macos")]
#[test]
fn macos_metadata_capture_rejects_a_replaced_source_object() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("source.txt");
    let displaced = temp.path().join("displaced.txt");
    fs::write(&path, b"original").unwrap();
    let identity = input_identity(&fs::metadata(&path).unwrap()).unwrap();
    fs::rename(&path, &displaced).unwrap();
    fs::write(&path, b"replacement").unwrap();

    let error = capture_native_file_metadata(&path, identity).unwrap_err();
    assert!(error
        .to_string()
        .contains("changed before metadata capture"));
}

#[cfg(target_os = "macos")]
#[test]
fn macos_symlink_capture_rejects_a_replaced_link_object() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("source-link");
    let displaced = temp.path().join("displaced-link");
    symlink("original-target", &path).unwrap();
    let identity = input_identity(&fs::symlink_metadata(&path).unwrap()).unwrap();
    fs::rename(&path, &displaced).unwrap();
    symlink("replacement-target", &path).unwrap();

    let error = capture_macos_symlink_metadata(&path, identity).unwrap_err();
    assert!(error
        .to_string()
        .contains("changed before metadata capture"));
}

#[cfg(windows)]
#[test]
fn windows_capture_rejects_metadata_classes_that_are_not_exactly_supported() {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileAttributesW, SetFileAttributesW, FILE_ATTRIBUTE_OFFLINE,
    };

    for attributes in [0x0000_0400, 0x0000_1000] {
        assert!(unsupported_windows_file_attribute_reason(attributes).is_some());
    }
    assert_eq!(unsupported_windows_file_attribute_reason(0x0000_4000), None);
    assert_eq!(unsupported_windows_file_attribute_reason(0x0000_0200), None);
    assert_eq!(unsupported_windows_file_attribute_reason(0x20), None);

    let temp = windows_test_tempdir();
    let offline = temp.path().join("offline-placeholder.bin");
    fs::write(&offline, b"must not be read").unwrap();
    let wide = offline
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: the path is NUL-terminated and remains live for both calls.
    let original = unsafe { GetFileAttributesW(wide.as_ptr()) };
    assert_ne!(original, u32::MAX);
    // SAFETY: as above; OFFLINE is a settable attribute on this ordinary fixture.
    assert_ne!(
        unsafe { SetFileAttributesW(wide.as_ptr(), original | FILE_ATTRIBUTE_OFFLINE) },
        0
    );
    let error = collect_input_specs(&[offline.to_string_lossy().into_owned()]).unwrap_err();
    assert!(format!("{error:#}").contains("explicit hydration policy"));
    // SAFETY: restore the original attributes so temporary-directory cleanup is ordinary.
    assert_ne!(unsafe { SetFileAttributesW(wide.as_ptr(), original) }, 0);
}

#[test]
fn archive_timestamp_canonicalizes_fractional_pre_epoch_times() {
    assert_eq!(
        archive_timestamp(UNIX_EPOCH - Duration::new(0, 100)).unwrap(),
        ArchiveTimestamp::new(-1, 999_999_900)
    );
    assert_eq!(
        archive_timestamp(UNIX_EPOCH - Duration::new(1, 500_000_000)).unwrap(),
        ArchiveTimestamp::new(-2, 500_000_000)
    );
}

#[cfg(windows)]
#[test]
fn windows_filetime_conversion_preserves_100ns_precision() {
    const UNIX_EPOCH_FILETIME: u64 = 116_444_736_000_000_000;
    assert_eq!(
        windows_filetime_timestamp(UNIX_EPOCH_FILETIME + 12_345_678).unwrap(),
        ArchiveTimestamp::new(1, 234_567_800)
    );
    assert_eq!(
        windows_filetime_timestamp(UNIX_EPOCH_FILETIME - 1).unwrap(),
        ArchiveTimestamp::new(-1, 999_999_900)
    );
    assert_eq!(
        windows_filetime_timestamp(0).unwrap(),
        ArchiveTimestamp::new(-11_644_473_600, 0)
    );
}

#[cfg(windows)]
#[test]
fn filesystem_scan_captures_windows_scalars_security_and_alternate_data() {
    use std::os::windows::ffi::OsStrExt as _;
    use std::ptr;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        SetFileSecurityW, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        PROTECTED_SACL_SECURITY_INFORMATION, SACL_SECURITY_INFORMATION, SE_RESTORE_NAME,
    };

    let temp = windows_test_tempdir();
    let path = temp.path().join("native.txt");
    fs::write(&path, b"payload").unwrap();
    let sacl_available = windows_sacl_capture_enabled();
    let sddl = if sacl_available {
        "D:P(A;;FA;;;SY)(A;;FA;;;BA)S:P(AU;SAFA;FW;;;WD)"
    } else {
        "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
    }
    .encode_utf16()
    .chain(std::iter::once(0))
    .collect::<Vec<_>>();
    let mut descriptor = ptr::null_mut();
    // SAFETY: the SDDL is NUL-terminated and the descriptor output is released with LocalFree.
    assert_ne!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        },
        0
    );
    let path_wide = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: the path and descriptor remain live and valid for the call.
    let security_information = DACL_SECURITY_INFORMATION
        | PROTECTED_DACL_SECURITY_INFORMATION
        | if sacl_available {
            SACL_SECURITY_INFORMATION | PROTECTED_SACL_SECURITY_INFORMATION
        } else {
            0
        };
    let set_security_ok = if sacl_available {
        // SAFETY: the path and descriptor remain live and valid for the call.
        unsafe { SetFileSecurityW(path_wide.as_ptr(), security_information, descriptor) }
    } else {
        // A filtered administrator token cannot restore this fixture DACL: replacing the
        // inherited descriptor with its SYSTEM/Administrators-only DACL would revoke this
        // test process's access before the ADS fixtures are created. The ordinary descriptor
        // still exercises owner/group/DACL capture in that environment.
        1
    };
    let set_security_error = std::io::Error::last_os_error();
    // SAFETY: the descriptor was allocated by the conversion API and is freed once.
    assert!(unsafe { LocalFree(descriptor) }.is_null());
    if sacl_available {
        assert_ne!(set_security_ok, 0, "{set_security_error}");
    }
    let alternate_path = PathBuf::from(format!("{}:tzap-test", path.display()));
    fs::write(&alternate_path, b"alternate metadata").unwrap();
    let unicode_alternate_path = PathBuf::from(format!("{}:元数据", path.display()));
    fs::write(&unicode_alternate_path, b"unicode alternate metadata").unwrap();
    let metadata = fs::metadata(&path).unwrap();
    let mut identity = input_identity(&metadata).unwrap();
    let file = File::open(&path).unwrap();
    augment_windows_input_identity(&mut identity, &file).unwrap();

    let native = capture_native_file_metadata(&path, identity).unwrap();

    assert_eq!(native.required_profiles, vec!["windows-backup-v1"]);
    for key in [
        "atime",
        "LIBARCHIVE.creationtime",
        "TZAP.windows.change-time",
        "TZAP.windows.file-attributes",
        "TZAP.windows.data-stream-attributes",
    ] {
        assert!(native.primary_pax_records.contains_key(key), "{key}");
    }
    let security = native
        .auxiliary_records
        .iter()
        .find(|record| record.kind == "windows.security-descriptor")
        .unwrap();
    let security_mask = u32::from_str_radix(
        std::str::from_utf8(&security.meta["TZAP.aux.meta.security-information"]).unwrap(),
        16,
    )
    .unwrap();
    assert_eq!(security_mask & 0xf, if sacl_available { 0xf } else { 0x7 });
    assert_eq!(security_mask & !0xf000_000f, 0);
    let security_control = u16::from_le_bytes([security.payload[2], security.payload[3]]);
    assert_eq!(
        security_mask & 0xa000_0000,
        if security_control & 0x1000 != 0 {
            0x8000_0000
        } else {
            0x2000_0000
        }
    );
    assert_eq!(
        security_mask & 0x5000_0000,
        if security_control & 0x0010 == 0 {
            0
        } else if security_control & 0x2000 != 0 {
            0x4000_0000
        } else {
            0x1000_0000
        }
    );
    let alternate = native
        .auxiliary_records
        .iter()
        .find(|record| {
            record.kind == "windows.alternate-data"
                && record.name
                    == ":tzap-test:$DATA"
                        .encode_utf16()
                        .flat_map(u16::to_le_bytes)
                        .collect::<Vec<_>>()
        })
        .unwrap();
    assert!(alternate.payload.is_empty());
    assert!(alternate.is_streamed());
    assert_eq!(
        alternate.stored_payload_size(),
        b"alternate metadata".len() as u64
    );
    assert_eq!(
        alternate.name,
        ":tzap-test:$DATA"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>()
    );

    let specs = collect_input_specs(&[path.to_string_lossy().into_owned()])
        .unwrap_or_else(|error| panic!("{error:#}"));
    let mut checked_reader = specs[0].open().unwrap();
    let mut checked_payload = Vec::new();
    checked_reader.read_to_end(&mut checked_payload).unwrap();
    assert_eq!(checked_payload, b"payload");

    let master_key = MasterKey::from_raw_key(&[7u8; 32]).unwrap();
    let mut sink = MemoryArchiveSink::default();
    write_archive_sources_to_sink_ordered_parallel(
        &specs,
        &master_key,
        WriterOptions {
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            ..WriterOptions::default()
        },
        &KdfParams::Raw,
        None,
        None,
        &mut sink,
    )
    .unwrap();
    let opened = tzap_core::open_archive(&sink.volumes[0], &master_key).unwrap();
    opened.verify().unwrap();
    let output = temp.path().join("native-output");
    fs::create_dir(&output).unwrap();
    let restore_report = opened
        .extract_all_to(
            &output,
            SafeExtractionOptions {
                restore_policy: RestorePolicy::SameOs,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();
    assert_eq!(fs::read(output.join("native.txt")).unwrap(), b"payload");
    assert_eq!(
        fs::read(PathBuf::from(format!(
            "{}:tzap-test",
            output.join("native.txt").display()
        )))
        .unwrap_or_else(|error| panic!("{error}; report={restore_report:#?}")),
        b"alternate metadata"
    );
    assert_eq!(
        fs::read(PathBuf::from(format!(
            "{}:元数据",
            output.join("native.txt").display()
        )))
        .unwrap(),
        b"unicode alternate metadata"
    );

    if !enable_windows_privilege(SE_RESTORE_NAME) {
        return;
    }

    let system_output = temp.path().join("native-system-output");
    fs::create_dir(&system_output).unwrap();
    opened
        .extract_all_to(
            &system_output,
            SafeExtractionOptions {
                restore_policy: RestorePolicy::System,
                system_authorized: true,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();
    let restored_file = File::open(system_output.join("native.txt")).unwrap();
    let restored_security = capture_windows_security_descriptor(&restored_file).unwrap();
    let expected_security = specs[0]
        .portable_metadata
        .native
        .auxiliary_records
        .iter()
        .find(|record| record.kind == "windows.security-descriptor")
        .unwrap();
    assert_eq!(restored_security.payload, expected_security.payload);
    assert_eq!(restored_security.meta, expected_security.meta);
}

#[cfg(windows)]
#[test]
fn windows_ea_backup_stream_round_trips_exactly() {
    fn write_backup_stream(file: &File, stream_id: u32, payload: &[u8]) -> io::Result<()> {
        use std::os::windows::io::AsRawHandle;
        use std::ptr;
        use windows_sys::Win32::Storage::FileSystem::BackupWrite;

        let mut bytes = Vec::with_capacity(20 + payload.len());
        bytes.extend_from_slice(&stream_id.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&(payload.len() as i64).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(payload);
        let mut context = ptr::null_mut();
        let result = (|| {
            let mut cursor = bytes.as_slice();
            while !cursor.is_empty() {
                let mut written = 0u32;
                // SAFETY: the file, context, and remaining input bytes live for this
                // synchronous BackupWrite call.
                if unsafe {
                    BackupWrite(
                        file.as_raw_handle().cast(),
                        cursor.as_ptr(),
                        cursor.len() as u32,
                        &mut written,
                        0,
                        0,
                        &mut context,
                    )
                } == 0
                {
                    return Err(io::Error::last_os_error());
                }
                if written == 0 || written as usize > cursor.len() {
                    return Err(io::Error::other("BackupWrite made no progress"));
                }
                cursor = &cursor[written as usize..];
            }
            Ok(())
        })();
        let mut ignored = 0u32;
        // SAFETY: aborting with an empty buffer releases this context once.
        unsafe {
            BackupWrite(
                file.as_raw_handle().cast(),
                ptr::null(),
                0,
                &mut ignored,
                1,
                0,
                &mut context,
            );
        }
        result
    }

    let temp = windows_test_tempdir();
    let source = temp.path().join("ea-source.bin");
    fs::write(&source, b"payload").unwrap();
    let source_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&source)
        .unwrap();
    let ea_name = b"TZAP";
    let ea_value = b"exact-ea-value";
    let mut ea = Vec::new();
    ea.extend_from_slice(&0u32.to_le_bytes());
    ea.push(0);
    ea.push(ea_name.len() as u8);
    ea.extend_from_slice(&(ea_value.len() as u16).to_le_bytes());
    ea.extend_from_slice(ea_name);
    ea.push(0);
    ea.extend_from_slice(ea_value);
    write_backup_stream(&source_file, 2, &ea).unwrap();
    drop(source_file);

    let specs = collect_input_specs(&[source.to_string_lossy().into_owned()]).unwrap();
    let captured = specs[0]
        .portable_metadata
        .native
        .auxiliary_records
        .iter()
        .find(|record| record.kind == "windows.ea-data")
        .expect("EA backup stream was not captured");
    assert_eq!(captured.payload, ea);

    let master_key = MasterKey::from_raw_key(&[25u8; 32]).unwrap();
    let mut sink = MemoryArchiveSink::default();
    write_archive_sources_to_sink(
        &specs,
        &master_key,
        WriterOptions {
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            ..WriterOptions::default()
        },
        None,
        &KdfParams::Raw,
        None,
        None,
        &mut sink,
    )
    .unwrap();
    let opened = tzap_core::open_archive(&sink.volumes[0], &master_key).unwrap();
    opened.verify().unwrap();
    let output = temp.path().join("ea-output");
    fs::create_dir(&output).unwrap();
    opened
        .extract_all_to(
            &output,
            SafeExtractionOptions {
                restore_policy: RestorePolicy::SameOs,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();
    let restored = output.join("ea-source.bin");
    let restored_specs = collect_input_specs(&[restored.to_string_lossy().into_owned()]).unwrap();
    let restored_ea = restored_specs[0]
        .portable_metadata
        .native
        .auxiliary_records
        .iter()
        .find(|record| record.kind == "windows.ea-data")
        .expect("restored EA backup stream was not captured");
    assert_eq!(restored_ea.payload, ea);
}

#[cfg(windows)]
#[test]
fn windows_object_id_backup_stream_round_trips_exactly() {
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;
    use std::ptr;
    use windows_sys::Win32::System::Ioctl::{FILE_OBJECTID_BUFFER, FSCTL_CREATE_OR_GET_OBJECT_ID};
    use windows_sys::Win32::System::IO::DeviceIoControl;

    let temp = windows_test_tempdir();
    let source = temp.path().join("object-id-source.bin");
    fs::write(&source, b"payload").unwrap();
    let source_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&source)
        .unwrap();
    let mut object_id = FILE_OBJECTID_BUFFER::default();
    let mut returned = 0u32;
    // SAFETY: the live file handle and fixed output structure remain valid for the call.
    if unsafe {
        DeviceIoControl(
            source_file.as_raw_handle().cast(),
            FSCTL_CREATE_OR_GET_OBJECT_ID,
            ptr::null(),
            0,
            (&mut object_id as *mut FILE_OBJECTID_BUFFER).cast(),
            size_of::<FILE_OBJECTID_BUFFER>() as u32,
            &mut returned,
            ptr::null_mut(),
        )
    } == 0
    {
        // Object IDs are not exposed by every Windows filesystem configuration.
        return;
    }
    assert_eq!(returned as usize, size_of::<FILE_OBJECTID_BUFFER>());
    drop(source_file);

    let specs = collect_input_specs(&[source.to_string_lossy().into_owned()]).unwrap();
    let captured = specs[0]
        .portable_metadata
        .native
        .auxiliary_records
        .iter()
        .find(|record| record.kind == "windows.object-id")
        .expect("object-ID backup stream was not captured")
        .payload
        .clone();
    let master_key = MasterKey::from_raw_key(&[26u8; 32]).unwrap();
    let mut sink = MemoryArchiveSink::default();
    write_archive_sources_to_sink(
        &specs,
        &master_key,
        WriterOptions {
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            ..WriterOptions::default()
        },
        None,
        &KdfParams::Raw,
        None,
        None,
        &mut sink,
    )
    .unwrap();
    let opened = tzap_core::open_archive(&sink.volumes[0], &master_key).unwrap();
    opened.verify().unwrap();
    if !enable_windows_privilege(windows_sys::Win32::Security::SE_RESTORE_NAME) {
        return;
    }
    // Object IDs are volume-unique. Remove the source before restoring its exact ID on the
    // same volume so the filesystem can accept the archived identity.
    fs::remove_file(&source).unwrap();
    let output = temp.path().join("object-id-output");
    fs::create_dir(&output).unwrap();
    let diagnostics = opened
        .extract_all_to(
            &output,
            SafeExtractionOptions {
                restore_policy: RestorePolicy::System,
                system_authorized: true,
                allow_degraded: true,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();
    assert!(
        !diagnostics
            .iter()
            .flat_map(|(_, diagnostics)| diagnostics)
            .any(|diagnostic| {
                diagnostic.metadata_class == "windows.object-id"
                    && diagnostic.status == MetadataDiagnosticStatus::Failed
            }),
        "object-ID restoration degraded: {diagnostics:#?}"
    );
    let restored = output.join("object-id-source.bin");
    let restored_specs = collect_input_specs(&[restored.to_string_lossy().into_owned()]).unwrap();
    let restored_object_id = restored_specs[0]
        .portable_metadata
        .native
        .auxiliary_records
        .iter()
        .find(|record| record.kind == "windows.object-id")
        .expect("restored object-ID backup stream was not captured");
    assert_eq!(restored_object_id.payload, captured);
}

#[cfg(windows)]
#[test]
fn windows_raw_efs_round_trips_without_plaintext_substitution() {
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::fs::MetadataExt as _;
    use windows_sys::Win32::Foundation::{ERROR_FILE_SYSTEM_LIMITATION, ERROR_NOT_SUPPORTED};
    use windows_sys::Win32::Storage::FileSystem::EncryptFileW;

    const FILE_ATTRIBUTE_ENCRYPTED: u32 = 0x0000_4000;
    let temp = windows_test_tempdir();
    let source = temp.path().join("encrypted.txt");
    let plaintext = b"raw EFS must be archived and restored through the native callback APIs";
    fs::write(&source, plaintext).unwrap();
    let alternate_plaintext = b"encrypted alternate stream";
    fs::write(
        PathBuf::from(format!("{}:efs-alternate", source.display())),
        alternate_plaintext,
    )
    .unwrap();
    let source_wide = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: the path is NUL-terminated and remains live for the synchronous call.
    if unsafe { EncryptFileW(source_wide.as_ptr()) } == 0 {
        let error = std::io::Error::last_os_error();
        if matches!(
            error.raw_os_error().map(|value| value as u32),
            Some(code) if code == ERROR_NOT_SUPPORTED || code == ERROR_FILE_SYSTEM_LIMITATION
        ) {
            return;
        }
        panic!("failed to create raw EFS fixture: {error}");
    }
    assert_ne!(
        fs::metadata(&source).unwrap().file_attributes() & FILE_ATTRIBUTE_ENCRYPTED,
        0
    );

    let specs = collect_input_specs(&[source.to_string_lossy().into_owned()])
        .unwrap_or_else(|error| panic!("{error:#}"));
    let raw = specs[0]
        .portable_metadata
        .native
        .auxiliary_records
        .iter()
        .find(|record| record.kind == "windows.efs-raw")
        .expect("encrypted input must retain a raw EFS record");
    assert!(raw.is_streamed());
    assert_eq!(raw.meta["TZAP.aux.meta.efs-version"], b"1");
    let (expected_raw_size, expected_raw_hash) = hash_windows_raw_efs(&source).unwrap();
    assert_eq!(raw.stored_payload_size(), expected_raw_size);

    let master_key = MasterKey::from_raw_key(&[19u8; 32]).unwrap();
    let mut sink = MemoryArchiveSink::default();
    write_archive_sources_to_sink_ordered_parallel(
        &specs,
        &master_key,
        WriterOptions {
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            ..WriterOptions::default()
        },
        &KdfParams::Raw,
        None,
        None,
        &mut sink,
    )
    .unwrap();
    let opened = tzap_core::open_archive(&sink.volumes[0], &master_key).unwrap();
    opened.verify().unwrap();
    let output = temp.path().join("efs-output");
    fs::create_dir(&output).unwrap();
    opened
        .extract_all_to(
            &output,
            SafeExtractionOptions {
                restore_policy: RestorePolicy::System,
                system_authorized: true,
                allow_degraded: true,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();

    let restored = output.join("encrypted.txt");
    assert_eq!(fs::read(&restored).unwrap(), plaintext);
    assert_eq!(
        fs::read(PathBuf::from(format!(
            "{}:efs-alternate",
            restored.display()
        )))
        .unwrap(),
        alternate_plaintext
    );
    assert_ne!(
        fs::metadata(&restored).unwrap().file_attributes() & FILE_ATTRIBUTE_ENCRYPTED,
        0
    );
    assert_eq!(
        hash_windows_raw_efs(&restored).unwrap(),
        (expected_raw_size, expected_raw_hash)
    );

    let encrypted_directory = temp.path().join("encrypted-directory");
    fs::create_dir(&encrypted_directory).unwrap();
    let directory_wide = encrypted_directory
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: the directory path is NUL-terminated and remains live for the call.
    assert_ne!(unsafe { EncryptFileW(directory_wide.as_ptr()) }, 0);
    let error =
        collect_input_specs(&[encrypted_directory.to_string_lossy().into_owned()]).unwrap_err();
    assert!(format!("{error:#}").contains("CREATE_FOR_DIR"));
}

#[cfg(windows)]
#[test]
fn standalone_windows_directory_alternate_data_round_trips() {
    let temp = windows_test_tempdir();
    let source = temp.path().join("native-directory");
    fs::create_dir(&source).unwrap();
    fs::write(
        PathBuf::from(format!("{}:tzap-directory", source.display())),
        b"directory alternate metadata",
    )
    .unwrap();

    let specs = collect_input_specs(&[source.to_string_lossy().into_owned()])
        .unwrap_or_else(|error| panic!("{error:#}"));
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].entry_kind, SourceEntryKind::Directory);
    assert!(specs[0]
        .portable_metadata
        .native
        .auxiliary_records
        .iter()
        .any(|record| record.kind == "windows.alternate-data"));

    let master_key = MasterKey::from_raw_key(&[11u8; 32]).unwrap();
    let mut sink = MemoryArchiveSink::default();
    write_archive_sources_to_sink_ordered_parallel(
        &specs,
        &master_key,
        WriterOptions {
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            ..WriterOptions::default()
        },
        &KdfParams::Raw,
        None,
        None,
        &mut sink,
    )
    .unwrap();
    let opened = tzap_core::open_archive(&sink.volumes[0], &master_key).unwrap();
    opened.verify().unwrap();
    let output = temp.path().join("directory-output");
    fs::create_dir(&output).unwrap();
    opened
        .extract_all_to(
            &output,
            SafeExtractionOptions {
                restore_policy: RestorePolicy::SameOs,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();
    let restored = output.join("native-directory");
    assert!(restored.is_dir());
    assert_eq!(
        fs::read(PathBuf::from(format!(
            "{}:tzap-directory",
            restored.display()
        )))
        .unwrap(),
        b"directory alternate metadata"
    );
}

#[cfg(windows)]
#[test]
fn windows_directory_case_sensitive_state_round_trips() {
    use std::mem::size_of;
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FileCaseSensitiveInfo, SetFileInformationByHandle, FILE_CASE_SENSITIVE_INFO,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, FILE_WRITE_ATTRIBUTES,
    };
    use windows_sys::Win32::System::SystemServices::FILE_CS_FLAG_CASE_SENSITIVE_DIR;

    let temp = windows_test_tempdir();
    let source = temp.path().join("case-sensitive-directory");
    fs::create_dir(&source).unwrap();
    let source_file = fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(&source)
        .unwrap();
    let enabled = FILE_CASE_SENSITIVE_INFO {
        Flags: FILE_CS_FLAG_CASE_SENSITIVE_DIR,
    };
    // SAFETY: the directory handle is live and `enabled` is correctly sized and initialized.
    assert_ne!(
        unsafe {
            SetFileInformationByHandle(
                source_file.as_raw_handle().cast(),
                FileCaseSensitiveInfo,
                (&enabled as *const FILE_CASE_SENSITIVE_INFO).cast(),
                size_of::<FILE_CASE_SENSITIVE_INFO>() as u32,
            )
        },
        0,
        "{}",
        io::Error::last_os_error()
    );
    assert_eq!(
        query_windows_directory_case_sensitive(&source_file).unwrap(),
        Some(true)
    );
    drop(source_file);

    let specs = collect_input_specs(&[source.to_string_lossy().into_owned()]).unwrap();
    assert_eq!(
        specs[0]
            .portable_metadata
            .native
            .primary_pax_records
            .get("TZAP.windows.directory-case-sensitive")
            .map(Vec::as_slice),
        Some(b"1".as_slice())
    );
    let master_key = MasterKey::from_raw_key(&[24u8; 32]).unwrap();
    let mut sink = MemoryArchiveSink::default();
    write_archive_sources_to_sink(
        &specs,
        &master_key,
        WriterOptions {
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            ..WriterOptions::default()
        },
        None,
        &KdfParams::Raw,
        None,
        None,
        &mut sink,
    )
    .unwrap();
    let opened = tzap_core::open_archive(&sink.volumes[0], &master_key).unwrap();
    opened.verify().unwrap();
    let same_os_output = temp.path().join("case-same-os-output");
    fs::create_dir(&same_os_output).unwrap();
    let same_os_diagnostics = opened
        .extract_all_to(
            &same_os_output,
            SafeExtractionOptions {
                restore_policy: RestorePolicy::SameOs,
                allow_degraded: true,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();
    assert!(same_os_diagnostics
        .iter()
        .flat_map(|(_, diagnostics)| diagnostics)
        .any(|diagnostic| {
            diagnostic.metadata_class == "directory-case-sensitive"
                && diagnostic.status == MetadataDiagnosticStatus::Unsupported
        }));
    let same_os_restored =
        open_windows_metadata_handle(&same_os_output.join("case-sensitive-directory")).unwrap();
    assert_eq!(
        query_windows_directory_case_sensitive(&same_os_restored).unwrap(),
        Some(false)
    );
    let output = temp.path().join("case-output");
    fs::create_dir(&output).unwrap();
    opened
        .extract_all_to(
            &output,
            SafeExtractionOptions {
                restore_policy: RestorePolicy::System,
                system_authorized: true,
                allow_degraded: true,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();
    let restored = open_windows_metadata_handle(&output.join("case-sensitive-directory")).unwrap();
    assert_eq!(
        query_windows_directory_case_sensitive(&restored).unwrap(),
        Some(true)
    );
}

#[cfg(windows)]
#[test]
fn sparse_windows_alternate_data_round_trips_ranges_and_content() {
    use std::os::windows::io::AsRawHandle;
    use std::ptr;
    use windows_sys::Win32::System::Ioctl::FSCTL_SET_SPARSE;
    use windows_sys::Win32::System::IO::DeviceIoControl;

    let temp = windows_test_tempdir();
    let source = temp.path().join("sparse-ads.bin");
    fs::write(&source, b"base payload").unwrap();
    let stream_path = PathBuf::from(format!("{}:sparse-test", source.display()));
    let mut stream = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&stream_path)
        .unwrap();
    let mut bytes_returned = 0u32;
    // SAFETY: the stream handle is live and FSCTL_SET_SPARSE accepts empty buffers.
    assert_ne!(
        unsafe {
            DeviceIoControl(
                stream.as_raw_handle().cast(),
                FSCTL_SET_SPARSE,
                ptr::null(),
                0,
                ptr::null_mut(),
                0,
                &mut bytes_returned,
                ptr::null_mut(),
            )
        },
        0
    );
    let logical_size = 1024 * 1024u64;
    stream.set_len(logical_size).unwrap();
    stream.seek(SeekFrom::Start(64 * 1024)).unwrap();
    stream.write_all(b"sparse ADS leading extent").unwrap();
    stream.seek(SeekFrom::Start(logical_size - 4096)).unwrap();
    stream.write_all(b"sparse ADS trailing extent").unwrap();
    stream.flush().unwrap();
    let source_ranges = query_windows_allocated_ranges(&stream, logical_size).unwrap();
    drop(stream);

    let specs = collect_input_specs(&[source.to_string_lossy().into_owned()])
        .unwrap_or_else(|error| panic!("{error:#}"));
    let sparse_record = specs[0]
        .portable_metadata
        .native
        .auxiliary_records
        .iter()
        .find(|record| record.kind == "windows.alternate-data")
        .unwrap();
    assert!(sparse_record.is_streamed());
    assert_eq!(sparse_record.flags, 1);
    assert_eq!(sparse_record.logical_size, logical_size);
    let captured_ranges = sparse_record.streamed_sparse_extents().unwrap();
    assert!(!captured_ranges.is_empty());
    if !source_ranges.is_empty() {
        assert_eq!(captured_ranges, source_ranges);
    }

    let key = MasterKey::from_raw_key(&[19u8; 32]).unwrap();
    let mut sink = MemoryArchiveSink::default();
    write_archive_sources_to_sink_ordered_parallel(
        &specs,
        &key,
        WriterOptions {
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            ..WriterOptions::default()
        },
        &KdfParams::Raw,
        None,
        None,
        &mut sink,
    )
    .unwrap();
    let opened = tzap_core::open_archive(&sink.volumes[0], &key).unwrap();
    opened.verify().unwrap();
    let output = temp.path().join("sparse-ads-output");
    fs::create_dir(&output).unwrap();
    opened
        .extract_all_to(
            &output,
            SafeExtractionOptions {
                restore_policy: RestorePolicy::SameOs,
                allow_degraded: true,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();
    let restored_stream_path = PathBuf::from(format!(
        "{}:sparse-test",
        output.join("sparse-ads.bin").display()
    ));
    let restored_stream = File::open(&restored_stream_path).unwrap();
    assert_eq!(restored_stream.metadata().unwrap().len(), logical_size);
    let restored_ranges = query_windows_allocated_ranges(&restored_stream, logical_size).unwrap();
    if !restored_ranges.is_empty() {
        assert_eq!(restored_ranges, captured_ranges);
    }
    let logical = fs::read(restored_stream_path).unwrap();
    assert_eq!(
        &logical[64 * 1024..64 * 1024 + 25],
        b"sparse ADS leading extent"
    );
    assert_eq!(
        &logical[logical_size as usize - 4096..logical_size as usize - 4096 + 26],
        b"sparse ADS trailing extent"
    );
}

#[cfg(windows)]
#[test]
fn windows_sparse_file_round_trips_logical_bytes_and_allocated_ranges() {
    use std::os::windows::io::AsRawHandle;
    use std::ptr;
    use windows_sys::Win32::System::Ioctl::FSCTL_SET_SPARSE;
    use windows_sys::Win32::System::IO::DeviceIoControl;

    let temp = windows_test_tempdir();
    let path = temp.path().join("sparse.bin");
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    let mut bytes_returned = 0u32;
    // SAFETY: the file handle is live and FSCTL_SET_SPARSE accepts empty synchronous buffers.
    assert_ne!(
        unsafe {
            DeviceIoControl(
                file.as_raw_handle().cast(),
                FSCTL_SET_SPARSE,
                ptr::null(),
                0,
                ptr::null_mut(),
                0,
                &mut bytes_returned,
                ptr::null_mut(),
            )
        },
        0
    );
    let logical_size = 1024 * 1024u64;
    file.set_len(logical_size).unwrap();
    file.seek(SeekFrom::Start(64 * 1024)).unwrap();
    file.write_all(b"leading extent").unwrap();
    file.seek(SeekFrom::Start(logical_size - 4096)).unwrap();
    file.write_all(b"trailing extent").unwrap();
    file.flush().unwrap();
    let refs_sparse_fallback = windows_file_system_is_refs(&file).unwrap();
    let source_ranges = query_windows_allocated_ranges(&file, logical_size).unwrap();
    assert!(!source_ranges.is_empty());
    drop(file);

    let specs = collect_input_specs(&[path.to_string_lossy().into_owned()])
        .unwrap_or_else(|error| panic!("{error:#}"));
    assert_eq!(specs.len(), 1);
    assert_eq!(
        specs[0].sparse_extents.as_deref(),
        Some(source_ranges.as_slice())
    );
    let master_key = MasterKey::from_raw_key(&[9u8; 32]).unwrap();
    let mut sink = MemoryArchiveSink::default();
    write_archive_sources_to_sink(
        &specs,
        &master_key,
        WriterOptions {
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            ..WriterOptions::default()
        },
        None,
        &KdfParams::Raw,
        None,
        None,
        &mut sink,
    )
    .unwrap();
    let opened = tzap_core::open_archive(&sink.volumes[0], &master_key).unwrap();
    opened.verify().unwrap();
    let index = opened.lookup_index_entry("sparse.bin").unwrap().unwrap();
    assert_eq!(index.file_data_size, logical_size);

    let output = temp.path().join("output");
    fs::create_dir(&output).unwrap();
    opened
        .extract_all_to(
            &output,
            SafeExtractionOptions {
                allow_degraded: refs_sparse_fallback,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();
    let restored_path = output.join("sparse.bin");
    let restored = File::open(&restored_path).unwrap();
    assert_eq!(restored.metadata().unwrap().len(), logical_size);
    assert_eq!(
        query_windows_allocated_ranges(&restored, logical_size).unwrap(),
        source_ranges
    );
    let logical = fs::read(restored_path).unwrap();
    assert_eq!(&logical[64 * 1024..64 * 1024 + 14], b"leading extent");
    assert_eq!(
        &logical[logical_size as usize - 4096..logical_size as usize - 4096 + 15],
        b"trailing extent"
    );
}

#[cfg(windows)]
#[test]
fn windows_basic_attributes_and_all_four_times_round_trip() {
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileBasicInfo, GetFileInformationByHandleEx, SetFileInformationByHandle, FILE_BASIC_INFO,
    };

    const READONLY: u32 = 0x0000_0001;
    const HIDDEN: u32 = 0x0000_0002;
    const SYSTEM: u32 = 0x0000_0004;
    const ARCHIVE: u32 = 0x0000_0020;
    const MUTABLE_MASK: u32 = READONLY | HIDDEN | SYSTEM | ARCHIVE | 0x100 | 0x2000;
    const WINDOWS_EPOCH_OFFSET: i64 = 116_444_736_000_000_000;

    let temp = windows_test_tempdir();
    let source = temp.path().join("basic.bin");
    fs::write(&source, b"windows basic metadata").unwrap();
    let source_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&source)
        .unwrap();
    let expected = FILE_BASIC_INFO {
        CreationTime: WINDOWS_EPOCH_OFFSET - 12_345_678_000_000,
        LastAccessTime: WINDOWS_EPOCH_OFFSET - 11_111_111_000_000,
        LastWriteTime: WINDOWS_EPOCH_OFFSET - 9_876_543_000_000,
        ChangeTime: WINDOWS_EPOCH_OFFSET - 8_765_432_000_000,
        FileAttributes: HIDDEN | SYSTEM | ARCHIVE,
    };
    // SAFETY: the handle is live and `expected` is a correctly sized initialized structure.
    assert_ne!(
        unsafe {
            SetFileInformationByHandle(
                source_file.as_raw_handle().cast(),
                FileBasicInfo,
                (&expected as *const FILE_BASIC_INFO).cast(),
                size_of::<FILE_BASIC_INFO>() as u32,
            )
        },
        0
    );
    drop(source_file);

    let specs = collect_input_specs(&[source.to_string_lossy().into_owned()]).unwrap();
    let master_key = MasterKey::from_raw_key(&[10u8; 32]).unwrap();
    let mut sink = MemoryArchiveSink::default();
    write_archive_sources_to_sink(
        &specs,
        &master_key,
        WriterOptions {
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            ..WriterOptions::default()
        },
        None,
        &KdfParams::Raw,
        None,
        None,
        &mut sink,
    )
    .unwrap();
    let opened = tzap_core::open_archive(&sink.volumes[0], &master_key).unwrap();
    opened.verify().unwrap();
    let output = temp.path().join("basic-output");
    fs::create_dir(&output).unwrap();
    opened
        .extract_all_to(
            &output,
            SafeExtractionOptions {
                restore_policy: RestorePolicy::SameOs,
                allow_degraded: true,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();

    let restored = File::open(output.join("basic.bin")).unwrap();
    let mut actual = FILE_BASIC_INFO::default();
    // SAFETY: the handle is live and `actual` is a correctly sized writable structure.
    assert_ne!(
        unsafe {
            GetFileInformationByHandleEx(
                restored.as_raw_handle().cast(),
                FileBasicInfo,
                (&mut actual as *mut FILE_BASIC_INFO).cast(),
                size_of::<FILE_BASIC_INFO>() as u32,
            )
        },
        0
    );
    assert_eq!(actual.CreationTime, expected.CreationTime);
    assert_eq!(actual.LastAccessTime, expected.LastAccessTime);
    assert_eq!(actual.LastWriteTime, expected.LastWriteTime);
    assert_eq!(actual.ChangeTime, expected.ChangeTime);
    assert_eq!(
        actual.FileAttributes & MUTABLE_MASK,
        expected.FileAttributes & MUTABLE_MASK
    );
}

#[cfg(windows)]
#[test]
fn windows_native_compression_round_trips_on_supported_filesystems() {
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;
    use std::ptr;
    use windows_sys::Win32::Storage::FileSystem::{
        FileBasicInfo, GetFileInformationByHandleEx, COMPRESSION_FORMAT_DEFAULT, FILE_BASIC_INFO,
    };
    use windows_sys::Win32::System::Ioctl::FSCTL_SET_COMPRESSION;
    use windows_sys::Win32::System::IO::DeviceIoControl;

    const FILE_ATTRIBUTE_COMPRESSED: u32 = 0x0000_0800;
    // Keep the source on NTFS. TZAP_WINDOWS_TEST_ROOT can independently direct the
    // destination to ReFS and exercise the required storage-layout degradation path.
    let source_temp = tempfile::tempdir().unwrap();
    let destination_temp = windows_test_tempdir();
    let source = source_temp.path().join("compressed.bin");
    fs::write(&source, vec![b'z'; 256 * 1024]).unwrap();
    let source_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&source)
        .unwrap();
    let mut compression = COMPRESSION_FORMAT_DEFAULT;
    let mut returned = 0u32;
    // SAFETY: the live file handle and initialized two-byte format input remain valid.
    if unsafe {
        DeviceIoControl(
            source_file.as_raw_handle().cast(),
            FSCTL_SET_COMPRESSION,
            (&mut compression as *mut u16).cast(),
            size_of::<u16>() as u32,
            ptr::null_mut(),
            0,
            &mut returned,
            ptr::null_mut(),
        )
    } == 0
    {
        panic!(
            "NTFS compression fixture failed: {}",
            io::Error::last_os_error()
        );
    }
    let mut source_basic = FILE_BASIC_INFO::default();
    // SAFETY: the handle is live and `source_basic` is correctly sized and writable.
    assert_ne!(
        unsafe {
            GetFileInformationByHandleEx(
                source_file.as_raw_handle().cast(),
                FileBasicInfo,
                (&mut source_basic as *mut FILE_BASIC_INFO).cast(),
                size_of::<FILE_BASIC_INFO>() as u32,
            )
        },
        0
    );
    assert_ne!(source_basic.FileAttributes & FILE_ATTRIBUTE_COMPRESSED, 0);
    drop(source_file);

    let specs = collect_input_specs(&[source.to_string_lossy().into_owned()]).unwrap();
    let captured_attributes = specs[0]
        .portable_metadata
        .native
        .primary_pax_records
        .get("TZAP.windows.file-attributes")
        .unwrap();
    let captured_attributes =
        u32::from_str_radix(std::str::from_utf8(captured_attributes).unwrap(), 16).unwrap();
    assert_ne!(captured_attributes & FILE_ATTRIBUTE_COMPRESSED, 0);

    let master_key = MasterKey::from_raw_key(&[23u8; 32]).unwrap();
    let mut sink = MemoryArchiveSink::default();
    write_archive_sources_to_sink(
        &specs,
        &master_key,
        WriterOptions {
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            ..WriterOptions::default()
        },
        None,
        &KdfParams::Raw,
        None,
        None,
        &mut sink,
    )
    .unwrap();
    let opened = tzap_core::open_archive(&sink.volumes[0], &master_key).unwrap();
    opened.verify().unwrap();
    let destination_root = open_windows_metadata_handle(destination_temp.path()).unwrap();
    let destination_refs = windows_file_system_is_refs(&destination_root).unwrap();
    let output = destination_temp.path().join("compressed-output");
    fs::create_dir(&output).unwrap();
    opened
        .extract_all_to(
            &output,
            SafeExtractionOptions {
                restore_policy: RestorePolicy::SameOs,
                allow_degraded: destination_refs,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();
    let restored = File::open(output.join("compressed.bin")).unwrap();
    let mut restored_basic = FILE_BASIC_INFO::default();
    // SAFETY: the handle is live and `restored_basic` is correctly sized and writable.
    assert_ne!(
        unsafe {
            GetFileInformationByHandleEx(
                restored.as_raw_handle().cast(),
                FileBasicInfo,
                (&mut restored_basic as *mut FILE_BASIC_INFO).cast(),
                size_of::<FILE_BASIC_INFO>() as u32,
            )
        },
        0
    );
    assert_eq!(
        restored_basic.FileAttributes & FILE_ATTRIBUTE_COMPRESSED != 0,
        !destination_refs
    );
    assert_eq!(
        fs::read(output.join("compressed.bin")).unwrap(),
        vec![b'z'; 256 * 1024]
    );
}

#[cfg(windows)]
#[test]
fn windows_relative_symlink_round_trips_portable_and_exact_reparse_data() {
    let temp = windows_test_tempdir();
    fs::write(temp.path().join("target.txt"), b"target").unwrap();
    let source = temp.path().join("link.txt");
    if !create_windows_relative_symlink(&source, "target.txt") {
        return;
    }
    let source_handle = open_windows_metadata_handle(&source).unwrap();
    let expected_reparse = query_windows_reparse_data(&source_handle).unwrap();
    assert!(matches!(
        validate_windows_known_reparse_data(&expected_reparse).unwrap(),
        WindowsKnownReparse::RelativeSymlink { .. }
    ));

    let specs = collect_input_specs(&[source.to_string_lossy().into_owned()])
        .unwrap_or_else(|error| panic!("{error:#}"));
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].entry_kind, SourceEntryKind::Symlink);
    assert!(specs[0]
        .portable_metadata
        .native
        .auxiliary_records
        .iter()
        .any(|record| record.kind == "windows.reparse-data" && record.payload == expected_reparse));

    let master_key = MasterKey::from_raw_key(&[11u8; 32]).unwrap();
    let mut sink = MemoryArchiveSink::default();
    write_archive_sources_to_sink(
        &specs,
        &master_key,
        WriterOptions {
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            ..WriterOptions::default()
        },
        None,
        &KdfParams::Raw,
        None,
        None,
        &mut sink,
    )
    .unwrap();
    let opened = tzap_core::open_archive(&sink.volumes[0], &master_key).unwrap();
    opened.verify().unwrap();

    let portable_output = temp.path().join("portable-links");
    fs::create_dir(&portable_output).unwrap();
    opened
        .extract_all_to(&portable_output, SafeExtractionOptions::default())
        .unwrap();
    assert_eq!(
        fs::read_link(portable_output.join("link.txt")).unwrap(),
        PathBuf::from("target.txt")
    );

    let exact_output = temp.path().join("exact-links");
    fs::create_dir(&exact_output).unwrap();
    opened
        .extract_all_to(
            &exact_output,
            SafeExtractionOptions {
                restore_policy: RestorePolicy::System,
                allow_degraded: true,
                system_authorized: true,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();
    let exact_handle = open_windows_metadata_handle(&exact_output.join("link.txt")).unwrap();
    assert_eq!(
        query_windows_reparse_data(&exact_handle).unwrap(),
        expected_reparse
    );
}

#[cfg(windows)]
#[test]
fn windows_junction_round_trips_as_skipped_placeholder_and_exact_reparse_data() {
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use std::ptr;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
        FILE_GENERIC_WRITE,
    };
    use windows_sys::Win32::System::Ioctl::FSCTL_SET_REPARSE_POINT;
    use windows_sys::Win32::System::IO::DeviceIoControl;

    let temp = windows_test_tempdir();
    let target = temp.path().join("junction-target");
    fs::create_dir(&target).unwrap();
    let junction = temp.path().join("junction");
    fs::create_dir(&junction).unwrap();

    let print = target.as_os_str().encode_wide().collect::<Vec<_>>();
    let mut substitute = "\\??\\".encode_utf16().collect::<Vec<_>>();
    substitute.extend_from_slice(&print);
    let substitute_bytes = substitute.len() * 2;
    let print_offset = substitute_bytes + 2;
    let mut path_units = substitute.clone();
    path_units.push(0);
    path_units.extend_from_slice(&print);
    path_units.push(0);
    let payload_len = 8 + path_units.len() * 2;
    let mut reparse = Vec::with_capacity(8 + payload_len);
    reparse.extend_from_slice(&0xA000_0003u32.to_le_bytes());
    reparse.extend_from_slice(&(payload_len as u16).to_le_bytes());
    reparse.extend_from_slice(&0u16.to_le_bytes());
    reparse.extend_from_slice(&0u16.to_le_bytes());
    reparse.extend_from_slice(&(substitute_bytes as u16).to_le_bytes());
    reparse.extend_from_slice(&(print_offset as u16).to_le_bytes());
    reparse.extend_from_slice(&((print.len() * 2) as u16).to_le_bytes());
    for unit in path_units {
        reparse.extend_from_slice(&unit.to_le_bytes());
    }
    let junction_handle = fs::OpenOptions::new()
        .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&junction)
        .unwrap();
    let mut returned = 0u32;
    // SAFETY: the handle and canonical mount-point payload remain live for the call.
    assert_ne!(
        unsafe {
            DeviceIoControl(
                junction_handle.as_raw_handle().cast(),
                FSCTL_SET_REPARSE_POINT,
                reparse.as_ptr().cast(),
                reparse.len() as u32,
                ptr::null_mut(),
                0,
                &mut returned,
                ptr::null_mut(),
            )
        },
        0
    );
    drop(junction_handle);
    let source_handle = open_windows_metadata_handle(&junction).unwrap();
    let expected_reparse = query_windows_reparse_data(&source_handle).unwrap();
    assert_eq!(expected_reparse, reparse);

    let specs = collect_input_specs(&[junction.to_string_lossy().into_owned()])
        .unwrap_or_else(|error| panic!("{error:#}"));
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].entry_kind, SourceEntryKind::ReparseDirectory);
    let master_key = MasterKey::from_raw_key(&[12u8; 32]).unwrap();
    let mut sink = MemoryArchiveSink::default();
    write_archive_sources_to_sink(
        &specs,
        &master_key,
        WriterOptions {
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            ..WriterOptions::default()
        },
        None,
        &KdfParams::Raw,
        None,
        None,
        &mut sink,
    )
    .unwrap();
    let opened = tzap_core::open_archive(&sink.volumes[0], &master_key).unwrap();
    opened.verify().unwrap();

    let portable_output = temp.path().join("portable-junction");
    fs::create_dir(&portable_output).unwrap();
    opened
        .extract_all_to(&portable_output, SafeExtractionOptions::default())
        .unwrap();
    assert!(!portable_output.join("junction").exists());

    let exact_output = temp.path().join("exact-junction");
    fs::create_dir(&exact_output).unwrap();
    let exact_report = opened
        .extract_all_to(
            &exact_output,
            SafeExtractionOptions {
                restore_policy: RestorePolicy::System,
                allow_degraded: true,
                system_authorized: true,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();
    let exact_handle = open_windows_metadata_handle(&exact_output.join("junction"))
        .unwrap_or_else(|error| panic!("{error}; report={exact_report:#?}"));
    assert_eq!(
        query_windows_reparse_data(&exact_handle).unwrap(),
        expected_reparse
    );
}

#[cfg(windows)]
#[test]
fn windows_opaque_reparse_tag_round_trips_as_skipped_placeholder_and_exact_data() {
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use std::ptr;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    };
    use windows_sys::Win32::System::Ioctl::FSCTL_SET_REPARSE_POINT;
    use windows_sys::Win32::System::IO::DeviceIoControl;

    let temp = windows_test_tempdir();
    let source = temp.path().join("opaque-reparse.bin");
    fs::write(&source, b"").unwrap();
    // Non-Microsoft tags use REPARSE_GUID_DATA_BUFFER. ReparseDataLength includes the GUID
    // and the tag-specific bytes after the common eight-byte header.
    let mut reparse = Vec::new();
    reparse.extend_from_slice(&0x0000_0042u32.to_le_bytes());
    reparse.extend_from_slice(&4u16.to_le_bytes());
    reparse.extend_from_slice(&0u16.to_le_bytes());
    reparse.extend_from_slice(&[
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88,
    ]);
    reparse.extend_from_slice(b"tzap");
    let handle = fs::OpenOptions::new()
        .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&source)
        .unwrap();
    let mut returned = 0u32;
    // SAFETY: the handle and complete opaque GUID reparse buffer remain live for the call.
    assert_ne!(
        unsafe {
            DeviceIoControl(
                handle.as_raw_handle().cast(),
                FSCTL_SET_REPARSE_POINT,
                reparse.as_ptr().cast(),
                reparse.len() as u32,
                ptr::null_mut(),
                0,
                &mut returned,
                ptr::null_mut(),
            )
        },
        0,
        "{}",
        io::Error::last_os_error()
    );
    drop(handle);
    let source_handle = open_windows_metadata_handle(&source).unwrap();
    let expected_reparse = query_windows_reparse_data(&source_handle).unwrap();
    assert_eq!(expected_reparse, reparse);
    assert_eq!(
        validate_windows_known_reparse_data(&expected_reparse).unwrap(),
        WindowsKnownReparse::Opaque
    );

    let specs = collect_input_specs(&[source.to_string_lossy().into_owned()])
        .unwrap_or_else(|error| panic!("{error:#}"));
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].entry_kind, SourceEntryKind::ReparseRegular);
    let master_key = MasterKey::from_raw_key(&[22u8; 32]).unwrap();
    let mut sink = MemoryArchiveSink::default();
    write_archive_sources_to_sink(
        &specs,
        &master_key,
        WriterOptions {
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            ..WriterOptions::default()
        },
        None,
        &KdfParams::Raw,
        None,
        None,
        &mut sink,
    )
    .unwrap();
    let opened = tzap_core::open_archive(&sink.volumes[0], &master_key).unwrap();
    opened.verify().unwrap();

    let portable_output = temp.path().join("opaque-portable");
    fs::create_dir(&portable_output).unwrap();
    opened
        .extract_all_to(&portable_output, SafeExtractionOptions::default())
        .unwrap();
    assert!(!portable_output.join("opaque-reparse.bin").exists());

    let exact_output = temp.path().join("opaque-exact");
    fs::create_dir(&exact_output).unwrap();
    opened
        .extract_all_to(
            &exact_output,
            SafeExtractionOptions {
                restore_policy: RestorePolicy::System,
                allow_degraded: true,
                system_authorized: true,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();
    let exact_handle =
        open_windows_metadata_handle(&exact_output.join("opaque-reparse.bin")).unwrap();
    assert_eq!(
        query_windows_reparse_data(&exact_handle).unwrap(),
        expected_reparse
    );
}

#[cfg(windows)]
#[test]
fn windows_selected_hardlinks_store_data_once_and_restore_shared_file_identity() {
    let temp = windows_test_tempdir();
    let alpha = temp.path().join("alpha.bin");
    let beta = temp.path().join("beta.bin");
    fs::write(&alpha, b"one physical file").unwrap();
    fs::hard_link(&alpha, &beta).unwrap();

    let specs = collect_input_specs(&[
        beta.to_string_lossy().into_owned(),
        alpha.to_string_lossy().into_owned(),
    ])
    .unwrap_or_else(|error| panic!("{error:#}"));
    assert_eq!(specs.len(), 2);
    assert_eq!(specs[0].archive_path, "alpha.bin");
    assert_eq!(specs[0].entry_kind, SourceEntryKind::Regular);
    assert_eq!(specs[1].entry_kind, SourceEntryKind::Hardlink);
    assert_eq!(
        specs[1].link_target.as_deref(),
        Some(b"alpha.bin".as_slice())
    );

    let master_key = MasterKey::from_raw_key(&[13u8; 32]).unwrap();
    let mut sink = MemoryArchiveSink::default();
    write_archive_sources_to_sink(
        &specs,
        &master_key,
        WriterOptions {
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            ..WriterOptions::default()
        },
        None,
        &KdfParams::Raw,
        None,
        None,
        &mut sink,
    )
    .unwrap();
    let opened = tzap_core::open_archive(&sink.volumes[0], &master_key).unwrap();
    opened.verify().unwrap();
    assert_eq!(
        opened
            .lookup_index_entry("alpha.bin")
            .unwrap()
            .unwrap()
            .file_data_size,
        b"one physical file".len() as u64
    );
    assert_eq!(
        opened
            .lookup_index_entry("beta.bin")
            .unwrap()
            .unwrap()
            .file_data_size,
        0
    );

    let output = temp.path().join("hardlink-output");
    fs::create_dir(&output).unwrap();
    opened
        .extract_all_to(&output, SafeExtractionOptions::default())
        .unwrap();
    assert_eq!(
        fs::read(output.join("beta.bin")).unwrap(),
        b"one physical file"
    );
    let alpha_file = File::open(output.join("alpha.bin")).unwrap();
    let beta_file = File::open(output.join("beta.bin")).unwrap();
    let mut alpha_identity = input_identity(&alpha_file.metadata().unwrap()).unwrap();
    let mut beta_identity = input_identity(&beta_file.metadata().unwrap()).unwrap();
    augment_windows_input_identity(&mut alpha_identity, &alpha_file).unwrap();
    augment_windows_input_identity(&mut beta_identity, &beta_file).unwrap();
    assert_eq!(alpha_identity.volume_serial, beta_identity.volume_serial);
    assert_eq!(alpha_identity.file_index, beta_identity.file_index);
    assert_eq!(alpha_identity.link_count, 2);
    assert_eq!(beta_identity.link_count, 2);
}
