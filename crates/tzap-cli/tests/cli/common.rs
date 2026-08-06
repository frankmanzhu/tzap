// Shared helpers and fixtures for the tzap CLI integration tests.
// Compiled into both the `tests/cli/main.rs` binary and the `tests/cli_errors.rs` binary;
// not every helper is used by every binary, hence the dead-code allowance.
#![allow(dead_code, unused_imports)]

pub use std::collections::BTreeSet;
pub use std::fs;
pub use std::path::{Path, PathBuf};

pub use assert_cmd::Command;
pub use openssl::asn1::Asn1Time;
pub use openssl::bn::{BigNum, MsbOption};
pub use openssl::hash::MessageDigest;
pub use openssl::pkey::{PKey, PKeyRef, Private};
pub use openssl::rsa::Rsa;
pub use openssl::x509::extension::{BasicConstraints, KeyUsage};
pub use openssl::x509::{X509NameBuilder, X509Ref, X509};
pub use predicates::prelude::*;
pub use serde_json::Value;
pub use tempfile::tempdir;
pub use tzap_core::format::{
    BlockKind, BLOCK_RECORD_FRAMING_LEN, BOOTSTRAP_SIDECAR_HEADER_LEN, FORMAT_VERSION,
    VOLUME_FORMAT_REV_45, VOLUME_HEADER_LEN, VOLUME_TRAILER_LEN,
};
pub use tzap_core::wire::{
    BlockRecord, BootstrapSidecarHeader, CriticalRecoveryLocator, CryptoHeader, VolumeHeader,
    VolumeTrailer,
};
pub use tzap_core::{
    crypto::compute_hmac, write_archive_with_recipient_wrap_records, ArchiveTimestamp, HmacDomain,
    MasterKey, RegularFile, Subkeys, WriterOptions,
};
pub use tzap_plugin_keywrap::{wrap_master_key_for_recipient, ArchiveIdentity, KeyWrapSuite};

pub const KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

pub const BAD_KEY_HEX: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

pub const SIDECAR_HMAC_COVERED_LEN: usize = 92;

#[cfg(unix)]
pub fn expected_input_mode(path: &Path) -> u32 {
    pub use std::os::unix::fs::PermissionsExt;

    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[cfg(not(unix))]
pub fn expected_input_mode(_path: &Path) -> u32 {
    0o644
}

#[cfg(windows)]
pub fn create_windows_relative_symlink(path: &Path, target: &str) {
    pub use std::os::windows::fs::OpenOptionsExt as _;
    pub use std::os::windows::io::AsRawHandle as _;
    pub use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    };
    pub use windows_sys::Win32::System::Ioctl::FSCTL_SET_REPARSE_POINT;
    pub use windows_sys::Win32::System::IO::DeviceIoControl;

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
    // SAFETY: the handle and complete relative-symlink reparse buffer remain
    // live for the synchronous call.
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
    assert_ne!(
        result,
        0,
        "failed to create relative symlink fixture: {}",
        std::io::Error::last_os_error()
    );
}

#[cfg(windows)]
pub fn windows_basic_info(
    path: &Path,
    write: bool,
) -> windows_sys::Win32::Storage::FileSystem::FILE_BASIC_INFO {
    pub use std::os::windows::fs::OpenOptionsExt as _;
    pub use std::os::windows::io::AsRawHandle as _;
    pub use windows_sys::Win32::Storage::FileSystem::{
        FileBasicInfo, GetFileInformationByHandleEx, FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    };

    let mut options = fs::OpenOptions::new();
    options
        .access_mode(if write {
            FILE_GENERIC_READ | FILE_GENERIC_WRITE
        } else {
            FILE_GENERIC_READ
        })
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options.open(path).unwrap();
    let mut info = FILE_BASIC_INFO::default();
    let status = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle().cast(),
            FileBasicInfo,
            (&mut info as *mut FILE_BASIC_INFO).cast(),
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    };
    assert_ne!(
        status,
        0,
        "failed to read basic metadata for {}",
        path.display()
    );
    info
}

#[cfg(windows)]
pub fn set_windows_basic_info(
    path: &Path,
    info: &windows_sys::Win32::Storage::FileSystem::FILE_BASIC_INFO,
) {
    pub use std::os::windows::fs::OpenOptionsExt as _;
    pub use std::os::windows::io::AsRawHandle as _;
    pub use windows_sys::Win32::Storage::FileSystem::{
        FileBasicInfo, SetFileInformationByHandle, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    };

    let file = fs::OpenOptions::new()
        .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .unwrap();
    let status = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle().cast(),
            FileBasicInfo,
            (info as *const windows_sys::Win32::Storage::FileSystem::FILE_BASIC_INFO).cast(),
            std::mem::size_of::<windows_sys::Win32::Storage::FileSystem::FILE_BASIC_INFO>() as u32,
        )
    };
    assert_ne!(
        status,
        0,
        "failed to set basic metadata for {}",
        path.display()
    );
}

#[cfg(windows)]
pub fn windows_process_is_elevated() -> bool {
    pub use std::mem::size_of;
    pub use windows_sys::Win32::Foundation::CloseHandle;
    pub use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    pub use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = std::ptr::null_mut();
    // SAFETY: the pseudo process handle is valid, and `token` receives one
    // owned handle which is closed below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return false;
    }
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0u32;
    // SAFETY: `token` is live and `elevation` is a correctly sized writable
    // output buffer for TokenElevation.
    let result = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    };
    // SAFETY: `token` is owned by this function and closed exactly once.
    unsafe {
        CloseHandle(token);
    }
    result != 0 && elevation.TokenIsElevated != 0
}

#[derive(Clone)]
pub struct PayloadRecordLocation {
    volume_index: usize,
    payload_offset: usize,
    block_size: usize,
    block_index: u64,
}

pub fn master_key_from_hex(hex: &str) -> Vec<u8> {
    let mut out = [0u8; 32];
    for (idx, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        out[idx] = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    out.to_vec()
}

pub fn numbered_volume_path(output_base: &Path, index: usize) -> PathBuf {
    let file_name = output_base.file_name().unwrap().to_string_lossy();
    let base = file_name.strip_suffix(".tzap").unwrap_or(&file_name);
    output_base.with_file_name(format!("{base}.vol{index:03}.tzap"))
}

pub fn tar_stream(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (path, data) in entries {
        out.extend_from_slice(&tar_header(path.as_bytes(), b'0', data.len() as u64));
        out.extend_from_slice(data);
        out.resize(out.len() + padding_to_512(data.len()), 0);
    }
    out.extend_from_slice(&[0u8; 1024]);
    out
}

pub fn tar_header(path: &[u8], kind: u8, size: u64) -> [u8; 512] {
    let mut header = [0u8; 512];
    header[..path.len()].copy_from_slice(path);
    write_tar_octal(&mut header[100..108], 0o644);
    write_tar_octal(&mut header[108..116], 0);
    write_tar_octal(&mut header[116..124], 0);
    write_tar_octal(&mut header[124..136], size);
    write_tar_octal(&mut header[136..148], 0);
    header[148..156].fill(b' ');
    header[156] = kind;
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum = header.iter().map(|byte| *byte as u64).sum::<u64>();
    write_tar_checksum(&mut header[148..156], checksum);
    header
}

pub fn write_tar_octal(field: &mut [u8], value: u64) {
    let digits = format!("{value:o}");
    field.fill(0);
    let start = field.len() - 1 - digits.len();
    field[..start].fill(b'0');
    field[start..start + digits.len()].copy_from_slice(digits.as_bytes());
}

pub fn write_tar_checksum(field: &mut [u8], value: u64) {
    let digits = format!("{value:06o}");
    field[0..6].copy_from_slice(digits.as_bytes());
    field[6] = 0;
    field[7] = b' ';
}

pub fn padding_to_512(len: usize) -> usize {
    let remainder = len % 512;
    if remainder == 0 {
        0
    } else {
        512 - remainder
    }
}

pub fn payload_data_record_locations(volume_index: usize, volume: &[u8]) -> Vec<PayloadRecordLocation> {
    let volume_header = VolumeHeader::parse(&volume[..VOLUME_HEADER_LEN]).unwrap();
    let crypto_start = volume_header.crypto_header_offset as usize;
    let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
    let crypto_header = CryptoHeader::parse(
        &volume[crypto_start..crypto_end],
        volume_header.crypto_header_length,
    )
    .unwrap();
    let block_size = crypto_header.fixed.block_size as usize;
    let record_len = block_size + BLOCK_RECORD_FRAMING_LEN;
    let locator = CriticalRecoveryLocator::parse(&volume[volume.len() - 128..]).unwrap();
    let trailer_offset = locator.volume_trailer_offset as usize;
    let trailer =
        VolumeTrailer::parse(&volume[trailer_offset..trailer_offset + VOLUME_TRAILER_LEN]).unwrap();
    let manifest_offset = trailer.manifest_footer_offset as usize;
    assert_eq!((manifest_offset - crypto_end) % record_len, 0);

    (crypto_end..manifest_offset)
        .step_by(record_len)
        .filter_map(|offset| {
            let record =
                BlockRecord::parse(&volume[offset..offset + record_len], block_size).unwrap();
            (record.kind == BlockKind::PayloadData).then_some(PayloadRecordLocation {
                volume_index,
                payload_offset: offset + 16,
                block_size,
                block_index: record.block_index,
            })
        })
        .collect()
}

pub fn corrupt_first_record_of_kind(volume: &mut [u8], kind: BlockKind) {
    let volume_header = VolumeHeader::parse(&volume[..VOLUME_HEADER_LEN]).unwrap();
    let crypto_start = volume_header.crypto_header_offset as usize;
    let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
    let crypto_header = CryptoHeader::parse(
        &volume[crypto_start..crypto_end],
        volume_header.crypto_header_length,
    )
    .unwrap();
    let block_size = crypto_header.fixed.block_size as usize;
    let record_len = block_size + BLOCK_RECORD_FRAMING_LEN;
    let locator = CriticalRecoveryLocator::parse(&volume[volume.len() - 128..]).unwrap();
    let trailer_offset = locator.volume_trailer_offset as usize;
    let trailer =
        VolumeTrailer::parse(&volume[trailer_offset..trailer_offset + VOLUME_TRAILER_LEN]).unwrap();
    let manifest_offset = trailer.manifest_footer_offset as usize;

    for offset in (crypto_end..manifest_offset).step_by(record_len) {
        let mut record =
            BlockRecord::parse(&volume[offset..offset + record_len], block_size).unwrap();
        if record.kind == kind {
            record.payload[0] ^= 0x55;
            volume[offset..offset + record_len].copy_from_slice(&record.to_bytes());
            return;
        }
    }
    panic!("no {kind:?} record found to corrupt");
}

pub fn corrupt_first_record_payload_crc_of_kind(volume: &mut [u8], kind: BlockKind) {
    let volume_header = VolumeHeader::parse(&volume[..VOLUME_HEADER_LEN]).unwrap();
    let crypto_start = volume_header.crypto_header_offset as usize;
    let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
    let crypto_header = CryptoHeader::parse(
        &volume[crypto_start..crypto_end],
        volume_header.crypto_header_length,
    )
    .unwrap();
    let block_size = crypto_header.fixed.block_size as usize;
    let record_len = block_size + BLOCK_RECORD_FRAMING_LEN;
    let locator = CriticalRecoveryLocator::parse(&volume[volume.len() - 128..]).unwrap();
    let trailer_offset = locator.volume_trailer_offset as usize;
    let trailer =
        VolumeTrailer::parse(&volume[trailer_offset..trailer_offset + VOLUME_TRAILER_LEN]).unwrap();
    let manifest_offset = trailer.manifest_footer_offset as usize;

    for offset in (crypto_end..manifest_offset).step_by(record_len) {
        let record = BlockRecord::parse(&volume[offset..offset + record_len], block_size).unwrap();
        if record.kind == kind {
            volume[offset + 16] ^= 0x55;
            return;
        }
    }
    panic!("no {kind:?} record found to corrupt");
}

pub fn corrupt_first_record_magic_of_kind(volume: &mut [u8], kind: BlockKind) {
    let volume_header = VolumeHeader::parse(&volume[..VOLUME_HEADER_LEN]).unwrap();
    let crypto_start = volume_header.crypto_header_offset as usize;
    let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
    let crypto_header = CryptoHeader::parse(
        &volume[crypto_start..crypto_end],
        volume_header.crypto_header_length,
    )
    .unwrap();
    let block_size = crypto_header.fixed.block_size as usize;
    let record_len = block_size + BLOCK_RECORD_FRAMING_LEN;
    let locator = CriticalRecoveryLocator::parse(&volume[volume.len() - 128..]).unwrap();
    let trailer_offset = locator.volume_trailer_offset as usize;
    let trailer =
        VolumeTrailer::parse(&volume[trailer_offset..trailer_offset + VOLUME_TRAILER_LEN]).unwrap();
    let manifest_offset = trailer.manifest_footer_offset as usize;

    for offset in (crypto_end..manifest_offset).step_by(record_len) {
        let record = BlockRecord::parse(&volume[offset..offset + record_len], block_size).unwrap();
        if record.kind == kind {
            volume[offset] ^= 0x55;
            return;
        }
    }
    panic!("no {kind:?} record found to corrupt");
}

pub fn zero_deterministic_payload_blocks(
    volume_paths: &[PathBuf],
    corruption_pct: usize,
) -> (usize, usize) {
    let mut volumes = volume_paths
        .iter()
        .map(|path| fs::read(path).unwrap())
        .collect::<Vec<_>>();
    let mut locations = volumes
        .iter()
        .enumerate()
        .flat_map(|(volume_index, volume)| payload_data_record_locations(volume_index, volume))
        .collect::<Vec<_>>();
    locations.sort_by_key(|location| location.block_index);
    assert!(
        locations.len() >= 50,
        "test archive should have enough payload blocks for a meaningful percent corruption"
    );

    let corrupt_count = locations.len() * corruption_pct / 100;
    assert!(
        corrupt_count > 0,
        "corruption percent should select at least one payload block"
    );

    let mut selected = BTreeSet::new();
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    while selected.len() < corrupt_count {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        selected.insert((state as usize) % locations.len());
    }

    for index in selected {
        let location = &locations[index];
        volumes[location.volume_index]
            [location.payload_offset..location.payload_offset + location.block_size]
            .fill(0);
    }

    for (path, bytes) in volume_paths.iter().zip(volumes) {
        fs::write(path, bytes).unwrap();
    }

    (corrupt_count, locations.len())
}

pub fn assert_no_archive_stream_claims(help: &str) {
    let lower = help.to_lowercase();
    for phrase in [
        "archive stdin",
        "archive from stdin",
        "read archive from stdin",
        "stdin archive",
        "pipe archive",
        "archive stdout",
        "create to stdout",
    ] {
        assert!(
            !lower.contains(phrase),
            "help text should not claim unsupported archive streaming via {phrase:?}"
        );
    }
}

pub fn create_dash_boundary_archive(temp: &Path) -> (PathBuf, PathBuf, Vec<u8>) {
    let keyfile = temp.join("key.hex");
    let input = temp.join("hello.txt");
    let archive = temp.join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello from dash archive\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();

    let archive_bytes = fs::read(&archive).unwrap();
    (keyfile, archive, archive_bytes)
}

pub fn create_plaintext_dash_archive(temp: &Path) -> (PathBuf, Vec<u8>) {
    let input = temp.join("plain.txt");
    let archive = temp.join("plain.tzap");

    fs::write(&input, b"hello plaintext stdin\n").unwrap();
    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--no-encryption",
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();

    (archive.clone(), fs::read(archive).unwrap())
}

pub fn is_lower_hex_byte(byte: u8) -> bool {
    matches!(byte, b'0'..=b'9' | b'a'..=b'f')
}

pub fn is_lower_hex_str(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn test_ca_cert(cn: &str) -> (X509, PKey<Private>) {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", cn).unwrap();
    let name = name.build();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_serial_number(&random_serial_number()).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();
    builder
        .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .unwrap(),
        )
        .unwrap();
    builder.sign(&key, MessageDigest::sha256()).unwrap();
    (builder.build(), key)
}

pub fn test_leaf_cert(cn: &str, ca_cert: &X509Ref, ca_key: &PKeyRef<Private>) -> (X509, PKey<Private>) {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", cn).unwrap();
    let name = name.build();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_serial_number(&random_serial_number()).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(ca_cert.subject_name()).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();
    builder
        .append_extension(BasicConstraints::new().build().unwrap())
        .unwrap();
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .build()
                .unwrap(),
        )
        .unwrap();
    builder.sign(ca_key, MessageDigest::sha256()).unwrap();
    (builder.build(), key)
}

pub fn test_x25519_recipient_cert() -> (X509, Vec<u8>) {
    let subject_key = PKey::generate_x25519().unwrap();
    let signer_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "Tzap Recipient").unwrap();
    let name = name.build();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_serial_number(&random_serial_number()).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&subject_key).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();
    builder
        .append_extension(BasicConstraints::new().build().unwrap())
        .unwrap();
    builder
        .append_extension(KeyUsage::new().critical().key_agreement().build().unwrap())
        .unwrap();
    builder.sign(&signer_key, MessageDigest::sha256()).unwrap();
    (builder.build(), subject_key.raw_private_key().unwrap())
}

pub fn random_serial_number() -> openssl::asn1::Asn1Integer {
    let mut serial = BigNum::new().unwrap();
    serial.rand(159, MsbOption::MAYBE_ZERO, false).unwrap();
    serial.to_asn1_integer().unwrap()
}
