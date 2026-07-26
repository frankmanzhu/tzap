use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, PKeyRef, Private};
use openssl::rsa::Rsa;
use openssl::x509::extension::{BasicConstraints, KeyUsage};
use openssl::x509::{X509NameBuilder, X509Ref, X509};
use predicates::prelude::*;
use serde_json::Value;
use tempfile::tempdir;
use tzap_core::format::{
    BlockKind, BLOCK_RECORD_FRAMING_LEN, BOOTSTRAP_SIDECAR_HEADER_LEN, FORMAT_VERSION,
    VOLUME_FORMAT_REV_45, VOLUME_HEADER_LEN, VOLUME_TRAILER_LEN,
};
use tzap_core::wire::{
    BlockRecord, BootstrapSidecarHeader, CriticalRecoveryLocator, CryptoHeader, VolumeHeader,
    VolumeTrailer,
};
use tzap_core::{
    crypto::compute_hmac, write_archive_with_recipient_wrap_records, ArchiveTimestamp, HmacDomain,
    MasterKey, RegularFile, Subkeys, WriterOptions,
};
use tzap_plugin_keywrap::{wrap_master_key_for_recipient, ArchiveIdentity, KeyWrapSuite};

const KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const BAD_KEY_HEX: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const SIDECAR_HMAC_COVERED_LEN: usize = 92;

#[cfg(unix)]
fn expected_input_mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;

    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn expected_input_mode(_path: &Path) -> u32 {
    0o644
}

#[derive(Clone)]
struct PayloadRecordLocation {
    volume_index: usize,
    payload_offset: usize,
    block_size: usize,
    block_index: u64,
}

fn master_key_from_hex(hex: &str) -> Vec<u8> {
    let mut out = [0u8; 32];
    for (idx, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        out[idx] = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    out.to_vec()
}

fn numbered_volume_path(output_base: &Path, index: usize) -> PathBuf {
    let file_name = output_base.file_name().unwrap().to_string_lossy();
    let base = file_name.strip_suffix(".tzap").unwrap_or(&file_name);
    output_base.with_file_name(format!("{base}.vol{index:03}.tzap"))
}

fn tar_stream(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (path, data) in entries {
        out.extend_from_slice(&tar_header(path.as_bytes(), b'0', data.len() as u64));
        out.extend_from_slice(data);
        out.resize(out.len() + padding_to_512(data.len()), 0);
    }
    out.extend_from_slice(&[0u8; 1024]);
    out
}

fn tar_header(path: &[u8], kind: u8, size: u64) -> [u8; 512] {
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

fn write_tar_octal(field: &mut [u8], value: u64) {
    let digits = format!("{value:o}");
    field.fill(0);
    let start = field.len() - 1 - digits.len();
    field[..start].fill(b'0');
    field[start..start + digits.len()].copy_from_slice(digits.as_bytes());
}

fn write_tar_checksum(field: &mut [u8], value: u64) {
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

fn payload_data_record_locations(volume_index: usize, volume: &[u8]) -> Vec<PayloadRecordLocation> {
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

fn corrupt_first_record_of_kind(volume: &mut [u8], kind: BlockKind) {
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

fn corrupt_first_record_payload_crc_of_kind(volume: &mut [u8], kind: BlockKind) {
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

fn corrupt_first_record_magic_of_kind(volume: &mut [u8], kind: BlockKind) {
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

fn zero_deterministic_payload_blocks(
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

fn assert_no_archive_stream_claims(help: &str) {
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

#[test]
fn cli_subcommand_help_paths_are_available() {
    for command in [
        "create",
        "extract",
        "list",
        "verify",
        "keygen",
        "signing-keygen",
    ] {
        Command::cargo_bin("tzap")
            .unwrap()
            .args([command, "--help"])
            .assert()
            .success();
    }
}

#[test]
fn cli_aliases_for_command_shorthands_are_not_enabled() {
    Command::cargo_bin("tzap")
        .unwrap()
        .arg("c")
        .assert()
        .failure()
        .stderr(predicate::str::contains("error:"));

    Command::cargo_bin("tzap")
        .unwrap()
        .arg("x")
        .assert()
        .failure()
        .stderr(predicate::str::contains("error:"));
}

#[test]
fn cli_top_level_help_contains_product_description_and_commands() {
    Command::cargo_bin("tzap")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Create, list, verify, and extract v45 archives",
        ))
        .stdout(predicate::str::contains("create"))
        .stdout(predicate::str::contains("extract"))
        .stdout(predicate::str::contains("list"))
        .stdout(predicate::str::contains("verify"))
        .stdout(predicate::str::contains("keygen"))
        .stdout(predicate::str::contains("signing-keygen"))
        .stdout(predicate::str::contains("--public-no-key"))
        .stdout(predicate::str::contains("K/KB/KiB"))
        .stdout(predicate::str::contains("Exit codes"));
}

#[test]
fn cli_help_does_not_advertise_archive_stdin_or_create_stdout() {
    let output = Command::cargo_bin("tzap")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_no_archive_stream_claims(&String::from_utf8_lossy(&output));

    for command in ["create", "extract", "list", "verify"] {
        let output = Command::cargo_bin("tzap")
            .unwrap()
            .args([command, "--help"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let help = String::from_utf8_lossy(&output);
        assert_no_archive_stream_claims(&help);
        match command {
            "create" => assert!(help.contains("single-volume output only")),
            "extract" | "list" | "verify" => {
                assert!(help.contains("single-volume archive input"));
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn cli_jobs_must_be_at_least_one() {
    let temp = tempdir().unwrap();
    let archive = temp.path().join("sample.tzap");
    let output = temp.path().join("out.tzap");
    let input = temp.path().join("input.txt");
    let directory = temp.path().join("extract");

    for args in [
        vec![
            "create",
            "--no-encryption",
            "--jobs",
            "0",
            "-o",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ],
        vec![
            "extract",
            "--jobs",
            "0",
            "--directory",
            directory.to_str().unwrap(),
            archive.to_str().unwrap(),
        ],
        vec!["list", "--jobs", "0", archive.to_str().unwrap()],
        vec!["verify", "--jobs", "0", archive.to_str().unwrap()],
    ] {
        Command::cargo_bin("tzap")
            .unwrap()
            .args(args)
            .assert()
            .code(2)
            .stderr(predicate::str::contains("--jobs must be at least 1"));
    }
}

#[test]
fn cli_create_help_includes_examples_and_flags() {
    let output = Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "--help"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8_lossy(&output);

    assert!(stdout.contains("Create a new archive"));
    assert!(stdout.contains("Examples:"));
    assert!(stdout.contains("--output <ARCHIVE>"));
    assert!(stdout.contains("--volumes <COUNT>"));
    assert!(stdout.contains("--volume-size <SIZE>"));
    assert!(stdout.contains("--volume-loss-tolerance <COUNT>"));
    assert!(stdout.contains("--bit-rot-buffer-pct <PERCENT>"));
    assert!(stdout.contains("--password"));
    assert!(stdout.contains("--password-stdin"));
    assert!(stdout.contains("--keyfile <KEYFILE>"));
    assert!(stdout.contains("--recipient-cert <FILE>"));
    assert!(stdout.contains("--no-encryption"));
    assert!(!stdout.contains("--insecure-zero-key"));
    assert!(stdout.contains("--argon2-t-cost <COUNT>"));
    assert!(stdout.contains("--argon2-m-cost-kib <KIB>"));
    assert!(stdout.contains("--argon2-parallelism <COUNT>"));
    assert!(stdout.contains("--dictionary <FILE>"));
    assert!(stdout.contains("--signing-key <FILE>"));
    assert!(stdout.contains("--signing-cert <FILE>"));
    assert!(stdout.contains("--signing-private-key <FILE>"));
    assert!(stdout.contains("--signing-chain <FILE>"));
    assert!(stdout.contains("--x509-signature-scheme <SCHEME>"));
    assert!(stdout.contains("--bootstrap-out <FILE>"));
    assert!(stdout.contains("--tar-stdin"));
    assert!(stdout.contains("--raw-stdin"));
    assert!(stdout.contains("--stdin-name <PATH>"));
    assert!(stdout.contains("--stdin-size <SIZE>"));
    assert!(stdout.contains("--spool-stdin"));
    assert!(stdout.contains("--compression-level <LEVEL>"));
    assert!(stdout.contains("--chunk-size <SIZE>"));
    assert!(stdout.contains("--envelope-size <SIZE>"));
    assert!(stdout.contains("--block-size <SIZE>"));
    assert!(stdout.contains("--jobs <N>"));
    assert!(stdout.contains("--timings"));
    assert!(stdout.contains("--force"));
    assert!(stdout.contains("--dry-run"));
    assert!(stdout.contains("tar cf -"));
    assert!(!stdout.contains("producer | tzap create --raw-stdin"));
}

#[test]
fn cli_extract_help_includes_examples_and_flags() {
    let output = Command::cargo_bin("tzap")
        .unwrap()
        .args(["extract", "--help"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8_lossy(&output);

    assert!(stdout.contains("Extract one or many archive members"));
    assert!(stdout.contains("Examples:"));
    assert!(stdout.contains("--directory"));
    assert!(stdout.contains("--stdout"));
    assert!(stdout.contains("--dry-run"));
    assert!(stdout.contains("--overwrite"));
    assert!(stdout.contains("--password"));
    assert!(stdout.contains("--bootstrap"));
    assert!(stdout.contains("--volume"));
    assert!(stdout.contains("--jobs <N>"));
    assert!(stdout.contains("--password-stdin"));
    assert!(stdout.contains("--keyfile <KEYFILE>"));
    assert!(stdout.contains("--recipient-key <FILE>"));
    assert!(!stdout.contains("--insecure-zero-key"));
}

#[test]
fn cli_list_help_includes_examples_and_flags() {
    let output = Command::cargo_bin("tzap")
        .unwrap()
        .args(["list", "--help"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8_lossy(&output);

    assert!(stdout.contains("List archive members in plain format"));
    assert!(stdout.contains("Examples:"));
    assert!(stdout.contains("--password"));
    assert!(stdout.contains("--password-stdin"));
    assert!(stdout.contains("--keyfile <KEYFILE>"));
    assert!(stdout.contains("--recipient-key <FILE>"));
    assert!(!stdout.contains("--insecure-zero-key"));
    assert!(stdout.contains("--bootstrap"));
    assert!(stdout.contains("--volume"));
    assert!(stdout.contains("--long"));
    assert!(stdout.contains("--json"));
    assert!(stdout.contains("--jobs <N>"));
}

#[test]
fn cli_verify_help_includes_examples_and_flags() {
    let output = Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", "--help"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8_lossy(&output);

    assert!(stdout.contains("Verify archive signatures"));
    assert!(stdout.contains("Examples:"));
    assert!(stdout.contains("--password"));
    assert!(stdout.contains("--password-stdin"));
    assert!(stdout.contains("--keyfile <KEYFILE>"));
    assert!(stdout.contains("--recipient-key <FILE>"));
    assert!(!stdout.contains("--insecure-zero-key"));
    assert!(stdout.contains("--trusted-public-key <FILE>"));
    assert!(stdout.contains("--trusted-ca-cert <FILE>"));
    assert!(stdout.contains("--trusted-system-roots"));
    assert!(stdout.contains("--public-no-key"));
    assert!(stdout.contains("--fast"));
    assert!(stdout.contains("--bootstrap"));
    assert!(stdout.contains("--json"));
    assert!(stdout.contains("--jobs <N>"));
    assert!(stdout.contains("--quiet"));
    assert!(stdout.contains("For multi-volume archives"));
}

#[test]
fn cli_keygen_help_includes_output_and_force_flags() {
    let output = Command::cargo_bin("tzap")
        .unwrap()
        .args(["keygen", "--help"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8_lossy(&output);

    assert!(stdout.contains("Generate a random 32-byte raw key"));
    assert!(stdout.contains("--output <KEYFILE>"));
    assert!(stdout.contains("--stdout"));
    assert!(stdout.contains("--force"));
}

#[test]
fn cli_signing_keygen_help_includes_keypair_outputs() {
    let output = Command::cargo_bin("tzap")
        .unwrap()
        .args(["signing-keygen", "--help"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8_lossy(&output);

    assert!(stdout.contains("Generate an Ed25519 RootAuth signing keypair"));
    assert!(stdout.contains("--secret-output <FILE>"));
    assert!(stdout.contains("--public-output <FILE>"));
    assert!(stdout.contains("--force"));
}

#[test]
fn cli_trust_info_reports_embedded_official_root() {
    Command::cargo_bin("tzap")
        .unwrap()
        .args(["trust-info"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("official-tzap-root-source: embedded").and(
                predicate::str::contains(
                    "official-tzap-root-sha256: sha256:d80d318f6cd6096dc791e314ec6f41434caa47feb75e85ad6f87d5bf72bbd53d",
                ),
            ),
        );

    let output = Command::cargo_bin("tzap")
        .unwrap()
        .args(["trust-info", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(
        value["official_tzap_root_certificate_sha256"],
        "sha256:d80d318f6cd6096dc791e314ec6f41434caa47feb75e85ad6f87d5bf72bbd53d"
    );
    assert_eq!(value["official_tzap_root_source"], "embedded");
}

#[test]
fn cli_create_requires_key_source_before_running() {
    let temp = tempdir().unwrap();
    let output = temp.path().join("sample.tzap");
    let input = temp.path().join("hello.txt");

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "-o",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("no key source provided"));
}

#[test]
fn cli_insecure_zero_key_is_removed() {
    let temp = tempdir().unwrap();
    let output = temp.path().join("sample.tzap");
    let input = temp.path().join("hello.txt");

    fs::write(&input, b"hello\n").unwrap();
    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--insecure-zero-key",
            "-o",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--insecure-zero-key was removed"));
}

#[test]
fn cli_create_requires_exactly_one_key_source() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let output = temp.path().join("sample.tzap");
    let input = temp.path().join("hello.txt");

    fs::write(&keyfile, KEY_HEX).unwrap();
    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--password-stdin",
            "-o",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn cli_create_rejects_conflicting_volume_flags() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let output = temp.path().join("sample.tzap");
    let input = temp.path().join("hello.txt");

    fs::write(&keyfile, KEY_HEX).unwrap();
    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--volumes",
            "2",
            "--volume-size",
            "1M",
            "-o",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn cli_create_rejects_password_source_conflicts() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let output = temp.path().join("sample.tzap");
    let input = temp.path().join("hello.txt");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello from tzap\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--password",
            "--password-stdin",
            "-o",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn cli_create_timings_prints_breakdown() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let output = temp.path().join("sample.tzap");
    let input = temp.path().join("hello.txt");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello from tzap\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--timings",
            "-o",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(
            predicate::str::contains("create timings:")
                .and(predicate::str::contains("writer timings:"))
                .and(predicate::str::contains("core writer + archive output:"))
                .and(predicate::str::contains("post-writer outputs:"))
                .and(predicate::str::contains("plan payload:"))
                .and(predicate::str::contains("emit payload:")),
        );
}

#[test]
fn cli_no_encryption_rejects_mixed_key_sources_and_public_no_key_rejects_keys() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let output = temp.path().join("sample.tzap");
    let input = temp.path().join("hello.txt");
    let public_key = temp.path().join("root.public.hex");
    let missing_archive = temp.path().join("missing.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello from tzap\n").unwrap();
    fs::write(&public_key, "00".repeat(32)).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--no-encryption",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--public-no-key",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--trusted-public-key",
            public_key.to_str().unwrap(),
            missing_archive.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "--public-no-key cannot be combined",
        ))
        .stderr(predicate::str::contains("--keyfile"));
}

#[test]
fn cli_verify_fast_plaintext_zero_recovery_reports_payload_semantics_deferred() {
    let temp = tempdir().unwrap();
    let output = temp.path().join("fast-plaintext.tzap");
    let input = temp.path().join("fast-plaintext.txt");
    fs::write(&input, b"fast plaintext zero recovery payload\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--no-encryption",
            "--bit-rot-buffer-pct",
            "0",
            "-o",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", "--fast", output.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("OK fast"))
        .stdout(predicate::str::contains("payload_semantics_deferred"));
}

#[test]
fn cli_verify_fast_reports_distinct_stdout_and_json() {
    let temp = tempdir().unwrap();
    let output = temp.path().join("fast.tzap");
    let input = temp.path().join("fast.txt");

    fs::write(&input, b"fast verify payload\n").unwrap();
    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--no-encryption",
            "--bit-rot-buffer-pct",
            "0",
            "-o",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", "--fast", output.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("OK fast"))
        .stdout(predicate::str::contains("root-auth: OK").not());

    let json_output = Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", "--json", "--fast", output.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&json_output).unwrap();
    assert_eq!(value.get("ok").unwrap().as_bool(), Some(true));
    assert_eq!(
        value.get("verification_mode").unwrap().as_str(),
        Some("fast")
    );
    assert_eq!(value.get("file_count").unwrap().as_u64(), Some(1));
    assert!(value
        .get("diagnostics")
        .and_then(|diagnostics| diagnostics.as_array())
        .unwrap()
        .iter()
        .any(|diagnostic| diagnostic.as_str() == Some("payload_semantics_deferred")));
    assert!(value.get("root_auth").is_none());
}

#[test]
fn cli_verify_fast_signed_archive_reports_root_auth_deferred() {
    let temp = tempdir().unwrap();
    let signing_secret = temp.path().join("root.signing.hex");
    let signing_public = temp.path().join("root.public.hex");
    let output = temp.path().join("signed-fast.tzap");
    let input = temp.path().join("signed-fast.txt");

    fs::write(&input, b"signed fast payload\n").unwrap();
    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "signing-keygen",
            "--secret-output",
            signing_secret.to_str().unwrap(),
            "--public-output",
            signing_public.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--no-encryption",
            "--signing-key",
            signing_secret.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();

    let stdout = Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", "--fast", output.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8_lossy(&stdout);
    assert!(stdout.contains("OK fast"));
    assert!(stdout.contains("root_auth_deferred_full_archive_scan_required"));
    assert!(!stdout.contains("root-auth: OK"));
}

#[test]
fn cli_verify_fast_rejects_archive_stdin() {
    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", "--fast", "-"])
        .write_stdin("")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--fast requires seekable archive paths",
        ));
}

#[test]
fn cli_verify_fast_rejects_full_root_auth_and_repair_options() {
    let temp = tempdir().unwrap();
    let public_key = temp.path().join("root.public.hex");
    let archive = temp.path().join("missing.tzap");

    fs::write(&public_key, "00".repeat(32)).unwrap();

    for args in [
        vec![
            "verify",
            "--fast",
            "--trusted-public-key",
            public_key.to_str().unwrap(),
            archive.to_str().unwrap(),
        ],
        vec![
            "verify",
            "--fast",
            "--public-no-key",
            "--trusted-public-key",
            public_key.to_str().unwrap(),
            archive.to_str().unwrap(),
        ],
        vec![
            "verify",
            "--fast",
            "--write-repaired",
            archive.to_str().unwrap(),
        ],
    ] {
        Command::cargo_bin("tzap")
            .unwrap()
            .args(args)
            .assert()
            .code(2)
            .stderr(predicate::str::contains("--fast cannot be combined"));
    }
}

#[test]
fn cli_create_stdin_modes_reject_incompatible_stdin_consumers() {
    let temp = tempdir().unwrap();
    let output = temp.path().join("stdin.tzap");

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--tar-stdin",
            "--password-stdin",
            "-o",
            output.to_str().unwrap(),
            "-",
        ])
        .assert()
        .code(16)
        .stderr(predicate::str::contains(
            "--password-stdin cannot be used when stdin carries archive payload bytes",
        ));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--tar-stdin",
            "--password",
            "-o",
            output.to_str().unwrap(),
            "-",
        ])
        .write_stdin(tar_stream(&[("payload.txt", b"payload".as_slice())]))
        .assert()
        .code(16)
        .stderr(predicate::str::contains(
            "--password cannot be used when stdin carries archive payload bytes",
        ));
}

#[test]
fn cli_create_stdin_modes_reject_dictionary_before_reading_it() {
    let temp = tempdir().unwrap();
    let output = temp.path().join("stdin.tzap");

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--tar-stdin",
            "--keyfile",
            "missing-key.hex",
            "--dictionary",
            "missing-dictionary.zstd",
            "-o",
            output.to_str().unwrap(),
            "-",
        ])
        .assert()
        .code(16)
        .stderr(predicate::str::contains(
            "--dictionary is not supported with stdin create modes",
        ));
}

#[test]
fn cli_create_stdin_modes_reject_volume_size_and_stdout_output() {
    let temp = tempdir().unwrap();
    let output = temp.path().join("stdin.tzap");

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--raw-stdin",
            "--stdin-name",
            "data.bin",
            "--keyfile",
            "missing-key.hex",
            "--volume-size",
            "1M",
            "-o",
            output.to_str().unwrap(),
            "-",
        ])
        .assert()
        .code(16)
        .stderr(predicate::str::contains(
            "--volume-size is not supported with stdin create modes",
        ));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--tar-stdin",
            "--keyfile",
            "missing-key.hex",
            "-o",
            "-",
            "-",
        ])
        .assert()
        .code(16)
        .stderr(predicate::str::contains("--output - is not archive stdout"));
}

#[test]
fn cli_create_stdin_modes_reject_unsupported_multi_volume_shapes() {
    let temp = tempdir().unwrap();
    let output = temp.path().join("stdin.tzap");

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--raw-stdin",
            "--stdin-name",
            "data.bin",
            "--volumes",
            "2",
            "--keyfile",
            "missing-key.hex",
            "-o",
            output.to_str().unwrap(),
            "-",
        ])
        .assert()
        .code(16)
        .stderr(predicate::str::contains(
            "--volumes > 1 is supported only with --tar-stdin, known-size --raw-stdin, or --raw-stdin --spool-stdin",
        ));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--tar-stdin",
            "--volumes",
            "2",
            "--volume-loss-tolerance",
            "1",
            "--keyfile",
            "missing-key.hex",
            "-o",
            output.to_str().unwrap(),
            "-",
        ])
        .assert()
        .code(16)
        .stderr(predicate::str::contains(
            "--volume-loss-tolerance > 0 is not supported with stdin create modes",
        ));
}

#[test]
fn cli_create_stdin_modes_reject_mixed_ordinary_input_paths() {
    let temp = tempdir().unwrap();
    let output = temp.path().join("stdin.tzap");

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--tar-stdin",
            "--keyfile",
            "missing-key.hex",
            "-o",
            output.to_str().unwrap(),
            "-",
            "ordinary.txt",
        ])
        .assert()
        .code(16)
        .stderr(predicate::str::contains(
            "stdin create modes require exactly one archive input path: -",
        ));
}

#[test]
fn cli_create_raw_stdin_requires_member_name_and_valid_size() {
    let temp = tempdir().unwrap();
    let output = temp.path().join("stdin.tzap");

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--raw-stdin",
            "--keyfile",
            "missing-key.hex",
            "-o",
            output.to_str().unwrap(),
            "-",
        ])
        .assert()
        .code(16)
        .stderr(predicate::str::contains(
            "--raw-stdin requires --stdin-name PATH",
        ));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--raw-stdin",
            "--stdin-name",
            "data.bin",
            "--stdin-size",
            "not-a-size",
            "--keyfile",
            "missing-key.hex",
            "-o",
            output.to_str().unwrap(),
            "-",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid stdin-size"));
}

#[test]
fn cli_create_stdin_modes_reject_conflicting_mode_flags() {
    let temp = tempdir().unwrap();
    let output = temp.path().join("stdin.tzap");

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--tar-stdin",
            "--raw-stdin",
            "--stdin-name",
            "data.bin",
            "--keyfile",
            "missing-key.hex",
            "-o",
            output.to_str().unwrap(),
            "-",
        ])
        .assert()
        .code(16)
        .stderr(predicate::str::contains(
            "--tar-stdin and --raw-stdin cannot be used together",
        ));
}

#[test]
fn cli_create_stdin_modes_reject_raw_adjunct_flags_without_raw_stdin() {
    let temp = tempdir().unwrap();
    let output = temp.path().join("stdin.tzap");

    for (args, expected) in [
        (
            vec!["--stdin-name", "data.bin"],
            "--stdin-name requires --raw-stdin",
        ),
        (
            vec!["--stdin-size", "4K"],
            "--stdin-size requires --raw-stdin",
        ),
        (vec!["--spool-stdin"], "--spool-stdin requires --raw-stdin"),
    ] {
        let mut command_args = vec!["create"];
        command_args.extend(args);
        command_args.extend([
            "--keyfile",
            "missing-key.hex",
            "-o",
            output.to_str().unwrap(),
            "-",
        ]);

        Command::cargo_bin("tzap")
            .unwrap()
            .args(command_args)
            .assert()
            .code(16)
            .stderr(predicate::str::contains(expected));
    }
}

#[test]
fn cli_create_raw_stdin_spool_rejects_known_size() {
    let temp = tempdir().unwrap();
    let output = temp.path().join("stdin.tzap");

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--raw-stdin",
            "--stdin-name",
            "data.bin",
            "--stdin-size",
            "4K",
            "--spool-stdin",
            "--keyfile",
            "missing-key.hex",
            "-o",
            output.to_str().unwrap(),
            "-",
        ])
        .assert()
        .code(16)
        .stderr(predicate::str::contains(
            "--spool-stdin is for unknown-size raw stdin; omit --stdin-size",
        ));
}

#[test]
fn cli_create_tar_stdin_round_trips_list_verify_and_extract() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let output = temp.path().join("stdin.tzap");
    let extract_dir = temp.path().join("extract");
    fs::write(&keyfile, KEY_HEX).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--tar-stdin",
            "--jobs",
            "2",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            "-",
        ])
        .write_stdin(tar_stream(&[
            ("alpha.txt", b"alpha payload".as_slice()),
            ("dir/beta.txt", b"beta payload".as_slice()),
        ]))
        .assert()
        .success()
        .stderr(predicate::str::contains("created 2 member(s)"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--jobs",
            "2",
            "--keyfile",
            keyfile.to_str().unwrap(),
            output.to_str().unwrap(),
        ])
        .assert()
        .success();
    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "list",
            "--jobs",
            "2",
            "--keyfile",
            keyfile.to_str().unwrap(),
            output.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("alpha.txt"))
        .stdout(predicate::str::contains("dir/beta.txt"));
    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--jobs",
            "2",
            "--allow-degraded",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-C",
            extract_dir.to_str().unwrap(),
            output.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(extract_dir.join("dir/beta.txt")).unwrap(),
        b"beta payload"
    );
}

#[test]
fn cli_create_tar_stdin_multi_volume_round_trips_list_verify_and_extract() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let output_base = temp.path().join("tar-stdin-mv.tzap");
    let extract_dir = temp.path().join("extract");
    let volume_0 = numbered_volume_path(&output_base, 0);
    let volume_1 = numbered_volume_path(&output_base, 1);
    let volume_2 = numbered_volume_path(&output_base, 2);
    let payload = (0..150_000)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    fs::write(&keyfile, KEY_HEX).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--tar-stdin",
            "--volumes",
            "3",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            output_base.to_str().unwrap(),
            "-",
        ])
        .write_stdin(tar_stream(&[
            ("alpha.txt", b"alpha payload".as_slice()),
            ("dir/beta.bin", payload.as_slice()),
        ]))
        .assert()
        .success()
        .stderr(predicate::str::contains("created 2 member(s)"))
        .stderr(predicate::str::contains("3 volume(s)"));

    assert!(volume_0.exists());
    assert!(volume_1.exists());
    assert!(volume_2.exists());
    assert!(!output_base.exists());

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            keyfile.to_str().unwrap(),
            volume_0.to_str().unwrap(),
            volume_1.to_str().unwrap(),
            volume_2.to_str().unwrap(),
        ])
        .assert()
        .success();
    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "list",
            "--keyfile",
            keyfile.to_str().unwrap(),
            volume_0.to_str().unwrap(),
            "--volume",
            volume_1.to_str().unwrap(),
            "--volume",
            volume_2.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("alpha.txt"))
        .stdout(predicate::str::contains("dir/beta.bin"));
    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--allow-degraded",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-C",
            extract_dir.to_str().unwrap(),
            volume_0.to_str().unwrap(),
            "--volume",
            volume_1.to_str().unwrap(),
            "--volume",
            volume_2.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(fs::read(extract_dir.join("dir/beta.bin")).unwrap(), payload);
}

#[test]
fn cli_create_tar_stdin_multi_volume_signed_archive_verifies_public_root_auth() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let signing_secret = temp.path().join("root.signing.hex");
    let signing_public = temp.path().join("root.public.hex");
    let output_base = temp.path().join("signed-tar-stdin-mv.tzap");
    let volume_0 = numbered_volume_path(&output_base, 0);
    let volume_1 = numbered_volume_path(&output_base, 1);
    let volume_2 = numbered_volume_path(&output_base, 2);
    let payload = (0..150_000)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    fs::write(&keyfile, KEY_HEX).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "signing-keygen",
            "--secret-output",
            signing_secret.to_str().unwrap(),
            "--public-output",
            signing_public.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--tar-stdin",
            "--volumes",
            "3",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--signing-key",
            signing_secret.to_str().unwrap(),
            "-o",
            output_base.to_str().unwrap(),
            "-",
        ])
        .write_stdin(tar_stream(&[("signed/beta.bin", payload.as_slice())]))
        .assert()
        .success()
        .stderr(predicate::str::contains("root auth: ed25519 signed"))
        .stderr(predicate::str::contains("3 volume(s)"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--public-no-key",
            "--trusted-public-key",
            signing_public.to_str().unwrap(),
            volume_0.to_str().unwrap(),
            volume_1.to_str().unwrap(),
            volume_2.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "public_data_block_commitment_verified",
        ));
}

#[test]
fn cli_create_tar_stdin_signed_archive_verifies_public_root_auth() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let signing_secret = temp.path().join("root.signing.hex");
    let signing_public = temp.path().join("root.public.hex");
    let output = temp.path().join("signed-stdin.tzap");
    fs::write(&keyfile, KEY_HEX).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "signing-keygen",
            "--secret-output",
            signing_secret.to_str().unwrap(),
            "--public-output",
            signing_public.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--tar-stdin",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--signing-key",
            signing_secret.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            "-",
        ])
        .write_stdin(tar_stream(&[("signed.txt", b"signed payload".as_slice())]))
        .assert()
        .success()
        .stderr(predicate::str::contains("root auth: ed25519 signed"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--public-no-key",
            "--trusted-public-key",
            signing_public.to_str().unwrap(),
            output.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "public_data_block_commitment_verified",
        ));
}

#[test]
fn cli_create_tar_stdin_late_reject_removes_output_path() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let output = temp.path().join("late-error.tzap");
    fs::write(&keyfile, KEY_HEX).unwrap();
    let mut input = tar_stream(&[("ok.txt", b"ok".as_slice())]);
    input.truncate(input.len() - 1024);
    input.extend_from_slice(&tar_header(b"hardlink", b'1', 0));
    input.extend_from_slice(&[0u8; 1024]);

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--tar-stdin",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            "-",
        ])
        .write_stdin(input)
        .assert()
        .code(16)
        .stderr(predicate::str::contains(
            "streaming tar stdin supports regular files, directories, and symlinks only",
        ));

    assert!(!output.exists());
}

#[test]
fn cli_create_tar_stdin_multi_volume_late_reject_removes_output_paths() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let output_base = temp.path().join("late-error-mv.tzap");
    let volume_0 = numbered_volume_path(&output_base, 0);
    let volume_1 = numbered_volume_path(&output_base, 1);
    let volume_2 = numbered_volume_path(&output_base, 2);
    fs::write(&keyfile, KEY_HEX).unwrap();
    let mut input = tar_stream(&[("ok.txt", b"ok".as_slice())]);
    input.truncate(input.len() - 1024);
    input.extend_from_slice(&tar_header(b"hardlink", b'1', 0));
    input.extend_from_slice(&[0u8; 1024]);

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--tar-stdin",
            "--volumes",
            "3",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            output_base.to_str().unwrap(),
            "-",
        ])
        .write_stdin(input)
        .assert()
        .code(16)
        .stderr(predicate::str::contains(
            "streaming tar stdin supports regular files, directories, and symlinks only",
        ));

    assert!(!output_base.exists());
    assert!(!volume_0.exists());
    assert!(!volume_1.exists());
    assert!(!volume_2.exists());
}

#[test]
fn cli_create_raw_stdin_known_size_round_trips_list_verify_and_extract() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let output = temp.path().join("raw-known.tzap");
    let extract_dir = temp.path().join("extract");
    let payload = b"raw bytes\nfrom stdin\0".to_vec();
    let size = payload.len().to_string();
    fs::write(&keyfile, KEY_HEX).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--raw-stdin",
            "--stdin-name",
            "raw/data.bin",
            "--stdin-size",
            size.as_str(),
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            "-",
        ])
        .write_stdin(payload.clone())
        .assert()
        .success()
        .stderr(predicate::str::contains("created 1 member(s)"))
        .stderr(predicate::str::contains("raw bytes in"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            keyfile.to_str().unwrap(),
            output.to_str().unwrap(),
        ])
        .assert()
        .success();
    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "list",
            "--keyfile",
            keyfile.to_str().unwrap(),
            output.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("raw/data.bin"));
    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-C",
            extract_dir.to_str().unwrap(),
            output.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(fs::read(extract_dir.join("raw/data.bin")).unwrap(), payload);
}

#[test]
fn cli_create_raw_stdin_known_size_multi_volume_round_trips_list_verify_and_extract() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let output_base = temp.path().join("raw-known-mv.tzap");
    let extract_dir = temp.path().join("extract");
    let volume_0 = numbered_volume_path(&output_base, 0);
    let volume_1 = numbered_volume_path(&output_base, 1);
    let volume_2 = numbered_volume_path(&output_base, 2);
    let payload = (0..150_000)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    let size = payload.len().to_string();
    fs::write(&keyfile, KEY_HEX).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--raw-stdin",
            "--stdin-name",
            "raw/data.bin",
            "--stdin-size",
            size.as_str(),
            "--volumes",
            "3",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            output_base.to_str().unwrap(),
            "-",
        ])
        .write_stdin(payload.clone())
        .assert()
        .success()
        .stderr(predicate::str::contains("created 1 member(s)"))
        .stderr(predicate::str::contains("3 volume(s)"));

    assert!(volume_0.exists());
    assert!(volume_1.exists());
    assert!(volume_2.exists());
    assert!(!output_base.exists());

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            keyfile.to_str().unwrap(),
            volume_0.to_str().unwrap(),
            volume_1.to_str().unwrap(),
            volume_2.to_str().unwrap(),
        ])
        .assert()
        .success();
    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "list",
            "--keyfile",
            keyfile.to_str().unwrap(),
            volume_0.to_str().unwrap(),
            "--volume",
            volume_1.to_str().unwrap(),
            "--volume",
            volume_2.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("raw/data.bin"));
    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-C",
            extract_dir.to_str().unwrap(),
            volume_0.to_str().unwrap(),
            "--volume",
            volume_1.to_str().unwrap(),
            "--volume",
            volume_2.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(fs::read(extract_dir.join("raw/data.bin")).unwrap(), payload);
}

#[test]
fn cli_create_raw_stdin_known_size_multi_volume_signed_archive_verifies_public_root_auth() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let signing_secret = temp.path().join("root.signing.hex");
    let signing_public = temp.path().join("root.public.hex");
    let output_base = temp.path().join("raw-signed-mv.tzap");
    let volume_0 = numbered_volume_path(&output_base, 0);
    let volume_1 = numbered_volume_path(&output_base, 1);
    let volume_2 = numbered_volume_path(&output_base, 2);
    let payload = (0..150_000)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    let size = payload.len().to_string();
    fs::write(&keyfile, KEY_HEX).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "signing-keygen",
            "--secret-output",
            signing_secret.to_str().unwrap(),
            "--public-output",
            signing_public.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--raw-stdin",
            "--stdin-name",
            "raw/signed.bin",
            "--stdin-size",
            size.as_str(),
            "--volumes",
            "3",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--signing-key",
            signing_secret.to_str().unwrap(),
            "-o",
            output_base.to_str().unwrap(),
            "-",
        ])
        .write_stdin(payload)
        .assert()
        .success()
        .stderr(predicate::str::contains("root auth: ed25519 signed"))
        .stderr(predicate::str::contains("3 volume(s)"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--public-no-key",
            "--trusted-public-key",
            signing_public.to_str().unwrap(),
            volume_0.to_str().unwrap(),
            volume_1.to_str().unwrap(),
            volume_2.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "public_data_block_commitment_verified",
        ));
}

#[test]
fn cli_create_raw_stdin_known_size_signed_archive_verifies_public_root_auth() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let signing_secret = temp.path().join("root.signing.hex");
    let signing_public = temp.path().join("root.public.hex");
    let output = temp.path().join("raw-signed.tzap");
    let payload = b"signed raw stdin payload".to_vec();
    let size = payload.len().to_string();
    fs::write(&keyfile, KEY_HEX).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "signing-keygen",
            "--secret-output",
            signing_secret.to_str().unwrap(),
            "--public-output",
            signing_public.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--raw-stdin",
            "--stdin-name",
            "raw/signed.bin",
            "--stdin-size",
            size.as_str(),
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--signing-key",
            signing_secret.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            "-",
        ])
        .write_stdin(payload)
        .assert()
        .success()
        .stderr(predicate::str::contains("root auth: ed25519 signed"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--public-no-key",
            "--trusted-public-key",
            signing_public.to_str().unwrap(),
            output.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "public_data_block_commitment_verified",
        ));
}

#[test]
fn cli_create_raw_stdin_spool_round_trips() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let output = temp.path().join("raw-spool.tzap");
    let extract_dir = temp.path().join("extract");
    let payload = b"unknown size raw bytes".to_vec();
    fs::write(&keyfile, KEY_HEX).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--raw-stdin",
            "--stdin-name",
            "spooled.bin",
            "--spool-stdin",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            "-",
        ])
        .write_stdin(payload.clone())
        .assert()
        .success()
        .stderr(predicate::str::contains("spooled raw bytes in"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-C",
            extract_dir.to_str().unwrap(),
            output.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(fs::read(extract_dir.join("spooled.bin")).unwrap(), payload);
}

#[test]
fn cli_create_raw_stdin_spool_multi_volume_round_trips_list_verify_and_extract() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let output_base = temp.path().join("raw-spool-mv.tzap");
    let extract_dir = temp.path().join("extract");
    let volume_0 = numbered_volume_path(&output_base, 0);
    let volume_1 = numbered_volume_path(&output_base, 1);
    let volume_2 = numbered_volume_path(&output_base, 2);
    let payload = (0..150_000)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    fs::write(&keyfile, KEY_HEX).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--raw-stdin",
            "--stdin-name",
            "raw/spooled.bin",
            "--spool-stdin",
            "--volumes",
            "3",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            output_base.to_str().unwrap(),
            "-",
        ])
        .write_stdin(payload.clone())
        .assert()
        .success()
        .stderr(predicate::str::contains("spooled raw bytes in"))
        .stderr(predicate::str::contains("3 volume(s)"));

    assert!(volume_0.exists());
    assert!(volume_1.exists());
    assert!(volume_2.exists());
    assert!(!output_base.exists());

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            keyfile.to_str().unwrap(),
            volume_0.to_str().unwrap(),
            volume_1.to_str().unwrap(),
            volume_2.to_str().unwrap(),
        ])
        .assert()
        .success();
    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "list",
            "--keyfile",
            keyfile.to_str().unwrap(),
            volume_0.to_str().unwrap(),
            "--volume",
            volume_1.to_str().unwrap(),
            "--volume",
            volume_2.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("raw/spooled.bin"));
    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-C",
            extract_dir.to_str().unwrap(),
            volume_0.to_str().unwrap(),
            "--volume",
            volume_1.to_str().unwrap(),
            "--volume",
            volume_2.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(extract_dir.join("raw/spooled.bin")).unwrap(),
        payload
    );
}

#[test]
fn cli_create_raw_stdin_spool_multi_volume_empty_input_round_trips() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let output_base = temp.path().join("raw-spool-empty-mv.tzap");
    let extract_dir = temp.path().join("extract");
    let volume_0 = numbered_volume_path(&output_base, 0);
    let volume_1 = numbered_volume_path(&output_base, 1);
    fs::write(&keyfile, KEY_HEX).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--raw-stdin",
            "--stdin-name",
            "empty.bin",
            "--spool-stdin",
            "--volumes",
            "2",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            output_base.to_str().unwrap(),
            "-",
        ])
        .write_stdin(Vec::<u8>::new())
        .assert()
        .success()
        .stderr(predicate::str::contains("0 spooled raw bytes in"))
        .stderr(predicate::str::contains("2 volume(s)"));

    assert!(volume_0.exists());
    assert!(volume_1.exists());
    assert!(!output_base.exists());

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "list",
            "--keyfile",
            keyfile.to_str().unwrap(),
            volume_0.to_str().unwrap(),
            "--volume",
            volume_1.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("empty.bin"));
    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-C",
            extract_dir.to_str().unwrap(),
            volume_0.to_str().unwrap(),
            "--volume",
            volume_1.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(fs::read(extract_dir.join("empty.bin")).unwrap(), b"");
}

#[test]
fn cli_create_raw_stdin_spool_multi_volume_signed_archive_verifies_public_root_auth() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let signing_secret = temp.path().join("root.signing.hex");
    let signing_public = temp.path().join("root.public.hex");
    let output_base = temp.path().join("raw-spool-signed-mv.tzap");
    let volume_0 = numbered_volume_path(&output_base, 0);
    let volume_1 = numbered_volume_path(&output_base, 1);
    let payload = (0..150_000)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    fs::write(&keyfile, KEY_HEX).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "signing-keygen",
            "--secret-output",
            signing_secret.to_str().unwrap(),
            "--public-output",
            signing_public.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--raw-stdin",
            "--stdin-name",
            "raw/spooled-signed.bin",
            "--spool-stdin",
            "--volumes",
            "2",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--signing-key",
            signing_secret.to_str().unwrap(),
            "-o",
            output_base.to_str().unwrap(),
            "-",
        ])
        .write_stdin(payload)
        .assert()
        .success()
        .stderr(predicate::str::contains("root auth: ed25519 signed"))
        .stderr(predicate::str::contains("2 volume(s)"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--public-no-key",
            "--trusted-public-key",
            signing_public.to_str().unwrap(),
            volume_0.to_str().unwrap(),
            volume_1.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "public_data_block_commitment_verified",
        ));
}

#[test]
fn cli_create_raw_stdin_known_size_mismatch_removes_output_path() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let short_output = temp.path().join("short.tzap");
    let long_output = temp.path().join("long.tzap");
    fs::write(&keyfile, KEY_HEX).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--raw-stdin",
            "--stdin-name",
            "data.bin",
            "--stdin-size",
            "8",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            short_output.to_str().unwrap(),
            "-",
        ])
        .write_stdin(b"short".as_slice())
        .assert()
        .code(3);
    assert!(!short_output.exists());

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--raw-stdin",
            "--stdin-name",
            "data.bin",
            "--stdin-size",
            "3",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            long_output.to_str().unwrap(),
            "-",
        ])
        .write_stdin(b"toolong".as_slice())
        .assert()
        .code(11)
        .stderr(predicate::str::contains(
            "raw stdin exceeds declared --stdin-size",
        ));
    assert!(!long_output.exists());
}

#[test]
fn cli_create_raw_stdin_known_size_multi_volume_mismatch_removes_output_paths() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let short_output = temp.path().join("short-mv.tzap");
    let long_output = temp.path().join("long-mv.tzap");
    let short_volumes = [
        numbered_volume_path(&short_output, 0),
        numbered_volume_path(&short_output, 1),
        numbered_volume_path(&short_output, 2),
    ];
    let long_volumes = [
        numbered_volume_path(&long_output, 0),
        numbered_volume_path(&long_output, 1),
        numbered_volume_path(&long_output, 2),
    ];
    fs::write(&keyfile, KEY_HEX).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--raw-stdin",
            "--stdin-name",
            "data.bin",
            "--stdin-size",
            "8",
            "--volumes",
            "3",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            short_output.to_str().unwrap(),
            "-",
        ])
        .write_stdin(b"short".as_slice())
        .assert()
        .code(3);
    assert!(!short_output.exists());
    assert!(short_volumes.iter().all(|path| !path.exists()));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--raw-stdin",
            "--stdin-name",
            "data.bin",
            "--stdin-size",
            "3",
            "--volumes",
            "3",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            long_output.to_str().unwrap(),
            "-",
        ])
        .write_stdin(b"toolong".as_slice())
        .assert()
        .code(11)
        .stderr(predicate::str::contains(
            "raw stdin exceeds declared --stdin-size",
        ));
    assert!(!long_output.exists());
    assert!(long_volumes.iter().all(|path| !path.exists()));
}

#[test]
fn cli_create_raw_stdin_unknown_no_spool_returns_profile_blocker() {
    let temp = tempdir().unwrap();
    let output = temp.path().join("stdin.tzap");

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--raw-stdin",
            "--stdin-name",
            "data.bin",
            "--keyfile",
            "missing-key.hex",
            "-o",
            output.to_str().unwrap(),
            "-",
        ])
        .assert()
        .code(16)
        .stderr(predicate::str::contains(
            "unknown-size raw stdin without --spool-stdin requires the future raw_stream_v1 profile",
        ));
}

#[test]
fn cli_create_with_interactive_password_requires_matching_confirmation() {
    let temp = tempdir().unwrap();
    let output = temp.path().join("password.tzap");
    let input = temp.path().join("secret.txt");

    fs::write(&input, b"interactive secret\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--password",
            "--argon2-t-cost",
            "1",
            "--argon2-m-cost-kib",
            "8",
            "--argon2-parallelism",
            "1",
            "-o",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .write_stdin("mismatch\nsecret\nsecret\nsecret\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("Passphrases do not match"));
}

#[test]
fn cli_extract_reads_unencrypted_archive_without_key_source() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("sample.txt");
    let archive = temp.path().join("sample.tzap");
    let output = temp.path().join("out");
    fs::write(&input, b"plaintext v45\n").unwrap();

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

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "-C",
            output.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(output.join("sample.txt")).unwrap(),
        b"plaintext v45\n"
    );
}

#[test]
fn cli_list_reads_unencrypted_archive_without_key_source() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("sample.txt");
    let archive = temp.path().join("sample.tzap");
    fs::write(&input, b"plaintext v45\n").unwrap();

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

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["list", archive.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("sample.txt"));
}

#[test]
fn cli_verify_reads_unencrypted_archive_without_key_source() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("sample.txt");
    let archive = temp.path().join("sample.tzap");
    fs::write(&input, b"plaintext v45\n").unwrap();

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

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", archive.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("(1 volume(s), 1 file(s))"));
}

#[test]
fn cli_no_key_does_not_open_encrypted_zero_key_archive() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("zero.key");
    let input = temp.path().join("sample.txt");
    let archive = temp.path().join("sample.tzap");

    fs::write(&keyfile, "00".repeat(32)).unwrap();
    fs::write(&input, b"encrypted zero key\n").unwrap();
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

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["list", archive.to_str().unwrap()])
        .assert()
        .code(10)
        .stderr(predicate::str::contains("wrong-key"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", archive.to_str().unwrap()])
        .assert()
        .code(10)
        .stderr(predicate::str::contains("wrong-key"));
}

#[test]
fn cli_plaintext_header_digest_corruption_is_corrupt_archive_not_wrong_key() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("sample.txt");
    let archive = temp.path().join("sample.tzap");

    fs::write(&input, b"plaintext v45\n").unwrap();
    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--no-encryption",
            "--bit-rot-buffer-pct",
            "0",
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();

    let mut bytes = fs::read(&archive).unwrap();
    let header = VolumeHeader::parse(&bytes[..VOLUME_HEADER_LEN]).unwrap();
    let digest_index =
        header.crypto_header_offset as usize + header.crypto_header_length as usize - 1;
    bytes[digest_index] ^= 0x01;
    fs::write(&archive, bytes).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", archive.to_str().unwrap()])
        .assert()
        .code(11)
        .stderr(predicate::str::contains("corrupt-archive"))
        .stderr(predicate::str::contains("integrity digest"));
}

#[test]
fn cli_verify_key_mode_and_archive_input_are_required() {
    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("required"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", "--keyfile", "key.hex"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("required"));
}

fn create_dash_boundary_archive(temp: &Path) -> (PathBuf, PathBuf, Vec<u8>) {
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

#[test]
fn cli_list_reads_dash_as_archive_stdin() {
    let temp = tempdir().unwrap();
    let (keyfile, _archive, archive_bytes) = create_dash_boundary_archive(temp.path());

    Command::cargo_bin("tzap")
        .unwrap()
        .current_dir(temp.path())
        .args(["list", "--keyfile", keyfile.to_str().unwrap(), "-"])
        .write_stdin(archive_bytes)
        .assert()
        .success()
        .stdout(predicate::str::contains("hello.txt\n"));
}

#[test]
fn cli_extract_reads_dash_as_archive_stdin() {
    let temp = tempdir().unwrap();
    let (keyfile, _archive, archive_bytes) = create_dash_boundary_archive(temp.path());
    let output = temp.path().join("out");

    Command::cargo_bin("tzap")
        .unwrap()
        .current_dir(temp.path())
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--directory",
            output.to_str().unwrap(),
            "-",
        ])
        .write_stdin(archive_bytes)
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "staged non-seekable stream extraction",
        ));

    assert_eq!(
        fs::read(output.join("hello.txt")).unwrap(),
        b"hello from dash archive\n"
    );
}

#[test]
fn cli_verify_reads_dash_as_archive_stdin() {
    let temp = tempdir().unwrap();
    let (keyfile, _archive, archive_bytes) = create_dash_boundary_archive(temp.path());

    Command::cargo_bin("tzap")
        .unwrap()
        .current_dir(temp.path())
        .args(["verify", "--keyfile", keyfile.to_str().unwrap(), "-"])
        .write_stdin(archive_bytes)
        .assert()
        .success()
        .stdout(predicate::str::contains("OK non-seekable stream"));
}

fn create_plaintext_dash_archive(temp: &Path) -> (PathBuf, Vec<u8>) {
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

#[test]
fn cli_unencrypted_archive_stdin_reads_without_key_source() {
    let temp = tempdir().unwrap();
    let (_archive, archive_bytes) = create_plaintext_dash_archive(temp.path());

    Command::cargo_bin("tzap")
        .unwrap()
        .current_dir(temp.path())
        .args(["list", "-"])
        .write_stdin(archive_bytes.clone())
        .assert()
        .success()
        .stdout(predicate::str::contains("plain.txt\n"));

    Command::cargo_bin("tzap")
        .unwrap()
        .current_dir(temp.path())
        .args(["verify", "-"])
        .write_stdin(archive_bytes)
        .assert()
        .success()
        .stdout(predicate::str::contains("OK non-seekable stream"));
}

#[test]
fn cli_encrypted_zero_key_archive_stdin_without_key_is_rejected() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("zero.key");
    let input = temp.path().join("sample.txt");
    let archive = temp.path().join("sample.tzap");

    fs::write(&keyfile, "00".repeat(32)).unwrap();
    fs::write(&input, b"encrypted zero key\n").unwrap();
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

    Command::cargo_bin("tzap")
        .unwrap()
        .current_dir(temp.path())
        .args(["verify", "-"])
        .write_stdin(fs::read(&archive).unwrap())
        .assert()
        .code(10)
        .stderr(predicate::str::contains("wrong-key"));
}

#[test]
fn cli_extract_plaintext_archive_stdin_digest_corruption_is_corrupt_archive() {
    let temp = tempdir().unwrap();
    let (_archive, mut archive_bytes) = create_plaintext_dash_archive(temp.path());
    let output = temp.path().join("out");
    let header = VolumeHeader::parse(&archive_bytes[..VOLUME_HEADER_LEN]).unwrap();
    let digest_index =
        header.crypto_header_offset as usize + header.crypto_header_length as usize - 1;
    archive_bytes[digest_index] ^= 0x01;

    Command::cargo_bin("tzap")
        .unwrap()
        .current_dir(temp.path())
        .args(["extract", "-C", output.to_str().unwrap(), "-"])
        .write_stdin(archive_bytes)
        .assert()
        .code(11)
        .stderr(predicate::str::contains("corrupt-archive"))
        .stderr(predicate::str::contains("integrity digest"));
}

#[test]
fn cli_archive_stdin_uses_bootstrap_sidecar_for_dictionary_archive() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let dictionary = temp.path().join("dictionary.bin");
    let input = temp.path().join("dict.txt");
    let archive = temp.path().join("dict.tzap");
    let bootstrap = temp.path().join("dict.tzap.bootstrap");
    let output = temp.path().join("out");
    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&dictionary, b"common words dictionary").unwrap();
    fs::write(&input, b"common words common words dictionary payload\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--dictionary",
            dictionary.to_str().unwrap(),
            "--bootstrap-out",
            bootstrap.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();
    let archive_bytes = fs::read(&archive).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--bootstrap",
            bootstrap.to_str().unwrap(),
            "-",
        ])
        .write_stdin(archive_bytes.clone())
        .assert()
        .success()
        .stdout(predicate::str::contains("OK non-seekable stream"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "list",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--bootstrap",
            bootstrap.to_str().unwrap(),
            "-",
        ])
        .write_stdin(archive_bytes.clone())
        .assert()
        .success()
        .stdout(predicate::str::contains("dict.txt\n"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--bootstrap",
            bootstrap.to_str().unwrap(),
            "--directory",
            output.to_str().unwrap(),
            "-",
        ])
        .write_stdin(archive_bytes)
        .assert()
        .success();

    assert_eq!(
        fs::read(output.join("dict.txt")).unwrap(),
        b"common words common words dictionary payload\n"
    );
}

#[test]
fn cli_commands_read_real_file_named_dash_with_explicit_relative_path() {
    let temp = tempdir().unwrap();
    let (keyfile, archive, _archive_bytes) = create_dash_boundary_archive(temp.path());
    let dash_archive = temp.path().join("-");
    let output = temp.path().join("out");
    fs::copy(&archive, &dash_archive).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .current_dir(temp.path())
        .args(["list", "--keyfile", keyfile.to_str().unwrap(), "./-"])
        .assert()
        .success()
        .stdout(predicate::str::contains("hello.txt\n"));

    Command::cargo_bin("tzap")
        .unwrap()
        .current_dir(temp.path())
        .args(["verify", "--keyfile", keyfile.to_str().unwrap(), "./-"])
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));

    Command::cargo_bin("tzap")
        .unwrap()
        .current_dir(temp.path())
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--directory",
            output.to_str().unwrap(),
            "./-",
            "hello.txt",
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(output.join("hello.txt")).unwrap(),
        b"hello from dash archive\n"
    );
}

#[test]
fn cli_open_commands_reject_multi_volume_bootstrap_before_archive_reads() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let primary = temp.path().join("missing-primary.vol000.tzap");
    let extra = temp.path().join("missing-primary.vol001.tzap");
    let bootstrap = temp.path().join("missing-primary.tzap.bootstrap");
    let output = temp.path().join("out");
    fs::write(&keyfile, KEY_HEX).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "list",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--bootstrap",
            bootstrap.to_str().unwrap(),
            primary.to_str().unwrap(),
            "--volume",
            extra.to_str().unwrap(),
        ])
        .assert()
        .code(16)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("unsupported-feature"))
        .stderr(predicate::str::contains(
            "multi-volume inputs with --bootstrap are not supported",
        ))
        .stderr(predicate::str::contains("failed to read archive").not());

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--bootstrap",
            bootstrap.to_str().unwrap(),
            "--directory",
            output.to_str().unwrap(),
            primary.to_str().unwrap(),
            "--volume",
            extra.to_str().unwrap(),
            "hello.txt",
        ])
        .assert()
        .code(16)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("unsupported-feature"))
        .stderr(predicate::str::contains(
            "multi-volume inputs with --bootstrap are not supported",
        ))
        .stderr(predicate::str::contains("failed to read archive").not());
    assert!(!output.exists());

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--bootstrap",
            bootstrap.to_str().unwrap(),
            primary.to_str().unwrap(),
            extra.to_str().unwrap(),
        ])
        .assert()
        .code(16)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("unsupported-feature"))
        .stderr(predicate::str::contains(
            "multi-volume inputs with --bootstrap are not supported",
        ))
        .stderr(predicate::str::contains("failed to read archive").not());
}

#[test]
fn cli_verify_json_reports_multi_volume_bootstrap_boundary_before_archive_reads() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let primary = temp.path().join("missing-primary.vol000.tzap");
    let extra = temp.path().join("missing-primary.vol001.tzap");
    let bootstrap = temp.path().join("missing-primary.tzap.bootstrap");
    fs::write(&keyfile, KEY_HEX).unwrap();

    let output = Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--json",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--bootstrap",
            bootstrap.to_str().unwrap(),
            primary.to_str().unwrap(),
            extra.to_str().unwrap(),
        ])
        .assert()
        .code(16)
        .stderr(predicate::str::is_empty())
        .get_output()
        .stdout
        .clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["ok"], false);
    assert_eq!(json["error"]["label"], "unsupported-feature");
    assert!(json["error"]["message"]
        .as_str()
        .unwrap()
        .contains("multi-volume inputs with --bootstrap are not supported"));
}

#[test]
fn cli_verify_one_volume_archive_with_keyfile_reports_summary_with_counts() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello from tzap\n").unwrap();

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

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            keyfile.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("(1 volume(s), 1 file(s))"));
}

#[test]
fn cli_verify_json_success_reports_machine_readable_summary() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello from tzap\n").unwrap();

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

    let output = Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--json",
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output).unwrap();

    assert!(value.get("ok").unwrap().as_bool().unwrap());
    assert_eq!(value.get("volume_count").unwrap().as_u64().unwrap(), 1);
    assert_eq!(value.get("file_count").unwrap().as_u64().unwrap(), 1);
    let archives = value.get("archives").unwrap().as_array().unwrap();
    assert_eq!(archives.len(), 1);
    assert_eq!(archives[0].as_str().unwrap(), archive.to_str().unwrap());
    let metadata = value.get("metadata").unwrap();
    assert!(metadata.get("capture_complete").unwrap().as_bool().unwrap());
    let expected_profiles = if cfg!(target_os = "linux") {
        serde_json::json!(["linux-backup-v1", "portable-v1", "posix-backup-v1"])
    } else if cfg!(target_os = "macos") {
        serde_json::json!(["macos-backup-v1", "portable-v1", "posix-backup-v1"])
    } else if cfg!(windows) {
        serde_json::json!(["portable-v1", "windows-backup-v1"])
    } else {
        serde_json::json!(["portable-v1"])
    };
    assert_eq!(
        metadata.get("profiles_present").unwrap(),
        &expected_profiles
    );
    let metadata_entries = metadata.get("entries").unwrap().as_array().unwrap();
    assert_eq!(metadata_entries.len(), 1);
    assert_eq!(
        metadata_entries[0]
            .get("policy_capabilities")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|capability| capability.get("policy").unwrap().as_str().unwrap())
            .collect::<Vec<_>>(),
        ["content", "portable", "same-os", "system"]
    );
}

#[test]
fn cli_verify_write_repaired_writes_sibling_for_crc_erased_payload_block() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("payload.bin");
    let archive = temp.path().join("sample.tzap");
    let repaired = temp.path().join("sample.repaired.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    let payload = (0..12_000)
        .map(|idx| ((idx * 37 + 11) % 251) as u8)
        .collect::<Vec<_>>();
    fs::write(&input, payload).unwrap();

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

    let mut archive_bytes = fs::read(&archive).unwrap();
    corrupt_first_record_payload_crc_of_kind(&mut archive_bytes, BlockKind::PayloadData);
    fs::write(&archive, archive_bytes).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--write-repaired",
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("(1 volume(s), 1 file(s))"))
        .stdout(predicate::str::contains("wrote repaired volume copy"))
        .stdout(predicate::str::contains("sample.repaired.tzap"));

    assert!(repaired.exists());
    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            keyfile.to_str().unwrap(),
            repaired.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("(1 volume(s), 1 file(s))"));
}

#[test]
fn cli_verify_write_repaired_writes_sibling_for_malformed_payload_block_slot() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("payload.bin");
    let archive = temp.path().join("sample.tzap");
    let repaired = temp.path().join("sample.repaired.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    let payload = (0..12_000)
        .map(|idx| ((idx * 41 + 7) % 251) as u8)
        .collect::<Vec<_>>();
    fs::write(&input, payload).unwrap();

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

    let mut archive_bytes = fs::read(&archive).unwrap();
    corrupt_first_record_magic_of_kind(&mut archive_bytes, BlockKind::PayloadData);
    fs::write(&archive, archive_bytes).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--write-repaired",
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("(1 volume(s), 1 file(s))"))
        .stdout(predicate::str::contains("wrote repaired volume copy"))
        .stdout(predicate::str::contains("sample.repaired.tzap"));

    assert!(repaired.exists());
    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            keyfile.to_str().unwrap(),
            repaired.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("(1 volume(s), 1 file(s))"));
}

#[test]
fn cli_verify_recovers_malformed_volume_header_from_cmra() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("payload.bin");
    let archive = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"front header recovery").unwrap();

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

    let mut archive_bytes = fs::read(&archive).unwrap();
    archive_bytes[0] ^= 0x55;
    fs::write(&archive, archive_bytes).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            keyfile.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("(1 volume(s), 1 file(s))"));
}

#[test]
fn cli_create_signed_archive_and_verify_root_auth_profiles() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let signing_secret = temp.path().join("root.signing.hex");
    let signing_public = temp.path().join("root.public.hex");
    let input = temp.path().join("signed.txt");
    let archive = temp.path().join("signed.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"signed payload\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "signing-keygen",
            "--secret-output",
            signing_secret.to_str().unwrap(),
            "--public-output",
            signing_public.to_str().unwrap(),
        ])
        .assert()
        .success();

    let public_hex = fs::read_to_string(&signing_public).unwrap();
    assert_eq!(public_hex.trim().len(), 64);

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--signing-key",
            signing_secret.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("root auth: ed25519 signed"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--trusted-public-key",
            signing_public.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("(1 volume(s), 1 file(s))")
                .and(predicate::str::contains("root-auth: OK ed25519")),
        );

    let output = Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--json",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--trusted-public-key",
            signing_public.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["ok"], true);
    assert_eq!(value["verification_mode"], "key-holding");
    assert_eq!(value["root_auth"]["status"], "root_auth_content_verified");
    assert_eq!(value["root_auth"]["key_id"], public_hex.trim());

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--public-no-key",
            "--trusted-public-key",
            signing_public.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("OK public-no-key")
                .and(predicate::str::contains(
                    "public_data_block_commitment_verified",
                ))
                .and(predicate::str::contains(
                    "public_physical_completeness_unverified",
                ))
                .and(predicate::str::contains("public_recovery_margin_unchecked")),
        );

    let output = Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--json",
            "--public-no-key",
            "--trusted-public-key",
            signing_public.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["ok"], true);
    assert_eq!(value["verification_mode"], "public-no-key");
    assert_eq!(
        value["root_auth"]["status"],
        "public_data_block_commitment_verified"
    );
    assert_eq!(value["root_auth"]["key_id"], public_hex.trim());
    assert!(value["public_diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry == "public_recovery_margin_unchecked"));
}

#[test]
fn cli_no_encryption_signed_archive_round_trips_and_publicly_verifies() {
    let temp = tempdir().unwrap();
    let signing_secret = temp.path().join("root.signing.hex");
    let signing_public = temp.path().join("root.public.hex");
    let input = temp.path().join("public.txt");
    let archive = temp.path().join("public.tzap");
    let output = temp.path().join("out");
    let payload = b"public convenience payload\n";

    fs::write(&input, payload).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "signing-keygen",
            "--secret-output",
            signing_secret.to_str().unwrap(),
            "--public-output",
            signing_public.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--no-encryption",
            "--signing-key",
            signing_secret.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("root auth: ed25519 signed"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["list", archive.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("public.txt"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--trusted-public-key",
            signing_public.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("(1 volume(s), 1 file(s))")
                .and(predicate::str::contains("root-auth: OK ed25519")),
        );

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--public-no-key",
            "--trusted-public-key",
            signing_public.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "public_data_block_commitment_verified",
        ));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "-C",
            output.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(fs::read(output.join("public.txt")).unwrap(), payload);
}

#[test]
fn cli_create_x509_signed_archive_and_verify_certificate_details() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let root_ca = temp.path().join("root-ca.pem");
    let signer_cert = temp.path().join("signer.pem");
    let signer_key = temp.path().join("signer.key");
    let input = temp.path().join("signed.txt");
    let archive = temp.path().join("signed-x509.tzap");

    let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
    let (leaf_cert, leaf_key) = test_leaf_cert(
        "Acme Release Signing",
        root_cert.as_ref(),
        root_key.as_ref(),
    );
    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&root_ca, root_cert.to_pem().unwrap()).unwrap();
    fs::write(&signer_cert, leaf_cert.to_pem().unwrap()).unwrap();
    fs::write(&signer_key, leaf_key.private_key_to_pem_pkcs8().unwrap()).unwrap();
    fs::write(&input, b"x509 signed payload\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--signing-cert",
            signer_cert.to_str().unwrap(),
            "--signing-private-key",
            signer_key.to_str().unwrap(),
            "--x509-signature-scheme",
            "rsa-pss-sha256",
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("root auth: x509 signed"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--trusted-ca-cert",
            root_ca.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("root-auth: OK x509")
                .and(predicate::str::contains(
                    "root-auth signer: CN=Acme Release Signing",
                ))
                .and(predicate::str::contains(
                    "root-auth issuer: CN=Acme Test Root CA",
                ))
                .and(predicate::str::contains("root-auth signed-at:"))
                .and(predicate::str::contains("root-auth chain-validation-time:"))
                .and(predicate::str::contains(
                    "root-auth x509-policy: signature-scheme=rsa-pss-sha256",
                )),
        );

    let output = Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--json",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--trusted-ca-cert",
            root_ca.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["ok"], true);
    assert_eq!(value["root_auth"]["authenticator"], "x509");
    assert_eq!(value["root_auth"]["subject"], "CN=Acme Release Signing");
    assert_eq!(value["root_auth"]["issuer"], "CN=Acme Test Root CA");
    assert_eq!(value["root_auth"]["time_source"], "signer_claimed");
    assert_eq!(value["root_auth"]["signature_scheme"], "rsa-pss-sha256");
    assert_eq!(
        value["root_auth"]["x509_time_policy"],
        "verifier_current_time"
    );
    assert_eq!(
        value["root_auth"]["chain_time_basis"],
        "verifier_current_time"
    );
    assert_eq!(value["root_auth"]["trusted_timestamp"], false);
    assert_eq!(value["root_auth"]["revocation_checked"], false);
    assert_eq!(
        value["root_auth"]["key_usage_policy"],
        "archive_signature_minimal"
    );
    assert_eq!(value["root_auth"]["eku_policy"], "none");
    assert_eq!(value["root_auth"]["trust_store_policy"], "caller_roots");
    assert!(value["root_auth"]["chain_validation_time_unix_seconds"].is_number());
    assert_eq!(
        value["root_auth"]["trust_anchor_subject"],
        "CN=Acme Test Root CA"
    );

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--public-no-key",
            "--trusted-ca-cert",
            root_ca.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("OK public-no-key")
                .and(predicate::str::contains("root-auth: OK public-no-key x509"))
                .and(predicate::str::contains(
                    "root-auth signer: CN=Acme Release Signing",
                ))
                .and(predicate::str::contains(
                    "public_data_block_commitment_verified",
                )),
        );

    let output = Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--json",
            "--public-no-key",
            "--trusted-ca-cert",
            root_ca.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["ok"], true);
    assert_eq!(value["verification_mode"], "public-no-key");
    assert_eq!(value["root_auth"]["authenticator"], "x509");
    assert_eq!(value["root_auth"]["signature_scheme"], "rsa-pss-sha256");
    assert_eq!(
        value["root_auth"]["x509_time_policy"],
        "verifier_current_time"
    );
    assert_eq!(value["root_auth"]["revocation_checked"], false);
    assert_eq!(
        value["root_auth"]["status"],
        "public_data_block_commitment_verified"
    );
    assert_eq!(value["root_auth"]["subject"], "CN=Acme Release Signing");
    assert_eq!(
        value["root_auth"]["trust_anchor_subject"],
        "CN=Acme Test Root CA"
    );
}

#[test]
fn cli_verify_quiet_conflicts_with_json_mode() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello from tzap\n").unwrap();

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

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--quiet",
            "--json",
            "--keyfile",
            keyfile.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(
            predicate::str::contains("cannot be used with").and(predicate::str::contains("--json")),
        );
}

#[test]
fn cli_verify_quiet_suppress_success_output_only() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello from tzap\n").unwrap();

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

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--quiet",
            "--keyfile",
            keyfile.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

#[test]
fn cli_create_with_global_quiet_suppresses_success_summary() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello from tzap\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--quiet",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

#[test]
fn cli_create_list_verify_and_extract_with_keyfile() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");
    let bootstrap = temp.path().join("sample.tzap.bootstrap");
    let extract_dir = temp.path().join("out");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello from tzap\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--bootstrap-out",
            bootstrap.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "created 1 member(s), 16 bytes in, ",
        ))
        .stderr(predicate::str::contains(
            "1 volume(s), volume-loss tolerance 0, bit-rot buffer 5%",
        ));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "list",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--bootstrap",
            bootstrap.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("hello.txt\n"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            keyfile.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-C",
            extract_dir.to_str().unwrap(),
            archive.to_str().unwrap(),
            "hello.txt",
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(extract_dir.join("hello.txt")).unwrap(),
        b"hello from tzap\n"
    );
}

#[test]
fn cli_create_list_verify_and_extract_with_recipient_wrap() {
    let temp = tempdir().unwrap();
    let recipient_cert_path = temp.path().join("recipient.pem");
    let recipient_key_path = temp.path().join("recipient.key");
    let wrong_key_path = temp.path().join("wrong-recipient.key");
    let input = temp.path().join("recipient.txt");
    let archive = temp.path().join("recipient-wrap.tzap");
    let plaintext_archive = temp.path().join("plaintext.tzap");
    let extract_dir = temp.path().join("out");

    let (recipient_cert, recipient_key) = test_x25519_recipient_cert();
    let (_wrong_cert, wrong_key) = test_x25519_recipient_cert();
    fs::write(&recipient_cert_path, recipient_cert.to_pem().unwrap()).unwrap();
    fs::write(&recipient_key_path, recipient_key).unwrap();
    fs::write(&wrong_key_path, wrong_key).unwrap();
    fs::write(&input, b"recipient wrapped\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--recipient-cert",
            recipient_cert_path.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("key wrap: recipient certificate"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--no-encryption",
            "-o",
            plaintext_archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "list",
            "--recipient-key",
            recipient_key_path.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("recipient.txt\n"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--recipient-key",
            recipient_key_path.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--json",
            "--recipient-key",
            recipient_key_path.to_str().unwrap(),
            "-",
        ])
        .write_stdin(fs::read(&archive).unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains(
            r#""decryption_keywrap":"recipientwrap_opened""#,
        ));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--json",
            "--recipient-key",
            recipient_key_path.to_str().unwrap(),
            "-",
        ])
        .write_stdin(fs::read(&plaintext_archive).unwrap())
        .assert()
        .code(10)
        .stdout(
            predicate::str::contains(r#""ok":false"#)
                .and(predicate::str::contains(r#""label":"wrong-key""#))
                .and(predicate::str::contains("recipientwrap_opened").not()),
        );

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--recipient-key",
            recipient_key_path.to_str().unwrap(),
            "-",
        ])
        .write_stdin(fs::read(&archive).unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--recipient-key",
            wrong_key_path.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .code(10)
        .stderr(
            predicate::str::contains("wrong-key")
                .and(predicate::str::contains("recipient private key")),
        );

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--recipient-key",
            recipient_key_path.to_str().unwrap(),
            "-C",
            extract_dir.to_str().unwrap(),
            archive.to_str().unwrap(),
            "recipient.txt",
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(extract_dir.join("recipient.txt")).unwrap(),
        b"recipient wrapped\n"
    );
}

#[test]
fn cli_verify_accepts_multivolume_recipient_wrap() {
    let temp = tempdir().unwrap();
    let recipient_key_path = temp.path().join("recipient.key");
    let output_base = temp.path().join("recipient-wrap.tzap");
    let volume0 = numbered_volume_path(&output_base, 0);
    let volume1 = numbered_volume_path(&output_base, 1);
    let archive_uuid = [0x31; 16];
    let session_id = [0x42; 16];
    let master = MasterKey::from_raw_key(&[0x77; 32]).unwrap();
    let (recipient_cert, recipient_key) = test_x25519_recipient_cert();
    fs::write(&recipient_key_path, recipient_key).unwrap();
    let record = wrap_master_key_for_recipient(
        ArchiveIdentity {
            archive_uuid,
            session_id,
            format_version: FORMAT_VERSION,
            volume_format_rev: VOLUME_FORMAT_REV_45,
        },
        &recipient_cert.to_der().unwrap(),
        &master.0,
        KeyWrapSuite::X25519HkdfSha256ChaCha20Poly1305,
    )
    .unwrap();
    let archive = write_archive_with_recipient_wrap_records(
        &[RegularFile::new(
            "wrapped.txt",
            b"multi recipient wrapped\n",
        )],
        &master,
        WriterOptions {
            stripe_width: 2,
            volume_loss_tolerance: 0,
            archive_uuid: Some(archive_uuid),
            session_id: Some(session_id),
            ..WriterOptions::default()
        },
        vec![record],
    )
    .unwrap();
    assert_eq!(archive.volumes.len(), 2);
    fs::write(&volume0, &archive.volumes[0]).unwrap();
    fs::write(&volume1, &archive.volumes[1]).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--recipient-key",
            recipient_key_path.to_str().unwrap(),
            volume0.to_str().unwrap(),
            volume1.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));
}

#[test]
fn cli_reports_wrong_key_with_stable_category_and_exit_code() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let bad_keyfile = temp.path().join("bad-key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&bad_keyfile, BAD_KEY_HEX).unwrap();
    fs::write(&input, b"hello from tzap\n").unwrap();

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

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            bad_keyfile.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .code(10)
        .stderr(predicate::str::contains("wrong-key"));
}

#[test]
fn cli_create_and_verify_with_password_stdin_argon2id() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("secret.txt");
    let archive = temp.path().join("password.tzap");

    fs::write(&input, b"password protected\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--password-stdin",
            "--argon2-t-cost",
            "1",
            "--argon2-m-cost-kib",
            "8",
            "--argon2-parallelism",
            "1",
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .write_stdin("correct horse battery staple\n")
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", "--password-stdin", archive.to_str().unwrap()])
        .write_stdin("correct horse battery staple\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));
}

#[test]
fn cli_extract_stdout_writes_exact_single_file_payload() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"stdout payload\n").unwrap();

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

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--stdout",
            archive.to_str().unwrap(),
            "hello.txt",
        ])
        .assert()
        .success()
        .stdout(predicate::eq("stdout payload\n"));
}

#[test]
fn cli_extract_stdout_outputs_binary_data_only_to_stdout() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.bin");
    let archive = temp.path().join("sample.tzap");
    let payload: Vec<u8> = (0..=255u8).collect();

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, &payload).unwrap();

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

    let output = Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--stdout",
            archive.to_str().unwrap(),
            "hello.bin",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    assert_eq!(output.stdout, payload);
    assert!(output.stderr.is_empty());
}

#[test]
fn cli_extract_stdout_emits_no_payload_when_archive_authentication_fails() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let bad_key = temp.path().join("bad.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&bad_key, BAD_KEY_HEX).unwrap();
    fs::write(&input, b"stdout payload\n").unwrap();

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

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            bad_key.to_str().unwrap(),
            "--stdout",
            archive.to_str().unwrap(),
            "hello.txt",
        ])
        .assert()
        .code(10)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("wrong-key"));
}

#[test]
fn cli_extract_with_global_quiet_suppresses_success_summary() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");
    let output = temp.path().join("out");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello from tzap\n").unwrap();

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

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--quiet",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--directory",
            output.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::is_empty());

    assert_eq!(
        fs::read(output.join("hello.txt")).unwrap(),
        b"hello from tzap\n"
    );
}

#[test]
fn cli_extract_with_global_quiet_still_emits_errors_to_stderr() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello from tzap\n").unwrap();

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

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--quiet",
            "--keyfile",
            keyfile.to_str().unwrap(),
            archive.to_str().unwrap(),
            "missing.txt",
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "missing archive path: missing.txt",
        ));
}

#[test]
fn cli_extract_with_global_quiet_still_outputs_stdout_payload() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.bin");
    let archive = temp.path().join("sample.tzap");
    let payload: Vec<u8> = (0u8..=254u8).collect();

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, &payload).unwrap();

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

    let output = Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--quiet",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--stdout",
            archive.to_str().unwrap(),
            "hello.bin",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    assert_eq!(output.stdout, payload);
    assert!(output.stderr.is_empty());
}

#[test]
fn cli_reports_corrupt_header_magic() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello from tzap\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--bit-rot-buffer-pct",
            "0",
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();

    let mut bytes = fs::read(&archive).unwrap();
    bytes[0] ^= 0xff;
    fs::write(&archive, bytes).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            keyfile.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .code(11)
        .stderr(predicate::str::contains("corrupt-header"));
}

#[test]
fn cli_reports_corrupt_archive_after_header_authentication_succeeds() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello from tzap\n").unwrap();

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

    let mut bytes = fs::read(&archive).unwrap();
    corrupt_first_record_of_kind(&mut bytes, BlockKind::PayloadData);
    fs::write(&archive, bytes).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            keyfile.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .code(11)
        .stderr(predicate::str::contains("corrupt-payload"));
}

#[test]
fn cli_reports_wrong_key_for_password_mode_on_raw_key_archive() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello from tzap\n").unwrap();

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

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", "--password-stdin", archive.to_str().unwrap()])
        .write_stdin("not the raw key\n")
        .assert()
        .code(10)
        .stderr(predicate::str::contains("wrong-key"))
        .stderr(predicate::str::contains(
            "raw-key archives require --keyfile",
        ));
}

#[test]
fn cli_reports_wrong_passphrase_with_stable_category_and_exit_code() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("secret.txt");
    let archive = temp.path().join("secret.tzap");
    let passphrase = "correct horse battery staple\n";

    fs::write(&input, b"secret data\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--password-stdin",
            "--argon2-t-cost",
            "1",
            "--argon2-m-cost-kib",
            "8",
            "--argon2-parallelism",
            "1",
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .write_stdin(passphrase)
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", "--password-stdin", archive.to_str().unwrap()])
        .write_stdin("wrong passphrase\n")
        .assert()
        .code(10)
        .stderr(predicate::str::contains("wrong-key"));
}

#[test]
fn cli_reports_unsupported_revision_with_stable_category_and_exit_code() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello from tzap\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--bit-rot-buffer-pct",
            "0",
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();

    let mut bytes = fs::read(&archive).unwrap();
    let mut header = VolumeHeader::parse(&bytes[..VOLUME_HEADER_LEN]).unwrap();
    header.volume_format_rev = 35;
    bytes[..VOLUME_HEADER_LEN].copy_from_slice(&header.to_bytes());
    fs::write(&archive, bytes).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            keyfile.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .code(12)
        .stderr(predicate::str::contains("unsupported-revision"));
}

#[test]
fn cli_verify_with_stripped_dictionary_sidecar_uses_terminal_archive_metadata() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let dictionary = temp.path().join("dict.txt");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");
    let bootstrap = temp.path().join("sample.tzap.bootstrap");
    let stripped_bootstrap = temp.path().join("sample.tzap.bootstrap.stripped");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&dictionary, b"dictionary payload bytes").unwrap();
    fs::write(&input, b"hello from tzap\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--dictionary",
            dictionary.to_str().unwrap(),
            "--bootstrap-out",
            bootstrap.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();

    let archive_bytes = fs::read(&archive).unwrap();
    let volume_header = VolumeHeader::parse(&archive_bytes[..VOLUME_HEADER_LEN]).unwrap();
    let bootstrap_original = fs::read(&bootstrap).unwrap();
    let mut bootstrap_header =
        BootstrapSidecarHeader::parse(&bootstrap_original[..BOOTSTRAP_SIDECAR_HEADER_LEN]).unwrap();
    bootstrap_header.flags &= !0x04;
    bootstrap_header.dictionary_records_offset = 0;
    bootstrap_header.dictionary_records_length = 0;

    let master_key = MasterKey::from_raw_key(&master_key_from_hex(KEY_HEX)).unwrap();
    let subkeys = Subkeys::derive(
        &master_key,
        &volume_header.archive_uuid,
        &volume_header.session_id,
    )
    .unwrap();
    let stripped_header = bootstrap_header.to_bytes();
    let sidecar_hmac = compute_hmac(
        HmacDomain::BootstrapSidecar,
        &subkeys.mac_key,
        &bootstrap_header.archive_uuid,
        &bootstrap_header.session_id,
        &stripped_header[..SIDECAR_HMAC_COVERED_LEN],
    );
    bootstrap_header.sidecar_hmac = sidecar_hmac;
    let stripped = bootstrap_header.to_bytes();

    let mut payload_end = BOOTSTRAP_SIDECAR_HEADER_LEN as u64;
    if bootstrap_header.has_manifest_footer() {
        assert_eq!(bootstrap_header.manifest_footer_offset, payload_end);
        payload_end = payload_end
            .checked_add(bootstrap_header.manifest_footer_length as u64)
            .unwrap();
    }
    if bootstrap_header.has_index_root_records() {
        assert_eq!(bootstrap_header.index_root_records_offset, payload_end);
        payload_end = payload_end
            .checked_add(bootstrap_header.index_root_records_length as u64)
            .unwrap();
    }

    let mut stripped_bootstrap_bytes = stripped.to_vec();
    stripped_bootstrap_bytes
        .extend_from_slice(&bootstrap_original[BOOTSTRAP_SIDECAR_HEADER_LEN..payload_end as usize]);
    fs::write(&stripped_bootstrap, stripped_bootstrap_bytes).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--bootstrap",
            stripped_bootstrap.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("(1 volume(s), 1 file(s))"));
}

#[test]
fn cli_reports_unsafe_path_as_stable_category_and_exit_code() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello from tzap\n").unwrap();

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

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--stdout",
            archive.to_str().unwrap(),
            "../evil.txt",
        ])
        .assert()
        .code(13)
        .stderr(predicate::str::contains("unsafe-path"));
}

#[test]
fn cli_reports_unsupported_feature_with_stable_category_and_exit_code() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let dictionary = temp.path().join("empty.dict");
    let input = temp.path().join("hello.txt");
    let output = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&dictionary, b"").unwrap();
    fs::write(&input, b"hello\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--dictionary",
            dictionary.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .code(16)
        .stderr(predicate::str::contains("unsupported-feature"));
}

#[test]
fn cli_create_missing_input_returns_io_error_code() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("missing.txt");
    let output = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("io-error"));
}

#[test]
fn cli_create_with_global_quiet_still_emits_io_errors_to_stderr() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let missing = temp.path().join("missing.txt");
    let output = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--quiet",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            missing.to_str().unwrap(),
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("io-error"));
}

#[test]
fn cli_reports_invalid_size_suffix_with_bad_value_in_message() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let output = temp.path().join("sample.tzap");
    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--volume-size",
            "10Q",
            "-o",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "invalid size '10Q': unsupported suffix 'Q'",
        ))
        .stderr(predicate::str::contains("supported: K/KB/KiB"));
}

#[test]
fn cli_create_and_verify_multi_volume_archive() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("striped.txt");
    let output_base = temp.path().join("striped.tzap");
    let volume_0 = numbered_volume_path(&output_base, 0);
    let volume_1 = numbered_volume_path(&output_base, 1);

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"multi-volume payload\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--volumes",
            "2",
            "--volume-loss-tolerance",
            "1",
            "-o",
            output_base.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("2 volume(s)"));

    assert!(volume_0.exists());
    assert!(volume_1.exists());

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            keyfile.to_str().unwrap(),
            volume_0.to_str().unwrap(),
            volume_1.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "list",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--volume",
            volume_1.to_str().unwrap(),
            volume_0.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("striped.txt\n"));
}

#[test]
fn cli_verify_autodiscovers_sibling_volumes_from_middle_volume() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("middle-anchor.txt");
    let output_base = temp.path().join("middle-anchor.tzap");
    let volume_1 = numbered_volume_path(&output_base, 1);

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"autodiscovery payload\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--volumes",
            "3",
            "--volume-loss-tolerance",
            "1",
            "-o",
            output_base.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            keyfile.to_str().unwrap(),
            volume_1.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("(3 volume(s), 1 file(s))"));
}

#[test]
fn cli_verify_autodiscovery_recovers_when_vol000_is_damaged() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("damaged-anchor.txt");
    let output_base = temp.path().join("damaged-anchor.tzap");
    let volume_0 = numbered_volume_path(&output_base, 0);

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"recover from damaged volume zero\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--volumes",
            "2",
            "--volume-loss-tolerance",
            "1",
            "-o",
            output_base.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();
    fs::write(&volume_0, b"not a valid tzap volume\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            keyfile.to_str().unwrap(),
            volume_0.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("(2 volume(s), 1 file(s))"));
}

#[test]
fn cli_verify_missing_archive_file_is_io_error() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let missing = temp.path().join("missing.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            keyfile.to_str().unwrap(),
            missing.to_str().unwrap(),
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("io-error"));
}

#[test]
fn cli_verify_json_failure_reports_error_object() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let missing = temp.path().join("missing.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();

    let output = Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--json",
            "--keyfile",
            keyfile.to_str().unwrap(),
            missing.to_str().unwrap(),
        ])
        .assert()
        .code(3)
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output).unwrap();

    assert!(!value.get("ok").unwrap().as_bool().unwrap());
    let error = value.get("error").unwrap();
    assert_eq!(error.get("label").unwrap().as_str().unwrap(), "io-error");
}

#[test]
fn cli_verify_quiet_still_prints_diagnostics_on_failure() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let missing = temp.path().join("missing.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--quiet",
            "--keyfile",
            keyfile.to_str().unwrap(),
            missing.to_str().unwrap(),
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("io-error"));
}

#[test]
fn cli_verify_missing_recoverable_volume_is_recovered_with_tolerance() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("striped.txt");
    let output_base = temp.path().join("recoverable.tzap");
    let volume_0 = numbered_volume_path(&output_base, 0);
    let volume_1 = numbered_volume_path(&output_base, 1);
    let volume_2 = numbered_volume_path(&output_base, 2);

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"recoverable payload\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--volumes",
            "3",
            "-o",
            output_base.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();
    fs::remove_file(&volume_1).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            keyfile.to_str().unwrap(),
            volume_0.to_str().unwrap(),
            volume_2.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("(3 volume(s), 1 file(s))"));
}

#[test]
fn cli_verify_missing_unrecoverable_volume_reports_missing_volume() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("striped.txt");
    let output_base = temp.path().join("unrecoverable.tzap");
    let volume_0 = numbered_volume_path(&output_base, 0);
    let volume_1 = numbered_volume_path(&output_base, 1);

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"unrecoverable payload\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--volumes",
            "2",
            "--volume-loss-tolerance",
            "0",
            "--bit-rot-buffer-pct",
            "0",
            "-o",
            output_base.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();
    fs::remove_file(&volume_1).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            keyfile.to_str().unwrap(),
            volume_0.to_str().unwrap(),
        ])
        .assert()
        .code(11)
        .stderr(predicate::str::contains("missing-volume"));
}

#[test]
fn cli_create_directory_tree_is_deterministic_and_includes_nested_files() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input_root = temp.path().join("input-dir");
    let archive = temp.path().join("tree.tzap");

    fs::create_dir(&input_root).unwrap();
    fs::create_dir(input_root.join("zeta")).unwrap();
    fs::write(input_root.join(".hidden"), b"hidden\n").unwrap();
    fs::write(input_root.join("b.txt"), b"root B\n").unwrap();
    fs::write(input_root.join("a.txt"), b"root A\n").unwrap();
    fs::write(input_root.join("zeta").join("c.txt"), b"nested C\n").unwrap();
    fs::write(input_root.join("zeta").join("a.txt"), b"nested A\n").unwrap();
    fs::write(&keyfile, KEY_HEX).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input_root.to_str().unwrap(),
        ])
        .assert()
        .success();

    let output = Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "list",
            "--keyfile",
            keyfile.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let listing = String::from_utf8_lossy(&output);

    let base = input_root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap();
    let expected = format!(
        "{base}\n{base}/.hidden\n{base}/a.txt\n{base}/b.txt\n{base}/zeta\n{base}/zeta/a.txt\n{base}/zeta/c.txt\n"
    );
    assert_eq!(listing, expected);
}

#[test]
fn cli_create_preserves_empty_directories() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input_root = temp.path().join("input");
    let archive = temp.path().join("empty-dir.tzap");

    fs::create_dir_all(input_root.join("empty")).unwrap();
    fs::write(input_root.join("keep.txt"), b"keep\n").unwrap();
    fs::write(&keyfile, KEY_HEX).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input_root.to_str().unwrap(),
        ])
        .assert()
        .success();

    let output = Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "list",
            "--keyfile",
            keyfile.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert_eq!(
        String::from_utf8_lossy(&output),
        "input\ninput/empty\ninput/keep.txt\n",
    );
}

#[cfg(target_os = "linux")]
#[test]
fn cli_directory_metadata_round_trips_after_children() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::time::{Duration, UNIX_EPOCH};

    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input_root = temp.path().join("tree");
    let nested = input_root.join("nested");
    let archive = temp.path().join("directory-metadata.tzap");
    let extract_dir = temp.path().join("extract");
    let stream_extract_dir = temp.path().join("stream-extract");
    fs::create_dir_all(&nested).unwrap();
    fs::write(nested.join("child.txt"), b"child").unwrap();
    fs::write(&keyfile, KEY_HEX).unwrap();

    let mut permissions = fs::metadata(&nested).unwrap().permissions();
    permissions.set_mode(0o751);
    fs::set_permissions(&nested, permissions).unwrap();
    let expected_time = UNIX_EPOCH + Duration::new(1_700_000_123, 456_789_000);
    fs::File::open(&nested)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(expected_time))
        .unwrap();
    xattr::set(&nested, "user.tzap-directory-test", b"directory-xattr").unwrap();
    let source = fs::metadata(&nested).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input_root.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--restore",
            "same-os",
            "--allow-degraded",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-C",
            extract_dir.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success();

    let restored = fs::metadata(extract_dir.join("tree/nested")).unwrap();
    assert_eq!(restored.mode() & 0o7777, 0o751);
    assert_eq!(restored.mtime(), source.mtime());
    assert_eq!(restored.mtime_nsec(), source.mtime_nsec());
    assert_eq!(restored.uid(), source.uid());
    assert_eq!(restored.gid(), source.gid());
    assert_eq!(
        xattr::get(extract_dir.join("tree/nested"), "user.tzap-directory-test")
            .unwrap()
            .as_deref(),
        Some(b"directory-xattr".as_slice())
    );
    assert_eq!(
        fs::read(extract_dir.join("tree/nested/child.txt")).unwrap(),
        b"child"
    );

    fs::create_dir_all(stream_extract_dir.join("tree/nested")).unwrap();
    let mut wrong_permissions = fs::metadata(stream_extract_dir.join("tree/nested"))
        .unwrap()
        .permissions();
    wrong_permissions.set_mode(0o700);
    fs::set_permissions(stream_extract_dir.join("tree/nested"), wrong_permissions).unwrap();
    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--restore",
            "same-os",
            "--allow-degraded",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-C",
            stream_extract_dir.to_str().unwrap(),
            "-",
        ])
        .write_stdin(fs::read(&archive).unwrap())
        .assert()
        .success();
    let stream_restored = fs::metadata(stream_extract_dir.join("tree/nested")).unwrap();
    assert_eq!(stream_restored.mode() & 0o7777, 0o751);
    assert_eq!(stream_restored.mtime(), source.mtime());
    assert_eq!(stream_restored.mtime_nsec(), source.mtime_nsec());
    assert_eq!(
        xattr::get(
            stream_extract_dir.join("tree/nested"),
            "user.tzap-directory-test"
        )
        .unwrap()
        .as_deref(),
        Some(b"directory-xattr".as_slice())
    );
}

#[cfg(target_os = "macos")]
#[test]
fn cli_macos_native_metadata_round_trips_for_files_and_directories() {
    use std::os::macos::fs::MetadataExt as _;

    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input_root = temp.path().join("tree");
    let nested = input_root.join("nested");
    let input_file = nested.join("native.txt");
    let archive = temp.path().join("macos-metadata.tzap");
    let extract_dir = temp.path().join("extract");
    fs::create_dir_all(&nested).unwrap();
    fs::write(&input_file, b"primary payload").unwrap();
    fs::write(&keyfile, KEY_HEX).unwrap();

    for (path, marker) in [(&input_file, 0x5au8), (&nested, 0x6bu8)] {
        xattr::set(path, "com.tzap.test", &[marker; 17]).unwrap();
        xattr::set(path, "com.apple.FinderInfo", &[marker; 32]).unwrap();
        if path.is_file() {
            fs::write(
                path.join("..namedfork/rsrc"),
                vec![marker; 2 * 1024 * 1024 + 31],
            )
            .unwrap();
            assert_eq!(
                fs::metadata(path.join("..namedfork/rsrc")).unwrap().len(),
                2 * 1024 * 1024 + 31
            );
        }
        assert!(std::process::Command::new("chmod")
            .args(["+a", "everyone deny delete"])
            .arg(path)
            .status()
            .unwrap()
            .success());
        assert!(std::process::Command::new("chflags")
            .arg("hidden")
            .arg(path)
            .status()
            .unwrap()
            .success());
    }
    let source_file = fs::metadata(&input_file).unwrap();
    let source_directory = fs::metadata(&nested).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input_root.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--restore",
            "same-os",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-C",
            extract_dir.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success();

    for (restored, source, marker) in [
        (
            extract_dir.join("tree/nested/native.txt"),
            &source_file,
            0x5au8,
        ),
        (extract_dir.join("tree/nested"), &source_directory, 0x6bu8),
    ] {
        let actual = fs::metadata(&restored).unwrap();
        assert_eq!(actual.st_flags(), source.st_flags());
        assert_eq!(actual.st_birthtime(), source.st_birthtime());
        assert_eq!(actual.st_birthtime_nsec(), source.st_birthtime_nsec());
        assert_eq!(
            xattr::get(&restored, "com.tzap.test").unwrap().as_deref(),
            Some([marker; 17].as_slice())
        );
        assert_eq!(
            xattr::get(&restored, "com.apple.FinderInfo")
                .unwrap()
                .as_deref(),
            Some([marker; 32].as_slice())
        );
        if restored.is_file() {
            let resource_fork = fs::read(restored.join("..namedfork/rsrc")).unwrap();
            assert_eq!(resource_fork.len(), 2 * 1024 * 1024 + 31);
            assert!(resource_fork.iter().all(|byte| *byte == marker));
        }
        let acl = std::process::Command::new("ls")
            .args(["-lde"])
            .arg(&restored)
            .output()
            .unwrap();
        assert!(acl.status.success());
        assert!(String::from_utf8_lossy(&acl.stdout).contains("everyone deny delete"));
    }
}

#[cfg(target_os = "macos")]
#[test]
fn cli_macos_symlink_metadata_round_trips_without_touching_target() {
    use std::os::macos::fs::MetadataExt as _;
    use std::os::unix::fs::symlink;

    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input_root = temp.path().join("tree");
    let target = input_root.join("target.txt");
    let link = input_root.join("link.txt");
    let archive = temp.path().join("macos-symlink-metadata.tzap");
    let extract_dir = temp.path().join("extract");
    fs::create_dir_all(&input_root).unwrap();
    fs::write(&target, b"target bytes").unwrap();
    symlink("target.txt", &link).unwrap();
    fs::write(&keyfile, KEY_HEX).unwrap();
    xattr::set(&target, "com.tzap.target", b"unchanged").unwrap();
    xattr::set(&link, "com.tzap.link", b"link metadata").unwrap();
    assert!(std::process::Command::new("chmod")
        .args(["-h", "+a", "everyone deny delete"])
        .arg(&link)
        .status()
        .unwrap()
        .success());
    assert!(std::process::Command::new("chflags")
        .args(["-h", "hidden"])
        .arg(&link)
        .status()
        .unwrap()
        .success());
    let source_link = fs::symlink_metadata(&link).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input_root.to_str().unwrap(),
        ])
        .assert()
        .success();
    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--restore",
            "same-os",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-C",
            extract_dir.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success();

    let restored_link = extract_dir.join("tree/link.txt");
    let restored_target = extract_dir.join("tree/target.txt");
    let actual_link = fs::symlink_metadata(&restored_link).unwrap();
    assert!(actual_link.file_type().is_symlink());
    assert_eq!(actual_link.st_flags(), source_link.st_flags());
    assert_eq!(
        xattr::get(&restored_link, "com.tzap.link")
            .unwrap()
            .as_deref(),
        Some(b"link metadata".as_slice())
    );
    let acl = std::process::Command::new("ls")
        .args(["-lde"])
        .arg(&restored_link)
        .output()
        .unwrap();
    assert!(acl.status.success());
    assert!(String::from_utf8_lossy(&acl.stdout).contains("everyone deny delete"));
    assert_eq!(
        xattr::get(&restored_target, "com.tzap.target")
            .unwrap()
            .as_deref(),
        Some(b"unchanged".as_slice())
    );
    assert_eq!(xattr::get(&restored_target, "com.tzap.link").unwrap(), None);
}

#[cfg(target_os = "macos")]
#[test]
fn cli_macos_fifo_metadata_round_trips_in_system_mode() {
    use std::ffi::CString;
    use std::os::macos::fs::MetadataExt as _;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};

    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input_root = temp.path().join("tree");
    let fifo = input_root.join("events.fifo");
    let archive = temp.path().join("macos-fifo-metadata.tzap");
    let same_os_extract_dir = temp.path().join("same-os-extract");
    let extract_dir = temp.path().join("extract");
    fs::create_dir_all(&input_root).unwrap();
    fs::write(&keyfile, KEY_HEX).unwrap();
    let fifo_c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o640) }, 0);
    xattr::set(&fifo, "com.tzap.fifo", b"fifo metadata").unwrap();
    assert!(std::process::Command::new("chmod")
        .args(["+a", "everyone deny delete"])
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    assert!(std::process::Command::new("chflags")
        .arg("hidden")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    let source = fs::symlink_metadata(&fifo).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input_root.to_str().unwrap(),
        ])
        .assert()
        .success();
    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--restore",
            "same-os",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-C",
            same_os_extract_dir.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success();
    assert!(!same_os_extract_dir.join("tree/events.fifo").exists());
    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--restore",
            "system",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-C",
            extract_dir.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success();

    let restored = extract_dir.join("tree/events.fifo");
    let actual = fs::symlink_metadata(&restored).unwrap();
    assert!(actual.file_type().is_fifo());
    assert_eq!(actual.permissions().mode() & 0o7777, 0o640);
    assert_eq!(actual.st_flags(), source.st_flags());
    assert_eq!(
        xattr::get(&restored, "com.tzap.fifo").unwrap().as_deref(),
        Some(b"fifo metadata".as_slice())
    );
    let acl = std::process::Command::new("ls")
        .args(["-lde"])
        .arg(&restored)
        .output()
        .unwrap();
    assert!(acl.status.success());
    assert!(String::from_utf8_lossy(&acl.stdout).contains("everyone deny delete"));
}

#[cfg(target_os = "macos")]
#[test]
fn cli_macos_privileged_system_flags_round_trip() {
    use std::os::macos::fs::MetadataExt as _;

    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input_root = temp.path().join("tree");
    let input_file = input_root.join("locked.txt");
    let archive = temp.path().join("macos-system-flags.tzap");
    let extract_dir = temp.path().join("extract");
    fs::create_dir_all(&input_root).unwrap();
    fs::write(&input_file, b"system flags").unwrap();
    fs::write(&keyfile, KEY_HEX).unwrap();
    assert!(std::process::Command::new("chflags")
        .args(["archived,schg"])
        .arg(&input_file)
        .status()
        .unwrap()
        .success());
    let source_flags = fs::metadata(&input_file).unwrap().st_flags();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input_root.to_str().unwrap(),
        ])
        .assert()
        .success();
    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--restore",
            "system",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-C",
            extract_dir.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success();

    let restored = extract_dir.join("tree/locked.txt");
    assert_eq!(fs::metadata(&restored).unwrap().st_flags(), source_flags);
    for path in [&input_file, &restored] {
        assert!(std::process::Command::new("chflags")
            .args(["noarchived,noschg"])
            .arg(path)
            .status()
            .unwrap()
            .success());
    }
}

#[cfg(target_os = "macos")]
#[test]
fn cli_macos_privileged_character_device_metadata_round_trips() {
    use std::ffi::CString;
    use std::os::macos::fs::MetadataExt as _;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};

    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let character = temp.path().join("character.dev");
    let archive = temp.path().join("macos-devices.tzap");
    let extract_dir = temp.path().join("extract");
    fs::write(&keyfile, KEY_HEX).unwrap();

    let character_c = CString::new(character.as_os_str().as_bytes()).unwrap();
    assert_eq!(
        unsafe {
            libc::mknod(
                character_c.as_ptr(),
                libc::S_IFCHR | 0o640,
                libc::makedev(3, 2),
            )
        },
        0
    );
    assert!(std::process::Command::new("chflags")
        .arg("hidden")
        .arg(&character)
        .status()
        .unwrap()
        .success());

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
        ])
        .arg(&character)
        .assert()
        .success();
    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--restore",
            "system",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-C",
            extract_dir.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success();

    let source = fs::symlink_metadata(&character).unwrap();
    let restored = fs::symlink_metadata(extract_dir.join("character.dev")).unwrap();
    assert!(restored.file_type().is_char_device());
    assert_eq!(restored.st_rdev(), source.st_rdev());
    assert_eq!(
        restored.permissions().mode() & 0o7777,
        source.permissions().mode() & 0o7777
    );
    assert_eq!(restored.st_flags(), source.st_flags());
    assert_eq!(restored.st_uid(), source.st_uid());
    assert_eq!(restored.st_gid(), source.st_gid());
    assert_eq!(restored.st_birthtime(), source.st_birthtime());
    assert_eq!(restored.st_birthtime_nsec(), source.st_birthtime_nsec());
}

#[test]
fn cli_create_supports_unicode_archive_paths() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let archive = temp.path().join("unicode.tzap");
    let input = temp.path().join("你好-ファイル.txt");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello unicode\n").unwrap();

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

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "list",
            "--keyfile",
            keyfile.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            input.file_name().and_then(|name| name.to_str()).unwrap(),
        ));
}

#[test]
fn cli_extract_selected_path_uses_core_unicode_normalization() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let archive = temp.path().join("unicode-selection.tzap");
    let input = temp.path().join("café.txt");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"normalized payload\n").unwrap();

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

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--stdout",
            archive.to_str().unwrap(),
            "cafe\u{301}.txt",
        ])
        .assert()
        .success()
        .stdout(predicate::eq(b"normalized payload\n".to_vec()));
}

#[test]
fn cli_create_supports_long_archive_paths() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input_root = temp.path().join("archive-root");
    let archive = temp.path().join("long.tzap");

    let segment = "segment_".to_owned() + &"a".repeat(50);
    let long_file = input_root
        .join(&segment)
        .join(&("nested_".to_owned() + &"b".repeat(50)))
        .join("long-path-".to_owned() + &"c".repeat(32));
    fs::create_dir_all(long_file.parent().unwrap()).unwrap();
    fs::write(&long_file, b"long path payload\n").unwrap();
    fs::write(&keyfile, KEY_HEX).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input_root.to_str().unwrap(),
        ])
        .assert()
        .success();

    let archive_member = long_file
        .strip_prefix(&input_root)
        .unwrap()
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/");

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "list",
            "--keyfile",
            keyfile.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(&archive_member));

    assert!(archive_member.len() >= 100);
}

#[test]
fn cli_create_handles_empty_file() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("empty.txt");
    let archive = temp.path().join("empty.tzap");
    let output = temp.path().join("out");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"").unwrap();

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

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-C",
            output.to_str().unwrap(),
            archive.to_str().unwrap(),
            "empty.txt",
        ])
        .assert()
        .success();

    assert_eq!(fs::read(output.join("empty.txt")).unwrap(), b"");
}

#[test]
fn cli_create_supports_binary_files() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("blob.bin");
    let archive = temp.path().join("binary.tzap");
    let output = temp.path().join("out");

    let payload: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, &payload).unwrap();

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

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-C",
            output.to_str().unwrap(),
            archive.to_str().unwrap(),
            "blob.bin",
        ])
        .assert()
        .success();

    assert_eq!(fs::read(output.join("blob.bin")).unwrap(), payload);
}

#[test]
fn cli_create_with_dictionary_file_succeeds() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let dictionary = temp.path().join("dictionary.txt");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("dict.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&dictionary, b"example dictionary bytes").unwrap();
    fs::write(&input, b"dictionary test payload\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--dictionary",
            dictionary.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "list",
            "--keyfile",
            keyfile.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("hello.txt\n"));
}

#[test]
fn cli_create_with_password_stdin_reports_key_mode_and_can_be_verified() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("secret.txt");
    let archive = temp.path().join("password.tzap");
    let pass = "stage2 password\n";

    fs::write(&input, b"hello from password mode\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--password-stdin",
            "--argon2-t-cost",
            "1",
            "--argon2-m-cost-kib",
            "8",
            "--argon2-parallelism",
            "1",
            "--dry-run",
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .write_stdin(pass)
        .assert()
        .success()
        .stderr(predicate::str::contains("key mode: password-stdin"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--password-stdin",
            "--argon2-t-cost",
            "1",
            "--argon2-m-cost-kib",
            "8",
            "--argon2-parallelism",
            "1",
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .write_stdin(pass)
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", "--password-stdin", archive.to_str().unwrap()])
        .write_stdin(pass)
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));
}

#[test]
fn cli_verify_with_bootstrap_sidecar_succeeds() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let dictionary = temp.path().join("dict.txt");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");
    let bootstrap = temp.path().join("sample.tzap.bootstrap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&dictionary, b"dictionary payload bytes").unwrap();
    fs::write(&input, b"hello from tzap\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--dictionary",
            dictionary.to_str().unwrap(),
            "--bootstrap-out",
            bootstrap.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--bootstrap",
            bootstrap.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));
}

#[test]
fn cli_create_dry_run_prints_summary_and_writes_nothing() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("dry.tzap");
    let bootstrap = temp.path().join("dry.tzap.bootstrap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"dry run payload\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--bootstrap-out",
            bootstrap.to_str().unwrap(),
            "--dry-run",
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("create dry-run summary:"))
        .stderr(predicate::str::contains("files: 1"))
        .stderr(predicate::str::contains("input bytes: 16"))
        .stderr(predicate::str::contains("key mode: keyfile"))
        .stderr(predicate::str::contains("planned archive paths:"))
        .stderr(predicate::str::contains("bootstrap"));

    assert!(!archive.exists());
    assert!(!bootstrap.exists());
}

#[test]
fn cli_create_rejects_existing_output_without_force() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let output = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello from tzap\n").unwrap();
    fs::write(&output, b"existing\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("already exists"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--force",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();
}

#[test]
fn cli_create_rejects_existing_multi_volume_outputs_without_force() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("striped.txt");
    let output = temp.path().join("striped.tzap");
    let output_volume_0 = numbered_volume_path(&output, 0);
    let output_volume_1 = numbered_volume_path(&output, 1);

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"multi-volume payload\n").unwrap();
    fs::write(&output_volume_0, b"collision\n").unwrap();
    fs::write(&output_volume_1, b"collision\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--volumes",
            "2",
            "-o",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn cli_create_rejects_existing_bootstrap_output_without_force() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let output = temp.path().join("sample.tzap");
    let bootstrap = temp.path().join("sample.tzap.bootstrap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello from tzap\n").unwrap();
    fs::write(&bootstrap, b"existing bootstrap\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--bootstrap-out",
            bootstrap.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn cli_create_rejects_archive_bootstrap_output_alias_even_with_force() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("hello.txt");
    let output = temp.path().join("sample.tzap");
    let aliased_bootstrap = temp.path().join(".").join("sample.tzap");

    fs::write(&input, b"hello from tzap\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--no-encryption",
            "--force",
            "--bootstrap-out",
            aliased_bootstrap.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("must be different paths"));
    assert!(!output.exists());
}

#[test]
fn cli_create_rejects_volume_size_output_collisions_for_dotted_base() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("sized.bin");
    let output = temp.path().join("sized.tzap");
    let collision = numbered_volume_path(&output, 0);
    let mut data = Vec::with_capacity(64 * 1024);
    for i in 0..(64 * 1024) {
        data.push((i % 251) as u8);
    }

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, &data).unwrap();
    fs::write(&collision, b"collision\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--volume-size",
            "8K",
            "--block-size",
            "4K",
            "--chunk-size",
            "4K",
            "--envelope-size",
            "128K",
            "-o",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("output path collision"));
}

#[cfg(target_os = "linux")]
#[test]
fn cli_create_archives_char_device_descriptor() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let output = temp.path().join("char.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            "/dev/null",
        ])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "list",
            "--long",
            "--keyfile",
            keyfile.to_str().unwrap(),
            output.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("character-device"));
}

#[cfg(target_os = "linux")]
#[test]
fn cli_create_archives_unopenable_block_device_descriptor_when_privileged() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let temp = tempdir().unwrap();
    let input = temp.path().join("unused-block-device");
    let output = temp.path().join("block.tzap");
    let input_c = CString::new(input.as_os_str().as_bytes()).unwrap();
    let status = unsafe {
        libc::mknod(
            input_c.as_ptr(),
            libc::S_IFBLK | 0o600,
            libc::makedev(240, 2),
        )
    };
    if status != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EPERM) {
            return;
        }
        panic!("failed to create block-device descriptor: {error}");
    }

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--no-encryption",
            "-o",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["list", "--long", output.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("block-device"));
}

#[cfg(unix)]
#[test]
fn cli_symlink_target_and_mtime_round_trip_without_following_target() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;

    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let output = temp.path().join("symlink.tzap");
    let link = temp.path().join("link.txt");
    let extract_dir = temp.path().join("extract");
    let restored_target = extract_dir.join("target.txt");

    fs::write(&keyfile, KEY_HEX).unwrap();
    std::os::unix::fs::symlink("target.txt", &link).unwrap();
    let link_path = CString::new(link.as_os_str().as_bytes()).unwrap();
    let expected_access_seconds = 1_699_000_123;
    let expected_access_nanoseconds = 123_456_000;
    let expected_seconds = 1_700_000_321;
    let expected_nanoseconds = 654_321_000;
    let times = [
        libc::timespec {
            tv_sec: expected_access_seconds,
            tv_nsec: expected_access_nanoseconds,
        },
        libc::timespec {
            tv_sec: expected_seconds,
            tv_nsec: expected_nanoseconds,
        },
    ];
    // SAFETY: the path and timespec array remain live for this call, and the
    // no-follow flag applies the timestamp to the link itself.
    assert_eq!(
        unsafe {
            libc::utimensat(
                libc::AT_FDCWD,
                link_path.as_ptr(),
                times.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        },
        0
    );

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            link.to_str().unwrap(),
        ])
        .assert()
        .success();

    fs::create_dir(&extract_dir).unwrap();
    fs::write(&restored_target, b"must not be touched").unwrap();
    let target_before = fs::symlink_metadata(&restored_target).unwrap();
    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--restore",
            "portable",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-C",
            extract_dir.to_str().unwrap(),
            output.to_str().unwrap(),
        ])
        .assert()
        .success();

    let restored_link = extract_dir.join("link.txt");
    let restored = fs::symlink_metadata(&restored_link).unwrap();
    assert_ne!(
        (restored.atime(), restored.atime_nsec()),
        (expected_access_seconds, expected_access_nanoseconds),
        "portable restore must not replay source atime"
    );
    assert_eq!(
        fs::read_link(&restored_link).unwrap(),
        Path::new("target.txt")
    );
    assert_eq!(restored.mtime(), expected_seconds);
    assert_eq!(restored.mtime_nsec(), expected_nanoseconds);
    let target_after = fs::symlink_metadata(restored_target).unwrap();
    assert_eq!(target_after.mtime(), target_before.mtime());
    assert_eq!(target_after.mtime_nsec(), target_before.mtime_nsec());
    assert_eq!(target_after.len(), target_before.len());
}

#[cfg(unix)]
#[test]
fn cli_extract_allow_absolute_symlinks_toggle() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let archive = temp.path().join("abs_symlink.tzap");
    let link = temp.path().join("abs_link");
    let extract_disallowed = temp.path().join("extract_disallowed");
    let extract_allowed = temp.path().join("extract_allowed");

    fs::write(&keyfile, KEY_HEX).unwrap();
    std::os::unix::fs::symlink("/tmp/abs_target", &link).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .arg("create")
        .arg("--output")
        .arg(&archive)
        .arg(&link)
        .arg("--keyfile")
        .arg(&keyfile)
        .assert()
        .success();

    // Default extraction rejects absolute symlink
    Command::cargo_bin("tzap")
        .unwrap()
        .arg("extract")
        .arg(&archive)
        .arg("-C")
        .arg(&extract_disallowed)
        .arg("--keyfile")
        .arg(&keyfile)
        .assert()
        .failure();

    // Extraction with --allow-absolute-symlinks succeeds
    Command::cargo_bin("tzap")
        .unwrap()
        .arg("extract")
        .arg(&archive)
        .arg("-C")
        .arg(&extract_allowed)
        .arg("--allow-absolute-symlinks")
        .arg("--keyfile")
        .arg(&keyfile)
        .assert()
        .success();

    let restored_link = extract_allowed.join("abs_link");
    assert_eq!(
        fs::read_link(&restored_link).unwrap(),
        Path::new("/tmp/abs_target")
    );
}

#[cfg(windows)]
#[test]
fn cli_create_rejects_windows_reserved_device_path_input() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let output = temp.path().join("reserved.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            "CON",
        ])
        .assert()
        .failure();
}

#[test]
fn cli_create_rejects_volumes_zero() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let output = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--volumes",
            "0",
            "-o",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("--volumes must be at least 1"));
}

#[test]
fn cli_create_rejects_volume_loss_tolerance_out_of_range() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let output = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--volume-loss-tolerance",
            "2",
            "-o",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .code(16)
        .stderr(predicate::str::contains("unsupported-feature"));
}

#[test]
fn cli_create_rejects_chunk_size_larger_than_envelope_size() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let output = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--chunk-size",
            "4M",
            "--envelope-size",
            "1M",
            "-o",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .code(16)
        .stderr(predicate::str::contains("unsupported-feature"));
}

#[test]
fn cli_create_rejects_size_overflow() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let output = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--volume-size",
            "18446744073709551615K",
            "-o",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("size overflow"));
}

#[test]
fn cli_create_rejects_unsupported_writer_scope() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let output = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--block-size",
            "3",
            "-o",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .code(16)
        .stderr(predicate::str::contains("unsupported-feature"));
}

#[test]
fn cli_create_rejects_archive_stdout_output_sentinel_before_writing() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let dash_output = temp.path().join("-");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .current_dir(temp.path())
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            "-",
            input.to_str().unwrap(),
        ])
        .assert()
        .code(16)
        .stderr(predicate::str::contains("unsupported-feature"))
        .stderr(predicate::str::contains("--output - is not archive stdout"));

    assert!(!dash_output.exists());
}

#[test]
fn cli_create_rejects_sidecar_stdout_output_sentinel_before_writing() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");
    let dash_output = temp.path().join("-");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .current_dir(temp.path())
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--bootstrap-out",
            "-",
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .code(16)
        .stderr(predicate::str::contains("unsupported-feature"))
        .stderr(predicate::str::contains(
            "--bootstrap-out - is not sidecar stdout",
        ));

    assert!(!archive.exists());
    assert!(!dash_output.exists());
}

#[test]
fn cli_create_with_volume_size_splits_archive_by_target_size() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("sized.bin");
    let output_base = temp.path().join("sized.tzap");
    let target_size = 8 * 1024u64;

    fs::write(&keyfile, KEY_HEX).unwrap();
    let mut data = Vec::with_capacity(64 * 1024);
    let mut state = 0x1234_5678u32;
    for _ in 0..64 * 1024 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        data.push((state >> 24) as u8);
    }
    fs::write(&input, data).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--volume-size",
            "8K",
            "--volume-loss-tolerance",
            "1",
            "--block-size",
            "4K",
            "--chunk-size",
            "4K",
            "--envelope-size",
            "128K",
            "-o",
            output_base.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("volume(s)"));

    let mut volumes = Vec::new();
    for index in 0.. {
        let volume = numbered_volume_path(&output_base, index);
        if !volume.exists() {
            break;
        }
        assert!(
            fs::metadata(&volume).unwrap().len() <= target_size,
            "{} exceeded target volume size",
            volume.display()
        );
        volumes.push(volume);
    }
    assert!(volumes.len() > 1);

    let mut args = vec![
        "verify".to_owned(),
        "--keyfile".to_owned(),
        keyfile.to_str().unwrap().to_owned(),
    ];
    args.extend(
        volumes
            .iter()
            .map(|volume| volume.to_str().unwrap().to_owned()),
    );
    Command::cargo_bin("tzap")
        .unwrap()
        .args(args)
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));
}

#[test]
fn cli_extracts_archive_created_with_volume_size_split() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("sized-extract.bin");
    let output_base = temp.path().join("sized-extract.tzap");
    let output = temp.path().join("out");
    let expected = (0..64 * 1024)
        .map(|idx| ((idx * 37 + 11) % 251) as u8)
        .collect::<Vec<_>>();

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, &expected).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--volume-size",
            "8K",
            "--volume-loss-tolerance",
            "1",
            "--block-size",
            "4K",
            "--chunk-size",
            "4K",
            "--envelope-size",
            "128K",
            "-o",
            output_base.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();

    let mut volume_args = Vec::new();
    for index in 0.. {
        let volume = numbered_volume_path(&output_base, index);
        if !volume.exists() {
            break;
        }
        volume_args.push(volume);
    }
    assert!(volume_args.len() > 1);

    let mut args = vec![
        "extract".to_owned(),
        "--keyfile".to_owned(),
        keyfile.to_str().unwrap().to_owned(),
        "--directory".to_owned(),
        output.to_str().unwrap().to_owned(),
        volume_args[0].to_str().unwrap().to_owned(),
    ];
    for volume in &volume_args[1..] {
        args.push("--volume".to_owned());
        args.push(volume.to_str().unwrap().to_owned());
    }
    args.push("sized-extract.bin".to_owned());

    Command::cargo_bin("tzap")
        .unwrap()
        .args(args)
        .assert()
        .success()
        .stderr(predicate::str::contains("extracted 1 file(s)"));

    assert_eq!(
        fs::read(output.join("sized-extract.bin")).unwrap(),
        expected
    );
}

fn is_lower_hex_byte(byte: u8) -> bool {
    matches!(byte, b'0'..=b'9' | b'a'..=b'f')
}

fn is_lower_hex_str(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

#[test]
fn cli_keygen_stdout_emits_hex_key_and_newline() {
    let output = Command::cargo_bin("tzap")
        .unwrap()
        .args(["keygen", "--stdout"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert_eq!(output.len(), 65, "expected 64 hex chars plus newline");
    assert_eq!(output.last(), Some(&b'\n'));
    assert!(output[..64].iter().all(|byte| is_lower_hex_byte(*byte)));
}

#[test]
fn cli_keygen_with_global_quiet_suppresses_success_summary() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("seed.hex");

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["keygen", "--quiet", "--output", keyfile.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::is_empty());
    assert!(keyfile.exists());
}

#[test]
fn cli_keygen_with_global_quiet_stdout_still_outputs_hex_key() {
    let output = Command::cargo_bin("tzap")
        .unwrap()
        .args(["keygen", "--quiet", "--stdout"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert_eq!(output.len(), 65, "expected 64 hex chars plus newline");
    assert_eq!(output.last(), Some(&b'\n'));
    assert!(output[..64].iter().all(|byte| is_lower_hex_byte(*byte)));
}

#[test]
fn cli_keygen_writes_keyfile_output_with_force_semantics() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("seed.hex");

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["keygen", "--output", keyfile.to_str().unwrap()])
        .assert()
        .success();
    assert!(keyfile.exists());
    let written = fs::read_to_string(&keyfile).unwrap();
    assert_eq!(written.len(), 65);
    assert_eq!(written.as_bytes()[64], b'\n');
    assert!(is_lower_hex_str(&written[..64]));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&keyfile).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["keygen", "--output", keyfile.to_str().unwrap()])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("already exists"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["keygen", "--force", "--output", keyfile.to_str().unwrap()])
        .assert()
        .success();
}

#[test]
fn cli_signing_keygen_writes_restrictive_secret_output() {
    let temp = tempdir().unwrap();
    let secret = temp.path().join("root.signing.hex");
    let public = temp.path().join("root.public.hex");

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "signing-keygen",
            "--secret-output",
            secret.to_str().unwrap(),
            "--public-output",
            public.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(fs::read_to_string(&secret).unwrap().len(), 65);
    assert_eq!(fs::read_to_string(&public).unwrap().len(), 65);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&secret).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[test]
fn cli_signing_keygen_rejects_aliased_secret_and_public_outputs() {
    let temp = tempdir().unwrap();
    let secret = temp.path().join("root.signing.hex");
    let public_alias = temp.path().join(".").join("root.signing.hex");

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "signing-keygen",
            "--force",
            "--secret-output",
            secret.to_str().unwrap(),
            "--public-output",
            public_alias.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("must be different paths"));
    assert!(!secret.exists());
}

#[test]
fn cli_keygen_rejects_missing_output_path_without_stdout_or_output() {
    Command::cargo_bin("tzap")
        .unwrap()
        .args(["keygen"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("required"));
}

#[test]
fn cli_create_with_password_stdin_strips_line_endings_and_preserves_spaces() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("secret.txt");
    let archive = temp.path().join("secret.tzap");
    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"secret\n").unwrap();

    for (pass, args) in [
        (
            "linefeed pass\n",
            vec![
                "create",
                "--password-stdin",
                "--argon2-t-cost",
                "1",
                "--argon2-m-cost-kib",
                "8",
                "--argon2-parallelism",
                "1",
                "-o",
                archive.to_str().unwrap(),
                input.to_str().unwrap(),
            ],
        ),
        (
            "crlf-pass\r\n",
            vec![
                "create",
                "--password-stdin",
                "--argon2-t-cost",
                "1",
                "--argon2-m-cost-kib",
                "8",
                "--argon2-parallelism",
                "1",
                "-o",
                archive.to_str().unwrap(),
                input.to_str().unwrap(),
            ],
        ),
        (
            "in tern al spaces\n",
            vec![
                "create",
                "--password-stdin",
                "--argon2-t-cost",
                "1",
                "--argon2-m-cost-kib",
                "8",
                "--argon2-parallelism",
                "1",
                "-o",
                archive.to_str().unwrap(),
                input.to_str().unwrap(),
            ],
        ),
    ] {
        Command::cargo_bin("tzap")
            .unwrap()
            .args(args.clone())
            .write_stdin(pass)
            .assert()
            .success();

        Command::cargo_bin("tzap")
            .unwrap()
            .args(["verify", "--password-stdin", archive.to_str().unwrap()])
            .write_stdin(pass)
            .assert()
            .success()
            .stdout(predicate::str::contains("OK"));

        fs::remove_file(&archive).unwrap();
    }
}

#[test]
fn cli_create_with_password_stdin_rejects_empty_passphrase() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("secret.txt");
    let archive = temp.path().join("secret.tzap");
    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"secret\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--password-stdin",
            "--argon2-t-cost",
            "1",
            "--argon2-m-cost-kib",
            "8",
            "--argon2-parallelism",
            "1",
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .write_stdin("\n")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("passphrase must not be empty"));
}

#[test]
fn cli_create_rejects_invalid_argon2_parameters_as_usage_error() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("password.tzap");
    fs::write(&input, b"hello\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--password-stdin",
            "--argon2-m-cost-kib",
            "4194305",
            "--argon2-t-cost",
            "1",
            "--argon2-parallelism",
            "1",
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .write_stdin("secret\n")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid-arguments"));
}

#[test]
fn cli_keyfile_raw_bytes_and_hex_with_whitespace_are_accepted() {
    let temp = tempdir().unwrap();
    let raw_keyfile = temp.path().join("raw.key");
    let hex_keyfile = temp.path().join("spaced.hex");
    let input = temp.path().join("hello.txt");
    let output_raw = temp.path().join("raw.tzap");
    let output_hex = temp.path().join("hex.tzap");

    fs::write(&raw_keyfile, [0x42u8; 32]).unwrap();
    fs::write(&hex_keyfile, format!("  {}\n", KEY_HEX)).unwrap();
    fs::write(&input, b"hello\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            raw_keyfile.to_str().unwrap(),
            "-o",
            output_raw.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            hex_keyfile.to_str().unwrap(),
            "-o",
            output_hex.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();
}

#[test]
fn cli_keyfile_with_invalid_hex_and_wrong_length_is_rejected() {
    let temp = tempdir().unwrap();
    let invalid_hex = temp.path().join("invalid-hex.txt");
    let invalid_len = temp.path().join("invalid-len.txt");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");

    let mut invalid_hex_bytes = [b'0'; 64];
    invalid_hex_bytes[63] = b'g';
    fs::write(&invalid_hex, invalid_hex_bytes).unwrap();
    fs::write(&invalid_len, [0x42u8; 31]).unwrap();
    fs::write(&input, b"hello\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            invalid_hex.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("non-hex"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            invalid_len.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "keyfile must contain either 32 raw bytes or 64 hex characters",
        ));
}

#[test]
fn cli_extract_with_password_prompt_and_stdin_fallback() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("secret.txt");
    let archive = temp.path().join("password.tzap");
    let output_dir = temp.path().join("out");
    let passphrase = "prompt backup phrase\n";

    fs::write(&input, b"payload\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--password-stdin",
            "--argon2-t-cost",
            "1",
            "--argon2-m-cost-kib",
            "8",
            "--argon2-parallelism",
            "1",
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .write_stdin(passphrase)
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--password",
            "-C",
            output_dir.to_str().unwrap(),
            archive.to_str().unwrap(),
            "secret.txt",
        ])
        .write_stdin(passphrase)
        .assert()
        .success()
        .stderr(predicate::str::contains("Passphrase:"));

    assert_eq!(
        fs::read(output_dir.join("secret.txt")).unwrap(),
        b"payload\n"
    );
}

#[test]
fn cli_list_with_password_prompt_and_stdin_fallback() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("secret.txt");
    let archive = temp.path().join("password.tzap");
    let passphrase = "prompt backup phrase\n";

    fs::write(&input, b"payload\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--password-stdin",
            "--argon2-t-cost",
            "1",
            "--argon2-m-cost-kib",
            "8",
            "--argon2-parallelism",
            "1",
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .write_stdin(passphrase)
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["list", "--password", archive.to_str().unwrap()])
        .write_stdin(passphrase)
        .assert()
        .success()
        .stdout(predicate::str::contains("secret.txt\n"));
}

#[test]
fn cli_list_one_file_archive_with_keyfile() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("secret.txt");
    let archive = temp.path().join("password.tzap");
    let keyfile = temp.path().join("key.hex");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"payload\n").unwrap();

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

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "list",
            "--keyfile",
            keyfile.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::eq("secret.txt\n"));
}

#[test]
fn cli_default_list_uses_index_entries_not_payload_metadata() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("payload.txt");
    let archive = temp.path().join("payload.tzap");
    let keyfile = temp.path().join("key.hex");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"payload\n").unwrap();

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

    let mut bytes = fs::read(&archive).unwrap();
    corrupt_first_record_of_kind(&mut bytes, BlockKind::PayloadData);
    fs::write(&archive, bytes).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "list",
            "--keyfile",
            keyfile.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::eq("payload.txt\n"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "list",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--long",
            archive.to_str().unwrap(),
        ])
        .assert()
        .code(11)
        .stderr(predicate::str::contains("corrupt-payload"));
}

#[test]
fn cli_list_with_long_output_includes_kind_mode_mtime() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("payload.bin");
    let archive = temp.path().join("payload.tzap");
    let keyfile = temp.path().join("key.hex");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"abcde\n").unwrap();
    let expected_mode = expected_input_mode(&input);
    let modified = fs::metadata(&input).unwrap().modified().unwrap();
    let modified_since_epoch = modified.duration_since(std::time::UNIX_EPOCH).unwrap();
    let expected_mtime = ArchiveTimestamp {
        seconds: i64::try_from(modified_since_epoch.as_secs()).unwrap(),
        nanoseconds: modified_since_epoch.subsec_nanos(),
    };

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

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "list",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--long",
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::eq(format!(
            "6\tfile\t{expected_mode}\t{expected_mtime}\tpayload.bin\n"
        )));
}

#[cfg(unix)]
#[test]
fn cli_list_with_long_output_preserves_unix_mode_bits() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let temp = tempdir().unwrap();
    let input = temp.path().join("script.sh");
    let archive = temp.path().join("script.tzap");
    let keyfile = temp.path().join("key.hex");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"echo hello\n").unwrap();
    let mut permissions = fs::metadata(&input).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&input, permissions).unwrap();
    let source_metadata = fs::metadata(&input).unwrap();
    let expected_mtime =
        ArchiveTimestamp::new(source_metadata.mtime(), source_metadata.mtime_nsec() as u32)
            .to_string();

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

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "list",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--long",
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::eq(format!(
            "11\tfile\t448\t{expected_mtime}\tscript.sh\n"
        )));
}

#[test]
fn cli_list_outputs_stable_json() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("json.txt");
    let archive = temp.path().join("json.tzap");
    let keyfile = temp.path().join("key.hex");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"json payload").unwrap();

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

    let output = Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "list",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--json",
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(
        value.get("metadata_source").unwrap().as_str().unwrap(),
        "index"
    );
    let files = value.get("files").unwrap().as_array().unwrap();
    assert_eq!(files.len(), 1);
    let file = &files[0];
    assert_eq!(file.get("path").unwrap().as_str().unwrap(), "json.txt");
    assert_eq!(file.get("name").unwrap().as_str().unwrap(), "json.txt");
    assert_eq!(file.get("size").unwrap().as_u64().unwrap(), 12);
    let flags = file.get("flags").unwrap().as_u64().unwrap();
    assert_eq!(flags & 1, 1);
    if cfg!(unix) {
        assert_ne!(flags, 1, "native metadata flags should be present on Unix");
    }
    assert!(file.get("path_hash").unwrap().as_str().unwrap().len() == 16);
    assert!(file.get("tar_member_group_size").unwrap().as_u64().unwrap() >= 1536);
    assert_eq!(file.get("first_frame_index").unwrap().as_u64().unwrap(), 0);
    assert_eq!(file.get("frame_count").unwrap().as_u64().unwrap(), 1);
    assert!(file.get("compressed_size").unwrap().as_u64().unwrap() > 0);
    let layout = file.get("layout").unwrap();
    assert_eq!(layout.get("envelope_count").unwrap().as_u64().unwrap(), 1);
    assert_eq!(
        layout
            .get("first_payload_block_index")
            .unwrap()
            .as_u64()
            .unwrap(),
        0
    );
}

#[test]
fn cli_list_supports_directory_only_archive() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input_root = temp.path().join("empty-root");
    let archive = temp.path().join("empty.tzap");

    fs::create_dir_all(input_root.join("nested").join("directories")).unwrap();
    fs::write(&keyfile, KEY_HEX).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input_root.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "list",
            "--keyfile",
            keyfile.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::eq(
            "empty-root\nempty-root/nested\nempty-root/nested/directories\n",
        ));
}

#[test]
fn cli_list_with_bootstrap_supports_passed_bootstrap_file() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("payload.txt");
    let archive = temp.path().join("payload.tzap");
    let bootstrap = temp.path().join("payload.tzap.bootstrap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"payload\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--bootstrap-out",
            bootstrap.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "list",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--bootstrap",
            bootstrap.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("payload.txt\n"));
}

#[test]
fn cli_list_rejects_long_with_json() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("reject.txt");
    let archive = temp.path().join("reject.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"payload\n").unwrap();

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

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "list",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--long",
            "--json",
            archive.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn cli_list_wrong_key_is_reported_with_stable_category() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let bad_keyfile = temp.path().join("bad-key.hex");
    let input = temp.path().join("payload.txt");
    let archive = temp.path().join("wrong-key.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&bad_keyfile, BAD_KEY_HEX).unwrap();
    fs::write(&input, b"payload\n").unwrap();

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

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "list",
            "--keyfile",
            bad_keyfile.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .code(10)
        .stderr(predicate::str::contains("wrong-key"));
}

#[test]
fn cli_list_corrupt_archive_reports_corruption() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("payload.txt");
    let archive = temp.path().join("corrupt.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"payload\n").unwrap();

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

    let mut bytes = fs::read(&archive).unwrap();
    corrupt_first_record_of_kind(&mut bytes, BlockKind::IndexShardData);
    fs::write(&archive, bytes).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "list",
            "--keyfile",
            keyfile.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .code(11)
        .stderr(predicate::str::contains("corrupt-payload"));
}

#[test]
fn cli_list_missing_archive_path_is_io_error() {
    let temp = tempdir().unwrap();
    let missing = temp.path().join("missing.tzap");
    let keyfile = temp.path().join("key.hex");

    fs::write(&keyfile, KEY_HEX).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "list",
            "--keyfile",
            keyfile.to_str().unwrap(),
            missing.to_str().unwrap(),
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("failed to read archive"));
}

#[test]
fn cli_list_missing_bootstrap_file_is_an_io_error() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("payload.txt");
    let archive = temp.path().join("payload.tzap");
    let bootstrap = temp.path().join("payload.tzap.bootstrap");
    let missing = temp.path().join("payload.tzap.bootstrap.missing");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"payload\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--bootstrap-out",
            bootstrap.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();
    fs::rename(&bootstrap, &missing).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "list",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--bootstrap",
            bootstrap.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("failed to read bootstrap sidecar"));
}

#[test]
fn cli_verify_with_password_prompt_and_stdin_fallback() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("secret.txt");
    let archive = temp.path().join("password.tzap");
    let passphrase = "prompt backup phrase\n";

    fs::write(&input, b"payload\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--password-stdin",
            "--argon2-t-cost",
            "1",
            "--argon2-m-cost-kib",
            "8",
            "--argon2-parallelism",
            "1",
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .write_stdin(passphrase)
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", "--password", archive.to_str().unwrap()])
        .write_stdin(passphrase)
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));
}

#[test]
fn cli_extract_all_files_to_default_directory() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input_root = temp.path().join("input");
    let input = input_root.join("hello.txt");
    let archive = temp.path().join("sample.tzap");
    let output_dir = temp.path().join("extract");
    let payload = b"destination default\n";

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::create_dir_all(&input_root).unwrap();
    fs::write(&input, payload).unwrap();
    fs::create_dir(&output_dir).unwrap();

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

    Command::cargo_bin("tzap")
        .unwrap()
        .current_dir(&output_dir)
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "../sample.tzap",
        ])
        .assert()
        .success();

    assert_eq!(fs::read(output_dir.join("hello.txt")).unwrap(), payload);
}

#[test]
fn cli_extract_all_files_to_specified_directory() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input_root = temp.path().join("input-dir");
    let archive = temp.path().join("tree.tzap");
    let output = temp.path().join("out");
    let expected = b"tree extraction\n";

    fs::create_dir_all(&input_root).unwrap();
    fs::write(input_root.join("a.txt"), expected).unwrap();
    fs::write(input_root.join("b.txt"), b"skip this\n").unwrap();
    fs::write(&keyfile, KEY_HEX).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input_root.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--directory",
            output.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(output.join("input-dir").join("a.txt")).unwrap(),
        expected
    );
}

#[test]
fn cli_extract_selected_file_paths() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input_root = temp.path().join("input");
    let archive = temp.path().join("selected.tzap");
    let output = temp.path().join("out");

    fs::create_dir_all(&input_root).unwrap();
    fs::write(input_root.join("a.txt"), b"a\n").unwrap();
    fs::write(input_root.join("b.txt"), b"b\n").unwrap();
    fs::write(&keyfile, KEY_HEX).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input_root.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--directory",
            output.to_str().unwrap(),
            archive.to_str().unwrap(),
            "input/a.txt",
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(output.join("input").join("a.txt")).unwrap(),
        b"a\n"
    );
    assert!(!output.join("input").join("b.txt").exists());
}

#[test]
fn cli_extract_multiple_selected_file_paths() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input_root = temp.path().join("input");
    let archive = temp.path().join("selected.tzap");
    let output = temp.path().join("out");

    fs::create_dir_all(&input_root).unwrap();
    fs::write(input_root.join("a.txt"), b"a\n").unwrap();
    fs::write(input_root.join("b.txt"), b"b\n").unwrap();
    fs::write(&keyfile, KEY_HEX).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input_root.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--directory",
            output.to_str().unwrap(),
            archive.to_str().unwrap(),
            "input/a.txt",
            "input/b.txt",
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(output.join("input").join("a.txt")).unwrap(),
        b"a\n"
    );
    assert_eq!(
        fs::read(output.join("input").join("b.txt")).unwrap(),
        b"b\n"
    );
}

#[test]
fn cli_extract_to_stdout_with_valid_single_file() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");
    let payload = b"stdout payload\n";

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, payload).unwrap();

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

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--stdout",
            archive.to_str().unwrap(),
            "hello.txt",
        ])
        .assert()
        .success()
        .stdout(predicate::eq(payload.to_vec()));
}

#[test]
fn cli_extract_with_overwrite_enabled() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");
    let output = temp.path().join("out");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"updated payload\n").unwrap();
    fs::create_dir(&output).unwrap();
    fs::write(output.join("hello.txt"), b"already there").unwrap();

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

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--directory",
            output.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .code(13)
        .stderr(predicate::str::contains("unsafe-path"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--overwrite",
            "--directory",
            output.to_str().unwrap(),
            archive.to_str().unwrap(),
            "hello.txt",
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(output.join("hello.txt")).unwrap(),
        b"updated payload\n"
    );
}

#[test]
fn cli_extract_with_passphrase_is_supported_and_safe() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("secret.txt");
    let archive = temp.path().join("password.tzap");
    let output = temp.path().join("out");
    let passphrase = "extract-passphrase\n";

    fs::write(&input, b"passphrase payload\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--password-stdin",
            "--argon2-t-cost",
            "1",
            "--argon2-m-cost-kib",
            "8",
            "--argon2-parallelism",
            "1",
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .write_stdin(passphrase)
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--password-stdin",
            "--directory",
            output.to_str().unwrap(),
            archive.to_str().unwrap(),
            "secret.txt",
        ])
        .write_stdin(passphrase)
        .assert()
        .success();

    assert_eq!(
        fs::read(output.join("secret.txt")).unwrap(),
        b"passphrase payload\n"
    );
}

#[test]
fn cli_extracts_password_multivolume_archive_with_missing_recoverable_volume() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("password-volume.bin");
    let output_base = temp.path().join("password-volume.tzap");
    let output = temp.path().join("out");
    let passphrase = "split passphrase recovery\n";
    let expected = (0..128 * 1024)
        .map(|idx| ((idx * 17 + 29) % 251) as u8)
        .collect::<Vec<_>>();

    fs::write(&input, &expected).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--password-stdin",
            "--argon2-t-cost",
            "1",
            "--argon2-m-cost-kib",
            "8",
            "--argon2-parallelism",
            "1",
            "--volumes",
            "3",
            "--volume-loss-tolerance",
            "1",
            "-o",
            output_base.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .write_stdin(passphrase)
        .assert()
        .success();

    let v0 = numbered_volume_path(&output_base, 0);
    let v1 = numbered_volume_path(&output_base, 1);
    let v2 = numbered_volume_path(&output_base, 2);
    fs::remove_file(&v1).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--password-stdin",
            "--directory",
            output.to_str().unwrap(),
            v0.to_str().unwrap(),
            "--volume",
            v2.to_str().unwrap(),
            "password-volume.bin",
        ])
        .write_stdin(passphrase)
        .assert()
        .success()
        .stderr(predicate::str::contains("extracted 1 file(s)"));

    assert_eq!(
        fs::read(output.join("password-volume.bin")).unwrap(),
        expected
    );
}

#[test]
fn cli_extract_with_bootstrap_sidecar() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");
    let bootstrap = temp.path().join("sample.tzap.bootstrap");
    let output = temp.path().join("out");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"bootstrap payload\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--bootstrap-out",
            bootstrap.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--bootstrap",
            bootstrap.to_str().unwrap(),
            "--directory",
            output.to_str().unwrap(),
            archive.to_str().unwrap(),
            "hello.txt",
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(output.join("hello.txt")).unwrap(),
        b"bootstrap payload\n"
    );
}

#[test]
fn cli_extract_multi_volume_archive() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let output_base = temp.path().join("multi.tzap");
    let output = temp.path().join("out");
    let v0 = numbered_volume_path(&output_base, 0);
    let v1 = numbered_volume_path(&output_base, 1);
    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"multi-volume payload\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--volumes",
            "2",
            "--volume-loss-tolerance",
            "1",
            "-o",
            output_base.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--directory",
            output.to_str().unwrap(),
            v0.to_str().unwrap(),
            "--volume",
            v1.to_str().unwrap(),
            "hello.txt",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("extracted 1 file(s)"));

    assert_eq!(
        fs::read(output.join("hello.txt")).unwrap(),
        b"multi-volume payload\n"
    );
}

#[test]
fn cli_extract_recovers_when_one_volume_is_missing_but_tolerance_allows_it() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("payload.bin");
    let output_base = temp.path().join("recoverable.tzap");
    let output = temp.path().join("out");
    let mut data = vec![0u8; 64 * 1024];
    for (idx, byte) in data.iter_mut().enumerate() {
        *byte = (idx % 251) as u8;
    }

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, &data).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--volumes",
            "3",
            "--volume-loss-tolerance",
            "1",
            "-o",
            output_base.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();

    let v0 = numbered_volume_path(&output_base, 0);
    let v1 = numbered_volume_path(&output_base, 1);
    let v2 = numbered_volume_path(&output_base, 2);

    fs::remove_file(&v1).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--directory",
            output.to_str().unwrap(),
            v0.to_str().unwrap(),
            "--volume",
            v2.to_str().unwrap(),
            "payload.bin",
        ])
        .assert()
        .success();

    assert_eq!(fs::read(output.join("payload.bin")).unwrap(), data);
}

#[test]
fn cli_bit_rot_buffer_recovers_corrupted_payload_blocks_in_split_archive() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("bitrot.bin");
    let output_base = temp.path().join("bitrot.tzap");
    let output = temp.path().join("out");
    let mut expected = Vec::with_capacity(512 * 1024);
    let mut state = 0x1234_5678_9abc_def0u64;
    for _ in 0..512 * 1024 {
        state = state
            .wrapping_mul(2_862_933_555_777_941_757)
            .wrapping_add(3_037_000_493);
        expected.push((state >> 56) as u8);
    }

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, &expected).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--volumes",
            "3",
            "--bit-rot-buffer-pct",
            "5",
            "--block-size",
            "4K",
            "--chunk-size",
            "4K",
            "--envelope-size",
            "1M",
            "-o",
            output_base.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("bit-rot buffer 5%"));

    let volume_paths = vec![
        numbered_volume_path(&output_base, 0),
        numbered_volume_path(&output_base, 1),
        numbered_volume_path(&output_base, 2),
    ];
    for path in &volume_paths {
        assert!(path.exists(), "{} should exist", path.display());
    }
    let (corrupted_blocks, payload_blocks) = zero_deterministic_payload_blocks(&volume_paths, 4);
    assert!(
        corrupted_blocks * 100 <= payload_blocks * 5,
        "test must stay within the configured bit-rot buffer"
    );

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            keyfile.to_str().unwrap(),
            volume_paths[0].to_str().unwrap(),
            volume_paths[1].to_str().unwrap(),
            volume_paths[2].to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("(3 volume(s), 1 file(s))"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--directory",
            output.to_str().unwrap(),
            volume_paths[0].to_str().unwrap(),
            "--volume",
            volume_paths[1].to_str().unwrap(),
            "--volume",
            volume_paths[2].to_str().unwrap(),
            "bitrot.bin",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("extracted 1 file(s)"));

    assert_eq!(fs::read(output.join("bitrot.bin")).unwrap(), expected);
}

#[test]
fn cli_extract_reports_missing_archive_path_and_lists_missing_paths() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"payload\n").unwrap();

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

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            archive.to_str().unwrap(),
            "missing.txt",
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "missing archive path: missing.txt",
        ));
}

#[test]
fn cli_extract_stdout_requires_exactly_one_path() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("missing-key.hex");
    let archive = temp.path().join("missing-archive.tzap");

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--stdout",
            archive.to_str().unwrap(),
        ])
        .assert()
        .code(16)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("unsupported-feature"))
        .stderr(predicate::str::contains(
            "--stdout requires exactly one archive path",
        ))
        .stderr(predicate::str::contains("failed to read").not());

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--stdout",
            archive.to_str().unwrap(),
            "hello.txt",
            "hello.txt",
        ])
        .assert()
        .code(16)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("unsupported-feature"))
        .stderr(predicate::str::contains(
            "--stdout requires exactly one archive path",
        ))
        .stderr(predicate::str::contains("failed to read").not());
}

#[test]
fn cli_extract_dry_run_conflicts_with_stdout() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");
    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"payload\n").unwrap();

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

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--dry-run",
            "--stdout",
            "--keyfile",
            keyfile.to_str().unwrap(),
            archive.to_str().unwrap(),
            "hello.txt",
        ])
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn cli_extract_wrong_key_fails_with_stable_category() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let bad_key = temp.path().join("bad.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&bad_key, BAD_KEY_HEX).unwrap();
    fs::write(&input, b"payload\n").unwrap();

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

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            bad_key.to_str().unwrap(),
            archive.to_str().unwrap(),
            "hello.txt",
        ])
        .assert()
        .code(10)
        .stderr(predicate::str::contains("wrong-key"));
}

#[test]
fn cli_extract_corrupt_archive_reports_corruption() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"payload\n").unwrap();

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

    let mut bytes = fs::read(&archive).unwrap();
    corrupt_first_record_of_kind(&mut bytes, BlockKind::PayloadData);
    fs::write(&archive, bytes).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            archive.to_str().unwrap(),
            "hello.txt",
        ])
        .assert()
        .code(11)
        .stderr(predicate::str::contains("corrupt-payload"));
}

#[test]
fn cli_extract_without_overwrite_when_destination_exists_is_rejected() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");
    let output = temp.path().join("out");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"payload\n").unwrap();
    fs::create_dir(&output).unwrap();
    fs::write(output.join("hello.txt"), b"existing\n").unwrap();

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

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--directory",
            output.to_str().unwrap(),
            archive.to_str().unwrap(),
            "hello.txt",
        ])
        .assert()
        .code(13)
        .stderr(predicate::str::contains("unsafe-path"));
}

#[test]
fn cli_extract_unsafe_path_is_rejected_for_stdout() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"payload\n").unwrap();

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

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--stdout",
            archive.to_str().unwrap(),
            "../outside.txt",
        ])
        .assert()
        .code(13)
        .stderr(predicate::str::contains("unsafe-path"));
}

#[test]
fn cli_extract_missing_bootstrap_file_is_an_io_error() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");
    let missing = temp.path().join("sample.tzap.bootstrap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"payload\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--bootstrap-out",
            missing.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();
    fs::remove_file(&missing).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--bootstrap",
            missing.to_str().unwrap(),
            archive.to_str().unwrap(),
            "hello.txt",
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("failed to read bootstrap sidecar"));
}

#[test]
fn cli_create_rejects_bootstrap_out_with_multi_volume_with_unsupported_error() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("multi.tzap");
    let bootstrap = temp.path().join("multi.tzap.bootstrap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"payload\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--volumes",
            "2",
            "--bootstrap-out",
            bootstrap.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .code(16)
        .stderr(predicate::str::contains("unsupported-feature"))
        .stderr(predicate::str::contains(
            "--bootstrap-out is currently supported only for single-volume output",
        ));
    assert!(!numbered_volume_path(&archive, 0).exists());
    assert!(!numbered_volume_path(&archive, 1).exists());
    assert!(!bootstrap.exists());
}

#[test]
fn cli_create_rejects_bootstrap_out_with_volume_size_before_writing() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("split.tzap");
    let bootstrap = temp.path().join("split.tzap.bootstrap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"payload\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--volume-size",
            "1M",
            "--bootstrap-out",
            bootstrap.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .code(16)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("unsupported-feature"))
        .stderr(predicate::str::contains(
            "--bootstrap-out is currently supported only for single-volume output",
        ));
    assert!(!archive.exists());
    assert!(!numbered_volume_path(&archive, 0).exists());
    assert!(!bootstrap.exists());
}

#[test]
fn cli_extract_missing_volume_tolerates_recovery_when_loss_tolerance_allows() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let output_base = temp.path().join("recoverable.tzap");
    let output = temp.path().join("out");
    let v0 = numbered_volume_path(&output_base, 0);
    let v1 = numbered_volume_path(&output_base, 1);
    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"recovery check\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--volumes",
            "2",
            "--volume-loss-tolerance",
            "1",
            "-o",
            output_base.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();
    fs::remove_file(&v1).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--directory",
            output.to_str().unwrap(),
            v0.to_str().unwrap(),
            "hello.txt",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("extracted 1 file(s)"));
}

#[test]
fn cli_extract_missing_volume_without_tolerance_is_reported_as_corruption() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let output_base = temp.path().join("unrecoverable.tzap");
    let output = temp.path().join("out");
    let v0 = numbered_volume_path(&output_base, 0);
    let v1 = numbered_volume_path(&output_base, 1);
    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, vec![0x42u8; 1_000_000]).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--volumes",
            "2",
            "--volume-loss-tolerance",
            "0",
            "--bit-rot-buffer-pct",
            "0",
            "-o",
            output_base.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();
    fs::remove_file(&v0).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--directory",
            output.to_str().unwrap(),
            v1.to_str().unwrap(),
            "hello.txt",
        ])
        .assert()
        .code(11)
        .stderr(predicate::str::contains("missing-volume"));
}

#[test]
fn cli_extract_dry_run_prints_planned_members_and_rejects_missing_selection() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");
    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"payload\n").unwrap();

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

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--dry-run",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--directory",
            temp.path().join("out").to_str().unwrap(),
            archive.to_str().unwrap(),
            "hello.txt",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("extract dry-run summary"))
        .stderr(predicate::str::contains("hello.txt"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--dry-run",
            "--keyfile",
            keyfile.to_str().unwrap(),
            archive.to_str().unwrap(),
            "missing.txt",
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "missing archive path: missing.txt",
        ));
}

#[test]
fn cli_extract_summary_reports_counts() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input_root = temp.path().join("input");
    let archive = temp.path().join("sample.tzap");
    let output = temp.path().join("out");

    fs::create_dir_all(&input_root).unwrap();
    fs::write(input_root.join("a.txt"), b"a\n").unwrap();
    fs::write(input_root.join("b.txt"), b"b\n").unwrap();
    fs::write(&keyfile, KEY_HEX).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input_root.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--directory",
            output.to_str().unwrap(),
            archive.to_str().unwrap(),
            "input/a.txt",
            "input/b.txt",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("extracted 2 file(s)"));
}

#[test]
fn cli_extract_preserves_crlf_payload_bytes() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("payload.txt");
    let archive = temp.path().join("payload.tzap");
    let output = temp.path().join("out");
    let expected = b"line1\r\nline2\r\n";

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, expected).unwrap();

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

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--directory",
            output.to_str().unwrap(),
            archive.to_str().unwrap(),
            "payload.txt",
        ])
        .assert()
        .success();

    assert_eq!(fs::read(output.join("payload.txt")).unwrap(), expected);
}

fn test_ca_cert(cn: &str) -> (X509, PKey<Private>) {
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

fn test_leaf_cert(cn: &str, ca_cert: &X509Ref, ca_key: &PKeyRef<Private>) -> (X509, PKey<Private>) {
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

fn test_x25519_recipient_cert() -> (X509, Vec<u8>) {
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

fn random_serial_number() -> openssl::asn1::Asn1Integer {
    let mut serial = BigNum::new().unwrap();
    serial.rand(159, MsbOption::MAYBE_ZERO, false).unwrap();
    serial.to_asn1_integer().unwrap()
}
