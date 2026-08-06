// CLI integration tests (crate root): shared helpers plus cross-cutting tests
// (help/aliases/jobs, dash-as-archive-stdin, no-encryption, key-mode semantics),
// the `list` command tests, and stable error-category/exit-code tests.
mod common;
mod create;
mod errors;
mod extract;
mod keywrap;
mod verify;

use common::*;

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

#[cfg(target_os = "linux")]
#[test]
fn cli_linux_entry_kind_restore_policy_matrix() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::{symlink, FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
    use std::time::{Duration, UNIX_EPOCH};

    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input_root = temp.path().join("matrix");
    let directory = input_root.join("directory");
    let file = directory.join("file.txt");
    let link = input_root.join("link.txt");
    let fifo = input_root.join("events.fifo");
    let archive = temp.path().join("linux-policy-matrix.tzap");
    fs::create_dir_all(&directory).unwrap();
    fs::write(&file, b"matrix payload").unwrap();
    symlink("directory/file.txt", &link).unwrap();
    fs::write(&keyfile, KEY_HEX).unwrap();
    let fifo_c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o620) }, 0);

    fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o750)).unwrap();
    let expected_mtime = UNIX_EPOCH + Duration::new(1_700_000_321, 654_321_000);
    fs::File::open(&file)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(expected_mtime))
        .unwrap();
    fs::File::open(&directory)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(expected_mtime))
        .unwrap();

    let acl = [
        2, 0, 0, 0, // POSIX ACL xattr version
        1, 0, 6, 0, 0xff, 0xff, 0xff, 0xff, // owning user
        2, 0, 6, 0, 0x39, 0x30, 0, 0, // named user 12345
        4, 0, 4, 0, 0xff, 0xff, 0xff, 0xff, // owning group
        0x10, 0, 6, 0, 0xff, 0xff, 0xff, 0xff, // mask
        0x20, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, // other
    ];
    let mut directory_acl = acl;
    for permission_index in [6, 14, 30] {
        directory_acl[permission_index] = 7;
    }
    directory_acl[22] = 5;
    xattr::set(&file, "user.tzap.matrix", b"file metadata").unwrap();
    xattr::set(&file, "system.posix_acl_access", &acl).unwrap();
    xattr::set(&directory, "user.tzap.matrix", b"directory metadata").unwrap();
    xattr::set(&directory, "system.posix_acl_access", &directory_acl).unwrap();

    let source_file = fs::symlink_metadata(&file).unwrap();
    let source_directory = fs::symlink_metadata(&directory).unwrap();
    let source_fifo = fs::symlink_metadata(&fifo).unwrap();
    let expected_file_acl = xattr::get(&file, "system.posix_acl_access")
        .unwrap()
        .unwrap();
    let expected_directory_acl = xattr::get(&directory, "system.posix_acl_access")
        .unwrap()
        .unwrap();

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

    let policies: &[&str] = if unsafe { libc::geteuid() } == 0 {
        &["portable", "same-os", "system"]
    } else {
        &["portable", "same-os"]
    };
    for &policy in policies {
        let destination = temp.path().join(format!("extract-{policy}"));
        let mut command = Command::cargo_bin("tzap").unwrap();
        command.args([
            "extract",
            "--restore",
            policy,
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-C",
            destination.to_str().unwrap(),
        ]);
        if policy != "portable" {
            command.arg("--allow-degraded");
        }
        command.arg(archive.to_str().unwrap()).assert().success();

        let restored_root = destination.join("matrix");
        let restored_file = restored_root.join("directory/file.txt");
        let restored_directory = restored_root.join("directory");
        let restored_link = restored_root.join("link.txt");
        let restored_fifo = restored_root.join("events.fifo");
        let file_metadata = fs::symlink_metadata(&restored_file).unwrap();
        let directory_metadata = fs::symlink_metadata(&restored_directory).unwrap();

        assert_eq!(fs::read(&restored_file).unwrap(), b"matrix payload");
        assert_eq!(
            fs::read_link(&restored_link).unwrap(),
            Path::new("directory/file.txt")
        );
        assert_eq!(file_metadata.mode() & 0o7777, source_file.mode() & 0o7777);
        assert_eq!(
            directory_metadata.mode() & 0o7777,
            source_directory.mode() & 0o7777
        );
        assert_eq!(
            (file_metadata.mtime(), file_metadata.mtime_nsec()),
            (source_file.mtime(), source_file.mtime_nsec())
        );
        assert_eq!(
            (directory_metadata.mtime(), directory_metadata.mtime_nsec()),
            (source_directory.mtime(), source_directory.mtime_nsec())
        );

        if policy == "portable" {
            assert_eq!(
                xattr::get(&restored_file, "user.tzap.matrix").unwrap(),
                None
            );
            assert!(!restored_fifo.exists());
            continue;
        }

        assert_eq!(
            xattr::get(&restored_file, "user.tzap.matrix")
                .unwrap()
                .as_deref(),
            Some(b"file metadata".as_slice())
        );
        assert_eq!(
            xattr::get(&restored_directory, "user.tzap.matrix")
                .unwrap()
                .as_deref(),
            Some(b"directory metadata".as_slice())
        );
        assert_eq!(
            xattr::get(&restored_file, "system.posix_acl_access")
                .unwrap()
                .as_deref(),
            Some(expected_file_acl.as_slice())
        );
        assert_eq!(
            xattr::get(&restored_directory, "system.posix_acl_access")
                .unwrap()
                .as_deref(),
            Some(expected_directory_acl.as_slice())
        );

        if policy == "same-os" {
            assert!(!restored_fifo.exists());
        } else {
            let fifo_metadata = fs::symlink_metadata(&restored_fifo).unwrap();
            assert!(fifo_metadata.file_type().is_fifo());
            assert_eq!(fifo_metadata.mode() & 0o7777, source_fifo.mode() & 0o7777);
            assert_eq!(fifo_metadata.uid(), source_fifo.uid());
            assert_eq!(fifo_metadata.gid(), source_fifo.gid());
        }
    }
}

#[cfg(windows)]
#[test]
fn cli_windows_entry_kind_restore_policy_matrix() {
    use std::os::windows::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_READONLY,
    };

    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input_root = temp.path().join("matrix");
    let directory = input_root.join("directory");
    let file = directory.join("file.txt");
    let link = input_root.join("link.txt");
    let archive = temp.path().join("windows-policy-matrix.tzap");
    fs::create_dir_all(&directory).unwrap();
    fs::write(&file, b"matrix payload").unwrap();
    create_windows_relative_symlink(&link, r"directory\file.txt");
    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(
        PathBuf::from(format!("{}:tzap.matrix", file.display())),
        b"file alternate data",
    )
    .unwrap();
    fs::write(
        PathBuf::from(format!("{}:tzap.matrix", directory.display())),
        b"directory alternate data",
    )
    .unwrap();

    let mut file_basic = windows_basic_info(&file, true);
    file_basic.CreationTime = 132_500_000_001_234_567;
    file_basic.LastAccessTime = 132_600_000_002_345_678;
    file_basic.LastWriteTime = 132_700_000_003_456_789;
    file_basic.ChangeTime = 132_800_000_004_567_890;
    file_basic.FileAttributes = FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_HIDDEN;
    set_windows_basic_info(&file, &file_basic);

    let mut directory_basic = windows_basic_info(&directory, true);
    directory_basic.CreationTime = 132_510_000_001_234_567;
    directory_basic.LastAccessTime = 132_610_000_002_345_678;
    directory_basic.LastWriteTime = 132_710_000_003_456_789;
    directory_basic.ChangeTime = 132_810_000_004_567_890;
    directory_basic.FileAttributes |= FILE_ATTRIBUTE_HIDDEN;
    set_windows_basic_info(&directory, &directory_basic);

    let source_file = windows_basic_info(&file, false);
    let source_directory = windows_basic_info(&directory, false);
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

    let policies: &[&str] = if windows_process_is_elevated() {
        &["portable", "same-os", "system"]
    } else {
        &["portable", "same-os"]
    };
    for &policy in policies {
        let destination = temp.path().join(format!("extract-{policy}"));
        let mut extract = Command::cargo_bin("tzap").unwrap();
        extract.args([
            "extract",
            "--restore",
            policy,
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-C",
            destination.to_str().unwrap(),
        ]);
        if policy == "portable" {
            // Portable restoration intentionally has no cross-platform
            // representation for Windows HIDDEN/SYSTEM/ARCHIVE bits.
            extract.arg("--allow-degraded");
        }
        extract.arg(archive.to_str().unwrap());
        extract.assert().success();

        let restored_root = destination.join("matrix");
        let restored_file = restored_root.join("directory/file.txt");
        let restored_directory = restored_root.join("directory");
        let restored_link = restored_root.join("link.txt");
        let file_metadata = fs::symlink_metadata(&restored_file).unwrap();
        let link_metadata = fs::symlink_metadata(&restored_link).unwrap();
        let restored_file_basic = windows_basic_info(&restored_file, false);
        let restored_directory_basic = windows_basic_info(&restored_directory, false);

        assert_eq!(fs::read(&restored_file).unwrap(), b"matrix payload");
        assert_eq!(
            fs::read_link(&restored_link).unwrap(),
            Path::new(r"directory\file.txt")
        );
        assert!(link_metadata.file_type().is_symlink());
        assert_eq!(
            file_metadata.last_write_time(),
            fs::symlink_metadata(&file).unwrap().last_write_time()
        );

        let restored_file_stream =
            PathBuf::from(format!("{}:tzap.matrix", restored_file.display()));
        let restored_directory_stream =
            PathBuf::from(format!("{}:tzap.matrix", restored_directory.display()));
        if policy == "portable" {
            assert!(!restored_file_stream.exists());
            assert!(!restored_directory_stream.exists());
            continue;
        }

        assert_eq!(restored_file_basic.CreationTime, source_file.CreationTime);
        assert_eq!(
            restored_file_basic.LastAccessTime,
            source_file.LastAccessTime
        );
        assert_eq!(restored_file_basic.LastWriteTime, source_file.LastWriteTime);
        assert_eq!(restored_file_basic.ChangeTime, source_file.ChangeTime);
        assert_eq!(
            restored_file_basic.FileAttributes
                & (FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_READONLY),
            source_file.FileAttributes
                & (FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_READONLY)
        );
        assert_eq!(
            restored_directory_basic.CreationTime,
            source_directory.CreationTime
        );
        assert_eq!(
            restored_directory_basic.LastAccessTime,
            source_directory.LastAccessTime
        );
        assert_eq!(
            restored_directory_basic.LastWriteTime,
            source_directory.LastWriteTime
        );
        assert_eq!(
            restored_directory_basic.ChangeTime,
            source_directory.ChangeTime
        );
        assert_eq!(
            fs::read(restored_file_stream).unwrap(),
            b"file alternate data"
        );
        assert_eq!(
            fs::read(restored_directory_stream).unwrap(),
            b"directory alternate data"
        );
        assert_ne!(source_link.file_attributes(), 0);
    }
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
fn cli_macos_entry_kind_restore_policy_matrix() {
    use std::ffi::CString;
    use std::os::macos::fs::MetadataExt as _;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::{symlink, FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
    use std::time::{Duration, UNIX_EPOCH};

    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input_root = temp.path().join("matrix");
    let directory = input_root.join("directory");
    let file = directory.join("file.txt");
    let link = input_root.join("link.txt");
    let fifo = input_root.join("events.fifo");
    let archive = temp.path().join("macos-policy-matrix.tzap");
    fs::create_dir_all(&directory).unwrap();
    fs::write(&file, b"matrix payload").unwrap();
    symlink("directory/file.txt", &link).unwrap();
    fs::write(&keyfile, KEY_HEX).unwrap();
    let fifo_c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o620) }, 0);

    fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o750)).unwrap();
    let expected_mtime = UNIX_EPOCH + Duration::new(1_700_000_321, 654_321_000);
    fs::File::open(&file)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(expected_mtime))
        .unwrap();
    fs::File::open(&directory)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(expected_mtime))
        .unwrap();

    for (path, marker) in [(&file, 0x41u8), (&directory, 0x42), (&fifo, 0x43)] {
        xattr::set(path, "com.tzap.matrix", &[marker; 19]).unwrap();
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
    xattr::set(&file, "com.apple.FinderInfo", &[0x51; 32]).unwrap();
    xattr::set(&directory, "com.apple.FinderInfo", &[0x52; 32]).unwrap();
    fs::write(
        file.join("..namedfork/rsrc"),
        vec![0x61; 2 * 1024 * 1024 + 17],
    )
    .unwrap();
    xattr::set(&link, "com.tzap.matrix-link", b"link metadata").unwrap();
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

    let source_file = fs::symlink_metadata(&file).unwrap();
    let source_directory = fs::symlink_metadata(&directory).unwrap();
    let source_link = fs::symlink_metadata(&link).unwrap();
    let source_fifo = fs::symlink_metadata(&fifo).unwrap();

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

    let policies: &[&str] = if unsafe { libc::geteuid() } == 0 {
        &["portable", "same-os", "system"]
    } else {
        &["portable", "same-os"]
    };
    for &policy in policies {
        let destination = temp.path().join(format!("extract-{policy}"));
        Command::cargo_bin("tzap")
            .unwrap()
            .args([
                "extract",
                "--restore",
                policy,
                "--keyfile",
                keyfile.to_str().unwrap(),
                "-C",
                destination.to_str().unwrap(),
                archive.to_str().unwrap(),
            ])
            .assert()
            .success();

        let restored_root = destination.join("matrix");
        let restored_file = restored_root.join("directory/file.txt");
        let restored_directory = restored_root.join("directory");
        let restored_link = restored_root.join("link.txt");
        let restored_fifo = restored_root.join("events.fifo");
        let file_metadata = fs::symlink_metadata(&restored_file).unwrap();
        let directory_metadata = fs::symlink_metadata(&restored_directory).unwrap();
        let link_metadata = fs::symlink_metadata(&restored_link).unwrap();

        assert_eq!(fs::read(&restored_file).unwrap(), b"matrix payload");
        assert_eq!(
            fs::read_link(&restored_link).unwrap(),
            Path::new("directory/file.txt")
        );
        assert_eq!(file_metadata.mode() & 0o7777, source_file.mode() & 0o7777);
        assert_eq!(
            directory_metadata.mode() & 0o7777,
            source_directory.mode() & 0o7777
        );
        assert_eq!(
            (file_metadata.mtime(), file_metadata.mtime_nsec()),
            (source_file.mtime(), source_file.mtime_nsec())
        );
        assert_eq!(
            (directory_metadata.mtime(), directory_metadata.mtime_nsec()),
            (source_directory.mtime(), source_directory.mtime_nsec())
        );
        assert!(link_metadata.file_type().is_symlink());

        if policy == "portable" {
            assert_eq!(xattr::get(&restored_file, "com.tzap.matrix").unwrap(), None);
            assert_eq!(
                xattr::get(&restored_link, "com.tzap.matrix-link").unwrap(),
                None
            );
            assert_eq!(file_metadata.st_flags() & libc::UF_HIDDEN, 0);
            assert!(!restored_fifo.exists());
            continue;
        }

        assert_eq!(file_metadata.st_flags(), source_file.st_flags());
        assert_eq!(directory_metadata.st_flags(), source_directory.st_flags());
        assert_eq!(link_metadata.st_flags(), source_link.st_flags());
        assert_eq!(
            (
                file_metadata.st_birthtime(),
                file_metadata.st_birthtime_nsec()
            ),
            (source_file.st_birthtime(), source_file.st_birthtime_nsec())
        );
        assert_eq!(
            (
                directory_metadata.st_birthtime(),
                directory_metadata.st_birthtime_nsec(),
            ),
            (
                source_directory.st_birthtime(),
                source_directory.st_birthtime_nsec(),
            )
        );
        assert_eq!(
            xattr::get(&restored_file, "com.tzap.matrix")
                .unwrap()
                .as_deref(),
            Some([0x41; 19].as_slice())
        );
        assert_eq!(
            xattr::get(&restored_directory, "com.tzap.matrix")
                .unwrap()
                .as_deref(),
            Some([0x42; 19].as_slice())
        );
        assert_eq!(
            xattr::get(&restored_link, "com.tzap.matrix-link")
                .unwrap()
                .as_deref(),
            Some(b"link metadata".as_slice())
        );
        assert_eq!(
            xattr::get(&restored_file, "com.apple.FinderInfo")
                .unwrap()
                .as_deref(),
            Some([0x51; 32].as_slice())
        );
        assert_eq!(
            xattr::get(&restored_directory, "com.apple.FinderInfo")
                .unwrap()
                .as_deref(),
            Some([0x52; 32].as_slice())
        );
        assert_eq!(
            fs::read(restored_file.join("..namedfork/rsrc")).unwrap(),
            vec![0x61; 2 * 1024 * 1024 + 17]
        );
        for restored in [&restored_file, &restored_directory, &restored_link] {
            let acl = std::process::Command::new("ls")
                .args(["-lde"])
                .arg(restored)
                .output()
                .unwrap();
            assert!(acl.status.success());
            assert!(String::from_utf8_lossy(&acl.stdout).contains("everyone deny delete"));
        }

        if policy == "same-os" {
            assert!(!restored_fifo.exists());
        } else {
            let fifo_metadata = fs::symlink_metadata(&restored_fifo).unwrap();
            assert!(fifo_metadata.file_type().is_fifo());
            assert_eq!(fifo_metadata.mode() & 0o7777, source_fifo.mode() & 0o7777);
            assert_eq!(fifo_metadata.st_flags(), source_fifo.st_flags());
            assert_eq!(fifo_metadata.uid(), source_fifo.uid());
            assert_eq!(fifo_metadata.gid(), source_fifo.gid());
            assert_eq!(
                xattr::get(&restored_fifo, "com.tzap.matrix")
                    .unwrap()
                    .as_deref(),
                Some([0x43; 19].as_slice())
            );
        }
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
        .code(0)
        .stdout(predicate::str::contains("payload.txt"));
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
        .stdout(predicate::str::starts_with(format!(
            "6\tfile\t{expected_mode}\t{expected_mtime}\t"
        )))
        .stdout(predicate::str::ends_with("payload.bin\n"));
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
        .stdout(predicate::str::starts_with(format!(
            "11\tfile\t448\t{expected_mtime}\t"
        )))
        .stdout(predicate::str::ends_with("script.sh\n"));
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
