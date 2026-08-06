// Error-path integration tests: stable error categories, exit codes, io errors,
// corrupt-archive and wrong-key reporting.
use super::*;

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
        .code(2)
        .stderr(predicate::str::contains("invalid-arguments"))
        .stderr(predicate::str::contains(
            "invalid size '10Q': unsupported suffix 'Q'",
        ))
        .stderr(predicate::str::contains("supported: K/KB/KiB"));
}

#[test]
fn cli_reports_invalid_layout_size_flags_with_usage_exit_code() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let output = temp.path().join("sample.tzap");
    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello\n").unwrap();

    for flag in ["--block-size", "--envelope-size", "--chunk-size"] {
        Command::cargo_bin("tzap")
            .unwrap()
            .args([
                "create",
                "--keyfile",
                keyfile.to_str().unwrap(),
                flag,
                "10Q",
                "-o",
                output.to_str().unwrap(),
                input.to_str().unwrap(),
            ])
            .assert()
            .code(2)
            .stderr(predicate::str::contains("invalid-arguments"))
            .stderr(predicate::str::contains(
                "invalid size '10Q': unsupported suffix 'Q'",
            ));
    }
}

#[test]
fn cli_reports_missing_bootstrap_with_stable_category_and_exit_code() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let dictionary = temp.path().join("sample.dict");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&dictionary, b"non-empty zstd dictionary bytes").unwrap();
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
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();

    // A dictionary archive carries a bootstrap sidecar: sequential (stdin)
    // verification cannot reconstruct it, so the reader must refuse.
    let archive_bytes = fs::read(&archive).unwrap();
    Command::cargo_bin("tzap")
        .unwrap()
        .current_dir(temp.path())
        .args(["verify", "--keyfile", keyfile.to_str().unwrap(), "-"])
        .write_stdin(archive_bytes)
        .assert()
        .code(14)
        .stderr(predicate::str::contains("missing-bootstrap"))
        .stderr(predicate::str::contains("--bootstrap"));
}

#[test]
fn cli_verify_json_failure_reports_unsupported_revision_shape() {
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
        .code(12)
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output).unwrap();

    assert!(!value.get("ok").unwrap().as_bool().unwrap());
    let error = value.get("error").unwrap();
    assert_eq!(
        error.get("label").unwrap().as_str().unwrap(),
        "unsupported-revision"
    );
    assert_eq!(
        error
            .get("observed")
            .unwrap()
            .get("volume_format_rev")
            .unwrap()
            .as_u64()
            .unwrap(),
        35
    );
    assert_eq!(
        error
            .get("supported")
            .unwrap()
            .get("max_volume_format_rev")
            .unwrap()
            .as_u64()
            .unwrap(),
        u64::from(READER_MAX_SUPPORTED_VOLUME_FORMAT_REV)
    );
    assert!(
        !error.get("action").unwrap().as_str().unwrap().is_empty(),
        "unsupported-revision JSON must carry an action"
    );
}
