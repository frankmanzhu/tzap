// Tests for key material handling: keygen, signing keygen, keyfiles, recipient wrap, and password/passphrase flows.
use super::*;

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
        .stderr(predicate::str::contains("created 1 member(s), 16 bytes in, "))
        .stderr(predicate::str::contains(
            "1 volume(s), data:parity 224:1, no volume-loss tolerance, bit-rot buffer 5%",
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
        .args(["verify", "--keyfile", keyfile.to_str().unwrap(), archive.to_str().unwrap()])
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

    assert_eq!(fs::read(extract_dir.join("hello.txt")).unwrap(), b"hello from tzap\n");
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
        .args(["create", "--no-encryption", "-o", plaintext_archive.to_str().unwrap(), input.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["list", "--recipient-key", recipient_key_path.to_str().unwrap(), archive.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("recipient.txt\n"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", "--recipient-key", recipient_key_path.to_str().unwrap(), archive.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", "--json", "--recipient-key", recipient_key_path.to_str().unwrap(), "-"])
        .write_stdin(fs::read(&archive).unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""decryption_keywrap":"recipientwrap_opened""#));

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", "--json", "--recipient-key", recipient_key_path.to_str().unwrap(), "-"])
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
        .args(["verify", "--recipient-key", recipient_key_path.to_str().unwrap(), "-"])
        .write_stdin(fs::read(&archive).unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", "--recipient-key", wrong_key_path.to_str().unwrap(), archive.to_str().unwrap()])
        .assert()
        .code(10)
        .stderr(predicate::str::contains("wrong-key").and(predicate::str::contains("recipient private key")));

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

    assert_eq!(fs::read(extract_dir.join("recipient.txt")).unwrap(), b"recipient wrapped\n");
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
        &[RegularFile::new("wrapped.txt", b"multi recipient wrapped\n")],
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
        Command::cargo_bin("tzap").unwrap().args(args.clone()).write_stdin(pass).assert().success();

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
        .stderr(predicate::str::contains("keyfile must contain either 32 raw bytes or 64 hex characters"));
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

    assert_eq!(fs::read(output_dir.join("secret.txt")).unwrap(), b"payload\n");
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

    assert_eq!(fs::read(output.join("secret.txt")).unwrap(), b"passphrase payload\n");
}

#[test]
fn cli_extracts_password_multivolume_archive_with_missing_recoverable_volume() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("password-volume.bin");
    let output_base = temp.path().join("password-volume.tzap");
    let output = temp.path().join("out");
    let passphrase = "split passphrase recovery\n";
    let expected = (0..128 * 1024).map(|idx| ((idx * 17 + 29) % 251) as u8).collect::<Vec<_>>();

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

    assert_eq!(fs::read(output.join("password-volume.bin")).unwrap(), expected);
}
