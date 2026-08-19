// Tests for the `tzap verify` CLI surface.
use super::*;

#[test]
fn cli_verify_help_includes_examples_and_flags() {
    let output = Command::cargo_bin("tzap").unwrap().args(["verify", "--help"]).assert().success().get_output().stdout.clone();
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
fn cli_verify_fast_plaintext_zero_recovery_reports_payload_semantics_deferred() {
    let temp = tempdir().unwrap();
    let output = temp.path().join("fast-plaintext.tzap");
    let input = temp.path().join("fast-plaintext.txt");
    fs::write(&input, b"fast plaintext zero recovery payload\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "--no-encryption", "--bit-rot-buffer-pct", "0", "-o", output.to_str().unwrap(), input.to_str().unwrap()])
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
        .args(["create", "--no-encryption", "--bit-rot-buffer-pct", "0", "-o", output.to_str().unwrap(), input.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", "--fast", output.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("OK fast"))
        .stdout(predicate::str::contains("root-auth: OK").not());

    let json_output =
        Command::cargo_bin("tzap").unwrap().args(["verify", "--json", "--fast", output.to_str().unwrap()]).assert().success().get_output().stdout.clone();
    let value: Value = serde_json::from_slice(&json_output).unwrap();
    assert_eq!(value.get("ok").unwrap().as_bool(), Some(true));
    assert_eq!(value.get("verification_mode").unwrap().as_str(), Some("fast"));
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
        .args(["signing-keygen", "--secret-output", signing_secret.to_str().unwrap(), "--public-output", signing_public.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "--no-encryption", "--signing-key", signing_secret.to_str().unwrap(), "-o", output.to_str().unwrap(), input.to_str().unwrap()])
        .assert()
        .success();

    let stdout = Command::cargo_bin("tzap").unwrap().args(["verify", "--fast", output.to_str().unwrap()]).assert().success().get_output().stdout.clone();
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
        .stderr(predicate::str::contains("--fast requires seekable archive paths"));
}

#[test]
fn cli_verify_fast_rejects_full_root_auth_and_repair_options() {
    let temp = tempdir().unwrap();
    let public_key = temp.path().join("root.public.hex");
    let archive = temp.path().join("missing.tzap");

    fs::write(&public_key, "00".repeat(32)).unwrap();

    for args in [
        vec!["verify", "--fast", "--trusted-public-key", public_key.to_str().unwrap(), archive.to_str().unwrap()],
        vec!["verify", "--fast", "--public-no-key", "--trusted-public-key", public_key.to_str().unwrap(), archive.to_str().unwrap()],
        vec!["verify", "--fast", "--write-repaired", archive.to_str().unwrap()],
    ] {
        Command::cargo_bin("tzap").unwrap().args(args).assert().code(2).stderr(predicate::str::contains("--fast cannot be combined"));
    }
}

#[test]
fn cli_verify_reads_unencrypted_archive_without_key_source() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("sample.txt");
    let archive = temp.path().join("sample.tzap");
    fs::write(&input, b"plaintext v45\n").unwrap();

    Command::cargo_bin("tzap").unwrap().args(["create", "--no-encryption", "-o", archive.to_str().unwrap(), input.to_str().unwrap()]).assert().success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", archive.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("(1 volume(s), 1 file(s))"));
}

#[test]
fn cli_verify_key_mode_and_archive_input_are_required() {
    Command::cargo_bin("tzap").unwrap().args(["verify"]).assert().code(2).stderr(predicate::str::contains("required"));

    Command::cargo_bin("tzap").unwrap().args(["verify", "--keyfile", "key.hex"]).assert().code(2).stderr(predicate::str::contains("required"));
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
        .args(["create", "--keyfile", keyfile.to_str().unwrap(), "-o", archive.to_str().unwrap(), input.to_str().unwrap()])
        .assert()
        .success();

    let output = Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", "--keyfile", keyfile.to_str().unwrap(), "--json", archive.to_str().unwrap()])
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
    assert_eq!(metadata.get("profiles_present").unwrap(), &expected_profiles);
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
    let payload = (0..12_000).map(|idx| ((idx * 37 + 11) % 251) as u8).collect::<Vec<_>>();
    fs::write(&input, payload).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "--keyfile", keyfile.to_str().unwrap(), "-o", archive.to_str().unwrap(), input.to_str().unwrap()])
        .assert()
        .success();

    let mut archive_bytes = fs::read(&archive).unwrap();
    corrupt_first_record_payload_crc_of_kind(&mut archive_bytes, BlockKind::PayloadData);
    fs::write(&archive, archive_bytes).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", "--keyfile", keyfile.to_str().unwrap(), "--write-repaired", archive.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("(1 volume(s), 1 file(s))"))
        .stdout(predicate::str::contains("wrote repaired volume copy"))
        .stdout(predicate::str::contains("sample.repaired.tzap"));

    assert!(repaired.exists());
    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", "--keyfile", keyfile.to_str().unwrap(), repaired.to_str().unwrap()])
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
    let payload = (0..12_000).map(|idx| ((idx * 41 + 7) % 251) as u8).collect::<Vec<_>>();
    fs::write(&input, payload).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "--keyfile", keyfile.to_str().unwrap(), "-o", archive.to_str().unwrap(), input.to_str().unwrap()])
        .assert()
        .success();

    let mut archive_bytes = fs::read(&archive).unwrap();
    corrupt_first_record_magic_of_kind(&mut archive_bytes, BlockKind::PayloadData);
    fs::write(&archive, archive_bytes).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", "--keyfile", keyfile.to_str().unwrap(), "--write-repaired", archive.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("(1 volume(s), 1 file(s))"))
        .stdout(predicate::str::contains("wrote repaired volume copy"))
        .stdout(predicate::str::contains("sample.repaired.tzap"));

    assert!(repaired.exists());
    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", "--keyfile", keyfile.to_str().unwrap(), repaired.to_str().unwrap()])
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
        .args(["create", "--keyfile", keyfile.to_str().unwrap(), "-o", archive.to_str().unwrap(), input.to_str().unwrap()])
        .assert()
        .success();

    let mut archive_bytes = fs::read(&archive).unwrap();
    archive_bytes[0] ^= 0x55;
    fs::write(&archive, archive_bytes).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", "--keyfile", keyfile.to_str().unwrap(), archive.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("(1 volume(s), 1 file(s))"));
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
        .args(["create", "--keyfile", keyfile.to_str().unwrap(), "-o", archive.to_str().unwrap(), input.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", "--quiet", "--json", "--keyfile", keyfile.to_str().unwrap(), archive.to_str().unwrap()])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with").and(predicate::str::contains("--json")));
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
        .args(["create", "--keyfile", keyfile.to_str().unwrap(), "-o", archive.to_str().unwrap(), input.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", "--quiet", "--keyfile", keyfile.to_str().unwrap(), archive.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
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
    let mut bootstrap_header = BootstrapSidecarHeader::parse(&bootstrap_original[..BOOTSTRAP_SIDECAR_HEADER_LEN]).unwrap();
    bootstrap_header.flags &= !0x04;
    bootstrap_header.dictionary_records_offset = 0;
    bootstrap_header.dictionary_records_length = 0;

    let master_key = MasterKey::from_raw_key(&master_key_from_hex(KEY_HEX)).unwrap();
    let subkeys = Subkeys::derive(&master_key, &volume_header.archive_uuid, &volume_header.session_id).unwrap();
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
        payload_end = payload_end.checked_add(bootstrap_header.manifest_footer_length as u64).unwrap();
    }
    if bootstrap_header.has_index_root_records() {
        assert_eq!(bootstrap_header.index_root_records_offset, payload_end);
        payload_end = payload_end.checked_add(bootstrap_header.index_root_records_length as u64).unwrap();
    }

    let mut stripped_bootstrap_bytes = stripped.to_vec();
    stripped_bootstrap_bytes.extend_from_slice(&bootstrap_original[BOOTSTRAP_SIDECAR_HEADER_LEN..payload_end as usize]);
    fs::write(&stripped_bootstrap, stripped_bootstrap_bytes).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", "--keyfile", keyfile.to_str().unwrap(), "--bootstrap", stripped_bootstrap.to_str().unwrap(), archive.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("(1 volume(s), 1 file(s))"));
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
        .args(["verify", "--keyfile", keyfile.to_str().unwrap(), volume_1.to_str().unwrap()])
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
        .args(["verify", "--keyfile", keyfile.to_str().unwrap(), volume_0.to_str().unwrap()])
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
        .args(["verify", "--keyfile", keyfile.to_str().unwrap(), missing.to_str().unwrap()])
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
        .args(["verify", "--json", "--keyfile", keyfile.to_str().unwrap(), missing.to_str().unwrap()])
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
        .args(["verify", "--quiet", "--keyfile", keyfile.to_str().unwrap(), missing.to_str().unwrap()])
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
        .args(["create", "--keyfile", keyfile.to_str().unwrap(), "--volumes", "3", "-o", output_base.to_str().unwrap(), input.to_str().unwrap()])
        .assert()
        .success();
    fs::remove_file(&volume_1).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", "--keyfile", keyfile.to_str().unwrap(), volume_0.to_str().unwrap(), volume_2.to_str().unwrap()])
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
        .args(["verify", "--keyfile", keyfile.to_str().unwrap(), volume_0.to_str().unwrap()])
        .assert()
        .code(11)
        .stderr(predicate::str::contains("missing-volume"));
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
        .args(["verify", "--keyfile", keyfile.to_str().unwrap(), "--bootstrap", bootstrap.to_str().unwrap(), archive.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));
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
        .args(["create", "--keyfile", keyfile.to_str().unwrap(), "-o", archive.to_str().unwrap(), input.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", "--keyfile", keyfile.to_str().unwrap(), archive.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("(1 volume(s), 1 file(s))"));
}
