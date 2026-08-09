// Tests for the `tzap create` CLI surface.
use super::*;

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
fn cli_create_requires_key_source_before_running() {
    let temp = tempdir().unwrap();
    let output = temp.path().join("sample.tzap");
    let input = temp.path().join("hello.txt");

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "-o", output.to_str().unwrap(), input.to_str().unwrap()])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("no key source provided"));
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
fn cli_create_stdin_modes_reject_incompatible_stdin_consumers() {
    let temp = tempdir().unwrap();
    let output = temp.path().join("stdin.tzap");

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "--tar-stdin", "--password-stdin", "-o", output.to_str().unwrap(), "-"])
        .assert()
        .code(16)
        .stderr(predicate::str::contains(
            "--password-stdin cannot be used when stdin carries archive payload bytes",
        ));

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "--tar-stdin", "--password", "-o", output.to_str().unwrap(), "-"])
        .write_stdin(tar_stream(&[("payload.txt", b"payload".as_slice())]))
        .assert()
        .code(16)
        .stderr(predicate::str::contains("--password cannot be used when stdin carries archive payload bytes"));
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
        .stderr(predicate::str::contains("--dictionary is not supported with stdin create modes"));
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
        .stderr(predicate::str::contains("--volume-size is not supported with stdin create modes"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "--tar-stdin", "--keyfile", "missing-key.hex", "-o", "-", "-"])
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
        .stderr(predicate::str::contains("--volume-loss-tolerance > 0 is not supported with stdin create modes"));
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
        .stderr(predicate::str::contains("stdin create modes require exactly one archive input path: -"));
}

#[test]
fn cli_create_raw_stdin_requires_member_name_and_valid_size() {
    let temp = tempdir().unwrap();
    let output = temp.path().join("stdin.tzap");

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "--raw-stdin", "--keyfile", "missing-key.hex", "-o", output.to_str().unwrap(), "-"])
        .assert()
        .code(16)
        .stderr(predicate::str::contains("--raw-stdin requires --stdin-name PATH"));

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
        .stderr(predicate::str::contains("--tar-stdin and --raw-stdin cannot be used together"));
}

#[test]
fn cli_create_stdin_modes_reject_raw_adjunct_flags_without_raw_stdin() {
    let temp = tempdir().unwrap();
    let output = temp.path().join("stdin.tzap");

    for (args, expected) in [
        (vec!["--stdin-name", "data.bin"], "--stdin-name requires --raw-stdin"),
        (vec!["--stdin-size", "4K"], "--stdin-size requires --raw-stdin"),
        (vec!["--spool-stdin"], "--spool-stdin requires --raw-stdin"),
    ] {
        let mut command_args = vec!["create"];
        command_args.extend(args);
        command_args.extend(["--keyfile", "missing-key.hex", "-o", output.to_str().unwrap(), "-"]);

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
        .stderr(predicate::str::contains("--spool-stdin is for unknown-size raw stdin; omit --stdin-size"));
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
        .args(["verify", "--jobs", "2", "--keyfile", keyfile.to_str().unwrap(), output.to_str().unwrap()])
        .assert()
        .success();
    Command::cargo_bin("tzap")
        .unwrap()
        .args(["list", "--jobs", "2", "--keyfile", keyfile.to_str().unwrap(), output.to_str().unwrap()])
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

    assert_eq!(fs::read(extract_dir.join("dir/beta.txt")).unwrap(), b"beta payload");
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
    let payload = (0..150_000).map(|index| (index % 251) as u8).collect::<Vec<_>>();
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
        .write_stdin(tar_stream(&[("alpha.txt", b"alpha payload".as_slice()), ("dir/beta.bin", payload.as_slice())]))
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
    let payload = (0..150_000).map(|index| (index % 251) as u8).collect::<Vec<_>>();
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
        .stdout(predicate::str::contains("public_data_block_commitment_verified"));
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
        .stdout(predicate::str::contains("public_data_block_commitment_verified"));
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
        .args(["verify", "--keyfile", keyfile.to_str().unwrap(), output.to_str().unwrap()])
        .assert()
        .success();
    Command::cargo_bin("tzap")
        .unwrap()
        .args(["list", "--keyfile", keyfile.to_str().unwrap(), output.to_str().unwrap()])
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
    let payload = (0..150_000).map(|index| (index % 251) as u8).collect::<Vec<_>>();
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
    let payload = (0..150_000).map(|index| (index % 251) as u8).collect::<Vec<_>>();
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
        .stdout(predicate::str::contains("public_data_block_commitment_verified"));
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
        .stdout(predicate::str::contains("public_data_block_commitment_verified"));
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
    let payload = (0..150_000).map(|index| (index % 251) as u8).collect::<Vec<_>>();
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

    assert_eq!(fs::read(extract_dir.join("raw/spooled.bin")).unwrap(), payload);
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
    let payload = (0..150_000).map(|index| (index % 251) as u8).collect::<Vec<_>>();
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
        .stdout(predicate::str::contains("public_data_block_commitment_verified"));
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
        .stderr(predicate::str::contains("raw stdin exceeds declared --stdin-size"));
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
        .stderr(predicate::str::contains("raw stdin exceeds declared --stdin-size"));
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
        .stdout(predicate::str::contains("(1 volume(s), 1 file(s))").and(predicate::str::contains("root-auth: OK ed25519")));

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
                .and(predicate::str::contains("public_data_block_commitment_verified"))
                .and(predicate::str::contains("public_physical_completeness_unverified"))
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
    assert_eq!(value["root_auth"]["status"], "public_data_block_commitment_verified");
    assert_eq!(value["root_auth"]["key_id"], public_hex.trim());
    assert!(value["public_diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry == "public_recovery_margin_unchecked"));
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
    let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
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
                .and(predicate::str::contains("root-auth signer: CN=Acme Release Signing"))
                .and(predicate::str::contains("root-auth issuer: CN=Acme Test Root CA"))
                .and(predicate::str::contains("root-auth signed-at:"))
                .and(predicate::str::contains("root-auth chain-validation-time:"))
                .and(predicate::str::contains("root-auth x509-policy: signature-scheme=rsa-pss-sha256")),
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
    assert_eq!(value["root_auth"]["x509_time_policy"], "verifier_current_time");
    assert_eq!(value["root_auth"]["chain_time_basis"], "verifier_current_time");
    assert_eq!(value["root_auth"]["trusted_timestamp"], false);
    assert_eq!(value["root_auth"]["revocation_checked"], false);
    assert_eq!(value["root_auth"]["key_usage_policy"], "archive_signature_minimal");
    assert_eq!(value["root_auth"]["eku_policy"], "none");
    assert_eq!(value["root_auth"]["trust_store_policy"], "caller_roots");
    assert!(value["root_auth"]["chain_validation_time_unix_seconds"].is_number());
    assert_eq!(value["root_auth"]["trust_anchor_subject"], "CN=Acme Test Root CA");

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
                .and(predicate::str::contains("root-auth signer: CN=Acme Release Signing"))
                .and(predicate::str::contains("public_data_block_commitment_verified")),
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
    assert_eq!(value["root_auth"]["x509_time_policy"], "verifier_current_time");
    assert_eq!(value["root_auth"]["revocation_checked"], false);
    assert_eq!(value["root_auth"]["status"], "public_data_block_commitment_verified");
    assert_eq!(value["root_auth"]["subject"], "CN=Acme Release Signing");
    assert_eq!(value["root_auth"]["trust_anchor_subject"], "CN=Acme Test Root CA");
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
        .args(["list", "--keyfile", keyfile.to_str().unwrap(), archive.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let listing = String::from_utf8_lossy(&output);

    let base = input_root.file_name().and_then(|name| name.to_str()).unwrap();
    let expected = format!("{base}\n{base}/.hidden\n{base}/a.txt\n{base}/b.txt\n{base}/zeta\n{base}/zeta/a.txt\n{base}/zeta/c.txt\n");
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
        .args(["list", "--keyfile", keyfile.to_str().unwrap(), archive.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert_eq!(String::from_utf8_lossy(&output), "input\ninput/empty\ninput/keep.txt\n",);
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
        .args(["list", "--keyfile", keyfile.to_str().unwrap(), archive.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains(input.file_name().and_then(|name| name.to_str()).unwrap()));
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
        .args(["list", "--keyfile", keyfile.to_str().unwrap(), archive.to_str().unwrap()])
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
        .args(["list", "--keyfile", keyfile.to_str().unwrap(), archive.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("hello.txt\n"));
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
        .args(["create", "--keyfile", keyfile.to_str().unwrap(), "-o", output.to_str().unwrap(), "/dev/null"])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["list", "--long", "--keyfile", keyfile.to_str().unwrap(), output.to_str().unwrap()])
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
    let status = unsafe { libc::mknod(input_c.as_ptr(), libc::S_IFBLK | 0o600, libc::makedev(240, 2)) };
    if status != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EPERM) {
            return;
        }
        panic!("failed to create block-device descriptor: {error}");
    }

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "--no-encryption", "-o", output.to_str().unwrap(), input.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["list", "--long", output.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("block-device"));
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
        .args(["create", "--keyfile", keyfile.to_str().unwrap(), "-o", output.to_str().unwrap(), "CON"])
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
        .code(2)
        .stderr(predicate::str::contains("invalid-arguments"))
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
        .args(["create", "--keyfile", keyfile.to_str().unwrap(), "-o", "-", input.to_str().unwrap()])
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
        .stderr(predicate::str::contains("--bootstrap-out - is not sidecar stdout"));

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

    let mut args = vec!["verify".to_owned(), "--keyfile".to_owned(), keyfile.to_str().unwrap().to_owned()];
    args.extend(volumes.iter().map(|volume| volume.to_str().unwrap().to_owned()));
    Command::cargo_bin("tzap")
        .unwrap()
        .args(args)
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));
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
        .stderr(predicate::str::contains("--bootstrap-out is currently supported only for single-volume output"));
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
        .stderr(predicate::str::contains("--bootstrap-out is currently supported only for single-volume output"));
    assert!(!archive.exists());
    assert!(!numbered_volume_path(&archive, 0).exists());
    assert!(!bootstrap.exists());
}

#[test]
fn cli_create_and_verify_all_zstd_compression_levels() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    fs::write(&keyfile, KEY_HEX).unwrap();

    let input_dir = temp.path().join("data");
    fs::create_dir(&input_dir).unwrap();
    let file1 = input_dir.join("file1.txt");
    let file2 = input_dir.join("file2.bin");
    fs::write(
        &file1,
        b"Hello Zstd Compression Level Test! Repeated string text to test compression ratio.\n".repeat(50),
    )
    .unwrap();
    let binary_data: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();
    fs::write(&file2, &binary_data).unwrap();

    for level in [1, 3, 9, 19, 22] {
        let archive = temp.path().join(format!("test_level_{level}.tzap"));
        let out_dir = temp.path().join(format!("out_level_{level}"));

        Command::cargo_bin("tzap")
            .unwrap()
            .args([
                "create",
                "--keyfile",
                keyfile.to_str().unwrap(),
                "--compression-level",
                &level.to_string(),
                "-o",
                archive.to_str().unwrap(),
                input_dir.to_str().unwrap(),
            ])
            .assert()
            .success();

        Command::cargo_bin("tzap")
            .unwrap()
            .args(["verify", "--keyfile", keyfile.to_str().unwrap(), archive.to_str().unwrap()])
            .assert()
            .success();

        Command::cargo_bin("tzap")
            .unwrap()
            .args([
                "extract",
                "--keyfile",
                keyfile.to_str().unwrap(),
                "-C",
                out_dir.to_str().unwrap(),
                archive.to_str().unwrap(),
            ])
            .assert()
            .success();

        let extracted_file1 = out_dir.join("data").join("file1.txt");
        let extracted_file2 = out_dir.join("data").join("file2.bin");
        assert_eq!(fs::read(&extracted_file1).unwrap(), fs::read(&file1).unwrap());
        assert_eq!(fs::read(&extracted_file2).unwrap(), fs::read(&file2).unwrap());
    }
}
