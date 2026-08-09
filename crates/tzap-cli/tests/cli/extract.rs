// Tests for the `tzap extract` CLI surface.
use super::*;

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
fn cli_extract_reads_unencrypted_archive_without_key_source() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("sample.txt");
    let archive = temp.path().join("sample.tzap");
    let output = temp.path().join("out");
    fs::write(&input, b"plaintext v45\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "--no-encryption", "-o", archive.to_str().unwrap(), input.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["extract", "-C", output.to_str().unwrap(), archive.to_str().unwrap()])
        .assert()
        .success();

    assert_eq!(fs::read(output.join("sample.txt")).unwrap(), b"plaintext v45\n");
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

    assert_eq!(fs::read(output.join("hello.txt")).unwrap(), b"hello from tzap\n");
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
        .stderr(predicate::str::contains("missing archive path: missing.txt"));
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
    assert_eq!(fs::read_link(&restored_link).unwrap(), Path::new("/tmp/abs_target"));
}

#[test]
fn cli_extracts_archive_created_with_volume_size_split() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("sized-extract.bin");
    let output_base = temp.path().join("sized-extract.tzap");
    let output = temp.path().join("out");
    let expected = (0..64 * 1024).map(|idx| ((idx * 37 + 11) % 251) as u8).collect::<Vec<_>>();

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

    assert_eq!(fs::read(output.join("sized-extract.bin")).unwrap(), expected);
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
        .args(["extract", "--keyfile", keyfile.to_str().unwrap(), "../sample.tzap"])
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

    assert_eq!(fs::read(output.join("input-dir").join("a.txt")).unwrap(), expected);
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

    assert_eq!(fs::read(output.join("input").join("a.txt")).unwrap(), b"a\n");
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

    assert_eq!(fs::read(output.join("input").join("a.txt")).unwrap(), b"a\n");
    assert_eq!(fs::read(output.join("input").join("b.txt")).unwrap(), b"b\n");
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

    assert_eq!(fs::read(output.join("hello.txt")).unwrap(), b"updated payload\n");
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

    assert_eq!(fs::read(output.join("hello.txt")).unwrap(), b"bootstrap payload\n");
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

    assert_eq!(fs::read(output.join("hello.txt")).unwrap(), b"multi-volume payload\n");
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
        state = state.wrapping_mul(2_862_933_555_777_941_757).wrapping_add(3_037_000_493);
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
        .args(["extract", "--keyfile", keyfile.to_str().unwrap(), archive.to_str().unwrap(), "missing.txt"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("missing archive path: missing.txt"));
}

#[test]
fn cli_extract_stdout_requires_exactly_one_path() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("missing-key.hex");
    let archive = temp.path().join("missing-archive.tzap");

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["extract", "--keyfile", keyfile.to_str().unwrap(), "--stdout", archive.to_str().unwrap()])
        .assert()
        .code(16)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("unsupported-feature"))
        .stderr(predicate::str::contains("--stdout requires exactly one archive path"))
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
        .stderr(predicate::str::contains("--stdout requires exactly one archive path"))
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
        .args(["extract", "--keyfile", bad_key.to_str().unwrap(), archive.to_str().unwrap(), "hello.txt"])
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
        .args(["extract", "--keyfile", keyfile.to_str().unwrap(), archive.to_str().unwrap(), "hello.txt"])
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
        .stderr(predicate::str::contains("missing archive path: missing.txt"));
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

#[test]
fn cli_extract_various_loss_tolerance_redundancy_and_bit_rot_levels() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    fs::write(&keyfile, KEY_HEX).unwrap();

    let input = temp.path().join("payload.bin");
    let payload_bytes: Vec<u8> = (0..500_000).map(|i| (i % 251) as u8).collect();
    fs::write(&input, &payload_bytes).unwrap();

    // Test volume loss tolerance counts: 1, 2 (out of 4 volumes)
    for tolerance_count in [1, 2] {
        let output_base = temp.path().join(format!("archive_tol_{tolerance_count}.tzap"));
        let out_dir = temp.path().join(format!("out_tol_{tolerance_count}"));

        Command::cargo_bin("tzap")
            .unwrap()
            .args([
                "create",
                "--keyfile",
                keyfile.to_str().unwrap(),
                "--volumes",
                "4",
                "--volume-loss-tolerance",
                &tolerance_count.to_string(),
                "--bit-rot-buffer-pct",
                "10",
                "-o",
                output_base.to_str().unwrap(),
                input.to_str().unwrap(),
            ])
            .assert()
            .success();

        // 1. Verify clean extraction without missing volumes
        Command::cargo_bin("tzap")
            .unwrap()
            .args([
                "extract",
                "--keyfile",
                keyfile.to_str().unwrap(),
                "-C",
                out_dir.to_str().unwrap(),
                numbered_volume_path(&output_base, 0).to_str().unwrap(),
            ])
            .assert()
            .success();
        assert_eq!(fs::read(out_dir.join("payload.bin")).unwrap(), payload_bytes);

        // 2. Corrupt one byte in a payload volume and test bit-rot recovery
        let vol1 = numbered_volume_path(&output_base, 1);
        let mut vol1_bytes = fs::read(&vol1).unwrap();
        let flip_idx = vol1_bytes.len() / 2;
        vol1_bytes[flip_idx] ^= 0xff;
        fs::write(&vol1, &vol1_bytes).unwrap();

        let out_corrupt_dir = temp.path().join(format!("out_corrupt_{tolerance_count}"));
        Command::cargo_bin("tzap")
            .unwrap()
            .args([
                "extract",
                "--keyfile",
                keyfile.to_str().unwrap(),
                "-C",
                out_corrupt_dir.to_str().unwrap(),
                numbered_volume_path(&output_base, 0).to_str().unwrap(),
            ])
            .assert()
            .success();
        assert_eq!(fs::read(out_corrupt_dir.join("payload.bin")).unwrap(), payload_bytes);
    }
}

#[test]
fn cli_extract_cross_os_restore_policy_matrix() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    fs::write(&keyfile, KEY_HEX).unwrap();

    let input = temp.path().join("doc.txt");
    fs::write(&input, b"cross-os policy content\n").unwrap();

    let archive = temp.path().join("cross_os.tzap");
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

    for policy in ["content", "portable", "same-os"] {
        let out_dir = temp.path().join(format!("out_policy_{policy}"));
        Command::cargo_bin("tzap")
            .unwrap()
            .args([
                "extract",
                "--keyfile",
                keyfile.to_str().unwrap(),
                "--restore",
                policy,
                "-C",
                out_dir.to_str().unwrap(),
                archive.to_str().unwrap(),
            ])
            .assert()
            .success();

        assert_eq!(fs::read(out_dir.join("doc.txt")).unwrap(), b"cross-os policy content\n");
    }
}
