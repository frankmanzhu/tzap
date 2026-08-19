#[cfg(unix)]
use super::restore::create_directory;
use super::restore::{plan_restore, prepare_destination, restore_tar_member};
use super::sparse::{create_temp_regular_file, publish_regular_file};
use super::*;
use crate::entry_metadata::*;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::collections::BTreeMap;
use tempfile::tempdir;

fn header(path: &[u8], kind: u8, size: usize, link: &[u8]) -> [u8; TAR_BLOCK_LEN] {
    let mut header = [0u8; TAR_BLOCK_LEN];
    header[..path.len()].copy_from_slice(path);
    write_octal(&mut header[100..108], 0o644);
    write_octal(&mut header[108..116], 0);
    write_octal(&mut header[116..124], 0);
    write_octal(&mut header[124..136], size as u64);
    write_octal(&mut header[136..148], 0);
    header[148..156].fill(b' ');
    header[156] = kind;
    header[157..157 + link.len()].copy_from_slice(link);
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum = header.iter().map(|byte| *byte as u64).sum::<u64>();
    write_checksum(&mut header[148..156], checksum);
    header
}

fn member(path: &[u8], kind: u8, data: &[u8], link: &[u8]) -> Vec<u8> {
    member_with_declared_size(path, kind, data.len(), data, link)
}

fn member_with_declared_size(path: &[u8], kind: u8, declared_size: usize, data: &[u8], link: &[u8]) -> Vec<u8> {
    let records = crate::entry_metadata::portable_primary_pax(path, 0o644, "other", false).unwrap();
    let pax = crate::entry_metadata::encode_canonical_pax(&records).unwrap();
    let mut pax_header = header(b"TZAP-PAX/PRIMARY", b'x', pax.len(), b"");
    write_octal(&mut pax_header[100..108], 0);
    pax_header[148..156].fill(b' ');
    let checksum = pax_header.iter().map(|byte| *byte as u64).sum::<u64>();
    write_checksum(&mut pax_header[148..156], checksum);
    let mut out = Vec::new();
    out.extend_from_slice(&pax_header);
    out.extend_from_slice(&pax);
    out.resize(out.len() + padding_to_512(pax.len()), 0);
    out.extend_from_slice(&header(path, kind, declared_size, link));
    out.extend_from_slice(data);
    out.resize(out.len() + padding_to_512(data.len()), 0);
    out
}

fn member_with_prefix(prefix: &[u8], path: &[u8], kind: u8, data: &[u8]) -> Vec<u8> {
    let mut full_path = prefix.to_vec();
    full_path.push(b'/');
    full_path.extend_from_slice(path);
    let records = crate::entry_metadata::portable_primary_pax(&full_path, 0o644, "other", false).unwrap();
    let pax = crate::entry_metadata::encode_canonical_pax(&records).unwrap();
    let mut pax_header = header(b"TZAP-PAX/PRIMARY", b'x', pax.len(), b"");
    write_octal(&mut pax_header[100..108], 0);
    pax_header[148..156].fill(b' ');
    let checksum = pax_header.iter().map(|byte| *byte as u64).sum::<u64>();
    write_checksum(&mut pax_header[148..156], checksum);
    let mut header = header(path, kind, data.len(), b"");
    header[345..345 + prefix.len()].copy_from_slice(prefix);
    header[148..156].fill(b' ');
    let checksum = header.iter().map(|byte| *byte as u64).sum::<u64>();
    write_checksum(&mut header[148..156], checksum);

    let mut out = Vec::new();
    out.extend_from_slice(&pax_header);
    out.extend_from_slice(&pax);
    out.resize(out.len() + padding_to_512(pax.len()), 0);
    out.extend_from_slice(&header);
    out.extend_from_slice(data);
    out.resize(out.len() + padding_to_512(data.len()), 0);
    out
}

fn pax_record(key: &str, value: &[u8]) -> Vec<u8> {
    let mut len = key.len() + value.len() + 4;
    loop {
        let candidate = len.to_string().len() + 1 + key.len() + 1 + value.len() + 1;
        if candidate == len {
            break;
        }
        len = candidate;
    }
    let mut out = Vec::new();
    out.extend_from_slice(len.to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(key.as_bytes());
    out.push(b'=');
    out.extend_from_slice(value);
    out.push(b'\n');
    out
}

fn write_octal(field: &mut [u8], value: u64) {
    let digits = format!("{value:o}");
    field.fill(0);
    let start = field.len() - 1 - digits.len();
    field[..start].fill(b'0');
    field[start..start + digits.len()].copy_from_slice(digits.as_bytes());
}

fn write_checksum(field: &mut [u8], value: u64) {
    let digits = format!("{value:06o}");
    field[0..6].copy_from_slice(digits.as_bytes());
    field[6] = 0;
    field[7] = b' ';
}

#[cfg(windows)]
#[test]
fn security_descriptor_equivalence_only_normalizes_protection_on_absent_acls() {
    let descriptor = |control: u16| {
        let mut bytes = vec![1, 0];
        bytes.extend_from_slice(&control.to_le_bytes());
        bytes.extend_from_slice(&[0; 16]);
        bytes
    };
    let base = 0x8004u16;
    assert!(windows_security_descriptors_equivalent(&descriptor(base | 0x2000), &descriptor(base)));
    assert!(windows_security_descriptors_equivalent(&descriptor(base | 0x0400), &descriptor(base | 0x0100)));
    assert!(!windows_security_descriptors_equivalent(&descriptor(base | 0x1000), &descriptor(base)));
    assert!(!windows_security_descriptors_equivalent(&descriptor(base), &descriptor(base | 0x0008)));
    let mut changed_body = descriptor(base | 0x2000);
    changed_body[10] = 1;
    assert!(!windows_security_descriptors_equivalent(&changed_body, &descriptor(base)));
}

#[cfg(windows)]
#[test]
fn security_descriptor_equivalence_ignores_self_relative_component_layout() {
    let owner = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    let group = [1, 1, 0, 0, 0, 0, 0, 5, 32, 2, 0, 0];
    let dacl = [2, 0, 8, 0, 0, 0, 0, 0];
    let descriptor = |order: [usize; 3]| {
        let components: [&[u8]; 3] = [&owner, &group, &dacl];
        let mut bytes = vec![0u8; 20];
        bytes[0] = 1;
        bytes[2..4].copy_from_slice(&0x8004u16.to_le_bytes());
        for index in order {
            let offset = bytes.len() as u32;
            let field = match index {
                0 => 4,
                1 => 8,
                2 => 16,
                _ => unreachable!(),
            };
            bytes[field..field + 4].copy_from_slice(&offset.to_le_bytes());
            bytes.extend_from_slice(components[index]);
        }
        bytes
    };
    let expected = descriptor([0, 1, 2]);
    let actual = descriptor([2, 1, 0]);
    assert_ne!(expected, actual);
    assert!(windows_security_descriptors_equivalent(&expected, &actual));

    let mut changed_dacl = actual;
    let dacl_offset = u32::from_le_bytes(changed_dacl[16..20].try_into().unwrap()) as usize;
    changed_dacl[dacl_offset] = 4;
    assert!(!windows_security_descriptors_equivalent(&expected, &changed_dacl));
}

#[test]
fn parses_ustar_regular_member() {
    let bytes = member(b"dir/file.txt", b'0', b"hello", b"");
    let parsed = parse_tar_member_group(&bytes, 4096).unwrap();

    assert_eq!(parsed.kind, TarEntryKind::Regular);
    assert_eq!(parsed.path, b"dir/file.txt");
    assert_eq!(parsed.data, b"hello");
    assert_eq!(parsed.logical_size, 5);
}

#[test]
fn canonicalizes_one_directory_trailing_slash_only_for_directories() {
    let dir = member(b"dir/", b'5', b"", b"");
    assert_eq!(parse_tar_member_group(&dir, 4096).unwrap().path, b"dir");

    let file = member(b"dir/", b'0', b"", b"");
    assert_eq!(parse_tar_member_group(&file, 4096).unwrap_err(), FormatError::UnsafeArchivePath);
}

#[test]
fn rejects_global_pax_headers() {
    let bytes = member(b"pax", b'g', b"11 path=x\n", b"");
    assert_eq!(parse_tar_member_group(&bytes, 4096).unwrap_err(), FormatError::InvalidArchive("global or GNU tar metadata is forbidden in revision 45"));
}

#[test]
fn rejects_global_pax_before_main_entry() {
    let global_pax = pax_record("path", b"poisoned.txt");
    let mut bytes = member(b"GlobalHead/path", b'g', &global_pax, b"");
    bytes.extend_from_slice(&member(b"safe.txt", b'0', b"abc", b""));

    assert_eq!(parse_tar_member_group(&bytes, 4096).unwrap_err(), FormatError::InvalidArchive("global or GNU tar metadata is forbidden in revision 45"));
}

#[test]
fn rejects_global_gnu_headers() {
    for typeflag in *b"VMN" {
        let bytes = member(b"global", typeflag, b"archive-label", b"");

        assert_eq!(
            parse_tar_member_group(&bytes, 4096).unwrap_err(),
            FormatError::InvalidArchive("global or GNU tar metadata is forbidden in revision 45"),
            "typeflag {typeflag:?}"
        );
    }
}

#[test]
fn rejects_unsupported_gnu_sparse_entry_type() {
    let bytes = member(b"sparse.bin", b'S', b"", b"");

    assert_eq!(parse_tar_member_group(&bytes, 4096).unwrap_err(), FormatError::InvalidArchive("global or GNU tar metadata is forbidden in revision 45"));
}

#[test]
fn rejects_noncanonical_extra_local_pax_path_and_size() {
    let pax = pax_record("path", b"long/name.txt");
    let mut bytes = member(b"PaxHeaders/name", b'x', &pax, b"");
    bytes.extend_from_slice(&member(b"short", b'0', b"abc", b""));

    assert!(parse_tar_member_group(&bytes, 4096).is_err());
}

#[test]
fn rejects_gnu_long_name_and_link_records() {
    let mut named = member(b"././@LongLink", b'L', b"long/path.txt\0", b"");
    named.extend_from_slice(&member(b"short", b'0', b"abc", b""));
    assert!(parse_tar_member_group(&named, 4096).is_err());

    let mut linked = member(b"././@LongLink", b'K', b"target/file.txt\0", b"");
    linked.extend_from_slice(&member(b"short-link", b'2', b"", b"fallback"));
    assert!(parse_tar_member_group(&linked, 4096).is_err());
}

#[test]
fn supported_tar_metadata_profile_matrix_matches_buffered_and_streaming_parsers() {
    struct Case {
        name: &'static str,
        bytes: Vec<u8>,
        expected_path: &'static [u8],
        expected_kind: TarEntryKind,
        expected_data: &'static [u8],
        expected_link_target: Option<&'static [u8]>,
        expected_logical_size: u64,
    }

    let cases = vec![
        Case {
            name: "regular ustar member",
            bytes: member(b"dir/file.txt", b'0', b"hello", b""),
            expected_path: b"dir/file.txt",
            expected_kind: TarEntryKind::Regular,
            expected_data: b"hello",
            expected_link_target: None,
            expected_logical_size: 5,
        },
        Case {
            name: "ustar prefix plus name",
            bytes: member_with_prefix(b"dir/prefix", b"file.txt", b'0', b"abc"),
            expected_path: b"dir/prefix/file.txt",
            expected_kind: TarEntryKind::Regular,
            expected_data: b"abc",
            expected_link_target: None,
            expected_logical_size: 3,
        },
        Case {
            name: "directory trailing slash",
            bytes: member(b"dir/", b'5', b"", b""),
            expected_path: b"dir",
            expected_kind: TarEntryKind::Directory,
            expected_data: b"",
            expected_link_target: None,
            expected_logical_size: 0,
        },
        Case {
            name: "canonical symlink",
            bytes: member(b"links/link", b'2', b"", b"target/file.txt"),
            expected_path: b"links/link",
            expected_kind: TarEntryKind::Symlink,
            expected_data: b"",
            expected_link_target: Some(b"target/file.txt"),
            expected_logical_size: 0,
        },
    ];

    for case in cases {
        let parsed = parse_tar_member_group(&case.bytes, 4096).unwrap_or_else(|err| panic!("{} should parse in buffered tar parser: {err:?}", case.name));
        assert_eq!(parsed.path, case.expected_path, "{}", case.name);
        assert_eq!(parsed.kind, case.expected_kind, "{}", case.name);
        assert_eq!(parsed.data, case.expected_data, "{}", case.name);
        assert_eq!(parsed.link_target.as_deref(), case.expected_link_target, "{}", case.name);
        assert_eq!(parsed.logical_size, case.expected_logical_size, "{}", case.name);

        let mut streaming = TarStreamSummaryValidator::with_observer(4096, u64::MAX, 4096, 16, NoopTarStreamObserver);
        streaming.observe(&case.bytes).unwrap_or_else(|err| panic!("{} should parse in streaming tar parser: {err:?}", case.name));
        let summary = streaming.finish().unwrap_or_else(|err| panic!("{} should finish in streaming tar parser: {err:?}", case.name));
        assert_eq!(summary.members.len(), 1, "{}", case.name);
        let member = &summary.members[0];
        assert_eq!(member.path, case.expected_path, "{}", case.name);
        assert_eq!(member.kind, case.expected_kind, "{}", case.name);
        assert_eq!(member.link_target.as_deref(), case.expected_link_target, "{}", case.name);
        assert_eq!(member.logical_size, case.expected_logical_size, "{}", case.name);
    }
}

#[test]
fn tar_metadata_rejects_unsafe_or_inconsistent_overrides_matrix() {
    let mut pax_absolute_path = member(b"PaxHeaders/file", b'x', &pax_record("path", b"/absolute"), b"");
    pax_absolute_path.extend_from_slice(&member(b"fallback", b'0', b"abc", b""));

    let mut pax_parent_path = member(b"PaxHeaders/file", b'x', &pax_record("path", b"../escape"), b"");
    pax_parent_path.extend_from_slice(&member(b"fallback", b'0', b"abc", b""));

    let mut pax_absolute_link = member(b"PaxHeaders/link", b'x', &pax_record("linkpath", b"/target"), b"");
    pax_absolute_link.extend_from_slice(&member(b"links/link", b'2', b"", b"safe"));

    let mut gnu_unsafe_name = member(b"././@LongLink", b'L', b"bad:name.txt\0", b"");
    gnu_unsafe_name.extend_from_slice(&member(b"fallback", b'0', b"abc", b""));

    let mut gnu_parent_hardlink = member(b"././@LongLink", b'K', b"../target.txt\0", b"");
    gnu_parent_hardlink.extend_from_slice(&member(b"links/hard", b'1', b"", b"safe"));

    let mut pax_size_on_directory = member(b"PaxHeaders/dir", b'x', &pax_record("size", b"1"), b"");
    pax_size_on_directory.extend_from_slice(&member_with_declared_size(b"dir", b'5', 0, b"x", b""));

    for (name, bytes) in [
        ("pax absolute path", pax_absolute_path),
        ("pax parent path", pax_parent_path),
        ("pax absolute symlink target", pax_absolute_link),
        ("gnu unsafe long name", gnu_unsafe_name),
        ("gnu hardlink parent target", gnu_parent_hardlink),
        ("pax size on directory", pax_size_on_directory),
    ] {
        assert!(parse_tar_member_group(&bytes, 4096).is_err(), "{name}");

        let mut streaming = TarStreamSummaryValidator::with_observer(4096, u64::MAX, 4096, 16, NoopTarStreamObserver);
        assert!(streaming.observe(&bytes).is_err(), "{name}");
    }
}

#[test]
fn pax_size_exceeding_available_group_is_rejected_by_buffered_and_streaming_parsers() {
    let mut bytes = member(b"PaxHeaders/file", b'x', &pax_record("size", b"4096"), b"");
    bytes.extend_from_slice(&member_with_declared_size(b"file", b'0', 0, b"short", b""));

    assert!(parse_tar_member_group(&bytes, 4096).is_err());

    let mut streaming = TarStreamSummaryValidator::with_observer(4096, u64::MAX, 4096, 16, NoopTarStreamObserver);
    assert!(streaming.observe(&bytes).is_err());
}

#[test]
fn malformed_pax_record_matrix_rejects_before_metadata_is_trusted() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("missing length", b"path=file\n".to_vec()),
        ("missing space", b"12path=file\n".to_vec()),
        ("record too short", b"3 a\n".to_vec()),
        ("missing newline", b"11 path=file".to_vec()),
        ("missing equals", b"10 pathfile\n".to_vec()),
        ("non utf8 key", vec![7, b' ', 0xff, b'=', b'x', b'\n']),
        ("bad size value", pax_record("size", b"12x")),
    ];

    for (name, payload) in cases {
        let mut bytes = member(b"PaxHeaders/file", b'x', &payload, b"");
        bytes.extend_from_slice(&member(b"file", b'0', b"abc", b""));

        assert!(matches!(parse_tar_member_group(&bytes, 4096).unwrap_err(), FormatError::InvalidArchive(_)), "{name}");

        let mut streaming = TarStreamSummaryValidator::with_observer(4096, u64::MAX, 4096, 16, NoopTarStreamObserver);
        assert!(matches!(streaming.observe(&bytes).unwrap_err(), FormatError::InvalidArchive(_)), "{name}");
    }
}

#[test]
fn rejects_unregistered_legacy_xattr_and_acl_pax_keys() {
    let mut pax = Vec::new();
    pax.extend_from_slice(&pax_record("SCHILY.xattr.user.comment", b"hello"));
    pax.extend_from_slice(&pax_record("LIBARCHIVE.xattr.user.comment", b"hello"));
    pax.extend_from_slice(&pax_record("SCHILY.acl.access", b"user::rw-"));
    pax.extend_from_slice(&pax_record("LIBARCHIVE.acl.access", b"user::rw-"));
    let mut bytes = member(b"PaxHeaders/file", b'x', &pax, b"");
    bytes.extend_from_slice(&member(b"file.txt", b'0', b"abc", b""));

    assert!(parse_tar_member_group(&bytes, 4096).is_err());
}

#[test]
fn rejects_unregistered_legacy_timestamp_pax_keys() {
    let mut pax = Vec::new();
    pax.extend_from_slice(&pax_record("atime", b"1.123456789"));
    pax.extend_from_slice(&pax_record("ctime", b"2.123456789"));
    pax.extend_from_slice(&pax_record("mtime", b"3.123456789"));
    let mut bytes = member(b"PaxHeaders/file", b'x', &pax, b"");
    bytes.extend_from_slice(&member(b"file.txt", b'0', b"abc", b""));

    assert!(parse_tar_member_group(&bytes, 4096).is_err());
}

#[test]
fn rejects_noncanonical_sparse_and_unknown_pax_keys() {
    let mut pax = Vec::new();
    pax.extend_from_slice(&pax_record("GNU.sparse.realsize", b"1024"));
    pax.extend_from_slice(&pax_record("GNU.sparse.map", b"0,1"));
    pax.extend_from_slice(&pax_record("comment", b"ignored"));
    let mut bytes = member(b"PaxHeaders/file", b'x', &pax, b"");
    bytes.extend_from_slice(&member(b"file.txt", b'0', b"abc", b""));

    assert!(parse_tar_member_group(&bytes, 4096).is_err());
}

#[test]
fn rejects_mixed_unregistered_local_pax_keys() {
    let mut pax = Vec::new();
    pax.extend_from_slice(&pax_record("SCHILY.xattr.user.comment", b"hello"));
    pax.extend_from_slice(&pax_record("GNU.sparse.realsize", b"1024"));
    pax.extend_from_slice(&pax_record("mtime", b"1.123456789"));
    pax.extend_from_slice(&pax_record("comment", b"ignored"));
    let mut bytes = member(b"PaxHeaders/file", b'x', &pax, b"");
    bytes.extend_from_slice(&member(b"file.txt", b'0', b"abc", b""));

    assert!(parse_tar_member_group(&bytes, 4096).is_err());
}

#[test]
fn rejects_platform_escape_paths() {
    for path in [b"/abs".as_slice(), b"../up".as_slice(), b"a//b".as_slice(), b"a\\b".as_slice(), b"a:b".as_slice(), b"CON".as_slice()] {
        let bytes = member(path, b'0', b"", b"");
        assert_eq!(parse_tar_member_group(&bytes, 4096).unwrap_err(), FormatError::UnsafeArchivePath);
    }
}

#[cfg(unix)]
#[test]
fn safe_restore_rejects_symlink_parent() {
    let tmp = tempdir().unwrap();
    let outside = tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), tmp.path().join("link")).unwrap();

    let member = OwnedTarMember {
        path: b"link/file.txt".to_vec(),
        kind: TarEntryKind::Regular,
        data: b"blocked".to_vec(),
        link_target: None,
        mode: 0o644,
        mtime: ArchiveTimestamp::UNIX_EPOCH,
        logical_size: 7,
        reparse_placeholder: false,
        v45_metadata: None,
        diagnostics: Vec::new(),
    };

    assert_eq!(restore_tar_member(tmp.path(), &member, SafeExtractionOptions::default()).unwrap_err(), FormatError::UnsafeArchivePath);
}

#[cfg(unix)]
#[test]
fn prepared_regular_file_uses_open_parent_after_parent_path_swap() {
    let tmp = tempdir().unwrap();
    let outside = tempdir().unwrap();
    let original_parent = tmp.path().join("a");
    let held_parent = tmp.path().join("held");
    fs::create_dir(&original_parent).unwrap();

    let destination = prepare_destination(tmp.path(), b"a/file.txt", TarEntryKind::Regular, SafeExtractionOptions::default()).unwrap();

    fs::rename(&original_parent, &held_parent).unwrap();
    std::os::unix::fs::symlink(outside.path(), &original_parent).unwrap();

    let (temp_leaf, mut file) = create_temp_regular_file(&destination).unwrap();
    file.write_all(b"inside").unwrap();
    publish_regular_file(&destination, &temp_leaf, file, SafeExtractionOptions::default()).unwrap();

    assert_eq!(fs::read(held_parent.join("file.txt")).unwrap(), b"inside");
    assert!(!outside.path().join("file.txt").exists());
}

#[cfg(unix)]
#[test]
fn directory_sync_tolerates_filesystems_that_reject_dir_fsync() {
    use super::restore::benign_directory_sync_error;
    // tmpfs and overlay lower layers on older kernels reject fsync on directories with
    // EINVAL/EOPNOTSUPP/ENOTSUP; those errors must not fail an otherwise-good restore.
    for code in [libc::EINVAL, libc::ENOTSUP, libc::EOPNOTSUPP] {
        assert!(benign_directory_sync_error(&std::io::Error::from_raw_os_error(code)), "errno {code} should be tolerated");
    }
    // Real failures (I/O error, out of space, bad fd) must still surface.
    for code in [libc::EIO, libc::ENOSPC, libc::EBADF] {
        assert!(!benign_directory_sync_error(&std::io::Error::from_raw_os_error(code)), "errno {code} must remain a hard failure");
    }
    assert!(!benign_directory_sync_error(&std::io::Error::other("no errno attached")));
}

#[cfg(windows)]
#[test]
fn open_file_publication_preserves_even_and_odd_length_names() {
    let tmp = tempdir().unwrap();
    for name in ["a", "bb"] {
        let destination = prepare_destination(tmp.path(), name.as_bytes(), TarEntryKind::Regular, SafeExtractionOptions::default()).unwrap();
        let (temp_leaf, mut file) = create_temp_regular_file(&destination).unwrap();
        file.write_all(name.as_bytes()).unwrap();
        publish_regular_file(&destination, &temp_leaf, file, SafeExtractionOptions::default()).unwrap();
        assert_eq!(fs::read(tmp.path().join(name)).unwrap(), name.as_bytes());
    }
    let mut names = fs::read_dir(tmp.path()).unwrap().map(|entry| entry.unwrap().file_name()).collect::<Vec<_>>();
    names.sort();
    assert_eq!(names, ["a", "bb"]);
}

#[cfg(unix)]
#[test]
fn create_directory_rechecks_leaf_without_following_symlink() {
    let tmp = tempdir().unwrap();
    let outside = tempdir().unwrap();
    let destination = prepare_destination(tmp.path(), b"dir", TarEntryKind::Directory, SafeExtractionOptions::default()).unwrap();

    std::os::unix::fs::symlink(outside.path(), tmp.path().join("dir")).unwrap();

    assert_eq!(create_directory(&destination).unwrap_err(), FormatError::UnsafeArchivePath);
    assert!(outside.path().read_dir().unwrap().next().is_none());
}

#[test]
fn safe_restore_requires_hardlink_target_to_be_existing_regular_file() {
    let tmp = tempdir().unwrap();
    fs::write(tmp.path().join("target.txt"), b"target").unwrap();
    let member = OwnedTarMember {
        path: b"linked.txt".to_vec(),
        kind: TarEntryKind::Hardlink,
        data: Vec::new(),
        link_target: Some(b"target.txt".to_vec()),
        mode: 0o644,
        mtime: ArchiveTimestamp::UNIX_EPOCH,
        logical_size: 0,
        reparse_placeholder: false,
        v45_metadata: None,
        diagnostics: Vec::new(),
    };

    restore_tar_member(tmp.path(), &member, SafeExtractionOptions::default()).unwrap();
    assert_eq!(fs::read(tmp.path().join("linked.txt")).unwrap(), b"target");
}

#[cfg(unix)]
#[test]
fn restore_applies_regular_file_mode_metadata() {
    let tmp = tempdir().unwrap();
    let member = OwnedTarMember {
        path: b"script.sh".to_vec(),
        kind: TarEntryKind::Regular,
        data: b"#!/bin/sh\n".to_vec(),
        link_target: None,
        mode: 0o755,
        mtime: ArchiveTimestamp::UNIX_EPOCH,
        logical_size: 10,
        reparse_placeholder: false,
        v45_metadata: None,
        diagnostics: Vec::new(),
    };

    let diagnostics = restore_tar_member(tmp.path(), &member, SafeExtractionOptions::default()).unwrap();

    assert!(diagnostics.is_empty());
    let mode = fs::metadata(tmp.path().join("script.sh")).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o755);
}

#[test]
fn restore_applies_regular_file_mtime_metadata() {
    let tmp = tempdir().unwrap();
    let member = OwnedTarMember {
        path: b"dated.txt".to_vec(),
        kind: TarEntryKind::Regular,
        data: b"dated".to_vec(),
        link_target: None,
        mode: 0o666,
        mtime: ArchiveTimestamp::from_seconds(1_700_000_000),
        logical_size: 5,
        reparse_placeholder: false,
        v45_metadata: None,
        diagnostics: Vec::new(),
    };

    let diagnostics = restore_tar_member(tmp.path(), &member, SafeExtractionOptions::default()).unwrap();

    assert!(diagnostics.is_empty());
    let modified = fs::metadata(tmp.path().join("dated.txt")).unwrap().modified().unwrap().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
    assert_eq!(modified, 1_700_000_000);
}

#[test]
fn restore_revalidates_symlink_targets_from_owned_members() {
    let tmp = tempdir().unwrap();
    let member = OwnedTarMember {
        path: b"link".to_vec(),
        kind: TarEntryKind::Symlink,
        data: Vec::new(),
        link_target: Some(b"/outside".to_vec()),
        mode: 0o644,
        mtime: ArchiveTimestamp::UNIX_EPOCH,
        logical_size: 0,
        reparse_placeholder: false,
        v45_metadata: None,
        diagnostics: Vec::new(),
    };

    assert_eq!(restore_tar_member(tmp.path(), &member, SafeExtractionOptions::default()).unwrap_err(), FormatError::UnsafeArchivePath);
    assert!(!tmp.path().join("link").exists());
}

#[test]
fn skipped_entries_do_not_create_destination_parents() {
    let tmp = tempdir().unwrap();
    for (path, kind, target) in
        [(b"symlink-parent/link".as_slice(), TarEntryKind::Symlink, Some(b"target".to_vec())), (b"special-parent/fifo".as_slice(), TarEntryKind::Fifo, None)]
    {
        let member = OwnedTarMember {
            path: path.to_vec(),
            kind,
            data: Vec::new(),
            link_target: target,
            mode: 0o644,
            mtime: ArchiveTimestamp::UNIX_EPOCH,
            logical_size: 0,
            reparse_placeholder: false,
            v45_metadata: None,
            diagnostics: Vec::new(),
        };
        restore_tar_member(tmp.path(), &member, SafeExtractionOptions { restore_policy: RestorePolicy::Content, ..SafeExtractionOptions::default() }).unwrap();
    }

    assert!(!tmp.path().join("symlink-parent").exists());
    assert!(!tmp.path().join("special-parent").exists());
}

#[test]
fn safe_restore_rejects_directory_over_existing_file_even_with_overwrite() {
    let tmp = tempdir().unwrap();
    let conflict = tmp.path().join("conflict");
    fs::write(&conflict, b"not a directory").unwrap();
    let member = OwnedTarMember {
        path: b"conflict".to_vec(),
        kind: TarEntryKind::Directory,
        data: Vec::new(),
        link_target: None,
        mode: 0o644,
        mtime: ArchiveTimestamp::UNIX_EPOCH,
        logical_size: 0,
        reparse_placeholder: false,
        v45_metadata: None,
        diagnostics: Vec::new(),
    };

    assert_eq!(
        restore_tar_member(tmp.path(), &member, SafeExtractionOptions { overwrite_existing: true, ..SafeExtractionOptions::default() }).unwrap_err(),
        FormatError::UnsafeOverwrite
    );
    assert!(conflict.is_file());
}

#[test]
fn hardlink_target_checks_use_component_position_not_value() {
    let tmp = tempdir().unwrap();
    fs::create_dir(tmp.path().join("a")).unwrap();
    fs::write(tmp.path().join("a").join("a"), b"target").unwrap();
    let member = OwnedTarMember {
        path: b"linked.txt".to_vec(),
        kind: TarEntryKind::Hardlink,
        data: Vec::new(),
        link_target: Some(b"a/a".to_vec()),
        mode: 0o644,
        mtime: ArchiveTimestamp::UNIX_EPOCH,
        logical_size: 0,
        reparse_placeholder: false,
        v45_metadata: None,
        diagnostics: Vec::new(),
    };

    restore_tar_member(tmp.path(), &member, SafeExtractionOptions::default()).unwrap();
    assert_eq!(fs::read(tmp.path().join("linked.txt")).unwrap(), b"target");
}

#[test]
fn hardlink_targets_obey_max_path_length() {
    let bytes = member(b"link", b'1', b"", b"long/name");

    assert_eq!(parse_tar_member_group(&bytes, 4).unwrap_err(), FormatError::UnsafeArchivePath);
}

fn member_summary(bytes: &[u8], group_start: u64) -> TarStreamMemberSummary {
    let parsed = parse_tar_member_group(bytes, 4096).unwrap();
    TarStreamMemberSummary {
        path: parsed.path,
        kind: parsed.kind,
        link_target: parsed.link_target,
        mode: parsed.mode,
        mtime: parsed.mtime,
        logical_size: parsed.logical_size,
        file_entry_flags: parsed.v45_metadata.file_entry_flags,
        reparse_placeholder: parsed.reparse_placeholder,
        v45_metadata: parsed.v45_metadata,
        diagnostics: parsed.diagnostics,
        group_start,
        group_size: bytes.len() as u64,
    }
}

#[test]
fn member_graph_accepts_hardlink_target_after_alias_and_rejects_mirror_mismatch() {
    let alias_bytes = member(b"alias.txt", b'1', b"", b"target.txt");
    let target_bytes = member(b"target.txt", b'0', b"payload", b"");
    let alias = member_summary(&alias_bytes, 0);
    let target = member_summary(&target_bytes, alias_bytes.len() as u64);
    assert!(validate_v45_member_graph(&[alias.clone(), target.clone()]).is_ok());

    let mut mismatched_alias = alias;
    mismatched_alias.v45_metadata.portable_mirror.mode = 0o600;
    assert_eq!(
        validate_v45_member_graph(&[mismatched_alias, target]).unwrap_err(),
        FormatError::InvalidArchive("hardlink portable metadata mirror differs from canonical target")
    );
}

#[test]
fn member_graph_rejects_writes_below_selected_symlink() {
    let link_bytes = member(b"dir", b'2', b"", b"target");
    let child_bytes = member(b"dir/file.txt", b'0', b"payload", b"");
    let link = member_summary(&link_bytes, 0);
    let child = member_summary(&child_bytes, link_bytes.len() as u64);

    assert_eq!(
        validate_v45_member_graph(&[link, child]).unwrap_err(),
        FormatError::InvalidArchive("selected path graph traverses a symlink or reparse ancestor")
    );
}

#[test]
fn partial_capture_diagnostics_preserve_authenticated_omission_details() {
    let bytes = member(b"file.txt", b'0', b"payload", b"");
    let parsed = parse_tar_member_group(&bytes, 4096).unwrap();
    let mut metadata = parsed.v45_metadata;
    metadata.declaration.capture_status = CaptureStatus::Partial;
    metadata.capture_report = Some(vec![CaptureReportRow {
        profile: "portable-v1".into(),
        metadata_class: "sparse-layout".into(),
        reason: "changed-during-read".into(),
        encoded_detail: "extent%20map%20changed".into(),
    }]);

    let diagnostics =
        plan_restore(b"file.txt", &metadata, TarEntryKind::Regular, false, SafeExtractionOptions { allow_degraded: true, ..SafeExtractionOptions::default() })
            .unwrap();

    assert!(diagnostics.iter().any(|diagnostic| {
        diagnostic.profile == "portable-v1"
            && diagnostic.metadata_class == "sparse-layout"
            && diagnostic.operation == MetadataOperation::Capture
            && diagnostic.status == MetadataDiagnosticStatus::Partial
            && diagnostic.message == "capture omission: changed-during-read; detail=extent%20map%20changed"
    }));
}

#[test]
fn content_restore_reports_portable_mode_and_mtime_as_skipped() {
    let bytes = member(b"file.txt", b'0', b"payload", b"");
    let parsed = parse_tar_member_group(&bytes, 4096).unwrap();

    let diagnostics = plan_restore(
        b"file.txt",
        &parsed.v45_metadata,
        TarEntryKind::Regular,
        false,
        SafeExtractionOptions { restore_policy: RestorePolicy::Content, ..SafeExtractionOptions::default() },
    )
    .unwrap();

    for metadata_class in ["mode", "mtime"] {
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.profile == "portable-v1"
                && diagnostic.metadata_class == metadata_class
                && diagnostic.status == MetadataDiagnosticStatus::Skipped
                && diagnostic.restore_policy == Some(RestorePolicy::Content)
        }));
    }
}

#[test]
fn unsupported_required_profile_needs_explicit_degraded_restore() {
    let bytes = member(b"file.txt", b'0', b"payload", b"");
    let parsed = parse_tar_member_group(&bytes, 4096).unwrap();
    let mut metadata = parsed.v45_metadata;
    metadata.declaration.required_profiles.push("x.com.example.test-v1".into());
    metadata.declaration.optional_profiles.push("x.com.example.optional-v1".into());

    assert_eq!(
        plan_restore(b"file.txt", &metadata, TarEntryKind::Regular, false, SafeExtractionOptions::default(),).unwrap_err(),
        FormatError::ReaderUnsupported("requested restore policy requires an unsupported required profile")
    );
    let diagnostics =
        plan_restore(b"file.txt", &metadata, TarEntryKind::Regular, false, SafeExtractionOptions { allow_degraded: true, ..SafeExtractionOptions::default() })
            .unwrap();
    assert!(diagnostics.iter().any(|diagnostic| {
        diagnostic.profile == "x.com.example.test-v1"
            && diagnostic.metadata_class == "required-profile"
            && diagnostic.status == MetadataDiagnosticStatus::Unsupported
    }));
    assert!(diagnostics.iter().any(|diagnostic| {
        diagnostic.profile == "x.com.example.optional-v1"
            && diagnostic.metadata_class == "optional-profile"
            && diagnostic.status == MetadataDiagnosticStatus::Skipped
    }));
}

#[test]
fn portable_directory_metadata_is_supported_without_degradation() {
    let bytes = member(b"dir", b'5', b"", b"");
    let parsed = parse_tar_member_group(&bytes, 4096).unwrap();

    let diagnostics = plan_restore(b"dir", &parsed.v45_metadata, TarEntryKind::Directory, false, SafeExtractionOptions::default()).unwrap();
    assert!(diagnostics.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn exact_linux_restore_rejects_unrecognized_inode_flag_bits() {
    let bytes = member(b"file.txt", b'0', b"payload", b"");
    let parsed = parse_tar_member_group(&bytes, 4096).unwrap();
    let mut metadata = parsed.v45_metadata;
    metadata.declaration.source_os = "linux".into();
    metadata.declaration.required_profiles.push("linux-backup-v1".into());
    metadata.declaration.required_profiles.sort();
    metadata.primary_has_native_scalar = true;
    metadata.primary_records.insert("TZAP.linux.fsflags".into(), b"0000000080000000".to_vec());

    assert_eq!(
        plan_restore(
            b"file.txt",
            &metadata,
            TarEntryKind::Regular,
            false,
            SafeExtractionOptions { restore_policy: RestorePolicy::System, system_authorized: true, ..SafeExtractionOptions::default() },
        )
        .unwrap_err(),
        FormatError::ReaderUnsupported("requested native metadata is not supported by this conformance class")
    );
}

#[test]
fn linux_restore_creationtime_supported_under_same_os() {
    let bytes = member(b"file.txt", b'0', b"payload", b"");
    let parsed = parse_tar_member_group(&bytes, 4096).unwrap();
    let mut metadata = parsed.v45_metadata;
    metadata.declaration.source_os = "linux".into();
    metadata.declaration.required_profiles.extend(["linux-backup-v1".into(), "posix-backup-v1".into()]);
    metadata.declaration.required_profiles.sort();
    metadata.declaration.required_profiles.dedup();
    metadata.primary_has_native_scalar = true;
    metadata.primary_records.insert("LIBARCHIVE.creationtime".into(), b"1700000000.000000000".to_vec());

    let plan_res = plan_restore(
        b"file.txt",
        &metadata,
        TarEntryKind::Regular,
        false,
        SafeExtractionOptions { restore_policy: RestorePolicy::SameOs, ..SafeExtractionOptions::default() },
    );

    if cfg!(target_os = "linux") {
        assert!(plan_res.is_ok());
    } else {
        assert_eq!(plan_res.unwrap_err(), FormatError::ReaderUnsupported("requested native metadata is not supported by this conformance class"));
    }
}

#[cfg(target_os = "macos")]
#[test]
fn macos_restore_plans_unknown_and_system_flags_without_silently_applying_them() {
    let bytes = member(b"file.txt", b'0', b"payload", b"");
    let parsed = parse_tar_member_group(&bytes, 4096).unwrap();
    let mut metadata = parsed.v45_metadata;
    metadata.declaration.source_os = "macos".into();
    metadata.declaration.required_profiles.extend(["macos-backup-v1".into(), "posix-backup-v1".into()]);
    metadata.declaration.required_profiles.sort();
    metadata.declaration.required_profiles.dedup();
    metadata.primary_has_native_scalar = true;
    // UF_COMPRESSED is retained but deliberately not in the recognized/settable mask;
    // UF_IMMUTABLE is recognized but System-class under the v45 restore policy.
    metadata.primary_records.insert("TZAP.macos.st-flags".into(), b"0000000000000022".to_vec());

    let diagnostics = plan_restore(
        b"file.txt",
        &metadata,
        TarEntryKind::Regular,
        false,
        SafeExtractionOptions { restore_policy: RestorePolicy::SameOs, ..SafeExtractionOptions::default() },
    )
    .unwrap();
    assert!(diagnostics
        .iter()
        .any(|diagnostic| { diagnostic.metadata_class == "unrecognized-file-flags" && diagnostic.status == MetadataDiagnosticStatus::Skipped }));
    assert!(diagnostics
        .iter()
        .any(|diagnostic| { diagnostic.metadata_class == "system-file-flags" && diagnostic.status == MetadataDiagnosticStatus::Skipped }));
}

#[cfg(target_os = "macos")]
#[test]
fn macos_required_unknown_ordinary_flag_needs_explicit_degraded_restore() {
    let bytes = member(b"file.txt", b'0', b"payload", b"");
    let parsed = parse_tar_member_group(&bytes, 4096).unwrap();
    let mut metadata = parsed.v45_metadata;
    metadata.declaration.source_os = "macos".into();
    metadata.declaration.required_profiles.extend(["macos-backup-v1".into(), "posix-backup-v1".into()]);
    metadata.declaration.required_profiles.sort();
    metadata.declaration.required_profiles.dedup();
    metadata.primary_has_native_scalar = true;
    metadata.primary_records.insert("TZAP.macos.st-flags".into(), b"0000000000000020".to_vec());

    let strict = plan_restore(
        b"file.txt",
        &metadata,
        TarEntryKind::Regular,
        false,
        SafeExtractionOptions { restore_policy: RestorePolicy::SameOs, ..SafeExtractionOptions::default() },
    );
    assert_eq!(strict.unwrap_err(), FormatError::ReaderUnsupported("requested native metadata is not supported by this conformance class"));
    let degraded = plan_restore(
        b"file.txt",
        &metadata,
        TarEntryKind::Regular,
        false,
        SafeExtractionOptions { restore_policy: RestorePolicy::SameOs, allow_degraded: true, ..SafeExtractionOptions::default() },
    )
    .unwrap();
    assert!(degraded
        .iter()
        .any(|diagnostic| { diagnostic.metadata_class == "unrecognized-file-flags" && diagnostic.status == MetadataDiagnosticStatus::Skipped }));
}

#[cfg(target_os = "macos")]
#[test]
fn macos_unregistered_superuser_flag_stays_system_class() {
    let bytes = member(b"file.txt", b'0', b"payload", b"");
    let parsed = parse_tar_member_group(&bytes, 4096).unwrap();
    let mut metadata = parsed.v45_metadata;
    metadata.declaration.source_os = "macos".into();
    metadata.declaration.required_profiles.extend(["macos-backup-v1".into(), "posix-backup-v1".into()]);
    metadata.declaration.required_profiles.sort();
    metadata.declaration.required_profiles.dedup();
    metadata.primary_has_native_scalar = true;
    // SF_NOUNLINK is Darwin System-class but is not registered for built-in application.
    metadata.primary_records.insert("TZAP.macos.st-flags".into(), b"0000000000100000".to_vec());

    let same_os = plan_restore(
        b"file.txt",
        &metadata,
        TarEntryKind::Regular,
        false,
        SafeExtractionOptions { restore_policy: RestorePolicy::SameOs, ..SafeExtractionOptions::default() },
    )
    .unwrap();
    assert!(same_os.iter().any(|diagnostic| { diagnostic.metadata_class == "system-file-flags" && diagnostic.status == MetadataDiagnosticStatus::Skipped }));
    assert_eq!(
        plan_restore(
            b"file.txt",
            &metadata,
            TarEntryKind::Regular,
            false,
            SafeExtractionOptions { restore_policy: RestorePolicy::System, system_authorized: true, ..SafeExtractionOptions::default() },
        )
        .unwrap_err(),
        FormatError::ReaderUnsupported("requested native metadata is not supported by this conformance class")
    );
}

#[cfg(target_os = "macos")]
#[test]
fn macos_system_file_flags_fail_preflight_without_superuser_privilege() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let bytes = member(b"file.txt", b'0', b"payload", b"");
    let parsed = parse_tar_member_group(&bytes, 4096).unwrap();
    let mut metadata = parsed.v45_metadata;
    metadata.declaration.source_os = "macos".into();
    metadata.declaration.required_profiles.extend(["macos-backup-v1".into(), "posix-backup-v1".into()]);
    metadata.declaration.required_profiles.sort();
    metadata.declaration.required_profiles.dedup();
    metadata.primary_has_native_scalar = true;
    metadata.primary_records.insert("TZAP.macos.st-flags".into(), b"0000000000020000".to_vec());

    assert_eq!(
        plan_restore(
            b"file.txt",
            &metadata,
            TarEntryKind::Regular,
            false,
            SafeExtractionOptions { restore_policy: RestorePolicy::System, system_authorized: true, ..SafeExtractionOptions::default() },
        )
        .unwrap_err(),
        FormatError::ReaderUnsupported("requested native metadata is not supported by this conformance class")
    );
}

#[cfg(target_os = "macos")]
#[test]
fn macos_device_restore_fails_preflight_without_superuser_privilege() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let bytes = member(b"device", b'0', b"", b"");
    let parsed = parse_tar_member_group(&bytes, 4096).unwrap();

    assert_eq!(
        plan_restore(
            b"device",
            &parsed.v45_metadata,
            TarEntryKind::CharacterDevice,
            false,
            SafeExtractionOptions { restore_policy: RestorePolicy::System, system_authorized: true, ..SafeExtractionOptions::default() },
        )
        .unwrap_err(),
        FormatError::ReaderUnsupported("requested native metadata is not supported by this conformance class")
    );
}

#[cfg(target_os = "macos")]
#[test]
fn macos_resource_fork_support_is_primary_kind_aware() {
    let record = AuxiliaryRecord {
        ordinal: 0,
        kind: "macos.resource-fork".into(),
        profile: "macos-backup-v1".into(),
        restore_class: RestoreClass::SameOs,
        native: true,
        name_encoding: "none".into(),
        decoded_name: Vec::new(),
        flags: 0,
        logical_size: u64::from(u32::MAX) + 1,
        stored_size: 0,
        sha256: [0; 32],
        meta: BTreeMap::new(),
        sparse_layout: None,
        capture_report_payload: None,
    };
    assert!(native_auxiliary_restore_supported(&record, false, Some(TarEntryKind::Regular)));
    assert!(!native_auxiliary_restore_supported(&record, false, Some(TarEntryKind::Symlink)));
    assert!(!native_auxiliary_restore_supported(&record, false, Some(TarEntryKind::Fifo)));
}

#[cfg(target_os = "linux")]
#[test]
fn generic_xattr_auxiliary_failure_is_bound_to_pinned_special_object() {
    use sha2::{Digest as _, Sha256};
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;

    let temp = tempfile::tempdir().unwrap();
    let fifo = temp.path().join("events.fifo");
    let fifo_c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
    let value = b"member-bound auxiliary value";
    let mut staged_file = tempfile::tempfile().unwrap();
    staged_file.write_all(value).unwrap();
    staged_file.seek(SeekFrom::Start(0)).unwrap();
    let mut staged = vec![StagedAuxiliary {
        record: AuxiliaryRecord {
            ordinal: 0,
            kind: "generic.xattr".into(),
            profile: "posix-backup-v1".into(),
            restore_class: RestoreClass::SameOs,
            native: true,
            name_encoding: "bytes".into(),
            decoded_name: b"user.tzap-aux".to_vec(),
            flags: 0,
            logical_size: value.len() as u64,
            stored_size: value.len() as u64,
            sha256: Sha256::digest(value).into(),
            meta: BTreeMap::new(),
            sparse_layout: None,
            capture_report_payload: None,
        },
        file: staged_file,
    }];
    let mut diagnostics = Vec::new();

    apply_generic_xattr_auxiliaries_to_path(
        &fifo,
        true,
        b"events.fifo",
        &mut staged,
        SafeExtractionOptions { restore_policy: RestorePolicy::SameOs, allow_degraded: true, ..SafeExtractionOptions::default() },
        &mut diagnostics,
    )
    .unwrap();

    assert!(staged.is_empty());
    assert!(diagnostics
        .iter()
        .any(|diagnostic| { diagnostic.metadata_class == "extended-attribute" && diagnostic.status == MetadataDiagnosticStatus::Failed }));
    assert_eq!(xattr::get(&fifo, "user.tzap-aux").unwrap(), None);
}

#[test]
fn sparse_layout_materialization_requires_explicit_degraded_portable_restore() {
    let bytes = member(b"sparse.bin", b'0', b"data", b"");
    let mut parsed = parse_tar_member_group(&bytes, 4096).unwrap();
    parsed.v45_metadata.file_entry_flags |= HAS_SPARSE_EXTENTS;

    let strict = plan_restore(b"sparse.bin", &parsed.v45_metadata, TarEntryKind::Regular, false, SafeExtractionOptions::default());
    #[cfg(any(windows, target_os = "linux"))]
    assert!(strict.unwrap().is_empty());
    #[cfg(not(any(windows, target_os = "linux")))]
    assert_eq!(strict.unwrap_err(), FormatError::ReaderUnsupported("sparse layout materialization needs explicit degraded restore"));

    let degraded = plan_restore(
        b"sparse.bin",
        &parsed.v45_metadata,
        TarEntryKind::Regular,
        false,
        SafeExtractionOptions { allow_degraded: true, ..SafeExtractionOptions::default() },
    )
    .unwrap();
    #[cfg(any(windows, target_os = "linux"))]
    assert!(degraded.is_empty());
    #[cfg(not(any(windows, target_os = "linux")))]
    assert!(degraded.iter().any(|diagnostic| {
        diagnostic.metadata_class == "sparse-layout"
            && diagnostic.status == MetadataDiagnosticStatus::Materialized
            && diagnostic.restore_policy == Some(RestorePolicy::Portable)
    }));

    let content = plan_restore(
        b"sparse.bin",
        &parsed.v45_metadata,
        TarEntryKind::Regular,
        false,
        SafeExtractionOptions { restore_policy: RestorePolicy::Content, ..SafeExtractionOptions::default() },
    )
    .unwrap();
    assert!(content.iter().any(|diagnostic| { diagnostic.metadata_class == "sparse-layout" && diagnostic.restore_policy == Some(RestorePolicy::Content) }));
}

#[test]
fn validate_symlink_target_rules() {
    // Valid absolute symlink target
    assert!(validate_symlink_target(b"sub/link", b"/tmp/abs_target").is_ok());

    // Invalid absolute symlink target with non-NFC characters
    let non_nfc_abs = "/tmp/abs_\u{0065}\u{0301}";
    assert!(validate_symlink_target(b"sub/link", non_nfc_abs.as_bytes()).is_err());

    // Invalid symlink targets containing null, backslash, or colon
    assert!(validate_symlink_target(b"sub/link", b"/tmp/target\0bad").is_err());
    assert!(validate_symlink_target(b"sub/link", b"/tmp/target\\bad").is_err());
    assert!(validate_symlink_target(b"sub/link", b"/tmp/target:bad").is_err());

    // Valid relative target within sub directory
    assert!(validate_symlink_target(b"sub/link", b"../file.txt").is_ok());

    // Invalid relative target escaping root
    assert!(validate_symlink_target(b"sub/link", b"../../file.txt").is_err());
}
