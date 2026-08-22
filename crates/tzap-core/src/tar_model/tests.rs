use super::pax::StreamingSparsePrimary;
#[cfg(unix)]
use super::restore::create_directory;
use super::restore::{
    plan_restore, prepare_destination, restore_tar_member, PreparedDestination, StreamedTarMemberMetadata, TarMemberGroupReader, TarMemberStreamHandler,
    TarStreamObserver,
};
use super::sparse::{create_temp_regular_file, publish_regular_file, stream_sparse_primary_payload, write_zero_run};
use super::*;
use crate::encode_v45_sparse_map;
use crate::entry_metadata::*;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::collections::BTreeMap;
use tempfile::tempdir;

fn header(path: &[u8], kind: u8, size: usize, link: &[u8]) -> [u8; TAR_BLOCK_LEN] {
    let mut header = [0u8; TAR_BLOCK_LEN];
    header[..path.len()].copy_from_slice(path);
    let mode = if kind == b'5' { 0o755 } else { 0o644 };
    write_octal(&mut header[100..108], mode);
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
    let mode = if kind == b'5' { 0o755 } else { 0o644 };
    let records = crate::entry_metadata::portable_primary_pax(path, mode, "other", false).unwrap();
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

struct SliceMemberReader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> SliceMemberReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }
}

impl TarMemberGroupReader for SliceMemberReader<'_> {
    fn read_some_member_bytes(&mut self, buf: &mut [u8]) -> Result<usize, ExtractError> {
        let available = &self.data[self.offset..];
        let n = buf.len().min(available.len());
        buf[..n].copy_from_slice(&available[..n]);
        self.offset += n;
        Ok(n)
    }
}

struct SliceReader<'a> {
    slice: &'a [u8],
}

impl<'a> TarMemberGroupReader for SliceReader<'a> {
    fn read_some_member_bytes(&mut self, buf: &mut [u8]) -> Result<usize, ExtractError> {
        let n = self.slice.len().min(buf.len());
        buf[..n].copy_from_slice(&self.slice[..n]);
        self.slice = &self.slice[n..];
        Ok(n)
    }
}

#[derive(Default)]
struct MockSparseStreamHandler {
    native_mode: bool,
    regular_payload: Vec<u8>,
    sparse_extents: Vec<(u64, Vec<u8>)>,
    finished: bool,
}

impl TarMemberStreamHandler for MockSparseStreamHandler {
    fn on_member(&mut self, _member: &StreamedTarMemberMetadata) -> Result<(), ExtractError> {
        Ok(())
    }
    fn write_regular_payload(&mut self, bytes: &[u8]) -> Result<(), ExtractError> {
        self.regular_payload.extend_from_slice(bytes);
        Ok(())
    }
    fn begin_sparse_payload(&mut self, _logical_size: u64, _extents: &[SparseExtent]) -> Result<bool, ExtractError> {
        Ok(self.native_mode)
    }
    fn write_sparse_extent(&mut self, offset: u64, bytes: &[u8]) -> Result<(), ExtractError> {
        self.sparse_extents.push((offset, bytes.to_vec()));
        Ok(())
    }
    fn finish_sparse_payload(&mut self) -> Result<(), ExtractError> {
        self.finished = true;
        Ok(())
    }
}

#[derive(Default)]
struct MockStreamObserver {
    native_mode: bool,
    regular_payload: Vec<u8>,
    sparse_extents: Vec<(u64, Vec<u8>)>,
    completed: bool,
}

impl TarStreamObserver for MockStreamObserver {
    fn on_regular_payload(&mut self, bytes: &[u8]) -> Result<(), FormatError> {
        self.regular_payload.extend_from_slice(bytes);
        Ok(())
    }
    fn on_sparse_layout(&mut self, _logical_size: u64, _extents: &[SparseExtent]) -> Result<bool, FormatError> {
        Ok(self.native_mode)
    }
    fn on_sparse_extent(&mut self, offset: u64, bytes: &[u8]) -> Result<(), FormatError> {
        self.sparse_extents.push((offset, bytes.to_vec()));
        Ok(())
    }
    fn on_sparse_complete(&mut self) -> Result<(), FormatError> {
        self.completed = true;
        Ok(())
    }
}

#[test]
fn stream_sparse_primary_payload_native_and_regular_modes() {
    let extents = vec![SparseExtent { offset: 100, length: 50 }, SparseExtent { offset: 200, length: 60 }];
    let logical_size = 300u64;
    let map = encode_v45_sparse_map(&extents, logical_size).unwrap();
    let extent1_data = vec![0x11u8; 50];
    let extent2_data = vec![0x22u8; 60];

    let mut payload = Vec::new();
    payload.extend_from_slice(&map);
    payload.extend_from_slice(&extent1_data);
    payload.extend_from_slice(&extent2_data);
    let stored_size = payload.len() as u64;

    // Test native output mode
    {
        let mut reader = SliceMemberReader::new(&payload);
        let mut remaining = stored_size;
        let mut handler = MockSparseStreamHandler { native_mode: true, ..Default::default() };
        stream_sparse_primary_payload(&mut reader, stored_size, logical_size, &mut remaining, &mut handler).unwrap();
        assert_eq!(remaining, 0);
        assert!(handler.finished);
        assert_eq!(handler.sparse_extents.len(), 2);
        assert_eq!(handler.sparse_extents[0], (100, extent1_data.clone()));
        assert_eq!(handler.sparse_extents[1], (200, extent2_data.clone()));
    }

    // Test non-native (degraded regular) mode
    {
        let mut reader = SliceMemberReader::new(&payload);
        let mut remaining = stored_size;
        let mut handler = MockSparseStreamHandler { native_mode: false, ..Default::default() };
        stream_sparse_primary_payload(&mut reader, stored_size, logical_size, &mut remaining, &mut handler).unwrap();
        assert_eq!(remaining, 0);
        assert_eq!(handler.regular_payload.len(), 300);
        assert_eq!(&handler.regular_payload[0..100], &[0u8; 100]);
        assert_eq!(&handler.regular_payload[100..150], &extent1_data);
        assert_eq!(&handler.regular_payload[150..200], &[0u8; 50]);
        assert_eq!(&handler.regular_payload[200..260], &extent2_data);
        assert_eq!(&handler.regular_payload[260..300], &[0u8; 40]);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn punch_linux_sparse_holes_comprehensive() {
    use super::sparse::punch_linux_sparse_holes;
    use tempfile::tempfile;

    let file = tempfile().unwrap();
    file.set_len(1000).unwrap();

    let extents = vec![SparseExtent { offset: 100, length: 200 }, SparseExtent { offset: 500, length: 300 }];
    assert!(punch_linux_sparse_holes(&file, 1000, &extents).is_ok());

    // Empty extents
    assert!(punch_linux_sparse_holes(&file, 1000, &[]).is_ok());
    // Zero length logical size
    assert!(punch_linux_sparse_holes(&file, 0, &[]).is_ok());
}

fn parsed_member(path: &[u8], kind: u8, data: &[u8], link: &[u8]) -> OwnedTarMember {
    let bytes = member(path, kind, data, link);
    let parsed = parse_tar_member_group(&bytes, 4096).unwrap();
    parsed.to_owned_member().unwrap()
}

#[test]
fn stream_sparse_primary_payload_error_cases() {
    let mut handler = MockSparseStreamHandler::default();

    // stored_size < 512
    let mut reader = SliceMemberReader::new(&[0u8; 256]);
    let mut remaining = 256;
    let err = stream_sparse_primary_payload(&mut reader, 256, 1000, &mut remaining, &mut handler).unwrap_err();
    assert!(matches!(err, ExtractError::Format(FormatError::InvalidArchive("sparse primary map is truncated"))));

    // Map stored size mismatch
    let extents = vec![SparseExtent { offset: 10, length: 20 }];
    let map = encode_v45_sparse_map(&extents, 100).unwrap();
    let mut payload = map.clone();
    payload.extend_from_slice(&[0u8; 10]); // shorter than declared 20 bytes
    let mut reader = SliceMemberReader::new(&payload);
    let mut remaining = payload.len() as u64;
    let err = stream_sparse_primary_payload(&mut reader, payload.len() as u64, 100, &mut remaining, &mut handler).unwrap_err();
    assert!(matches!(err, ExtractError::Format(FormatError::InvalidArchive("sparse primary stored size does not match its map"))));
}

#[test]
fn write_zero_run_variations() {
    let mut handler = MockSparseStreamHandler::default();
    let zeros = [0u8; 64 * 1024];

    // 0 length
    write_zero_run(&mut handler, &zeros, 0).unwrap();
    assert!(handler.regular_payload.is_empty());

    // Small length
    write_zero_run(&mut handler, &zeros, 15).unwrap();
    assert_eq!(handler.regular_payload.len(), 15);
    assert_eq!(handler.regular_payload, vec![0u8; 15]);

    // Multi-chunk length
    handler.regular_payload.clear();
    let big_len = (64 * 1024 * 2) + 500;
    write_zero_run(&mut handler, &zeros, big_len as u64).unwrap();
    assert_eq!(handler.regular_payload.len(), big_len);
    assert!(handler.regular_payload.iter().all(|&b| b == 0));
}

#[test]
fn create_and_publish_temp_regular_file() {
    let dir = tempfile::tempdir().unwrap();
    let ambient_dir = cap_std::fs::Dir::open_ambient_dir(dir.path(), cap_std::ambient_authority()).unwrap();
    let prep = PreparedDestination { parent: ambient_dir, leaf: PathBuf::from("target.txt") };
    let (tmp_leaf, mut tmp_file) = create_temp_regular_file(&prep).unwrap();
    assert!(tmp_leaf.to_str().unwrap().contains(".tzap-tmp-"));
    tmp_file.write_all(b"sparse file data").unwrap();

    let published = publish_regular_file(
        &prep,
        &tmp_leaf,
        tmp_file,
        SafeExtractionOptions { overwrite_existing: false, sync_published_files: false, ..Default::default() },
    )
    .unwrap();
    drop(published);

    assert_eq!(fs::read(dir.path().join("target.txt")).unwrap(), b"sparse file data");

    // Publishing again without overwrite_existing must fail
    let (tmp_leaf2, mut tmp_file2) = create_temp_regular_file(&prep).unwrap();
    tmp_file2.write_all(b"new data").unwrap();
    let err = publish_regular_file(
        &prep,
        &tmp_leaf2,
        tmp_file2,
        SafeExtractionOptions { overwrite_existing: false, sync_published_files: false, ..Default::default() },
    )
    .unwrap_err();
    assert_eq!(err, FormatError::UnsafeOverwrite);

    // Publishing with overwrite_existing and sync_published_files must succeed
    let (tmp_leaf3, mut tmp_file3) = create_temp_regular_file(&prep).unwrap();
    tmp_file3.write_all(b"overwritten content").unwrap();
    let published3 = publish_regular_file(
        &prep,
        &tmp_leaf3,
        tmp_file3,
        SafeExtractionOptions { overwrite_existing: true, sync_published_files: true, ..Default::default() },
    )
    .unwrap();
    drop(published3);
    assert_eq!(fs::read(dir.path().join("target.txt")).unwrap(), b"overwritten content");
}

#[test]
fn streaming_sparse_primary_observer_behaviour() {
    let extents = vec![SparseExtent { offset: 50, length: 30 }, SparseExtent { offset: 120, length: 40 }];
    let logical_size = 200u64;
    let map = encode_v45_sparse_map(&extents, logical_size).unwrap();
    let extent1 = vec![0x33u8; 30];
    let extent2 = vec![0x44u8; 40];

    let mut payload = Vec::new();
    payload.extend_from_slice(&map);
    payload.extend_from_slice(&extent1);
    payload.extend_from_slice(&extent2);

    // Test with native observer
    {
        let mut observer = MockStreamObserver { native_mode: true, ..Default::default() };
        let mut sparse = StreamingSparsePrimary::new(logical_size);
        for chunk in payload.chunks(64) {
            sparse.observe(chunk, &mut observer).unwrap();
        }
        sparse.finish(&mut observer).unwrap();
        assert!(observer.completed);
        let total_sparse_bytes: usize = observer.sparse_extents.iter().map(|(_, b)| b.len()).sum();
        assert_eq!(total_sparse_bytes, 70);
    }

    // Test with non-native observer (expands holes as zeros)
    {
        let mut observer = MockStreamObserver { native_mode: false, ..Default::default() };
        let mut sparse = StreamingSparsePrimary::new(logical_size);
        for chunk in payload.chunks(64) {
            sparse.observe(chunk, &mut observer).unwrap();
        }
        sparse.finish(&mut observer).unwrap();
        assert_eq!(observer.regular_payload.len(), 200);
        assert_eq!(&observer.regular_payload[0..50], &[0u8; 50]);
        assert_eq!(&observer.regular_payload[50..80], &extent1);
        assert_eq!(&observer.regular_payload[80..120], &[0u8; 40]);
        assert_eq!(&observer.regular_payload[120..160], &extent2);
        assert_eq!(&observer.regular_payload[160..200], &[0u8; 40]);
    }
}

#[test]
fn parse_tar_member_group_error_branches() {
    // Length not a multiple of 512
    assert_eq!(parse_tar_member_group(&[0u8; 100], 4096).unwrap_err(), FormatError::InvalidArchive("tar member group is not block aligned"));

    // Empty / all-zero header block
    let zeros = vec![0u8; 1536];
    assert_eq!(parse_tar_member_group(&zeros, 4096).unwrap_err(), FormatError::InvalidArchive("tar member header is empty"));

    // Corrupted checksum (change payload byte without updating checksum)
    let mut valid_group = member(b"test.txt", b'0', b"hello", b"");
    valid_group[0] = b'X'; // modifies header name so checksum won't match
    assert_eq!(parse_tar_member_group(&valid_group, 4096).unwrap_err(), FormatError::InvalidArchive("tar header checksum mismatch"));

    // Non-zero padding after payload
    let mut non_zero_pad = member(b"test.txt", b'0', b"hello", b"");
    // Find the end of payload data (which is 5 bytes), then corrupt padding in the block
    let last_byte = non_zero_pad.len() - 1;
    non_zero_pad[last_byte] = 0xFF;
    assert_eq!(parse_tar_member_group(&non_zero_pad, 4096).unwrap_err(), FormatError::InvalidArchive("tar member padding is non-zero"));
}

#[test]
fn validate_v45_member_graph_and_owned_restore_plan_error_branches() {
    use super::pax::validate_owned_restore_plan;

    // Case 1: Hardlink target not present in the graph
    let alias_bytes = member(b"link.txt", b'1', b"", b"nonexistent.txt");
    let alias = member_summary(&alias_bytes, 0);
    assert_eq!(validate_v45_member_graph(&[alias]).unwrap_err(), FormatError::InvalidArchive("hardlink target is not present in the selected archive graph"));

    // Case 2: Hardlink target is not a regular file (e.g. target is a symlink)
    let link_bytes = member(b"alias_to_sym.txt", b'1', b"", b"symlink_target");
    let sym_bytes = member(b"symlink_target", b'2', b"", b"real_file");
    let link = member_summary(&link_bytes, 0);
    let sym = member_summary(&sym_bytes, link_bytes.len() as u64);
    assert_eq!(validate_v45_member_graph(&[link, sym]).unwrap_err(), FormatError::InvalidArchive("hardlink target is not a canonical regular primary"));

    // Case 3: Path traverses a non-directory ancestor (e.g., "file" is a regular file, but "file/child.txt" is selected)
    let file_bytes = member(b"file", b'0', b"data", b"");
    let child_bytes = member(b"file/child.txt", b'0', b"data", b"");
    let file = member_summary(&file_bytes, 0);
    let child = member_summary(&child_bytes, file_bytes.len() as u64);
    assert_eq!(validate_v45_member_graph(&[file, child]).unwrap_err(), FormatError::InvalidArchive("selected path graph traverses a non-directory ancestor"));

    // Case 4: validate_owned_restore_plan duplicate paths
    let m1_bytes = member(b"duplicate.txt", b'0', b"a", b"");
    let m1 = parse_tar_member_group(&m1_bytes, 4096).unwrap().to_owned_member().unwrap();
    let m2_bytes = member(b"duplicate.txt", b'0', b"b", b"");
    let m2 = parse_tar_member_group(&m2_bytes, 4096).unwrap().to_owned_member().unwrap();
    assert_eq!(
        validate_owned_restore_plan(&[&m1, &m2], SafeExtractionOptions::default()).unwrap_err(),
        FormatError::InvalidArchive("restore plan contains duplicate selected paths")
    );

    // Case 5: validate_owned_restore_plan hardlink target missing in restore graph
    let h1_bytes = member(b"alias.txt", b'1', b"", b"missing.txt");
    let h1 = parse_tar_member_group(&h1_bytes, 4096).unwrap().to_owned_member().unwrap();
    assert_eq!(
        validate_owned_restore_plan(&[&h1], SafeExtractionOptions::default()).unwrap_err(),
        FormatError::InvalidArchive("hardlink target is not present in the selected restore graph")
    );
}

fn member_with_auxiliary(path: &[u8], aux_kind: &str, aux_name: &[u8], aux_data: &[u8], file_data: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    let mut records = crate::entry_metadata::portable_primary_pax(path, 0o644, "linux", false).unwrap();
    records.insert("TZAP.metadata.optional-profiles".into(), b"posix-backup-v1".to_vec());
    let primary_pax = crate::entry_metadata::encode_canonical_pax(&records).unwrap();
    let mut primary_pax_header = header(b"TZAP-PAX/PRIMARY", b'x', primary_pax.len(), b"");
    write_octal(&mut primary_pax_header[100..108], 0);
    primary_pax_header[148..156].fill(b' ');
    let checksum = primary_pax_header.iter().map(|b| *b as u64).sum::<u64>();
    write_checksum(&mut primary_pax_header[148..156], checksum);

    let sha256_hex = format!("{:x}", sha2::Sha256::digest(aux_data));
    let mut aux_records = PaxRecords::new();
    aux_records.insert("TZAP.aux.version".into(), b"1".to_vec());
    aux_records.insert("TZAP.aux.kind".into(), aux_kind.as_bytes().to_vec());
    aux_records.insert("TZAP.aux.profile".into(), b"posix-backup-v1".to_vec());
    aux_records.insert("TZAP.aux.restore-class".into(), b"same-os".to_vec());
    aux_records.insert("TZAP.aux.native".into(), b"1".to_vec());
    aux_records.insert("TZAP.aux.name-encoding".into(), b"bytes-base64".to_vec());
    aux_records.insert("TZAP.aux.name".into(), canonical_base64_encode(aux_name));
    aux_records.insert("TZAP.aux.flags".into(), b"0000000000000000".to_vec());
    aux_records.insert("TZAP.aux.logical-size".into(), format!("{}", aux_data.len()).into_bytes());
    aux_records.insert("TZAP.aux.sha256".into(), sha256_hex.into_bytes());

    let aux_pax = crate::entry_metadata::encode_canonical_pax(&aux_records).unwrap();
    let mut aux_pax_header = header(b"TZAP-PAX/AUX/00000000", b'x', aux_pax.len(), b"");
    write_octal(&mut aux_pax_header[100..108], 0);
    aux_pax_header[148..156].fill(b' ');
    let checksum = aux_pax_header.iter().map(|b| *b as u64).sum::<u64>();
    write_checksum(&mut aux_pax_header[148..156], checksum);

    let mut aux_data_header = header(b"TZAP-AUX/00000000", b'Z', aux_data.len(), b"");
    write_octal(&mut aux_data_header[100..108], 0);
    aux_data_header[148..156].fill(b' ');
    let checksum = aux_data_header.iter().map(|b| *b as u64).sum::<u64>();
    write_checksum(&mut aux_data_header[148..156], checksum);

    let mut out = Vec::new();
    out.extend_from_slice(&aux_pax_header);
    out.extend_from_slice(&aux_pax);
    out.resize(out.len() + padding_to_512(aux_pax.len()), 0);

    out.extend_from_slice(&aux_data_header);
    out.extend_from_slice(aux_data);
    out.resize(out.len() + padding_to_512(aux_data.len()), 0);

    out.extend_from_slice(&primary_pax_header);
    out.extend_from_slice(&primary_pax);
    out.resize(out.len() + padding_to_512(primary_pax.len()), 0);

    out.extend_from_slice(&header(path, b'0', file_data.len(), b""));
    out.extend_from_slice(file_data);
    out.resize(out.len() + padding_to_512(file_data.len()), 0);

    out
}

#[test]
fn parse_tar_member_group_with_auxiliary_records_and_stream_handling() {
    let aux_group = member_with_auxiliary(b"hello.txt", "generic.xattr", b"user.meta", b"custom metadata value", b"file body text");
    let parsed = parse_tar_member_group(&aux_group, 4096).unwrap();
    assert_eq!(parsed.path, b"hello.txt");
    assert_eq!(parsed.kind, TarEntryKind::Regular);
    assert_eq!(parsed.v45_metadata.auxiliary.len(), 1);
    assert_eq!(parsed.v45_metadata.auxiliary[0].kind, "generic.xattr");
    assert_eq!(parsed.v45_metadata.auxiliary[0].decoded_name, b"user.meta");

    // Trait default implementations coverage
    struct DefaultHandler;
    impl TarMemberStreamHandler for DefaultHandler {
        fn on_member(&mut self, _member: &StreamedTarMemberMetadata) -> Result<(), ExtractError> {
            Ok(())
        }
        fn write_regular_payload(&mut self, _bytes: &[u8]) -> Result<(), ExtractError> {
            Ok(())
        }
    }

    let mut handler = DefaultHandler;
    let aux_rec = &parsed.v45_metadata.auxiliary[0];
    assert!(!handler.begin_auxiliary_payload(aux_rec).unwrap());
    assert!(handler.write_auxiliary_payload(b"test").is_ok());
    assert!(handler.finish_auxiliary_payload(aux_rec).is_ok());
    assert!(!handler.begin_sparse_payload(100, &[]).unwrap());
    assert!(handler.write_sparse_extent(0, b"data").is_err());
    assert!(handler.finish_sparse_payload().is_ok());
}

#[test]
fn restore_tar_member_various_kinds_and_policies() {
    let temp = tempdir().unwrap();
    let root = temp.path();

    // 1. Regular file restore under Content policy
    let reg_bytes = member(b"regular.txt", b'0', b"hello content", b"");
    let reg_member = parse_tar_member_group(&reg_bytes, 4096).unwrap().to_owned_member().unwrap();
    let opts_content =
        SafeExtractionOptions { restore_policy: RestorePolicy::Content, overwrite_existing: true, allow_degraded: true, ..SafeExtractionOptions::default() };
    let diags = restore_tar_member(root, &reg_member, opts_content).unwrap();
    assert_eq!(std::fs::read(root.join("regular.txt")).unwrap(), b"hello content");
    assert_eq!(diags.len(), 2);
    assert_eq!(diags[0].status, MetadataDiagnosticStatus::Skipped);

    // 2. Directory restore under Content and Portable policies
    let dir_bytes = member(b"somedir", b'5', b"", b"");
    let dir_member = parse_tar_member_group(&dir_bytes, 4096).unwrap().to_owned_member().unwrap();
    let diags_dir = restore_tar_member(root, &dir_member, opts_content).unwrap();
    assert!(root.join("somedir").is_dir());
    assert_eq!(diags_dir.len(), 2);
    assert_eq!(diags_dir[0].status, MetadataDiagnosticStatus::Skipped);

    let opts_portable =
        SafeExtractionOptions { restore_policy: RestorePolicy::Portable, overwrite_existing: true, allow_degraded: true, ..SafeExtractionOptions::default() };
    let diags_dir_port = restore_tar_member(root, &dir_member, opts_portable).unwrap();
    assert!(diags_dir_port.is_empty());

    // 3. Hardlink restore under Content policy (materializes target bytes)
    let hl_bytes = member(b"hardlink_copy.txt", b'1', b"", b"regular.txt");
    let hl_member = parse_tar_member_group(&hl_bytes, 4096).unwrap().to_owned_member().unwrap();
    let diags_hl = restore_tar_member(root, &hl_member, opts_content).unwrap();
    assert_eq!(std::fs::read(root.join("hardlink_copy.txt")).unwrap(), b"hello content");
    assert_eq!(diags_hl.len(), 3);
    assert!(diags_hl.iter().any(|d| d.status == MetadataDiagnosticStatus::Materialized));

    // 4. Special object (Fifo) under Portable policy (skipped)
    let mut fifo_records = crate::entry_metadata::portable_primary_pax(b"my_fifo", 0o644, "linux", false).unwrap();
    fifo_records.insert("TZAP.metadata.required-profiles".into(), b"portable-v1,posix-backup-v1".to_vec());
    let fifo_pax = crate::entry_metadata::encode_canonical_pax(&fifo_records).unwrap();
    let mut fifo_pax_header = header(b"TZAP-PAX/PRIMARY", b'x', fifo_pax.len(), b"");
    write_octal(&mut fifo_pax_header[100..108], 0);
    fifo_pax_header[148..156].fill(b' ');
    let checksum = fifo_pax_header.iter().map(|b| *b as u64).sum::<u64>();
    write_checksum(&mut fifo_pax_header[148..156], checksum);
    let mut fifo_bytes = Vec::new();
    fifo_bytes.extend_from_slice(&fifo_pax_header);
    fifo_bytes.extend_from_slice(&fifo_pax);
    fifo_bytes.resize(fifo_bytes.len() + padding_to_512(fifo_pax.len()), 0);
    fifo_bytes.extend_from_slice(&header(b"my_fifo", b'6', 0, b""));
    fifo_bytes.resize(fifo_bytes.len() + padding_to_512(0), 0);

    let fifo_member = parse_tar_member_group(&fifo_bytes, 4096).unwrap().to_owned_member().unwrap();
    let diags_fifo = restore_tar_member(root, &fifo_member, opts_portable).unwrap();
    assert_eq!(diags_fifo.len(), 3);
    assert!(diags_fifo.iter().all(|d| d.status == MetadataDiagnosticStatus::Skipped));

    // 5. Symlink restore under Content policy (symlink skipped)
    let sym_bytes = member(b"symlink_rel", b'2', b"", b"regular.txt");
    let sym_member = parse_tar_member_group(&sym_bytes, 4096).unwrap().to_owned_member().unwrap();
    let diags_sym_content = restore_tar_member(root, &sym_member, opts_content).unwrap();
    assert_eq!(diags_sym_content.len(), 3);
    assert!(diags_sym_content.iter().all(|d| d.status == MetadataDiagnosticStatus::Skipped));

    // 6. Symlink restore under Portable policy
    let diags_sym_port = restore_tar_member(root, &sym_member, opts_portable).unwrap();
    assert!(diags_sym_port.is_empty());
    #[cfg(unix)]
    assert_eq!(std::fs::read_link(root.join("symlink_rel")).unwrap(), std::path::Path::new("regular.txt"));
}

#[test]
fn restore_directory_and_symlink_and_hardlink_members() {
    let tmp = tempdir().unwrap();

    // 1. Restore Directory
    let dir_member = parsed_member(b"subdir", b'5', b"", b"");
    restore_tar_member(tmp.path(), &dir_member, SafeExtractionOptions::default()).unwrap();
    assert!(tmp.path().join("subdir").is_dir());

    // 2. Restore Regular file in Directory
    let file_member = parsed_member(b"subdir/file.txt", b'0', b"hello world", b"");
    restore_tar_member(tmp.path(), &file_member, SafeExtractionOptions::default()).unwrap();
    assert_eq!(fs::read(tmp.path().join("subdir/file.txt")).unwrap(), b"hello world");

    // 3. Restore Symlink
    #[cfg(unix)]
    {
        let symlink_member = parsed_member(b"subdir/link.txt", b'2', b"", b"file.txt");
        restore_tar_member(tmp.path(), &symlink_member, SafeExtractionOptions::default()).unwrap();
        assert!(tmp.path().join("subdir/link.txt").is_symlink());
    }

    // 4. Restore Hardlink
    let hardlink_member = parsed_member(b"subdir/hard.txt", b'1', b"", b"subdir/file.txt");
    restore_tar_member(tmp.path(), &hardlink_member, SafeExtractionOptions::default()).unwrap();
    assert_eq!(fs::read(tmp.path().join("subdir/hard.txt")).unwrap(), b"hello world");

    // 5. Hardlink with missing target fails
    let bad_hardlink = parsed_member(b"subdir/bad_hard.txt", b'1', b"", b"nonexistent.txt");
    assert_eq!(restore_tar_member(tmp.path(), &bad_hardlink, SafeExtractionOptions::default()).unwrap_err(), FormatError::UnsafeArchivePath);
}

#[test]
fn metadata_verification_report_generation() {
    use super::os_restore::metadata_verification_report;

    let bytes = member(b"file.txt", b'0', b"hello", b"");
    let summary = member_summary(&bytes, 0);

    let report = metadata_verification_report(&[summary]).unwrap();
    assert!(report.all_capture_complete);
    assert_eq!(report.entries.len(), 1);
    assert_eq!(report.entries[0].path, b"file.txt");
    assert!(report.entries[0].policy_capabilities.iter().any(|c| c.policy == RestorePolicy::Portable && c.policy_complete));
}

#[test]
fn safe_restore_rejects_unsafe_paths_and_overwrites() {
    let tmp = tempdir().unwrap();

    // Absolute path
    let mut abs_member = parsed_member(b"file.txt", b'0', b"bad", b"");
    abs_member.path = b"/etc/passwd".to_vec();
    assert_eq!(restore_tar_member(tmp.path(), &abs_member, SafeExtractionOptions::default()).unwrap_err(), FormatError::UnsafeArchivePath);

    // Path with ..
    let mut escape_member = parsed_member(b"file.txt", b'0', b"bad", b"");
    escape_member.path = b"../escape.txt".to_vec();
    assert_eq!(restore_tar_member(tmp.path(), &escape_member, SafeExtractionOptions::default()).unwrap_err(), FormatError::UnsafeArchivePath);

    // Overwriting existing file without overwrite flag
    let regular = parsed_member(b"exists.txt", b'0', b"v1", b"");
    restore_tar_member(tmp.path(), &regular, SafeExtractionOptions::default()).unwrap();

    let overwrite_attempt = parsed_member(b"exists.txt", b'0', b"v2", b"");
    assert_eq!(
        restore_tar_member(tmp.path(), &overwrite_attempt, SafeExtractionOptions { overwrite_existing: false, ..SafeExtractionOptions::default() })
            .unwrap_err(),
        FormatError::UnsafeOverwrite
    );

    // With overwrite = true, it succeeds
    assert!(restore_tar_member(tmp.path(), &overwrite_attempt, SafeExtractionOptions { overwrite_existing: true, ..SafeExtractionOptions::default() }).is_ok());
    assert_eq!(fs::read(tmp.path().join("exists.txt")).unwrap(), b"v2");
}

#[test]
fn os_restore_flags_and_auxiliary_checks() {
    use super::os_restore::{
        macos_flags_require_system, macos_flags_supported, native_auxiliary_restore_supported,
        parse_macos_flags, source_os_matches_current_host, special_object_restore_supported,
        system_xattr_name,
    };
    #[cfg(target_os = "macos")]
    use super::os_restore::validate_darwin_acl_external;

    // 1. macOS flags
    assert_eq!(parse_macos_flags(b"00000000").unwrap(), 0);
    assert_eq!(parse_macos_flags(b"00008000").unwrap(), 0x8000);
    assert!(parse_macos_flags(b"invalid").is_err());
    assert!(parse_macos_flags(b"100000000").is_err()); // overflow u32
    assert!(macos_flags_supported(0x8000));
    assert!(macos_flags_require_system(0x0002_0000)); // SF_IMMUTABLE

    // 2. Special object and source OS checks
    assert!(special_object_restore_supported(TarEntryKind::Fifo));
    assert!(special_object_restore_supported(TarEntryKind::CharacterDevice));
    assert!(special_object_restore_supported(TarEntryKind::BlockDevice));

    assert!(source_os_matches_current_host(std::env::consts::OS));
    assert!(!source_os_matches_current_host("unknown_os_12345"));

    // 3. System xattr name checks
    assert!(system_xattr_name(b"security.selinux", "linux"));
    assert!(system_xattr_name(b"system.posix_acl_access", "linux"));
    assert!(system_xattr_name(b"trusted.overlay", "linux"));
    assert!(!system_xattr_name(b"user.comment", "linux"));

    // 4. Darwin ACL validation (on macos)
    #[cfg(target_os = "macos")]
    {
        assert!(validate_darwin_acl_external(b"short").is_err());
        let mut darwin_acl = vec![0u8; 16]; // DARWIN_ACL_EXTERNAL_HEADER_LEN = 16
        darwin_acl[0..4].copy_from_slice(&0x0000_0001u32.to_le_bytes()); // magic
        assert!(validate_darwin_acl_external(&darwin_acl).is_ok());
    }

    // 5. Auxiliary restore support
    let mut aux = AuxiliaryRecord {
        ordinal: 0,
        kind: "generic.xattr".into(),
        profile: "posix-backup-v1".into(),
        restore_class: RestoreClass::SameOs,
        native: true,
        name_encoding: "bytes".into(),
        decoded_name: b"user.tag".to_vec(),
        flags: 0,
        logical_size: 5,
        stored_size: 5,
        sha256: [0u8; 32],
        meta: BTreeMap::new(),
        sparse_layout: None,
        capture_report_payload: None,
    };
    assert!(native_auxiliary_restore_supported(&aux, false, None));

    aux.restore_class = RestoreClass::System;
    assert!(!native_auxiliary_restore_supported(&aux, false, None));
    assert!(native_auxiliary_restore_supported(&aux, true, None));

    aux.kind = "unknown.kind".into();
    assert!(!native_auxiliary_restore_supported(&aux, false, None));
}

#[test]
fn streaming_restore_helpers_and_group_end() {
    use super::restore::{
        restore_streaming_tar_member_group, stream_regular_tar_member_group_to_writer, try_tar_member_group_end,
        StreamingMemberExpectation,
    };

    let member_bytes = member(b"stream_file.txt", b'0', b"streaming contents", b"");
    let group_len = member_bytes.len() as u64;
    let parsed = parse_tar_member_group(&member_bytes, 4096).unwrap();
    let expected_flags = parsed.v45_metadata.file_entry_flags;

    // 1. try_tar_member_group_end on valid member
    assert_eq!(try_tar_member_group_end(&member_bytes, 0).unwrap(), Some(member_bytes.len()));

    // 2. try_tar_member_group_end on empty/short slice
    assert_eq!(try_tar_member_group_end(&[], 0).unwrap(), None);
    assert_eq!(try_tar_member_group_end(&member_bytes[..100], 0).unwrap(), None);

    // 3. stream_regular_tar_member_group_to_writer
    let mut reader = SliceReader { slice: &member_bytes };
    let mut writer = Vec::new();
    let _diag = stream_regular_tar_member_group_to_writer(
        &mut reader,
        b"stream_file.txt",
        b"streaming contents".len() as u64,
        expected_flags,
        group_len,
        4096,
        &mut writer,
    )
    .unwrap();
    assert_eq!(writer, b"streaming contents");

    // 4. stream_regular_tar_member_group_to_writer fails on unaligned size
    let mut bad_reader = SliceReader { slice: &member_bytes };
    let mut bad_writer = Vec::new();
    assert!(stream_regular_tar_member_group_to_writer(
        &mut bad_reader,
        b"stream_file.txt",
        b"streaming contents".len() as u64,
        expected_flags,
        100,
        4096,
        &mut bad_writer,
    )
    .is_err());

    // 5. restore_streaming_tar_member_group
    let tmp = tempdir().unwrap();
    let mut reader = SliceReader { slice: &member_bytes };
    let expectation = StreamingMemberExpectation {
        path: b"stream_file.txt",
        file_data_size: b"streaming contents".len() as u64,
        file_flags: expected_flags,
        group_len,
        max_path_length: 4096,
    };
    assert!(restore_streaming_tar_member_group(tmp.path(), expectation, SafeExtractionOptions::default(), &mut reader).is_ok());
    assert_eq!(fs::read(tmp.path().join("stream_file.txt")).unwrap(), b"streaming contents");

    // 6. restore_streaming_tar_member_group fails on path mismatch
    let mut reader = SliceReader { slice: &member_bytes };
    let bad_path_exp = StreamingMemberExpectation {
        path: b"different.txt",
        file_data_size: b"streaming contents".len() as u64,
        file_flags: expected_flags,
        group_len,
        max_path_length: 4096,
    };
    assert!(restore_streaming_tar_member_group(tmp.path(), bad_path_exp, SafeExtractionOptions::default(), &mut reader).is_err());
}

#[test]
fn parse_tar_member_group_negatives_and_validation() {
    use super::pax::validate_tar_stream_total_extraction_size;

    let valid_member = member(b"valid.txt", b'0', b"valid data", b"");

    // 1. Total extraction size cap exceeded
    assert!(validate_tar_stream_total_extraction_size(&valid_member, 4096, 5).is_err());
    assert!(validate_tar_stream_total_extraction_size(&valid_member, 4096, 1024).is_ok());

    // 2. Unaligned tar stream
    assert!(validate_tar_stream_total_extraction_size(&valid_member[..100], 4096, 1024).is_err());

    // 3. parse_tar_member_group with non-zero payload on directory
    let bad_dir = member(b"baddir", b'5', b"some payload", b"");
    assert!(parse_tar_member_group(&bad_dir, 4096).is_err());

    // 4. parse_tar_member_group with metadata but no main entry
    let records = crate::entry_metadata::portable_primary_pax(b"missing_main", 0o644, "other", false).unwrap();
    let pax = crate::entry_metadata::encode_canonical_pax(&records).unwrap();
    let mut pax_header = header(b"TZAP-PAX/PRIMARY", b'x', pax.len(), b"");
    write_octal(&mut pax_header[100..108], 0);
    pax_header[148..156].fill(b' ');
    let checksum = pax_header.iter().map(|byte| *byte as u64).sum::<u64>();
    write_checksum(&mut pax_header[148..156], checksum);
    let mut only_pax = Vec::new();
    only_pax.extend_from_slice(&pax_header);
    only_pax.extend_from_slice(&pax);
    only_pax.resize(only_pax.len() + padding_to_512(pax.len()), 0);
    assert!(parse_tar_member_group(&only_pax, 4096).is_err());

    // 5. parse_tar_member_group with non-canonical ustar magic
    let mut bad_ustar = valid_member;
    bad_ustar[257..263].copy_from_slice(b"badmag");
    assert!(parse_tar_member_group(&bad_ustar, 4096).is_err());
}
