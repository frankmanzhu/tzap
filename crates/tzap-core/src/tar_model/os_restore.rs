use super::restore::{plan_restore, PreparedDestination, StagedAuxiliary};
#[cfg(windows)]
use super::sparse::{prepare_windows_sparse_file, query_windows_sparse_ranges, windows_file_system_is_refs};
use super::*;

#[cfg(windows)]
use cap_std::fs::OpenOptionsExt as _;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    FileBasicInfo, GetFileInformationByHandleEx, SetFileInformationByHandle, DELETE, FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
};

const MACOS_SETTABLE_ORDINARY_FLAGS: u32 = 0x0000_800f;
const MACOS_SETTABLE_SYSTEM_FLAGS: u32 = 0x0007_0000;
// UF_IMMUTABLE/UF_APPEND, entitlement-protected UF_DATAVAULT, and every
// Darwin SF_SUPPORTED bit have System-class restore semantics even when this
// reader deliberately does not register the bit for built-in application.
const MACOS_SYSTEM_CLASS_FLAGS: u32 = 0x009f_0086;
pub(crate) const MACOS_KNOWN_SETTABLE_FLAGS: u32 = MACOS_SETTABLE_ORDINARY_FLAGS | MACOS_SETTABLE_SYSTEM_FLAGS;

pub(crate) fn parse_macos_flags(encoded: &[u8]) -> Result<u32, FormatError> {
    std::str::from_utf8(encoded)
        .ok()
        .and_then(|value| u64::from_str_radix(value, 16).ok())
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(FormatError::InvalidArchive("invalid macOS file flags"))
}

pub(crate) fn macos_flags_supported(flags: u32) -> bool {
    flags & !MACOS_KNOWN_SETTABLE_FLAGS == 0
}

pub(crate) fn macos_flags_require_system(flags: u32) -> bool {
    flags & MACOS_SYSTEM_CLASS_FLAGS != 0
}

fn macos_system_flags_privileges_available(flags: u32) -> bool {
    if flags & MACOS_SETTABLE_SYSTEM_FLAGS == 0 {
        return true;
    }
    #[cfg(target_os = "macos")]
    {
        // Setting system file flags is restricted to the superuser by Darwin.
        (unsafe { libc::geteuid() }) == 0
    }
    #[cfg(not(target_os = "macos"))]
    false
}

pub(crate) fn special_object_restore_supported(kind: TarEntryKind) -> bool {
    #[cfg(target_os = "linux")]
    {
        let _ = kind;
        true
    }
    #[cfg(target_os = "macos")]
    {
        kind == TarEntryKind::Fifo || (unsafe { libc::geteuid() }) == 0
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = kind;
        false
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn validate_darwin_acl_external(value: &[u8]) -> Result<(), FormatError> {
    const ACL_MAX_ENTRIES: usize = 128;
    const DARWIN_EXTERNAL_ACL_HEADER: usize = 40;
    const DARWIN_EXTERNAL_ACE_SIZE: usize = 28;
    const DARWIN_EXTERNAL_ACL_MAGIC: [u8; 4] = [0x01, 0x2c, 0xc1, 0x6d];
    if value.get(..4) != Some(DARWIN_EXTERNAL_ACL_MAGIC.as_slice()) {
        return Err(FormatError::InvalidArchive("macOS ACL external form has an invalid magic value"));
    }
    let entry_count = value
        .get(36..40)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or(FormatError::InvalidArchive("macOS ACL external form is truncated"))? as usize;
    let expected = DARWIN_EXTERNAL_ACL_HEADER
        .checked_add(
            entry_count
                .checked_mul(DARWIN_EXTERNAL_ACE_SIZE)
                .ok_or(FormatError::InvalidArchive("macOS ACL entry count overflows"))?,
        )
        .ok_or(FormatError::InvalidArchive("macOS ACL size overflows"))?;
    if entry_count > ACL_MAX_ENTRIES || expected != value.len() {
        return Err(FormatError::InvalidArchive("macOS ACL external form has an invalid size"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
const LINUX_KNOWN_FSFLAGS: u64 = (linux_raw_sys::general::FS_SECRM_FL
    | linux_raw_sys::general::FS_UNRM_FL
    | linux_raw_sys::general::FS_COMPR_FL
    | linux_raw_sys::general::FS_SYNC_FL
    | linux_raw_sys::general::FS_IMMUTABLE_FL
    | linux_raw_sys::general::FS_APPEND_FL
    | linux_raw_sys::general::FS_NODUMP_FL
    | linux_raw_sys::general::FS_NOATIME_FL
    | linux_raw_sys::general::FS_DIRTY_FL
    | linux_raw_sys::general::FS_COMPRBLK_FL
    | linux_raw_sys::general::FS_NOCOMP_FL
    | linux_raw_sys::general::FS_ENCRYPT_FL
    | linux_raw_sys::general::FS_BTREE_FL
    | linux_raw_sys::general::FS_IMAGIC_FL
    | linux_raw_sys::general::FS_JOURNAL_DATA_FL
    | linux_raw_sys::general::FS_NOTAIL_FL
    | linux_raw_sys::general::FS_DIRSYNC_FL
    | linux_raw_sys::general::FS_TOPDIR_FL
    | linux_raw_sys::general::FS_HUGE_FILE_FL
    | linux_raw_sys::general::FS_EXTENT_FL
    | linux_raw_sys::general::FS_VERITY_FL
    | linux_raw_sys::general::FS_EA_INODE_FL
    | linux_raw_sys::general::FS_EOFBLOCKS_FL
    | linux_raw_sys::general::FS_NOCOW_FL
    | linux_raw_sys::general::FS_DAX_FL
    | linux_raw_sys::general::FS_INLINE_DATA_FL
    | linux_raw_sys::general::FS_PROJINHERIT_FL
    | linux_raw_sys::general::FS_CASEFOLD_FL) as u64;
pub(crate) fn native_auxiliary_restore_supported(record: &AuxiliaryRecord, include_system: bool, kind: Option<TarEntryKind>) -> bool {
    if cfg!(target_os = "macos") {
        return match record.kind.as_str() {
            "macos.resource-fork" => {
                record.restore_class == RestoreClass::SameOs
                    && match kind {
                        Some(TarEntryKind::Symlink) => record.logical_size <= u64::from(u32::MAX),
                        Some(TarEntryKind::Regular | TarEntryKind::Directory) | None => true,
                        Some(_) => false,
                    }
            }
            "macos.finder-info" => record.restore_class == RestoreClass::SameOs,
            "macos.acl-native" => {
                record.restore_class == RestoreClass::SameOs
                    && record
                        .meta
                        .get("TZAP.aux.meta.acl-format")
                        .is_some_and(|value| value == b"darwin-acl-external-v1")
            }
            "generic.xattr" => record.restore_class == RestoreClass::SameOs || include_system && record.restore_class == RestoreClass::System,
            _ => false,
        };
    }
    if cfg!(target_os = "linux") && record.kind == "generic.xattr" {
        return record.restore_class == RestoreClass::SameOs || (include_system && record.restore_class == RestoreClass::System);
    }
    if !cfg!(windows) {
        return false;
    }
    if record.kind == "windows.alternate-data" {
        return record.restore_class == RestoreClass::SameOs
            && record
                .meta
                .get("TZAP.aux.meta.stream-attributes")
                .is_some_and(|value| value == b"00000000" && record.flags == 0 || value == b"00000008" && record.flags == 1);
    }
    if matches!(record.kind.as_str(), "windows.ea-data" | "windows.property-data" | "windows.object-id") {
        let expected_type = match record.kind.as_str() {
            "windows.ea-data" => b"00000002".as_slice(),
            "windows.property-data" => b"00000006".as_slice(),
            "windows.object-id" => b"00000007".as_slice(),
            _ => unreachable!(),
        };
        return (record.restore_class == RestoreClass::SameOs || include_system && record.restore_class == RestoreClass::System)
            && (record.restore_class != RestoreClass::System || windows_security_restore_privileges_available(0))
            && record.flags == 0
            && record.name_encoding == "none"
            && record.decoded_name.is_empty()
            && record.meta.get("TZAP.aux.meta.stream-type").is_some_and(|value| value == expected_type)
            && record
                .meta
                .get("TZAP.aux.meta.stream-attributes")
                .and_then(|value| parse_lower_hex_u32(value, "Windows stream attributes").ok())
                .is_some_and(|attributes| {
                    attributes & !(STREAM_MODIFIED_WHEN_READ | STREAM_CONTAINS_SECURITY) == 0
                        && (record.kind == "windows.object-id" || attributes & STREAM_CONTAINS_SECURITY != 0) == (record.restore_class == RestoreClass::System)
                });
    }
    if !include_system {
        return false;
    }
    if record.kind == "windows.efs-raw" {
        return record.restore_class == RestoreClass::System && record.meta.get("TZAP.aux.meta.efs-version").is_some_and(|value| value == b"1");
    }
    if record.kind == "windows.reparse-data" {
        return record
            .capture_report_payload
            .as_deref()
            .is_some_and(|payload| validate_windows_essential_reparse_data(payload).is_ok());
    }
    if record.kind == "windows.security-descriptor" {
        return record.capture_report_payload.is_some()
            && record
                .meta
                .get("TZAP.aux.meta.security-information")
                .and_then(|value| parse_lower_hex_u32(value, "Windows security information").ok())
                .is_some_and(windows_security_restore_privileges_available);
    }
    false
}

#[cfg(windows)]
pub(super) fn windows_security_restore_privileges_available(security_information: u32) -> bool {
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, SetLastError, ERROR_SUCCESS};
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, SE_BACKUP_NAME, SE_PRIVILEGE_ENABLED, SE_RESTORE_NAME, SE_SECURITY_NAME, TOKEN_ADJUST_PRIVILEGES,
        TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = ptr::null_mut();
    // SAFETY: `token` is a valid output slot and the process pseudo-handle is live.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &mut token) } == 0 {
        return false;
    }
    let enable = |name| {
        let mut privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            ..Default::default()
        };
        // SAFETY: the one-element privilege array provides valid input/output storage.
        if unsafe { LookupPrivilegeValueW(ptr::null(), name, &mut privileges.Privileges[0].Luid) } == 0 {
            return false;
        }
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        unsafe { SetLastError(ERROR_SUCCESS) };
        // SAFETY: `token` is live and the initialized one-entry structure is readable.
        unsafe { AdjustTokenPrivileges(token, 0, &privileges, 0, ptr::null_mut(), ptr::null_mut()) != 0 && GetLastError() == ERROR_SUCCESS }
    };
    let available = enable(SE_BACKUP_NAME) && enable(SE_RESTORE_NAME) && (security_information & 0x0000_0008 == 0 || enable(SE_SECURITY_NAME));
    // SAFETY: `token` was returned by OpenProcessToken and is closed once.
    unsafe { CloseHandle(token) };
    available
}

#[cfg(not(windows))]
pub(super) fn windows_security_restore_privileges_available(_security_information: u32) -> bool {
    false
}

pub(crate) fn windows_reparse_metadata_supported(metadata: &MemberMetadata) -> bool {
    metadata.declaration.source_os == "windows"
        && metadata
            .auxiliary
            .iter()
            .find(|record| record.kind == "windows.reparse-data")
            .is_some_and(|record| native_auxiliary_restore_supported(record, true, None))
}

pub(crate) fn native_primary_restore_unsupported(metadata: &MemberMetadata, include_system: bool) -> bool {
    metadata.primary_records.keys().any(|key| {
        let native = key.starts_with("TZAP.linux.")
            || key.starts_with("TZAP.macos.")
            || key.starts_with("TZAP.windows.")
            || key.starts_with("TZAP.posix.")
            || key.starts_with("LIBARCHIVE.")
            || key.starts_with("SCHILY.")
            || key == "TZAP.unix.ctime-observed";
        if !native {
            return false;
        }
        if key == "TZAP.unix.ctime-observed" {
            return false;
        }
        if key == "TZAP.linux.fsflags" {
            return linux_inode_flags_restore_unsupported(metadata.primary_records.get(key).map(Vec::as_slice));
        }
        if key == "TZAP.linux.project-id" {
            return !cfg!(target_os = "linux") || !include_system;
        }
        if key == "TZAP.linux.whiteout" {
            return !cfg!(target_os = "linux") || !include_system;
        }
        if key.starts_with("TZAP.posix.device-") {
            return !cfg!(any(target_os = "linux", target_os = "macos")) || !include_system;
        }
        if key == "TZAP.windows.file-attributes" {
            if !cfg!(windows) || metadata.declaration.source_os != "windows" {
                return true;
            }
            return metadata
                .primary_records
                .get(key)
                .and_then(|value| parse_lower_hex_u32(value, "Windows file attributes").ok())
                .is_none_or(|attributes| {
                    attributes & !(WINDOWS_ESSENTIAL_SETTABLE_ATTRIBUTES | WINDOWS_ESSENTIAL_INTRINSIC_ATTRIBUTES | FILE_ATTRIBUTE_NORMAL) != 0
                });
        }
        if key == "TZAP.windows.change-time" {
            return !cfg!(windows) || metadata.declaration.source_os != "windows";
        }
        if key == "TZAP.windows.data-stream-attributes" {
            return !cfg!(windows)
                || metadata.declaration.source_os != "windows"
                || metadata
                    .primary_records
                    .get(key)
                    .is_none_or(|value| value != b"00000000" && value != b"00000008");
        }
        if key == "TZAP.windows.reparse-placeholder" {
            return !cfg!(windows) || !include_system || !windows_reparse_metadata_supported(metadata);
        }
        if key == "TZAP.windows.directory-case-sensitive" {
            return include_system && (!cfg!(windows) || metadata.declaration.source_os != "windows");
        }
        if key == "LIBARCHIVE.creationtime" && metadata.declaration.source_os == "windows" {
            return !cfg!(windows);
        }
        if key == "LIBARCHIVE.creationtime" && metadata.declaration.source_os == "macos" {
            return !cfg!(target_os = "macos");
        }
        if key == "TZAP.macos.st-flags" {
            let flags = metadata.primary_records.get(key).and_then(|value| parse_macos_flags(value).ok());
            return !cfg!(target_os = "macos")
                || metadata.declaration.source_os != "macos"
                || flags.is_none_or(|flags| {
                    if macos_flags_require_system(flags) && !include_system {
                        false
                    } else {
                        !macos_flags_supported(flags) || include_system && !macos_system_flags_privileges_available(flags)
                    }
                });
        }
        if key.starts_with("SCHILY.acl.") || key.starts_with("TZAP.acl.") {
            return !cfg!(target_os = "linux");
        }
        if let Some(encoded_name) = key.strip_prefix("LIBARCHIVE.xattr.") {
            let system = decode_percent_name(encoded_name.as_bytes())
                .ok()
                .is_some_and(|name| system_xattr_name(&name, &metadata.declaration.source_os));
            return !cfg!(unix) && (!system || include_system);
        }
        true
    })
}

#[cfg(target_os = "linux")]
fn linux_inode_flags_restore_unsupported(encoded: Option<&[u8]>) -> bool {
    encoded
        .and_then(|value| std::str::from_utf8(value).ok())
        .and_then(|value| u64::from_str_radix(value, 16).ok())
        .is_none_or(|flags| flags & !LINUX_KNOWN_FSFLAGS != 0)
}

#[cfg(not(target_os = "linux"))]
fn linux_inode_flags_restore_unsupported(_encoded: Option<&[u8]>) -> bool {
    true
}

pub(crate) fn source_os_matches_current_host(source_os: &str) -> bool {
    source_os == current_host_os()
}

#[cfg(target_os = "linux")]
fn current_host_os() -> &'static str {
    "linux"
}

#[cfg(target_os = "macos")]
fn current_host_os() -> &'static str {
    "macos"
}

#[cfg(target_os = "windows")]
fn current_host_os() -> &'static str {
    "windows"
}

#[cfg(target_os = "freebsd")]
fn current_host_os() -> &'static str {
    "freebsd"
}

#[cfg(target_os = "netbsd")]
fn current_host_os() -> &'static str {
    "netbsd"
}

#[cfg(target_os = "openbsd")]
fn current_host_os() -> &'static str {
    "openbsd"
}

#[cfg(target_os = "solaris")]
fn current_host_os() -> &'static str {
    "solaris"
}

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "solaris"
    ))
))]
fn current_host_os() -> &'static str {
    "other-unix"
}

#[cfg(not(any(unix, windows)))]
fn current_host_os() -> &'static str {
    "other"
}

#[cfg(unix)]
pub(crate) fn numeric_ownership_supported(metadata: &MemberMetadata) -> bool {
    metadata.portable_mirror.uid.and_then(|uid| libc::uid_t::try_from(uid).ok()).is_some()
        && metadata.portable_mirror.gid.and_then(|gid| libc::gid_t::try_from(gid).ok()).is_some()
}

#[cfg(not(unix))]
pub(crate) fn numeric_ownership_supported(_metadata: &MemberMetadata) -> bool {
    false
}

pub(crate) fn metadata_verification_report(members: &[TarStreamMemberSummary]) -> Result<MetadataVerificationReport, FormatError> {
    let mut profiles_present = std::collections::BTreeSet::new();
    let mut auxiliary_kinds_present = std::collections::BTreeSet::new();
    let mut entries = Vec::with_capacity(members.len());

    for member in members {
        let metadata = &member.v45_metadata;
        profiles_present.extend(metadata.declaration.required_profiles.iter().cloned());
        profiles_present.extend(metadata.declaration.optional_profiles.iter().cloned());
        let mut auxiliary_kinds = metadata.auxiliary.iter().map(|record| record.kind.clone()).collect::<Vec<_>>();
        auxiliary_kinds.sort();
        auxiliary_kinds.dedup();
        auxiliary_kinds_present.extend(auxiliary_kinds.iter().cloned());

        let mut policy_capabilities = Vec::with_capacity(4);
        for policy in [RestorePolicy::Content, RestorePolicy::Portable, RestorePolicy::SameOs, RestorePolicy::System] {
            let strict = SafeExtractionOptions {
                restore_policy: policy,
                allow_degraded: false,
                system_authorized: policy == RestorePolicy::System,
                ..SafeExtractionOptions::default()
            };
            let (policy_complete, reason) = match plan_restore(&member.path, metadata, member.kind, member.reparse_placeholder, strict) {
                Ok(_) => (true, None),
                Err(FormatError::ReaderUnsupported(reason)) => (false, Some(reason)),
                Err(error) => return Err(error),
            };
            let degraded_restore_available = if policy_complete {
                true
            } else {
                plan_restore(
                    &member.path,
                    metadata,
                    member.kind,
                    member.reparse_placeholder,
                    SafeExtractionOptions {
                        allow_degraded: true,
                        ..strict
                    },
                )
                .is_ok()
            };
            policy_capabilities.push(RestorePolicyCapability {
                policy,
                policy_complete,
                degraded_restore_available,
                reason,
            });
        }

        let mut diagnostics = member.diagnostics.clone();
        diagnostics.extend(plan_restore(
            &member.path,
            metadata,
            member.kind,
            member.reparse_placeholder,
            SafeExtractionOptions {
                allow_degraded: true,
                ..SafeExtractionOptions::default()
            },
        )?);
        let system_complete = policy_capabilities
            .iter()
            .find(|capability| capability.policy == RestorePolicy::System)
            .is_some_and(|capability| capability.policy_complete);
        let full_fidelity_possible = metadata.declaration.capture_status == CaptureStatus::Complete
            && system_complete
            && !diagnostics.iter().any(|diagnostic| {
                matches!(
                    diagnostic.status,
                    MetadataDiagnosticStatus::Materialized | MetadataDiagnosticStatus::Unsupported | MetadataDiagnosticStatus::Failed
                )
            });
        entries.push(EntryMetadataVerification {
            path: member.path.clone(),
            capture_status: metadata.declaration.capture_status,
            required_profiles: metadata.declaration.required_profiles.clone(),
            optional_profiles: metadata.declaration.optional_profiles.clone(),
            auxiliary_kinds,
            policy_capabilities,
            full_fidelity_possible,
            diagnostics,
        });
    }

    Ok(MetadataVerificationReport {
        all_capture_complete: entries.iter().all(|entry| entry.capture_status == CaptureStatus::Complete),
        full_fidelity_possible: entries.iter().all(|entry| entry.full_fidelity_possible),
        profiles_present: profiles_present.into_iter().collect(),
        auxiliary_kinds_present: auxiliary_kinds_present.into_iter().collect(),
        entries,
    })
}
pub(crate) fn restore_regular_file_metadata_to_open_file(
    file: &fs::File,
    member: &OwnedTarMember,
    options: SafeExtractionOptions,
) -> Result<Vec<MetadataDiagnostic>, FormatError> {
    if member.kind != TarEntryKind::Regular {
        return Err(FormatError::ReaderUnsupported("open-file metadata restore requires a regular archive member"));
    }
    let metadata = member
        .v45_metadata
        .as_ref()
        .ok_or(FormatError::InvalidArchive("revision-45 member metadata is missing"))?;
    let mut diagnostics = plan_owned_member_restore(member, options)?;
    if options.restore_policy != RestorePolicy::Content {
        apply_restored_regular_file_metadata_parts(
            file,
            &member.path,
            RestoredRegularMetadata::from(&metadata.portable_mirror),
            Some(metadata),
            None,
            options,
            &mut diagnostics,
        )?;
    }
    Ok(diagnostics)
}

#[cfg(test)]
pub(crate) fn apply_restored_regular_file_metadata(
    file: &fs::File,
    member: &OwnedTarMember,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    if member.v45_metadata.is_some() {
        diagnostics.extend(restore_regular_file_metadata_to_open_file(file, member, options)?);
        return Ok(());
    }
    apply_restored_regular_file_metadata_parts(
        file,
        &member.path,
        RestoredRegularMetadata {
            mode: member.mode,
            mtime: (member.mtime.seconds, member.mtime.nanoseconds),
            attributes: None,
            mode_origin_native: false,
            uid: None,
            gid: None,
        },
        None,
        None,
        options,
        diagnostics,
    )
}

#[derive(Clone, Copy)]
pub(crate) struct RestoredRegularMetadata {
    mode: u32,
    mtime: (i64, u32),
    attributes: Option<u32>,
    mode_origin_native: bool,
    uid: Option<u64>,
    gid: Option<u64>,
}

impl From<&PortableMetadataMirror> for RestoredRegularMetadata {
    fn from(metadata: &PortableMetadataMirror) -> Self {
        Self {
            mode: metadata.mode,
            mtime: metadata.mtime,
            attributes: metadata.attributes,
            mode_origin_native: metadata.mode_origin_native,
            uid: metadata.uid,
            gid: metadata.gid,
        }
    }
}

pub(crate) fn apply_restored_regular_file_metadata_parts(
    file: &fs::File,
    path: &[u8],
    metadata: RestoredRegularMetadata,
    member_metadata: Option<&MemberMetadata>,
    staged_auxiliary: Option<&mut Vec<StagedAuxiliary>>,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    let RestoredRegularMetadata {
        mode,
        mtime,
        attributes,
        mode_origin_native,
        uid,
        gid,
    } = metadata;
    apply_regular_file_ownership(file, path, uid, gid, options, diagnostics)?;
    let mode = if options.restore_policy == RestorePolicy::System && options.system_authorized {
        mode
    } else {
        mode & !0o6000
    };
    apply_regular_file_mode(file, path, mode, mode_origin_native, options, diagnostics)?;
    if let Some(member_metadata) = member_metadata {
        apply_regular_file_posix_acl(file, path, member_metadata, options, diagnostics)?;
        if let Some(staged) = staged_auxiliary {
            apply_macos_native_metadata(file, path, member_metadata, staged, options, diagnostics)?;
            apply_generic_xattr_auxiliaries(file, path, staged, options, diagnostics)?;
        }
        apply_regular_file_xattrs(file, path, member_metadata, options, diagnostics)?;
    }
    if member_metadata
        .is_some_and(|metadata| metadata.declaration.source_os == "macos" && matches!(options.restore_policy, RestorePolicy::SameOs | RestorePolicy::System))
    {
        apply_macos_file_timestamps(file, path, member_metadata.unwrap(), mtime, options, diagnostics)?;
    } else {
        apply_regular_file_mtime(file, path, mtime, options, diagnostics)?;
    }
    apply_regular_file_attributes(file, path, attributes, options, diagnostics)?;
    if let Some(member_metadata) = member_metadata {
        apply_windows_security_descriptor(file, path, member_metadata, options, diagnostics)?;
        apply_windows_basic_metadata(file, path, member_metadata, options, diagnostics)?;
        apply_linux_project_id(file, path, member_metadata, options, diagnostics)?;
        apply_linux_inode_flags(file, path, member_metadata, options, diagnostics)?;
        apply_macos_file_flags(file, path, member_metadata, options, diagnostics)?;
    }
    Ok(())
}

#[cfg(windows)]
struct WindowsAlternateStreamRollback {
    paths: Vec<Vec<u16>>,
    committed: bool,
}

#[cfg(windows)]
impl Drop for WindowsAlternateStreamRollback {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        use windows_sys::Win32::Storage::FileSystem::DeleteFileW;
        for path in self.paths.iter().rev() {
            // SAFETY: every path is retained as a NUL-terminated UTF-16 buffer until this call.
            unsafe {
                DeleteFileW(path.as_ptr());
            }
        }
    }
}

#[cfg(windows)]
struct WindowsRawEfsContext(*mut std::ffi::c_void);

#[cfg(windows)]
impl Drop for WindowsRawEfsContext {
    fn drop(&mut self) {
        use windows_sys::Win32::Storage::FileSystem::CloseEncryptedFileRaw;

        if !self.0.is_null() {
            // SAFETY: this context was returned by OpenEncryptedFileRawW and is closed once.
            unsafe { CloseEncryptedFileRaw(self.0) };
        }
    }
}

#[cfg(windows)]
fn windows_final_path(file: &fs::File, description: &'static str) -> Result<Vec<u16>, FormatError> {
    use windows_sys::Win32::Storage::FileSystem::{GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED, VOLUME_NAME_DOS};

    let handle = file.as_raw_handle().cast();
    // SAFETY: the handle is live; the zero-length query returns the required UTF-16 count.
    let required = unsafe { GetFinalPathNameByHandleW(handle, std::ptr::null_mut(), 0, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) };
    if required == 0 {
        return Err(FormatError::FilesystemExtractionFailed(description));
    }
    let mut path = vec![0u16; required as usize + 1];
    // SAFETY: `path` provides the queried capacity and remains writable for the call.
    let written = unsafe { GetFinalPathNameByHandleW(handle, path.as_mut_ptr(), path.len() as u32, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) };
    if written == 0 || written as usize >= path.len() {
        return Err(FormatError::FilesystemExtractionFailed(description));
    }
    path.truncate(written as usize);
    path.push(0);
    Ok(path)
}

#[cfg(windows)]
fn open_windows_raw_efs(path: &[u16], flags: u32) -> Result<WindowsRawEfsContext, FormatError> {
    use windows_sys::Win32::Storage::FileSystem::OpenEncryptedFileRawW;

    let mut context = std::ptr::null_mut();
    // SAFETY: `path` is NUL-terminated and `context` is a writable output slot.
    let status = unsafe { OpenEncryptedFileRawW(path.as_ptr(), flags, &mut context) };
    if status != 0 {
        return Err(FormatError::FilesystemExtractionFailed("failed to open Windows raw EFS stream"));
    }
    Ok(WindowsRawEfsContext(context))
}

#[cfg(windows)]
struct WindowsRawEfsImport<'a> {
    file: &'a mut fs::File,
    bytes: u64,
    error: Option<std::io::Error>,
}

#[cfg(windows)]
unsafe extern "system" fn windows_raw_efs_import_callback(buffer: *mut u8, context: *const std::ffi::c_void, length: *mut u32) -> u32 {
    use windows_sys::Win32::Foundation::{ERROR_READ_FAULT, ERROR_SUCCESS};

    if buffer.is_null() || context.is_null() || length.is_null() {
        return ERROR_READ_FAULT;
    }
    // SAFETY: WriteEncryptedFileRaw passes back the context pointer supplied by the caller for
    // the duration of the synchronous call, and provides a writable buffer of `*length` bytes.
    let state = unsafe { &mut *context.cast_mut().cast::<WindowsRawEfsImport<'_>>() };
    let requested = unsafe { *length } as usize;
    let output = unsafe { std::slice::from_raw_parts_mut(buffer, requested) };
    match state.file.read(output) {
        Ok(count) => {
            unsafe { *length = count as u32 };
            state.bytes = state.bytes.saturating_add(count as u64);
            ERROR_SUCCESS
        }
        Err(error) => {
            state.error = Some(error);
            unsafe { *length = 0 };
            ERROR_READ_FAULT
        }
    }
}

#[cfg(windows)]
struct WindowsRawEfsDigest {
    hasher: sha2::Sha256,
    bytes: u64,
}

#[cfg(windows)]
unsafe extern "system" fn windows_raw_efs_digest_callback(bytes: *const u8, context: *const std::ffi::c_void, length: u32) -> u32 {
    use windows_sys::Win32::Foundation::{ERROR_READ_FAULT, ERROR_SUCCESS};

    if length == 0 {
        return ERROR_SUCCESS;
    }
    if context.is_null() || bytes.is_null() {
        return ERROR_READ_FAULT;
    }
    // SAFETY: ReadEncryptedFileRaw passes back the context pointer supplied by the caller and a
    // readable byte range for the duration of this synchronous callback.
    let state = unsafe { &mut *context.cast_mut().cast::<WindowsRawEfsDigest>() };
    let input = unsafe { std::slice::from_raw_parts(bytes, length as usize) };
    sha2::Digest::update(&mut state.hasher, input);
    state.bytes = state.bytes.saturating_add(length as u64);
    ERROR_SUCCESS
}

#[cfg(windows)]
fn verify_windows_raw_efs(path: &[u16], record: &AuxiliaryRecord) -> Result<(), FormatError> {
    use sha2::Digest as _;
    use windows_sys::Win32::Storage::FileSystem::ReadEncryptedFileRaw;

    let context = open_windows_raw_efs(path, 0)?;
    let mut digest = WindowsRawEfsDigest {
        hasher: sha2::Sha256::new(),
        bytes: 0,
    };
    // SAFETY: the callback and its stack context remain live for this synchronous export.
    let status = unsafe {
        ReadEncryptedFileRaw(
            Some(windows_raw_efs_digest_callback),
            (&mut digest as *mut WindowsRawEfsDigest).cast(),
            context.0,
        )
    };
    if status != 0 {
        return Err(FormatError::FilesystemExtractionFailed("failed to verify restored Windows raw EFS stream"));
    }
    if digest.bytes != record.stored_size || digest.hasher.finalize().as_slice() != record.sha256 {
        return Err(FormatError::FilesystemExtractionFailed("restored Windows raw EFS stream did not verify"));
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn restore_windows_efs_temp(
    destination: &PreparedDestination,
    temp_leaf: &Path,
    mut output: fs::File,
    staged: &mut Vec<StagedAuxiliary>,
    options: SafeExtractionOptions,
) -> Result<fs::File, FormatError> {
    use std::os::windows::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::WriteEncryptedFileRaw;
    use windows_sys::Win32::System::WindowsProgramming::CREATE_FOR_IMPORT;

    let Some(index) = staged.iter().position(|item| item.record.kind == "windows.efs-raw") else {
        return Ok(output);
    };
    if options.restore_policy != RestorePolicy::System || !options.system_authorized {
        return Err(FormatError::FilesystemExtractionFailed(
            "Windows raw EFS restoration requires authorized system policy",
        ));
    }
    output
        .flush()
        .map_err(|_| FormatError::FilesystemExtractionFailed("failed to flush Windows raw EFS temporary file"))?;
    let raw_path = windows_final_path(&output, "failed to resolve Windows raw EFS temporary file")?;
    drop(output);
    destination
        .parent
        .remove_file_or_symlink(temp_leaf)
        .map_err(|_| FormatError::FilesystemExtractionFailed("failed to replace temporary file with Windows raw EFS data"))?;

    let StagedAuxiliary { record, file: mut staged_file } = staged.remove(index);
    let staged_len = staged_file
        .metadata()
        .map_err(|_| FormatError::FilesystemExtractionFailed("failed to inspect staged Windows raw EFS data"))?
        .len();
    if staged_len != record.stored_size {
        return Err(FormatError::InvalidArchive("staged Windows raw EFS size is inconsistent"));
    }
    staged_file
        .seek(SeekFrom::Start(0))
        .map_err(|_| FormatError::FilesystemExtractionFailed("failed to rewind staged Windows raw EFS data"))?;

    let context = open_windows_raw_efs(&raw_path, CREATE_FOR_IMPORT)?;
    let mut import = WindowsRawEfsImport {
        file: &mut staged_file,
        bytes: 0,
        error: None,
    };
    // SAFETY: the callback, staged file, and callback context remain live for this synchronous
    // import, and `context` is an import context returned for the resolved temporary path.
    let status = unsafe {
        WriteEncryptedFileRaw(
            Some(windows_raw_efs_import_callback),
            (&mut import as *mut WindowsRawEfsImport<'_>).cast(),
            context.0,
        )
    };
    if status != 0 || import.error.is_some() || import.bytes != record.stored_size {
        return Err(FormatError::FilesystemExtractionFailed("failed to restore Windows raw EFS data"));
    }
    drop(context);
    verify_windows_raw_efs(&raw_path, &record)?;

    let mut reopen = CapOpenOptions::new();
    reopen
        .read(true)
        .write(true)
        .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .follow(FollowSymlinks::No);
    let output = destination
        .parent
        .open_with(temp_leaf, &reopen)
        .map(cap_std::fs::File::into_std)
        .map_err(|_| FormatError::FilesystemExtractionFailed("failed to reopen restored Windows raw EFS temporary file"))?;
    let metadata = output
        .metadata()
        .map_err(|_| FormatError::FilesystemExtractionFailed("failed to inspect restored Windows raw EFS file"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.file_attributes() & FILE_ATTRIBUTE_ENCRYPTED == 0 {
        return Err(FormatError::FilesystemExtractionFailed("restored Windows raw EFS file is not encrypted"));
    }
    Ok(output)
}

#[cfg(not(windows))]
pub(crate) fn restore_windows_efs_temp(
    _destination: &PreparedDestination,
    _temp_leaf: &Path,
    output: fs::File,
    staged: &mut [StagedAuxiliary],
    _options: SafeExtractionOptions,
) -> Result<fs::File, FormatError> {
    if staged.iter().any(|item| item.record.kind == "windows.efs-raw") {
        return Err(FormatError::FilesystemExtractionFailed("Windows raw EFS restore is unavailable on this host"));
    }
    Ok(output)
}

#[cfg(windows)]
pub(crate) fn apply_windows_alternate_streams(
    base_file: &fs::File,
    path: &[u8],
    staged: &mut Vec<StagedAuxiliary>,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    use std::os::windows::io::FromRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, GetFinalPathNameByHandleW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_NAME_NORMALIZED, VOLUME_NAME_DOS,
    };

    if staged.is_empty() {
        return Ok(());
    }
    if !matches!(options.restore_policy, RestorePolicy::SameOs | RestorePolicy::System) {
        staged.clear();
        return Ok(());
    }
    let handle = base_file.as_raw_handle().cast();
    // SAFETY: the handle is live; the zero-length query returns the required UTF-16 count.
    let required = unsafe { GetFinalPathNameByHandleW(handle, std::ptr::null_mut(), 0, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) };
    if required == 0 {
        return Err(FormatError::FilesystemExtractionFailed(
            "failed to resolve restored object for alternate-stream creation",
        ));
    }
    let mut base_path = vec![0u16; required as usize + 1];
    // SAFETY: `base_path` provides the queried capacity and remains writable for the call.
    let written = unsafe { GetFinalPathNameByHandleW(handle, base_path.as_mut_ptr(), base_path.len() as u32, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) };
    if written == 0 || written as usize >= base_path.len() {
        return Err(FormatError::FilesystemExtractionFailed(
            "failed to resolve restored object for alternate-stream creation",
        ));
    }
    base_path.truncate(written as usize);
    let mut rollback = WindowsAlternateStreamRollback {
        paths: Vec::new(),
        committed: false,
    };

    for staged_record in std::mem::take(staged) {
        let StagedAuxiliary { record, mut file } = staged_record;
        if record.kind != "windows.alternate-data" {
            restore_windows_backup_metadata_stream(base_file, path, &record, &mut file, options, diagnostics)?;
            continue;
        }
        if record.decoded_name.len() % 2 != 0 {
            return Err(FormatError::InvalidArchive("Windows alternate stream name is not UTF-16LE"));
        }
        let stream_name = record
            .decoded_name
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        let mut stream_path = Vec::with_capacity(base_path.len() + stream_name.len() + 1);
        stream_path.extend_from_slice(&base_path);
        stream_path.extend_from_slice(&stream_name);
        stream_path.push(0);
        // SAFETY: the base path comes from the pinned destination handle and the suffix passed
        // built-in UTF-16 alternate-stream grammar validation during archive parsing.
        let stream_handle = unsafe {
            CreateFileW(
                stream_path.as_ptr(),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        if stream_handle.is_null() || stream_handle as isize == -1 {
            let error = std::io::Error::last_os_error();
            return record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    "windows-backup-v1",
                    "alternate-data",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    "failed to create Windows alternate data stream",
                )
                .for_restore(options.restore_policy, 2)
                .with_native_error(&error),
                options,
                "failed to create Windows alternate data stream",
            );
        }
        // SAFETY: ownership of the newly created handle transfers to `stream` exactly once.
        let mut stream = unsafe { fs::File::from_raw_handle(stream_handle.cast()) };
        rollback.paths.push(stream_path);
        restore_windows_alternate_stream_payload(&mut file, &mut stream, &record)?;
    }
    rollback.committed = true;
    Ok(())
}

#[cfg(windows)]
fn restore_windows_backup_metadata_stream(
    base_file: &fs::File,
    path: &[u8],
    record: &AuxiliaryRecord,
    payload: &mut fs::File,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::ptr;
    use windows_sys::Win32::Storage::FileSystem::{
        BackupWrite, ReOpenFile, FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let stream_type = record
        .meta
        .get("TZAP.aux.meta.stream-type")
        .ok_or(FormatError::InvalidArchive("Windows backup metadata stream type is missing"))
        .and_then(|value| parse_lower_hex_u32(value, "Windows backup stream type"))?;
    let stream_attributes = record
        .meta
        .get("TZAP.aux.meta.stream-attributes")
        .ok_or(FormatError::InvalidArchive("Windows backup metadata stream attributes are missing"))
        .and_then(|value| parse_lower_hex_u32(value, "Windows backup stream attributes"))?;
    let expected_type = match record.kind.as_str() {
        "windows.ea-data" => 2,
        "windows.property-data" => 6,
        "windows.object-id" => 7,
        _ => {
            return Err(FormatError::InvalidArchive("staged Windows backup metadata stream has unsupported framing"));
        }
    };
    if stream_type != expected_type || record.flags != 0 || record.logical_size != record.stored_size || !record.decoded_name.is_empty() {
        return Err(FormatError::InvalidArchive("Windows backup metadata stream declaration is inconsistent"));
    }
    if record.kind == "windows.object-id" {
        return restore_windows_object_id(base_file, path, record, payload, options, diagnostics);
    }
    // SAFETY: the source handle is live; the returned handle, if valid, receives independent
    // ownership and is converted to `File` exactly once.
    let reopened = unsafe {
        ReOpenFile(
            base_file.as_raw_handle().cast(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_FLAG_BACKUP_SEMANTICS,
        )
    };
    if reopened.is_null() || reopened as isize == -1 {
        let error = std::io::Error::last_os_error();
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "windows-backup-v1",
                &record.kind,
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to reopen Windows object for backup-stream restoration",
            )
            .for_restore(options.restore_policy, 2)
            .with_native_error(&error),
            options,
            "failed to reopen Windows object for backup-stream restoration",
        );
    }
    // SAFETY: ownership of the newly reopened handle transfers to `destination` once.
    let destination = unsafe { fs::File::from_raw_handle(reopened.cast()) };
    let mut context = ptr::null_mut();
    let signed_size = i64::try_from(record.logical_size).map_err(|_| FormatError::ReaderUnsupported("Windows backup metadata stream exceeds i64"))?;
    let mut header = [0u8; 20];
    header[0..4].copy_from_slice(&stream_type.to_le_bytes());
    header[4..8].copy_from_slice(&stream_attributes.to_le_bytes());
    header[8..16].copy_from_slice(&signed_size.to_le_bytes());
    let result = (|| {
        windows_backup_write_all(&destination, &mut context, &header)?;
        payload
            .seek(SeekFrom::Start(0))
            .map_err(|_| FormatError::FilesystemExtractionFailed("failed to rewind staged Windows backup metadata stream"))?;
        let mut buffer = [0u8; 64 * 1024];
        let mut remaining = record.logical_size;
        while remaining != 0 {
            let count = buffer.len().min(usize::try_from(remaining).unwrap_or(usize::MAX));
            payload
                .read_exact(&mut buffer[..count])
                .map_err(|_| FormatError::FilesystemExtractionFailed("staged Windows backup metadata stream ended early"))?;
            windows_backup_write_all(&destination, &mut context, &buffer[..count])?;
            remaining -= count as u64;
        }
        Ok(())
    })();
    let mut ignored = 0u32;
    // SAFETY: aborting with an empty buffer releases exactly this BackupWrite context.
    let abort_ok = unsafe { BackupWrite(destination.as_raw_handle().cast(), ptr::null(), 0, &mut ignored, 1, 0, &mut context) } != 0;
    let result = if result.is_ok() && !abort_ok {
        Err(FormatError::FilesystemExtractionFailed(
            "failed to finalize Windows backup metadata stream restoration",
        ))
    } else {
        result
    };
    match result {
        Ok(()) => Ok(()),
        Err(error @ FormatError::FilesystemExtractionFailed(_)) => record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "windows-backup-v1",
                &record.kind,
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                error.to_string(),
            )
            .for_restore(options.restore_policy, 2),
            options,
            "failed to restore Windows backup metadata stream",
        ),
        Err(error) => Err(error),
    }
}

#[cfg(windows)]
fn restore_windows_object_id(
    destination: &fs::File,
    path: &[u8],
    record: &AuxiliaryRecord,
    payload: &mut fs::File,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    use std::mem::size_of;
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
    use windows_sys::Win32::Storage::FileSystem::{
        ReOpenFile, FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    use windows_sys::Win32::System::Ioctl::{FILE_OBJECTID_BUFFER, FSCTL_GET_OBJECT_ID, FSCTL_SET_OBJECT_ID};
    use windows_sys::Win32::System::IO::DeviceIoControl;

    let size = size_of::<FILE_OBJECTID_BUFFER>();
    if record.logical_size != size as u64 {
        return Err(FormatError::InvalidArchive("Windows object-ID backup stream is not exactly 64 bytes"));
    }
    let mut desired = FILE_OBJECTID_BUFFER::default();
    payload
        .seek(SeekFrom::Start(0))
        .map_err(|_| FormatError::FilesystemExtractionFailed("failed to rewind staged Windows object ID"))?;
    {
        // SAFETY: `desired` is live and writable, and the slice covers exactly its object
        // representation so the authenticated 64-byte stream can be copied without alignment loss.
        let desired_bytes = unsafe { std::slice::from_raw_parts_mut((&mut desired as *mut FILE_OBJECTID_BUFFER).cast::<u8>(), size) };
        payload
            .read_exact(desired_bytes)
            .map_err(|_| FormatError::FilesystemExtractionFailed("staged Windows object ID ended early"))?;
    }

    let reopened_handle = unsafe {
        ReOpenFile(
            destination.as_raw_handle().cast(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_FLAG_BACKUP_SEMANTICS,
        )
    };
    if reopened_handle.is_null() || reopened_handle as isize == -1 {
        let error = std::io::Error::last_os_error();
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "windows-backup-v1",
                &record.kind,
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to reopen Windows object for object-ID restoration",
            )
            .for_restore(options.restore_policy, 2)
            .with_native_error(&error),
            options,
            "failed to reopen Windows object for object-ID restoration",
        );
    }
    let reopened = unsafe { fs::File::from_raw_handle(reopened_handle.cast()) };

    let mut returned = 0u32;
    // SAFETY: the destination handle is live and `desired` is a fully initialized fixed-size
    // FILE_OBJECTID_BUFFER retained for the duration of this synchronous control request.
    let set_ok = unsafe {
        DeviceIoControl(
            reopened.as_raw_handle().cast(),
            FSCTL_SET_OBJECT_ID,
            (&mut desired as *mut FILE_OBJECTID_BUFFER).cast(),
            size as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    } != 0;
    let set_error = (!set_ok).then(std::io::Error::last_os_error);
    let mut actual = FILE_OBJECTID_BUFFER::default();
    returned = 0;
    // SAFETY: the destination handle and writable `actual` output buffer remain live for this
    // synchronous request, with the exact structure size supplied to the kernel.
    let get_ok = unsafe {
        DeviceIoControl(
            reopened.as_raw_handle().cast(),
            FSCTL_GET_OBJECT_ID,
            std::ptr::null(),
            0,
            (&mut actual as *mut FILE_OBJECTID_BUFFER).cast(),
            size as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    } != 0;
    // SAFETY: both initialized structures remain live and are viewed over their exact object
    // representations solely for byte-for-byte verification.
    let actual_bytes = unsafe { std::slice::from_raw_parts((&actual as *const FILE_OBJECTID_BUFFER).cast::<u8>(), size) };
    let desired_bytes = unsafe { std::slice::from_raw_parts((&desired as *const FILE_OBJECTID_BUFFER).cast::<u8>(), size) };
    if get_ok && returned as usize == size && actual_bytes == desired_bytes {
        return Ok(());
    }
    let error = set_error.unwrap_or_else(std::io::Error::last_os_error);
    record_metadata_application_failure(
        diagnostics,
        MetadataDiagnostic::new(
            path,
            "windows-backup-v1",
            "windows.object-id",
            MetadataOperation::Restore,
            MetadataDiagnosticStatus::Failed,
            "failed to restore and verify Windows object ID",
        )
        .for_restore(options.restore_policy, 2)
        .with_native_error(&error),
        options,
        "failed to restore and verify Windows object ID",
    )
}

#[cfg(windows)]
fn windows_backup_write_all(destination: &fs::File, context: &mut *mut std::ffi::c_void, mut bytes: &[u8]) -> Result<(), FormatError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::BackupWrite;

    while !bytes.is_empty() {
        let count = bytes.len().min(u32::MAX as usize);
        let mut written = 0u32;
        // SAFETY: the destination and context are live, and the input slice is readable for the
        // exact requested byte count during this synchronous call.
        if unsafe { BackupWrite(destination.as_raw_handle().cast(), bytes.as_ptr(), count as u32, &mut written, 0, 0, context) } == 0 {
            return Err(FormatError::FilesystemExtractionFailed("failed to restore Windows backup metadata stream"));
        }
        if written == 0 || written as usize > count {
            return Err(FormatError::FilesystemExtractionFailed("Windows BackupWrite made no progress"));
        }
        bytes = &bytes[written as usize..];
    }
    Ok(())
}

#[cfg(windows)]
fn restore_windows_alternate_stream_payload(staged: &mut fs::File, stream: &mut fs::File, record: &AuxiliaryRecord) -> Result<(), FormatError> {
    let sparse_layout = record.sparse_layout.as_ref();
    let extents = sparse_layout.map(|layout| layout.extents.as_slice());
    let extent_bytes = extents
        .unwrap_or_default()
        .iter()
        .try_fold(0u64, |sum, extent| sum.checked_add(extent.length))
        .ok_or(FormatError::InvalidArchive("sparse Windows alternate stream extent size overflow"))?;
    let data_offset = if let Some(extents) = extents {
        let map_size = sparse_layout.expect("sparse extents require a layout").map_and_padding_size as u64;
        if map_size.checked_add(extent_bytes) != Some(record.stored_size) {
            return Err(FormatError::InvalidArchive("sparse Windows alternate stream stored size is inconsistent"));
        }
        prepare_windows_sparse_file(stream, record.logical_size)?;
        staged
            .seek(SeekFrom::Start(map_size))
            .map_err(|_| FormatError::FilesystemExtractionFailed("failed to seek staged sparse alternate stream"))?;
        for extent in extents {
            stream
                .seek(SeekFrom::Start(extent.offset))
                .map_err(|_| FormatError::FilesystemExtractionFailed("failed to seek sparse alternate stream"))?;
            copy_exact_bytes(staged, stream, extent.length, "Windows sparse alternate stream")?;
        }
        map_size
    } else {
        staged
            .seek(SeekFrom::Start(0))
            .map_err(|_| FormatError::FilesystemExtractionFailed("failed to rewind staged alternate stream"))?;
        copy_exact_bytes(staged, stream, record.logical_size, "Windows alternate stream")?;
        0
    };
    stream
        .flush()
        .map_err(|_| FormatError::FilesystemExtractionFailed("failed to flush Windows alternate stream"))?;
    if stream
        .metadata()
        .map_err(|_| FormatError::FilesystemExtractionFailed("failed to inspect Windows alternate stream"))?
        .len()
        != record.logical_size
    {
        return Err(FormatError::FilesystemExtractionFailed("Windows alternate stream logical size did not verify"));
    }
    if let Some(extents) = extents {
        let actual_extents = query_windows_sparse_ranges(stream, record.logical_size)?;
        if actual_extents != extents && !windows_file_system_is_refs(stream)? {
            return Err(FormatError::FilesystemExtractionFailed("Windows sparse alternate stream ranges did not verify"));
        }
    }
    staged
        .seek(SeekFrom::Start(data_offset))
        .map_err(|_| FormatError::FilesystemExtractionFailed("failed to rewind staged alternate stream data"))?;
    if let Some(extents) = extents {
        for extent in extents {
            stream
                .seek(SeekFrom::Start(extent.offset))
                .map_err(|_| FormatError::FilesystemExtractionFailed("failed to seek restored sparse alternate stream"))?;
            compare_exact_bytes(staged, stream, extent.length, "Windows sparse alternate stream")?;
        }
    } else {
        stream
            .seek(SeekFrom::Start(0))
            .map_err(|_| FormatError::FilesystemExtractionFailed("failed to rewind Windows alternate stream"))?;
        compare_exact_bytes(staged, stream, record.logical_size, "Windows alternate stream")?;
    }
    Ok(())
}

#[cfg(windows)]
fn copy_exact_bytes(input: &mut fs::File, output: &mut fs::File, mut remaining: u64, description: &'static str) -> Result<(), FormatError> {
    let mut buffer = [0u8; 64 * 1024];
    while remaining > 0 {
        let count = buffer.len().min(usize::try_from(remaining).unwrap_or(usize::MAX));
        input
            .read_exact(&mut buffer[..count])
            .map_err(|_| FormatError::FilesystemExtractionFailed("staged auxiliary payload ended early"))?;
        output
            .write_all(&buffer[..count])
            .map_err(|_| FormatError::FilesystemExtractionFailed(description))?;
        remaining -= count as u64;
    }
    Ok(())
}

#[cfg(windows)]
fn compare_exact_bytes(expected: &mut fs::File, actual: &mut fs::File, mut remaining: u64, description: &'static str) -> Result<(), FormatError> {
    let mut expected_buffer = [0u8; 64 * 1024];
    let mut actual_buffer = [0u8; 64 * 1024];
    while remaining > 0 {
        let count = expected_buffer.len().min(usize::try_from(remaining).unwrap_or(usize::MAX));
        expected
            .read_exact(&mut expected_buffer[..count])
            .map_err(|_| FormatError::FilesystemExtractionFailed("failed to read staged auxiliary payload"))?;
        actual
            .read_exact(&mut actual_buffer[..count])
            .map_err(|_| FormatError::FilesystemExtractionFailed("failed to read restored auxiliary payload"))?;
        if expected_buffer[..count] != actual_buffer[..count] {
            return Err(FormatError::FilesystemExtractionFailed(description));
        }
        remaining -= count as u64;
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn apply_generic_xattr_auxiliaries(
    base_file: &fs::File,
    path: &[u8],
    staged: &mut Vec<StagedAuxiliary>,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use xattr::FileExt as _;

    let mut remaining = Vec::new();
    for mut item in std::mem::take(staged) {
        if item.record.kind != "generic.xattr" {
            remaining.push(item);
            continue;
        }
        if item.record.restore_class == RestoreClass::System && !(options.restore_policy == RestorePolicy::System && options.system_authorized) {
            continue;
        }
        item.file
            .seek(SeekFrom::Start(0))
            .map_err(|_| FormatError::FilesystemExtractionFailed("failed to rewind staged extended attribute"))?;
        let value_len = usize::try_from(item.record.logical_size).map_err(|_| FormatError::ReaderUnsupported("extended attribute exceeds platform limits"))?;
        let mut value = vec![0u8; value_len];
        item.file
            .read_exact(&mut value)
            .map_err(|_| FormatError::FilesystemExtractionFailed("failed to read staged extended attribute"))?;
        let name = OsStr::from_bytes(&item.record.decoded_name);
        if let Err(error) = base_file.set_xattr(name, &value) {
            record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    &item.record.profile,
                    "extended-attribute",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    "failed to apply auxiliary extended attribute",
                )
                .for_restore(options.restore_policy, 4)
                .with_native_error(&error),
                options,
                "failed to apply auxiliary extended attribute",
            )?;
            continue;
        }
        if base_file.get_xattr(name).ok().flatten().as_deref() != Some(value.as_slice()) {
            record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    &item.record.profile,
                    "extended-attribute",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    "auxiliary extended attribute did not verify after restoration",
                )
                .for_restore(options.restore_policy, 4),
                options,
                "auxiliary extended attribute did not verify after restoration",
            )?;
        }
    }
    *staged = remaining;
    Ok(())
}

#[cfg(target_os = "macos")]
fn open_macos_resource_fork(file: &fs::File, write: bool) -> std::io::Result<fs::File> {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt as _;
    use std::os::unix::fs::MetadataExt as _;

    let mut path = vec![0u8; libc::PATH_MAX as usize];
    // SAFETY: `path` is writable for PATH_MAX bytes and F_GETPATH writes a NUL-terminated path.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, path.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let length = path
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "macOS returned an unterminated descriptor path"))?;
    path.truncate(length);
    path.extend_from_slice(b"/..namedfork/rsrc");
    let path = PathBuf::from(OsString::from_vec(path));
    let mut options = fs::OpenOptions::new();
    options.read(true);
    if write {
        options.write(true).truncate(true).create(true);
    }
    let fork = options.open(path)?;
    let owner = file.metadata()?;
    let fork_metadata = fork.metadata()?;
    #[allow(clippy::unnecessary_cast)]
    if owner.dev() != fork_metadata.dev() || owner.ino() != fork_metadata.ino() {
        return Err(std::io::Error::other("resource fork path no longer identifies the pinned file"));
    }
    Ok(fork)
}

#[cfg(target_os = "macos")]
fn apply_macos_native_metadata(
    file: &fs::File,
    path: &[u8],
    metadata: &MemberMetadata,
    staged: &mut Vec<StagedAuxiliary>,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    use std::ffi::{c_int, c_void, OsStr};
    use std::os::unix::ffi::OsStrExt as _;
    use xattr::FileExt as _;

    if metadata.declaration.source_os != "macos" || !matches!(options.restore_policy, RestorePolicy::SameOs | RestorePolicy::System) {
        return Ok(());
    }

    extern "C" {
        fn acl_copy_int(buffer: *const c_void) -> *mut c_void;
        fn acl_copy_ext(buffer: *mut c_void, acl: *mut c_void, size: libc::ssize_t) -> libc::ssize_t;
        fn acl_size(acl: *mut c_void) -> libc::ssize_t;
        fn acl_set_fd_np(fd: c_int, acl: *mut c_void, acl_type: c_int) -> c_int;
        fn acl_get_fd_np(fd: c_int, acl_type: c_int) -> *mut c_void;
        fn acl_free(object: *mut c_void) -> c_int;
    }

    const ACL_TYPE_EXTENDED: c_int = 0x0000_0100;

    let fail = |diagnostics: &mut Vec<MetadataDiagnostic>, class: &'static str, message: &'static str, error: Option<&std::io::Error>| {
        let mut diagnostic = MetadataDiagnostic::new(
            path,
            "macos-backup-v1",
            class,
            MetadataOperation::Restore,
            MetadataDiagnosticStatus::Failed,
            message,
        )
        .for_restore(options.restore_policy, 4);
        if let Some(error) = error {
            diagnostic = diagnostic.with_native_error(error);
        }
        record_metadata_application_failure(diagnostics, diagnostic, options, message)
    };

    let mut items = std::mem::take(staged);
    items.sort_by_key(|item| match item.record.kind.as_str() {
        "macos.resource-fork" => 0,
        "macos.acl-native" => 1,
        "macos.finder-info" => 2,
        _ => 3,
    });
    let mut remaining = Vec::new();
    for mut item in items {
        match item.record.kind.as_str() {
            "macos.finder-info" => {
                if item.record.logical_size != 32 {
                    return Err(FormatError::InvalidArchive("macOS FinderInfo is not exactly 32 bytes"));
                }
                let mut value = [0u8; 32];
                item.file
                    .seek(SeekFrom::Start(0))
                    .map_err(|_| FormatError::FilesystemExtractionFailed("failed to rewind staged macOS FinderInfo"))?;
                item.file
                    .read_exact(&mut value)
                    .map_err(|_| FormatError::FilesystemExtractionFailed("failed to read staged macOS FinderInfo"))?;
                let name = OsStr::from_bytes(b"com.apple.FinderInfo");
                if let Err(error) = file.set_xattr(name, &value) {
                    fail(diagnostics, "finder-info", "failed to apply macOS FinderInfo", Some(&error))?;
                } else if file.get_xattr(name).ok().flatten().as_deref() != Some(value.as_slice()) {
                    fail(diagnostics, "finder-info", "macOS FinderInfo did not verify after restoration", None)?;
                }
            }
            "macos.resource-fork" => {
                item.file
                    .seek(SeekFrom::Start(0))
                    .map_err(|_| FormatError::FilesystemExtractionFailed("failed to rewind staged macOS resource fork"))?;
                let mut fork = match open_macos_resource_fork(file, true) {
                    Ok(fork) => fork,
                    Err(error) => {
                        fail(diagnostics, "resource-fork", "failed to open macOS resource fork", Some(&error))?;
                        continue;
                    }
                };
                if std::io::copy(&mut item.file, &mut fork)
                    .ok()
                    .is_none_or(|copied| copied != item.record.logical_size)
                    || fork.sync_all().is_err()
                {
                    fail(diagnostics, "resource-fork", "failed to write macOS resource fork", None)?;
                } else {
                    drop(fork);
                    let mut fork = open_macos_resource_fork(file, false)
                        .map_err(|_| FormatError::FilesystemExtractionFailed("failed to reopen macOS resource fork for verification"))?;
                    item.file
                        .seek(SeekFrom::Start(0))
                        .map_err(|_| FormatError::FilesystemExtractionFailed("failed to rewind staged macOS resource fork"))?;
                    let mut expected = vec![0u8; 1024 * 1024];
                    let mut actual = vec![0u8; 1024 * 1024];
                    let mut remaining = item.record.logical_size;
                    let mut verified = true;
                    while remaining > 0 {
                        let count = expected.len().min(usize::try_from(remaining).unwrap_or(usize::MAX));
                        if item.file.read_exact(&mut expected[..count]).is_err()
                            || fork.read_exact(&mut actual[..count]).is_err()
                            || expected[..count] != actual[..count]
                        {
                            verified = false;
                            break;
                        }
                        remaining -= count as u64;
                    }
                    let mut trailing = [0u8; 1];
                    if verified && fork.read(&mut trailing).ok() != Some(0) {
                        verified = false;
                    }
                    if !verified {
                        fail(
                            diagnostics,
                            "resource-fork",
                            "macOS resource fork content did not verify after restoration",
                            None,
                        )?;
                    }
                }
            }
            "macos.acl-native" => {
                let size = usize::try_from(item.record.logical_size).map_err(|_| FormatError::ReaderUnsupported("macOS ACL exceeds platform limits"))?;
                let mut value = vec![0u8; size];
                item.file
                    .seek(SeekFrom::Start(0))
                    .map_err(|_| FormatError::FilesystemExtractionFailed("failed to rewind staged macOS ACL"))?;
                item.file
                    .read_exact(&mut value)
                    .map_err(|_| FormatError::FilesystemExtractionFailed("failed to read staged macOS ACL"))?;
                validate_darwin_acl_external(&value)?;
                // SAFETY: the external form was structurally bounded above; returned ACLs are freed.
                let acl = unsafe { acl_copy_int(value.as_ptr().cast()) };
                if acl.is_null() || unsafe { acl_size(acl) } != size as libc::ssize_t {
                    if !acl.is_null() {
                        unsafe { acl_free(acl) };
                    }
                    return Err(FormatError::InvalidArchive("macOS ACL external form is invalid"));
                }
                if unsafe { acl_set_fd_np(file.as_raw_fd(), acl, ACL_TYPE_EXTENDED) } != 0 {
                    let error = std::io::Error::last_os_error();
                    unsafe { acl_free(acl) };
                    fail(diagnostics, "acl-native", "failed to apply native macOS ACL", Some(&error))?;
                    continue;
                }
                unsafe { acl_free(acl) };
                let restored = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
                if restored.is_null() || unsafe { acl_size(restored) } != size as libc::ssize_t {
                    if !restored.is_null() {
                        unsafe { acl_free(restored) };
                    }
                    fail(diagnostics, "acl-native", "native macOS ACL did not verify after restoration", None)?;
                    continue;
                }
                let mut actual = vec![0u8; size];
                let copied = unsafe { acl_copy_ext(actual.as_mut_ptr().cast(), restored, size as libc::ssize_t) };
                unsafe { acl_free(restored) };
                if copied != size as libc::ssize_t || actual != value {
                    fail(diagnostics, "acl-native", "native macOS ACL did not verify after restoration", None)?;
                }
            }
            _ => remaining.push(item),
        }
    }
    *staged = remaining;

    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn apply_macos_native_metadata(
    _file: &fs::File,
    _path: &[u8],
    _metadata: &MemberMetadata,
    _staged: &mut Vec<StagedAuxiliary>,
    _options: SafeExtractionOptions,
    _diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    Ok(())
}

#[cfg(target_os = "macos")]
fn apply_macos_file_timestamps(
    file: &fs::File,
    path: &[u8],
    metadata: &MemberMetadata,
    mtime: (i64, u32),
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    use std::ffi::{c_int, c_void};
    use std::os::macos::fs::MetadataExt as _;

    #[repr(C)]
    struct AttrList {
        bitmap_count: u16,
        reserved: u16,
        common_attr: u32,
        volume_attr: u32,
        directory_attr: u32,
        file_attr: u32,
        fork_attr: u32,
    }
    extern "C" {
        fn fsetattrlist(fd: c_int, attributes: *const c_void, buffer: *const c_void, size: usize, options: u32) -> c_int;
    }
    let mut common_attr = 0x0000_0400;
    let mut times = Vec::<libc::timespec>::new();
    let creation_time = metadata
        .primary_records
        .get("LIBARCHIVE.creationtime")
        .map(|encoded| parse_timestamp(encoded))
        .transpose()?;
    if let Some((seconds, nanoseconds)) = creation_time {
        common_attr |= 0x0000_0200;
        times.push(libc::timespec {
            tv_sec: seconds,
            tv_nsec: i64::from(nanoseconds),
        });
    }
    times.push(libc::timespec {
        tv_sec: mtime.0,
        tv_nsec: i64::from(mtime.1),
    });
    let attributes = AttrList {
        bitmap_count: 5,
        reserved: 0,
        common_attr,
        volume_attr: 0,
        directory_attr: 0,
        file_attr: 0,
        fork_attr: 0,
    };
    if unsafe {
        fsetattrlist(
            file.as_raw_fd(),
            (&attributes as *const AttrList).cast(),
            times.as_ptr().cast(),
            times.len() * std::mem::size_of::<libc::timespec>(),
            0,
        )
    } != 0
    {
        let error = std::io::Error::last_os_error();
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "macos-backup-v1",
                "timestamps",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to apply macOS timestamps",
            )
            .for_restore(options.restore_policy, 4)
            .with_native_error(&error),
            options,
            "failed to apply macOS timestamps",
        );
    }
    let actual = file
        .metadata()
        .map_err(|_| FormatError::FilesystemExtractionFailed("failed to inspect restored macOS timestamps"))?;
    if (actual.st_mtime(), actual.st_mtime_nsec() as u32) != mtime
        || creation_time.is_some_and(|creation| (actual.st_birthtime(), actual.st_birthtime_nsec() as u32) != creation)
    {
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "macos-backup-v1",
                "timestamps",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "macOS timestamps did not verify after restoration",
            )
            .for_restore(options.restore_policy, 4),
            options,
            "macOS timestamps did not verify after restoration",
        );
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn apply_macos_file_timestamps(
    _file: &fs::File,
    _path: &[u8],
    _metadata: &MemberMetadata,
    _mtime: (i64, u32),
    _options: SafeExtractionOptions,
    _diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    Ok(())
}

#[cfg(target_os = "macos")]
fn apply_macos_file_flags(
    file: &fs::File,
    path: &[u8],
    metadata: &MemberMetadata,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    use std::os::macos::fs::MetadataExt as _;

    if metadata.declaration.source_os != "macos" || !matches!(options.restore_policy, RestorePolicy::SameOs | RestorePolicy::System) {
        return Ok(());
    }
    let Some(encoded) = metadata.primary_records.get("TZAP.macos.st-flags") else {
        return Ok(());
    };
    let desired = parse_macos_flags(encoded)? & MACOS_KNOWN_SETTABLE_FLAGS;
    if macos_flags_require_system(desired) && !(options.restore_policy == RestorePolicy::System && options.system_authorized) {
        return Ok(());
    }
    let retained_unknown = file.metadata().map(|value| value.st_flags() & !MACOS_KNOWN_SETTABLE_FLAGS).unwrap_or(0);
    let applied = retained_unknown | desired;
    // SAFETY: `file` owns a live descriptor and the desired value was range checked.
    if unsafe { libc::fchflags(file.as_raw_fd(), applied) } != 0 {
        let error = std::io::Error::last_os_error();
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "macos-backup-v1",
                "file-flags",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to apply macOS file flags",
            )
            .for_restore(options.restore_policy, 4)
            .with_native_error(&error),
            options,
            "failed to apply macOS file flags",
        );
    }
    if file.metadata().map(|value| value.st_flags() & MACOS_KNOWN_SETTABLE_FLAGS).ok() != Some(desired) {
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "macos-backup-v1",
                "file-flags",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "macOS file flags did not verify after restoration",
            )
            .for_restore(options.restore_policy, 4),
            options,
            "macOS file flags did not verify after restoration",
        );
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn apply_macos_file_flags(
    _file: &fs::File,
    _path: &[u8],
    _metadata: &MemberMetadata,
    _options: SafeExtractionOptions,
    _diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn apply_generic_xattr_auxiliaries_to_path(
    base_path: &Path,
    dereference: bool,
    path: &[u8],
    staged: &mut Vec<StagedAuxiliary>,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let mut remaining = Vec::new();
    for mut item in std::mem::take(staged) {
        if item.record.kind != "generic.xattr" {
            remaining.push(item);
            continue;
        }
        if item.record.restore_class == RestoreClass::System && !(options.restore_policy == RestorePolicy::System && options.system_authorized) {
            continue;
        }
        item.file
            .seek(SeekFrom::Start(0))
            .map_err(|_| FormatError::FilesystemExtractionFailed("failed to rewind staged extended attribute"))?;
        let value_len = usize::try_from(item.record.logical_size).map_err(|_| FormatError::ReaderUnsupported("extended attribute exceeds platform limits"))?;
        let mut value = vec![0u8; value_len];
        item.file
            .read_exact(&mut value)
            .map_err(|_| FormatError::FilesystemExtractionFailed("failed to read staged extended attribute"))?;
        let name = OsStr::from_bytes(&item.record.decoded_name);
        let set_result = if dereference {
            xattr::set_deref(base_path, name, &value)
        } else {
            xattr::set(base_path, name, &value)
        };
        if let Err(error) = set_result {
            record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    &item.record.profile,
                    "extended-attribute",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    "failed to apply auxiliary extended attribute",
                )
                .for_restore(options.restore_policy, 4)
                .with_native_error(&error),
                options,
                "failed to apply auxiliary extended attribute",
            )?;
            continue;
        }
        let restored = if dereference {
            xattr::get_deref(base_path, name)
        } else {
            xattr::get(base_path, name)
        };
        if restored.ok().flatten().as_deref() != Some(value.as_slice()) {
            record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    &item.record.profile,
                    "extended-attribute",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    "auxiliary extended attribute did not verify after restoration",
                )
                .for_restore(options.restore_policy, 4),
                options,
                "auxiliary extended attribute did not verify after restoration",
            )?;
        }
    }
    *staged = remaining;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn apply_generic_xattr_auxiliaries(
    _base_file: &fs::File,
    _path: &[u8],
    _staged: &mut Vec<StagedAuxiliary>,
    _options: SafeExtractionOptions,
    _diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    Ok(())
}

#[cfg(not(windows))]
pub(crate) fn apply_windows_alternate_streams(
    _base_file: &fs::File,
    _path: &[u8],
    _staged: &mut Vec<StagedAuxiliary>,
    _options: SafeExtractionOptions,
    _diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    Ok(())
}

#[cfg(windows)]
pub(crate) fn apply_windows_security_descriptor(
    file: &fs::File,
    path: &[u8],
    metadata: &MemberMetadata,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER};
    use windows_sys::Win32::Security::Authorization::{SetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        GetKernelObjectSecurity, GetSecurityDescriptorDacl, GetSecurityDescriptorGroup, GetSecurityDescriptorOwner, GetSecurityDescriptorSacl,
        SetKernelObjectSecurity,
    };
    use windows_sys::Win32::Storage::FileSystem::{ReOpenFile, READ_CONTROL, WRITE_DAC, WRITE_OWNER};
    use windows_sys::Win32::System::SystemServices::ACCESS_SYSTEM_SECURITY;

    if metadata.declaration.source_os != "windows" || options.restore_policy != RestorePolicy::System || !options.system_authorized {
        return Ok(());
    }
    let Some(record) = metadata.auxiliary.iter().find(|record| record.kind == "windows.security-descriptor") else {
        return Ok(());
    };
    let payload = record
        .capture_report_payload
        .as_deref()
        .ok_or(FormatError::InvalidArchive("Windows security descriptor was not retained"))?;
    let security_information = record
        .meta
        .get("TZAP.aux.meta.security-information")
        .map(|value| parse_lower_hex_u32(value, "Windows security information"))
        .transpose()?
        .ok_or(FormatError::InvalidArchive("Windows security descriptor lacks its information mask"))?;
    let query_security_information = security_information & 0x0000_000f;
    let control = u16::from_le_bytes([payload[2], payload[3]]);
    let mut application_security_information = security_information;
    if security_information & 0x0000_0004 != 0 && security_information & 0xa000_0000 == 0 {
        application_security_information |= if control & 0x1000 != 0 { 0x8000_0000 } else { 0x2000_0000 };
    }
    if security_information & 0x0000_0008 != 0 && security_information & 0x5000_0000 == 0 {
        application_security_information |= if control & 0x2000 != 0 { 0x4000_0000 } else { 0x1000_0000 };
    }
    if !windows_security_restore_privileges_available(security_information) {
        let diagnostic = MetadataDiagnostic::new(
            path,
            "windows-backup-v1",
            "security-descriptor",
            MetadataOperation::Restore,
            MetadataDiagnosticStatus::Unsupported,
            "required Windows restore privilege is unavailable",
        )
        .for_restore(options.restore_policy, 4);
        if options.allow_degraded {
            diagnostics.push(diagnostic);
            return Ok(());
        }
        return Err(FormatError::ReaderUnsupported(
            "Windows security restoration requires SeBackupPrivilege, SeRestorePrivilege, and optional SeSecurityPrivilege",
        ));
    }
    let desired_access = READ_CONTROL | WRITE_DAC | WRITE_OWNER | if security_information & 0x0000_0008 != 0 { ACCESS_SYSTEM_SECURITY } else { 0 };
    // SAFETY: the original handle is live and flags preserve no-follow access to its object.
    let reopened_security_handle = unsafe {
        ReOpenFile(
            file.as_raw_handle().cast(),
            desired_access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        )
    };
    let (security_handle, owns_security_handle) = if reopened_security_handle.is_null() || reopened_security_handle as isize == -1 {
        if file.metadata().is_ok_and(|metadata| metadata.is_dir()) {
            // Directory finalization opens its pinned handle with the
            // security access mask up front. ReOpenFile can still reject
            // directory handles even with backup semantics, so retain the
            // already-authorized pinned handle.
            (file.as_raw_handle().cast(), false)
        } else {
            (reopened_security_handle, true)
        }
    } else {
        (reopened_security_handle, true)
    };
    if security_handle.is_null() || security_handle as isize == -1 {
        let error = std::io::Error::last_os_error();
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "windows-backup-v1",
                "security-descriptor",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to open object for Windows security restoration",
            )
            .for_restore(options.restore_policy, 4)
            .with_native_error(&error),
            options,
            "failed to open object for Windows security restoration",
        );
    }
    let descriptor = payload.as_ptr().cast_mut().cast();
    let mut owner = ptr::null_mut();
    let mut group = ptr::null_mut();
    let mut dacl = ptr::null_mut();
    let mut sacl = ptr::null_mut();
    let mut owner_defaulted = 0;
    let mut group_defaulted = 0;
    let mut dacl_present = 0;
    let mut dacl_defaulted = 0;
    let mut sacl_present = 0;
    let mut sacl_defaulted = 0;
    // SAFETY: the parser-validated self-relative descriptor remains readable and every
    // component output points to initialized local storage for these calls.
    let descriptor_components_ok = unsafe {
        GetSecurityDescriptorOwner(descriptor, &mut owner, &mut owner_defaulted) != 0
            && GetSecurityDescriptorGroup(descriptor, &mut group, &mut group_defaulted) != 0
            && GetSecurityDescriptorDacl(descriptor, &mut dacl_present, &mut dacl, &mut dacl_defaulted) != 0
            && GetSecurityDescriptorSacl(descriptor, &mut sacl_present, &mut sacl, &mut sacl_defaulted) != 0
    };
    if !descriptor_components_ok {
        if owns_security_handle {
            unsafe { CloseHandle(security_handle) };
        }
        return Err(FormatError::InvalidArchive("Windows security descriptor components are invalid"));
    }
    let mut set_error = None;
    let owner_group_information = application_security_information & 0x0000_0003;
    if owner_group_information != 0
        // SAFETY: the handle is live and the validated descriptor contains the selected fields.
        && unsafe { SetKernelObjectSecurity(security_handle, owner_group_information, descriptor) }
            == 0
    {
        set_error = Some(std::io::Error::last_os_error());
    }
    let dacl_information = application_security_information & 0xa000_0004;
    if set_error.is_none() && dacl_information & 0x0000_0004 != 0 {
        if dacl_present == 0 || control & 0x0400 != 0 {
            // SAFETY: the handle and DACL pointer remain live for automatic-inheritance apply.
            let status = unsafe {
                SetSecurityInfo(
                    security_handle,
                    SE_FILE_OBJECT,
                    dacl_information,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    dacl,
                    ptr::null_mut(),
                )
            };
            if status != 0 {
                set_error = Some(std::io::Error::from_raw_os_error(status as i32));
            }
        } else if unsafe {
            // SAFETY: the handle is live and the validated descriptor contains the DACL.
            SetKernelObjectSecurity(security_handle, dacl_information, descriptor)
        } == 0
        {
            set_error = Some(std::io::Error::last_os_error());
        }
    }
    let sacl_information = application_security_information & 0x5000_0008;
    if set_error.is_none() && sacl_information & 0x0000_0008 != 0 {
        if sacl_present == 0 || control & 0x0800 != 0 {
            // SAFETY: the handle and SACL pointer remain live for automatic-inheritance apply.
            let status = unsafe {
                SetSecurityInfo(
                    security_handle,
                    SE_FILE_OBJECT,
                    sacl_information,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    sacl,
                )
            };
            if status != 0 {
                set_error = Some(std::io::Error::from_raw_os_error(status as i32));
            }
        } else if unsafe {
            // SAFETY: the handle is live and the validated descriptor contains the SACL.
            SetKernelObjectSecurity(security_handle, sacl_information, descriptor)
        } == 0
        {
            set_error = Some(std::io::Error::last_os_error());
        }
    }
    if let Some(set_error) = set_error {
        if owns_security_handle {
            unsafe { CloseHandle(security_handle) };
        }
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "windows-backup-v1",
                "security-descriptor",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to apply Windows security descriptor",
            )
            .for_restore(options.restore_policy, 4)
            .with_native_error(&set_error),
            options,
            "failed to apply Windows security descriptor",
        );
    }

    let mut needed = 0u32;
    // SAFETY: the null-buffer query returns the descriptor size through `needed`.
    let first = unsafe { GetKernelObjectSecurity(security_handle, query_security_information, ptr::null_mut(), 0, &mut needed) };
    let first_error = std::io::Error::last_os_error();
    let mut actual = vec![0u8; needed as usize];
    // SAFETY: `actual` has the queried size and remains writable for the call.
    let get_ok = first == 0
        && first_error.raw_os_error() == Some(ERROR_INSUFFICIENT_BUFFER as i32)
        && needed != 0
        && unsafe { GetKernelObjectSecurity(security_handle, query_security_information, actual.as_mut_ptr().cast(), needed, &mut needed) } != 0;
    if owns_security_handle {
        unsafe { CloseHandle(security_handle) };
    }
    if get_ok && actual != payload && windows_security_descriptors_equivalent(payload, &actual) {
        diagnostics.push(
            MetadataDiagnostic::new(
                path,
                "windows-backup-v1",
                "security-descriptor",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Materialized,
                "Windows returned a semantically equivalent security descriptor with normalized self-relative layout or absent-ACL protection; all represented components verified",
            )
            .for_restore(options.restore_policy, 4),
        );
        return Ok(());
    }
    if !get_ok || actual != payload {
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "windows-backup-v1",
                "security-descriptor",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "Windows security descriptor did not verify after restoration",
            )
            .for_restore(options.restore_policy, 4),
            options,
            "Windows security descriptor did not verify after restoration",
        );
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn windows_security_descriptors_equivalent(expected: &[u8], actual: &[u8]) -> bool {
    const DACL_PRESENT: u16 = 0x0004;
    const SACL_PRESENT: u16 = 0x0010;
    const DACL_AUTO_INHERIT_REQ: u16 = 0x0100;
    const SACL_AUTO_INHERIT_REQ: u16 = 0x0200;
    const DACL_AUTO_INHERITED: u16 = 0x0400;
    const SACL_AUTO_INHERITED: u16 = 0x0800;
    const DACL_PROTECTED: u16 = 0x1000;
    const SACL_PROTECTED: u16 = 0x2000;

    if expected.len() < 20 || actual.len() < 20 || expected[..2] != actual[..2] {
        return false;
    }
    let expected_control = u16::from_le_bytes([expected[2], expected[3]]);
    let actual_control = u16::from_le_bytes([actual[2], actual[3]]);
    let mut ignorable = DACL_AUTO_INHERIT_REQ | SACL_AUTO_INHERIT_REQ | DACL_AUTO_INHERITED | SACL_AUTO_INHERITED;
    if expected_control & DACL_PRESENT == 0 && actual_control & DACL_PRESENT == 0 {
        ignorable |= DACL_PROTECTED;
    }
    if expected_control & SACL_PRESENT == 0 && actual_control & SACL_PRESENT == 0 {
        ignorable |= SACL_PROTECTED;
    }
    if (expected_control ^ actual_control) & !ignorable != 0 {
        return false;
    }

    // A self-relative descriptor does not prescribe component order or offsets. In particular,
    // EFS import followed by GetKernelObjectSecurity can return the same SIDs and ACLs in a
    // differently packed buffer than GetSecurityInfo used during capture. Compare the represented
    // components rather than requiring byte-identical offset fields and padding.
    for (offset_field, acl, represented) in [
        (4usize, false, true),
        (8, false, true),
        (12, true, expected_control & SACL_PRESENT != 0),
        (16, true, expected_control & DACL_PRESENT != 0),
    ] {
        if represented {
            let Some(expected_component) = security_descriptor_component(expected, offset_field, acl) else {
                return false;
            };
            let Some(actual_component) = security_descriptor_component(actual, offset_field, acl) else {
                return false;
            };
            if expected_component != actual_component {
                return false;
            }
        }
    }
    true
}

#[cfg(windows)]
fn security_descriptor_component(descriptor: &[u8], offset_field: usize, acl: bool) -> Option<&[u8]> {
    let offset_bytes = descriptor.get(offset_field..offset_field.checked_add(4)?)?;
    let offset = u32::from_le_bytes(offset_bytes.try_into().ok()?) as usize;
    if offset == 0 {
        return Some(&[]);
    }
    let length = if acl {
        let header = descriptor.get(offset..offset.checked_add(4)?)?;
        u16::from_le_bytes([header[2], header[3]]) as usize
    } else {
        let header = descriptor.get(offset..offset.checked_add(8)?)?;
        8usize.checked_add(usize::from(header[1]).checked_mul(4)?)?
    };
    descriptor.get(offset..offset.checked_add(length)?)
}

#[cfg(not(windows))]
pub(crate) fn apply_windows_security_descriptor(
    _file: &fs::File,
    _path: &[u8],
    _metadata: &MemberMetadata,
    _options: SafeExtractionOptions,
    _diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    Ok(())
}

#[cfg(windows)]
fn pax_timestamp_to_windows_filetime(timestamp: (i64, u32)) -> Result<i64, FormatError> {
    const WINDOWS_TO_UNIX_EPOCH_100NS: i128 = 116_444_736_000_000_000;
    let (seconds, nanoseconds) = timestamp;
    if nanoseconds % 100 != 0 {
        return Err(FormatError::FilesystemExtractionFailed(
            "Windows timestamp is not representable at 100-nanosecond precision",
        ));
    }
    let ticks = i128::from(seconds)
        .checked_mul(10_000_000)
        .and_then(|value| value.checked_add(i128::from(nanoseconds / 100)))
        .and_then(|value| value.checked_add(WINDOWS_TO_UNIX_EPOCH_100NS))
        .and_then(|value| i64::try_from(value).ok())
        .ok_or(FormatError::FilesystemExtractionFailed("Windows timestamp is outside the FILETIME range"))?;
    if ticks < 0 {
        return Err(FormatError::FilesystemExtractionFailed("Windows timestamp predates the FILETIME epoch"));
    }
    Ok(ticks)
}

#[cfg(windows)]
pub(crate) fn apply_windows_basic_metadata(
    file: &fs::File,
    path: &[u8],
    metadata: &MemberMetadata,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    if metadata.declaration.source_os != "windows" || !matches!(options.restore_policy, RestorePolicy::SameOs | RestorePolicy::System) {
        return Ok(());
    }

    apply_windows_directory_case_sensitive(file, path, metadata, options, diagnostics)?;

    let desired_attributes = metadata
        .primary_records
        .get("TZAP.windows.file-attributes")
        .map(|value| parse_lower_hex_u32(value, "Windows file attributes"))
        .transpose()?;
    let compression_exact = if let Some(desired) = desired_attributes {
        apply_windows_compression(file, path, desired & FILE_ATTRIBUTE_COMPRESSED != 0, options, diagnostics)?
    } else {
        true
    };
    let intrinsic_verification_mask = WINDOWS_ESSENTIAL_INTRINSIC_ATTRIBUTES
        & if options.restore_policy == RestorePolicy::System {
            u32::MAX
        } else {
            !FILE_ATTRIBUTE_ENCRYPTED
        }
        & if compression_exact { u32::MAX } else { !FILE_ATTRIBUTE_COMPRESSED };
    let attribute_verification_mask = WINDOWS_ESSENTIAL_SETTABLE_ATTRIBUTES | intrinsic_verification_mask;
    let parse_optional_timestamp = |key: &str| {
        metadata
            .primary_records
            .get(key)
            .map(|value| parse_timestamp(value).and_then(pax_timestamp_to_windows_filetime))
            .transpose()
    };
    let creation_time = parse_optional_timestamp("LIBARCHIVE.creationtime")?;
    let access_time = parse_optional_timestamp("atime")?;
    let write_time = Some(pax_timestamp_to_windows_filetime(metadata.portable_mirror.mtime)?);
    let change_time = parse_optional_timestamp("TZAP.windows.change-time")?;

    let mut current = FILE_BASIC_INFO::default();
    let handle = file.as_raw_handle().cast();
    // SAFETY: `handle` is live and `current` is a correctly sized writable structure.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileBasicInfo,
            (&mut current as *mut FILE_BASIC_INFO).cast(),
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        let error = std::io::Error::last_os_error();
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "windows-backup-v1",
                "basic-metadata",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to inspect Windows basic metadata",
            )
            .for_restore(options.restore_policy, 4)
            .with_native_error(&error),
            options,
            "failed to inspect Windows basic metadata",
        );
    }

    let mut restored = current;
    if let Some(value) = creation_time {
        restored.CreationTime = value;
    }
    if let Some(value) = access_time {
        restored.LastAccessTime = value;
    }
    if let Some(value) = write_time {
        restored.LastWriteTime = value;
    }
    if let Some(value) = change_time {
        restored.ChangeTime = value;
    }
    if let Some(desired) = desired_attributes {
        let unsupported = desired & !(WINDOWS_ESSENTIAL_SETTABLE_ATTRIBUTES | WINDOWS_ESSENTIAL_INTRINSIC_ATTRIBUTES | FILE_ATTRIBUTE_NORMAL);
        if unsupported != 0 {
            let diagnostic = MetadataDiagnostic::new(
                path,
                "windows-backup-v1",
                "file-attributes",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Unsupported,
                format!("unsupported Windows attribute bits were not applied: {unsupported:08x}"),
            )
            .for_restore(options.restore_policy, 4);
            if options.allow_degraded {
                diagnostics.push(diagnostic);
            } else {
                return Err(FormatError::ReaderUnsupported("Windows file attributes contain unsupported bits"));
            }
        }
        let intrinsic_mismatch = (current.FileAttributes ^ desired) & intrinsic_verification_mask;
        if intrinsic_mismatch != 0 {
            record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    "windows-backup-v1",
                    "file-attributes",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    format!("restored Windows object has mismatched intrinsic attributes: {intrinsic_mismatch:08x}"),
                )
                .for_restore(options.restore_policy, 4),
                options,
                "restored Windows object has mismatched intrinsic attributes",
            )?;
        }
        restored.FileAttributes = (current.FileAttributes & !WINDOWS_ESSENTIAL_SETTABLE_ATTRIBUTES) | (desired & WINDOWS_ESSENTIAL_SETTABLE_ATTRIBUTES);
        if restored.FileAttributes & (WINDOWS_ESSENTIAL_SETTABLE_ATTRIBUTES | WINDOWS_ESSENTIAL_INTRINSIC_ATTRIBUTES) == 0 {
            restored.FileAttributes |= FILE_ATTRIBUTE_NORMAL;
        } else {
            restored.FileAttributes &= !FILE_ATTRIBUTE_NORMAL;
        }
    }

    // SAFETY: `handle` is live and `restored` is a correctly sized initialized structure.
    if unsafe {
        SetFileInformationByHandle(
            handle,
            FileBasicInfo,
            (&restored as *const FILE_BASIC_INFO).cast(),
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        let error = std::io::Error::last_os_error();
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "windows-backup-v1",
                "basic-metadata",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to apply Windows basic metadata",
            )
            .for_restore(options.restore_policy, 4)
            .with_native_error(&error),
            options,
            "failed to apply Windows basic metadata",
        );
    }

    let mut actual = FILE_BASIC_INFO::default();
    // SAFETY: `handle` is live and `actual` is a correctly sized writable structure.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileBasicInfo,
            (&mut actual as *mut FILE_BASIC_INFO).cast(),
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
        || actual.CreationTime != restored.CreationTime
        || actual.LastAccessTime != restored.LastAccessTime
        || actual.LastWriteTime != restored.LastWriteTime
        || actual.ChangeTime != restored.ChangeTime
        || actual.FileAttributes & attribute_verification_mask != restored.FileAttributes & attribute_verification_mask
    {
        let error = std::io::Error::last_os_error();
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "windows-backup-v1",
                "basic-metadata",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "Windows basic metadata did not verify after restoration",
            )
            .for_restore(options.restore_policy, 4)
            .with_native_error(&error),
            options,
            "Windows basic metadata did not verify after restoration",
        );
    }
    Ok(())
}

#[cfg(windows)]
fn apply_windows_compression(
    file: &fs::File,
    path: &[u8],
    compressed: bool,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<bool, FormatError> {
    use std::os::windows::io::AsRawHandle;
    use std::ptr;
    use windows_sys::Win32::Storage::FileSystem::{
        FileBasicInfo, GetFileInformationByHandleEx, COMPRESSION_FORMAT_DEFAULT, COMPRESSION_FORMAT_NONE, FILE_BASIC_INFO,
    };
    use windows_sys::Win32::System::Ioctl::FSCTL_SET_COMPRESSION;
    use windows_sys::Win32::System::IO::DeviceIoControl;

    let handle = file.as_raw_handle().cast();
    let mut current = FILE_BASIC_INFO::default();
    // SAFETY: the handle is live and `current` is correctly sized and writable.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileBasicInfo,
            (&mut current as *mut FILE_BASIC_INFO).cast(),
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(FormatError::FilesystemExtractionFailed("failed to inspect Windows compression state"));
    }
    if (current.FileAttributes & FILE_ATTRIBUTE_COMPRESSED != 0) == compressed {
        return Ok(true);
    }
    let mut format = if compressed { COMPRESSION_FORMAT_DEFAULT } else { COMPRESSION_FORMAT_NONE };
    let mut ignored = 0u32;
    // SAFETY: the handle is live, the compression-format input is initialized, and this
    // synchronous FSCTL has no output buffer.
    if unsafe {
        DeviceIoControl(
            handle,
            FSCTL_SET_COMPRESSION,
            (&mut format as *mut u16).cast(),
            std::mem::size_of::<u16>() as u32,
            ptr::null_mut(),
            0,
            &mut ignored,
            ptr::null_mut(),
        )
    } == 0
    {
        let error = std::io::Error::last_os_error();
        record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "windows-backup-v1",
                "compression-layout",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Materialized,
                if compressed {
                    "native Windows compression could not be recreated"
                } else {
                    "native Windows compression could not be removed"
                },
            )
            .for_restore(options.restore_policy, 4)
            .with_native_error(&error),
            options,
            "failed to apply native Windows compression state",
        )?;
        return Ok(false);
    }
    Ok(true)
}

#[cfg(windows)]
fn apply_windows_directory_case_sensitive(
    file: &fs::File,
    path: &[u8],
    metadata: &MemberMetadata,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{FileCaseSensitiveInfo, GetFileInformationByHandleEx, SetFileInformationByHandle, FILE_CASE_SENSITIVE_INFO};
    use windows_sys::Win32::System::SystemServices::FILE_CS_FLAG_CASE_SENSITIVE_DIR;

    let Some(encoded) = metadata.primary_records.get("TZAP.windows.directory-case-sensitive") else {
        return Ok(());
    };
    let desired = match encoded.as_slice() {
        b"0" => 0,
        b"1" => FILE_CS_FLAG_CASE_SENSITIVE_DIR,
        _ => {
            return Err(FormatError::InvalidArchive("invalid Windows directory case-sensitivity state"));
        }
    };
    let handle = file.as_raw_handle().cast();
    let mut current = FILE_CASE_SENSITIVE_INFO::default();
    // SAFETY: the handle is live and `current` is correctly sized and writable.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileCaseSensitiveInfo,
            (&mut current as *mut FILE_CASE_SENSITIVE_INFO).cast(),
            std::mem::size_of::<FILE_CASE_SENSITIVE_INFO>() as u32,
        )
    } == 0
    {
        let error = std::io::Error::last_os_error();
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "windows-backup-v1",
                "directory-case-sensitive",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to inspect Windows directory case-sensitivity state",
            )
            .for_restore(options.restore_policy, 4)
            .with_native_error(&error),
            options,
            "failed to inspect Windows directory case-sensitivity state",
        );
    }
    if current.Flags == desired {
        return Ok(());
    }
    if options.restore_policy != RestorePolicy::System || !options.system_authorized {
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "windows-backup-v1",
                "directory-case-sensitive",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Unsupported,
                "changing Windows directory case-sensitivity requires authorized System restore",
            )
            .for_restore(options.restore_policy, 4),
            options,
            "Windows directory case-sensitivity state requires authorized System restore",
        );
    }
    let updated = FILE_CASE_SENSITIVE_INFO { Flags: desired };
    // SAFETY: the handle is live and `updated` is a correctly sized initialized structure.
    if unsafe {
        SetFileInformationByHandle(
            handle,
            FileCaseSensitiveInfo,
            (&updated as *const FILE_CASE_SENSITIVE_INFO).cast(),
            std::mem::size_of::<FILE_CASE_SENSITIVE_INFO>() as u32,
        )
    } == 0
    {
        let error = std::io::Error::last_os_error();
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "windows-backup-v1",
                "directory-case-sensitive",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to apply Windows directory case-sensitivity state",
            )
            .for_restore(options.restore_policy, 4)
            .with_native_error(&error),
            options,
            "failed to apply Windows directory case-sensitivity state",
        );
    }
    let mut actual = FILE_CASE_SENSITIVE_INFO::default();
    // SAFETY: the handle is live and `actual` is correctly sized and writable.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileCaseSensitiveInfo,
            (&mut actual as *mut FILE_CASE_SENSITIVE_INFO).cast(),
            std::mem::size_of::<FILE_CASE_SENSITIVE_INFO>() as u32,
        )
    } == 0
        || actual.Flags != desired
    {
        let error = std::io::Error::last_os_error();
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "windows-backup-v1",
                "directory-case-sensitive",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "Windows directory case-sensitivity state did not verify after restoration",
            )
            .for_restore(options.restore_policy, 4)
            .with_native_error(&error),
            options,
            "Windows directory case-sensitivity state did not verify after restoration",
        );
    }
    Ok(())
}

#[cfg(not(windows))]
pub(crate) fn apply_windows_basic_metadata(
    _file: &fs::File,
    _path: &[u8],
    _metadata: &MemberMetadata,
    _options: SafeExtractionOptions,
    _diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn apply_linux_inode_flags(
    file: &fs::File,
    path: &[u8],
    metadata: &MemberMetadata,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    if !source_os_matches_current_host(&metadata.declaration.source_os) {
        return Ok(());
    }
    let Some(encoded) = metadata.primary_records.get("TZAP.linux.fsflags") else {
        return Ok(());
    };
    let text = std::str::from_utf8(encoded).map_err(|_| FormatError::InvalidArchive("Linux inode flags are not ASCII"))?;
    let desired = u64::from_str_radix(text, 16).map_err(|_| FormatError::InvalidArchive("Linux inode flags are invalid"))?;
    let no_change = desired & u64::from(linux_raw_sys::general::FS_IMMUTABLE_FL | linux_raw_sys::general::FS_APPEND_FL) != 0;
    if !matches!(options.restore_policy, RestorePolicy::SameOs | RestorePolicy::System)
        || (no_change && !(options.restore_policy == RestorePolicy::System && options.system_authorized))
    {
        return Ok(());
    }
    let apply_result = (|| -> std::io::Result<()> {
        if desired & !LINUX_KNOWN_FSFLAGS != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "archive contains unrecognized Linux inode flag bits",
            ));
        }
        let mut current: libc::c_long = 0;
        // SAFETY: these ioctls read/write one c_long through valid pointers and
        // operate on the live descriptor owned by `file`.
        if unsafe { libc::ioctl(file.as_raw_fd(), libc::FS_IOC_GETFLAGS, &mut current) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let modifiable = u64::from(linux_raw_sys::general::FS_FL_USER_MODIFIABLE);
        let mut restored = ((current as u64 & !modifiable) | (desired & modifiable)) as libc::c_long;
        // SAFETY: as above, SETFLAGS reads the initialized c_long value.
        if unsafe { libc::ioctl(file.as_raw_fd(), libc::FS_IOC_SETFLAGS, &mut restored) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut actual: libc::c_long = 0;
        if unsafe { libc::ioctl(file.as_raw_fd(), libc::FS_IOC_GETFLAGS, &mut actual) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if actual as u64 != desired {
            return Err(std::io::Error::other(format!(
                "Linux inode flags did not verify: wanted {desired:016x}, got {:016x}",
                actual as u64
            )));
        }
        Ok(())
    })();
    if apply_result.is_ok() {
        return Ok(());
    }
    let error = apply_result.unwrap_err();
    record_metadata_application_failure(
        diagnostics,
        MetadataDiagnostic::new(
            path,
            "linux-backup-v1",
            "inode-flags",
            MetadataOperation::Restore,
            MetadataDiagnosticStatus::Failed,
            "failed to apply Linux inode flags",
        )
        .for_restore(options.restore_policy, 4)
        .with_native_error(&error),
        options,
        "failed to apply Linux inode flags",
    )
}

#[cfg(target_os = "linux")]
pub(crate) fn apply_linux_project_id(
    file: &fs::File,
    path: &[u8],
    metadata: &MemberMetadata,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    if metadata.declaration.source_os != "linux" || options.restore_policy != RestorePolicy::System || !options.system_authorized {
        return Ok(());
    }
    let Some(encoded) = metadata.primary_records.get("TZAP.linux.project-id") else {
        return Ok(());
    };
    let desired = std::str::from_utf8(encoded)
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or(FormatError::InvalidArchive("Linux project ID is invalid"))?;
    // fsxattr consists only of integer and reserved-byte fields; zero is valid initialization.
    let mut attributes: linux_raw_sys::general::fsxattr = unsafe { std::mem::zeroed() };
    let get_result = unsafe { libc::ioctl(file.as_raw_fd(), linux_raw_sys::ioctl::FS_IOC_FSGETXATTR as libc::Ioctl, &mut attributes) };
    if get_result == 0 {
        attributes.fsx_projid = desired;
        if unsafe { libc::ioctl(file.as_raw_fd(), linux_raw_sys::ioctl::FS_IOC_FSSETXATTR as libc::Ioctl, &attributes) } == 0 {
            let mut actual: linux_raw_sys::general::fsxattr = unsafe { std::mem::zeroed() };
            if unsafe { libc::ioctl(file.as_raw_fd(), linux_raw_sys::ioctl::FS_IOC_FSGETXATTR as libc::Ioctl, &mut actual) } == 0
                && actual.fsx_projid == desired
            {
                return Ok(());
            }
        }
    }
    let error = std::io::Error::last_os_error();
    record_metadata_application_failure(
        diagnostics,
        MetadataDiagnostic::new(
            path,
            "linux-backup-v1",
            "project-id",
            MetadataOperation::Restore,
            MetadataDiagnosticStatus::Failed,
            "failed to apply Linux project ID",
        )
        .for_restore(options.restore_policy, 4)
        .with_native_error(&error),
        options,
        "failed to apply Linux project ID",
    )
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn apply_linux_project_id(
    _file: &fs::File,
    _path: &[u8],
    _metadata: &MemberMetadata,
    _options: SafeExtractionOptions,
    _diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn apply_linux_inode_flags(
    _file: &fs::File,
    _path: &[u8],
    _metadata: &MemberMetadata,
    _options: SafeExtractionOptions,
    _diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_regular_file_posix_acl(
    file: &fs::File,
    path: &[u8],
    metadata: &MemberMetadata,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    use xattr::FileExt as _;

    if !source_os_matches_current_host(&metadata.declaration.source_os) || !matches!(options.restore_policy, RestorePolicy::SameOs | RestorePolicy::System) {
        return Ok(());
    }
    for (key, name) in [
        ("SCHILY.acl.access", "system.posix_acl_access"),
        ("SCHILY.acl.default", "system.posix_acl_default"),
    ] {
        let Some(text) = metadata.primary_records.get(key) else {
            continue;
        };
        let value = schily_posix_acl_to_linux_xattr(text)?;
        if let Err(error) = file.set_xattr(name, &value) {
            record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    "posix-backup-v1",
                    "posix-acl",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    "failed to apply POSIX ACL",
                )
                .for_restore(options.restore_policy, 4)
                .with_native_error(&error),
                options,
                "failed to apply POSIX ACL",
            )?;
            continue;
        }
        if file.get_xattr(name).ok().flatten().as_deref() != Some(value.as_slice()) {
            record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    "posix-backup-v1",
                    "posix-acl",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    "POSIX ACL did not verify after restoration",
                )
                .for_restore(options.restore_policy, 4),
                options,
                "POSIX ACL did not verify after restoration",
            )?;
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn apply_regular_file_posix_acl(
    _file: &fs::File,
    _path: &[u8],
    _metadata: &MemberMetadata,
    _options: SafeExtractionOptions,
    _diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    Ok(())
}

#[cfg(unix)]
fn apply_regular_file_xattrs(
    file: &fs::File,
    path: &[u8],
    metadata: &MemberMetadata,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use xattr::FileExt as _;

    if !source_os_matches_current_host(&metadata.declaration.source_os) || !matches!(options.restore_policy, RestorePolicy::SameOs | RestorePolicy::System) {
        return Ok(());
    }
    for (key, encoded) in metadata.primary_records.iter().filter(|(key, _)| key.starts_with("LIBARCHIVE.xattr.")) {
        let name = decode_percent_name(&key.as_bytes()["LIBARCHIVE.xattr.".len()..])?;
        let system = system_xattr_name(&name, &metadata.declaration.source_os);
        if system && !(options.restore_policy == RestorePolicy::System && options.system_authorized) {
            continue;
        }
        let value = canonical_base64_decode(encoded)?;
        if let Err(error) = file.set_xattr(OsStr::from_bytes(&name), &value) {
            record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    if system && metadata.declaration.source_os == "macos" {
                        "macos-backup-v1"
                    } else if system {
                        "linux-backup-v1"
                    } else {
                        "posix-backup-v1"
                    },
                    "extended-attribute",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    "failed to apply extended attribute",
                )
                .for_restore(options.restore_policy, 4)
                .with_native_error(&error),
                options,
                "failed to apply extended attribute",
            )?;
            continue;
        }
        if file.get_xattr(OsStr::from_bytes(&name)).ok().flatten().as_deref() != Some(value.as_slice()) {
            record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    if system && metadata.declaration.source_os == "macos" {
                        "macos-backup-v1"
                    } else if system {
                        "linux-backup-v1"
                    } else {
                        "posix-backup-v1"
                    },
                    "extended-attribute",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    "extended attribute did not verify after restoration",
                )
                .for_restore(options.restore_policy, 4),
                options,
                "extended attribute did not verify after restoration",
            )?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn apply_regular_file_xattrs(
    _file: &fs::File,
    _path: &[u8],
    _metadata: &MemberMetadata,
    _options: SafeExtractionOptions,
    _diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    Ok(())
}

pub(crate) fn system_xattr_name(name: &[u8], source_os: &str) -> bool {
    name.starts_with(b"security.")
        || name.starts_with(b"trusted.")
        || name.starts_with(b"system.")
        || (source_os == "linux" && !name.starts_with(b"user.") && !name.starts_with(b"com.apple."))
}

#[cfg(unix)]
fn apply_regular_file_ownership(
    file: &fs::File,
    path: &[u8],
    uid: Option<u64>,
    gid: Option<u64>,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    if options.restore_policy != RestorePolicy::System || !options.system_authorized {
        return Ok(());
    }
    let (Some(uid), Some(gid)) = (uid, gid) else {
        return Ok(());
    };
    let uid = libc::uid_t::try_from(uid).map_err(|_| FormatError::FilesystemExtractionFailed("archived UID exceeds host uid_t"))?;
    let gid = libc::gid_t::try_from(gid).map_err(|_| FormatError::FilesystemExtractionFailed("archived GID exceeds host gid_t"))?;

    // SAFETY: fchown only observes the valid descriptor owned by `file`; both
    // numeric arguments were range-checked for this host ABI.
    if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
        let error = std::io::Error::last_os_error();
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "portable-v1",
                "numeric-ownership",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to apply numeric ownership",
            )
            .for_restore(options.restore_policy, 4)
            .with_native_error(&error),
            options,
            "failed to apply numeric ownership",
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn apply_regular_file_ownership(
    _file: &fs::File,
    _path: &[u8],
    _uid: Option<u64>,
    _gid: Option<u64>,
    _options: SafeExtractionOptions,
    _diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    Ok(())
}

#[cfg(windows)]
fn apply_regular_file_attributes(
    file: &fs::File,
    path: &[u8],
    attributes: Option<u32>,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    let Some(attributes) = attributes else {
        return Ok(());
    };
    let metadata = match file.metadata() {
        Ok(metadata) => metadata,
        Err(error) => {
            return record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    "portable-v1",
                    "portable-attributes",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    "failed to inspect file before applying readonly attribute projection",
                )
                .for_restore(options.restore_policy, 4)
                .with_native_error(&error),
                options,
                "failed to inspect file before applying readonly attribute projection",
            );
        }
    };
    let mut permissions = metadata.permissions();
    permissions.set_readonly(attributes & 1 != 0);
    if let Err(error) = file.set_permissions(permissions) {
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "portable-v1",
                "portable-attributes",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to apply readonly attribute projection",
            )
            .for_restore(options.restore_policy, 4)
            .with_native_error(&error),
            options,
            "failed to apply readonly attribute projection",
        );
    }
    Ok(())
}

#[cfg(not(windows))]
fn apply_regular_file_attributes(
    _file: &fs::File,
    _path: &[u8],
    _attributes: Option<u32>,
    _options: SafeExtractionOptions,
    _diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    Ok(())
}

#[cfg(unix)]
fn apply_regular_file_mode(
    file: &fs::File,
    path: &[u8],
    mode: u32,
    _mode_origin_native: bool,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    match file.metadata() {
        Ok(metadata) => {
            let mut permissions = metadata.permissions();
            permissions.set_mode(mode & 0o7777);
            if let Err(error) = file.set_permissions(permissions) {
                return record_metadata_application_failure(
                    diagnostics,
                    MetadataDiagnostic::new(
                        path,
                        "portable-v1",
                        "mode",
                        MetadataOperation::Restore,
                        MetadataDiagnosticStatus::Failed,
                        "failed to apply mode metadata",
                    )
                    .for_restore(options.restore_policy, 4)
                    .with_native_error(&error),
                    options,
                    "failed to apply mode metadata",
                );
            }
        }
        Err(error) => {
            return record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    "portable-v1",
                    "mode",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    "failed to inspect file before applying mode metadata",
                )
                .for_restore(options.restore_policy, 4)
                .with_native_error(&error),
                options,
                "failed to inspect file before applying mode metadata",
            );
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn apply_regular_file_mode(
    file: &fs::File,
    path: &[u8],
    mode: u32,
    mode_origin_native: bool,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    match file.metadata() {
        Ok(metadata) => {
            let mut permissions = metadata.permissions();
            permissions.set_readonly(mode & 0o222 == 0);
            if let Err(error) = file.set_permissions(permissions) {
                return record_metadata_application_failure(
                    diagnostics,
                    MetadataDiagnostic::new(
                        path,
                        "portable-v1",
                        "mode",
                        MetadataOperation::Restore,
                        MetadataDiagnosticStatus::Failed,
                        "failed to apply mode metadata",
                    )
                    .for_restore(options.restore_policy, 4)
                    .with_native_error(&error),
                    options,
                    "failed to apply mode metadata",
                );
            }
            if mode_origin_native && mode & 0o777 != 0o444 && mode & 0o777 != 0o666 {
                let diagnostic = MetadataDiagnostic::new(
                    path,
                    "portable-v1",
                    "mode",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Partial,
                    "mode metadata was only partially applied on this platform",
                )
                .for_restore(options.restore_policy, 4);
                if options.allow_degraded {
                    diagnostics.push(diagnostic);
                } else {
                    return Err(FormatError::FilesystemExtractionFailed(
                        "portable mode cannot be represented exactly on this host",
                    ));
                }
            }
        }
        Err(error) => {
            return record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    "portable-v1",
                    "mode",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    "failed to inspect file before applying mode metadata",
                )
                .for_restore(options.restore_policy, 4)
                .with_native_error(&error),
                options,
                "failed to inspect file before applying mode metadata",
            );
        }
    }
    Ok(())
}

fn apply_regular_file_mtime(
    file: &fs::File,
    path: &[u8],
    (seconds, nanoseconds): (i64, u32),
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    let duration = Duration::new(seconds.unsigned_abs(), nanoseconds);
    let modified = if seconds < 0 {
        SystemTime::UNIX_EPOCH.checked_sub(duration)
    } else {
        SystemTime::UNIX_EPOCH.checked_add(duration)
    };
    let Some(modified) = modified else {
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "portable-v1",
                "mtime",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to apply mtime metadata",
            )
            .for_restore(options.restore_policy, 4),
            options,
            "mtime cannot be represented on this host",
        );
    };
    let times = fs::FileTimes::new().set_modified(modified);
    if let Err(error) = file.set_times(times) {
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "portable-v1",
                "mtime",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to apply mtime metadata",
            )
            .for_restore(options.restore_policy, 4)
            .with_native_error(&error),
            options,
            "failed to apply mtime metadata",
        );
    }
    Ok(())
}

pub(crate) fn record_metadata_application_failure(
    diagnostics: &mut Vec<MetadataDiagnostic>,
    diagnostic: MetadataDiagnostic,
    options: SafeExtractionOptions,
    strict_error: &'static str,
) -> Result<(), FormatError> {
    if options.allow_degraded {
        diagnostics.push(diagnostic);
        Ok(())
    } else {
        Err(FormatError::FilesystemExtractionFailed(strict_error))
    }
}
