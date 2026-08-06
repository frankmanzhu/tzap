use super::*;

use std::io::{self};
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::json;
use tzap_core::format::{FormatError, FORMAT_VERSION, READER_MAX_SUPPORTED_VOLUME_FORMAT_REV};
use tzap_core::reader::{ArchiveEntry, ArchiveIndexEntry};
use tzap_core::{
    ArchiveWriteError, ExtractError, MetadataDiagnostic, MetadataVerificationReport, RestorePolicy,
    TarEntryKind, WriterTimings,
};

use crate::commands::UsageError;

pub(crate) fn emit_trust_info(json_output: bool) -> io::Result<()> {
    let build_profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    if json_output {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "official_tzap_root_certificate_sha256": OFFICIAL_TZAP_ROOT_CERT_SHA256,
                "official_tzap_root_source": "embedded",
                "package": env!("CARGO_PKG_NAME"),
                "version": env!("CARGO_PKG_VERSION"),
                "repository": env!("CARGO_PKG_REPOSITORY"),
                "build_profile": build_profile,
                "target_os": std::env::consts::OS,
                "target_arch": std::env::consts::ARCH,
            }))
            .expect("trust-info JSON is serializable")
        );
        return Ok(());
    }
    println!("tzap {}", env!("CARGO_PKG_VERSION"));
    println!("repository: {}", env!("CARGO_PKG_REPOSITORY"));
    println!("build-profile: {build_profile}");
    println!(
        "target: {}-{}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    println!("official-tzap-root-source: embedded");
    println!("official-tzap-root-sha256: {OFFICIAL_TZAP_ROOT_CERT_SHA256}");
    Ok(())
}

pub(crate) fn emit_success_summary(quiet: bool, message: &str) -> io::Result<()> {
    if quiet {
        return Ok(());
    }
    eprintln!("{message}");
    Ok(())
}

pub(crate) fn emit_create_timing_report(
    scan_inputs: Duration,
    read_inputs: Duration,
    core_writer: Duration,
    write_outputs: Duration,
    total: Duration,
    writer: WriterTimings,
) -> io::Result<()> {
    emit_create_timing_report_with_labels(
        scan_inputs,
        read_inputs,
        core_writer,
        write_outputs,
        total,
        writer,
        "core writer",
        "write outputs",
    )
}

pub(crate) fn emit_sink_backed_create_timing_report(
    scan_inputs: Duration,
    read_inputs: Duration,
    core_writer: Duration,
    write_outputs: Duration,
    total: Duration,
    writer: WriterTimings,
) -> io::Result<()> {
    emit_create_timing_report_with_labels(
        scan_inputs,
        read_inputs,
        core_writer,
        write_outputs,
        total,
        writer,
        "core writer + archive output",
        "post-writer outputs",
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn emit_create_timing_report_with_labels(
    scan_inputs: Duration,
    read_inputs: Duration,
    core_writer: Duration,
    write_outputs: Duration,
    total: Duration,
    writer: WriterTimings,
    core_writer_label: &str,
    write_outputs_label: &str,
) -> io::Result<()> {
    let accounted = scan_inputs + read_inputs + core_writer + write_outputs;
    let other_cli = total.saturating_sub(accounted);
    eprintln!("create timings:");
    eprintln!("  scan inputs: {}", format_duration(scan_inputs));
    eprintln!("  read inputs: {}", format_duration(read_inputs));
    eprintln!("  {core_writer_label}: {}", format_duration(core_writer));
    eprintln!(
        "  {write_outputs_label}: {}",
        format_duration(write_outputs)
    );
    eprintln!("  other CLI: {}", format_duration(other_cli));
    eprintln!("  total: {}", format_duration(total));
    eprintln!("writer timings:");
    eprintln!("  plan payload: {}", format_duration(writer.plan_payload));
    eprintln!("  plan metadata: {}", format_duration(writer.plan_metadata));
    eprintln!("  emit payload: {}", format_duration(writer.emit_payload));
    eprintln!("  emit metadata: {}", format_duration(writer.emit_metadata));
    eprintln!("  total: {}", format_duration(writer.total));
    Ok(())
}

pub(crate) fn format_duration(duration: Duration) -> String {
    format!("{:.3}s", duration.as_secs_f64())
}

pub(crate) fn emit_success_stdout(quiet: bool, message: &str) -> io::Result<()> {
    if quiet {
        return Ok(());
    }
    println!("{message}");
    Ok(())
}

pub(crate) fn metadata_diagnostic_line(path: &str, diagnostic: &MetadataDiagnostic) -> String {
    let mut line = format!(
        "tzap: degraded-metadata: {}: {}: {}: {:?}/{:?}: {}",
        path,
        diagnostic.profile,
        diagnostic.metadata_class,
        diagnostic.operation,
        diagnostic.status,
        diagnostic.message
    );
    if let (Some(policy), Some(phase)) = (diagnostic.restore_policy, diagnostic.restore_phase) {
        line.push_str(&format!(" [policy={policy:?} phase={phase}]"));
    }
    if let Some(error) = &diagnostic.native_host_error {
        line.push_str(&format!(" [native-error={error}]"));
    }
    if let (Some(staged), Some(committed)) = (diagnostic.bytes_staged, diagnostic.bytes_committed) {
        line.push_str(&format!(" [staged={staged} committed={committed}]"));
    }
    line
}

pub(crate) fn emit_member_metadata_diagnostics(
    quiet: bool,
    path: &str,
    diagnostics: &[MetadataDiagnostic],
) -> io::Result<()> {
    if quiet {
        return Ok(());
    }
    for diagnostic in diagnostics {
        eprintln!("{}", metadata_diagnostic_line(path, diagnostic));
    }
    Ok(())
}

pub(crate) fn metadata_diagnostic_lines_for_entries(entries: &[ArchiveEntry]) -> Vec<String> {
    entries
        .iter()
        .flat_map(|entry| {
            entry
                .diagnostics
                .iter()
                .map(|diagnostic| metadata_diagnostic_line(&entry.path, diagnostic))
        })
        .collect()
}

#[cfg(test)]
pub(crate) fn metadata_diagnostic_lines_for_paths(
    entries: &[ArchiveEntry],
    paths: &[String],
) -> Vec<String> {
    paths
        .iter()
        .filter_map(|path| entries.iter().find(|entry| entry.path == *path))
        .flat_map(|entry| {
            entry
                .diagnostics
                .iter()
                .map(|diagnostic| metadata_diagnostic_line(&entry.path, diagnostic))
        })
        .collect()
}

pub(crate) fn emit_entry_metadata_diagnostics(
    quiet: bool,
    entries: &[ArchiveEntry],
) -> io::Result<()> {
    if quiet {
        return Ok(());
    }
    for line in metadata_diagnostic_lines_for_entries(entries) {
        eprintln!("{line}");
    }
    Ok(())
}

pub(crate) fn restore_policy_label(policy: RestorePolicy) -> &'static str {
    match policy {
        RestorePolicy::Content => "content",
        RestorePolicy::Portable => "portable",
        RestorePolicy::SameOs => "same-os",
        RestorePolicy::System => "system",
    }
}

pub(crate) fn metadata_verification_json(report: &MetadataVerificationReport) -> serde_json::Value {
    json!({
        "capture_complete": report.all_capture_complete,
        "full_fidelity_possible": report.full_fidelity_possible,
        "profiles_present": report.profiles_present,
        "auxiliary_kinds_present": report.auxiliary_kinds_present,
        "entries": report.entries.iter().map(|entry| json!({
            "path": String::from_utf8_lossy(&entry.path),
            "capture_status": format!("{:?}", entry.capture_status).to_ascii_lowercase(),
            "required_profiles": entry.required_profiles,
            "optional_profiles": entry.optional_profiles,
            "auxiliary_kinds": entry.auxiliary_kinds,
            "full_fidelity_possible": entry.full_fidelity_possible,
            "policy_capabilities": entry.policy_capabilities.iter().map(|capability| json!({
                "policy": restore_policy_label(capability.policy),
                "policy_complete": capability.policy_complete,
                "degraded_restore_available": capability.degraded_restore_available,
                "reason": capability.reason,
            })).collect::<Vec<_>>(),
            "diagnostics": entry.diagnostics.iter().map(|diagnostic| json!({
                "path": String::from_utf8_lossy(&diagnostic.path),
                "profile": diagnostic.profile,
                "metadata_class": diagnostic.metadata_class,
                "operation": format!("{:?}", diagnostic.operation).to_ascii_lowercase(),
                "status": format!("{:?}", diagnostic.status).to_ascii_lowercase(),
                "reason": diagnostic.message,
                "restore_policy": diagnostic.restore_policy.map(restore_policy_label),
                "restore_phase": diagnostic.restore_phase,
                "native_host_error": diagnostic.native_host_error,
                "bytes_staged": diagnostic.bytes_staged,
                "bytes_committed": diagnostic.bytes_committed,
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    })
}

pub(crate) fn metadata_verification_stdout_lines(
    report: &MetadataVerificationReport,
) -> Vec<String> {
    let mut lines = vec![format!(
        "metadata: capture={} full-fidelity={} profiles=[{}] auxiliary-kinds=[{}]",
        if report.all_capture_complete {
            "complete"
        } else {
            "partial"
        },
        if report.full_fidelity_possible {
            "possible"
        } else {
            "not-possible"
        },
        report.profiles_present.join(","),
        report.auxiliary_kinds_present.join(","),
    )];
    for policy in [
        RestorePolicy::Content,
        RestorePolicy::Portable,
        RestorePolicy::SameOs,
        RestorePolicy::System,
    ] {
        let complete = report
            .entries
            .iter()
            .filter(|entry| {
                entry
                    .policy_capabilities
                    .iter()
                    .any(|capability| capability.policy == policy && capability.policy_complete)
            })
            .count();
        lines.push(format!(
            "metadata-policy {}: {complete}/{} entries policy-complete",
            restore_policy_label(policy),
            report.entries.len()
        ));
    }
    lines
}

pub(crate) fn emit_metadata_verification_stdout(
    quiet: bool,
    report: &MetadataVerificationReport,
) -> io::Result<()> {
    if quiet {
        return Ok(());
    }
    for line in metadata_verification_stdout_lines(report) {
        println!("{line}");
    }
    Ok(())
}

pub(crate) fn archive_index_entry_json(entry: &ArchiveIndexEntry) -> serde_json::Value {
    json!({
        "path": &entry.path,
        "name": &entry.name,
        "size": entry.file_data_size,
        "flags": entry.flags,
        "path_hash": encode_hex(&entry.path_hash),
        "tar_member_group_size": entry.tar_member_group_size,
        "first_frame_index": entry.first_frame_index,
        "frame_count": entry.frame_count,
        "offset_in_first_frame_plaintext": entry.offset_in_first_frame_plaintext,
        "compressed_size": entry.layout.compressed_size,
        "layout": {
            "decompressed_frame_size": entry.layout.decompressed_frame_size,
            "envelope_count": entry.layout.envelope_count,
            "first_envelope_index": entry.layout.first_envelope_index,
            "last_envelope_index": entry.layout.last_envelope_index,
            "first_payload_block_index": entry.layout.first_payload_block_index,
            "payload_data_block_count": entry.layout.payload_data_block_count,
            "payload_parity_block_count": entry.layout.payload_parity_block_count,
            "payload_encrypted_size": entry.layout.payload_encrypted_size,
        },
    })
}

pub(crate) fn archive_entry_kind_label(kind: TarEntryKind) -> &'static str {
    match kind {
        TarEntryKind::Regular => "file",
        TarEntryKind::Directory => "directory",
        TarEntryKind::Symlink => "symlink",
        TarEntryKind::Hardlink => "hardlink",
        TarEntryKind::CharacterDevice => "character-device",
        TarEntryKind::BlockDevice => "block-device",
        TarEntryKind::Fifo => "fifo",
    }
}

pub(crate) fn emit_verify_json_error(
    archives: &[String],
    volume_count: Option<u64>,
    file_count: Option<u64>,
    err: &anyhow::Error,
) -> Result<()> {
    let diagnostic = classify_error(err);
    if diagnostic.label == "unsupported-revision" {
        let payload = json!({
            "ok": false,
            "archives": archives,
            "error": unsupported_revision_error_json(err, diagnostic.action),
        });
        println!(
            "{}",
            serde_json::to_string(&payload)
                .context("failed to encode verify error output as JSON")?
        );
        return Ok(());
    }
    let mut payload = json!({
        "ok": false,
        "archives": archives,
        "error": {
            "label": diagnostic.label,
            "action": diagnostic.action,
            "message": err.to_string(),
        },
    });
    if let Some(volume_count) = volume_count {
        payload["volume_count"] = json!(volume_count);
    }
    if let Some(file_count) = file_count {
        payload["file_count"] = json!(file_count);
    }
    println!(
        "{}",
        serde_json::to_string(&payload).context("failed to encode verify error output as JSON")?
    );
    Ok(())
}

pub(crate) fn unsupported_revision_error_json(
    err: &anyhow::Error,
    action: &'static str,
) -> serde_json::Value {
    for cause in err.chain() {
        if let Some(format) = cause.downcast_ref::<FormatError>() {
            match format {
                FormatError::UnsupportedFormatVersion(observed_format_version) => {
                    return json!({
                    "label": "unsupported-revision",
                    "observed": {
                        "format_version": observed_format_version,
                    },
                    "supported": {
                        "format_version": FORMAT_VERSION,
                        "max_volume_format_rev": READER_MAX_SUPPORTED_VOLUME_FORMAT_REV,
                    },
                    "action": action,
                    });
                }
                FormatError::UnsupportedVolumeFormatRevision {
                    format_version,
                    volume_format_rev,
                    reader_max_supported_revision,
                } => {
                    return json!({
                    "label": "unsupported-revision",
                    "observed": {
                        "format_version": format_version,
                        "volume_format_rev": volume_format_rev,
                    },
                    "supported": {
                        "format_version": FORMAT_VERSION,
                        "max_volume_format_rev": reader_max_supported_revision,
                    },
                    "action": action,
                    });
                }
                _ => {}
            }
        }
    }
    json!({
        "label": "unsupported-revision",
        "observed": null,
        "supported": {
            "format_version": FORMAT_VERSION,
            "max_volume_format_rev": READER_MAX_SUPPORTED_VOLUME_FORMAT_REV,
        },
        "action": action,
    })
}

// ---------------------------------------------------------------------------
// Error classification: stable CLI labels, exit codes, and user actions.
// ---------------------------------------------------------------------------

pub(crate) const EXIT_USAGE: u8 = 2;
pub(crate) const EXIT_IO: u8 = 3;
pub(crate) const EXIT_WRONG_KEY: u8 = 10;
pub(crate) const EXIT_CORRUPT_ARCHIVE: u8 = 11;
pub(crate) const EXIT_UNSUPPORTED_REVISION: u8 = 12;
pub(crate) const EXIT_UNSAFE_PATH: u8 = 13;
pub(crate) const EXIT_MISSING_BOOTSTRAP: u8 = 14;
pub(crate) const EXIT_UNSUPPORTED_FEATURE: u8 = 16;
pub(crate) const EXIT_GENERIC: u8 = 1;

#[derive(Debug, Clone, Copy)]
pub(crate) struct Diagnostic {
    pub(crate) label: &'static str,
    pub(crate) exit_code: u8,
    pub(crate) action: &'static str,
}

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = std::fmt::Write::write_fmt(&mut output, format_args!("{:02x}", byte));
    }
    output
}

pub(crate) fn classify_error(err: &anyhow::Error) -> Diagnostic {
    // anyhow's `with_context` wraps the original error in a ContextError; the
    // chain only exposes that wrapper and its source as `&dyn Error`, so a
    // downcast on a chain element cannot reach the UsageError stored as the
    // context value. `anyhow::Error::downcast_ref` special-cases the context
    // wrapper, so checking the outer error first is what actually finds
    // UsageErrors attached with `with_context` (e.g. invalid stdin-size).
    if err.downcast_ref::<UsageError>().is_some() {
        return Diagnostic {
            label: "invalid-arguments",
            exit_code: EXIT_USAGE,
            action: "check command arguments",
        };
    }
    for cause in err.chain() {
        if cause.downcast_ref::<UsageError>().is_some() {
            return Diagnostic {
                label: "invalid-arguments",
                exit_code: EXIT_USAGE,
                action: "check command arguments",
            };
        }
        if let Some(write_error) = cause.downcast_ref::<ArchiveWriteError>() {
            return match write_error {
                ArchiveWriteError::Format(format) => classify_format_error(format),
                ArchiveWriteError::Io(io_error) => classify_io_error(io_error),
            };
        }
        if let Some(extract_error) = cause.downcast_ref::<ExtractError>() {
            return match extract_error {
                ExtractError::Format(format) => classify_format_error(format),
                ExtractError::Output(io_error) => classify_io_error(io_error),
            };
        }
        if let Some(format) = cause.downcast_ref::<FormatError>() {
            return classify_format_error(format);
        }
        if let Some(io_error) = cause.downcast_ref::<io::Error>() {
            return classify_io_error(io_error);
        }
    }
    Diagnostic {
        label: "error",
        exit_code: EXIT_GENERIC,
        action: "",
    }
}

pub(crate) fn classify_io_error(err: &io::Error) -> Diagnostic {
    match err.kind() {
        io::ErrorKind::PermissionDenied
        | io::ErrorKind::NotFound
        | io::ErrorKind::AlreadyExists => Diagnostic {
            label: "io-error",
            exit_code: EXIT_IO,
            action: "check file paths and permissions",
        },
        _ => Diagnostic {
            label: "io-error",
            exit_code: EXIT_IO,
            action: "check filesystem state",
        },
    }
}

pub(crate) fn classify_format_error(err: &FormatError) -> Diagnostic {
    match err {
        FormatError::UnsupportedFormatVersion(_)
        | FormatError::UnsupportedVolumeFormatRevision { .. }
        | FormatError::UnknownCompressionAlgo(_)
        | FormatError::UnknownAeadAlgo(_)
        | FormatError::UnknownFecAlgo(_)
        | FormatError::UnknownKdfAlgo(_)
        | FormatError::UnsupportedCompression(_)
        | FormatError::UnsupportedFec(_)
        | FormatError::UnsupportedBootstrapSidecarVersion(_) => Diagnostic {
            label: "unsupported-revision",
            exit_code: EXIT_UNSUPPORTED_REVISION,
            action: "upgrade tzap or use a reader that supports this archive revision",
        },
        FormatError::BadMagic {
            structure: "VolumeHeader",
        }
        | FormatError::BadMagic {
            structure: "VolumeTrailer",
        }
        | FormatError::BadMagic {
            structure: "ManifestFooter",
        } => Diagnostic {
            label: "corrupt-header",
            exit_code: EXIT_CORRUPT_ARCHIVE,
            action: "verify the archive header/trailer bytes and source file path",
        },
        FormatError::HmacMismatch {
            structure: "CryptoHeader",
        }
        | FormatError::KeyMaterialMismatch
        | FormatError::InvalidRawMasterKeyLength => Diagnostic {
            label: "wrong-key",
            exit_code: EXIT_WRONG_KEY,
            action: "confirm the archive key source (passphrase/raw key/recipient key)",
        },
        FormatError::IntegrityDigestMismatch { .. } => Diagnostic {
            label: "corrupt-archive",
            exit_code: EXIT_CORRUPT_ARCHIVE,
            action: "verify the archive bytes and source file path",
        },
        FormatError::FecTooFewAvailableShards => Diagnostic {
            label: "missing-volume",
            exit_code: EXIT_CORRUPT_ARCHIVE,
            action: "add the missing archive volume(s) or confirm volume-loss tolerance",
        },
        FormatError::InvalidArchive(message)
            if *message == "complete volume set has missing global blocks" =>
        {
            Diagnostic {
                label: "missing-volume",
                exit_code: EXIT_CORRUPT_ARCHIVE,
                action: "add the missing archive volume(s) or confirm volume-loss tolerance",
            }
        }
        FormatError::InvalidArchive(message)
            if *message == "missing volume count exceeds volume_loss_tolerance" =>
        {
            Diagnostic {
                label: "missing-volume",
                exit_code: EXIT_CORRUPT_ARCHIVE,
                action: "add the missing archive volume(s) or confirm volume-loss tolerance",
            }
        }
        FormatError::HmacMismatch { .. } | FormatError::AeadFailure => Diagnostic {
            label: "corrupt-payload",
            exit_code: EXIT_CORRUPT_ARCHIVE,
            action: "verify archive payload integrity",
        },
        FormatError::BadCrc {
            structure: "VolumeHeader",
        }
        | FormatError::BadCrc {
            structure: "VolumeTrailer",
        }
        | FormatError::BadCrc {
            structure: "ManifestFooter",
        }
        | FormatError::InvalidMetadata {
            structure: "ManifestFooter",
            ..
        }
        | FormatError::InvalidMetadata {
            structure: "VolumeHeader",
            ..
        } => Diagnostic {
            label: "corrupt-header",
            exit_code: EXIT_CORRUPT_ARCHIVE,
            action: "inspect archive metadata and source file path",
        },
        FormatError::BadCrc { structure: _ } => Diagnostic {
            label: "corrupt-payload",
            exit_code: EXIT_CORRUPT_ARCHIVE,
            action: "verify payload integrity",
        },
        FormatError::InvalidKdfParams(message) => Diagnostic {
            label: "invalid-arguments",
            exit_code: EXIT_USAGE,
            action: message,
        },
        FormatError::InvalidMetadata { structure, .. } => Diagnostic {
            label: if *structure == "IndexRoot"
                || *structure == "FrameEntry"
                || *structure == "EnvelopeEntry"
            {
                "corrupt-payload"
            } else {
                "corrupt-header"
            },
            exit_code: EXIT_CORRUPT_ARCHIVE,
            action: if *structure == "IndexRoot"
                || *structure == "FrameEntry"
                || *structure == "EnvelopeEntry"
            {
                "inspect archive metadata tables and payload"
            } else {
                "inspect archive header metadata"
            },
        },
        FormatError::ReaderResourceLimitExceeded { .. } => Diagnostic {
            label: "invalid-arguments",
            exit_code: EXIT_USAGE,
            action:
                "archive exceeds reader resource limits (payload/metadata size caps, or argon2 parameters via --argon2-t-cost, --argon2-m-cost-kib, --argon2-parallelism)",
        },
        FormatError::UnsafeArchivePath => Diagnostic {
            label: "unsafe-path",
            exit_code: EXIT_UNSAFE_PATH,
            action: "archive contains unsafe paths; extract paths should be reviewed first",
        },
        FormatError::UnsafeOverwrite => Diagnostic {
            label: "unsafe-path",
            exit_code: EXIT_UNSAFE_PATH,
            action: "add --overwrite if overwriting existing files is intended",
        },
        FormatError::ReaderUnsupported(message) | FormatError::WriterUnsupported(message)
            if message.contains("bootstrap sidecar")
                || message.contains("dictionary bootstrap required") =>
        {
            Diagnostic {
                label: "missing-bootstrap",
                exit_code: EXIT_MISSING_BOOTSTRAP,
                action: "use --bootstrap with a matching sidecar",
            }
        }
        FormatError::ReaderUnsupported(_) | FormatError::WriterUnsupported(_) => Diagnostic {
            label: "unsupported-feature",
            exit_code: EXIT_UNSUPPORTED_FEATURE,
            action: "use a supported archive shape or upgrade tzap",
        },
        _ => Diagnostic {
            label: "corrupt-archive",
            exit_code: EXIT_CORRUPT_ARCHIVE,
            action: "verify archive integrity and source",
        },
    }
}
