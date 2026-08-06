use super::*;

use std::io::{self};
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::json;
#[cfg(windows)]
use tzap_core::encode_v45_sparse_map;
use tzap_core::format::{
    FormatError, FORMAT_VERSION,
    READER_MAX_SUPPORTED_VOLUME_FORMAT_REV,
};
use tzap_core::reader::{ArchiveEntry, ArchiveIndexEntry};
use tzap_core::{
    MetadataDiagnostic,
    MetadataVerificationReport,
    RestorePolicy, TarEntryKind, WriterTimings,
};


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
pub(crate) fn metadata_diagnostic_lines_for_paths(entries: &[ArchiveEntry], paths: &[String]) -> Vec<String> {
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

pub(crate) fn emit_entry_metadata_diagnostics(quiet: bool, entries: &[ArchiveEntry]) -> io::Result<()> {
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

pub(crate) fn emit_metadata_verification_stdout(
    quiet: bool,
    report: &MetadataVerificationReport,
) -> io::Result<()> {
    emit_success_stdout(
        quiet,
        &format!(
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
        ),
    )?;
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
        emit_success_stdout(
            quiet,
            &format!(
                "metadata-policy {}: {complete}/{} entries policy-complete",
                restore_policy_label(policy),
                report.entries.len()
            ),
        )?;
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

pub(crate) fn unsupported_revision_error_json(err: &anyhow::Error, action: &'static str) -> serde_json::Value {
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

