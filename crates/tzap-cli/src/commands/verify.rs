use super::*;

use std::io::{self};

use anyhow::{anyhow, Context, Result};
use serde_json::json;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tzap_core::format::{FormatError, FORMAT_VERSION, VOLUME_FORMAT_REV_45};
use tzap_core::{
    public_no_key_verify_volumes_with_options, verify_non_seekable_stream_with_bootstrap_sidecar,
    verify_non_seekable_stream_with_options,
    verify_non_seekable_stream_with_recipient_wrap_resolver_and_bootstrap_sidecar,
    verify_non_seekable_stream_with_recipient_wrap_resolver_options,
    verify_unencrypted_non_seekable_stream_with_bootstrap_sidecar,
    verify_unencrypted_non_seekable_stream_with_options, AeadAlgo, ArchiveContentVerification,
    KdfAlgo, OpenedArchive, PublicNoKeyVerification, ReaderOptions, RootAuthVerification,
    SequentialRootAuthStatus,
};
use tzap_plugin_signing::ed25519_raw::{
    self, Ed25519RootAuthOutcome, Ed25519VerificationMode, ED25519_AUTHENTICATOR_ID,
};
use tzap_plugin_signing::x509_chain::{self, X509RootAuthReport, X509_AUTHENTICATOR_ID};

pub(crate) fn run_verify(quiet: bool, args: VerifyArgs) -> Result<()> {
    let VerifyArgs {
        archives,
        password_stdin,
        password,
        keyfile,
        recipient_key,
        insecure_zero_key,
        trusted_public_key,
        trusted_ca_cert,
        trusted_system_roots,
        public_no_key,
        fast,
        bootstrap,
        json,
        write_repaired,
        jobs,
    } = args;

    let first = archives
        .first()
        .ok_or_else(|| anyhow!("at least one archive volume is required"))?;
    let archive_paths = archives.to_vec();
    let reader_options = reader_options(match resolve_jobs(jobs) {
        Ok(jobs) => jobs,
        Err(err) => {
            if json {
                emit_verify_json_error(&archive_paths, None, None, &err)?;
            }
            return Err(err);
        }
    });
    if let Err(err) = validate_fast_verify_options(
        fast,
        public_no_key,
        trusted_public_key.is_some(),
        !trusted_ca_cert.is_empty(),
        trusted_system_roots,
        write_repaired,
    ) {
        if json {
            emit_verify_json_error(&archive_paths, None, None, &err)?;
        }
        return Err(err);
    }
    if archives.iter().any(|path| path == "-") {
        if write_repaired {
            let err = anyhow!(FormatError::ReaderUnsupported(
                "--write-repaired is not supported for archive stdin",
            ));
            if json {
                emit_verify_json_error(&archive_paths, None, None, &err)?;
            }
            return Err(err);
        }
        if fast {
            let err = anyhow!(UsageError(
                        "--fast requires seekable archive paths; archive stdin uses full non-seekable verification",
                    ));
            if json {
                emit_verify_json_error(&archive_paths, None, None, &err)?;
            }
            return Err(err);
        }
        if json && archives.len() != 1 {
            let err = anyhow!(FormatError::ReaderUnsupported(
                "archive stdin must be the only archive input",
            ));
            emit_verify_json_error(&archive_paths, None, None, &err)?;
            return Err(err);
        }
        if first != "-" || archives.len() != 1 {
            return Err(anyhow!(FormatError::ReaderUnsupported(
                "archive stdin must be the only archive input",
            )));
        }
        if public_no_key {
            let err = anyhow!(FormatError::ReaderUnsupported(
                "public no-key verification is not supported for archive stdin",
            ));
            if json {
                emit_verify_json_error(&archive_paths, None, None, &err)?;
            }
            return Err(err);
        }
        if trusted_public_key.is_some() || !trusted_ca_cert.is_empty() || trusted_system_roots {
            let err = anyhow!(FormatError::ReaderUnsupported(
                "RootAuth external verification is not supported for archive stdin",
            ));
            if json {
                emit_verify_json_error(&archive_paths, None, None, &err)?;
            }
            return Err(err);
        }
        let bootstrap_bytes = match read_optional_bootstrap_sidecar(bootstrap.as_deref()) {
            Ok(bootstrap_bytes) => bootstrap_bytes,
            Err(err) => {
                if json {
                    emit_verify_json_error(&archive_paths, None, None, &err)?;
                }
                return Err(err);
            }
        };
        let stdin = io::stdin();
        let result = if let Some(keyfile) = keyfile.as_deref() {
            let master_key = match load_archive_stdin_key(
                Some(keyfile),
                password_stdin,
                password,
                insecure_zero_key,
            ) {
                Ok(master_key) => master_key,
                Err(err) => {
                    if json {
                        emit_verify_json_error(&archive_paths, None, None, &err)?;
                    }
                    return Err(err);
                }
            };
            if let Some(bootstrap_bytes) = bootstrap_bytes.as_deref() {
                verify_non_seekable_stream_with_bootstrap_sidecar(
                    stdin.lock(),
                    bootstrap_bytes,
                    &master_key,
                    non_seekable_reader_options(reader_options),
                )
            } else {
                verify_non_seekable_stream_with_options(
                    stdin.lock(),
                    &master_key,
                    non_seekable_reader_options(reader_options),
                )
            }
        } else if let Some(recipient_key) = recipient_key.as_deref() {
            let lookup = match load_recipient_private_key_lookup(recipient_key) {
                Ok(lookup) => lookup,
                Err(err) => {
                    if json {
                        emit_verify_json_error(&archive_paths, None, None, &err)?;
                    }
                    return Err(err);
                }
            };
            let mut stats = RecipientWrapOpenStats::default();
            if let Some(bootstrap_bytes) = bootstrap_bytes.as_deref() {
                verify_non_seekable_stream_with_recipient_wrap_resolver_and_bootstrap_sidecar(
                    stdin.lock(),
                    bootstrap_bytes,
                    |context| recipient_wrap_candidates_for_record(context, &lookup, &mut stats),
                    non_seekable_reader_options(reader_options),
                )
            } else {
                verify_non_seekable_stream_with_recipient_wrap_resolver_options(
                    stdin.lock(),
                    |context| recipient_wrap_candidates_for_record(context, &lookup, &mut stats),
                    non_seekable_reader_options(reader_options),
                )
            }
        } else {
            if let Some(bootstrap_bytes) = bootstrap_bytes.as_deref() {
                verify_unencrypted_non_seekable_stream_with_bootstrap_sidecar(
                    stdin.lock(),
                    bootstrap_bytes,
                    non_seekable_reader_options(reader_options),
                )
            } else {
                verify_unencrypted_non_seekable_stream_with_options(
                    stdin.lock(),
                    non_seekable_reader_options(reader_options),
                )
            }
        }
        .context("failed to verify non-seekable archive stream");
        let report = match result {
            Ok(report) => report,
            Err(err) => {
                if json {
                    emit_verify_json_error(&archive_paths, None, None, &err)?;
                }
                return Err(err);
            }
        };
        if json {
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "ok": true,
                    "archives": &archive_paths,
                    "verification_mode": "key-holding-non-seekable-stream",
                    "status": {
                        "revision_mode": revision_mode_label(report.volume_format_rev),
                        "format_version": FORMAT_VERSION,
                        "volume_format_rev": report.volume_format_rev,
                        "header_base_integrity": "verified",
                        "decryption_keywrap": if recipient_key.is_some() {
                            "recipientwrap_opened"
                        } else if keyfile.is_some() {
                            "key_holding_decrypted"
                        } else {
                            "plaintext_opened"
                        },
                        "root_auth_signer": match report.root_auth {
                            SequentialRootAuthStatus::Absent => "absent",
                            SequentialRootAuthStatus::WireValidOnly => "wire_valid_only",
                        },
                        "trust_policy": "not_requested",
                        "public_no_key_metadata_only": "not_requested",
                    },
                    "volume_count": report.total_volumes,
                    "file_count": report.file_count,
                    "tar_total_size": report.tar_total_size,
                    "metadata": metadata_verification_json(&report.metadata),
                }))
                .context("failed to encode verify output as JSON")?
            );
            return Ok(());
        }
        emit_success_stdout(
            quiet,
            &format!(
                "{} {} ({} volume(s), {} file(s))",
                "-: OK non-seekable stream",
                revision_mode_label(report.volume_format_rev),
                report.total_volumes,
                report.file_count
            ),
        )?;
        if report.root_auth == SequentialRootAuthStatus::WireValidOnly {
            emit_success_stdout(
                quiet,
                "root-auth: wire-valid-only (signer trust not checked)",
            )?;
        }
        emit_metadata_verification_stdout(quiet, &report.metadata)?;
        return Ok(());
    }
    if public_no_key {
        if write_repaired {
            let err = anyhow!(FormatError::ReaderUnsupported(
                "--write-repaired requires key-holding verification",
            ));
            if json {
                emit_verify_json_error(&archive_paths, None, None, &err)?;
            }
            return Err(err);
        }
        return run_public_no_key_verify(PublicNoKeyVerifyRequest {
            archive_paths: &archive_paths,
            trusted_public_key: trusted_public_key.as_deref(),
            trusted_ca_cert: &trusted_ca_cert,
            trusted_system_roots,
            password_stdin,
            password,
            keyfile: keyfile.as_deref(),
            recipient_key: recipient_key.as_deref(),
            insecure_zero_key,
            bootstrap: bootstrap.as_deref(),
            reader_options,
            quiet,
            json,
        });
    }
    if let Err(err) = validate_verify_key_holding_key_source(
        keyfile.as_deref(),
        recipient_key.as_deref(),
        password_stdin,
        password,
        insecure_zero_key,
    ) {
        if json {
            emit_verify_json_error(&archive_paths, None, None, &err)?;
        }
        return Err(err);
    }
    if let Err(err) = reject_multi_volume_bootstrap(archives.len(), bootstrap.as_deref()) {
        if json {
            emit_verify_json_error(&archive_paths, None, None, &err)?;
        }
        return Err(err);
    }
    if write_repaired && bootstrap.is_some() {
        let err = anyhow!(FormatError::ReaderUnsupported(
            "--write-repaired is not supported with --bootstrap",
        ));
        if json {
            emit_verify_json_error(&archive_paths, None, None, &err)?;
        }
        return Err(err);
    }
    let selection = match resolve_archive_input_paths(first, &archives[1..], bootstrap.is_none()) {
        Ok(selection) => selection,
        Err(err) => {
            if json {
                emit_verify_json_error(&archive_paths, None, None, &err)?;
            }
            return Err(err);
        }
    };
    let archive_paths = selection.paths.clone();
    let opened_selection_result = if let Some(recipient_key) = recipient_key.as_deref() {
        open_selection_with_recipient_key(
            &selection,
            recipient_key,
            bootstrap.as_deref(),
            reader_options,
        )
    } else {
        let master_key = match load_open_key_from_paths(
            keyfile.as_deref(),
            password_stdin,
            password,
            insecure_zero_key,
            &selection.paths,
        ) {
            Ok(master_key) => master_key,
            Err(err) => {
                if json {
                    emit_verify_json_error(&archive_paths, None, None, &err)?;
                }
                return Err(err);
            }
        };
        open_selection_maybe_bootstrap_resolved(
            &selection,
            &master_key,
            bootstrap.as_deref(),
            reader_options,
        )
    };
    let opened_selection =
        match opened_selection_result.with_context(|| format!("failed to open archive {first}")) {
            Ok(opened) => opened,
            Err(err) => {
                if json {
                    emit_verify_json_error(&archive_paths, None, None, &err)?;
                }
                return Err(err);
            }
        };
    let archive_paths = opened_selection.paths;
    let opened = opened_selection.opened;
    let result = if fast {
        opened
            .verify_content_fast()
            .with_context(|| format!("failed to fast-verify archive {first}"))
    } else {
        opened
            .verify_content()
            .with_context(|| format!("failed to verify archive {first}"))
    };
    let volume_count = opened.manifest_footer.total_volumes;
    let file_count = opened.index_root.header.file_count;
    match result {
        Ok(content_verification) => {
            let metadata_report = content_verification.metadata_report().cloned();
            let root_auth = if fast {
                None
            } else {
                match verify_opened_root_auth(
                    &opened,
                    &content_verification,
                    trusted_public_key.as_deref(),
                    &trusted_ca_cert,
                    trusted_system_roots,
                )
                .with_context(|| format!("failed to verify RootAuth for {first}"))
                {
                    Ok(root_auth) => root_auth,
                    Err(err) => {
                        if json {
                            emit_verify_json_error(
                                &archive_paths,
                                Some(volume_count as u64),
                                Some(file_count),
                                &err,
                            )?;
                        }
                        return Err(err);
                    }
                }
            };
            if let Some(report) = &metadata_report {
                for entry in &report.entries {
                    emit_member_metadata_diagnostics(
                        quiet,
                        &String::from_utf8_lossy(&entry.path),
                        &entry.diagnostics,
                    )?;
                }
            } else {
                let entries = match opened.list_files() {
                    Ok(entries) => entries,
                    Err(err) => {
                        if json {
                            let err = anyhow::Error::from(err);
                            emit_verify_json_error(
                                &archive_paths,
                                Some(volume_count as u64),
                                Some(file_count),
                                &err,
                            )?;
                            return Err(err);
                        }
                        return Err(err.into());
                    }
                };
                emit_entry_metadata_diagnostics(quiet, &entries)?;
            }
            let repaired_outputs = if write_repaired {
                match write_repaired_archive_copies(&archive_paths, &opened) {
                    Ok(outputs) => outputs,
                    Err(err) => {
                        if json {
                            emit_verify_json_error(
                                &archive_paths,
                                Some(volume_count as u64),
                                Some(file_count),
                                &err,
                            )?;
                        }
                        return Err(err);
                    }
                }
            } else {
                Vec::new()
            };
            if json {
                let mut payload = json!({
                    "ok": true,
                    "archives": &archive_paths,
                    "verification_mode": if fast { "fast" } else { "key-holding" },
                    "status": key_holding_status_json(
                        &opened,
                        root_auth.as_ref(),
                        fast,
                        recipient_key.is_some(),
                        trusted_public_key.is_some()
                            || !trusted_ca_cert.is_empty()
                            || trusted_system_roots,
                    ),
                    "volume_count": volume_count,
                    "file_count": file_count,
                });
                if let Some(root_auth) = &root_auth {
                    payload["root_auth"] = root_auth_json(root_auth);
                } else if fast {
                    let diagnostics = fast_verify_diagnostic_labels(&opened);
                    payload["diagnostics"] = json!(diagnostics);
                    if opened.root_auth_footer.is_some() {
                        payload["root_auth"] = json!({
                            "status": "root_auth_deferred_full_archive_scan_required",
                            "diagnostics": ["root_auth_deferred_full_archive_scan_required"],
                        });
                    }
                }
                if let Some(report) = &metadata_report {
                    payload["metadata"] = metadata_verification_json(report);
                }
                if write_repaired {
                    payload["repaired_outputs"] = json!(repaired_outputs
                        .iter()
                        .map(|output| json!({
                            "path": output.path.clone(),
                            "volume_index": output.volume_index,
                            "repaired_block_count": output.repaired_block_count,
                        }))
                        .collect::<Vec<_>>());
                }
                println!(
                    "{}",
                    serde_json::to_string(&payload)
                        .context("failed to encode verify output as JSON")?
                );
                return Ok(());
            }
            emit_success_stdout(
                quiet,
                &format!(
                    "{}: OK{} {} {} ({} volume(s), {} file(s))",
                    first,
                    if fast { " fast" } else { "" },
                    revision_mode_label(opened.volume_header.volume_format_rev),
                    key_access_status(&opened, recipient_key.is_some()),
                    volume_count,
                    file_count
                ),
            )?;
            if fast {
                emit_fast_verify_diagnostics_stdout(quiet, &opened)?;
            } else if let Some(root_auth) = &root_auth {
                emit_root_auth_stdout(quiet, root_auth)?;
            } else if opened.root_auth_footer.is_some() {
                emit_root_auth_skipped_warning(quiet)?;
            }
            if let Some(report) = &metadata_report {
                emit_metadata_verification_stdout(quiet, report)?;
            }
            if write_repaired {
                if repaired_outputs.is_empty() {
                    emit_success_stdout(
                        quiet,
                        "no repaired output written; no recoverable block damage found",
                    )?;
                } else {
                    for output in repaired_outputs {
                        emit_success_stdout(
                            quiet,
                            &format!(
                                "wrote repaired volume copy {} ({} block(s))",
                                output.path, output.repaired_block_count
                            ),
                        )?;
                    }
                }
            }
            Ok(())
        }
        Err(err) => {
            if json {
                emit_verify_json_error(
                    &archive_paths,
                    Some(volume_count as u64),
                    Some(file_count),
                    &err,
                )?;
            }
            Err(err)
        }
    }
}

pub(crate) struct VerifyArgs {
    pub(crate) archives: Vec<String>,
    pub(crate) password_stdin: bool,
    pub(crate) password: bool,
    pub(crate) keyfile: Option<String>,
    pub(crate) recipient_key: Option<String>,
    pub(crate) insecure_zero_key: bool,
    pub(crate) trusted_public_key: Option<String>,
    pub(crate) trusted_ca_cert: Vec<String>,
    pub(crate) trusted_system_roots: bool,
    pub(crate) public_no_key: bool,
    pub(crate) fast: bool,
    pub(crate) bootstrap: Option<String>,
    pub(crate) json: bool,
    pub(crate) write_repaired: bool,
    pub(crate) jobs: Option<usize>,
}

pub(crate) fn validate_fast_verify_options(
    fast: bool,
    public_no_key: bool,
    has_trusted_public_key: bool,
    has_trusted_ca_cert: bool,
    trusted_system_roots: bool,
    write_repaired: bool,
) -> Result<()> {
    if !fast {
        return Ok(());
    }
    if public_no_key {
        return Err(UsageError("--fast cannot be combined with --public-no-key").into());
    }
    if has_trusted_public_key || has_trusted_ca_cert || trusted_system_roots {
        return Err(UsageError(
            "--fast cannot be combined with RootAuth trust options; omit --fast for full RootAuth verification",
        )
        .into());
    }
    if write_repaired {
        return Err(UsageError("--fast cannot be combined with --write-repaired").into());
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) enum VerifiedRootAuth {
    Ed25519(RootAuthVerification),
    X509 {
        verification: RootAuthVerification,
        report: Box<X509RootAuthReport>,
    },
}

#[derive(Debug)]
pub(crate) enum PublicNoKeyTrust {
    Ed25519 {
        public_key: [u8; 32],
    },
    X509 {
        trusted_roots_der: Vec<Vec<u8>>,
        trusted_system_roots: bool,
        /// The embedded official TZAP root is included in `trusted_roots_der`.
        include_official_tzap_root: bool,
    },
}

#[derive(Debug)]
pub(crate) enum VerifiedPublicNoKeyRootAuth {
    Ed25519(PublicNoKeyVerification),
    X509 {
        verification: PublicNoKeyVerification,
        report: Box<X509RootAuthReport>,
    },
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct PublicNoKeyVerifyRequest<'a> {
    pub(crate) archive_paths: &'a [String],
    pub(crate) trusted_public_key: Option<&'a str>,
    pub(crate) trusted_ca_cert: &'a [String],
    pub(crate) trusted_system_roots: bool,
    pub(crate) password_stdin: bool,
    pub(crate) password: bool,
    pub(crate) keyfile: Option<&'a str>,
    pub(crate) recipient_key: Option<&'a str>,
    pub(crate) insecure_zero_key: bool,
    pub(crate) bootstrap: Option<&'a str>,
    pub(crate) reader_options: ReaderOptions,
    pub(crate) quiet: bool,
    pub(crate) json: bool,
}

pub(crate) fn run_public_no_key_verify(request: PublicNoKeyVerifyRequest<'_>) -> Result<()> {
    let trust = match load_public_no_key_trust(&request) {
        Ok(trust) => trust,
        Err(err) => {
            if request.json {
                emit_verify_json_error(request.archive_paths, None, None, &err)?;
            }
            return Err(err);
        }
    };
    let first = request
        .archive_paths
        .first()
        .ok_or(UsageError("at least one archive volume is required"))?;
    let selection = match resolve_archive_input_paths(first, &request.archive_paths[1..], true) {
        Ok(selection) => selection,
        Err(err) => {
            if request.json {
                emit_verify_json_error(request.archive_paths, None, None, &err)?;
            }
            return Err(err);
        }
    };
    let archive_paths = selection.paths;
    let volume_inputs = match map_volume_inputs_from_paths(&archive_paths) {
        Ok(volume_inputs) => volume_inputs,
        Err(err) => {
            if request.json {
                emit_verify_json_error(&archive_paths, None, None, &err)?;
            }
            return Err(err);
        }
    };
    let borrowed = volume_inputs
        .iter()
        .map(MappedVolumeInput::as_slice)
        .collect::<Vec<_>>();
    let mut x509_report = None;
    let mut x509_error = None;
    let verification = match public_no_key_verify_volumes_with_options(
        &borrowed,
        |footer, archive_root| match &trust {
            PublicNoKeyTrust::Ed25519 { public_key } => {
                if footer.authenticator_id != ED25519_AUTHENTICATOR_ID {
                    return Err(FormatError::ReaderUnsupported(
                        "trusted public key can only verify Ed25519 RootAuth",
                    ));
                }
                Ok(matches!(
                    ed25519_raw::verify_root_auth_footer(
                        footer,
                        archive_root,
                        Some(*public_key),
                        Ed25519VerificationMode::PublicNoKey,
                    ),
                    Ed25519RootAuthOutcome::PublicDataBlockCommitmentVerified { .. }
                ))
            }
            PublicNoKeyTrust::X509 {
                trusted_roots_der,
                trusted_system_roots,
                include_official_tzap_root,
            } => {
                if footer.authenticator_id != X509_AUTHENTICATOR_ID {
                    return Err(FormatError::ReaderUnsupported(
                        "X.509 trust can only verify X.509 RootAuth",
                    ));
                }
                match x509_chain::verify_root_auth_footer(
                    footer,
                    archive_root,
                    trusted_roots_der,
                    *trusted_system_roots,
                    *include_official_tzap_root,
                ) {
                    Ok(report) => {
                        x509_report = Some(report);
                        Ok(true)
                    }
                    Err(err) => {
                        x509_error = Some(err.to_string());
                        Ok(false)
                    }
                }
            }
        },
        request.reader_options,
    )
    .map_err(|err| {
        if let Some(detail) = x509_error.take() {
            anyhow!("{err}: {detail}")
        } else {
            anyhow!(err)
        }
    })
    .with_context(|| format!("failed to verify public RootAuth for {first}"))
    {
        Ok(verification) => verification,
        Err(err) => {
            if request.json {
                emit_verify_json_error(&archive_paths, None, None, &err)?;
            }
            return Err(err);
        }
    };
    let root_auth = match trust {
        PublicNoKeyTrust::Ed25519 { .. } => VerifiedPublicNoKeyRootAuth::Ed25519(verification),
        PublicNoKeyTrust::X509 { .. } => {
            let report = x509_report.ok_or(FormatError::InvalidArchive(
                "missing X.509 public no-key verification report",
            ))?;
            VerifiedPublicNoKeyRootAuth::X509 {
                verification,
                report: Box::new(report),
            }
        }
    };
    if request.json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "ok": true,
                "archives": &archive_paths,
                "verification_mode": "public-no-key",
                "status": public_no_key_status_json(&root_auth),
                "volume_count": archive_paths.len(),
                "root_auth": public_no_key_root_auth_json(&root_auth),
                "public_diagnostics": public_no_key_diagnostic_labels_for_root_auth(&root_auth),
                "public_outcome": PUBLIC_NO_KEY_OUTCOME_NOTE,
            }))
            .context("failed to encode verify output as JSON")?
        );
        return Ok(());
    }
    emit_success_stdout(
        request.quiet,
        &format!(
            "{}: OK public-no-key metadata-only ({} volume(s), {} data block(s))",
            first,
            archive_paths.len(),
            public_no_key_total_data_block_count(&root_auth)
        ),
    )?;
    emit_public_no_key_root_auth_stdout(request.quiet, &root_auth)?;
    for diagnostic in public_no_key_diagnostic_labels_for_root_auth(&root_auth) {
        emit_success_stdout(request.quiet, &format!("public-no-key: {diagnostic}"))?;
    }
    emit_success_stdout(
        request.quiet,
        &format!("public-no-key outcome: {PUBLIC_NO_KEY_OUTCOME_NOTE}"),
    )?;
    Ok(())
}

pub(crate) fn load_public_no_key_trust(
    request: &PublicNoKeyVerifyRequest<'_>,
) -> Result<PublicNoKeyTrust> {
    let wants_ed25519 = request.trusted_public_key.is_some();
    let wants_x509 = !request.trusted_ca_cert.is_empty() || request.trusted_system_roots;
    if wants_ed25519 && wants_x509 {
        return Err(UsageError(
            "use either --trusted-public-key or X.509 trust options with --public-no-key, not both",
        )
        .into());
    }
    if request.insecure_zero_key {
        return Err(removed_insecure_zero_key_error().into());
    }
    if request.password_stdin
        || request.password
        || request.keyfile.is_some()
        || request.recipient_key.is_some()
    {
        return Err(UsageError(
            "--public-no-key cannot be combined with --keyfile, --recipient-key, --password, or --password-stdin",
        )
        .into());
    }
    if request.bootstrap.is_some() {
        return Err(UsageError("--public-no-key does not use --bootstrap sidecars").into());
    }
    if let Some(path) = request.trusted_public_key {
        return Ok(PublicNoKeyTrust::Ed25519 {
            public_key: load_ed25519_public_key(path)?,
        });
    }
    Ok(PublicNoKeyTrust::X509 {
        trusted_roots_der: load_x509_trusted_roots(request.trusted_ca_cert, !wants_x509)?,
        trusted_system_roots: request.trusted_system_roots,
        include_official_tzap_root: !wants_x509,
    })
}

pub(crate) fn verify_opened_root_auth_ed25519(
    opened: &OpenedArchive,
    content_verification: &ArchiveContentVerification<'_>,
    trusted_public_key: &str,
) -> Result<RootAuthVerification> {
    let public_key = load_ed25519_public_key(trusted_public_key)?;
    opened
        .verify_root_auth_with_verified_content(content_verification, |footer, archive_root| {
            Ok(matches!(
                ed25519_raw::verify_root_auth_footer(
                    footer,
                    archive_root,
                    Some(public_key),
                    Ed25519VerificationMode::KeyHoldingRootAuth,
                ),
                Ed25519RootAuthOutcome::RootAuthContentVerified { .. }
            ))
        })
        .map_err(Into::into)
}

pub(crate) fn verify_opened_root_auth(
    opened: &OpenedArchive,
    content_verification: &ArchiveContentVerification<'_>,
    trusted_public_key: Option<&str>,
    trusted_ca_cert: &[String],
    trusted_system_roots: bool,
) -> Result<Option<VerifiedRootAuth>> {
    let wants_ed25519 = trusted_public_key.is_some();
    let wants_explicit_x509 = !trusted_ca_cert.is_empty() || trusted_system_roots;
    if wants_ed25519 && wants_explicit_x509 {
        return Err(
            UsageError("use either --trusted-public-key or X.509 trust options, not both").into(),
        );
    }
    let Some(footer) = opened.root_auth_footer.as_ref() else {
        if wants_ed25519 || wants_explicit_x509 {
            return Err(FormatError::InvalidArchive("missing RootAuthFooter").into());
        }
        return Ok(None);
    };
    let wants_official_x509 =
        !wants_ed25519 && !wants_explicit_x509 && footer.authenticator_id == X509_AUTHENTICATOR_ID;
    if !wants_ed25519 && !wants_explicit_x509 && !wants_official_x509 {
        return Ok(None);
    }
    match footer.authenticator_id {
        ED25519_AUTHENTICATOR_ID if wants_ed25519 => {
            let public_key = trusted_public_key.expect("checked Ed25519 trust request");
            Ok(Some(VerifiedRootAuth::Ed25519(
                verify_opened_root_auth_ed25519(opened, content_verification, public_key)?,
            )))
        }
        X509_AUTHENTICATOR_ID if wants_explicit_x509 || wants_official_x509 => {
            let trusted_roots_der = load_x509_trusted_roots(trusted_ca_cert, wants_official_x509)?;
            Ok(Some(verify_opened_root_auth_x509(
                opened,
                content_verification,
                &trusted_roots_der,
                trusted_system_roots,
                wants_official_x509,
            )?))
        }
        ED25519_AUTHENTICATOR_ID => {
            Err(UsageError("Ed25519 RootAuth requires --trusted-public-key FILE").into())
        }
        X509_AUTHENTICATOR_ID => Err(UsageError(
            "X.509 RootAuth requires --trusted-ca-cert FILE or --trusted-system-roots",
        )
        .into()),
        _ => Err(FormatError::ReaderUnsupported("unsupported RootAuth authenticator id").into()),
    }
}

pub(crate) fn verify_opened_root_auth_x509(
    opened: &OpenedArchive,
    content_verification: &ArchiveContentVerification<'_>,
    trusted_roots_der: &[Vec<u8>],
    trusted_system_roots: bool,
    include_official_tzap_root: bool,
) -> Result<VerifiedRootAuth> {
    let mut report = None;
    let mut x509_error = None;
    let verification = opened
        .verify_root_auth_with_verified_content(content_verification, |footer, archive_root| {
            match x509_chain::verify_root_auth_footer(
                footer,
                archive_root,
                trusted_roots_der,
                trusted_system_roots,
                include_official_tzap_root,
            ) {
                Ok(value) => {
                    report = Some(value);
                    Ok(true)
                }
                Err(err) => {
                    x509_error = Some(err.to_string());
                    Ok(false)
                }
            }
        })
        .map_err(|err| {
            if let Some(detail) = x509_error {
                anyhow!("{err}: {detail}")
            } else {
                anyhow!(err)
            }
        })?;
    let report = report.ok_or(FormatError::InvalidArchive(
        "missing X.509 RootAuth verification report",
    ))?;
    Ok(VerifiedRootAuth::X509 {
        verification,
        report: Box::new(report),
    })
}

pub(crate) fn revision_mode_label(volume_format_rev: u16) -> &'static str {
    match volume_format_rev {
        VOLUME_FORMAT_REV_45 => "v45",
        _ => "unsupported",
    }
}

pub(crate) fn key_access_status(opened: &OpenedArchive, used_recipient_key: bool) -> &'static str {
    if opened.crypto_header.aead_algo == AeadAlgo::None {
        "plaintext_opened"
    } else if used_recipient_key || opened.crypto_header.kdf_algo == KdfAlgo::RecipientWrap {
        "recipientwrap_opened"
    } else {
        "key_holding_decrypted"
    }
}

pub(crate) fn key_holding_status_json(
    opened: &OpenedArchive,
    root_auth: Option<&VerifiedRootAuth>,
    fast: bool,
    used_recipient_key: bool,
    trust_requested: bool,
) -> serde_json::Value {
    json!({
        "revision_mode": revision_mode_label(opened.volume_header.volume_format_rev),
        "format_version": opened.volume_header.format_version,
        "volume_format_rev": opened.volume_header.volume_format_rev,
        "header_base_integrity": if fast { "fast_verified" } else { "verified" },
        "decryption_keywrap": key_access_status(opened, used_recipient_key),
        "root_auth_signer": key_holding_root_auth_status(opened, root_auth, fast),
        "trust_policy": key_holding_trust_policy_status(root_auth, trust_requested),
        "public_no_key_metadata_only": "not_requested",
    })
}

pub(crate) fn key_holding_root_auth_status(
    opened: &OpenedArchive,
    root_auth: Option<&VerifiedRootAuth>,
    fast: bool,
) -> &'static str {
    if let Some(root_auth) = root_auth {
        return verified_root_auth_status(root_auth);
    }
    if fast && opened.root_auth_footer.is_some() {
        "deferred_full_archive_scan_required"
    } else if opened.root_auth_footer.is_some() {
        "not_requested"
    } else {
        "absent"
    }
}

pub(crate) fn key_holding_trust_policy_status(
    root_auth: Option<&VerifiedRootAuth>,
    trust_requested: bool,
) -> &'static str {
    if root_auth.is_some() {
        "trusted"
    } else if trust_requested {
        "unverified"
    } else {
        "not_requested"
    }
}

pub(crate) fn verified_root_auth_status(root_auth: &VerifiedRootAuth) -> &'static str {
    match root_auth {
        VerifiedRootAuth::Ed25519(verification) => root_auth_status(verification),
        VerifiedRootAuth::X509 { verification, .. } => root_auth_status(verification),
    }
}

/// §30.11: the explanatory sentence that MUST accompany every successful
/// public no-key result.
const PUBLIC_NO_KEY_OUTCOME_NOTE: &str = "Trusted key signed a commitment to this observed CRC-valid public data-block set (ciphertext in an encryption mode, plaintext in unencrypted mode) and to opaque component digests. Plaintext recovery for encrypted archives, decoded file/content authenticity, IndexRoot, mode-specifically authenticated metadata, physical completeness, and recovery margin were not inspected.";

pub(crate) fn public_no_key_status_json(
    root_auth: &VerifiedPublicNoKeyRootAuth,
) -> serde_json::Value {
    let verification = public_no_key_verification(root_auth);
    json!({
        "revision_mode": revision_mode_label(verification.volume_format_rev),
        "format_version": verification.format_version,
        "volume_format_rev": verification.volume_format_rev,
        "header_base_integrity": "public_metadata_verified",
        "decryption_keywrap": "not_used",
        "root_auth_signer": public_no_key_status(verification),
        "trust_policy": "public_trust_matched",
        "public_no_key_metadata_only": "metadata_commitments_verified",
    })
}

pub(crate) fn public_no_key_verification(
    root_auth: &VerifiedPublicNoKeyRootAuth,
) -> &PublicNoKeyVerification {
    match root_auth {
        VerifiedPublicNoKeyRootAuth::Ed25519(verification) => verification,
        VerifiedPublicNoKeyRootAuth::X509 { verification, .. } => verification,
    }
}

pub(crate) fn root_auth_json(root_auth: &VerifiedRootAuth) -> serde_json::Value {
    match root_auth {
        VerifiedRootAuth::Ed25519(root_auth) => {
            let mut payload = json!({
                "status": root_auth_status(root_auth),
                "diagnostics": root_auth_diagnostic_labels(root_auth),
                "revision_mode": revision_mode_label(root_auth.volume_format_rev),
                "format_version": root_auth.format_version,
                "volume_format_rev": root_auth.volume_format_rev,
                "authenticator": "ed25519",
                "archive_root": encode_hex(&root_auth.archive_root),
                "authenticator_id": root_auth.authenticator_id,
                "signer_identity_type": root_auth.signer_identity_type,
                "signer_identity": encode_hex(&root_auth.signer_identity_bytes),
                "total_data_block_count": root_auth.total_data_block_count,
            });
            if root_auth.signer_identity_type == 1 && root_auth.signer_identity_bytes.len() == 32 {
                payload["key_id"] = json!(encode_hex(&root_auth.signer_identity_bytes));
            }
            payload
        }
        VerifiedRootAuth::X509 {
            verification,
            report,
        } => json!({
            "status": root_auth_status(verification),
            "diagnostics": root_auth_diagnostic_labels(verification),
            "revision_mode": revision_mode_label(verification.volume_format_rev),
            "format_version": verification.format_version,
            "volume_format_rev": verification.volume_format_rev,
            "authenticator": "x509",
            "archive_root": encode_hex(&verification.archive_root),
            "authenticator_id": verification.authenticator_id,
            "signer_identity_type": verification.signer_identity_type,
            "signer_identity": encode_hex(&verification.signer_identity_bytes),
            "total_data_block_count": verification.total_data_block_count,
            "subject": &report.subject,
            "issuer": &report.issuer,
            "serial_number": &report.serial_number_hex,
            "certificate_sha256": encode_hex(&report.certificate_sha256),
            "signed_at_unix_seconds": report.signed_at_unix_seconds,
            "signed_at": format_unix_timestamp(report.signed_at_unix_seconds),
            "time_source": "signer_claimed",
            "signature_scheme": report.signature_scheme,
            "chain_validation_time_unix_seconds": report.chain_validation_time_unix_seconds,
            "chain_validation_time": format_unix_timestamp(report.chain_validation_time_unix_seconds),
            "x509_time_policy": report.x509_time_policy,
            "chain_time_basis": report.chain_time_basis,
            "trusted_timestamp": report.trusted_timestamp,
            "revocation_checked": report.revocation_checked,
            "trust_store_policy": report.trust_store_policy,
            "key_usage_policy": report.key_usage_policy,
            "eku_policy": report.eku_policy,
            "verified_chain_subjects": &report.verified_chain_subjects,
            "trust_anchor_subject": &report.trust_anchor_subject,
        }),
    }
}

pub(crate) fn root_auth_status(root_auth: &RootAuthVerification) -> &'static str {
    root_auth
        .diagnostics
        .first()
        .map(|diagnostic| diagnostic.label())
        .unwrap_or("root_auth_content_verified")
}

pub(crate) fn root_auth_diagnostic_labels(root_auth: &RootAuthVerification) -> Vec<&'static str> {
    root_auth
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.label())
        .collect()
}

pub(crate) fn emit_root_auth_skipped_warning(quiet: bool) -> io::Result<()> {
    if quiet {
        return Ok(());
    }
    // The archive is signed but no trust configuration was provided (e.g. an Ed25519
    // archive without --trusted-public-key), so the signature was NOT verified. A bare
    // "OK" line would otherwise give automation false assurance.
    eprintln!("warning: archive is signed, but no trust configuration was provided; the signature was NOT verified");
    Ok(())
}

pub(crate) fn emit_root_auth_stdout(quiet: bool, root_auth: &VerifiedRootAuth) -> io::Result<()> {
    match root_auth {
        VerifiedRootAuth::Ed25519(verification) => {
            emit_success_stdout(
                quiet,
                &format!(
                    "root-auth: OK ed25519 {}",
                    encode_hex(&verification.archive_root)
                ),
            )?;
            emit_root_auth_diagnostics_stdout(quiet, verification)
        }
        VerifiedRootAuth::X509 {
            verification,
            report,
        } => {
            emit_success_stdout(
                quiet,
                &format!(
                    "root-auth: OK x509 {}",
                    encode_hex(&verification.archive_root)
                ),
            )?;
            emit_success_stdout(quiet, &format!("root-auth signer: {}", report.subject))?;
            emit_success_stdout(quiet, &format!("root-auth issuer: {}", report.issuer))?;
            if let Some(trust_anchor) = &report.trust_anchor_subject {
                emit_success_stdout(quiet, &format!("root-auth trust-anchor: {trust_anchor}"))?;
            }
            emit_success_stdout(
                quiet,
                &format!(
                    "root-auth signed-at: {} (signer-claimed)",
                    format_unix_timestamp(report.signed_at_unix_seconds)
                ),
            )?;
            emit_success_stdout(
                quiet,
                &format!(
                    "root-auth chain-validation-time: {} ({})",
                    format_unix_timestamp(report.chain_validation_time_unix_seconds),
                    report.chain_time_basis
                ),
            )?;
            emit_success_stdout(
                quiet,
                &format!(
                    "root-auth x509-policy: signature-scheme={} trust-store={} key-usage={} eku={} revocation-checked={} trusted-timestamp={}",
                    report.signature_scheme,
                    report.trust_store_policy,
                    report.key_usage_policy,
                    report.eku_policy,
                    report.revocation_checked,
                    report.trusted_timestamp
                ),
            )?;
            emit_success_stdout(
                quiet,
                &format!(
                    "root-auth certificate-sha256: {}",
                    encode_hex(&report.certificate_sha256)
                ),
            )?;
            emit_root_auth_diagnostics_stdout(quiet, verification)
        }
    }
}

pub(crate) fn emit_root_auth_diagnostics_stdout(
    quiet: bool,
    verification: &RootAuthVerification,
) -> io::Result<()> {
    for diagnostic in &verification.diagnostics {
        emit_success_stdout(quiet, &format!("root-auth: {}", diagnostic.label()))?;
    }
    Ok(())
}

pub(crate) fn fast_verify_diagnostic_labels(opened: &OpenedArchive) -> Vec<&'static str> {
    let mut diagnostics = Vec::new();
    if opened.fast_verify_defers_payload_semantics() {
        diagnostics.push("payload_semantics_deferred");
    }
    if opened.root_auth_footer.is_some() {
        diagnostics.push("root_auth_deferred_full_archive_scan_required");
    }
    if opened.crypto_header.fec_parity_shards > 0
        || opened.crypto_header.index_fec_parity_shards > 0
        || opened.crypto_header.index_root_fec_parity_shards > 0
        || opened.manifest_footer.index_root_parity_block_count > 0
    {
        diagnostics.push("recovery_margin_unchecked");
    }
    diagnostics
}

pub(crate) fn emit_fast_verify_diagnostics_stdout(
    quiet: bool,
    opened: &OpenedArchive,
) -> io::Result<()> {
    for diagnostic in fast_verify_diagnostic_labels(opened) {
        emit_success_stdout(quiet, &format!("fast-verify: {diagnostic}"))?;
    }
    Ok(())
}

pub(crate) fn public_no_key_root_auth_json(
    root_auth: &VerifiedPublicNoKeyRootAuth,
) -> serde_json::Value {
    match root_auth {
        VerifiedPublicNoKeyRootAuth::Ed25519(verification) => {
            let mut payload = json!({
                "status": public_no_key_status(verification),
                "diagnostics": public_no_key_diagnostic_labels(verification),
                "revision_mode": revision_mode_label(verification.volume_format_rev),
                "format_version": verification.format_version,
                "volume_format_rev": verification.volume_format_rev,
                "authenticator": "ed25519",
                "archive_root": encode_hex(&verification.archive_root),
                "authenticator_id": verification.authenticator_id,
                "signer_identity_type": verification.signer_identity_type,
                "signer_identity": encode_hex(&verification.signer_identity_bytes),
                "total_data_block_count": verification.total_data_block_count,
            });
            if verification.signer_identity_type == 1
                && verification.signer_identity_bytes.len() == 32
            {
                payload["key_id"] = json!(encode_hex(&verification.signer_identity_bytes));
            }
            payload
        }
        VerifiedPublicNoKeyRootAuth::X509 {
            verification,
            report,
        } => json!({
            "status": public_no_key_status(verification),
            "diagnostics": public_no_key_diagnostic_labels(verification),
            "revision_mode": revision_mode_label(verification.volume_format_rev),
            "format_version": verification.format_version,
            "volume_format_rev": verification.volume_format_rev,
            "authenticator": "x509",
            "archive_root": encode_hex(&verification.archive_root),
            "authenticator_id": verification.authenticator_id,
            "signer_identity_type": verification.signer_identity_type,
            "signer_identity": encode_hex(&verification.signer_identity_bytes),
            "total_data_block_count": verification.total_data_block_count,
            "subject": &report.subject,
            "issuer": &report.issuer,
            "serial_number": &report.serial_number_hex,
            "certificate_sha256": encode_hex(&report.certificate_sha256),
            "signed_at_unix_seconds": report.signed_at_unix_seconds,
            "signed_at": format_unix_timestamp(report.signed_at_unix_seconds),
            "time_source": "signer_claimed",
            "signature_scheme": report.signature_scheme,
            "chain_validation_time_unix_seconds": report.chain_validation_time_unix_seconds,
            "chain_validation_time": format_unix_timestamp(report.chain_validation_time_unix_seconds),
            "x509_time_policy": report.x509_time_policy,
            "chain_time_basis": report.chain_time_basis,
            "trusted_timestamp": report.trusted_timestamp,
            "revocation_checked": report.revocation_checked,
            "trust_store_policy": report.trust_store_policy,
            "key_usage_policy": report.key_usage_policy,
            "eku_policy": report.eku_policy,
            "verified_chain_subjects": &report.verified_chain_subjects,
            "trust_anchor_subject": &report.trust_anchor_subject,
        }),
    }
}

pub(crate) fn public_no_key_status(verification: &PublicNoKeyVerification) -> &'static str {
    verification
        .diagnostics
        .first()
        .map(|diagnostic| diagnostic.label())
        .unwrap_or("public_data_block_commitment_verified")
}

pub(crate) fn public_no_key_diagnostic_labels(
    verification: &PublicNoKeyVerification,
) -> Vec<&'static str> {
    verification
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.label())
        .collect()
}

pub(crate) fn public_no_key_diagnostic_labels_for_root_auth(
    root_auth: &VerifiedPublicNoKeyRootAuth,
) -> Vec<&'static str> {
    match root_auth {
        VerifiedPublicNoKeyRootAuth::Ed25519(verification) => {
            public_no_key_diagnostic_labels(verification)
        }
        VerifiedPublicNoKeyRootAuth::X509 { verification, .. } => {
            public_no_key_diagnostic_labels(verification)
        }
    }
}

pub(crate) fn emit_public_no_key_root_auth_stdout(
    quiet: bool,
    root_auth: &VerifiedPublicNoKeyRootAuth,
) -> io::Result<()> {
    match root_auth {
        VerifiedPublicNoKeyRootAuth::Ed25519(verification) => emit_success_stdout(
            quiet,
            &format!(
                "root-auth: OK public-no-key ed25519 {}",
                encode_hex(&verification.archive_root)
            ),
        ),
        VerifiedPublicNoKeyRootAuth::X509 {
            verification,
            report,
        } => {
            emit_success_stdout(
                quiet,
                &format!(
                    "root-auth: OK public-no-key x509 {}",
                    encode_hex(&verification.archive_root)
                ),
            )?;
            emit_success_stdout(quiet, &format!("root-auth signer: {}", report.subject))?;
            emit_success_stdout(quiet, &format!("root-auth issuer: {}", report.issuer))?;
            if let Some(trust_anchor) = &report.trust_anchor_subject {
                emit_success_stdout(quiet, &format!("root-auth trust-anchor: {trust_anchor}"))?;
            }
            emit_success_stdout(
                quiet,
                &format!(
                    "root-auth signed-at: {} (signer-claimed)",
                    format_unix_timestamp(report.signed_at_unix_seconds)
                ),
            )?;
            emit_success_stdout(
                quiet,
                &format!(
                    "root-auth chain-validation-time: {} ({})",
                    format_unix_timestamp(report.chain_validation_time_unix_seconds),
                    report.chain_time_basis
                ),
            )?;
            emit_success_stdout(
                quiet,
                &format!(
                    "root-auth x509-policy: signature-scheme={} trust-store={} key-usage={} eku={} revocation-checked={} trusted-timestamp={}",
                    report.signature_scheme,
                    report.trust_store_policy,
                    report.key_usage_policy,
                    report.eku_policy,
                    report.revocation_checked,
                    report.trusted_timestamp
                ),
            )
        }
    }
}

pub(crate) fn public_no_key_total_data_block_count(root_auth: &VerifiedPublicNoKeyRootAuth) -> u64 {
    match root_auth {
        VerifiedPublicNoKeyRootAuth::Ed25519(verification) => verification.total_data_block_count,
        VerifiedPublicNoKeyRootAuth::X509 { verification, .. } => {
            verification.total_data_block_count
        }
    }
}

pub(crate) fn format_unix_timestamp(unix_seconds: i64) -> String {
    match OffsetDateTime::from_unix_timestamp(unix_seconds) {
        Ok(date_time) => date_time
            .format(&Rfc3339)
            .unwrap_or_else(|_| unix_seconds.to_string()),
        Err(_) => unix_seconds.to_string(),
    }
}
