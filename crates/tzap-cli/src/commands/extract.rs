use super::*;

use std::fs::{self};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
#[cfg(windows)]
use tzap_core::encode_v45_sparse_map;
use tzap_core::format::FormatError;
use tzap_core::reader::ArchiveIndexEntry;
use tzap_core::{
    extract_non_seekable_stream_to_dir, extract_non_seekable_stream_to_dir_with_bootstrap_sidecar,
    extract_non_seekable_stream_to_dir_with_recipient_wrap_resolver,
    extract_non_seekable_stream_to_dir_with_recipient_wrap_resolver_and_bootstrap_sidecar,
    extract_unencrypted_non_seekable_stream_to_dir,
    extract_unencrypted_non_seekable_stream_to_dir_with_bootstrap_sidecar, ExtractError, OpenedArchive,
    SafeExtractionOptions,
};


pub(crate) fn run_extract(quiet: bool, args: ExtractArgs) -> Result<()> {
    let ExtractArgs {
        archive,
        paths,
        directory,
        stdout,
        dry_run,
        overwrite,
        restore,
        allow_degraded,
        allow_absolute_symlinks,
        password_stdin,
        password,
        keyfile,
        recipient_key,
        insecure_zero_key,
        bootstrap,
        volumes,
        jobs,
    } = args;

            let reader_options = reader_options(resolve_jobs(jobs)?);
            reject_multi_volume_bootstrap(1 + volumes.len(), bootstrap.as_deref())?;
            reject_stdout_extract_shape(stdout, paths.len())?;
            if archive == "-" {
                reject_archive_stdin_open_options(ArchiveStdinOpenOptions {
                    paths: &paths,
                    stdout,
                    volumes: &volumes,
                    password_stdin,
                    password,
                    keyfile: keyfile.as_deref(),
                    recipient_key: recipient_key.as_deref(),
                    insecure_zero_key,
                })?;
                if dry_run {
                    eprintln!("extract dry-run summary:");
                    eprintln!("  input: archive stdin");
                    eprintln!("  destination: {}", directory);
                    eprintln!("  mode: staged non-seekable extract-all");
                    return Ok(());
                }
                let options = SafeExtractionOptions {
                    overwrite_existing: overwrite,
                    restore_policy: restore.into(),
                    allow_degraded,
                    system_authorized: restore == CliRestorePolicy::System,
                    allow_absolute_symlinks,
                };
                let bootstrap_bytes = read_optional_bootstrap_sidecar(bootstrap.as_deref())?;
                let stdin = io::stdin();
                let report = if let Some(keyfile) = keyfile.as_deref() {
                    let master_key = load_archive_stdin_key(
                        Some(keyfile),
                        password_stdin,
                        password,
                        insecure_zero_key,
                    )?;
                    if let Some(bootstrap_bytes) = bootstrap_bytes.as_deref() {
                        extract_non_seekable_stream_to_dir_with_bootstrap_sidecar(
                            stdin.lock(),
                            bootstrap_bytes,
                            &master_key,
                            Path::new(&directory),
                            non_seekable_reader_options(reader_options),
                            options,
                        )
                    } else {
                        extract_non_seekable_stream_to_dir(
                            stdin.lock(),
                            &master_key,
                            Path::new(&directory),
                            non_seekable_reader_options(reader_options),
                            options,
                        )
                    }
                } else if let Some(recipient_key) = recipient_key.as_deref() {
                    let lookup = load_recipient_private_key_lookup(recipient_key)?;
                    let mut stats = RecipientWrapOpenStats::default();
                    if let Some(bootstrap_bytes) = bootstrap_bytes.as_deref() {
                        extract_non_seekable_stream_to_dir_with_recipient_wrap_resolver_and_bootstrap_sidecar(
                            stdin.lock(),
                            bootstrap_bytes,
                            |context| recipient_wrap_candidates_for_record(context, &lookup, &mut stats),
                            Path::new(&directory),
                            non_seekable_reader_options(reader_options),
                            options,
                        )
                    } else {
                        extract_non_seekable_stream_to_dir_with_recipient_wrap_resolver(
                            stdin.lock(),
                            |context| recipient_wrap_candidates_for_record(context, &lookup, &mut stats),
                            Path::new(&directory),
                            non_seekable_reader_options(reader_options),
                            options,
                        )
                    }
                } else {
                    if let Some(bootstrap_bytes) = bootstrap_bytes.as_deref() {
                        extract_unencrypted_non_seekable_stream_to_dir_with_bootstrap_sidecar(
                            stdin.lock(),
                            bootstrap_bytes,
                            Path::new(&directory),
                            non_seekable_reader_options(reader_options),
                            options,
                        )
                    } else {
                        extract_unencrypted_non_seekable_stream_to_dir(
                            stdin.lock(),
                            Path::new(&directory),
                            non_seekable_reader_options(reader_options),
                            options,
                        )
                    }
                }
                .context("failed to extract non-seekable archive stream")?;
                emit_success_summary(
                    quiet,
                    &format!(
                        "extracted {} member(s), {} degraded metadata items to {} using staged non-seekable stream extraction",
                        report.extracted_member_count,
                        report.degraded_metadata_count,
                        directory
                    ),
                )?;
                return Ok(());
            }
            let selection = resolve_archive_input_paths(&archive, &volumes, bootstrap.is_none())?;
            let opened = if let Some(recipient_key) = recipient_key.as_deref() {
                open_selection_with_recipient_key(
                    &selection,
                    recipient_key,
                    bootstrap.as_deref(),
                    reader_options,
                )
                .map(|opened_selection| opened_selection.opened)
            } else {
                let master_key = load_open_key_from_paths(
                    keyfile.as_deref(),
                    password_stdin,
                    password,
                    insecure_zero_key,
                    &selection.paths,
                )?;
                open_selection_maybe_bootstrap(
                    &selection,
                    &master_key,
                    bootstrap.as_deref(),
                    reader_options,
                )
            }
            .with_context(|| format!("failed to open archive {archive}"))?;
            let (requested_entries, missing_paths) = if stdout || dry_run || !paths.is_empty() {
                resolve_extract_index_entries(&opened, &paths)?
            } else {
                (Vec::new(), Vec::new())
            };
            if !missing_paths.is_empty() {
                for missing in missing_paths {
                    eprintln!("missing archive path: {missing}");
                }
                return Err(anyhow!("missing requested archive paths"));
            }
            if stdout {
                let path = requested_entries[0].path.as_str();
                let mut stdout = io::stdout().lock();
                let diagnostics = match opened.extract_file_to_writer(path, &mut stdout) {
                    Ok(Some(diagnostics)) => diagnostics,
                    Ok(None) => bail!("path not found in archive: {path}"),
                    Err(ExtractError::Format(FormatError::ReaderUnsupported(message)))
                        if message.contains("regular file") =>
                    {
                        bail!("--stdout supports regular file members only");
                    }
                    Err(err) => return Err(err.into()),
                };
                stdout.flush()?;
                emit_member_metadata_diagnostics(quiet, path, &diagnostics)?;
                return Ok(());
            }

            if dry_run {
                eprintln!("extract dry-run summary:");
                eprintln!("  destination: {}", directory);
                eprintln!("  archive members:");
                for entry in &requested_entries {
                    eprintln!("    {} ({} bytes)", entry.path, entry.file_data_size);
                }
                return Ok(());
            }

            let root = PathBuf::from(directory);
            fs::create_dir_all(&root).with_context(|| {
                format!("failed to create extraction directory {}", root.display())
            })?;
            let mut extracted_count = 0u64;
            let mut degraded_metadata_count = 0u64;
            let options = SafeExtractionOptions {
                overwrite_existing: overwrite,
                restore_policy: restore.into(),
                allow_degraded,
                system_authorized: restore == CliRestorePolicy::System,
                allow_absolute_symlinks,
            };
            let diagnostics = if paths.is_empty() {
                opened.extract_indexed_files_to(&root, options, reader_options.jobs)?
            } else {
                opened.extract_selected_files_to(&paths, &root, options, reader_options.jobs)?
            };
            for (path, diagnostics) in diagnostics {
                extracted_count = extracted_count
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("extracted path count overflow"))?;
                degraded_metadata_count = degraded_metadata_count
                    .checked_add(diagnostics.len() as u64)
                    .ok_or_else(|| anyhow!("degraded metadata count overflow"))?;
                emit_member_metadata_diagnostics(quiet, &path, &diagnostics)?;
            }
            emit_success_summary(
                quiet,
                &format!(
                    "extracted {extracted_count} file(s), {degraded_metadata_count} degraded metadata items to {}",
                    root.display()
                ),
            )?;
            Ok(())
}

pub(crate) struct ExtractArgs {
    pub(crate) archive: String,
    pub(crate) paths: Vec<String>,
    pub(crate) directory: String,
    pub(crate) stdout: bool,
    pub(crate) dry_run: bool,
    pub(crate) overwrite: bool,
    pub(crate) restore: CliRestorePolicy,
    pub(crate) allow_degraded: bool,
    pub(crate) allow_absolute_symlinks: bool,
    pub(crate) password_stdin: bool,
    pub(crate) password: bool,
    pub(crate) keyfile: Option<String>,
    pub(crate) recipient_key: Option<String>,
    pub(crate) insecure_zero_key: bool,
    pub(crate) bootstrap: Option<String>,
    pub(crate) volumes: Vec<String>,
    pub(crate) jobs: Option<usize>,
}



pub(crate) fn resolve_extract_index_entries(
    opened: &OpenedArchive,
    requested: &[String],
) -> Result<(Vec<ArchiveIndexEntry>, Vec<String>)> {
    if requested.is_empty() {
        return Ok((opened.list_index_entries()?, Vec::new()));
    }

    let mut resolved = Vec::with_capacity(requested.len());
    let mut missing = Vec::new();
    for path in requested {
        match opened.lookup_index_entry(path)? {
            Some(entry) => resolved.push(entry),
            None => missing.push(path.clone()),
        }
    }
    Ok((resolved, missing))
}


pub(crate) fn reject_stdout_extract_shape(stdout: bool, path_count: usize) -> Result<()> {
    if stdout && path_count != 1 {
        return Err(anyhow!(FormatError::ReaderUnsupported(
            "--stdout requires exactly one archive path",
        )));
    }
    Ok(())
}
