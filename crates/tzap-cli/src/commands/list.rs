use super::*;

use std::io::{self};

use anyhow::{Context, Result};
use serde_json::json;
use tzap_core::{
    list_non_seekable_stream, list_non_seekable_stream_with_bootstrap_sidecar, list_non_seekable_stream_with_recipient_wrap_resolver,
    list_non_seekable_stream_with_recipient_wrap_resolver_and_bootstrap_sidecar, list_unencrypted_non_seekable_stream,
    list_unencrypted_non_seekable_stream_with_bootstrap_sidecar,
};

pub(crate) fn run_list(quiet: bool, args: ListArgs) -> Result<()> {
    let ListArgs { archive, password_stdin, password, keyfile, recipient_key, insecure_zero_key, bootstrap, volumes, long, json, jobs } = args;

    let reader_options = reader_options(resolve_jobs(jobs)?);
    reject_multi_volume_bootstrap(1 + volumes.len(), bootstrap.as_deref())?;
    if archive == "-" {
        reject_archive_stdin_list_options(&volumes, password_stdin, password, keyfile.as_deref(), recipient_key.as_deref(), insecure_zero_key)?;
        let bootstrap_bytes = read_optional_bootstrap_sidecar(bootstrap.as_deref())?;
        let stdin = io::stdin();
        let report = if let Some(keyfile) = keyfile.as_deref() {
            let master_key = load_archive_stdin_key(Some(keyfile), password_stdin, password, insecure_zero_key)?;
            if let Some(bootstrap_bytes) = bootstrap_bytes.as_deref() {
                list_non_seekable_stream_with_bootstrap_sidecar(stdin.lock(), bootstrap_bytes, &master_key, non_seekable_reader_options(reader_options))
            } else {
                list_non_seekable_stream(stdin.lock(), &master_key, non_seekable_reader_options(reader_options))
            }
        } else if let Some(recipient_key) = recipient_key.as_deref() {
            let lookup = load_recipient_private_key_lookup(recipient_key)?;
            let mut stats = RecipientWrapOpenStats::default();
            if let Some(bootstrap_bytes) = bootstrap_bytes.as_deref() {
                list_non_seekable_stream_with_recipient_wrap_resolver_and_bootstrap_sidecar(
                    stdin.lock(),
                    bootstrap_bytes,
                    |context| recipient_wrap_candidates_for_record(context, &lookup, &mut stats),
                    non_seekable_reader_options(reader_options),
                )
            } else {
                list_non_seekable_stream_with_recipient_wrap_resolver(
                    stdin.lock(),
                    |context| recipient_wrap_candidates_for_record(context, &lookup, &mut stats),
                    non_seekable_reader_options(reader_options),
                )
            }
        } else {
            if let Some(bootstrap_bytes) = bootstrap_bytes.as_deref() {
                list_unencrypted_non_seekable_stream_with_bootstrap_sidecar(stdin.lock(), bootstrap_bytes, non_seekable_reader_options(reader_options))
            } else {
                list_unencrypted_non_seekable_stream(stdin.lock(), non_seekable_reader_options(reader_options))
            }
        }
        .context("failed to list non-seekable archive stream")?;
        emit_entry_metadata_diagnostics(quiet, &report.entries)?;
        if json {
            let files = report.index_entries.iter().map(archive_index_entry_json).collect::<Vec<_>>();
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "streaming_mode": "non-seekable",
                    "metadata_source": "index",
                    "verification": {
                        "file_count": report.verification.file_count,
                        "tar_total_size": report.verification.tar_total_size,
                    },
                    "files": files,
                }))
                .context("failed to encode list output as JSON")?
            );
            return Ok(());
        }
        if long {
            for entry in report.entries {
                let kind = archive_entry_kind_label(entry.kind);
                println!("{}\t{}\t{}\t{}\t{}", entry.file_data_size, kind, entry.mode, entry.mtime, entry.path);
            }
            return Ok(());
        }
        for entry in report.entries {
            println!("{}", entry.path);
        }
        return Ok(());
    }
    let selection = resolve_archive_input_paths(&archive, &volumes, bootstrap.is_none())?;
    let opened = if let Some(recipient_key) = recipient_key.as_deref() {
        open_selection_with_recipient_key(&selection, recipient_key, bootstrap.as_deref(), reader_options).map(|opened_selection| opened_selection.opened)
    } else {
        let master_key = load_open_key_from_paths(keyfile.as_deref(), password_stdin, password, insecure_zero_key, &selection.paths)?;
        open_selection_maybe_bootstrap(&selection, &master_key, bootstrap.as_deref(), reader_options)
    }
    .with_context(|| format!("failed to open archive {archive}"))?;
    if json {
        let files = opened.list_index_entries()?.iter().map(archive_index_entry_json).collect::<Vec<_>>();
        println!(
            "{}",
            serde_json::to_string(&json!({
                "metadata_source": "index",
                "files": files,
            }))
            .context("failed to encode list output as JSON")?
        );
        Ok(())
    } else if long {
        let entries = opened.list_index_entries()?;
        for entry in entries {
            let kind = archive_entry_kind_label(entry.kind);
            let uid = entry.uid.map_or("null".to_owned(), |v| v.to_string());
            let gid = entry.gid.map_or("null".to_owned(), |v| v.to_string());
            let uname = entry.uname.as_deref().unwrap_or("null");
            let gname = entry.gname.as_deref().unwrap_or("null");
            let created = entry.created.map_or("null".to_owned(), |t| t.to_string());
            let accessed = entry.accessed.map_or("null".to_owned(), |t| t.to_string());
            let attributes = entry.attributes.map_or("null".to_owned(), |v| format!("{:#010X}", v));
            let link_target = entry.link_target.as_deref().unwrap_or("null");
            println!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                entry.file_data_size, kind, entry.mode, entry.mtime, created, accessed, uid, gid, uname, gname, attributes, link_target, entry.path
            );
        }
        Ok(())
    } else {
        for entry in opened.list_index_entries()? {
            println!("{}", entry.path);
        }
        Ok(())
    }
}

pub(crate) struct ListArgs {
    pub(crate) archive: String,
    pub(crate) password_stdin: bool,
    pub(crate) password: bool,
    pub(crate) keyfile: Option<String>,
    pub(crate) recipient_key: Option<String>,
    pub(crate) insecure_zero_key: bool,
    pub(crate) bootstrap: Option<String>,
    pub(crate) volumes: Vec<String>,
    pub(crate) long: bool,
    pub(crate) json: bool,
    pub(crate) jobs: Option<usize>,
}
