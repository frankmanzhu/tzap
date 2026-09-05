use super::*;

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
#[cfg(windows)]
use tzap_core::encode_v45_sparse_map;
use tzap_core::format::FormatError;
#[cfg(any(target_os = "macos", windows))]
use tzap_core::NativeAuxiliaryNameEncoding;
use tzap_core::{
    volume_file, write_archive_sources_to_sink, write_archive_sources_to_sink_ordered_parallel,
    write_archive_sources_to_sink_ordered_parallel_with_recipient_wrap_records, write_sized_raw_member_archive_to_sink_with_kdf_and_root_auth,
    write_tar_stream_archive_to_sink_with_kdf_and_root_auth, AeadAlgo, ArchiveTimestamp, ArchiveWriteError, ArchiveWriteSink, MasterKey, MemoryArchiveSink,
    NativeFileMetadata, PortableFileMetadata, RegularFileSource, RootAuthSigningRequest, RootAuthWriterConfig, SourceEntryKind, SparseExtent,
    StreamingRawWriterSummary, StreamingTarWriterSummary, WriterOptions, WrittenArchiveSummary,
};
use tzap_plugin_signing::ed25519_raw::{self, ED25519_AUTHENTICATOR_ID, ED25519_AUTHENTICATOR_VALUE_LEN};

use plaintext_spool::{spool_unknown_size_raw_stdin, ExplicitPlaintextSpool};

/// §27: the create summary states the chosen parity and the resilience
/// guarantee in plain English.
fn create_summary_fec_fragment(options: &WriterOptions, tolerance: u8) -> String {
    let resilience = match tolerance {
        0 => "no volume-loss tolerance".to_string(),
        1 => "survives loss of any 1 volume".to_string(),
        t => format!("survives loss of any {t} volumes"),
    };
    format!("data:parity {}:{}, {resilience}", options.fec_data_shards, options.fec_parity_shards)
}

pub(crate) fn run_create(quiet: bool, args: CreateArgs) -> Result<()> {
    let CreateArgs {
        output,
        volumes,
        volume_size,
        volume_loss_tolerance,
        bit_rot_buffer_pct,
        password_stdin,
        password,
        keyfile,
        recipient_cert,
        no_encryption,
        insecure_zero_key,
        force,
        argon2_t_cost,
        argon2_m_cost_kib,
        argon2_parallelism,
        dictionary,
        signing_key,
        signing_cert,
        signing_private_key,
        signing_chain,
        x509_signature_scheme,
        bootstrap_out,
        tar_stdin,
        raw_stdin,
        stdin_name,
        stdin_size,
        spool_stdin,
        compression_level,
        chunk_size,
        envelope_size,
        block_size,
        jobs,
        timings,
        dry_run,
        paths,
    } = args;

    let create_total_started = Instant::now();
    let jobs = resolve_jobs(jobs)?;
    let resolved_volume_loss_tolerance =
        resolve_create_volume_loss_tolerance(volume_loss_tolerance, volumes, volume_size.as_deref(), tar_stdin || raw_stdin || spool_stdin);
    let layout_overrides =
        CreateLayoutOverrides { chunk_size: chunk_size.as_deref(), envelope_size: envelope_size.as_deref(), block_size: block_size.as_deref() };
    let build_writer_options = |total_input_size: Option<u64>| -> Result<WriterOptions> {
        let mut options = create_writer_options(CreateWriterOptionsArgs {
            volumes,
            volume_size: volume_size.as_deref(),
            volume_loss_tolerance: resolved_volume_loss_tolerance,
            bit_rot_buffer_pct,
            compression_level,
            jobs,
            layout_overrides,
            total_input_size,
        })?;
        if no_encryption {
            options.aead_algo = AeadAlgo::None;
        }
        Ok(options)
    };
    validate_create_key_source(keyfile.as_deref(), recipient_cert.as_deref(), password_stdin, password, no_encryption, insecure_zero_key)?;
    if bootstrap_out.is_some() && (volumes.unwrap_or(1) > 1 || volume_size.is_some()) {
        return Err(FormatError::WriterUnsupported("--bootstrap-out is currently supported only for single-volume output").into());
    }
    reject_create_stdout_sentinels(&output, bootstrap_out.as_deref())?;
    let stdin_mode = validate_create_stdin_mode(CreateStdinArgs {
        tar_stdin,
        raw_stdin,
        stdin_name: stdin_name.as_deref(),
        stdin_size: stdin_size.as_deref(),
        spool_stdin,
        paths: &paths,
        password_stdin,
        password,
        has_dictionary: dictionary.is_some(),
        volumes,
        volume_size: volume_size.as_deref(),
        volume_loss_tolerance,
    })?;
    validate_create_recipient_wrap_scope(
        recipient_cert.as_deref(),
        stdin_mode,
        dictionary.is_some(),
        signing_key.is_some() || signing_cert.is_some(),
        volumes,
        volume_size.as_deref(),
    )?;

    ensure_create_output_paths_can_be_written(&output, volumes, volume_size.is_some(), bootstrap_out.as_deref(), force)?;
    if let Some(stdin_mode) = stdin_mode {
        if dry_run {
            let dry_run_input_size = match stdin_mode {
                CreateStdinMode::RawKnownSize => Some(parse_size(stdin_size.as_deref().expect("validated stdin-size"))?),
                CreateStdinMode::Tar | CreateStdinMode::RawSpool | CreateStdinMode::RawUnknownSize => None,
            };
            let options = build_writer_options(dry_run_input_size)?;
            validate_create_writer_options(&options)?;
        }
        if dry_run {
            eprintln!("create dry-run summary:");
            eprintln!("  files: streaming stdin");
            eprintln!("  input bytes: unknown until stdin is consumed");
            eprintln!(
                "  key mode: {}",
                create_key_mode_label(keyfile.as_deref(), recipient_cert.as_deref(), password_stdin, password, no_encryption, insecure_zero_key)
            );
            eprintln!("  root auth: {}", create_root_auth_mode_label(signing_key.as_deref(), signing_cert.as_deref()));
            eprintln!("  volume mode: {}", describe_planned_volume_mode(volumes, volume_size.as_deref()));
            eprintln!("  planned archive paths:");
            for path in create_dry_run_output_paths(&output, volumes, volume_size.is_some()) {
                eprintln!("    {path}");
            }
            if let Some(bootstrap_path) = bootstrap_out.as_ref() {
                eprintln!("  bootstrap: {}", bootstrap_path);
            }
            return Ok(());
        }

        if matches!(stdin_mode, CreateStdinMode::RawUnknownSize) {
            return Err(FormatError::WriterUnsupported("unknown-size raw stdin without --spool-stdin requires the future raw_stream_v1 profile").into());
        }

        let key = load_create_key(
            keyfile.as_deref(),
            password_stdin,
            password,
            no_encryption,
            insecure_zero_key,
            argon2_t_cost,
            argon2_m_cost_kib,
            argon2_parallelism,
        )?;
        let root_auth_profile = load_create_root_auth_profile(
            signing_key.as_deref(),
            signing_cert.as_deref(),
            signing_private_key.as_deref(),
            &signing_chain,
            x509_signature_scheme,
        )?;
        let root_auth = root_auth_profile.as_ref().map(CreateRootAuthProfile::root_auth_writer_config).transpose()?;
        let core_writer_started = Instant::now();
        let (bootstrap_sidecar, summary_text, writer_timings) = match stdin_mode {
            CreateStdinMode::Tar => {
                let options = build_writer_options(None)?;
                validate_create_writer_options(&options)?;
                let fec_fragment = create_summary_fec_fragment(&options, resolved_volume_loss_tolerance);
                let (summary, bootstrap_sidecar) = write_tar_stdin_archive_output(&output, &key, options, root_auth, root_auth_profile.as_ref(), force)?;
                let summary_text = format!(
                    "created {} member(s), {} tar bytes in, {} archive bytes, {} volume(s), {}, bit-rot buffer {}%",
                    summary.input_member_count,
                    summary.input_tar_bytes,
                    summary.archive.archive_bytes,
                    summary.archive.volume_count,
                    fec_fragment,
                    bit_rot_buffer_pct
                );
                (bootstrap_sidecar, summary_text, summary.archive.timings)
            }
            CreateStdinMode::RawKnownSize => {
                let stdin_size = parse_size(stdin_size.as_deref().expect("validated stdin-size"))?;
                let options = build_writer_options(Some(stdin_size))?;
                validate_create_writer_options(&options)?;
                let fec_fragment = create_summary_fec_fragment(&options, resolved_volume_loss_tolerance);
                let (summary, bootstrap_sidecar) = write_raw_stdin_archive_output(
                    &output,
                    io::stdin().lock(),
                    stdin_name.as_deref().expect("validated stdin-name"),
                    stdin_size,
                    &key,
                    options,
                    root_auth,
                    root_auth_profile.as_ref(),
                    force,
                )?;
                let summary_text = format!(
                    "created 1 member(s), {} raw bytes in, {} archive bytes, {} volume(s), {}, bit-rot buffer {}%",
                    summary.input_bytes, summary.archive.archive_bytes, summary.archive.volume_count, fec_fragment, bit_rot_buffer_pct
                );
                (bootstrap_sidecar, summary_text, summary.archive.timings)
            }
            CreateStdinMode::RawSpool => {
                let stdin = io::stdin();
                let mut stdin_lock = stdin.lock();
                let spool = spool_unknown_size_raw_stdin(&mut stdin_lock, u64::MAX, ExplicitPlaintextSpool::acknowledge_plaintext_spool())?;
                let known_size_source = spool.known_size_source();
                let spool_reader = spool.reopen()?;
                let options = build_writer_options(Some(known_size_source.size()))?;
                validate_create_writer_options(&options)?;
                let fec_fragment = create_summary_fec_fragment(&options, resolved_volume_loss_tolerance);
                let (summary, bootstrap_sidecar) = write_raw_stdin_archive_output(
                    &output,
                    spool_reader,
                    stdin_name.as_deref().expect("validated stdin-name"),
                    known_size_source.size(),
                    &key,
                    options,
                    root_auth,
                    root_auth_profile.as_ref(),
                    force,
                )?;
                let summary_text = format!(
                    "created 1 member(s), {} spooled raw bytes in, {} archive bytes, {} volume(s), {}, bit-rot buffer {}%",
                    summary.input_bytes, summary.archive.archive_bytes, summary.archive.volume_count, fec_fragment, bit_rot_buffer_pct
                );
                (bootstrap_sidecar, summary_text, summary.archive.timings)
            }
            CreateStdinMode::RawUnknownSize => unreachable!("rejected before key loading"),
        };
        let core_writer = core_writer_started.elapsed();
        let write_outputs_started = Instant::now();
        if let Some(path) = bootstrap_out.as_deref() {
            if bootstrap_sidecar.is_empty() {
                return Err(FormatError::WriterUnsupported("bootstrap output is unavailable for this archive shape").into());
            }
            write_bootstrap_output_with_archive_rollback(path, &bootstrap_sidecar, &output, 1, force)?;
        }
        let write_outputs = write_outputs_started.elapsed();
        emit_success_summary(quiet, &summary_text)?;
        if let Some(profile) = root_auth_profile.as_ref() {
            emit_success_summary(quiet, &format!("  root auth: {} signed", profile.label()))?;
        }
        if let Some(path) = bootstrap_out.as_ref() {
            emit_success_summary(quiet, &format!("  bootstrap output: {}", path))?;
        }
        if timings {
            emit_sink_backed_create_timing_report(
                Duration::default(),
                Duration::default(),
                core_writer,
                write_outputs,
                create_total_started.elapsed(),
                writer_timings,
            )?;
        }
        return Ok(());
    }
    let scan_inputs_started = Instant::now();
    let input_specs = collect_input_specs(&paths)?;
    let scan_inputs = scan_inputs_started.elapsed();
    let bootstrap_output = bootstrap_out.clone();
    let input_bytes = input_specs_total_size(&input_specs)?;
    let options = build_writer_options(Some(input_bytes))?;
    validate_create_writer_options(&options)?;

    if dry_run {
        eprintln!("create dry-run summary:");
        eprintln!("  files: {}", input_specs.len());
        eprintln!("  input bytes: {}", input_bytes);
        eprintln!(
            "  key mode: {}",
            create_key_mode_label(keyfile.as_deref(), recipient_cert.as_deref(), password_stdin, password, no_encryption, insecure_zero_key)
        );
        eprintln!("  root auth: {}", create_root_auth_mode_label(signing_key.as_deref(), signing_cert.as_deref()));
        eprintln!("  volume mode: {}", describe_planned_volume_mode(volumes, volume_size.as_deref()));
        eprintln!("  planned archive paths:");
        for path in create_dry_run_output_paths(&output, volumes, volume_size.is_some()) {
            eprintln!("    {path}");
        }
        if let Some(bootstrap_path) = bootstrap_output {
            eprintln!("  bootstrap: {}", bootstrap_path);
        }
        return Ok(());
    }

    if let Some(recipient_cert_path) = recipient_cert.as_deref() {
        let fec_fragment = create_summary_fec_fragment(&options, resolved_volume_loss_tolerance);
        let mut recipient_options = options;
        let master_key = generate_random_master_key()?;
        let recipient_record = build_recipient_wrap_record(recipient_cert_path, &master_key, &mut recipient_options)?;
        let core_writer_started = Instant::now();
        let (archive, bootstrap_sidecar) =
            write_file_inputs_ordered_parallel_recipient_wrap_to_output(&output, &input_specs, &master_key, recipient_options, recipient_record, force)
                .context("failed to create recipient-wrap archive")?;
        let core_writer = core_writer_started.elapsed();

        let write_outputs_started = Instant::now();
        if let Some(path) = bootstrap_out.as_deref() {
            if bootstrap_sidecar.is_empty() {
                return Err(FormatError::WriterUnsupported("bootstrap output is unavailable for this archive shape").into());
            }
            write_bootstrap_output_with_archive_rollback(path, &bootstrap_sidecar, &output, archive.volume_count, force)?;
        }
        let write_outputs = write_outputs_started.elapsed();
        let summary = format!(
            "created {} member(s), {} bytes in, {} archive bytes, {} volume(s), {}, bit-rot buffer {}%",
            input_specs.len(),
            input_bytes,
            archive.archive_bytes,
            archive.volume_count,
            fec_fragment,
            bit_rot_buffer_pct
        );
        emit_success_summary(quiet, &summary)?;
        emit_success_summary(quiet, "  key wrap: recipient certificate")?;
        if let Some(path) = bootstrap_output {
            emit_success_summary(quiet, &format!("  bootstrap output: {}", path))?;
        }
        if timings {
            emit_sink_backed_create_timing_report(
                scan_inputs,
                Duration::default(),
                core_writer,
                write_outputs,
                create_total_started.elapsed(),
                archive.timings,
            )?;
        }
        return Ok(());
    }

    let key =
        load_create_key(keyfile.as_deref(), password_stdin, password, no_encryption, insecure_zero_key, argon2_t_cost, argon2_m_cost_kib, argon2_parallelism)?;
    let dictionary_bytes = dictionary.as_deref().map(|path| fs::read(path).with_context(|| format!("failed to read dictionary {path}"))).transpose()?;
    let root_auth_profile =
        load_create_root_auth_profile(signing_key.as_deref(), signing_cert.as_deref(), signing_private_key.as_deref(), &signing_chain, x509_signature_scheme)?;
    let root_auth = root_auth_profile.as_ref().map(CreateRootAuthProfile::root_auth_writer_config).transpose()?;

    if dictionary_bytes.is_none() && options.target_volume_size.is_none() && options.volume_loss_tolerance == 0 {
        let fec_fragment = create_summary_fec_fragment(&options, resolved_volume_loss_tolerance);
        let core_writer_started = Instant::now();
        let (archive, bootstrap_sidecar) =
            write_file_inputs_ordered_parallel_to_output(&output, &input_specs, &key, options, root_auth, root_auth_profile.as_ref(), force)
                .context("failed to create archive")?;
        let core_writer = core_writer_started.elapsed();

        let write_outputs_started = Instant::now();
        if let Some(path) = bootstrap_out.as_deref() {
            if bootstrap_sidecar.is_empty() {
                return Err(FormatError::WriterUnsupported("bootstrap output is unavailable for this archive shape").into());
            }
            write_bootstrap_output_with_archive_rollback(path, &bootstrap_sidecar, &output, archive.volume_count, force)?;
        }
        let write_outputs = write_outputs_started.elapsed();
        let summary = format!(
            "created {} member(s), {} bytes in, {} archive bytes, {} volume(s), {}, bit-rot buffer {}%",
            input_specs.len(),
            input_bytes,
            archive.archive_bytes,
            archive.volume_count,
            fec_fragment,
            bit_rot_buffer_pct
        );
        emit_success_summary(quiet, &summary)?;
        if let Some(profile) = root_auth_profile.as_ref() {
            emit_success_summary(quiet, &format!("  root auth: {} signed", profile.label()))?;
        }
        if let Some(path) = bootstrap_output {
            emit_success_summary(quiet, &format!("  bootstrap output: {}", path))?;
        }
        if timings {
            emit_sink_backed_create_timing_report(
                scan_inputs,
                Duration::default(),
                core_writer,
                write_outputs,
                create_total_started.elapsed(),
                archive.timings,
            )?;
        }
        return Ok(());
    }

    let read_inputs = Duration::default();
    let core_writer_started = Instant::now();
    let mut archive_sink = MemoryArchiveSink::default();
    let fec_fragment = create_summary_fec_fragment(&options, resolved_volume_loss_tolerance);
    let archive = if let (Some(root_auth), Some(profile)) = (root_auth, root_auth_profile.as_ref()) {
        let mut authenticator = |request: &RootAuthSigningRequest| root_auth_authenticator_value(profile, request);
        write_archive_sources_to_sink(
            &input_specs,
            &key.master_key,
            options,
            dictionary_bytes.as_deref(),
            &key.kdf_params,
            Some(root_auth),
            Some(&mut authenticator),
            &mut archive_sink,
        )
    } else {
        write_archive_sources_to_sink(&input_specs, &key.master_key, options, dictionary_bytes.as_deref(), &key.kdf_params, None, None, &mut archive_sink)
    }
    .context("failed to create archive")?;
    let core_writer = core_writer_started.elapsed();

    let output_paths = create_output_paths(&output, archive_sink.volumes.len());
    if !force {
        check_archive_paths_free_for_write(&output_paths)?;
    }
    if let Some(bootstrap_path) = &bootstrap_output {
        if !force {
            check_output_path_free("bootstrap", Path::new(bootstrap_path))?;
        }
    }

    let write_outputs_started = Instant::now();
    write_archive_outputs_with_optional_bootstrap(&output, &archive_sink.volumes, bootstrap_out.as_deref(), &archive_sink.bootstrap_sidecar, force)?;
    let write_outputs = write_outputs_started.elapsed();
    let summary = format!(
        "created {} member(s), {} bytes in, {} archive bytes, {} volume(s), {}, bit-rot buffer {}%",
        input_specs.len(),
        input_bytes,
        archive_sink.volumes.iter().map(|volume| volume.len() as u64).sum::<u64>(),
        archive_sink.volumes.len(),
        fec_fragment,
        bit_rot_buffer_pct
    );
    emit_success_summary(quiet, &summary)?;
    if let Some(profile) = root_auth_profile.as_ref() {
        emit_success_summary(quiet, &format!("  root auth: {} signed", profile.label()))?;
    }
    if let Some(path) = bootstrap_output {
        emit_success_summary(quiet, &format!("  bootstrap output: {}", path))?;
    }
    if timings {
        emit_create_timing_report(scan_inputs, read_inputs, core_writer, write_outputs, create_total_started.elapsed(), archive.timings)?;
    }
    Ok(())
}

pub(crate) struct CreateArgs {
    pub(crate) output: String,
    pub(crate) volumes: Option<u32>,
    pub(crate) volume_size: Option<String>,
    pub(crate) volume_loss_tolerance: Option<u8>,
    pub(crate) bit_rot_buffer_pct: u8,
    pub(crate) password_stdin: bool,
    pub(crate) password: bool,
    pub(crate) keyfile: Option<String>,
    pub(crate) recipient_cert: Option<String>,
    pub(crate) no_encryption: bool,
    pub(crate) insecure_zero_key: bool,
    pub(crate) force: bool,
    pub(crate) argon2_t_cost: u32,
    pub(crate) argon2_m_cost_kib: u32,
    pub(crate) argon2_parallelism: u32,
    pub(crate) dictionary: Option<String>,
    pub(crate) signing_key: Option<String>,
    pub(crate) signing_cert: Option<String>,
    pub(crate) signing_private_key: Option<String>,
    pub(crate) signing_chain: Vec<String>,
    pub(crate) x509_signature_scheme: Option<CliX509SignatureScheme>,
    pub(crate) bootstrap_out: Option<String>,
    pub(crate) tar_stdin: bool,
    pub(crate) raw_stdin: bool,
    pub(crate) stdin_name: Option<String>,
    pub(crate) stdin_size: Option<String>,
    pub(crate) spool_stdin: bool,
    pub(crate) compression_level: i32,
    pub(crate) chunk_size: Option<String>,
    pub(crate) envelope_size: Option<String>,
    pub(crate) block_size: Option<String>,
    pub(crate) jobs: Option<usize>,
    pub(crate) timings: bool,
    pub(crate) dry_run: bool,
    pub(crate) paths: Vec<String>,
}

pub(crate) type CliRootAuthAuthenticator<'a> = dyn FnMut(&RootAuthSigningRequest) -> std::result::Result<Vec<u8>, FormatError> + 'a;

#[derive(Debug, Clone, Copy)]
pub(crate) struct CreateLayoutOverrides<'a> {
    pub(crate) chunk_size: Option<&'a str>,
    pub(crate) envelope_size: Option<&'a str>,
    pub(crate) block_size: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CreateLayout {
    pub(crate) block_size: u32,
    pub(crate) chunk_size: u32,
    pub(crate) envelope_target_size: u32,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CreateWriterOptionsArgs<'a> {
    pub(crate) volumes: Option<u32>,
    pub(crate) volume_size: Option<&'a str>,
    pub(crate) volume_loss_tolerance: u8,
    pub(crate) bit_rot_buffer_pct: u8,
    pub(crate) compression_level: i32,
    pub(crate) jobs: usize,
    pub(crate) layout_overrides: CreateLayoutOverrides<'a>,
    pub(crate) total_input_size: Option<u64>,
}

pub(crate) fn create_writer_options(args: CreateWriterOptionsArgs<'_>) -> Result<WriterOptions> {
    let layout = resolve_create_layout(args.layout_overrides, args.total_input_size)?;
    Ok(WriterOptions {
        stripe_width: args.volumes.unwrap_or(1),
        target_volume_size: args.volume_size.map(|value| parse_size(value).with_context(|| UsageError("invalid volume-size"))).transpose()?,
        volume_loss_tolerance: args.volume_loss_tolerance,
        bit_rot_buffer_pct: args.bit_rot_buffer_pct,
        zstd_level: args.compression_level,
        jobs: args.jobs,
        chunk_size: layout.chunk_size,
        envelope_target_size: layout.envelope_target_size,
        block_size: layout.block_size,
        ..WriterOptions::default()
    })
}

pub(crate) fn resolve_create_layout(overrides: CreateLayoutOverrides<'_>, total_input_size: Option<u64>) -> Result<CreateLayout> {
    let mut layout = default_create_layout(total_input_size);
    if let Some(value) = overrides.block_size {
        layout.block_size = parse_size_u32(value, "block-size").with_context(|| UsageError("invalid block-size"))?;
    }
    if let Some(value) = overrides.envelope_size {
        layout.envelope_target_size = parse_size_u32(value, "envelope-size").with_context(|| UsageError("invalid envelope-size"))?;
    }
    if let Some(value) = overrides.chunk_size {
        layout.chunk_size = parse_size_u32(value, "chunk-size").with_context(|| UsageError("invalid chunk-size"))?;
        if overrides.envelope_size.is_none() && layout.chunk_size > layout.envelope_target_size {
            layout.envelope_target_size = layout.chunk_size;
        }
    }
    Ok(layout)
}

pub(crate) fn default_create_layout(total_input_size: Option<u64>) -> CreateLayout {
    match total_input_size {
        Some(size) if size <= LARGE_CREATE_LAYOUT_THRESHOLD => {
            CreateLayout { block_size: 64 * 1024, chunk_size: 256 * 1024, envelope_target_size: 1024 * 1024 }
        }
        Some(_) | None => CreateLayout { block_size: 1024 * 1024, chunk_size: 32 * 1024 * 1024, envelope_target_size: 64 * 1024 * 1024 },
    }
}

#[derive(Debug)]
pub(crate) struct InputSpec {
    pub(crate) source: PathBuf,
    pub(crate) archive_path: String,
    pub(crate) entry_kind: SourceEntryKind,
    pub(crate) link_target: Option<Vec<u8>>,
    pub(crate) mode: u32,
    pub(crate) mtime: ArchiveTimestamp,
    pub(crate) portable_metadata: PortableFileMetadata,
    pub(crate) size: u64,
    pub(crate) sparse_extents: Option<Vec<SparseExtent>>,
    pub(crate) identity: InputIdentity,
}

impl RegularFileSource for InputSpec {
    fn archive_path(&self) -> &str {
        &self.archive_path
    }

    fn entry_kind(&self) -> SourceEntryKind {
        self.entry_kind
    }

    fn link_target(&self) -> Option<&[u8]> {
        self.link_target.as_deref()
    }

    fn file_data_size(&self) -> u64 {
        self.size
    }

    fn sparse_extents(&self) -> Option<&[SparseExtent]> {
        self.sparse_extents.as_deref()
    }

    fn mode(&self) -> u32 {
        self.mode
    }

    fn mtime(&self) -> ArchiveTimestamp {
        self.mtime
    }

    fn portable_metadata(&self) -> PortableFileMetadata {
        self.portable_metadata.clone()
    }

    fn open(&self) -> std::result::Result<Box<dyn Read + '_>, ArchiveWriteError> {
        if self.entry_kind != SourceEntryKind::Regular {
            let metadata = fs::symlink_metadata(&self.source).map_err(ArchiveWriteError::Io)?;
            let actual = input_identity(&metadata).map_err(ArchiveWriteError::Io)?;
            #[cfg(windows)]
            let actual = {
                let mut actual = actual;
                let file = open_windows_metadata_handle(&self.source).map_err(ArchiveWriteError::Io)?;
                augment_windows_input_identity(&mut actual, &file).map_err(ArchiveWriteError::Io)?;
                actual
            };
            let kind_matches = match self.entry_kind {
                SourceEntryKind::Directory => metadata.is_dir(),
                SourceEntryKind::Symlink => metadata.file_type().is_symlink(),
                SourceEntryKind::Hardlink => metadata.is_file(),
                #[cfg(unix)]
                SourceEntryKind::CharacterDevice => {
                    use std::os::unix::fs::FileTypeExt;
                    metadata.file_type().is_char_device()
                }
                #[cfg(not(unix))]
                SourceEntryKind::CharacterDevice => false,
                #[cfg(unix)]
                SourceEntryKind::BlockDevice => {
                    use std::os::unix::fs::FileTypeExt;
                    metadata.file_type().is_block_device()
                }
                #[cfg(not(unix))]
                SourceEntryKind::BlockDevice => false,
                #[cfg(unix)]
                SourceEntryKind::Fifo => {
                    use std::os::unix::fs::FileTypeExt;
                    metadata.file_type().is_fifo()
                }
                #[cfg(not(unix))]
                SourceEntryKind::Fifo => false,
                #[cfg(windows)]
                SourceEntryKind::ReparseDirectory => open_windows_metadata_handle(&self.source)
                    .and_then(|file| query_windows_reparse_data(&file))
                    .and_then(|data| validate_windows_known_reparse_data(&data))
                    .is_ok_and(|kind| matches!(kind, WindowsKnownReparse::Junction | WindowsKnownReparse::Opaque) && metadata.is_dir()),
                #[cfg(not(windows))]
                SourceEntryKind::ReparseDirectory => false,
                #[cfg(windows)]
                SourceEntryKind::ReparseRegular => open_windows_metadata_handle(&self.source)
                    .and_then(|file| query_windows_reparse_data(&file))
                    .and_then(|data| validate_windows_known_reparse_data(&data))
                    .is_ok_and(|kind| kind == WindowsKnownReparse::Opaque && !metadata.is_dir()),
                #[cfg(not(windows))]
                SourceEntryKind::ReparseRegular => false,
                SourceEntryKind::Regular => false,
            };
            let target_matches = if self.entry_kind == SourceEntryKind::Symlink {
                #[cfg(windows)]
                let actual_target = open_windows_metadata_handle(&self.source)
                    .and_then(|file| query_windows_reparse_data(&file))
                    .and_then(|data| validate_windows_known_reparse_data(&data))
                    .ok()
                    .and_then(|kind| match kind {
                        WindowsKnownReparse::RelativeSymlink { portable_target } => Some(portable_target),
                        WindowsKnownReparse::Junction | WindowsKnownReparse::Opaque => None,
                    });
                #[cfg(not(windows))]
                let actual_target = symlink_target_bytes(&self.source).ok();
                actual_target.as_deref() == self.link_target.as_deref()
            } else {
                true
            };
            if !kind_matches || !target_matches || !input_identity_matches_after_read(self.identity, actual) {
                return Err(ArchiveWriteError::Io(io::Error::other("non-regular input changed after scan")));
            }
            return Ok(Box::new(io::empty()));
        }
        let file = File::open(&self.source).map_err(ArchiveWriteError::Io)?;
        validate_opened_input_identity(&file, self.identity).map_err(ArchiveWriteError::Io)?;
        if let Some(extents) = self.sparse_extents.as_deref() {
            return Ok(Box::new(SparseExtentInputReader {
                file,
                expected: self.identity,
                expected_extents: extents,
                extent_index: 0,
                extent_remaining: 0,
                validated: false,
            }) as Box<dyn Read + '_>);
        }
        Ok(Box::new(IdentityCheckedInputReader { file, expected: self.identity, remaining: self.size, validated: false }) as Box<dyn Read + '_>)
    }

    fn open_auxiliary(&self, ordinal: usize) -> std::result::Result<Box<dyn Read + '_>, ArchiveWriteError> {
        let record = self.portable_metadata.native.auxiliary_records.get(ordinal).ok_or(FormatError::WriterInvariant("auxiliary source ordinal is missing"))?;
        if !record.is_streamed() {
            return Ok(Box::new(io::Cursor::new(record.payload.as_slice())));
        }
        #[cfg(target_os = "macos")]
        {
            if record.kind != "macos.resource-fork" || record.name_encoding != NativeAuxiliaryNameEncoding::None || !record.name.is_empty() {
                return Err(FormatError::WriterUnsupported("unsupported streamed macOS auxiliary source").into());
            }
            let source = if self.entry_kind == SourceEntryKind::Symlink {
                MacosResourceForkSource::Symlink(open_macos_symlink(&self.source).map_err(ArchiveWriteError::Io)?)
            } else {
                let file = File::open(&self.source).map_err(ArchiveWriteError::Io)?;
                open_macos_resource_fork_for_read(file).map_err(ArchiveWriteError::Io)?
            };
            Ok(Box::new(MacosResourceForkReader::new(source, self.identity, Some(record.logical_size)).map_err(ArchiveWriteError::Io)?))
        }
        #[cfg(windows)]
        {
            if record.kind == "windows.efs-raw" {
                if record.name_encoding != NativeAuxiliaryNameEncoding::None || !record.name.is_empty() {
                    return Err(FormatError::WriterUnsupported("raw EFS auxiliary source has an unexpected name").into());
                }
                return Ok(Box::new(WindowsRawEfsReader::spawn(self.source.clone(), self.identity, record.stored_payload_size())));
            }
            if record.kind != "windows.alternate-data" || record.name_encoding != NativeAuxiliaryNameEncoding::Utf16Le || record.name.len() % 2 != 0 {
                return Err(FormatError::WriterUnsupported("unsupported streamed Windows auxiliary source").into());
            }
            let metadata = fs::symlink_metadata(&self.source).map_err(ArchiveWriteError::Io)?;
            let mut actual = input_identity(&metadata).map_err(ArchiveWriteError::Io)?;
            let base = open_windows_metadata_handle(&self.source).map_err(ArchiveWriteError::Io)?;
            augment_windows_input_identity(&mut actual, &base).map_err(ArchiveWriteError::Io)?;
            if !input_identity_matches_after_read(self.identity, actual) {
                return Err(ArchiveWriteError::Io(io::Error::other("Windows input changed before alternate-stream read")));
            }
            let stream_path = windows_alternate_stream_path(&self.source, &record.name).map_err(ArchiveWriteError::Io)?;
            let stream = File::open(stream_path).map_err(ArchiveWriteError::Io)?;
            if stream.metadata().map_err(ArchiveWriteError::Io)?.len() != record.logical_size {
                return Err(ArchiveWriteError::Io(io::Error::other("Windows alternate stream changed after scan")));
            }
            if let Some(extents) = record.streamed_sparse_extents() {
                let map = encode_v45_sparse_map(extents, record.logical_size)?;
                return Ok(Box::new(io::Cursor::new(map).chain(WindowsSparseAlternateStreamReader {
                    file: stream,
                    logical_size: record.logical_size,
                    expected_extents: extents.to_vec(),
                    extent_index: 0,
                    extent_remaining: 0,
                    validated: false,
                })));
            }
            Ok(Box::new(stream))
        }
        #[cfg(not(any(windows, target_os = "macos")))]
        Err(FormatError::WriterUnsupported("streamed Windows auxiliary sources require Windows").into())
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum CreateStdinMode {
    Tar,
    RawUnknownSize,
    RawKnownSize,
    RawSpool,
}

#[derive(Debug)]
pub(crate) struct CreateStdinArgs<'a> {
    pub(crate) tar_stdin: bool,
    pub(crate) raw_stdin: bool,
    pub(crate) stdin_name: Option<&'a str>,
    pub(crate) stdin_size: Option<&'a str>,
    pub(crate) spool_stdin: bool,
    pub(crate) paths: &'a [String],
    pub(crate) password_stdin: bool,
    pub(crate) password: bool,
    pub(crate) has_dictionary: bool,
    pub(crate) volumes: Option<u32>,
    pub(crate) volume_size: Option<&'a str>,
    pub(crate) volume_loss_tolerance: Option<u8>,
}
pub(crate) fn collect_input_specs(paths: &[String]) -> Result<Vec<InputSpec>> {
    let mut out = Vec::new();
    for path in paths {
        let input = PathBuf::from(path);
        let base = input.file_name().and_then(OsStr::to_str).ok_or_else(|| anyhow!("input path has no valid UTF-8 file name: {path}"))?.to_owned();
        collect_one_input_spec(&input, Path::new(&base), &mut out).with_context(|| format!("failed to collect input {path}"))?;
    }
    out.sort_by(|left, right| left.archive_path.cmp(&right.archive_path));
    #[cfg(any(unix, windows))]
    apply_selected_hardlink_topology(&mut out)?;
    Ok(out)
}

#[cfg(any(unix, windows))]
pub(crate) fn apply_selected_hardlink_topology(specs: &mut [InputSpec]) -> Result<()> {
    let mut selected_objects = BTreeMap::<(u64, u64), usize>::new();
    for index in 0..specs.len() {
        let spec = &specs[index];
        if spec.entry_kind != SourceEntryKind::Regular || spec.identity.link_count < 2 {
            continue;
        }
        #[cfg(unix)]
        let identity = (spec.identity.dev, spec.identity.ino);
        #[cfg(windows)]
        let identity = (spec.identity.volume_serial, spec.identity.file_index);
        if let Some(&canonical_index) = selected_objects.get(&identity) {
            let canonical = &specs[canonical_index];
            if canonical.identity != spec.identity {
                bail!("selected hardlink identity changed while grouping inputs");
            }
            let (canonical_target, mode, mtime, mut portable_metadata) =
                (canonical.archive_path.as_bytes().to_vec(), canonical.mode, canonical.mtime, canonical.portable_metadata.clone());
            // A hardlink alias owns topology, not a second file object.
            // Creation/access times belong to the canonical inode and would
            // otherwise introduce source-OS primary keys on an alias whose
            // v45 declaration is intentionally portable-only.
            portable_metadata.created = None;
            portable_metadata.accessed = None;
            portable_metadata.native = NativeFileMetadata::default();
            let alias = &mut specs[index];
            alias.entry_kind = SourceEntryKind::Hardlink;
            alias.link_target = Some(canonical_target);
            alias.mode = mode;
            alias.mtime = mtime;
            alias.portable_metadata = portable_metadata;
            alias.size = 0;
            alias.sparse_extents = None;
        } else {
            selected_objects.insert(identity, index);
        }
    }
    Ok(())
}

pub(crate) fn input_specs_total_size(specs: &[InputSpec]) -> Result<u64> {
    specs.iter().try_fold(0u64, |sum, entry| sum.checked_add(entry.size).ok_or_else(|| anyhow!("input byte count overflow")))
}

pub(crate) fn collect_one_input_spec(input: &Path, archive_path: &Path, out: &mut Vec<InputSpec>) -> Result<()> {
    #[cfg(windows)]
    use std::os::windows::fs::MetadataExt as _;

    let metadata = fs::symlink_metadata(input).with_context(|| format!("failed to inspect input {}", input.display()))?;
    #[cfg(windows)]
    if metadata.file_attributes() & 0x0000_1000 != 0 {
        // This must precede every handle open, reparse query, directory enumeration, and data
        // read. Cloud providers may combine OFFLINE with REPARSE_POINT, and touching the
        // placeholder through those paths can hydrate it before the ordinary-file guard runs.
        bail!("Windows metadata capture does not support {}: offline/cloud placeholders require an explicit hydration policy", input.display());
    }
    #[cfg(windows)]
    if metadata.file_attributes() & 0x0000_0400 != 0 {
        return collect_windows_known_reparse_input(input, archive_path, metadata, out);
    }
    if metadata.file_type().is_symlink() {
        let archive_path = archive_path_to_string(archive_path)?;
        let identity = input_identity(&metadata).with_context(|| format!("failed to identify symlink {}", input.display()))?;
        let link_target = symlink_target_bytes(input).with_context(|| format!("failed to read symlink {}", input.display()))?;
        out.push(InputSpec {
            source: input.to_owned(),
            archive_path,
            entry_kind: SourceEntryKind::Symlink,
            link_target: Some(link_target),
            mode: readonly_mode(&metadata),
            mtime: identity.mtime,
            portable_metadata: portable_symlink_metadata(identity, input)?,
            size: 0,
            sparse_extents: None,
            identity,
        });
        return Ok(());
    }
    if metadata.is_dir() {
        #[cfg(windows)]
        if metadata.file_attributes() & 0x0000_4000 != 0 {
            bail!(
                "Windows metadata capture does not support encrypted directory {}: raw EFS directory import requires a distinct CREATE_FOR_DIR restore path",
                input.display()
            );
        }
        let archive_path_string = archive_path_to_string(archive_path)?;
        let identity = input_identity(&metadata).with_context(|| format!("failed to identify input {}", input.display()))?;
        #[cfg(windows)]
        let identity = {
            let mut identity = identity;
            let file = open_windows_metadata_handle(input).with_context(|| format!("failed to open Windows directory {}", input.display()))?;
            augment_windows_input_identity(&mut identity, &file).with_context(|| format!("failed to identify Windows directory {}", input.display()))?;
            identity
        };
        let portable_metadata = portable_input_metadata(identity, input)?;
        out.push(InputSpec {
            source: input.to_owned(),
            archive_path: archive_path_string,
            entry_kind: SourceEntryKind::Directory,
            link_target: None,
            mode: readonly_mode(&metadata),
            mtime: identity.mtime,
            portable_metadata,
            size: 0,
            sparse_extents: None,
            identity,
        });
        let mut entries = fs::read_dir(input).with_context(|| format!("failed to read directory {}", input.display()))?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let child_name = entry.file_name().into_string().map_err(|_| anyhow!("input path is not valid UTF-8"))?;
            collect_one_input_spec(&entry.path(), &archive_path.join(child_name), out)?;
        }
        return Ok(());
    }
    #[cfg(unix)]
    {
        #[cfg(target_os = "linux")]
        use std::os::linux::fs::MetadataExt as _;
        #[cfg(target_os = "macos")]
        use std::os::macos::fs::MetadataExt as _;
        use std::os::unix::fs::FileTypeExt as _;

        let file_type = metadata.file_type();
        let entry_kind = if file_type.is_char_device() {
            Some(SourceEntryKind::CharacterDevice)
        } else if file_type.is_block_device() {
            Some(SourceEntryKind::BlockDevice)
        } else if file_type.is_fifo() {
            Some(SourceEntryKind::Fifo)
        } else {
            None
        };
        if let Some(entry_kind) = entry_kind {
            let archive_path = archive_path_to_string(archive_path)?;
            let identity = input_identity(&metadata).with_context(|| format!("failed to identify input {}", input.display()))?;
            let mut portable_metadata = portable_input_metadata(identity, input)?;
            portable_metadata.native.required_profiles.push("posix-backup-v1".into());
            if matches!(entry_kind, SourceEntryKind::CharacterDevice | SourceEntryKind::BlockDevice) {
                let device = libc::dev_t::try_from(metadata.st_rdev()).map_err(|_| anyhow!("device identifier exceeds host ABI"))?;
                let major = libc::major(device);
                let minor = libc::minor(device);
                portable_metadata.native.primary_pax_records.insert("TZAP.posix.device-major".into(), major.to_string().into_bytes());
                portable_metadata.native.primary_pax_records.insert("TZAP.posix.device-minor".into(), minor.to_string().into_bytes());
                #[cfg(target_os = "linux")]
                if entry_kind == SourceEntryKind::CharacterDevice && major == 0 && minor == 0 {
                    portable_metadata.native.primary_pax_records.insert("TZAP.linux.whiteout".into(), b"1".to_vec());
                    portable_metadata.native.required_profiles.push("linux-backup-v1".into());
                }
            }
            portable_metadata.native.required_profiles.sort();
            portable_metadata.native.required_profiles.dedup();
            out.push(InputSpec {
                source: input.to_owned(),
                archive_path,
                entry_kind,
                link_target: None,
                mode: readonly_mode(&metadata),
                mtime: identity.mtime,
                portable_metadata,
                size: 0,
                sparse_extents: None,
                identity,
            });
            return Ok(());
        }
    }
    if !metadata.is_file() {
        bail!("unsupported input type {}", input.display());
    }
    #[cfg(windows)]
    reject_unsupported_windows_regular_file(&metadata, input)?;
    let archive_path = archive_path_to_string(archive_path)?;
    let identity = input_identity(&metadata).with_context(|| format!("failed to identify input {}", input.display()))?;
    #[cfg(windows)]
    let (identity, sparse_extents, sparse_layout_partial) = {
        let mut identity = identity;
        let file = File::open(input).with_context(|| format!("failed to open {} for identity capture", input.display()))?;
        augment_windows_input_identity(&mut identity, &file).with_context(|| format!("failed to identify Windows input {}", input.display()))?;
        const FILE_ATTRIBUTE_SPARSE_FILE: u32 = 0x0000_0200;
        let sparse_extents = if identity.file_attributes & FILE_ATTRIBUTE_SPARSE_FILE != 0 {
            Some(
                query_windows_allocated_ranges(&file, identity.len)
                    .with_context(|| format!("failed to query sparse ranges for Windows input {}", input.display()))?,
            )
        } else {
            None
        };
        let sparse_layout_partial = sparse_extents.is_some() && windows_file_system_is_refs(&file)?;
        (identity, sparse_extents, sparse_layout_partial)
    };
    #[cfg(target_os = "linux")]
    let sparse_extents = {
        let file = File::open(input).with_context(|| format!("failed to open {} for sparse-range capture", input.display()))?;
        query_linux_sparse_extents(&file, identity.len).with_context(|| format!("failed to query sparse ranges for Linux input {}", input.display()))?
    };
    #[cfg(all(not(windows), not(target_os = "linux")))]
    let sparse_extents = None;
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut portable_metadata = portable_input_metadata(identity, input)?;
    #[cfg(windows)]
    if sparse_layout_partial {
        add_windows_refs_sparse_layout_omission(&mut portable_metadata.native);
    }
    out.push(InputSpec {
        source: input.to_owned(),
        archive_path,
        entry_kind: SourceEntryKind::Regular,
        link_target: None,
        mode: readonly_mode(&metadata),
        mtime: identity.mtime,
        portable_metadata,
        size: metadata.len(),
        sparse_extents,
        identity,
    });
    Ok(())
}

pub(crate) fn write_archive_outputs(output: &str, volumes: &[Vec<u8>], force: bool) -> Result<()> {
    if volumes.is_empty() {
        bail!("writer returned no volumes");
    }
    let output_paths = create_output_paths(output, volumes.len());
    let mut temps = create_archive_output_temps(&output_paths)?;
    for ((temp, output_path), volume) in temps.iter_mut().zip(&output_paths).zip(volumes) {
        temp.as_file_mut().write_all(volume).with_context(|| format!("failed to write temporary archive volume for {}", output_path.display()))?;
    }
    flush_archive_output_temps(&mut temps, &output_paths)?;
    publish_archive_output_temps(temps, &output_paths, force)?;
    Ok(())
}

pub(crate) fn write_archive_outputs_with_optional_bootstrap(
    output: &str,
    volumes: &[Vec<u8>],
    bootstrap_out: Option<&str>,
    bootstrap_sidecar: &[u8],
    force: bool,
) -> Result<()> {
    if bootstrap_out.is_some() && bootstrap_sidecar.is_empty() {
        return Err(FormatError::WriterUnsupported("bootstrap output is unavailable for this archive shape").into());
    }

    write_archive_outputs(output, volumes, force)?;
    if let Some(path) = bootstrap_out {
        write_bootstrap_output_with_archive_rollback(path, bootstrap_sidecar, output, volumes.len(), force)?;
    }
    Ok(())
}

pub(crate) fn write_bootstrap_output_with_archive_rollback(path: &str, bytes: &[u8], output: &str, volume_count: usize, force: bool) -> Result<()> {
    if let Err(err) = write_bootstrap_output(path, bytes, force) {
        for output_path in create_output_paths(output, volume_count) {
            let _ = fs::remove_file(output_path);
        }
        return Err(err).with_context(|| "failed to publish bootstrap output; removed archive outputs published by this command");
    }
    Ok(())
}

pub(crate) struct PathBackedArchiveSink<'a> {
    pub(crate) temps: &'a mut [tempfile::NamedTempFile],
    pub(crate) bootstrap_sidecar: Vec<u8>,
}

impl ArchiveWriteSink for PathBackedArchiveSink<'_> {
    fn begin_archive(&mut self, volume_count: usize) -> std::result::Result<(), ArchiveWriteError> {
        if volume_count != self.temps.len() {
            return Err(FormatError::WriterInvariant("stdin file sink volume count does not match output paths").into());
        }
        for temp in self.temps.iter_mut() {
            let file = temp.as_file_mut();
            file.set_len(0).map_err(ArchiveWriteError::Io)?;
            file.seek(SeekFrom::Start(0)).map_err(ArchiveWriteError::Io)?;
        }
        self.bootstrap_sidecar.clear();
        Ok(())
    }

    fn write_volume(&mut self, volume_index: usize, bytes: &[u8]) -> std::result::Result<(), ArchiveWriteError> {
        let temp = self.temps.get_mut(volume_index).ok_or(FormatError::WriterInvariant("stdin file sink volume index is out of bounds"))?;
        temp.as_file_mut().write_all(bytes).map_err(ArchiveWriteError::Io)
    }

    fn write_bootstrap_sidecar(&mut self, bytes: &[u8]) -> std::result::Result<(), ArchiveWriteError> {
        self.bootstrap_sidecar.extend_from_slice(bytes);
        Ok(())
    }
}

pub(crate) fn write_tar_stdin_archive_output(
    output: &str,
    key: &CreateKey,
    options: WriterOptions,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    root_auth_profile: Option<&CreateRootAuthProfile>,
    force: bool,
) -> Result<(StreamingTarWriterSummary, Vec<u8>)> {
    let stdin = io::stdin();
    let mut stdin_lock = stdin.lock();
    if let (Some(profile), Some(root_auth)) = (root_auth_profile, root_auth) {
        let mut authenticator = |request: &RootAuthSigningRequest| root_auth_authenticator_value(profile, request);
        return write_tar_stdin_archive_output_from_reader(output, &mut stdin_lock, key, options, Some(root_auth), Some(&mut authenticator), force);
    }
    write_tar_stdin_archive_output_from_reader(output, &mut stdin_lock, key, options, None, None, force)
}

pub(crate) fn write_tar_stdin_archive_output_from_reader<R: Read>(
    output: &str,
    reader: &mut R,
    key: &CreateKey,
    options: WriterOptions,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    authenticator: Option<&mut CliRootAuthAuthenticator<'_>>,
    force: bool,
) -> Result<(StreamingTarWriterSummary, Vec<u8>)> {
    let volume_count = options.stripe_width as usize;
    write_stdin_archive_output_with_sink(output, volume_count, force, |sink| {
        write_tar_stream_archive_to_sink_with_kdf_and_root_auth(reader, &key.master_key, options, &key.kdf_params, root_auth, authenticator, sink)
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn write_raw_stdin_archive_output<R: Read>(
    output: &str,
    mut reader: R,
    archive_path: &str,
    input_size: u64,
    key: &CreateKey,
    options: WriterOptions,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    root_auth_profile: Option<&CreateRootAuthProfile>,
    force: bool,
) -> Result<(StreamingRawWriterSummary, Vec<u8>)> {
    if let (Some(profile), Some(root_auth)) = (root_auth_profile, root_auth) {
        let mut authenticator = |request: &RootAuthSigningRequest| root_auth_authenticator_value(profile, request);
        return write_raw_stdin_archive_output_from_reader(
            output,
            &mut reader,
            archive_path,
            input_size,
            key,
            options,
            Some(root_auth),
            Some(&mut authenticator),
            force,
        );
    }
    write_raw_stdin_archive_output_from_reader(output, &mut reader, archive_path, input_size, key, options, None, None, force)
}

pub(crate) fn write_file_inputs_ordered_parallel_to_output(
    output: &str,
    input_specs: &[InputSpec],
    key: &CreateKey,
    options: WriterOptions,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    root_auth_profile: Option<&CreateRootAuthProfile>,
    force: bool,
) -> Result<(WrittenArchiveSummary, Vec<u8>)> {
    if let (Some(profile), Some(root_auth)) = (root_auth_profile, root_auth) {
        let mut authenticator = |request: &RootAuthSigningRequest| root_auth_authenticator_value(profile, request);
        return write_file_inputs_ordered_parallel_to_output_with_authenticator(
            output,
            input_specs,
            key,
            options,
            Some(root_auth),
            Some(&mut authenticator),
            force,
        );
    }
    write_file_inputs_ordered_parallel_to_output_with_authenticator(output, input_specs, key, options, None, None, force)
}

pub(crate) fn write_file_inputs_ordered_parallel_to_output_with_authenticator(
    output: &str,
    input_specs: &[InputSpec],
    key: &CreateKey,
    options: WriterOptions,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    authenticator: Option<&mut CliRootAuthAuthenticator<'_>>,
    force: bool,
) -> Result<(WrittenArchiveSummary, Vec<u8>)> {
    let volume_count = options.stripe_width as usize;
    write_stdin_archive_output_with_sink(output, volume_count, force, |sink| {
        write_archive_sources_to_sink_ordered_parallel(input_specs, &key.master_key, options, &key.kdf_params, root_auth, authenticator, sink)
    })
}

pub(crate) fn write_file_inputs_ordered_parallel_recipient_wrap_to_output(
    output: &str,
    input_specs: &[InputSpec],
    master_key: &MasterKey,
    options: WriterOptions,
    recipient_record: tzap_core::wire::RecipientRecordV1,
    force: bool,
) -> Result<(WrittenArchiveSummary, Vec<u8>)> {
    let volume_count = options.stripe_width as usize;
    write_stdin_archive_output_with_sink(output, volume_count, force, |sink| {
        write_archive_sources_to_sink_ordered_parallel_with_recipient_wrap_records(input_specs, master_key, options, vec![recipient_record], None, None, sink)
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn write_raw_stdin_archive_output_from_reader<R: Read>(
    output: &str,
    reader: &mut R,
    archive_path: &str,
    input_size: u64,
    key: &CreateKey,
    options: WriterOptions,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    authenticator: Option<&mut CliRootAuthAuthenticator<'_>>,
    force: bool,
) -> Result<(StreamingRawWriterSummary, Vec<u8>)> {
    let volume_count = options.stripe_width as usize;
    write_stdin_archive_output_with_sink(output, volume_count, force, |sink| {
        write_sized_raw_member_archive_to_sink_with_kdf_and_root_auth(
            reader,
            archive_path,
            input_size,
            &key.master_key,
            options,
            &key.kdf_params,
            root_auth,
            authenticator,
            sink,
        )
    })
}

pub(crate) fn write_stdin_archive_output_with_sink<T>(
    output: &str,
    volume_count: usize,
    force: bool,
    write_archive: impl FnOnce(&mut PathBackedArchiveSink<'_>) -> std::result::Result<T, ArchiveWriteError>,
) -> Result<(T, Vec<u8>)> {
    if volume_count == 0 {
        bail!("writer returned no volumes");
    }
    let output_paths = create_output_paths(output, volume_count);
    let mut temps = create_archive_output_temps(&output_paths)?;
    let (summary, bootstrap_sidecar) = {
        let mut sink = PathBackedArchiveSink { temps: temps.as_mut_slice(), bootstrap_sidecar: Vec::new() };
        let summary = write_archive(&mut sink)?;
        (summary, sink.bootstrap_sidecar)
    };
    flush_archive_output_temps(&mut temps, &output_paths)?;
    publish_archive_output_temps(temps, &output_paths, force)?;
    Ok((summary, bootstrap_sidecar))
}

pub(crate) fn create_archive_output_temps(output_paths: &[PathBuf]) -> Result<Vec<tempfile::NamedTempFile>> {
    output_paths
        .iter()
        .map(|output_path| {
            let parent = output_path.parent().filter(|path| !path.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
            tempfile::Builder::new()
                .prefix(".tzap-create-")
                .suffix(".partial")
                .tempfile_in(parent)
                .with_context(|| format!("failed to create temporary archive output in {}", parent.display()))
        })
        .collect()
}

pub(crate) fn flush_archive_output_temps(temps: &mut [tempfile::NamedTempFile], output_paths: &[PathBuf]) -> Result<()> {
    for (temp, output_path) in temps.iter_mut().zip(output_paths) {
        temp.as_file_mut().flush().with_context(|| format!("failed to flush temporary archive for {}", output_path.display()))?;
        temp.as_file_mut().sync_all().with_context(|| format!("failed to sync temporary archive for {}", output_path.display()))?;
    }
    Ok(())
}

pub(crate) fn publish_archive_output_temps(temps: Vec<tempfile::NamedTempFile>, output_paths: &[PathBuf], force: bool) -> Result<()> {
    let volume_count = output_paths.len();
    let publish_order = if volume_count == 1 { vec![0] } else { (1..volume_count).chain(std::iter::once(0)).collect() };
    let mut temp_slots = temps.into_iter().map(Some).collect::<Vec<_>>();
    let mut persisted_paths = Vec::new();
    for volume_index in publish_order {
        let temp = temp_slots[volume_index].take().ok_or_else(|| anyhow!("missing temporary archive volume {volume_index}"))?;
        let output_path = &output_paths[volume_index];
        let publish_result = if force { temp.persist(output_path) } else { temp.persist_noclobber(output_path) };
        if let Err(error) = publish_result {
            for path in &persisted_paths {
                let _ = fs::remove_file(path);
            }
            return Err(error.error).with_context(|| format!("failed to publish archive {}", output_path.display()));
        }
        persisted_paths.push(output_path.clone());
    }
    Ok(())
}

pub(crate) fn write_bootstrap_output(path: &str, bytes: &[u8], force: bool) -> Result<()> {
    write_atomic_output_file("bootstrap output", Path::new(path), bytes, force)
}

pub(crate) fn reject_create_stdout_sentinels(output: &str, bootstrap_out: Option<&str>) -> Result<()> {
    if output == "-" {
        return Err(anyhow!(FormatError::WriterUnsupported("--output - is not archive stdout; create output must be a file path",)));
    }
    if matches!(bootstrap_out, Some("-")) {
        return Err(anyhow!(FormatError::WriterUnsupported("--bootstrap-out - is not sidecar stdout; sidecar output must be a file path",)));
    }
    Ok(())
}

pub(crate) fn validate_create_stdin_mode(args: CreateStdinArgs<'_>) -> Result<Option<CreateStdinMode>> {
    if args.tar_stdin && args.raw_stdin {
        return Err(anyhow!(FormatError::WriterUnsupported("--tar-stdin and --raw-stdin cannot be used together",)));
    }
    if args.spool_stdin && !args.raw_stdin {
        return Err(anyhow!(FormatError::WriterUnsupported("--spool-stdin requires --raw-stdin",)));
    }
    if args.stdin_name.is_some() && !args.raw_stdin {
        return Err(anyhow!(FormatError::WriterUnsupported("--stdin-name requires --raw-stdin",)));
    }
    if args.stdin_size.is_some() && !args.raw_stdin {
        return Err(anyhow!(FormatError::WriterUnsupported("--stdin-size requires --raw-stdin",)));
    }

    let Some(mode) = (if args.tar_stdin {
        Some(CreateStdinMode::Tar)
    } else if args.raw_stdin && args.spool_stdin {
        Some(CreateStdinMode::RawSpool)
    } else if args.raw_stdin && args.stdin_size.is_some() {
        Some(CreateStdinMode::RawKnownSize)
    } else if args.raw_stdin {
        Some(CreateStdinMode::RawUnknownSize)
    } else {
        None
    }) else {
        return Ok(None);
    };

    if args.paths != ["-"] {
        return Err(anyhow!(FormatError::WriterUnsupported("stdin create modes require exactly one archive input path: -",)));
    }
    if args.password_stdin {
        return Err(anyhow!(FormatError::WriterUnsupported("--password-stdin cannot be used when stdin carries archive payload bytes",)));
    }
    if args.password {
        return Err(anyhow!(FormatError::WriterUnsupported("--password cannot be used when stdin carries archive payload bytes",)));
    }
    if args.has_dictionary {
        return Err(anyhow!(FormatError::WriterUnsupported("--dictionary is not supported with stdin create modes",)));
    }
    if args.volume_size.is_some() {
        return Err(anyhow!(FormatError::WriterUnsupported("--volume-size is not supported with stdin create modes",)));
    }
    if args.volume_loss_tolerance.unwrap_or(0) != 0 {
        return Err(anyhow!(FormatError::WriterUnsupported("--volume-loss-tolerance > 0 is not supported with stdin create modes",)));
    }
    if matches!(args.volumes, Some(volumes) if volumes > 1) && !matches!(mode, CreateStdinMode::Tar | CreateStdinMode::RawKnownSize | CreateStdinMode::RawSpool)
    {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "--volumes > 1 is supported only with --tar-stdin, known-size --raw-stdin, or --raw-stdin --spool-stdin",
        )));
    }

    match mode {
        CreateStdinMode::Tar => {
            if args.stdin_name.is_some() || args.stdin_size.is_some() || args.spool_stdin {
                return Err(anyhow!(FormatError::WriterUnsupported("--stdin-name, --stdin-size, and --spool-stdin require --raw-stdin",)));
            }
        }
        CreateStdinMode::RawUnknownSize => {
            if args.stdin_name.is_none() {
                return Err(anyhow!(FormatError::WriterUnsupported("--raw-stdin requires --stdin-name PATH",)));
            }
        }
        CreateStdinMode::RawKnownSize => {
            if args.stdin_name.is_none() {
                return Err(anyhow!(FormatError::WriterUnsupported("--raw-stdin requires --stdin-name PATH",)));
            }
            parse_size(args.stdin_size.expect("checked raw known-size stdin")).with_context(|| UsageError("invalid stdin-size"))?;
        }
        CreateStdinMode::RawSpool => {
            if args.stdin_name.is_none() {
                return Err(anyhow!(FormatError::WriterUnsupported("--raw-stdin requires --stdin-name PATH",)));
            }
            if args.stdin_size.is_some() {
                return Err(anyhow!(FormatError::WriterUnsupported("--spool-stdin is for unknown-size raw stdin; omit --stdin-size",)));
            }
        }
    }

    Ok(Some(mode))
}

pub(crate) fn ensure_create_output_paths_can_be_written(
    output: &str,
    volumes: Option<u32>,
    has_volume_size: bool,
    bootstrap_out: Option<&str>,
    force: bool,
) -> Result<()> {
    if let Some(path) = bootstrap_out {
        ensure_distinct_output_paths("archive output", Path::new(output), "bootstrap output", Path::new(path))?;
    }
    if let Some(volumes) = volumes {
        if volumes == 0 {
            bail!("--volumes must be at least 1");
        }
        if !force && volumes == 1 {
            check_output_path_free("archive output", Path::new(output))?;
        }
        if !force && volumes > 1 {
            let paths = create_output_paths(output, volumes as usize);
            check_archive_paths_free_for_write(&paths)?;
        }
        if let Some(path) = bootstrap_out {
            if !force {
                check_output_path_free("bootstrap output", Path::new(path))?;
            }
        }
        return Ok(());
    }
    if has_volume_size {
        if !force {
            check_output_path_collisions_for_volume_size_output(output)?;
            if let Some(path) = bootstrap_out {
                check_output_path_free("bootstrap output", Path::new(path))?;
            }
        }
        return Ok(());
    }
    if !force {
        check_output_path_free("archive output", Path::new(output))?;
        if let Some(path) = bootstrap_out {
            check_output_path_free("bootstrap output", Path::new(path))?;
        }
    }
    Ok(())
}

pub(crate) fn check_output_path_collisions_for_volume_size_output(output: &str) -> Result<()> {
    check_output_path_free("archive output", Path::new(output))?;
    let output_path = Path::new(output);
    // A bare relative output path (`archive.tzap`, no directory component)
    // has `parent() == Some("")`, not `None`; `unwrap_or_else` only
    // substitutes "." on `None`, so `read_dir` below used to receive the
    // empty path, fail with `NotFound`, and have that treated as "no
    // existing volumes" -- silently skipping the collision check (and thus
    // overwriting/corrupting pre-existing volume files) for the most common
    // way to invoke this from inside the destination directory.
    let parent = output_path.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let file_name = output_path.file_name().and_then(|name| name.to_str()).ok_or_else(|| anyhow!("output path has invalid UTF-8: {output}"))?;
    let base = volume_file::multi_volume_base_name(file_name);
    let entries = match fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err).with_context(|| format!("failed to inspect output directory {}", parent.display())),
    };
    for entry in entries.filter_map(|entry| entry.ok()) {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if volume_file::parse_volume_file_name(name).is_some_and(|pattern| pattern.base == base) {
            bail!("output path collision: {base}.volNNN.tzap already exists; use --force to overwrite");
        }
    }
    Ok(())
}

pub(crate) fn check_archive_paths_free_for_write(paths: &[PathBuf]) -> Result<()> {
    for path in paths {
        check_output_path_free("archive output", path)?;
    }
    Ok(())
}

pub(crate) fn resolve_create_volume_loss_tolerance(
    explicit: Option<u8>,
    volumes: Option<u32>,
    volume_size: Option<&str>,
    stdin_payload_mode_requested: bool,
) -> u8 {
    explicit.unwrap_or_else(|| if stdin_payload_mode_requested || (volumes.unwrap_or(1) <= 1 && volume_size.is_none()) { 0 } else { 1 })
}

pub(crate) fn validate_create_writer_options(options: &WriterOptions) -> Result<()> {
    if options.block_size < 4096 || options.block_size % 2 != 0 {
        return Err(anyhow!(FormatError::WriterUnsupported("writer requires an even block size of at least 4096",)));
    }
    if options.stripe_width == 0 {
        return Err(anyhow!(FormatError::WriterUnsupported("stripe_width must be non-zero",)));
    }
    let effective_stripe_width =
        if options.target_volume_size.is_some() { options.stripe_width.max(options.volume_loss_tolerance as u32 + 1) } else { options.stripe_width };
    if options.volume_loss_tolerance as u32 >= effective_stripe_width {
        return Err(anyhow!(FormatError::WriterUnsupported("volume_loss_tolerance must be less than stripe_width",)));
    }
    if effective_stripe_width == 1 && options.volume_loss_tolerance != 0 {
        return Err(anyhow!(FormatError::WriterUnsupported("single-volume archives cannot tolerate volume loss",)));
    }
    if matches!(options.target_volume_size, Some(0)) {
        return Err(anyhow!(FormatError::WriterUnsupported("target_volume_size must be non-zero",)));
    }
    if options.bit_rot_buffer_pct > 100 {
        return Err(anyhow!(FormatError::WriterUnsupported("bit_rot_buffer_pct must be at most 100",)));
    }
    if options.chunk_size == 0 || options.chunk_size > options.envelope_target_size {
        return Err(anyhow!(FormatError::WriterUnsupported("chunk_size must be non-zero and no larger than envelope_target_size",)));
    }
    Ok(())
}

pub(crate) fn create_output_paths(output: &str, volume_count: usize) -> Vec<PathBuf> {
    if volume_count == 1 {
        vec![PathBuf::from(output)]
    } else {
        (0..volume_count).map(|index| volume_file::volume_output_path(Path::new(output), index)).collect()
    }
}

pub(crate) fn create_dry_run_output_paths(output: &str, volumes: Option<u32>, has_volume_size: bool) -> Vec<String> {
    if let Some(volumes) = volumes {
        return create_output_paths(output, volumes as usize).into_iter().map(|path| path.display().to_string()).collect();
    }
    if has_volume_size {
        let first = volume_file::volume_output_path(Path::new(output), 0);
        let second = volume_file::volume_output_path(Path::new(output), 1);
        return vec![format!("{output} (if one volume is emitted)"), format!("{}, {}, ... (if split)", first.display(), second.display())];
    }
    vec![output.to_owned()]
}

pub(crate) fn describe_planned_volume_mode(volumes: Option<u32>, volume_size: Option<&str>) -> String {
    if let Some(volumes) = volumes {
        return format!("{volumes} explicit volume(s) requested");
    }
    if let Some(size) = volume_size {
        return format!("volume-size mode, target size {size}");
    }
    "single volume".to_string()
}

pub(crate) fn create_key_mode_label(
    keyfile: Option<&str>,
    recipient_cert: Option<&str>,
    password_stdin: bool,
    password: bool,
    no_encryption: bool,
    insecure_zero_key: bool,
) -> String {
    if password_stdin {
        return "password-stdin".to_string();
    }
    if password {
        return "password".to_string();
    }
    if keyfile.is_some() {
        return "keyfile".to_string();
    }
    if recipient_cert.is_some() {
        return "recipient-cert".to_string();
    }
    if no_encryption {
        return "no-encryption".to_string();
    }
    if insecure_zero_key {
        return "insecure-zero-key".to_string();
    }
    "unknown".to_string()
}

pub(crate) fn validate_create_key_source(
    keyfile: Option<&str>,
    recipient_cert: Option<&str>,
    password_stdin: bool,
    password: bool,
    no_encryption: bool,
    insecure_zero_key: bool,
) -> Result<()> {
    if insecure_zero_key {
        return Err(removed_insecure_zero_key_error().into());
    }
    let count = usize::from(keyfile.is_some())
        + usize::from(recipient_cert.is_some())
        + usize::from(password_stdin)
        + usize::from(password)
        + usize::from(no_encryption);
    if count == 0 {
        return Err(UsageError("no key source provided; use --password-stdin, --password, --keyfile PATH, --recipient-cert FILE, or --no-encryption").into());
    }
    if count > 1 {
        return Err(
            UsageError("create accepts exactly one protection mode: --keyfile, --password, --password-stdin, --recipient-cert, or --no-encryption").into()
        );
    }
    Ok(())
}

pub(crate) fn validate_create_recipient_wrap_scope(
    recipient_cert: Option<&str>,
    stdin_mode: Option<CreateStdinMode>,
    has_dictionary: bool,
    has_root_auth: bool,
    volumes: Option<u32>,
    volume_size: Option<&str>,
) -> Result<()> {
    if recipient_cert.is_none() {
        return Ok(());
    }
    if stdin_mode.is_some() {
        return Err(anyhow!(FormatError::WriterUnsupported("--recipient-cert is currently supported only for file-backed create inputs",)));
    }
    if has_dictionary {
        return Err(anyhow!(FormatError::WriterUnsupported("--recipient-cert is not yet supported with --dictionary",)));
    }
    if has_root_auth {
        return Err(anyhow!(FormatError::WriterUnsupported("--recipient-cert is not yet supported with RootAuth signing flags",)));
    }
    if volumes.unwrap_or(1) != 1 || volume_size.is_some() {
        return Err(anyhow!(FormatError::WriterUnsupported("--recipient-cert is currently supported only for single-volume create",)));
    }
    Ok(())
}

pub(crate) fn create_root_auth_mode_label(signing_key: Option<&str>, signing_cert: Option<&str>) -> String {
    if signing_key.is_some() {
        return "ed25519".to_string();
    }
    if signing_cert.is_some() {
        return "x509".to_string();
    }
    "unsigned".to_string()
}

impl CreateRootAuthProfile {
    fn label(&self) -> &'static str {
        match self {
            Self::Ed25519 { .. } => "ed25519",
            Self::X509(_) => "x509",
        }
    }

    fn root_auth_writer_config(&self) -> Result<RootAuthWriterConfig<'_>> {
        match self {
            Self::Ed25519 { signer_identity, .. } => Ok(RootAuthWriterConfig {
                authenticator_id: ED25519_AUTHENTICATOR_ID,
                signer_identity_type: 1,
                signer_identity,
                authenticator_value_length: ED25519_AUTHENTICATOR_VALUE_LEN,
            }),
            Self::X509(signer) => signer.root_auth_writer_config().map_err(Into::into),
        }
    }
}

pub(crate) fn root_auth_authenticator_value(profile: &CreateRootAuthProfile, request: &RootAuthSigningRequest) -> Result<Vec<u8>, FormatError> {
    match profile {
        CreateRootAuthProfile::Ed25519 { signing_key, .. } => Ok(ed25519_raw::authenticator_value_for_request(signing_key, request).to_vec()),
        CreateRootAuthProfile::X509(signer) => {
            signer.authenticator_value_for_request(request).map_err(|_| FormatError::WriterUnsupported("X.509 RootAuth signing failed"))
        }
    }
}
pub(crate) fn parse_size_u32(value: &str, name: &'static str) -> Result<u32> {
    let size = parse_size(value).with_context(|| format!("invalid {name}: {value}"))?;
    u32::try_from(size).with_context(|| format!("{name} exceeds u32"))
}

pub(crate) fn parse_size(value: &str) -> Result<u64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("size is empty");
    }
    let split_at = trimmed.find(|ch: char| !ch.is_ascii_digit()).unwrap_or(trimmed.len());
    let (digits, suffix) = trimmed.split_at(split_at);
    if digits.is_empty() {
        bail!("invalid size '{value}': missing size digits");
    }
    let number = digits.parse::<u64>().with_context(|| format!("invalid size '{trimmed}': bad digit sequence"))?;
    let multiplier = match suffix.to_ascii_lowercase().as_str() {
        "" => 1,
        "k" | "kb" | "kib" => 1024,
        "m" | "mb" | "mib" => 1024 * 1024,
        "g" | "gb" | "gib" => 1024 * 1024 * 1024,
        _ => bail!("invalid size '{trimmed}': unsupported suffix '{suffix}'; supported: K/KB/KiB, M/MB/MiB, G/GB/GiB"),
    };
    number.checked_mul(multiplier).ok_or_else(|| anyhow!("size overflow"))
}
