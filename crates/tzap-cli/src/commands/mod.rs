use super::*;

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, IsTerminal, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::SigningKey;
use memmap2::Mmap;
use openssl::pkey::PKey;
use openssl::x509::X509;
use rand::RngCore;
use tzap_core::format::{
    FormatError, CRYPTO_HEADER_FIXED_LEN, FORMAT_VERSION, READER_MAX_ARGON2ID_M_COST_KIB, READER_MAX_ARGON2ID_PARALLELISM, READER_MAX_ARGON2ID_T_COST,
    VOLUME_FORMAT_REV_45, VOLUME_HEADER_LEN,
};
use tzap_core::reader::RecipientWrapRecordContext;
use tzap_core::wire::{CryptoHeader, CryptoHeaderFixed, VolumeHeader};
use tzap_core::{
    open_seekable_archive, open_seekable_archive_volumes_with_recipient_wrap_resolver_options, open_seekable_archive_with_bootstrap_sidecar_options,
    volume_file, AeadAlgo, ArchiveRepairPatch, KdfAlgo, KdfParams, MasterKey, NonSeekableReaderOptions, OpenedArchive, ReaderOptions, WriterOptions,
};
use tzap_plugin_keywrap::{
    dispatch_key_wrap_record, wrap_master_key_for_recipient, ArchiveIdentity as KeyWrapArchiveIdentity, KeyWrapOutcome, KeyWrapSuite, PrivateKeyLookup,
    RecipientRecordInput, RecipientRecordMetadata,
};
use tzap_plugin_signing::x509_chain::{self, X509RootAuthSigner};

pub(crate) mod create;
pub(crate) mod extract;
pub(crate) mod keygen;
pub(crate) mod list;
pub(crate) mod verify;

pub(crate) use crate::cli::*;
pub(crate) use crate::formatters::*;
pub(crate) use crate::os_input::*;

#[cfg(test)]
pub(crate) use create::*;
#[cfg(test)]
pub(crate) use verify::*;

pub(crate) fn resolve_jobs(jobs: Option<usize>) -> Result<usize> {
    let jobs = jobs.unwrap_or_else(default_jobs);
    if jobs == 0 {
        return Err(UsageError("--jobs must be at least 1").into());
    }
    Ok(jobs)
}

#[derive(Debug)]
pub(crate) struct UsageError(pub(crate) &'static str);

impl std::fmt::Display for UsageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for UsageError {}

#[derive(Debug, Clone)]
pub(crate) struct ArchiveInputSelection {
    pub(crate) paths: Vec<String>,
    pub(crate) autodiscovered: bool,
}

pub(crate) struct OpenedArchiveSelection {
    pub(crate) paths: Vec<String>,
    pub(crate) opened: OpenedArchive,
}

#[derive(Debug)]
pub(crate) struct CliRecipientPrivateKeyLookup {
    pub(crate) private_key_bytes: Vec<u8>,
    pub(crate) private_key_spki_der: Option<Vec<u8>>,
}

impl PrivateKeyLookup for CliRecipientPrivateKeyLookup {
    fn lookup_private_key(
        &self,
        _archive_identity: &KeyWrapArchiveIdentity,
        _metadata: &RecipientRecordMetadata,
        recipient_identity_bytes: &[u8],
    ) -> Option<Vec<u8>> {
        if let Some(private_key_spki_der) = self.private_key_spki_der.as_ref() {
            let certificate = X509::from_der(recipient_identity_bytes).ok()?;
            let certificate_spki_der = certificate.public_key().ok()?.public_key_to_der().ok()?;
            if certificate_spki_der != *private_key_spki_der {
                return None;
            }
        }
        Some(self.private_key_bytes.clone())
    }
}

#[derive(Debug, Default)]
pub(crate) struct RecipientWrapOpenStats {
    pub(crate) records_seen: usize,
    pub(crate) no_matching_private_key: usize,
    pub(crate) invalid_record_or_unwrap: usize,
    pub(crate) policy_rejected: usize,
    pub(crate) unsupported_record: usize,
    pub(crate) candidate_count: usize,
}

pub(crate) struct RepairedArchiveOutput {
    pub(crate) path: String,
    pub(crate) volume_index: u32,
    pub(crate) repaired_block_count: usize,
}

pub(crate) fn resolve_archive_input_paths(primary: &str, additional: &[String], allow_autodiscovery: bool) -> Result<ArchiveInputSelection> {
    let mut paths = Vec::with_capacity(additional.len() + 1);
    paths.push(primary.to_owned());
    paths.extend(additional.iter().cloned());
    if !allow_autodiscovery || !additional.is_empty() || primary == "-" {
        return Ok(ArchiveInputSelection { paths, autodiscovered: false });
    }

    let Some(file_name) = Path::new(primary).file_name().and_then(|name| name.to_str()) else {
        return Ok(ArchiveInputSelection { paths, autodiscovered: false });
    };
    let Some(pattern) = volume_file::parse_volume_file_name(file_name) else {
        return Ok(ArchiveInputSelection { paths, autodiscovered: false });
    };
    let discovered = discover_volume_siblings(Path::new(primary), &pattern.base)?;
    if discovered.is_empty() {
        return Ok(ArchiveInputSelection { paths, autodiscovered: false });
    }
    Ok(ArchiveInputSelection { paths: discovered, autodiscovered: true })
}

pub(crate) enum MappedVolumeInput {
    Empty(Vec<u8>),
    Mapped(Mmap),
}

impl MappedVolumeInput {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Empty(bytes) => bytes,
            Self::Mapped(map) => map.as_ref(),
        }
    }
}

pub(crate) fn map_volume_inputs_from_paths(paths: &[String]) -> Result<Vec<MappedVolumeInput>> {
    paths
        .iter()
        .map(|path| {
            let file = File::open(path).with_context(|| format!("failed to read archive {path}"))?;
            if file.metadata().with_context(|| format!("failed to inspect archive {path}"))?.len() == 0 {
                return Ok(MappedVolumeInput::Empty(Vec::new()));
            }
            // SAFETY: the mapping is read-only and retained while verifier slices are in use.
            let map = unsafe { Mmap::map(&file) }.with_context(|| format!("failed to map archive {path}"))?;
            Ok(MappedVolumeInput::Mapped(map))
        })
        .collect()
}

pub(crate) fn open_volume_inputs_from_paths(paths: &[String]) -> Result<Vec<File>> {
    paths.iter().map(|path| File::open(path).with_context(|| format!("failed to read archive {path}"))).collect()
}

pub(crate) fn write_repaired_archive_copies(paths: &[String], opened: &OpenedArchive) -> Result<Vec<RepairedArchiveOutput>> {
    let patches = opened.repair_patches().context("failed to prepare repaired archive output")?;
    if patches.is_empty() {
        return Ok(Vec::new());
    }

    let mut path_by_volume = BTreeMap::<u32, String>::new();
    for path in paths {
        let volume_index = read_volume_index_from_path(path)?;
        if path_by_volume.insert(volume_index, path.clone()).is_some() {
            bail!("duplicate archive input for volume index {volume_index}");
        }
    }

    let mut patches_by_volume = BTreeMap::<u32, Vec<&ArchiveRepairPatch>>::new();
    for patch in &patches {
        patches_by_volume.entry(patch.volume_index).or_default().push(patch);
    }

    let mut jobs = Vec::new();
    for (volume_index, volume_patches) in patches_by_volume {
        let input_path = path_by_volume.get(&volume_index).ok_or_else(|| anyhow!("repair output references unavailable volume index {volume_index}"))?;
        let output_path = repaired_archive_output_path(input_path)?;
        if output_path.exists() {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("repaired output already exists: {}", output_path.display())).into());
        }
        jobs.push((volume_index, input_path.clone(), output_path, volume_patches));
    }

    let mut outputs: Vec<RepairedArchiveOutput> = Vec::new();
    for (volume_index, input_path, output_path, volume_patches) in jobs {
        let parent = output_path.parent().filter(|path| !path.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
        let mut temp = tempfile::Builder::new()
            .prefix(".tzap-repaired-")
            .suffix(".partial")
            .tempfile_in(parent)
            .with_context(|| format!("failed to create temporary repaired output in {}", parent.display()))?;
        let mut input = File::open(&input_path).with_context(|| format!("failed to open archive volume {}", input_path))?;
        io::copy(&mut input, temp.as_file_mut()).with_context(|| format!("failed to copy archive volume {} to {}", input_path, output_path.display()))?;

        for patch in &volume_patches {
            temp.as_file_mut()
                .seek(SeekFrom::Start(patch.record_offset))
                .with_context(|| format!("failed to seek repaired output {} to offset {}", output_path.display(), patch.record_offset))?;
            temp.as_file_mut()
                .write_all(&patch.record_bytes)
                .with_context(|| format!("failed to write repaired block {} to {}", patch.block_index, output_path.display()))?;
        }
        temp.as_file_mut().flush().with_context(|| format!("failed to flush repaired output {}", output_path.display()))?;
        temp.as_file_mut().sync_all().with_context(|| format!("failed to sync repaired output {}", output_path.display()))?;

        if let Err(error) = temp.persist_noclobber(&output_path) {
            for output in &outputs {
                let _ = fs::remove_file(&output.path);
            }
            return Err(error.error).with_context(|| format!("failed to publish repaired output {}", output_path.display()));
        }
        outputs.push(RepairedArchiveOutput { path: output_path.to_string_lossy().into_owned(), volume_index, repaired_block_count: volume_patches.len() });
    }

    Ok(outputs)
}

pub(crate) fn read_volume_index_from_path(path: &str) -> Result<u32> {
    let mut file = File::open(path).with_context(|| format!("failed to read archive {path}"))?;
    let mut header = [0u8; VOLUME_HEADER_LEN];
    file.read_exact(&mut header).with_context(|| format!("failed to read archive header {path}"))?;
    Ok(VolumeHeader::parse(&header).with_context(|| format!("failed to parse archive header {path}"))?.volume_index)
}

pub(crate) fn repaired_archive_output_path(input: &str) -> Result<PathBuf> {
    let path = Path::new(input);
    let file_name = path.file_name().and_then(|file_name| file_name.to_str()).ok_or_else(|| anyhow!("archive path has no UTF-8 file name: {input}"))?;
    let repaired_name = if let Some(pattern) = volume_file::parse_volume_file_name(file_name) {
        volume_file::volume_file_name(&format!("{}.repaired", pattern.base), pattern.volume_index)
    } else {
        let base = volume_file::multi_volume_base_name(file_name);
        if base != file_name {
            format!("{base}.repaired.tzap")
        } else {
            format!("{file_name}.repaired")
        }
    };
    Ok(path.with_file_name(repaired_name))
}

pub(crate) fn discover_volume_siblings(primary: &Path, base: &str) -> Result<Vec<String>> {
    let parent = primary.parent().unwrap_or_else(|| Path::new("."));
    let discovered = match volume_file::discover_sibling_volume_paths(parent, base) {
        Ok(paths) => paths,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err).with_context(|| format!("failed to inspect archive directory {}", parent.display())),
    };
    Ok(discovered.into_iter().map(|path| path.to_string_lossy().into_owned()).collect())
}

pub(crate) fn reject_multi_volume_bootstrap(volume_count: usize, bootstrap: Option<&str>) -> Result<()> {
    if volume_count > 1 && bootstrap.is_some() {
        return Err(anyhow!(FormatError::ReaderUnsupported("multi-volume inputs with --bootstrap are not supported; pass volume files without --bootstrap",)));
    }
    Ok(())
}

pub(crate) struct ArchiveStdinOpenOptions<'a> {
    pub(crate) paths: &'a [String],
    pub(crate) stdout: bool,
    pub(crate) volumes: &'a [String],
    pub(crate) password_stdin: bool,
    pub(crate) password: bool,
    pub(crate) keyfile: Option<&'a str>,
    pub(crate) recipient_key: Option<&'a str>,
    pub(crate) insecure_zero_key: bool,
}

pub(crate) fn reject_archive_stdin_open_options(options: ArchiveStdinOpenOptions<'_>) -> Result<()> {
    if !options.volumes.is_empty() {
        return Err(anyhow!(FormatError::ReaderUnsupported("archive stdin must be the only archive input",)));
    }
    if options.stdout {
        return Err(anyhow!(FormatError::ReaderUnsupported("--stdout is not supported for archive stdin extraction",)));
    }
    if !options.paths.is_empty() {
        return Err(anyhow!(FormatError::ReaderUnsupported("selected-path extraction is not supported for archive stdin",)));
    }
    reject_archive_stdin_key_options(options.password_stdin, options.password, options.keyfile, options.recipient_key, options.insecure_zero_key)
}

pub(crate) fn reject_archive_stdin_list_options(
    volumes: &[String],
    password_stdin: bool,
    password: bool,
    keyfile: Option<&str>,
    recipient_key: Option<&str>,
    insecure_zero_key: bool,
) -> Result<()> {
    if !volumes.is_empty() {
        return Err(anyhow!(FormatError::ReaderUnsupported("archive stdin must be the only archive input",)));
    }
    reject_archive_stdin_key_options(password_stdin, password, keyfile, recipient_key, insecure_zero_key)
}

pub(crate) fn reject_archive_stdin_key_options(
    password_stdin: bool,
    password: bool,
    _keyfile: Option<&str>,
    _recipient_key: Option<&str>,
    insecure_zero_key: bool,
) -> Result<()> {
    if insecure_zero_key {
        return Err(removed_insecure_zero_key_error().into());
    }
    if password_stdin || password {
        return Err(anyhow!(FormatError::ReaderUnsupported(
            "archive stdin currently supports raw --keyfile, --recipient-key, or no-key unencrypted archives only",
        )));
    }
    Ok(())
}

pub(crate) fn load_archive_stdin_key(keyfile: Option<&str>, password_stdin: bool, password: bool, insecure_zero_key: bool) -> Result<MasterKey> {
    reject_archive_stdin_key_options(password_stdin, password, keyfile, None, insecure_zero_key)?;
    if keyfile.is_some() {
        return load_raw_master_key(keyfile);
    }
    Err(anyhow!(FormatError::KeyMaterialMismatch).context("encrypted archive stdin requires --keyfile; unencrypted archive stdin uses no key source"))
}

pub(crate) fn read_optional_bootstrap_sidecar(path: Option<&str>) -> Result<Option<Vec<u8>>> {
    path.map(|path| fs::read(path).with_context(|| format!("failed to read bootstrap sidecar {path}"))).transpose()
}

pub(crate) fn open_inputs_maybe_bootstrap(
    volume_files: Vec<File>,
    master_key: &MasterKey,
    bootstrap: Option<&str>,
    options: ReaderOptions,
) -> Result<OpenedArchive> {
    if volume_files.len() > 1 {
        reject_multi_volume_bootstrap(volume_files.len(), bootstrap)?;
        return OpenedArchive::open_seekable_volumes_with_options(volume_files, master_key, options).map_err(Into::into);
    }
    let volume_file = volume_files.into_iter().next().ok_or_else(|| anyhow!("at least one archive volume is required"))?;
    if let Some(path) = bootstrap {
        let sidecar = fs::read(path).with_context(|| format!("failed to read bootstrap sidecar {path}"))?;
        open_seekable_archive_with_bootstrap_sidecar_options(volume_file, &sidecar, master_key, options).map_err(Into::into)
    } else {
        OpenedArchive::open_seekable_volumes_with_options(vec![volume_file], master_key, options).map_err(Into::into)
    }
}

pub(crate) fn open_selection_maybe_bootstrap(
    selection: &ArchiveInputSelection,
    master_key: &MasterKey,
    bootstrap: Option<&str>,
    options: ReaderOptions,
) -> Result<OpenedArchive> {
    Ok(open_selection_maybe_bootstrap_resolved(selection, master_key, bootstrap, options)?.opened)
}

pub(crate) fn open_selection_maybe_bootstrap_resolved(
    selection: &ArchiveInputSelection,
    master_key: &MasterKey,
    bootstrap: Option<&str>,
    options: ReaderOptions,
) -> Result<OpenedArchiveSelection> {
    let volume_files = open_volume_inputs_from_paths(&selection.paths)?;
    match open_inputs_maybe_bootstrap(volume_files, master_key, bootstrap, options) {
        Ok(opened) => Ok(OpenedArchiveSelection { paths: selection.paths.clone(), opened }),
        Err(err) if selection.autodiscovered && bootstrap.is_none() && selection.paths.len() > 1 => {
            let usable_paths =
                filter_usable_autodiscovered_volume_paths(&selection.paths, master_key).with_context(|| "failed to filter autodiscovered archive volumes")?;
            if usable_paths == selection.paths {
                return Err(err);
            }
            let volume_files = open_volume_inputs_from_paths(&usable_paths)?;
            let opened = open_inputs_maybe_bootstrap(volume_files, master_key, bootstrap, options)?;
            Ok(OpenedArchiveSelection { paths: usable_paths, opened })
        }
        Err(err) => Err(err),
    }
}

pub(crate) fn open_selection_with_recipient_key(
    selection: &ArchiveInputSelection,
    recipient_key: &str,
    bootstrap: Option<&str>,
    options: ReaderOptions,
) -> Result<OpenedArchiveSelection> {
    if bootstrap.is_some() {
        return Err(anyhow!(FormatError::ReaderUnsupported("--recipient-key is not currently supported with --bootstrap",)));
    }
    let volume_files = open_volume_inputs_from_paths(&selection.paths)?;
    let lookup = load_recipient_private_key_lookup(recipient_key)?;
    let mut stats = RecipientWrapOpenStats::default();
    let opened = open_seekable_archive_volumes_with_recipient_wrap_resolver_options(
        volume_files,
        |context| recipient_wrap_candidates_for_record(context, &lookup, &mut stats),
        options,
    )
    .map_err(|err| recipient_wrap_open_error(err, &stats))
    .with_context(|| "failed to open RecipientWrap archive")?;
    Ok(OpenedArchiveSelection { paths: selection.paths.clone(), opened })
}

pub(crate) fn recipient_wrap_candidates_for_record(
    context: RecipientWrapRecordContext<'_>,
    lookup: &CliRecipientPrivateKeyLookup,
    stats: &mut RecipientWrapOpenStats,
) -> std::result::Result<Vec<[u8; 32]>, FormatError> {
    stats.records_seen += 1;
    let input = RecipientRecordInput {
        archive_identity: KeyWrapArchiveIdentity {
            archive_uuid: context.archive_identity.archive_uuid,
            session_id: context.archive_identity.session_id,
            format_version: context.archive_identity.format_version,
            volume_format_rev: context.archive_identity.volume_format_rev,
        },
        metadata: RecipientRecordMetadata {
            profile_id: context.record.profile_id,
            recipient_identity_type: context.record.recipient_identity_type,
            recipient_identity_digest: context.record.recipient_identity_digest,
        },
        recipient_identity_bytes: context.record.recipient_identity_bytes.clone(),
        profile_payload_bytes: context.record.profile_payload_bytes.clone(),
    };
    match dispatch_key_wrap_record(input, lookup) {
        KeyWrapOutcome::UnwrappedCandidateMasterKey { master_key, .. } => {
            stats.candidate_count += 1;
            Ok(vec![master_key])
        }
        KeyWrapOutcome::NoMatchingPrivateKey => {
            stats.no_matching_private_key += 1;
            Ok(Vec::new())
        }
        KeyWrapOutcome::InvalidRecord => {
            stats.invalid_record_or_unwrap += 1;
            Ok(Vec::new())
        }
        KeyWrapOutcome::CertificatePolicyRejected => {
            stats.policy_rejected += 1;
            Ok(Vec::new())
        }
        KeyWrapOutcome::UnsupportedProfileId
        | KeyWrapOutcome::UnsupportedArchiveIdentity
        | KeyWrapOutcome::UnsupportedRecipientIdentity
        | KeyWrapOutcome::UnsupportedSuite => {
            stats.unsupported_record += 1;
            Ok(Vec::new())
        }
    }
}

pub(crate) fn recipient_wrap_open_error(err: FormatError, stats: &RecipientWrapOpenStats) -> anyhow::Error {
    if !matches!(err, FormatError::KeyMaterialMismatch) {
        return anyhow!(err);
    }
    if stats.candidate_count > 0 {
        return anyhow!(err).context("recipient private key unwrapped a candidate, but archive header_hmac did not verify");
    }
    if stats.records_seen == 0 {
        return anyhow!(err).context("recipient-wrap archive has no recipient records");
    }
    if stats.policy_rejected > 0 && stats.invalid_record_or_unwrap == 0 {
        return anyhow!(err).context("recipient record matched, but was rejected by recipient certificate policy");
    }
    if stats.no_matching_private_key > 0 && stats.invalid_record_or_unwrap == 0 {
        return anyhow!(err).context("no matching recipient private key for archive");
    }
    anyhow!(err).context("recipient private key did not match any recipient record or failed recipient unwrap")
}

pub(crate) fn filter_usable_autodiscovered_volume_paths(paths: &[String], master_key: &MasterKey) -> Result<Vec<String>> {
    let mut usable = Vec::new();
    let mut first_error = None;
    for path in paths {
        let file = match File::open(path) {
            Ok(file) => file,
            Err(err) => {
                if first_error.is_none() {
                    first_error = Some(anyhow!(err).context(format!("failed to read archive {path}")));
                }
                continue;
            }
        };
        match open_seekable_archive(file, master_key) {
            Ok(_) => usable.push(path.clone()),
            Err(err) if is_single_volume_candidate_usable_error(&err) => usable.push(path.clone()),
            Err(err) => {
                if first_error.is_none() {
                    first_error = Some(anyhow!(err).context(format!("failed to open archive {path}")));
                }
            }
        }
    }
    if usable.is_empty() {
        return Err(first_error.unwrap_or_else(|| anyhow!("no autodiscovered archive volumes found")));
    }
    Ok(usable)
}

pub(crate) fn is_single_volume_candidate_usable_error(err: &FormatError) -> bool {
    matches!(err, FormatError::FecTooFewAvailableShards)
        || matches!(
            err,
            FormatError::InvalidArchive(message)
                if *message == "missing volume count exceeds volume_loss_tolerance"
        )
}

pub(crate) fn validate_verify_key_holding_key_source(
    keyfile: Option<&str>,
    recipient_key: Option<&str>,
    password_stdin: bool,
    password: bool,
    insecure_zero_key: bool,
) -> Result<()> {
    if insecure_zero_key {
        return Err(removed_insecure_zero_key_error().into());
    }
    let count = usize::from(keyfile.is_some()) + usize::from(recipient_key.is_some()) + usize::from(password_stdin) + usize::from(password);
    if count > 1 {
        return Err(UsageError("verify accepts at most one key source: --keyfile, --recipient-key, --password, or --password-stdin").into());
    }
    Ok(())
}

pub(crate) fn load_ed25519_signing_key(path: &str) -> Result<SigningKey> {
    let seed = load_32_byte_key_file("Ed25519 signing key seed", path)?;
    Ok(SigningKey::from_bytes(&seed))
}

pub(crate) fn load_create_root_auth_profile(
    signing_key: Option<&str>,
    signing_cert: Option<&str>,
    signing_private_key: Option<&str>,
    signing_chain: &[String],
    x509_signature_scheme: Option<CliX509SignatureScheme>,
) -> Result<Option<CreateRootAuthProfile>> {
    match (signing_key, signing_cert, signing_private_key) {
        (Some(path), None, None) => {
            if x509_signature_scheme.is_some() {
                return Err(UsageError("--x509-signature-scheme requires --signing-cert").into());
            }
            let signing_key = load_ed25519_signing_key(path)?;
            let signer_identity = signing_key.verifying_key().to_bytes();
            Ok(Some(CreateRootAuthProfile::Ed25519 { signing_key, signer_identity }))
        }
        (None, Some(cert_path), Some(private_key_path)) => {
            let cert = fs::read(cert_path).with_context(|| format!("failed to read signing certificate {cert_path}"))?;
            let private_key = fs::read(private_key_path).with_context(|| format!("failed to read signing private key {private_key_path}"))?;
            let chain_der = load_x509_certificate_files(signing_chain)?;
            let signed_at = current_unix_seconds()?;
            let signer = if let Some(scheme) = x509_signature_scheme {
                X509RootAuthSigner::from_pem_or_der_with_signature_scheme(&cert, &private_key, chain_der, signed_at, scheme.to_plugin_scheme())
            } else {
                X509RootAuthSigner::from_pem_or_der(&cert, &private_key, chain_der, signed_at)
            }
            .with_context(|| format!("failed to load X.509 signing profile from {cert_path}"))?;
            Ok(Some(CreateRootAuthProfile::X509(signer)))
        }
        (None, None, None) => {
            if !signing_chain.is_empty() {
                return Err(UsageError("--signing-chain requires --signing-cert").into());
            }
            if x509_signature_scheme.is_some() {
                return Err(UsageError("--x509-signature-scheme requires --signing-cert").into());
            }
            Ok(None)
        }
        _ => Err(UsageError("create requires either --signing-key or --signing-cert with --signing-private-key").into()),
    }
}

pub(crate) fn load_ed25519_public_key(path: &str) -> Result<[u8; 32]> {
    load_32_byte_key_file("Ed25519 public key", path)
}

pub(crate) fn load_x509_certificate_files(paths: &[String]) -> Result<Vec<Vec<u8>>> {
    let mut certificates = Vec::new();
    for path in paths {
        let bytes = fs::read(path).with_context(|| format!("failed to read certificate {path}"))?;
        certificates.extend(x509_chain::certificates_der_from_pem_or_der(&bytes).with_context(|| format!("failed to parse certificate {path}"))?);
    }
    Ok(certificates)
}

pub(crate) fn load_x509_trusted_roots(paths: &[String], include_official_tzap_root: bool) -> Result<Vec<Vec<u8>>> {
    let mut certificates = Vec::new();
    if include_official_tzap_root {
        certificates.push(
            x509_chain::certificate_der_from_pem_or_der(OFFICIAL_TZAP_ROOT_CERT_PEM)
                .with_context(|| format!("failed to parse embedded TZAP root certificate {OFFICIAL_TZAP_ROOT_CERT_SHA256}"))?,
        );
    }
    certificates.extend(load_x509_certificate_files(paths)?);
    Ok(certificates)
}

pub(crate) fn load_single_x509_certificate_file(label: &'static str, path: &str) -> Result<Vec<u8>> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {label} {path}"))?;
    let certificates = x509_chain::certificates_der_from_pem_or_der(&bytes).with_context(|| format!("failed to parse {label} {path}"))?;
    match certificates.as_slice() {
        [certificate] => Ok(certificate.clone()),
        [] => bail!("{label} must contain exactly one X.509 certificate"),
        _ => bail!("{label} must contain exactly one X.509 certificate"),
    }
}

pub(crate) fn load_recipient_private_key_lookup(path: &str) -> Result<CliRecipientPrivateKeyLookup> {
    let bytes = fs::read(path).with_context(|| format!("failed to read recipient key {path}"))?;
    if bytes.len() == 32 {
        return Ok(CliRecipientPrivateKeyLookup { private_key_bytes: bytes, private_key_spki_der: None });
    }
    let private_key = if bytes.starts_with(b"-----BEGIN") {
        PKey::private_key_from_pem(&bytes).with_context(|| format!("failed to parse recipient private key {path}"))?
    } else {
        PKey::private_key_from_der(&bytes).with_context(|| format!("failed to parse recipient private key {path}"))?
    };
    let private_key_bytes = private_key.private_key_to_der().with_context(|| format!("failed to normalize recipient private key {path}"))?;
    let private_key_spki_der = private_key.public_key_to_der().ok();
    Ok(CliRecipientPrivateKeyLookup { private_key_bytes, private_key_spki_der })
}

pub(crate) fn generate_random_master_key() -> Result<MasterKey> {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    MasterKey::from_raw_key(&bytes).map_err(Into::into)
}

pub(crate) fn build_recipient_wrap_record(
    recipient_cert_path: &str,
    master_key: &MasterKey,
    options: &mut WriterOptions,
) -> Result<tzap_core::wire::RecipientRecordV1> {
    let recipient_certificate = load_single_x509_certificate_file("recipient certificate", recipient_cert_path)?;
    let archive_identity = recipient_wrap_archive_identity_for_writer(options);
    let master_key_bytes = master_key.0;
    for suite in [KeyWrapSuite::X25519HkdfSha256ChaCha20Poly1305, KeyWrapSuite::P256HkdfSha256Aes256Gcm] {
        match wrap_master_key_for_recipient(archive_identity.clone(), &recipient_certificate, &master_key_bytes, suite) {
            Ok(record) => return Ok(record),
            Err(KeyWrapOutcome::InvalidRecord) | Err(KeyWrapOutcome::UnsupportedSuite) => {}
            Err(outcome) => return Err(key_wrap_outcome_error(outcome)),
        }
    }
    Err(anyhow!(FormatError::WriterUnsupported("recipient certificate is not supported by keywrap-v1 suites",)))
}

pub(crate) fn recipient_wrap_archive_identity_for_writer(options: &mut WriterOptions) -> KeyWrapArchiveIdentity {
    let archive_uuid = *options.archive_uuid.get_or_insert_with(random_16_bytes);
    let session_id = *options.session_id.get_or_insert_with(random_16_bytes);
    KeyWrapArchiveIdentity { archive_uuid, session_id, format_version: FORMAT_VERSION, volume_format_rev: VOLUME_FORMAT_REV_45 }
}

pub(crate) fn random_16_bytes() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

pub(crate) fn key_wrap_outcome_error(outcome: KeyWrapOutcome) -> anyhow::Error {
    match outcome {
        KeyWrapOutcome::UnsupportedProfileId => anyhow!(FormatError::ReaderUnsupported("unsupported keywrap recipient profile",)),
        KeyWrapOutcome::UnsupportedArchiveIdentity => anyhow!(FormatError::ReaderUnsupported("unsupported keywrap archive identity",)),
        KeyWrapOutcome::UnsupportedRecipientIdentity => anyhow!(FormatError::ReaderUnsupported("unsupported keywrap recipient identity",)),
        KeyWrapOutcome::UnsupportedSuite => anyhow!(FormatError::ReaderUnsupported("unsupported keywrap recipient suite",)),
        KeyWrapOutcome::CertificatePolicyRejected => anyhow!(FormatError::ReaderUnsupported("recipient certificate policy rejected",)),
        KeyWrapOutcome::InvalidRecord => anyhow!(FormatError::InvalidArchive("invalid keywrap recipient record",)),
        KeyWrapOutcome::NoMatchingPrivateKey => anyhow!(FormatError::KeyMaterialMismatch).context("no matching recipient private key for archive"),
        KeyWrapOutcome::UnwrappedCandidateMasterKey { .. } => anyhow!(FormatError::WriterInvariant("keywrap success outcome cannot be converted to error",)),
    }
}

pub(crate) fn current_unix_seconds() -> Result<i64> {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH).context("system clock is before the Unix epoch")?.as_secs();
    i64::try_from(seconds).context("current Unix timestamp exceeds i64")
}

pub(crate) fn load_32_byte_key_file(label: &'static str, path: &str) -> Result<[u8; 32]> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {label} {path}"))?;
    if bytes.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        return Ok(out);
    }

    let hex = std::str::from_utf8(&bytes).with_context(|| format!("{label} must contain either 32 raw bytes or 64 hex characters"))?.trim();
    if hex.len() != 64 {
        bail!("{label} must contain either 32 raw bytes or 64 hex characters");
    }
    let mut out = [0u8; 32];
    for (idx, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        out[idx] = decode_hex_byte(chunk)?;
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn load_create_key(
    keyfile: Option<&str>,
    password_stdin: bool,
    password: bool,
    no_encryption: bool,
    insecure_zero_key: bool,
    t_cost: u32,
    m_cost_kib: u32,
    parallelism: u32,
) -> Result<CreateKey> {
    if password_stdin {
        let passphrase = read_passphrase_stdin()?;
        validate_argon2_params(t_cost, m_cost_kib, parallelism)?;
        let mut salt = vec![0u8; DEFAULT_ARGON2_SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        let kdf_params = KdfParams::Argon2id { t_cost, m_cost_kib, parallelism, salt };
        let master_key = MasterKey::derive_from_passphrase(&kdf_params, &passphrase)?;
        return Ok(CreateKey { master_key, kdf_params });
    }
    if password {
        let passphrase = read_passphrase_interactive_create()?;
        validate_argon2_params(t_cost, m_cost_kib, parallelism)?;
        let mut salt = vec![0u8; DEFAULT_ARGON2_SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        let kdf_params = KdfParams::Argon2id { t_cost, m_cost_kib, parallelism, salt };
        let master_key = MasterKey::derive_from_passphrase(&kdf_params, &passphrase)?;
        return Ok(CreateKey { master_key, kdf_params });
    }
    if no_encryption {
        return Ok(CreateKey { master_key: insecure_zero_master_key()?, kdf_params: KdfParams::None });
    }
    if insecure_zero_key {
        return Err(removed_insecure_zero_key_error().into());
    }
    Ok(CreateKey { master_key: load_raw_master_key(keyfile)?, kdf_params: KdfParams::Raw })
}

pub(crate) fn load_open_key_from_paths(
    keyfile: Option<&str>,
    password_stdin: bool,
    password: bool,
    insecure_zero_key: bool,
    volume_paths: &[String],
) -> Result<MasterKey> {
    if password_stdin {
        let passphrase = read_passphrase_stdin()?;
        let kdf_params = read_kdf_params_from_any_volume_path(volume_paths)?;
        return derive_key_from_passphrase(&kdf_params, &passphrase);
    }
    if password {
        let passphrase = read_passphrase_interactive_open()?;
        let kdf_params = read_kdf_params_from_any_volume_path(volume_paths)?;
        return derive_key_from_passphrase(&kdf_params, &passphrase);
    }
    if insecure_zero_key {
        return Err(removed_insecure_zero_key_error().into());
    }
    if keyfile.is_some() {
        return load_raw_master_key(keyfile);
    }
    let protection = read_archive_protection_from_any_volume_path(volume_paths)?;
    if protection.aead_algo == AeadAlgo::None && protection.kdf_algo == KdfAlgo::None {
        return insecure_zero_master_key();
    }
    Err(anyhow!(FormatError::KeyMaterialMismatch).context("encrypted archives require --keyfile, --password, or --password-stdin"))
}

pub(crate) fn insecure_zero_master_key() -> Result<MasterKey> {
    MasterKey::from_raw_key(&INSECURE_ZERO_KEY).map_err(Into::into)
}

pub(crate) fn derive_key_from_passphrase(kdf_params: &KdfParams, passphrase: &str) -> Result<MasterKey> {
    match kdf_params {
        KdfParams::Argon2id { .. } => MasterKey::derive_from_passphrase(kdf_params, passphrase).map_err(Into::into),
        KdfParams::Raw => Err(anyhow!(FormatError::KeyMaterialMismatch).context("raw-key archives require --keyfile, not passphrase input")),
        KdfParams::RecipientWrap { .. } => {
            Err(anyhow!(FormatError::KeyMaterialMismatch).context("recipient-wrap archives require recipient key unwrap, not passphrase input"))
        }
        KdfParams::None => Err(anyhow!(FormatError::KeyMaterialMismatch).context("unencrypted archives do not use passphrase input")),
    }
}

pub(crate) fn validate_argon2_params(t_cost: u32, m_cost_kib: u32, parallelism: u32) -> Result<()> {
    if t_cost == 0 {
        return Err(anyhow!(FormatError::InvalidKdfParams("argon2 t_cost must be at least 1",)));
    }
    if t_cost > READER_MAX_ARGON2ID_T_COST {
        return Err(anyhow!(FormatError::InvalidKdfParams("argon2 t_cost exceeds reader maximum",)));
    }
    if parallelism == 0 {
        return Err(anyhow!(FormatError::InvalidKdfParams("argon2 parallelism must be at least 1",)));
    }
    if parallelism > READER_MAX_ARGON2ID_PARALLELISM {
        return Err(anyhow!(FormatError::InvalidKdfParams("argon2 parallelism exceeds reader maximum",)));
    }
    if m_cost_kib > READER_MAX_ARGON2ID_M_COST_KIB {
        return Err(anyhow!(FormatError::InvalidKdfParams("argon2 memory cost exceeds reader maximum",)));
    }
    let min_memory = parallelism.checked_mul(8).ok_or_else(|| anyhow!(FormatError::InvalidKdfParams("argon2 memory per lane computation overflows",)))?;
    if m_cost_kib < min_memory {
        return Err(anyhow!(FormatError::InvalidKdfParams("argon2 memory must be at least 8 KiB per lane",)));
    }
    Ok(())
}

pub(crate) fn load_raw_master_key(keyfile: Option<&str>) -> Result<MasterKey> {
    let keyfile = keyfile.ok_or_else(|| {
        anyhow!("no key source provided; use --password-stdin, --password, --keyfile PATH, --recipient-cert FILE, or --no-encryption for create")
    })?;
    let bytes = fs::read(keyfile).with_context(|| format!("failed to read keyfile {keyfile}"))?;
    if bytes.len() == 32 {
        return MasterKey::from_raw_key(&bytes).map_err(Into::into);
    }

    let hex = std::str::from_utf8(&bytes).context("keyfile must contain either 32 raw bytes or 64 hex characters")?.trim();
    if hex.len() != 64 {
        bail!("keyfile must contain either 32 raw bytes or 64 hex characters");
    }
    let mut raw = [0u8; 32];
    for (idx, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        raw[idx] = decode_hex_byte(chunk)?;
    }
    MasterKey::from_raw_key(&raw).map_err(Into::into)
}

pub(crate) fn read_passphrase_stdin() -> Result<String> {
    let mut passphrase = String::new();
    io::stdin().read_to_string(&mut passphrase).context("failed to read passphrase from stdin")?;
    if passphrase.ends_with('\n') {
        passphrase.pop();
        if passphrase.ends_with('\r') {
            passphrase.pop();
        }
    }
    if passphrase.is_empty() {
        bail!("passphrase must not be empty");
    }
    Ok(passphrase)
}

pub(crate) fn read_passphrase_interactive_create() -> Result<String> {
    loop {
        let first = read_passphrase_interactive("Passphrase: ")?;
        let second = read_passphrase_interactive("Confirm passphrase: ")?;
        if first == second {
            return Ok(first);
        }
        eprintln!("Passphrases do not match; try again.");
    }
}

pub(crate) fn read_passphrase_interactive_open() -> Result<String> {
    read_passphrase_interactive("Passphrase: ")
}

pub(crate) fn read_passphrase_interactive(prompt: &str) -> Result<String> {
    if !io::stdin().is_terminal() {
        eprint!("{prompt}");
        io::stderr().flush()?;
        return read_non_empty_passphrase(read_passphrase_stdin_fallback()?);
    }

    let passphrase = match read_passphrase_hidden(prompt) {
        Ok(passphrase) => passphrase,
        Err(err) => {
            let _ = err;
            eprint!("{prompt}");
            io::stderr().flush()?;
            read_passphrase_stdin_fallback()?
        }
    };
    read_non_empty_passphrase(passphrase)
}

pub(crate) fn read_non_empty_passphrase(passphrase: String) -> Result<String> {
    if passphrase.is_empty() {
        bail!("passphrase must not be empty");
    }
    Ok(passphrase)
}

pub(crate) fn read_passphrase_hidden(prompt: &str) -> Result<String> {
    Ok(rpassword::prompt_password(prompt)?)
}

pub(crate) fn read_passphrase_stdin_fallback() -> Result<String> {
    let mut passphrase = String::new();
    io::stdin().read_line(&mut passphrase).context("failed to read passphrase from stdin")?;
    if passphrase.ends_with('\n') {
        passphrase.pop();
        if passphrase.ends_with('\r') {
            passphrase.pop();
        }
    }
    Ok(passphrase)
}

#[cfg(test)]
pub(crate) fn read_kdf_params_from_volume(bytes: &[u8]) -> Result<KdfParams> {
    let header_bytes = bytes.get(..VOLUME_HEADER_LEN).ok_or_else(|| anyhow!(FormatError::InvalidArchive("volume is too short for VolumeHeader")))?;
    let volume_header = VolumeHeader::parse(header_bytes)?;
    let offset = volume_header.crypto_header_offset as usize;
    let length = volume_header.crypto_header_length as usize;
    let end = offset.checked_add(length).ok_or_else(|| anyhow!(FormatError::InvalidArchive("CryptoHeader range overflow")))?;
    let crypto_header_bytes = bytes.get(offset..end).ok_or_else(|| anyhow!(FormatError::InvalidArchive("volume is too short for CryptoHeader")))?;
    Ok(read_archive_protection_from_headers(header_bytes, crypto_header_bytes)?.kdf_params)
}

pub(crate) fn read_kdf_params_from_volume_path(path: &str) -> Result<KdfParams> {
    Ok(read_archive_protection_from_volume_path(path)?.kdf_params)
}

#[derive(Debug)]
pub(crate) struct ArchiveProtection {
    pub(crate) aead_algo: AeadAlgo,
    pub(crate) kdf_algo: KdfAlgo,
    pub(crate) kdf_params: KdfParams,
}

pub(crate) fn read_archive_protection_from_volume_path(path: &str) -> Result<ArchiveProtection> {
    let mut file = File::open(path).with_context(|| format!("failed to open archive {path}"))?;
    let mut header_bytes = vec![0u8; VOLUME_HEADER_LEN];
    file.read_exact(&mut header_bytes).with_context(|| format!("failed to read VolumeHeader from {path}"))?;
    let volume_header = VolumeHeader::parse(&header_bytes)?;
    let offset = volume_header.crypto_header_offset as u64;
    let length = volume_header.crypto_header_length as usize;
    file.seek(SeekFrom::Start(offset)).with_context(|| format!("failed to seek to CryptoHeader in {path}"))?;
    let mut crypto_header_bytes = vec![0u8; length];
    file.read_exact(&mut crypto_header_bytes).with_context(|| format!("failed to read CryptoHeader from {path}"))?;
    read_archive_protection_from_headers(&header_bytes, &crypto_header_bytes)
}

pub(crate) fn read_kdf_params_from_any_volume_path(paths: &[String]) -> Result<KdfParams> {
    let mut first_error = None;
    for path in paths {
        match read_kdf_params_from_volume_path(path) {
            Ok(params) => return Ok(params),
            Err(err) => {
                if first_error.is_none() {
                    first_error = Some(err);
                }
            }
        }
    }
    Err(first_error.unwrap_or_else(|| anyhow!("at least one archive volume is required"))).context("failed to read KDF parameters from any archive volume")
}

pub(crate) fn read_archive_protection_from_any_volume_path(paths: &[String]) -> Result<ArchiveProtection> {
    let mut first_error = None;
    for path in paths {
        match read_archive_protection_from_volume_path(path) {
            Ok(protection) => return Ok(protection),
            Err(err) => {
                if first_error.is_none() {
                    first_error = Some(err);
                }
            }
        }
    }
    Err(first_error.unwrap_or_else(|| anyhow!("at least one archive volume is required"))).context("failed to read protection mode from any archive volume")
}

pub(crate) fn read_archive_protection_from_headers(header_bytes: &[u8], crypto_header_bytes: &[u8]) -> Result<ArchiveProtection> {
    let volume_header = VolumeHeader::parse(header_bytes)?;
    let fixed_bytes = crypto_header_bytes.get(..CRYPTO_HEADER_FIXED_LEN).ok_or_else(|| {
        anyhow!(FormatError::InvalidLength { structure: "CryptoHeaderFixed", expected: CRYPTO_HEADER_FIXED_LEN, actual: crypto_header_bytes.len() })
    })?;
    let fixed = CryptoHeaderFixed::parse(fixed_bytes, volume_header.crypto_header_length)?;
    if fixed.stripe_width != volume_header.stripe_width {
        return Err(anyhow!(FormatError::InvalidArchive("VolumeHeader and CryptoHeader stripe_width differ")));
    }
    let crypto_header = CryptoHeader::parse(crypto_header_bytes, volume_header.crypto_header_length)?;
    Ok(ArchiveProtection { aead_algo: fixed.aead_algo, kdf_algo: fixed.kdf_algo, kdf_params: crypto_header.kdf_params })
}

pub(crate) fn decode_hex_byte(bytes: &[u8]) -> Result<u8> {
    Ok((decode_hex_nibble(bytes[0])? << 4) | decode_hex_nibble(bytes[1])?)
}

pub(crate) fn decode_hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => bail!("keyfile contains non-hex characters"),
    }
}

pub(crate) fn default_jobs() -> usize {
    std::thread::available_parallelism().map(|jobs| jobs.get()).unwrap_or(1)
}
pub(crate) struct CreateKey {
    pub(crate) master_key: MasterKey,
    pub(crate) kdf_params: KdfParams,
}
#[derive(Debug)]
pub(crate) enum CreateRootAuthProfile {
    Ed25519 { signing_key: SigningKey, signer_identity: [u8; 32] },
    X509(X509RootAuthSigner),
}
pub(crate) fn ensure_distinct_output_paths(left_label: &str, left: &Path, right_label: &str, right: &Path) -> Result<()> {
    let left_identity = output_identity_path(left)?;
    let right_identity = output_identity_path(right)?;
    if left_identity == right_identity {
        bail!("{left_label} and {right_label} must be different paths: {}", left.display());
    }
    Ok(())
}
pub(crate) fn output_identity_path(path: &Path) -> Result<PathBuf> {
    let parent = path.parent().filter(|path| !path.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().ok_or_else(|| anyhow!("output path must include a file name: {}", path.display()))?;
    let parent = parent.canonicalize().with_context(|| format!("failed to inspect output directory {}", parent.display()))?;
    Ok(parent.join(file_name))
}
pub(crate) fn check_output_path_free(label: &str, path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Ok(());
    }
    if path.exists() {
        bail!("{label} already exists: {}; use --force to overwrite", path.display());
    }
    Ok(())
}
pub(crate) fn removed_insecure_zero_key_error() -> UsageError {
    UsageError("--insecure-zero-key was removed in v43; use --no-encryption for plaintext archives")
}
pub(crate) fn reader_options(jobs: usize) -> ReaderOptions {
    ReaderOptions { jobs, ..ReaderOptions::default() }
}
pub(crate) fn non_seekable_reader_options(reader: ReaderOptions) -> NonSeekableReaderOptions {
    NonSeekableReaderOptions { reader, ..NonSeekableReaderOptions::default() }
}
pub(crate) fn archive_path_to_string(path: &Path) -> Result<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        let std::path::Component::Normal(part) = component else {
            bail!("unsafe archive path component in {}", path.display());
        };
        parts.push(part.to_str().ok_or_else(|| anyhow!("archive path is not valid UTF-8"))?.to_owned());
    }
    if parts.is_empty() {
        bail!("empty archive path");
    }
    Ok(parts.join("/"))
}
pub(crate) struct AtomicOutput<'a> {
    pub(crate) label: &'a str,
    pub(crate) path: &'a Path,
    pub(crate) bytes: &'a [u8],
}
pub(crate) fn write_atomic_output_file(label: &str, path: &Path, bytes: &[u8], force: bool) -> Result<()> {
    write_atomic_output_files(&[AtomicOutput { label, path, bytes }], force)
}
pub(crate) fn write_atomic_output_files(outputs: &[AtomicOutput<'_>], force: bool) -> Result<()> {
    for (index, output) in outputs.iter().enumerate() {
        for previous in &outputs[..index] {
            ensure_distinct_output_paths(previous.label, previous.path, output.label, output.path)?;
        }
        if !force && output.path.exists() {
            bail!("{} already exists: {}; use --force to overwrite", output.label, output.path.display());
        }
    }

    let mut temps = Vec::with_capacity(outputs.len());
    for output in outputs {
        let parent = output.path.parent().filter(|path| !path.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
        let mut temp = tempfile::Builder::new()
            .prefix(".tzap-write-")
            .suffix(".partial")
            .tempfile_in(parent)
            .with_context(|| format!("failed to create temporary {} in {}", output.label, parent.display()))?;
        temp.as_file_mut().write_all(output.bytes).with_context(|| format!("failed to write temporary {} {}", output.label, output.path.display()))?;
        temp.as_file_mut().flush().with_context(|| format!("failed to flush temporary {} {}", output.label, output.path.display()))?;
        temp.as_file_mut().sync_all().with_context(|| format!("failed to sync temporary {} {}", output.label, output.path.display()))?;
        temps.push(Some(temp));
    }

    let mut persisted_paths = Vec::new();
    for (index, output) in outputs.iter().enumerate() {
        let temp = temps[index].take().ok_or_else(|| anyhow!("missing temporary {}", output.label))?;
        let publish_result = if force { temp.persist(output.path) } else { temp.persist_noclobber(output.path) };
        match publish_result {
            Ok(_) => persisted_paths.push(output.path.to_path_buf()),
            Err(error) if !force && error.error.kind() == io::ErrorKind::AlreadyExists => {
                for path in &persisted_paths {
                    let _ = fs::remove_file(path);
                }
                bail!("{} already exists: {}; use --force to overwrite", output.label, output.path.display());
            }
            Err(error) => {
                for path in &persisted_paths {
                    let _ = fs::remove_file(path);
                }
                return Err(error.error).with_context(|| format!("failed to publish {} {}", output.label, output.path.display()));
            }
        }
    }
    Ok(())
}
