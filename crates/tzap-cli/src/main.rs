use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, IsTerminal, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use clap::{ArgGroup, Parser, Subcommand, ValueEnum};
use ed25519_dalek::SigningKey;
use memmap2::Mmap;
use openssl::pkey::PKey;
use openssl::x509::X509;
use rand::RngCore;
use serde_json::json;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
#[cfg(windows)]
use tzap_core::encode_v45_sparse_map;
use tzap_core::format::{
    FormatError, CRYPTO_HEADER_FIXED_LEN, FORMAT_VERSION, READER_MAX_ARGON2ID_M_COST_KIB,
    READER_MAX_ARGON2ID_PARALLELISM, READER_MAX_ARGON2ID_T_COST,
    READER_MAX_SUPPORTED_VOLUME_FORMAT_REV, VOLUME_FORMAT_REV_45, VOLUME_HEADER_LEN,
};
#[cfg(target_os = "linux")]
use tzap_core::linux_posix_acl_xattr_to_schily;
use tzap_core::reader::{ArchiveEntry, ArchiveIndexEntry, RecipientWrapRecordContext};
use tzap_core::wire::{CryptoHeader, CryptoHeaderFixed, VolumeHeader};
#[cfg(all(test, target_os = "macos"))]
use tzap_core::write_archive;
#[cfg(unix)]
use tzap_core::PortablePosixOwner;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use tzap_core::{canonical_base64_encode, encode_percent_name};
use tzap_core::{
    extract_non_seekable_stream_to_dir, extract_non_seekable_stream_to_dir_with_bootstrap_sidecar,
    extract_non_seekable_stream_to_dir_with_recipient_wrap_resolver,
    extract_non_seekable_stream_to_dir_with_recipient_wrap_resolver_and_bootstrap_sidecar,
    extract_unencrypted_non_seekable_stream_to_dir,
    extract_unencrypted_non_seekable_stream_to_dir_with_bootstrap_sidecar,
    list_non_seekable_stream, list_non_seekable_stream_with_bootstrap_sidecar,
    list_non_seekable_stream_with_recipient_wrap_resolver,
    list_non_seekable_stream_with_recipient_wrap_resolver_and_bootstrap_sidecar,
    list_unencrypted_non_seekable_stream,
    list_unencrypted_non_seekable_stream_with_bootstrap_sidecar, open_seekable_archive,
    open_seekable_archive_volumes_with_recipient_wrap_resolver_options,
    open_seekable_archive_with_bootstrap_sidecar_options,
    public_no_key_verify_volumes_with_options, verify_non_seekable_stream_with_bootstrap_sidecar,
    verify_non_seekable_stream_with_options,
    verify_non_seekable_stream_with_recipient_wrap_resolver_and_bootstrap_sidecar,
    verify_non_seekable_stream_with_recipient_wrap_resolver_options,
    verify_unencrypted_non_seekable_stream_with_bootstrap_sidecar,
    verify_unencrypted_non_seekable_stream_with_options, write_archive_sources_to_sink,
    write_archive_sources_to_sink_ordered_parallel,
    write_archive_sources_to_sink_ordered_parallel_with_recipient_wrap_records,
    write_sized_raw_member_archive_to_sink_with_kdf_and_root_auth,
    write_tar_stream_archive_to_sink_with_kdf_and_root_auth, AeadAlgo, ArchiveContentVerification,
    ArchiveRepairPatch, ArchiveTimestamp, ArchiveWriteError, ArchiveWriteSink, ExtractError,
    KdfAlgo, KdfParams, MasterKey, MemoryArchiveSink, MetadataDiagnostic,
    MetadataVerificationReport, NativeFileMetadata, NonSeekableReaderOptions, OpenedArchive,
    PortableFileMetadata, PortableModeOrigin, PublicNoKeyVerification, ReaderOptions,
    RegularFileSource, RestorePolicy, RootAuthSigningRequest, RootAuthVerification,
    RootAuthWriterConfig, SafeExtractionOptions, SequentialRootAuthStatus, SourceEntryKind,
    SparseExtent, StreamingRawWriterSummary, StreamingTarWriterSummary, TarEntryKind,
    WriterOptions, WriterTimings, WrittenArchiveSummary,
};
#[cfg(test)]
use tzap_core::{write_archive_with_kdf, RegularFile};
#[cfg(test)]
use tzap_core::{MetadataDiagnosticStatus, MetadataOperation};
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use tzap_core::{NativeAuxiliaryMetadata, NativeAuxiliaryNameEncoding, RestoreClass};
use tzap_plugin_keywrap::{
    dispatch_key_wrap_record, wrap_master_key_for_recipient,
    ArchiveIdentity as KeyWrapArchiveIdentity, KeyWrapOutcome, KeyWrapSuite, PrivateKeyLookup,
    RecipientRecordInput, RecipientRecordMetadata,
};
use tzap_plugin_signing::ed25519_raw::{
    self, Ed25519RootAuthOutcome, Ed25519VerificationMode, ED25519_AUTHENTICATOR_ID,
    ED25519_AUTHENTICATOR_VALUE_LEN,
};
use tzap_plugin_signing::x509_chain::{
    self, X509RootAuthReport, X509RootAuthSigner, X509SignatureScheme, X509_AUTHENTICATOR_ID,
};

mod plaintext_spool;
use plaintext_spool::{spool_unknown_size_raw_stdin, ExplicitPlaintextSpool};

const EXIT_USAGE: u8 = 2;
const EXIT_IO: u8 = 3;
const EXIT_WRONG_KEY: u8 = 10;
const EXIT_CORRUPT_ARCHIVE: u8 = 11;
const EXIT_UNSUPPORTED_REVISION: u8 = 12;
const EXIT_UNSAFE_PATH: u8 = 13;
const EXIT_MISSING_BOOTSTRAP: u8 = 14;
const EXIT_UNSUPPORTED_FEATURE: u8 = 16;
const EXIT_GENERIC: u8 = 1;

const DEFAULT_ARGON2_T_COST: u32 = 3;
const DEFAULT_ARGON2_M_COST_KIB: u32 = 262_144;
const DEFAULT_ARGON2_PARALLELISM: u32 = 4;
const DEFAULT_ARGON2_SALT_LEN: usize = 16;
const INSECURE_ZERO_KEY: [u8; 32] = [0; 32];
const LARGE_CREATE_LAYOUT_THRESHOLD: u64 = 100 * 1024 * 1024 * 1024;
const OFFICIAL_TZAP_ROOT_CERT_SHA256: &str =
    "sha256:d80d318f6cd6096dc791e314ec6f41434caa47feb75e85ad6f87d5bf72bbd53d";
const OFFICIAL_TZAP_ROOT_CERT_PEM: &[u8] = include_bytes!("trust/tzap-production-root-ca-2026.pem");

type CliRootAuthAuthenticator<'a> =
    dyn FnMut(&RootAuthSigningRequest) -> std::result::Result<Vec<u8>, FormatError> + 'a;

#[derive(Debug, Parser)]
#[command(name = "tzap")]
#[command(version)]
#[command(about = "Create, list, verify, and extract v45 archives")]
#[command(
    long_about = "Create, list, verify, and extract v45 archives.\n\nCreate selects one protection mode: `--keyfile` for encrypted raw-key archives, `--password` or `--password-stdin` for encrypted passphrase archives, `--recipient-cert` for encrypted v45 RecipientWrap archives, or `--no-encryption` for explicit plaintext archives. Plaintext archives can be listed, verified, and extracted without a password or keyfile. RecipientWrap archives are opened with `--recipient-key`. The `verify --public-no-key` mode verifies signed public RootAuth commitments without the archive key.\n\nSize suffixes accepted by size flags:\n  0-9 (bytes), K/KB/KiB, M/MB/MiB, G/GB/GiB.\n\nMulti-volume output naming for this CLI:\n  - one volume: --output writes exactly that path\n  - multiple volumes: --output backup.tzap writes backup.vol000.tzap, backup.vol001.tzap, ...\n\nExit codes:\n  2  usage / argument error\n  3  I/O failure (missing file, permission denied, etc.)\n  10 wrong key\n  11 archive corruption or integrity mismatch\n  12 unsupported archive revision / format version\n  13 unsafe extraction attempt\n  14 missing required bootstrap metadata\n  16 unsupported feature in this CLI/core version\n  1  generic failure\n\nSubcommands:\n  create   Build a new archive\n  extract  Extract files from an archive\n  list     List archive contents\n  verify   Validate archive integrity\n  keygen   Generate a random raw keyfile\n  signing-keygen Generate an Ed25519 RootAuth signing keypair"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    #[arg(
        long = "quiet",
        global = true,
        help = "Suppress routine success output and non-fatal diagnostics; failures are still reported."
    )]
    quiet: bool,

    #[arg(long = "verbose", global = true, help = "Enable verbose diagnostics.")]
    verbose: bool,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
enum Command {
    #[command(
        about = "Create a new archive",
        long_about = "Create a new archive from files and directories.\n\nThe command writes one output path for single-volume archives, or `.vol000.tzap`, `.vol001.tzap`, ... files for multi-volume archives.",
        after_help = "Examples:\n  tzap create --keyfile key.hex -o backup.tzap file.txt\n  tzap create --recipient-cert recipient.pem -o backup.tzap file.txt\n  tzap create --password -o backup.tzap file.txt\n  tzap create --password-stdin --argon2-t-cost 1 --argon2-m-cost-kib 8192 -o backup.tzap file.txt\n  tar cf - ./dir | tzap create --tar-stdin --keyfile key.hex -o backup.tzap -\n  tzap create --keyfile key.hex --signing-key root.signing.hex -o backup.tzap file.txt\n  tzap create --keyfile key.hex --signing-cert signer.pem --signing-private-key signer.key -o backup.tzap file.txt\n  tzap create --keyfile key.hex -o backup.tzap --volumes 3 dir/\n  tzap create --keyfile key.hex --volume-size 64M --volume-loss-tolerance 1 -o backup.tzap dir/\n  tzap create --keyfile key.hex --bootstrap-out backup.tzap.bootstrap file.txt",
        group(ArgGroup::new("create-key-source").args([
            "password_stdin",
            "password",
            "keyfile",
            "recipient_cert",
            "no_encryption",
        ]))
    )]
    Create {
        #[arg(
            short = 'o',
            long = "output",
            value_name = "ARCHIVE",
            help = "Write output to ARCHIVE (single volume) or base path for multi-volume output."
        )]
        output: String,

        #[arg(
            long = "volumes",
            value_name = "COUNT",
            conflicts_with = "volume_size",
            help = "Create exactly COUNT output volumes."
        )]
        volumes: Option<u32>,

        #[arg(
            long = "volume-size",
            value_name = "SIZE",
            conflicts_with = "volumes",
            help = "Create as many fixed-size output volumes as needed."
        )]
        volume_size: Option<String>,

        #[arg(
            long = "volume-loss-tolerance",
            value_name = "COUNT",
            help = "Allowed missing-volume recovery tolerance for multi-volume archives."
        )]
        volume_loss_tolerance: Option<u8>,

        #[arg(
            long = "bit-rot-buffer-pct",
            value_name = "PERCENT",
            default_value_t = 5,
            help = "Percent of archive reserved for bit-rot recovery structures."
        )]
        bit_rot_buffer_pct: u8,

        #[arg(
            long = "password-stdin",
            conflicts_with = "keyfile",
            conflicts_with = "password",
            conflicts_with = "no_encryption",
            value_name = "STDIN",
            help = "Read passphrase from stdin; one trailing LF or CRLF is stripped."
        )]
        password_stdin: bool,

        #[arg(
            long = "password",
            conflicts_with = "keyfile",
            conflicts_with = "password_stdin",
            conflicts_with = "no_encryption",
            help = "Read passphrase from an interactive prompt."
        )]
        password: bool,

        #[arg(
            long = "keyfile",
            value_name = "KEYFILE",
            conflicts_with = "no_encryption",
            conflicts_with = "recipient_cert",
            help = "Use a raw key from KEYFILE."
        )]
        keyfile: Option<String>,

        #[arg(
            long = "recipient-cert",
            value_name = "FILE",
            conflicts_with = "keyfile",
            conflicts_with = "password",
            conflicts_with = "password_stdin",
            conflicts_with = "no_encryption",
            help = "Encrypt a v45 RecipientWrap archive to one X.509 recipient certificate."
        )]
        recipient_cert: Option<String>,

        #[arg(
            long = "no-encryption",
            conflicts_with = "recipient_cert",
            help = "Create an explicit plaintext v45 archive with no password or keyfile."
        )]
        no_encryption: bool,

        #[arg(
            long = "insecure-zero-key",
            hide = true,
            help = "Removed in v43; use --no-encryption for plaintext archives."
        )]
        insecure_zero_key: bool,

        #[arg(
            long = "force",
            help = "Overwrite existing output files and bootstrap sidecar."
        )]
        force: bool,

        #[arg(
            long = "argon2-t-cost",
            value_name = "COUNT",
            default_value_t = DEFAULT_ARGON2_T_COST,
            help = "Argon2 iterations when deriving from passphrase."
        )]
        argon2_t_cost: u32,

        #[arg(
            long = "argon2-m-cost-kib",
            value_name = "KIB",
            default_value_t = DEFAULT_ARGON2_M_COST_KIB,
            help = "Argon2 memory cost (KiB) when deriving from passphrase."
        )]
        argon2_m_cost_kib: u32,

        #[arg(
            long = "argon2-parallelism",
            value_name = "COUNT",
            default_value_t = DEFAULT_ARGON2_PARALLELISM,
            help = "Argon2 parallelism when deriving from passphrase."
        )]
        argon2_parallelism: u32,

        #[arg(
            long = "dictionary",
            value_name = "FILE",
            help = "Read compression dictionary from FILE."
        )]
        dictionary: Option<String>,

        #[arg(
            long = "signing-key",
            value_name = "FILE",
            conflicts_with = "signing_cert",
            help = "Sign RootAuth with an Ed25519 signing key seed from FILE."
        )]
        signing_key: Option<String>,

        #[arg(
            long = "signing-cert",
            value_name = "FILE",
            conflicts_with = "signing_key",
            requires = "signing_private_key",
            help = "Sign RootAuth with an X.509 leaf certificate from FILE."
        )]
        signing_cert: Option<String>,

        #[arg(
            long = "signing-private-key",
            value_name = "FILE",
            conflicts_with = "signing_key",
            requires = "signing_cert",
            help = "Private key for --signing-cert."
        )]
        signing_private_key: Option<String>,

        #[arg(
            long = "signing-chain",
            value_name = "FILE",
            requires = "signing_cert",
            help = "PEM or DER intermediate certificate chain for --signing-cert."
        )]
        signing_chain: Vec<String>,

        #[arg(
            long = "x509-signature-scheme",
            value_name = "SCHEME",
            value_enum,
            requires = "signing_cert",
            help = "X.509 RootAuth signature scheme: rsa-pkcs1-sha256, ecdsa-sha256-der, or rsa-pss-sha256."
        )]
        x509_signature_scheme: Option<CliX509SignatureScheme>,

        #[arg(
            long = "bootstrap-out",
            value_name = "FILE",
            help = "Write bootstrap recovery sidecar to FILE (single-volume output only)."
        )]
        bootstrap_out: Option<String>,

        #[arg(
            long = "tar-stdin",
            help = "Treat PATH '-' as a tar stream read from stdin."
        )]
        tar_stdin: bool,

        #[arg(
            long = "raw-stdin",
            help = "Treat PATH '-' as one raw stdin member named by --stdin-name."
        )]
        raw_stdin: bool,

        #[arg(
            long = "stdin-name",
            value_name = "PATH",
            help = "Archive member path for --raw-stdin."
        )]
        stdin_name: Option<String>,

        #[arg(
            long = "stdin-size",
            value_name = "SIZE",
            help = "Expected byte size for known-size --raw-stdin."
        )]
        stdin_size: Option<String>,

        #[arg(
            long = "spool-stdin",
            help = "Spool unknown-size raw stdin to a restrictive temporary file before archiving."
        )]
        spool_stdin: bool,

        #[arg(
            long = "compression-level",
            value_name = "LEVEL",
            default_value_t = 3,
            help = "zstd compression level."
        )]
        compression_level: i32,

        #[arg(
            long = "chunk-size",
            value_name = "SIZE",
            help = "Compression chunk size (default: auto by input size)."
        )]
        chunk_size: Option<String>,

        #[arg(
            long = "envelope-size",
            value_name = "SIZE",
            help = "Archive envelope size (default: auto by input size)."
        )]
        envelope_size: Option<String>,

        #[arg(
            long = "block-size",
            value_name = "SIZE",
            help = "Block size for archive payload layout (default: auto by input size)."
        )]
        block_size: Option<String>,

        #[arg(
            long = "jobs",
            value_name = "N",
            help = "Worker jobs for reader/writer CPU work (default: logical CPU count)."
        )]
        jobs: Option<usize>,

        #[arg(
            long = "timings",
            help = "Print create-stage timing breakdown to stderr."
        )]
        timings: bool,

        #[arg(
            long = "dry-run",
            help = "Print a create plan and file summary without writing archive bytes."
        )]
        dry_run: bool,

        #[arg(
            required = true,
            value_name = "PATH",
            help = "One or more input files or directories."
        )]
        paths: Vec<String>,
    },
    #[command(
        about = "Extract files from an archive",
        long_about = "Extract one or many archive members into a directory, with safe-path protections enabled by default.",
        after_help = "Examples:\n  tzap extract --keyfile key.hex -C out/ backup.tzap\n  tzap extract --recipient-key recipient.key -C out/ backup.tzap\n  tzap extract --keyfile key.hex backup.tzap file.txt\n  tzap extract --keyfile key.hex --stdout backup.tzap hello.txt > out.bin\n  tzap extract --password-stdin --overwrite backup.tzap target/\n  tzap extract --dry-run -C out backup.tzap file.txt\n  tzap extract --bootstrap backup.tzap.bootstrap -C out backup.tzap",
        group(
            ArgGroup::new("open-key-source")
                .args(["password_stdin", "password", "keyfile", "recipient_key", "insecure_zero_key"])
        )
    )]
    Extract {
        #[arg(
            value_name = "ARCHIVE",
            help = "Archive input. A .volNNN.tzap path discovers sibling volumes unless --volume is used."
        )]
        archive: String,

        #[arg(
            value_name = "PATH",
            help = "Optional archive member paths to extract."
        )]
        paths: Vec<String>,

        #[arg(
            short = 'C',
            long = "directory",
            value_name = "DIR",
            default_value = ".",
            help = "Destination directory for extracted files."
        )]
        directory: String,

        #[arg(
            long = "stdout",
            conflicts_with = "dry_run",
            help = "Write a single selected member to stdout."
        )]
        stdout: bool,

        #[arg(
            long = "dry-run",
            help = "Show what would be extracted without writing files."
        )]
        dry_run: bool,

        #[arg(long = "overwrite", help = "Allow overwriting existing output files.")]
        overwrite: bool,

        #[arg(
            long = "restore",
            value_enum,
            default_value = "portable",
            help = "Restore policy: content, portable, same-os, or system."
        )]
        restore: CliRestorePolicy,

        #[arg(
            long = "allow-degraded",
            help = "Explicitly permit requested unsupported metadata to be skipped with diagnostics."
        )]
        allow_degraded: bool,

        #[arg(
            long = "allow-absolute-symlinks",
            help = "Permit extraction of symlinks pointing to absolute paths outside the destination directory."
        )]
        allow_absolute_symlinks: bool,

        #[arg(
            long = "password-stdin",
            conflicts_with = "keyfile",
            conflicts_with = "password",
            conflicts_with = "insecure_zero_key",
            value_name = "STDIN",
            help = "Read passphrase from stdin; one trailing LF or CRLF is stripped."
        )]
        password_stdin: bool,

        #[arg(
            long = "password",
            conflicts_with = "keyfile",
            conflicts_with = "password_stdin",
            conflicts_with = "insecure_zero_key",
            help = "Read passphrase from an interactive prompt."
        )]
        password: bool,

        #[arg(
            long = "keyfile",
            value_name = "KEYFILE",
            conflicts_with = "insecure_zero_key",
            conflicts_with = "recipient_key",
            help = "Use a raw key from KEYFILE."
        )]
        keyfile: Option<String>,

        #[arg(
            long = "recipient-key",
            value_name = "FILE",
            conflicts_with = "keyfile",
            conflicts_with = "password",
            conflicts_with = "password_stdin",
            conflicts_with = "insecure_zero_key",
            help = "Use a local recipient private key to open a v45 RecipientWrap archive."
        )]
        recipient_key: Option<String>,

        #[arg(
            long = "insecure-zero-key",
            hide = true,
            help = "Removed in v43; plaintext archives need no key source."
        )]
        insecure_zero_key: bool,

        #[arg(
            long = "bootstrap",
            value_name = "FILE",
            help = "Use bootstrap sidecar FILE for single-volume archive input."
        )]
        bootstrap: Option<String>,

        #[arg(
            long = "volume",
            value_name = "FILE",
            help = "Explicit additional volume path."
        )]
        volumes: Vec<String>,

        #[arg(
            long = "jobs",
            value_name = "N",
            help = "Worker jobs for reader CPU work (default: logical CPU count)."
        )]
        jobs: Option<usize>,
    },
    #[command(
        about = "List archive contents",
        long_about = "List archive members in plain format by default.",
        after_help = "Examples:\n  tzap list --keyfile key.hex backup.tzap\n  tzap list --recipient-key recipient.key backup.tzap\n  tzap list --keyfile key.hex --long backup.tzap\n  tzap list --keyfile key.hex --json backup.tzap\n  tzap list --password-stdin --bootstrap backup.tzap.bootstrap backup.tzap",
        group(
            ArgGroup::new("open-key-source")
                .args(["password_stdin", "password", "keyfile", "recipient_key", "insecure_zero_key"])
        )
    )]
    List {
        #[arg(
            value_name = "ARCHIVE",
            help = "Archive to inspect. A .volNNN.tzap path discovers sibling volumes unless --volume is used."
        )]
        archive: String,

        #[arg(
            long = "password-stdin",
            conflicts_with = "keyfile",
            conflicts_with = "password",
            conflicts_with = "insecure_zero_key",
            value_name = "STDIN",
            help = "Read passphrase from stdin; one trailing LF or CRLF is stripped."
        )]
        password_stdin: bool,

        #[arg(
            long = "password",
            conflicts_with = "keyfile",
            conflicts_with = "password_stdin",
            conflicts_with = "insecure_zero_key",
            help = "Read passphrase from an interactive prompt."
        )]
        password: bool,

        #[arg(
            long = "keyfile",
            value_name = "KEYFILE",
            conflicts_with = "insecure_zero_key",
            conflicts_with = "recipient_key",
            help = "Use a raw key from KEYFILE."
        )]
        keyfile: Option<String>,

        #[arg(
            long = "recipient-key",
            value_name = "FILE",
            conflicts_with = "keyfile",
            conflicts_with = "password",
            conflicts_with = "password_stdin",
            conflicts_with = "insecure_zero_key",
            help = "Use a local recipient private key to open a v45 RecipientWrap archive."
        )]
        recipient_key: Option<String>,

        #[arg(
            long = "insecure-zero-key",
            hide = true,
            help = "Removed in v43; plaintext archives need no key source."
        )]
        insecure_zero_key: bool,

        #[arg(
            long = "bootstrap",
            value_name = "FILE",
            help = "Use bootstrap sidecar FILE for single-volume archive input."
        )]
        bootstrap: Option<String>,

        #[arg(
            long = "volume",
            value_name = "FILE",
            help = "Explicit additional volume path."
        )]
        volumes: Vec<String>,

        #[arg(
            long = "long",
            conflicts_with = "json",
            help = "Use verbose listing output."
        )]
        long: bool,

        #[arg(
            long = "json",
            conflicts_with = "long",
            help = "Emit stable machine-readable JSON output."
        )]
        json: bool,

        #[arg(
            long = "jobs",
            value_name = "N",
            help = "Worker jobs for reader CPU work (default: logical CPU count)."
        )]
        jobs: Option<usize>,
    },
    #[command(
        about = "Verify archive integrity",
        long_about = "Verify archive signatures and checksum integrity. No payload changes are made unless --write-repaired is set; original archive files are never modified.\n\nEncrypted archives need --keyfile, --password, --password-stdin, or --recipient-key for v45 RecipientWrap archives. Unencrypted archives need no key source. Official TZAP X.509 RootAuth uses the embedded TZAP root by default. With --public-no-key, verify uses the public RootAuth profile and does not require the archive key.",
        after_help = "Examples:\n  tzap verify --keyfile key.hex backup.tzap\n  tzap verify --recipient-key recipient.key backup.tzap\n  tzap verify --keyfile key.hex --write-repaired backup.tzap\n  tzap verify --keyfile key.hex --trusted-public-key root.public.hex backup.tzap\n  tzap verify --keyfile key.hex --trusted-ca-cert root-ca.pem backup.tzap\n  tzap verify --public-no-key backup.tzap\n  tzap verify --public-no-key --trusted-public-key root.public.hex backup.tzap\n  tzap verify --public-no-key --trusted-ca-cert root-ca.pem backup.tzap\n  tzap verify --keyfile key.hex backup.vol000.tzap backup.vol001.tzap\n  tzap verify --password-stdin backup.tzap\n  tzap verify --json --keyfile key.hex backup.tzap\n  tzap verify --quiet --keyfile key.hex backup.tzap\n\nFor multi-volume archives named `.volNNN.tzap`, passing any one volume discovers matching siblings in the same directory. Additional positionals are explicit extra volumes."
    )]
    Verify {
        #[arg(
            required = true,
            value_name = "ARCHIVE",
            help = "Archive path. A .volNNN.tzap path discovers sibling volumes unless extra archive paths are supplied."
        )]
        archives: Vec<String>,

        #[arg(
            long = "password-stdin",
            conflicts_with = "keyfile",
            conflicts_with = "password",
            conflicts_with = "insecure_zero_key",
            value_name = "STDIN",
            help = "Read passphrase from stdin; one trailing LF or CRLF is stripped."
        )]
        password_stdin: bool,

        #[arg(
            long = "password",
            conflicts_with = "keyfile",
            conflicts_with = "password_stdin",
            conflicts_with = "insecure_zero_key",
            help = "Read passphrase from an interactive prompt."
        )]
        password: bool,

        #[arg(
            long = "keyfile",
            value_name = "KEYFILE",
            conflicts_with = "insecure_zero_key",
            conflicts_with = "recipient_key",
            help = "Use a raw key from KEYFILE."
        )]
        keyfile: Option<String>,

        #[arg(
            long = "recipient-key",
            value_name = "FILE",
            conflicts_with = "keyfile",
            conflicts_with = "password",
            conflicts_with = "password_stdin",
            conflicts_with = "insecure_zero_key",
            help = "Use a local recipient private key to verify a v45 RecipientWrap archive."
        )]
        recipient_key: Option<String>,

        #[arg(
            long = "insecure-zero-key",
            hide = true,
            help = "Removed in v43; plaintext archives need no key source."
        )]
        insecure_zero_key: bool,

        #[arg(
            long = "trusted-public-key",
            value_name = "FILE",
            help = "Verify Ed25519 RootAuth with trusted public key FILE."
        )]
        trusted_public_key: Option<String>,

        #[arg(
            long = "trusted-ca-cert",
            value_name = "FILE",
            help = "Verify X.509 RootAuth with trusted CA certificate FILE."
        )]
        trusted_ca_cert: Vec<String>,

        #[arg(
            long = "trusted-system-roots",
            help = "Allow X.509 RootAuth verification with OpenSSL default trust roots."
        )]
        trusted_system_roots: bool,

        #[arg(
            long = "public-no-key",
            help = "Verify public RootAuth commitments without the archive key."
        )]
        public_no_key: bool,

        #[arg(
            long = "fast",
            help = "Verify readable archive content with repair-on-demand parity reads, but skip RootAuth and recovery-margin checks."
        )]
        fast: bool,

        #[arg(
            long = "bootstrap",
            value_name = "FILE",
            help = "Use bootstrap sidecar FILE for single-volume archive input."
        )]
        bootstrap: Option<String>,

        #[arg(
            long = "json",
            conflicts_with = "quiet",
            help = "Emit stable machine-readable JSON output."
        )]
        json: bool,

        #[arg(
            long = "write-repaired",
            help = "After successful key-holding verification, write repaired copies for volumes that had recoverable block damage."
        )]
        write_repaired: bool,

        #[arg(
            long = "jobs",
            value_name = "N",
            help = "Worker jobs for reader CPU work (default: logical CPU count)."
        )]
        jobs: Option<usize>,
    },
    #[command(
        about = "Generate a random raw key",
        long_about = "Generate a random 32-byte raw key and write it as 64 lowercase hex characters.\n\nBy default, --output refuses to overwrite an existing file.\nUse --force if you want to replace it.\n\nUse --stdout to print the key to stdout instead.",
        group(
            ArgGroup::new("keygen-output")
                .required(true)
                .args(["output", "stdout"])
        )
    )]
    Keygen {
        #[arg(
            short = 'o',
            long = "output",
            value_name = "KEYFILE",
            conflicts_with = "stdout",
            help = "Write the generated key to KEYFILE."
        )]
        output: Option<String>,

        #[arg(long = "stdout", help = "Write the generated key to stdout.")]
        stdout: bool,

        #[arg(long = "force", help = "Overwrite an existing output keyfile.")]
        force: bool,
    },
    #[command(
        name = "signing-keygen",
        about = "Generate an Ed25519 RootAuth signing keypair",
        long_about = "Generate an Ed25519 RootAuth signing keypair. The secret output is a 32-byte signing seed encoded as 64 lowercase hex characters; the public output is a 32-byte Ed25519 verifying key encoded the same way."
    )]
    SigningKeygen {
        #[arg(
            long = "secret-output",
            value_name = "FILE",
            help = "Write the generated Ed25519 signing seed to FILE."
        )]
        secret_output: String,

        #[arg(
            long = "public-output",
            value_name = "FILE",
            help = "Write the generated Ed25519 public key to FILE."
        )]
        public_output: String,

        #[arg(long = "force", help = "Overwrite existing keypair output files.")]
        force: bool,
    },
    #[command(
        name = "trust-info",
        about = "Show embedded official TZAP trust and build identity",
        long_about = "Show the embedded official TZAP root certificate fingerprint and build identity used by this tzap binary."
    )]
    TrustInfo {
        #[arg(long = "json", help = "Emit stable machine-readable JSON output.")]
        json: bool,
    },
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            let code = if err.use_stderr() { EXIT_USAGE } else { 0 };
            let _ = err.print();
            return ExitCode::from(code);
        }
    };
    if cli.quiet && matches!(&cli.command, Command::Verify { json: true, .. }) {
        eprintln!("error: --quiet cannot be used with --json for verify");
        return ExitCode::from(EXIT_USAGE);
    }
    let is_verify_json = matches!(&cli.command, Command::Verify { json: true, .. });

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let diagnostic = classify_error(&err);
            if !is_verify_json {
                if diagnostic.action.is_empty() {
                    eprintln!("tzap: {}: {err:#}", diagnostic.label);
                } else {
                    eprintln!("tzap: {}: {err:#}: {}", diagnostic.label, diagnostic.action);
                }
            }
            ExitCode::from(diagnostic.exit_code)
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    let quiet = cli.quiet;
    match cli.command {
        Command::Create {
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
            dry_run,
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
            paths,
        } => {
            let create_total_started = Instant::now();
            let jobs = resolve_jobs(jobs)?;
            let resolved_volume_loss_tolerance = resolve_create_volume_loss_tolerance(
                volume_loss_tolerance,
                volumes,
                volume_size.as_deref(),
                tar_stdin || raw_stdin || spool_stdin,
            );
            let layout_overrides = CreateLayoutOverrides {
                chunk_size: chunk_size.as_deref(),
                envelope_size: envelope_size.as_deref(),
                block_size: block_size.as_deref(),
            };
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
            validate_create_key_source(
                keyfile.as_deref(),
                recipient_cert.as_deref(),
                password_stdin,
                password,
                no_encryption,
                insecure_zero_key,
            )?;
            if bootstrap_out.is_some() && (volumes.unwrap_or(1) > 1 || volume_size.is_some()) {
                return Err(FormatError::WriterUnsupported(
                    "--bootstrap-out is currently supported only for single-volume output",
                )
                .into());
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

            ensure_create_output_paths_can_be_written(
                &output,
                volumes,
                volume_size.is_some(),
                bootstrap_out.as_deref(),
                force,
            )?;
            if let Some(stdin_mode) = stdin_mode {
                if dry_run {
                    let dry_run_input_size = match stdin_mode {
                        CreateStdinMode::RawKnownSize => Some(parse_size(
                            stdin_size.as_deref().expect("validated stdin-size"),
                        )?),
                        CreateStdinMode::Tar
                        | CreateStdinMode::RawSpool
                        | CreateStdinMode::RawUnknownSize => None,
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
                        create_key_mode_label(
                            keyfile.as_deref(),
                            recipient_cert.as_deref(),
                            password_stdin,
                            password,
                            no_encryption,
                            insecure_zero_key
                        )
                    );
                    eprintln!(
                        "  root auth: {}",
                        create_root_auth_mode_label(
                            signing_key.as_deref(),
                            signing_cert.as_deref()
                        )
                    );
                    eprintln!(
                        "  volume mode: {}",
                        describe_planned_volume_mode(volumes, volume_size.as_deref())
                    );
                    eprintln!("  planned archive paths:");
                    for path in create_dry_run_output_paths(&output, volumes, volume_size.is_some())
                    {
                        eprintln!("    {path}");
                    }
                    if let Some(bootstrap_path) = bootstrap_out.as_ref() {
                        eprintln!("  bootstrap: {}", bootstrap_path);
                    }
                    return Ok(());
                }

                if matches!(stdin_mode, CreateStdinMode::RawUnknownSize) {
                    return Err(FormatError::WriterUnsupported(
                        "unknown-size raw stdin without --spool-stdin requires the future raw_stream_v1 profile",
                    )
                    .into());
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
                let root_auth = root_auth_profile
                    .as_ref()
                    .map(CreateRootAuthProfile::root_auth_writer_config)
                    .transpose()?;
                let core_writer_started = Instant::now();
                let (bootstrap_sidecar, summary_text, writer_timings) = match stdin_mode {
                    CreateStdinMode::Tar => {
                        let options = build_writer_options(None)?;
                        validate_create_writer_options(&options)?;
                        let (summary, bootstrap_sidecar) = write_tar_stdin_archive_output(
                            &output,
                            &key,
                            options,
                            root_auth,
                            root_auth_profile.as_ref(),
                            force,
                        )?;
                        let summary_text = format!(
                            "created {} member(s), {} tar bytes in, {} archive bytes, {} volume(s), volume-loss tolerance {}, bit-rot buffer {}%",
                            summary.input_member_count,
                            summary.input_tar_bytes,
                            summary.archive.archive_bytes,
                            summary.archive.volume_count,
                            resolved_volume_loss_tolerance,
                            bit_rot_buffer_pct
                        );
                        (bootstrap_sidecar, summary_text, summary.archive.timings)
                    }
                    CreateStdinMode::RawKnownSize => {
                        let stdin_size =
                            parse_size(stdin_size.as_deref().expect("validated stdin-size"))?;
                        let options = build_writer_options(Some(stdin_size))?;
                        validate_create_writer_options(&options)?;
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
                            "created 1 member(s), {} raw bytes in, {} archive bytes, {} volume(s), volume-loss tolerance {}, bit-rot buffer {}%",
                            summary.input_bytes,
                            summary.archive.archive_bytes,
                            summary.archive.volume_count,
                            resolved_volume_loss_tolerance,
                            bit_rot_buffer_pct
                        );
                        (bootstrap_sidecar, summary_text, summary.archive.timings)
                    }
                    CreateStdinMode::RawSpool => {
                        let stdin = io::stdin();
                        let mut stdin_lock = stdin.lock();
                        let spool = spool_unknown_size_raw_stdin(
                            &mut stdin_lock,
                            u64::MAX,
                            ExplicitPlaintextSpool::acknowledge_plaintext_spool(),
                        )?;
                        let known_size_source = spool.known_size_source();
                        let spool_reader = spool.reopen()?;
                        let options = build_writer_options(Some(known_size_source.size()))?;
                        validate_create_writer_options(&options)?;
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
                            "created 1 member(s), {} spooled raw bytes in, {} archive bytes, {} volume(s), volume-loss tolerance {}, bit-rot buffer {}%",
                            summary.input_bytes,
                            summary.archive.archive_bytes,
                            summary.archive.volume_count,
                            resolved_volume_loss_tolerance,
                            bit_rot_buffer_pct
                        );
                        (bootstrap_sidecar, summary_text, summary.archive.timings)
                    }
                    CreateStdinMode::RawUnknownSize => unreachable!("rejected before key loading"),
                };
                let core_writer = core_writer_started.elapsed();
                let write_outputs_started = Instant::now();
                if let Some(path) = bootstrap_out.as_deref() {
                    if bootstrap_sidecar.is_empty() {
                        return Err(FormatError::WriterUnsupported(
                            "bootstrap output is unavailable for this archive shape",
                        )
                        .into());
                    }
                    write_bootstrap_output_with_archive_rollback(
                        path,
                        &bootstrap_sidecar,
                        &output,
                        1,
                        force,
                    )?;
                }
                let write_outputs = write_outputs_started.elapsed();
                emit_success_summary(quiet, &summary_text)?;
                if let Some(profile) = root_auth_profile.as_ref() {
                    emit_success_summary(
                        quiet,
                        &format!("  root auth: {} signed", profile.label()),
                    )?;
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
                    create_key_mode_label(
                        keyfile.as_deref(),
                        recipient_cert.as_deref(),
                        password_stdin,
                        password,
                        no_encryption,
                        insecure_zero_key
                    )
                );
                eprintln!(
                    "  root auth: {}",
                    create_root_auth_mode_label(signing_key.as_deref(), signing_cert.as_deref())
                );
                eprintln!(
                    "  volume mode: {}",
                    describe_planned_volume_mode(volumes, volume_size.as_deref())
                );
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
                let mut recipient_options = options;
                let master_key = generate_random_master_key()?;
                let recipient_record = build_recipient_wrap_record(
                    recipient_cert_path,
                    &master_key,
                    &mut recipient_options,
                )?;
                let core_writer_started = Instant::now();
                let (archive, bootstrap_sidecar) =
                    write_file_inputs_ordered_parallel_recipient_wrap_to_output(
                        &output,
                        &input_specs,
                        &master_key,
                        recipient_options,
                        recipient_record,
                        force,
                    )
                    .context("failed to create recipient-wrap archive")?;
                let core_writer = core_writer_started.elapsed();

                let write_outputs_started = Instant::now();
                if let Some(path) = bootstrap_out.as_deref() {
                    if bootstrap_sidecar.is_empty() {
                        return Err(FormatError::WriterUnsupported(
                            "bootstrap output is unavailable for this archive shape",
                        )
                        .into());
                    }
                    write_bootstrap_output_with_archive_rollback(
                        path,
                        &bootstrap_sidecar,
                        &output,
                        archive.volume_count,
                        force,
                    )?;
                }
                let write_outputs = write_outputs_started.elapsed();
                let summary = format!(
                    "created {} member(s), {} bytes in, {} archive bytes, {} volume(s), volume-loss tolerance {}, bit-rot buffer {}%",
                    input_specs.len(),
                    input_bytes,
                    archive.archive_bytes,
                    archive.volume_count,
                    resolved_volume_loss_tolerance,
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
            let dictionary_bytes = dictionary
                .as_deref()
                .map(|path| {
                    fs::read(path).with_context(|| format!("failed to read dictionary {path}"))
                })
                .transpose()?;
            let root_auth_profile = load_create_root_auth_profile(
                signing_key.as_deref(),
                signing_cert.as_deref(),
                signing_private_key.as_deref(),
                &signing_chain,
                x509_signature_scheme,
            )?;
            let root_auth = root_auth_profile
                .as_ref()
                .map(CreateRootAuthProfile::root_auth_writer_config)
                .transpose()?;

            if dictionary_bytes.is_none()
                && options.target_volume_size.is_none()
                && options.volume_loss_tolerance == 0
            {
                let core_writer_started = Instant::now();
                let (archive, bootstrap_sidecar) = write_file_inputs_ordered_parallel_to_output(
                    &output,
                    &input_specs,
                    &key,
                    options,
                    root_auth,
                    root_auth_profile.as_ref(),
                    force,
                )
                .context("failed to create archive")?;
                let core_writer = core_writer_started.elapsed();

                let write_outputs_started = Instant::now();
                if let Some(path) = bootstrap_out.as_deref() {
                    if bootstrap_sidecar.is_empty() {
                        return Err(FormatError::WriterUnsupported(
                            "bootstrap output is unavailable for this archive shape",
                        )
                        .into());
                    }
                    write_bootstrap_output_with_archive_rollback(
                        path,
                        &bootstrap_sidecar,
                        &output,
                        archive.volume_count,
                        force,
                    )?;
                }
                let write_outputs = write_outputs_started.elapsed();
                let summary = format!(
                    "created {} member(s), {} bytes in, {} archive bytes, {} volume(s), volume-loss tolerance {}, bit-rot buffer {}%",
                    input_specs.len(),
                    input_bytes,
                    archive.archive_bytes,
                    archive.volume_count,
                    resolved_volume_loss_tolerance,
                    bit_rot_buffer_pct
                );
                emit_success_summary(quiet, &summary)?;
                if let Some(profile) = root_auth_profile.as_ref() {
                    emit_success_summary(
                        quiet,
                        &format!("  root auth: {} signed", profile.label()),
                    )?;
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
            let archive =
                if let (Some(root_auth), Some(profile)) = (root_auth, root_auth_profile.as_ref()) {
                    let mut authenticator = |request: &RootAuthSigningRequest| {
                        root_auth_authenticator_value(profile, request)
                    };
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
                    write_archive_sources_to_sink(
                        &input_specs,
                        &key.master_key,
                        options,
                        dictionary_bytes.as_deref(),
                        &key.kdf_params,
                        None,
                        None,
                        &mut archive_sink,
                    )
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
            write_archive_outputs_with_optional_bootstrap(
                &output,
                &archive_sink.volumes,
                bootstrap_out.as_deref(),
                &archive_sink.bootstrap_sidecar,
                force,
            )?;
            let write_outputs = write_outputs_started.elapsed();
            let summary = format!(
                "created {} member(s), {} bytes in, {} archive bytes, {} volume(s), volume-loss tolerance {}, bit-rot buffer {}%",
                input_specs.len(),
                input_bytes,
                archive_sink.volumes.iter().map(|volume| volume.len() as u64).sum::<u64>(),
                archive_sink.volumes.len(),
                resolved_volume_loss_tolerance,
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
                emit_create_timing_report(
                    scan_inputs,
                    read_inputs,
                    core_writer,
                    write_outputs,
                    create_total_started.elapsed(),
                    archive.timings,
                )?;
            }
            Ok(())
        }
        Command::Extract {
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
        } => {
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
        Command::List {
            archive,
            password_stdin,
            password,
            keyfile,
            recipient_key,
            insecure_zero_key,
            bootstrap,
            volumes,
            long,
            json,
            jobs,
        } => {
            let reader_options = reader_options(resolve_jobs(jobs)?);
            reject_multi_volume_bootstrap(1 + volumes.len(), bootstrap.as_deref())?;
            if archive == "-" {
                reject_archive_stdin_list_options(
                    &volumes,
                    password_stdin,
                    password,
                    keyfile.as_deref(),
                    recipient_key.as_deref(),
                    insecure_zero_key,
                )?;
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
                        list_non_seekable_stream_with_bootstrap_sidecar(
                            stdin.lock(),
                            bootstrap_bytes,
                            &master_key,
                            non_seekable_reader_options(reader_options),
                        )
                    } else {
                        list_non_seekable_stream(
                            stdin.lock(),
                            &master_key,
                            non_seekable_reader_options(reader_options),
                        )
                    }
                } else if let Some(recipient_key) = recipient_key.as_deref() {
                    let lookup = load_recipient_private_key_lookup(recipient_key)?;
                    let mut stats = RecipientWrapOpenStats::default();
                    if let Some(bootstrap_bytes) = bootstrap_bytes.as_deref() {
                        list_non_seekable_stream_with_recipient_wrap_resolver_and_bootstrap_sidecar(
                            stdin.lock(),
                            bootstrap_bytes,
                            |context| {
                                recipient_wrap_candidates_for_record(context, &lookup, &mut stats)
                            },
                            non_seekable_reader_options(reader_options),
                        )
                    } else {
                        list_non_seekable_stream_with_recipient_wrap_resolver(
                            stdin.lock(),
                            |context| {
                                recipient_wrap_candidates_for_record(context, &lookup, &mut stats)
                            },
                            non_seekable_reader_options(reader_options),
                        )
                    }
                } else {
                    if let Some(bootstrap_bytes) = bootstrap_bytes.as_deref() {
                        list_unencrypted_non_seekable_stream_with_bootstrap_sidecar(
                            stdin.lock(),
                            bootstrap_bytes,
                            non_seekable_reader_options(reader_options),
                        )
                    } else {
                        list_unencrypted_non_seekable_stream(
                            stdin.lock(),
                            non_seekable_reader_options(reader_options),
                        )
                    }
                }
                .context("failed to list non-seekable archive stream")?;
                emit_entry_metadata_diagnostics(quiet, &report.entries)?;
                if json {
                    let files = report
                        .index_entries
                        .iter()
                        .map(archive_index_entry_json)
                        .collect::<Vec<_>>();
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
                        println!(
                            "{}\t{}\t{}\t{}\t{}",
                            entry.file_data_size, kind, entry.mode, entry.mtime, entry.path
                        );
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
            if json {
                let files = opened
                    .list_index_entries()?
                    .iter()
                    .map(archive_index_entry_json)
                    .collect::<Vec<_>>();
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
                let entries = opened.list_files()?;
                emit_entry_metadata_diagnostics(quiet, &entries)?;
                for entry in entries {
                    let kind = archive_entry_kind_label(entry.kind);
                    println!(
                        "{}\t{}\t{}\t{}\t{}",
                        entry.file_data_size, kind, entry.mode, entry.mtime, entry.path
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
        Command::Verify {
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
        } => {
            let reader_options = reader_options(resolve_jobs(jobs)?);
            let first = archives
                .first()
                .ok_or_else(|| anyhow!("at least one archive volume is required"))?;
            let archive_paths = archives.to_vec();
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
                if trusted_public_key.is_some()
                    || !trusted_ca_cert.is_empty()
                    || trusted_system_roots
                {
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
            let selection =
                match resolve_archive_input_paths(first, &archives[1..], bootstrap.is_none()) {
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
            let opened_selection = match opened_selection_result
                .with_context(|| format!("failed to open archive {first}"))
            {
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
                        let entries = opened.list_files()?;
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
        Command::Keygen {
            output,
            stdout,
            force,
        } => {
            let bytes = generate_random_key_material()?;
            let key_hex = format!("{}\n", encode_hex(&bytes));
            if stdout {
                print!("{}", key_hex);
                io::stdout().flush()?;
                return Ok(());
            }
            let output = output.expect("--output required by clap");
            write_keyfile(&output, &key_hex, force).context("failed to write keyfile")?;
            emit_success_summary(quiet, &format!("wrote keyfile to {}", output))?;
            Ok(())
        }
        Command::SigningKeygen {
            secret_output,
            public_output,
            force,
        } => {
            ensure_distinct_output_paths(
                "signing secret output",
                Path::new(&secret_output),
                "signing public output",
                Path::new(&public_output),
            )?;
            if !force {
                check_output_path_free("signing secret output", Path::new(&secret_output))?;
                check_output_path_free("signing public output", Path::new(&public_output))?;
            }
            let signing_key = generate_ed25519_signing_key();
            let secret_hex = format!("{}\n", encode_hex(&signing_key.to_bytes()));
            let public_hex = format!("{}\n", encode_hex(&signing_key.verifying_key().to_bytes()));
            write_atomic_output_files(
                &[
                    AtomicOutput {
                        label: "signing secret",
                        path: Path::new(&secret_output),
                        bytes: secret_hex.as_bytes(),
                    },
                    AtomicOutput {
                        label: "signing public key",
                        path: Path::new(&public_output),
                        bytes: public_hex.as_bytes(),
                    },
                ],
                force,
            )?;
            emit_success_summary(
                quiet,
                &format!("wrote signing keypair to {secret_output} and {public_output}"),
            )?;
            Ok(())
        }
        Command::TrustInfo { json } => emit_trust_info(json).map_err(Into::into),
    }
}

fn emit_trust_info(json_output: bool) -> io::Result<()> {
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

fn emit_success_summary(quiet: bool, message: &str) -> io::Result<()> {
    if quiet {
        return Ok(());
    }
    eprintln!("{message}");
    Ok(())
}

fn emit_create_timing_report(
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

fn emit_sink_backed_create_timing_report(
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
fn emit_create_timing_report_with_labels(
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

fn format_duration(duration: Duration) -> String {
    format!("{:.3}s", duration.as_secs_f64())
}

fn emit_success_stdout(quiet: bool, message: &str) -> io::Result<()> {
    if quiet {
        return Ok(());
    }
    println!("{message}");
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct CreateLayoutOverrides<'a> {
    chunk_size: Option<&'a str>,
    envelope_size: Option<&'a str>,
    block_size: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CreateLayout {
    block_size: u32,
    chunk_size: u32,
    envelope_target_size: u32,
}

#[derive(Debug, Clone, Copy)]
struct CreateWriterOptionsArgs<'a> {
    volumes: Option<u32>,
    volume_size: Option<&'a str>,
    volume_loss_tolerance: u8,
    bit_rot_buffer_pct: u8,
    compression_level: i32,
    jobs: usize,
    layout_overrides: CreateLayoutOverrides<'a>,
    total_input_size: Option<u64>,
}

fn create_writer_options(args: CreateWriterOptionsArgs<'_>) -> Result<WriterOptions> {
    let layout = resolve_create_layout(args.layout_overrides, args.total_input_size)?;
    Ok(WriterOptions {
        stripe_width: args.volumes.unwrap_or(1),
        target_volume_size: args
            .volume_size
            .map(|value| parse_size(value).with_context(|| format!("invalid volume-size: {value}")))
            .transpose()?,
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

fn resolve_create_layout(
    overrides: CreateLayoutOverrides<'_>,
    total_input_size: Option<u64>,
) -> Result<CreateLayout> {
    let mut layout = default_create_layout(total_input_size);
    if let Some(value) = overrides.block_size {
        layout.block_size = parse_size_u32(value, "block-size")?;
    }
    if let Some(value) = overrides.envelope_size {
        layout.envelope_target_size = parse_size_u32(value, "envelope-size")?;
    }
    if let Some(value) = overrides.chunk_size {
        layout.chunk_size = parse_size_u32(value, "chunk-size")?;
        if overrides.envelope_size.is_none() && layout.chunk_size > layout.envelope_target_size {
            layout.envelope_target_size = layout.chunk_size;
        }
    }
    Ok(layout)
}

fn default_create_layout(total_input_size: Option<u64>) -> CreateLayout {
    match total_input_size {
        Some(size) if size <= LARGE_CREATE_LAYOUT_THRESHOLD => CreateLayout {
            block_size: 64 * 1024,
            chunk_size: 256 * 1024,
            envelope_target_size: 1024 * 1024,
        },
        Some(_) | None => CreateLayout {
            block_size: 1024 * 1024,
            chunk_size: 32 * 1024 * 1024,
            envelope_target_size: 64 * 1024 * 1024,
        },
    }
}

fn default_jobs() -> usize {
    std::thread::available_parallelism()
        .map(|jobs| jobs.get())
        .unwrap_or(1)
}

fn resolve_jobs(jobs: Option<usize>) -> Result<usize> {
    let jobs = jobs.unwrap_or_else(default_jobs);
    if jobs == 0 {
        return Err(UsageError("--jobs must be at least 1").into());
    }
    Ok(jobs)
}

fn validate_fast_verify_options(
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

fn reader_options(jobs: usize) -> ReaderOptions {
    ReaderOptions {
        jobs,
        ..ReaderOptions::default()
    }
}

fn non_seekable_reader_options(reader: ReaderOptions) -> NonSeekableReaderOptions {
    NonSeekableReaderOptions {
        reader,
        ..NonSeekableReaderOptions::default()
    }
}

fn metadata_diagnostic_line(path: &str, diagnostic: &MetadataDiagnostic) -> String {
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

fn emit_member_metadata_diagnostics(
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

fn metadata_diagnostic_lines_for_entries(entries: &[ArchiveEntry]) -> Vec<String> {
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
fn metadata_diagnostic_lines_for_paths(entries: &[ArchiveEntry], paths: &[String]) -> Vec<String> {
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

fn emit_entry_metadata_diagnostics(quiet: bool, entries: &[ArchiveEntry]) -> io::Result<()> {
    if quiet {
        return Ok(());
    }
    for line in metadata_diagnostic_lines_for_entries(entries) {
        eprintln!("{line}");
    }
    Ok(())
}

fn restore_policy_label(policy: RestorePolicy) -> &'static str {
    match policy {
        RestorePolicy::Content => "content",
        RestorePolicy::Portable => "portable",
        RestorePolicy::SameOs => "same-os",
        RestorePolicy::System => "system",
    }
}

fn metadata_verification_json(report: &MetadataVerificationReport) -> serde_json::Value {
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

fn emit_metadata_verification_stdout(
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

fn archive_index_entry_json(entry: &ArchiveIndexEntry) -> serde_json::Value {
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

fn archive_entry_kind_label(kind: TarEntryKind) -> &'static str {
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

fn emit_verify_json_error(
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

fn unsupported_revision_error_json(err: &anyhow::Error, action: &'static str) -> serde_json::Value {
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

#[derive(Debug)]
struct InputSpec {
    source: PathBuf,
    archive_path: String,
    entry_kind: SourceEntryKind,
    link_target: Option<Vec<u8>>,
    mode: u32,
    mtime: ArchiveTimestamp,
    portable_metadata: PortableFileMetadata,
    size: u64,
    sparse_extents: Option<Vec<SparseExtent>>,
    identity: InputIdentity,
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
                let file =
                    open_windows_metadata_handle(&self.source).map_err(ArchiveWriteError::Io)?;
                augment_windows_input_identity(&mut actual, &file)
                    .map_err(ArchiveWriteError::Io)?;
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
                    .is_ok_and(|kind| {
                        matches!(
                            kind,
                            WindowsKnownReparse::Junction | WindowsKnownReparse::Opaque
                        ) && metadata.is_dir()
                    }),
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
                        WindowsKnownReparse::RelativeSymlink { portable_target } => {
                            Some(portable_target)
                        }
                        WindowsKnownReparse::Junction | WindowsKnownReparse::Opaque => None,
                    });
                #[cfg(not(windows))]
                let actual_target = symlink_target_bytes(&self.source).ok();
                actual_target.as_deref() == self.link_target.as_deref()
            } else {
                true
            };
            if !kind_matches
                || !target_matches
                || !input_identity_matches_after_read(self.identity, actual)
            {
                return Err(ArchiveWriteError::Io(io::Error::other(
                    "non-regular input changed after scan",
                )));
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
        Ok(Box::new(IdentityCheckedInputReader {
            file,
            expected: self.identity,
            remaining: self.size,
            validated: false,
        }) as Box<dyn Read + '_>)
    }

    fn open_auxiliary(
        &self,
        ordinal: usize,
    ) -> std::result::Result<Box<dyn Read + '_>, ArchiveWriteError> {
        let record = self
            .portable_metadata
            .native
            .auxiliary_records
            .get(ordinal)
            .ok_or(FormatError::WriterInvariant(
                "auxiliary source ordinal is missing",
            ))?;
        if !record.is_streamed() {
            return Ok(Box::new(io::Cursor::new(record.payload.as_slice())));
        }
        #[cfg(target_os = "macos")]
        {
            if record.kind != "macos.resource-fork"
                || record.name_encoding != NativeAuxiliaryNameEncoding::None
                || !record.name.is_empty()
            {
                return Err(FormatError::WriterUnsupported(
                    "unsupported streamed macOS auxiliary source",
                )
                .into());
            }
            let source = if self.entry_kind == SourceEntryKind::Symlink {
                MacosResourceForkSource::Symlink(
                    open_macos_symlink(&self.source).map_err(ArchiveWriteError::Io)?,
                )
            } else {
                let file = File::open(&self.source).map_err(ArchiveWriteError::Io)?;
                open_macos_resource_fork_for_read(file).map_err(ArchiveWriteError::Io)?
            };
            Ok(Box::new(
                MacosResourceForkReader::new(source, self.identity, Some(record.logical_size))
                    .map_err(ArchiveWriteError::Io)?,
            ))
        }
        #[cfg(windows)]
        {
            if record.kind == "windows.efs-raw" {
                if record.name_encoding != NativeAuxiliaryNameEncoding::None
                    || !record.name.is_empty()
                {
                    return Err(FormatError::WriterUnsupported(
                        "raw EFS auxiliary source has an unexpected name",
                    )
                    .into());
                }
                return Ok(Box::new(WindowsRawEfsReader::spawn(
                    self.source.clone(),
                    self.identity,
                    record.stored_payload_size(),
                )));
            }
            if record.kind != "windows.alternate-data"
                || record.name_encoding != NativeAuxiliaryNameEncoding::Utf16Le
                || record.name.len() % 2 != 0
            {
                return Err(FormatError::WriterUnsupported(
                    "unsupported streamed Windows auxiliary source",
                )
                .into());
            }
            let metadata = fs::symlink_metadata(&self.source).map_err(ArchiveWriteError::Io)?;
            let mut actual = input_identity(&metadata).map_err(ArchiveWriteError::Io)?;
            let base = open_windows_metadata_handle(&self.source).map_err(ArchiveWriteError::Io)?;
            augment_windows_input_identity(&mut actual, &base).map_err(ArchiveWriteError::Io)?;
            if !input_identity_matches_after_read(self.identity, actual) {
                return Err(ArchiveWriteError::Io(io::Error::other(
                    "Windows input changed before alternate-stream read",
                )));
            }
            let stream_path = windows_alternate_stream_path(&self.source, &record.name)
                .map_err(ArchiveWriteError::Io)?;
            let stream = File::open(stream_path).map_err(ArchiveWriteError::Io)?;
            if stream.metadata().map_err(ArchiveWriteError::Io)?.len() != record.logical_size {
                return Err(ArchiveWriteError::Io(io::Error::other(
                    "Windows alternate stream changed after scan",
                )));
            }
            if let Some(extents) = record.streamed_sparse_extents() {
                let map = encode_v45_sparse_map(extents, record.logical_size)?;
                return Ok(Box::new(io::Cursor::new(map).chain(
                    WindowsSparseAlternateStreamReader {
                        file: stream,
                        logical_size: record.logical_size,
                        expected_extents: extents.to_vec(),
                        extent_index: 0,
                        extent_remaining: 0,
                        validated: false,
                    },
                )));
            }
            Ok(Box::new(stream))
        }
        #[cfg(not(any(windows, target_os = "macos")))]
        Err(
            FormatError::WriterUnsupported("streamed Windows auxiliary sources require Windows")
                .into(),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InputIdentity {
    len: u64,
    mtime: ArchiveTimestamp,
    mode: u32,
    attributes: Option<u32>,
    #[cfg(unix)]
    uid: u64,
    #[cfg(unix)]
    gid: u64,
    #[cfg(unix)]
    raw_mode: u32,
    #[cfg(unix)]
    link_count: u64,
    #[cfg(unix)]
    change_time_seconds: i64,
    #[cfg(unix)]
    change_time_nanoseconds: i64,
    #[cfg(unix)]
    creation_time: Option<ArchiveTimestamp>,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(windows)]
    creation_time_100ns: u64,
    #[cfg(windows)]
    last_access_time_100ns: u64,
    #[cfg(windows)]
    change_time_100ns: u64,
    #[cfg(windows)]
    file_attributes: u32,
    #[cfg(windows)]
    link_count: u64,
    #[cfg(windows)]
    volume_serial: u64,
    #[cfg(windows)]
    file_index: u64,
}

#[derive(Debug)]
struct CreateKey {
    master_key: MasterKey,
    kdf_params: KdfParams,
}

#[derive(Debug)]
enum CreateRootAuthProfile {
    Ed25519 {
        signing_key: SigningKey,
        signer_identity: [u8; 32],
    },
    X509(X509RootAuthSigner),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliX509SignatureScheme {
    #[value(name = "rsa-pkcs1-sha256")]
    RsaPkcs1Sha256,
    #[value(name = "ecdsa-sha256-der")]
    EcdsaSha256Der,
    #[value(name = "rsa-pss-sha256")]
    RsaPssSha256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum CliRestorePolicy {
    Content,
    Portable,
    #[value(name = "same-os")]
    SameOs,
    System,
}

impl From<CliRestorePolicy> for RestorePolicy {
    fn from(value: CliRestorePolicy) -> Self {
        match value {
            CliRestorePolicy::Content => Self::Content,
            CliRestorePolicy::Portable => Self::Portable,
            CliRestorePolicy::SameOs => Self::SameOs,
            CliRestorePolicy::System => Self::System,
        }
    }
}

impl CliX509SignatureScheme {
    fn to_plugin_scheme(self) -> X509SignatureScheme {
        match self {
            Self::RsaPkcs1Sha256 => X509SignatureScheme::RsaPkcs1Sha256,
            Self::EcdsaSha256Der => X509SignatureScheme::EcdsaSha256Der,
            Self::RsaPssSha256 => X509SignatureScheme::RsaPssSha256,
        }
    }
}

#[derive(Debug)]
enum VerifiedRootAuth {
    Ed25519(RootAuthVerification),
    X509 {
        verification: RootAuthVerification,
        report: Box<X509RootAuthReport>,
    },
}

#[derive(Debug)]
enum PublicNoKeyTrust {
    Ed25519 {
        public_key: [u8; 32],
    },
    X509 {
        trusted_roots_der: Vec<Vec<u8>>,
        trusted_system_roots: bool,
    },
}

#[derive(Debug)]
enum VerifiedPublicNoKeyRootAuth {
    Ed25519(PublicNoKeyVerification),
    X509 {
        verification: PublicNoKeyVerification,
        report: Box<X509RootAuthReport>,
    },
}

#[derive(Debug, Clone, Copy)]
enum CreateStdinMode {
    Tar,
    RawUnknownSize,
    RawKnownSize,
    RawSpool,
}

#[derive(Debug)]
struct CreateStdinArgs<'a> {
    tar_stdin: bool,
    raw_stdin: bool,
    stdin_name: Option<&'a str>,
    stdin_size: Option<&'a str>,
    spool_stdin: bool,
    paths: &'a [String],
    password_stdin: bool,
    password: bool,
    has_dictionary: bool,
    volumes: Option<u32>,
    volume_size: Option<&'a str>,
    volume_loss_tolerance: Option<u8>,
}

#[derive(Debug, Clone, Copy)]
struct Diagnostic {
    label: &'static str,
    exit_code: u8,
    action: &'static str,
}

#[derive(Debug)]
struct UsageError(&'static str);

impl std::fmt::Display for UsageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for UsageError {}

fn collect_input_specs(paths: &[String]) -> Result<Vec<InputSpec>> {
    let mut out = Vec::new();
    for path in paths {
        let input = PathBuf::from(path);
        let base = input
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| anyhow!("input path has no valid UTF-8 file name: {path}"))?
            .to_owned();
        collect_one_input_spec(&input, Path::new(&base), &mut out)
            .with_context(|| format!("failed to collect input {path}"))?;
    }
    out.sort_by(|left, right| left.archive_path.cmp(&right.archive_path));
    #[cfg(any(unix, windows))]
    apply_selected_hardlink_topology(&mut out)?;
    Ok(out)
}

#[cfg(any(unix, windows))]
fn apply_selected_hardlink_topology(specs: &mut [InputSpec]) -> Result<()> {
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
            let (canonical_target, mode, mtime, mut portable_metadata) = (
                canonical.archive_path.as_bytes().to_vec(),
                canonical.mode,
                canonical.mtime,
                canonical.portable_metadata.clone(),
            );
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

fn input_specs_total_size(specs: &[InputSpec]) -> Result<u64> {
    specs.iter().try_fold(0u64, |sum, entry| {
        sum.checked_add(entry.size)
            .ok_or_else(|| anyhow!("input byte count overflow"))
    })
}

fn collect_one_input_spec(
    input: &Path,
    archive_path: &Path,
    out: &mut Vec<InputSpec>,
) -> Result<()> {
    #[cfg(windows)]
    use std::os::windows::fs::MetadataExt as _;

    let metadata = fs::symlink_metadata(input)
        .with_context(|| format!("failed to inspect input {}", input.display()))?;
    #[cfg(windows)]
    if metadata.file_attributes() & 0x0000_1000 != 0 {
        // This must precede every handle open, reparse query, directory enumeration, and data
        // read. Cloud providers may combine OFFLINE with REPARSE_POINT, and touching the
        // placeholder through those paths can hydrate it before the ordinary-file guard runs.
        bail!(
            "Windows metadata capture does not support {}: offline/cloud placeholders require an explicit hydration policy",
            input.display()
        );
    }
    #[cfg(windows)]
    if metadata.file_attributes() & 0x0000_0400 != 0 {
        return collect_windows_known_reparse_input(input, archive_path, metadata, out);
    }
    if metadata.file_type().is_symlink() {
        let archive_path = archive_path_to_string(archive_path)?;
        let identity = input_identity(&metadata)
            .with_context(|| format!("failed to identify symlink {}", input.display()))?;
        let link_target = symlink_target_bytes(input)
            .with_context(|| format!("failed to read symlink {}", input.display()))?;
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
        let identity = input_identity(&metadata)
            .with_context(|| format!("failed to identify input {}", input.display()))?;
        #[cfg(windows)]
        let identity = {
            let mut identity = identity;
            let file = open_windows_metadata_handle(input)
                .with_context(|| format!("failed to open Windows directory {}", input.display()))?;
            augment_windows_input_identity(&mut identity, &file).with_context(|| {
                format!("failed to identify Windows directory {}", input.display())
            })?;
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
        let mut entries = fs::read_dir(input)
            .with_context(|| format!("failed to read directory {}", input.display()))?
            .collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let child_name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow!("input path is not valid UTF-8"))?;
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
            let identity = input_identity(&metadata)
                .with_context(|| format!("failed to identify input {}", input.display()))?;
            let mut portable_metadata = portable_input_metadata(identity, input)?;
            portable_metadata
                .native
                .required_profiles
                .push("posix-backup-v1".into());
            if matches!(
                entry_kind,
                SourceEntryKind::CharacterDevice | SourceEntryKind::BlockDevice
            ) {
                let device = libc::dev_t::try_from(metadata.st_rdev())
                    .map_err(|_| anyhow!("device identifier exceeds host ABI"))?;
                let major = libc::major(device);
                let minor = libc::minor(device);
                portable_metadata.native.primary_pax_records.insert(
                    "TZAP.posix.device-major".into(),
                    major.to_string().into_bytes(),
                );
                portable_metadata.native.primary_pax_records.insert(
                    "TZAP.posix.device-minor".into(),
                    minor.to_string().into_bytes(),
                );
                #[cfg(target_os = "linux")]
                if entry_kind == SourceEntryKind::CharacterDevice && major == 0 && minor == 0 {
                    portable_metadata
                        .native
                        .primary_pax_records
                        .insert("TZAP.linux.whiteout".into(), b"1".to_vec());
                    portable_metadata
                        .native
                        .required_profiles
                        .push("linux-backup-v1".into());
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
    let identity = input_identity(&metadata)
        .with_context(|| format!("failed to identify input {}", input.display()))?;
    #[cfg(windows)]
    let (identity, sparse_extents, sparse_layout_partial) = {
        let mut identity = identity;
        let file = File::open(input)
            .with_context(|| format!("failed to open {} for identity capture", input.display()))?;
        augment_windows_input_identity(&mut identity, &file)
            .with_context(|| format!("failed to identify Windows input {}", input.display()))?;
        const FILE_ATTRIBUTE_SPARSE_FILE: u32 = 0x0000_0200;
        let sparse_extents = if identity.file_attributes & FILE_ATTRIBUTE_SPARSE_FILE != 0 {
            Some(
                query_windows_allocated_ranges(&file, identity.len).with_context(|| {
                    format!(
                        "failed to query sparse ranges for Windows input {}",
                        input.display()
                    )
                })?,
            )
        } else {
            None
        };
        let sparse_layout_partial = sparse_extents.is_some() && windows_file_system_is_refs(&file)?;
        (identity, sparse_extents, sparse_layout_partial)
    };
    #[cfg(target_os = "linux")]
    let sparse_extents = {
        let file = File::open(input).with_context(|| {
            format!(
                "failed to open {} for sparse-range capture",
                input.display()
            )
        })?;
        query_linux_sparse_extents(&file, identity.len).with_context(|| {
            format!(
                "failed to query sparse ranges for Linux input {}",
                input.display()
            )
        })?
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

#[cfg(windows)]
fn add_windows_refs_sparse_layout_omission(native: &mut NativeFileMetadata) {
    const HEADER: &str = "tzap-capture-report-v1\n";
    const ROW: &str = "windows-backup-v1\tsparse-layout\tunsupported-filesystem\tReFS%20does%20not%20expose%20exact%20sparse%20ranges";
    if let Some(report) = native
        .auxiliary_records
        .iter_mut()
        .find(|record| record.kind == "tzap.capture-report")
    {
        let text = std::str::from_utf8(&report.payload)
            .expect("internally generated capture reports are UTF-8");
        let mut rows = text
            .strip_prefix(HEADER)
            .expect("internally generated capture report has canonical header")
            .split_terminator('\n')
            .collect::<Vec<_>>();
        rows.push(ROW);
        rows.sort_unstable();
        rows.dedup();
        report.payload = format!("{HEADER}{}\n", rows.join("\n")).into_bytes();
        report.logical_size = report.payload.len() as u64;
        return;
    }
    let payload = format!("{HEADER}{ROW}\n").into_bytes();
    let mut report = NativeAuxiliaryMetadata::new(
        "tzap.capture-report",
        "tzap-core-v1",
        RestoreClass::None,
        payload,
    );
    report.native = false;
    native.auxiliary_records.push(report);
}

#[cfg(target_os = "linux")]
fn query_linux_sparse_extents(
    file: &File,
    logical_size: u64,
) -> io::Result<Option<Vec<SparseExtent>>> {
    use std::os::fd::AsRawFd;

    if logical_size == 0 {
        return Ok(None);
    }
    let end = libc::off_t::try_from(logical_size)
        .map_err(|_| io::Error::other("file size exceeds Linux off_t"))?;
    let fd = file.as_raw_fd();
    let mut cursor: libc::off_t = 0;
    let mut extents = Vec::new();
    while cursor < end {
        // SAFETY: `fd` is live and SEEK_DATA does not mutate caller memory.
        let data = unsafe { libc::lseek(fd, cursor, libc::SEEK_DATA) };
        if data < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENXIO) {
                break;
            }
            if cursor == 0
                && error.raw_os_error().is_some_and(|code| {
                    code == libc::EINVAL || code == libc::EOPNOTSUPP || code == libc::ENOTSUP
                })
            {
                return Ok(None);
            }
            return Err(error);
        }
        // SAFETY: as above, SEEK_HOLE only updates the descriptor offset.
        let hole = unsafe { libc::lseek(fd, data, libc::SEEK_HOLE) };
        if hole < 0 {
            return Err(io::Error::last_os_error());
        }
        let data = u64::try_from(data).map_err(|_| io::Error::other("negative data offset"))?;
        let hole = u64::try_from(hole).map_err(|_| io::Error::other("negative hole offset"))?;
        let hole = hole.min(logical_size);
        if hole <= data {
            return Err(io::Error::other("Linux sparse-range query did not advance"));
        }
        extents.push(SparseExtent {
            offset: data,
            length: hole - data,
        });
        cursor = libc::off_t::try_from(hole)
            .map_err(|_| io::Error::other("sparse offset exceeds Linux off_t"))?;
    }

    let allocated = extents.iter().try_fold(0u64, |sum, extent| {
        sum.checked_add(extent.length)
            .ok_or_else(|| io::Error::other("sparse extent length overflow"))
    })?;
    Ok((allocated < logical_size).then_some(extents))
}

#[cfg(windows)]
fn collect_windows_known_reparse_input(
    input: &Path,
    archive_path: &Path,
    metadata: fs::Metadata,
    out: &mut Vec<InputSpec>,
) -> Result<()> {
    let file = open_windows_metadata_handle(input)
        .with_context(|| format!("failed to open Windows reparse point {}", input.display()))?;
    let mut identity = input_identity(&metadata)
        .with_context(|| format!("failed to identify reparse point {}", input.display()))?;
    augment_windows_input_identity(&mut identity, &file)
        .with_context(|| format!("failed to identify reparse point {}", input.display()))?;
    let reparse_data = query_windows_reparse_data(&file)
        .with_context(|| format!("failed to query reparse point {}", input.display()))?;
    let known = validate_windows_known_reparse_data(&reparse_data)
        .with_context(|| format!("unsupported Windows reparse point {}", input.display()))?;
    let archive_path = archive_path_to_string(archive_path)?;
    let mut portable_metadata = portable_input_metadata(identity, input)?;
    match known {
        WindowsKnownReparse::RelativeSymlink { portable_target } => {
            out.push(InputSpec {
                source: input.to_owned(),
                archive_path,
                entry_kind: SourceEntryKind::Symlink,
                link_target: Some(portable_target),
                mode: readonly_mode(&metadata),
                mtime: identity.mtime,
                portable_metadata,
                size: 0,
                sparse_extents: None,
                identity,
            });
        }
        WindowsKnownReparse::Junction => {
            portable_metadata
                .native
                .primary_pax_records
                .insert("TZAP.windows.reparse-placeholder".into(), b"1".to_vec());
            out.push(InputSpec {
                source: input.to_owned(),
                archive_path,
                entry_kind: SourceEntryKind::ReparseDirectory,
                link_target: None,
                mode: readonly_mode(&metadata),
                mtime: identity.mtime,
                portable_metadata,
                size: 0,
                sparse_extents: None,
                identity,
            });
        }
        WindowsKnownReparse::Opaque => {
            portable_metadata
                .native
                .primary_pax_records
                .insert("TZAP.windows.reparse-placeholder".into(), b"1".to_vec());
            out.push(InputSpec {
                source: input.to_owned(),
                archive_path,
                entry_kind: if metadata.is_dir() {
                    SourceEntryKind::ReparseDirectory
                } else {
                    SourceEntryKind::ReparseRegular
                },
                link_target: None,
                mode: readonly_mode(&metadata),
                mtime: identity.mtime,
                portable_metadata,
                size: 0,
                sparse_extents: None,
                identity,
            });
        }
    }
    Ok(())
}

#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq)]
enum WindowsKnownReparse {
    RelativeSymlink { portable_target: Vec<u8> },
    Junction,
    Opaque,
}

#[cfg(windows)]
fn query_windows_reparse_data(file: &File) -> io::Result<Vec<u8>> {
    use std::os::windows::io::AsRawHandle;
    use std::ptr;
    use windows_sys::Win32::System::Ioctl::FSCTL_GET_REPARSE_POINT;
    use windows_sys::Win32::System::IO::DeviceIoControl;

    const MAX_REPARSE_DATA_BUFFER_SIZE: usize = 16 * 1024;
    let mut buffer = vec![0u8; MAX_REPARSE_DATA_BUFFER_SIZE];
    let mut bytes_returned = 0u32;
    // SAFETY: the handle is live and the fixed output allocation remains valid for this
    // synchronous call. FSCTL_GET_REPARSE_POINT has no input buffer.
    if unsafe {
        DeviceIoControl(
            file.as_raw_handle().cast(),
            FSCTL_GET_REPARSE_POINT,
            ptr::null(),
            0,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
            &mut bytes_returned,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    buffer.truncate(bytes_returned as usize);
    if buffer.len() < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "reparse buffer is truncated",
        ));
    }
    let tag = u32::from_le_bytes(buffer[0..4].try_into().unwrap());
    let declared = usize::from(u16::from_le_bytes([buffer[4], buffer[5]]));
    let header_len = if tag & 0x8000_0000 == 0 { 24 } else { 8 };
    if declared + header_len != buffer.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "reparse buffer length is inconsistent",
        ));
    }
    Ok(buffer)
}

#[cfg(windows)]
fn validate_windows_known_reparse_data(data: &[u8]) -> io::Result<WindowsKnownReparse> {
    const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
    const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
    const SYMLINK_FLAG_RELATIVE: u32 = 1;

    let invalid = |message| io::Error::new(io::ErrorKind::InvalidData, message);
    if data.len() < 8 {
        return Err(invalid("reparse buffer is truncated"));
    }
    let tag = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let payload_len = usize::from(u16::from_le_bytes(data[4..6].try_into().unwrap()));
    let header_len = if tag & 0x8000_0000 == 0 { 24 } else { 8 };
    if payload_len + header_len != data.len() {
        return Err(invalid("reparse buffer length is inconsistent"));
    }
    let (fixed_len, flags) = match tag {
        IO_REPARSE_TAG_SYMLINK => {
            if payload_len < 12 {
                return Err(invalid("symbolic-link reparse payload is truncated"));
            }
            (
                12usize,
                u32::from_le_bytes(data[16..20].try_into().unwrap()),
            )
        }
        IO_REPARSE_TAG_MOUNT_POINT => {
            if payload_len < 8 {
                return Err(invalid("mount-point reparse payload is truncated"));
            }
            (8usize, 0)
        }
        _ => return Ok(WindowsKnownReparse::Opaque),
    };
    let substitute_offset = usize::from(u16::from_le_bytes(data[8..10].try_into().unwrap()));
    let substitute_len = usize::from(u16::from_le_bytes(data[10..12].try_into().unwrap()));
    let print_offset = usize::from(u16::from_le_bytes(data[12..14].try_into().unwrap()));
    let print_len = usize::from(u16::from_le_bytes(data[14..16].try_into().unwrap()));
    if substitute_offset % 2 != 0
        || substitute_len % 2 != 0
        || print_offset % 2 != 0
        || print_len % 2 != 0
    {
        return Err(invalid("reparse path fields are not UTF-16 aligned"));
    }
    let path_buffer = &data[8 + fixed_len..];
    let decode_name = |offset: usize, len: usize| -> io::Result<String> {
        let end = offset
            .checked_add(len)
            .ok_or_else(|| invalid("reparse path range overflows"))?;
        let bytes = path_buffer
            .get(offset..end)
            .ok_or_else(|| invalid("reparse path range exceeds the payload"))?;
        let units = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        let text =
            String::from_utf16(&units).map_err(|_| invalid("reparse path is not valid UTF-16"))?;
        if text.contains('\0') {
            return Err(invalid("reparse path contains NUL"));
        }
        Ok(text)
    };
    let substitute = decode_name(substitute_offset, substitute_len)?;
    let print = decode_name(print_offset, print_len)?;
    if substitute.is_empty() {
        return Err(invalid("reparse substitute name is empty"));
    }

    if tag == IO_REPARSE_TAG_SYMLINK {
        if flags != SYMLINK_FLAG_RELATIVE {
            return Err(invalid(
                "only relative Windows symbolic links are supported",
            ));
        }
        let target = if print.is_empty() { substitute } else { print };
        let target = target.replace('\\', "/").into_bytes();
        if target.is_empty() || target[0] == b'/' || target.contains(&b':') {
            return Err(invalid("Windows symbolic-link target is absolute"));
        }
        Ok(WindowsKnownReparse::RelativeSymlink {
            portable_target: target,
        })
    } else {
        if !substitute.starts_with("\\??\\") || print.is_empty() {
            return Err(invalid("junction path fields are not canonical"));
        }
        Ok(WindowsKnownReparse::Junction)
    }
}

fn input_identity(metadata: &fs::Metadata) -> io::Result<InputIdentity> {
    Ok(InputIdentity {
        len: metadata.len(),
        mtime: archive_timestamp(metadata.modified()?)?,
        mode: readonly_mode(metadata),
        attributes: portable_attributes(metadata),
        #[cfg(unix)]
        uid: {
            use std::os::unix::fs::MetadataExt;
            metadata.uid() as u64
        },
        #[cfg(unix)]
        gid: {
            use std::os::unix::fs::MetadataExt;
            metadata.gid() as u64
        },
        #[cfg(unix)]
        raw_mode: {
            use std::os::unix::fs::MetadataExt;
            metadata.mode()
        },
        #[cfg(unix)]
        link_count: {
            use std::os::unix::fs::MetadataExt;
            metadata.nlink()
        },
        #[cfg(unix)]
        change_time_seconds: {
            use std::os::unix::fs::MetadataExt;
            metadata.ctime()
        },
        #[cfg(unix)]
        change_time_nanoseconds: {
            use std::os::unix::fs::MetadataExt;
            metadata.ctime_nsec()
        },
        #[cfg(unix)]
        creation_time: metadata
            .created()
            .ok()
            .and_then(|time| archive_timestamp(time).ok()),
        #[cfg(unix)]
        dev: {
            use std::os::unix::fs::MetadataExt;
            metadata.dev()
        },
        #[cfg(unix)]
        ino: {
            use std::os::unix::fs::MetadataExt;
            metadata.ino()
        },
        #[cfg(windows)]
        creation_time_100ns: {
            use std::os::windows::fs::MetadataExt;
            metadata.creation_time()
        },
        #[cfg(windows)]
        last_access_time_100ns: {
            use std::os::windows::fs::MetadataExt;
            metadata.last_access_time()
        },
        #[cfg(windows)]
        change_time_100ns: 0,
        #[cfg(windows)]
        file_attributes: {
            use std::os::windows::fs::MetadataExt;
            metadata.file_attributes()
        },
        #[cfg(windows)]
        link_count: 0,
        #[cfg(windows)]
        volume_serial: 0,
        #[cfg(windows)]
        file_index: 0,
    })
}

fn validate_opened_input_identity(file: &File, expected: InputIdentity) -> io::Result<()> {
    let actual_metadata = file.metadata()?;
    let actual = input_identity(&actual_metadata)?;
    #[cfg(windows)]
    let actual = {
        let mut actual = actual;
        augment_windows_input_identity(&mut actual, file)?;
        actual
    };
    if !input_identity_matches_after_read(expected, actual) {
        return Err(io::Error::other("input changed after scan"));
    }
    Ok(())
}

fn input_identity_matches_after_read(expected: InputIdentity, actual: InputIdentity) -> bool {
    #[cfg(windows)]
    {
        let mut expected = expected;
        let mut actual = actual;
        // Opening and reading the file may update LastAccessTime. Preserve the pre-read value in
        // the archive, but exclude this self-induced field from the final source identity check.
        expected.last_access_time_100ns = 0;
        actual.last_access_time_100ns = 0;
        expected == actual
    }
    #[cfg(all(unix, not(windows)))]
    {
        expected == actual
    }
    #[cfg(not(any(unix, windows)))]
    {
        expected == actual
    }
}

#[cfg(windows)]
fn augment_windows_input_identity(identity: &mut InputIdentity, file: &File) -> io::Result<()> {
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileBasicInfo, GetFileInformationByHandle, GetFileInformationByHandleEx,
        BY_HANDLE_FILE_INFORMATION, FILE_BASIC_INFO,
    };

    let handle = file.as_raw_handle().cast();
    let mut basic = FILE_BASIC_INFO::default();
    // SAFETY: `handle` is live and both output pointers reference correctly sized structures.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileBasicInfo,
            (&mut basic as *mut FILE_BASIC_INFO).cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut by_handle = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `handle` is live and `by_handle` is a valid writable output structure.
    if unsafe { GetFileInformationByHandle(handle, &mut by_handle) } == 0 {
        return Err(io::Error::last_os_error());
    }
    identity.creation_time_100ns = basic.CreationTime as u64;
    identity.last_access_time_100ns = basic.LastAccessTime as u64;
    identity.change_time_100ns = basic.ChangeTime as u64;
    identity.file_attributes = basic.FileAttributes;
    identity.link_count = u64::from(by_handle.nNumberOfLinks);
    identity.volume_serial = u64::from(by_handle.dwVolumeSerialNumber);
    identity.file_index =
        (u64::from(by_handle.nFileIndexHigh) << 32) | u64::from(by_handle.nFileIndexLow);
    Ok(())
}

#[cfg(windows)]
fn query_windows_allocated_ranges(file: &File, logical_size: u64) -> io::Result<Vec<SparseExtent>> {
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;
    use std::ptr;
    use windows_sys::Win32::Foundation::ERROR_MORE_DATA;
    use windows_sys::Win32::System::Ioctl::{
        FILE_ALLOCATED_RANGE_BUFFER, FSCTL_QUERY_ALLOCATED_RANGES,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;

    const QUERY_BATCH: usize = 1024;
    const MAX_EXTENTS: usize = 1_048_576;
    if logical_size == 0 {
        return Ok(Vec::new());
    }
    // FSCTL_QUERY_ALLOCATED_RANGES is not supported by ReFS. Retrieval pointers do not resolve
    // the ambiguity: ReFS reports LCN -1 for a run that may be either a hole or partially
    // allocated. Materialize the logical bytes and pair this fallback with an authenticated
    // sparse-layout omission so the archive cannot claim exact storage-layout fidelity.
    if windows_file_system_is_refs(file)? {
        return Ok(vec![SparseExtent {
            offset: 0,
            length: logical_size,
        }]);
    }
    let logical_size_i64 = i64::try_from(logical_size)
        .map_err(|_| io::Error::other("sparse logical size exceeds Windows range API"))?;
    let mut query_start = 0u64;
    let mut extents = Vec::<SparseExtent>::new();
    while query_start < logical_size {
        let mut query = FILE_ALLOCATED_RANGE_BUFFER {
            FileOffset: i64::try_from(query_start)
                .map_err(|_| io::Error::other("sparse query offset exceeds Windows range API"))?,
            Length: logical_size_i64 - query_start as i64,
        };
        let mut output = [FILE_ALLOCATED_RANGE_BUFFER::default(); QUERY_BATCH];
        let mut bytes_returned = 0u32;
        // SAFETY: the live file handle and fixed-size input/output buffers remain valid for the
        // synchronous DeviceIoControl call, and the byte lengths exactly match those buffers.
        let success = unsafe {
            DeviceIoControl(
                file.as_raw_handle().cast(),
                FSCTL_QUERY_ALLOCATED_RANGES,
                (&mut query as *mut FILE_ALLOCATED_RANGE_BUFFER).cast(),
                size_of::<FILE_ALLOCATED_RANGE_BUFFER>() as u32,
                output.as_mut_ptr().cast(),
                size_of::<[FILE_ALLOCATED_RANGE_BUFFER; QUERY_BATCH]>() as u32,
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };
        let error = io::Error::last_os_error();
        if success == 0 && error.raw_os_error() != Some(ERROR_MORE_DATA as i32) {
            return Err(error);
        }
        if bytes_returned as usize % size_of::<FILE_ALLOCATED_RANGE_BUFFER>() != 0 {
            return Err(io::Error::other(
                "Windows returned a truncated allocated-range row",
            ));
        }
        let count = bytes_returned as usize / size_of::<FILE_ALLOCATED_RANGE_BUFFER>();
        if count > QUERY_BATCH || (success == 0 && count == 0) {
            return Err(io::Error::other(
                "Windows allocated-range query made no progress",
            ));
        }
        let mut next_query_start = query_start;
        for range in &output[..count] {
            if range.FileOffset < 0 || range.Length <= 0 {
                return Err(io::Error::other(
                    "Windows returned an invalid allocated range",
                ));
            }
            let offset = range.FileOffset as u64;
            let end = offset
                .checked_add(range.Length as u64)
                .ok_or_else(|| io::Error::other("Windows allocated range overflow"))?
                .min(logical_size);
            if offset >= logical_size || end <= offset {
                return Err(io::Error::other(
                    "Windows returned an out-of-bounds allocated range",
                ));
            }
            if let Some(previous) = extents.last_mut() {
                let previous_end = previous.offset + previous.length;
                if offset <= previous_end {
                    previous.length = previous_end.max(end) - previous.offset;
                } else {
                    extents.push(SparseExtent {
                        offset,
                        length: end - offset,
                    });
                }
            } else {
                extents.push(SparseExtent {
                    offset,
                    length: end - offset,
                });
            }
            if extents.len() > MAX_EXTENTS {
                return Err(io::Error::other(
                    "sparse extent count exceeds revision-45 limit",
                ));
            }
            next_query_start = next_query_start.max(end);
        }
        if success != 0 {
            break;
        }
        if next_query_start <= query_start {
            return Err(io::Error::other(
                "Windows allocated-range query did not advance",
            ));
        }
        query_start = next_query_start;
    }
    Ok(extents)
}

#[cfg(windows)]
fn windows_file_system_is_refs(file: &File) -> io::Result<bool> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::GetVolumeInformationByHandleW;

    let mut name = [0u16; 32];
    // SAFETY: the file handle is live, optional outputs are null, and `name` is writable for the
    // exact capacity supplied to this synchronous query.
    if unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle().cast(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            name.as_mut_ptr(),
            name.len() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let length = name
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(name.len());
    Ok(String::from_utf16_lossy(&name[..length]).eq_ignore_ascii_case("refs"))
}

#[cfg(windows)]
fn open_windows_metadata_handle(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

struct IdentityCheckedInputReader {
    file: File,
    expected: InputIdentity,
    remaining: u64,
    validated: bool,
}

struct SparseExtentInputReader<'a> {
    file: File,
    expected: InputIdentity,
    expected_extents: &'a [SparseExtent],
    extent_index: usize,
    extent_remaining: u64,
    validated: bool,
}

#[cfg(target_os = "macos")]
enum MacosResourceForkSource {
    File { owner: File, fork: File },
    Symlink(File),
}

#[cfg(target_os = "macos")]
fn open_macos_symlink(input: &Path) -> io::Result<File> {
    use std::ffi::CString;
    use std::os::fd::FromRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;

    const O_SYMLINK: libc::c_int = 0x0020_0000;
    let path = CString::new(input.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))?;
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC | O_SYMLINK) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

#[cfg(target_os = "macos")]
fn open_macos_resource_fork_for_read(owner: File) -> io::Result<MacosResourceForkSource> {
    use std::ffi::OsString;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::ffi::OsStringExt as _;
    use std::os::unix::fs::MetadataExt as _;

    let mut path = vec![0u8; libc::PATH_MAX as usize];
    if unsafe { libc::fcntl(owner.as_raw_fd(), libc::F_GETPATH, path.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let length = path.iter().position(|byte| *byte == 0).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "macOS returned an unterminated descriptor path",
        )
    })?;
    path.truncate(length);
    path.extend_from_slice(b"/..namedfork/rsrc");
    let fork = File::open(PathBuf::from(OsString::from_vec(path)))?;
    let owner_metadata = owner.metadata()?;
    let fork_metadata = fork.metadata()?;
    if owner_metadata.dev() != fork_metadata.dev() || owner_metadata.ino() != fork_metadata.ino() {
        return Err(io::Error::other(
            "resource fork path no longer identifies the pinned file",
        ));
    }
    Ok(MacosResourceForkSource::File { owner, fork })
}

#[cfg(target_os = "macos")]
struct MacosResourceForkReader {
    source: MacosResourceForkSource,
    expected: InputIdentity,
    logical_size: u64,
    offset: u64,
    validated: bool,
}

#[cfg(target_os = "macos")]
impl MacosResourceForkReader {
    fn new(
        source: MacosResourceForkSource,
        expected: InputIdentity,
        expected_size: Option<u64>,
    ) -> io::Result<Self> {
        let actual = Self::identity(&source)?;
        if actual != expected {
            return Err(io::Error::other(
                "macOS resource-fork owner changed before read",
            ));
        }
        let logical_size = macos_resource_fork_size(&source)?;
        if expected_size.is_some_and(|size| size != logical_size) {
            return Err(io::Error::other(
                "macOS resource fork changed after metadata scan",
            ));
        }
        if matches!(&source, MacosResourceForkSource::Symlink(_))
            && logical_size > u64::from(u32::MAX)
        {
            return Err(io::Error::other(
                "macOS resource fork exceeds Darwin positional xattr limits",
            ));
        }
        Ok(Self {
            source,
            expected,
            logical_size,
            offset: 0,
            validated: false,
        })
    }

    fn identity(source: &MacosResourceForkSource) -> io::Result<InputIdentity> {
        match source {
            MacosResourceForkSource::File { owner, .. } => input_identity(&owner.metadata()?),
            MacosResourceForkSource::Symlink(file) => {
                let metadata = file.metadata()?;
                if !metadata.file_type().is_symlink() {
                    return Err(io::Error::other(
                        "macOS resource-fork owner is no longer a symlink",
                    ));
                }
                input_identity(&metadata)
            }
        }
    }

    fn validate_finished(&mut self) -> io::Result<()> {
        if !self.validated {
            if Self::identity(&self.source)? != self.expected
                || macos_resource_fork_size(&self.source)? != self.logical_size
            {
                return Err(io::Error::other("macOS resource fork changed during read"));
            }
            self.validated = true;
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
impl Read for MacosResourceForkReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.offset == self.logical_size {
            self.validate_finished()?;
            return Ok(0);
        }
        let count =
            usize::try_from((self.logical_size - self.offset).min(out.len() as u64)).unwrap();
        let read = macos_read_resource_fork(&self.source, self.offset, &mut out[..count])?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "macOS resource fork ended before its scanned size",
            ));
        }
        self.offset += read as u64;
        if self.offset == self.logical_size {
            self.validate_finished()?;
        }
        Ok(read)
    }
}

#[cfg(target_os = "macos")]
fn macos_resource_fork_size(source: &MacosResourceForkSource) -> io::Result<u64> {
    use std::ffi::{c_char, c_int, c_void};
    use std::os::fd::AsRawFd as _;

    extern "C" {
        fn fgetxattr(
            fd: c_int,
            name: *const c_char,
            value: *mut c_void,
            size: usize,
            position: u32,
            options: c_int,
        ) -> libc::ssize_t;
    }
    const RESOURCE_FORK: &[u8] = b"com.apple.ResourceFork\0";
    let size = match source {
        MacosResourceForkSource::File { fork, .. } => return Ok(fork.metadata()?.len()),
        MacosResourceForkSource::Symlink(file) => unsafe {
            fgetxattr(
                file.as_raw_fd(),
                RESOURCE_FORK.as_ptr().cast(),
                std::ptr::null_mut(),
                0,
                0,
                0,
            )
        },
    };
    if size < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(size as u64)
    }
}

#[cfg(target_os = "macos")]
fn macos_read_resource_fork(
    source: &MacosResourceForkSource,
    position: u64,
    out: &mut [u8],
) -> io::Result<usize> {
    use std::ffi::{c_char, c_int, c_void};
    use std::os::fd::AsRawFd as _;

    extern "C" {
        fn fgetxattr(
            fd: c_int,
            name: *const c_char,
            value: *mut c_void,
            size: usize,
            position: u32,
            options: c_int,
        ) -> libc::ssize_t;
    }
    const RESOURCE_FORK: &[u8] = b"com.apple.ResourceFork\0";
    let read = match source {
        MacosResourceForkSource::File { fork, .. } => {
            use std::os::unix::fs::FileExt as _;
            return fork.read_at(out, position);
        }
        MacosResourceForkSource::Symlink(file) => unsafe {
            fgetxattr(
                file.as_raw_fd(),
                RESOURCE_FORK.as_ptr().cast(),
                out.as_mut_ptr().cast(),
                out.len(),
                u32::try_from(position).map_err(|_| {
                    io::Error::other("macOS symlink resource fork exceeds Darwin positional limits")
                })?,
                0,
            )
        },
    };
    if read < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(read as usize)
    }
}

#[cfg(windows)]
fn windows_alternate_stream_path(base: &Path, name: &[u8]) -> io::Result<PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};

    if name.len() % 2 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows alternate stream name is not UTF-16LE",
        ));
    }
    let mut stream_path = base.as_os_str().encode_wide().collect::<Vec<_>>();
    stream_path.extend(
        name.chunks_exact(2)
            .map(|unit| u16::from_le_bytes([unit[0], unit[1]])),
    );
    Ok(PathBuf::from(OsString::from_wide(&stream_path)))
}

#[cfg(windows)]
struct WindowsSparseAlternateStreamReader {
    file: File,
    logical_size: u64,
    expected_extents: Vec<SparseExtent>,
    extent_index: usize,
    extent_remaining: u64,
    validated: bool,
}

#[cfg(windows)]
impl WindowsSparseAlternateStreamReader {
    fn validate_finished(&mut self) -> io::Result<()> {
        if !self.validated {
            if self.file.metadata()?.len() != self.logical_size
                || query_windows_allocated_ranges(&self.file, self.logical_size)?
                    != self.expected_extents
            {
                return Err(io::Error::other(
                    "sparse Windows alternate stream changed after scan",
                ));
            }
            self.validated = true;
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Read for WindowsSparseAlternateStreamReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let mut written = 0usize;
        while written < out.len() {
            if self.extent_remaining == 0 {
                let Some(extent) = self.expected_extents.get(self.extent_index) else {
                    self.validate_finished()?;
                    break;
                };
                self.file.seek(SeekFrom::Start(extent.offset))?;
                self.extent_remaining = extent.length;
            }
            let count = (out.len() - written)
                .min(usize::try_from(self.extent_remaining).unwrap_or(usize::MAX));
            let read = self.file.read(&mut out[written..written + count])?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "sparse Windows alternate extent ended before its scanned size",
                ));
            }
            written += read;
            self.extent_remaining -= read as u64;
            if self.extent_remaining == 0 {
                self.extent_index += 1;
            }
        }
        if self.extent_index == self.expected_extents.len() && self.extent_remaining == 0 {
            self.validate_finished()?;
        }
        Ok(written)
    }
}

impl SparseExtentInputReader<'_> {
    fn validate_finished(&mut self) -> io::Result<()> {
        if self.validated {
            return Ok(());
        }
        validate_opened_input_identity(&self.file, self.expected)?;
        #[cfg(windows)]
        if query_windows_allocated_ranges(&self.file, self.expected.len)? != self.expected_extents {
            return Err(io::Error::other(
                "sparse allocated ranges changed after scan",
            ));
        }
        self.validated = true;
        Ok(())
    }
}

impl Read for SparseExtentInputReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let mut written = 0usize;
        while written < out.len() {
            if self.extent_remaining == 0 {
                let Some(extent) = self.expected_extents.get(self.extent_index) else {
                    self.validate_finished()?;
                    break;
                };
                self.file.seek(SeekFrom::Start(extent.offset))?;
                self.extent_remaining = extent.length;
            }
            let count = (out.len() - written)
                .min(usize::try_from(self.extent_remaining).unwrap_or(usize::MAX));
            let read = self.file.read(&mut out[written..written + count])?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "sparse extent ended before its scanned size",
                ));
            }
            written += read;
            self.extent_remaining -= read as u64;
            if self.extent_remaining == 0 {
                self.extent_index += 1;
            }
        }
        if self.extent_index == self.expected_extents.len() && self.extent_remaining == 0 {
            self.validate_finished()?;
        }
        Ok(written)
    }
}

impl Read for IdentityCheckedInputReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            if !self.validated {
                validate_opened_input_identity(&self.file, self.expected)?;
                self.validated = true;
            }
            return Ok(0);
        }
        let max_read = out
            .len()
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        let count = self.file.read(&mut out[..max_read])?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "input ended before its scanned size",
            ));
        }
        self.remaining -= count as u64;
        if self.remaining == 0 {
            validate_opened_input_identity(&self.file, self.expected)?;
            self.validated = true;
        }
        Ok(count)
    }
}

fn archive_timestamp(time: SystemTime) -> io::Result<ArchiveTimestamp> {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => Ok(ArchiveTimestamp::new(
            i64::try_from(duration.as_secs())
                .map_err(|_| io::Error::other("input mtime exceeds revision-45 i64 range"))?,
            duration.subsec_nanos(),
        )),
        Err(error) => {
            let duration = error.duration();
            let (seconds, nanoseconds) = if duration.subsec_nanos() == 0 {
                (-i128::from(duration.as_secs()), 0)
            } else {
                (
                    -i128::from(duration.as_secs()) - 1,
                    1_000_000_000 - duration.subsec_nanos(),
                )
            };
            let seconds = i64::try_from(seconds)
                .map_err(|_| io::Error::other("input mtime exceeds revision-45 i64 range"))?;
            Ok(ArchiveTimestamp::new(seconds, nanoseconds))
        }
    }
}

fn resolve_extract_index_entries(
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

fn archive_path_to_string(path: &Path) -> Result<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        let std::path::Component::Normal(part) = component else {
            bail!("unsafe archive path component in {}", path.display());
        };
        parts.push(
            part.to_str()
                .ok_or_else(|| anyhow!("archive path is not valid UTF-8"))?
                .to_owned(),
        );
    }
    if parts.is_empty() {
        bail!("empty archive path");
    }
    Ok(parts.join("/"))
}

#[cfg(windows)]
fn reject_unsupported_windows_regular_file(metadata: &fs::Metadata, input: &Path) -> Result<()> {
    use std::os::windows::fs::MetadataExt;

    let attributes = metadata.file_attributes();
    if let Some(reason) = unsupported_windows_file_attribute_reason(attributes) {
        bail!(
            "Windows metadata capture does not support {}: {reason}",
            input.display()
        );
    }
    Ok(())
}

#[cfg(windows)]
fn unsupported_windows_file_attribute_reason(attributes: u32) -> Option<&'static str> {
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    const FILE_ATTRIBUTE_OFFLINE: u32 = 0x0000_1000;
    [
        (
            FILE_ATTRIBUTE_REPARSE_POINT,
            "reparse points require exact reparse-data capture",
        ),
        (
            FILE_ATTRIBUTE_OFFLINE,
            "offline/cloud placeholders require an explicit hydration policy",
        ),
    ]
    .into_iter()
    .find_map(|(flag, reason)| (attributes & flag != 0).then_some(reason))
}

#[cfg(unix)]
fn readonly_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn readonly_mode(metadata: &fs::Metadata) -> u32 {
    if metadata.permissions().readonly() {
        0o444
    } else {
        0o644
    }
}

fn portable_input_metadata(identity: InputIdentity, input: &Path) -> Result<PortableFileMetadata> {
    let metadata = fs::symlink_metadata(input)?;
    let created = metadata
        .created()
        .ok()
        .and_then(|t| archive_timestamp(t).ok());
    let accessed = metadata
        .accessed()
        .ok()
        .and_then(|t| archive_timestamp(t).ok());
    Ok(PortableFileMetadata {
        source_os: source_os_label().into(),
        source_filesystem: "unknown".into(),
        mode_origin: if cfg!(unix) {
            PortableModeOrigin::Native
        } else {
            PortableModeOrigin::Projected
        },
        #[cfg(unix)]
        posix_owner: Some(PortablePosixOwner {
            uid: identity.uid,
            gid: identity.gid,
            uname: None,
            gname: None,
        }),
        #[cfg(not(unix))]
        posix_owner: None,
        attributes: identity.attributes,
        created,
        accessed,
        native: capture_native_file_metadata(input, identity)?,
    })
}

fn portable_symlink_metadata(
    identity: InputIdentity,
    _input: &Path,
) -> Result<PortableFileMetadata> {
    Ok(PortableFileMetadata {
        source_os: source_os_label().into(),
        source_filesystem: "unknown".into(),
        mode_origin: if cfg!(unix) {
            PortableModeOrigin::Native
        } else {
            PortableModeOrigin::Projected
        },
        #[cfg(unix)]
        posix_owner: Some(PortablePosixOwner {
            uid: identity.uid,
            gid: identity.gid,
            uname: None,
            gname: None,
        }),
        #[cfg(not(unix))]
        posix_owner: None,
        attributes: identity.attributes,
        created: None,
        accessed: None,
        #[cfg(target_os = "linux")]
        native: capture_linux_symlink_metadata(_input, identity)?,
        #[cfg(target_os = "macos")]
        native: capture_macos_symlink_metadata(_input, identity)?,
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        native: NativeFileMetadata::default(),
    })
}

#[cfg(target_os = "linux")]
fn capture_linux_symlink_metadata(
    input: &Path,
    identity: InputIdentity,
) -> Result<NativeFileMetadata> {
    use std::os::unix::ffi::OsStrExt;

    let mut native = NativeFileMetadata::default();
    for name in xattr::list(input)
        .with_context(|| format!("failed to list symlink xattrs for {}", input.display()))?
    {
        let Some(value) = xattr::get(input, &name)
            .with_context(|| format!("failed to read symlink xattr on {}", input.display()))?
        else {
            bail!("symlink xattr changed while scanning {}", input.display());
        };
        let name_bytes = name.as_bytes();
        let profile = if name_bytes.starts_with(b"security.")
            || name_bytes.starts_with(b"trusted.")
            || name_bytes.starts_with(b"system.")
        {
            "linux-backup-v1"
        } else {
            "posix-backup-v1"
        };
        let encoded_name = encode_percent_name(name_bytes).map_err(|error| anyhow!(error))?;
        native.primary_pax_records.insert(
            format!("LIBARCHIVE.xattr.{encoded_name}"),
            canonical_base64_encode(&value),
        );
        native.required_profiles.push(profile.into());
    }
    native.primary_pax_records.insert(
        "TZAP.unix.ctime-observed".into(),
        ArchiveTimestamp::new(
            identity.change_time_seconds,
            identity.change_time_nanoseconds as u32,
        )
        .canonical_pax_value()
        .map_err(|error| anyhow!(error))?,
    );
    if let Some(creation_time) = identity.creation_time {
        native.primary_pax_records.insert(
            "LIBARCHIVE.creationtime".into(),
            creation_time
                .canonical_pax_value()
                .map_err(|error| anyhow!(error))?,
        );
        native.required_profiles.push("linux-backup-v1".into());
    }
    native.required_profiles.push("posix-backup-v1".into());
    native.required_profiles.sort();
    native.required_profiles.dedup();
    Ok(native)
}

#[cfg(unix)]
fn symlink_target_bytes(path: &Path) -> io::Result<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    Ok(fs::read_link(path)?.as_os_str().as_bytes().to_vec())
}

#[cfg(not(unix))]
fn symlink_target_bytes(path: &Path) -> io::Result<Vec<u8>> {
    fs::read_link(path)?
        .to_str()
        .map(|target| target.as_bytes().to_vec())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "symlink target is not UTF-8"))
}

#[cfg(target_os = "linux")]
fn capture_native_file_metadata(
    input: &Path,
    identity: InputIdentity,
) -> Result<NativeFileMetadata> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::ffi::OsStrExt;
    use xattr::FileExt as _;

    let (file, metadata_only) = open_linux_metadata_file(input)
        .with_context(|| format!("failed to open {} for metadata capture", input.display()))?;
    let opened_identity = input_identity(&file.metadata().with_context(|| {
        format!(
            "failed to identify opened metadata object {}",
            input.display()
        )
    })?)?;
    if opened_identity != identity {
        bail!("input changed before metadata capture: {}", input.display());
    }
    let mut native = NativeFileMetadata::default();
    // Keep the primary local-PAX record comfortably below its aggregate cap.
    // Larger aggregate xattr sets use the format's hashed auxiliary framing.
    const INLINE_XATTR_BUDGET: usize = 32 * 1024 * 1024;
    let mut inline_xattr_bytes = 0usize;
    #[cfg(target_os = "linux")]
    let mut captured_posix_acl = false;
    let metadata_path =
        metadata_only.then(|| PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd())));
    for name in if let Some(path) = &metadata_path {
        xattr::list_deref(path)
    } else {
        file.list_xattr()
    }
    .with_context(|| format!("failed to list xattrs for {}", input.display()))?
    {
        let name_bytes = name.as_bytes();
        let Some(value) = if let Some(path) = &metadata_path {
            xattr::get_deref(path, &name)
        } else {
            file.get_xattr(&name)
        }
        .with_context(|| format!("failed to read xattr on {}", input.display()))?
        else {
            bail!("xattr changed while scanning {}", input.display());
        };
        #[cfg(target_os = "linux")]
        if name_bytes == b"system.posix_acl_access" || name_bytes == b"system.posix_acl_default" {
            let key = if name_bytes.ends_with(b"access") {
                "SCHILY.acl.access"
            } else {
                "SCHILY.acl.default"
            };
            native.primary_pax_records.insert(
                key.into(),
                linux_posix_acl_xattr_to_schily(&value).map_err(|error| anyhow!(error))?,
            );
            captured_posix_acl = true;
            native.required_profiles.push("posix-backup-v1".into());
            continue;
        }
        let profile = if name_bytes.starts_with(b"security.")
            || name_bytes.starts_with(b"trusted.")
            || name_bytes.starts_with(b"system.")
        {
            "linux-backup-v1"
        } else if name_bytes.starts_with(b"com.apple.") {
            "macos-backup-v1"
        } else {
            "posix-backup-v1"
        };
        let restore_class = if profile == "linux-backup-v1" {
            RestoreClass::System
        } else {
            RestoreClass::SameOs
        };
        let encoded_name = encode_percent_name(name_bytes).map_err(|error| anyhow!(error))?;
        let encoded_value = canonical_base64_encode(&value);
        if inline_xattr_bytes
            .saturating_add(encoded_name.len())
            .saturating_add(encoded_value.len())
            > INLINE_XATTR_BUDGET
        {
            let mut record =
                NativeAuxiliaryMetadata::new("generic.xattr", profile, restore_class, value);
            record.name_encoding = NativeAuxiliaryNameEncoding::Bytes;
            record.name = name_bytes.to_vec();
            native.auxiliary_records.push(record);
        } else {
            inline_xattr_bytes = inline_xattr_bytes
                .saturating_add(encoded_name.len())
                .saturating_add(encoded_value.len());
            native
                .primary_pax_records
                .insert(format!("LIBARCHIVE.xattr.{encoded_name}"), encoded_value);
        }
        native.required_profiles.push(profile.into());
    }
    #[cfg(target_os = "linux")]
    if captured_posix_acl {
        native
            .primary_pax_records
            .insert("TZAP.acl.projection".into(), b"exact".to_vec());
        native.primary_pax_records.insert(
            "TZAP.acl.syntax".into(),
            b"schily-posix1e-extra-id-v1".to_vec(),
        );
    }
    native.required_profiles.sort();
    native.required_profiles.dedup();
    if !metadata_only {
        capture_linux_inode_flags(&file, &mut native).with_context(|| {
            format!(
                "failed to capture Linux inode flags for {}",
                input.display()
            )
        })?;
        capture_linux_project_id(&file, &mut native).with_context(|| {
            format!("failed to capture Linux project ID for {}", input.display())
        })?;
    }
    native.primary_pax_records.insert(
        "TZAP.unix.ctime-observed".into(),
        ArchiveTimestamp::new(
            identity.change_time_seconds,
            identity.change_time_nanoseconds as u32,
        )
        .canonical_pax_value()
        .map_err(|error| anyhow!(error))?,
    );
    if let Some(creation_time) = identity.creation_time {
        native.primary_pax_records.insert(
            "LIBARCHIVE.creationtime".into(),
            creation_time
                .canonical_pax_value()
                .map_err(|error| anyhow!(error))?,
        );
        native.required_profiles.push("linux-backup-v1".into());
    }
    native.required_profiles.push("posix-backup-v1".into());
    native.required_profiles.sort();
    native.required_profiles.dedup();
    native.auxiliary_records.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.name.cmp(&right.name))
    });
    let final_identity =
        input_identity(&file.metadata().with_context(|| {
            format!("failed to reidentify metadata object {}", input.display())
        })?)?;
    if final_identity != identity {
        bail!("input changed during metadata capture: {}", input.display());
    }
    Ok(native)
}

#[cfg(target_os = "linux")]
fn open_linux_metadata_file(input: &Path) -> io::Result<(File, bool)> {
    use std::os::unix::fs::OpenOptionsExt as _;

    match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(input)
    {
        Ok(file) => Ok((file, false)),
        Err(error)
            if error.raw_os_error() == Some(libc::ENXIO)
                || error.raw_os_error() == Some(libc::ENODEV) =>
        {
            use std::ffi::CString;
            use std::os::fd::FromRawFd as _;
            use std::os::unix::ffi::OsStrExt as _;

            let path = CString::new(input.as_os_str().as_bytes()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte")
            })?;
            // SAFETY: `path` is NUL-terminated and a successful descriptor is
            // transferred immediately to `File`.
            let fd = unsafe {
                libc::open(
                    path.as_ptr(),
                    libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_PATH,
                )
            };
            if fd < 0 {
                Err(io::Error::last_os_error())
            } else {
                // SAFETY: `fd` is newly opened and exclusively owned here.
                Ok((unsafe { File::from_raw_fd(fd) }, true))
            }
        }
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "macos")]
fn open_macos_metadata_file(input: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    const O_EVTONLY: libc::c_int = 0x0000_8000;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK | O_EVTONLY)
        .open(input)
}

#[cfg(target_os = "macos")]
fn capture_native_file_metadata(
    input: &Path,
    identity: InputIdentity,
) -> Result<NativeFileMetadata> {
    use std::os::macos::fs::MetadataExt;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::FileTypeExt as _;
    use xattr::FileExt as _;

    // Leave ample room below the 64 MiB local-PAX cap for declarations and
    // caller-owned native records. Xattrs beyond this aggregate budget use
    // the format's hashed auxiliary representation instead.
    const INLINE_XATTR_BUDGET: usize = 32 * 1024 * 1024;

    let file = open_macos_metadata_file(input)
        .with_context(|| format!("failed to open {} for metadata capture", input.display()))?;
    let opened_identity = input_identity(&file.metadata().with_context(|| {
        format!(
            "failed to identify opened metadata object {}",
            input.display()
        )
    })?)?;
    if opened_identity != identity {
        bail!("input changed before metadata capture: {}", input.display());
    }
    let mut native = NativeFileMetadata::default();
    let mut inline_xattr_bytes = 0usize;
    let file_type = file.metadata()?.file_type();
    let device_without_metadata_api = file_type.is_char_device() || file_type.is_block_device();
    native.primary_pax_records.insert(
        "TZAP.macos.st-flags".into(),
        format!("{:016x}", file.metadata()?.st_flags()).into_bytes(),
    );
    native.primary_pax_records.insert(
        "TZAP.unix.ctime-observed".into(),
        ArchiveTimestamp::new(
            identity.change_time_seconds,
            identity.change_time_nanoseconds as u32,
        )
        .canonical_pax_value()
        .map_err(|error| anyhow!(error))?,
    );
    if let Some(creation_time) = identity.creation_time {
        native.primary_pax_records.insert(
            "LIBARCHIVE.creationtime".into(),
            creation_time
                .canonical_pax_value()
                .map_err(|error| anyhow!(error))?,
        );
    }

    let xattr_names = match file.list_xattr() {
        Ok(names) => names.collect::<Vec<_>>(),
        Err(error)
            if device_without_metadata_api
                && error
                    .raw_os_error()
                    .is_some_and(|code| code == libc::EPERM || code == libc::ENOTSUP) =>
        {
            Vec::new()
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to list xattrs for {}", input.display()));
        }
    };
    for name in xattr_names {
        let name_bytes = name.as_bytes();
        if name_bytes == b"com.apple.ResourceFork" {
            native.auxiliary_records.push(
                capture_macos_resource_fork(
                    open_macos_resource_fork_for_read(file.try_clone()?)?,
                    identity,
                )
                .with_context(|| {
                    format!("failed to capture resource fork for {}", input.display())
                })?,
            );
            continue;
        }
        let Some(value) = file
            .get_xattr(&name)
            .with_context(|| format!("failed to read xattr on {}", input.display()))?
        else {
            bail!("xattr changed while scanning {}", input.display());
        };
        match name_bytes {
            b"com.apple.FinderInfo" => {
                if value.len() != 32 {
                    bail!("FinderInfo on {} is not exactly 32 bytes", input.display());
                }
                native.auxiliary_records.push(NativeAuxiliaryMetadata::new(
                    "macos.finder-info",
                    "macos-backup-v1",
                    RestoreClass::SameOs,
                    value,
                ));
            }
            _ if inline_xattr_bytes
                .saturating_add(name_bytes.len())
                .saturating_add(value.len().saturating_mul(4).div_ceil(3))
                > INLINE_XATTR_BUDGET =>
            {
                let profile = if name_bytes.starts_with(b"com.apple.") {
                    "macos-backup-v1"
                } else {
                    "posix-backup-v1"
                };
                let mut record = NativeAuxiliaryMetadata::new(
                    "generic.xattr",
                    profile,
                    if macos_system_xattr(name_bytes) {
                        RestoreClass::System
                    } else {
                        RestoreClass::SameOs
                    },
                    value,
                );
                record.name_encoding = NativeAuxiliaryNameEncoding::Bytes;
                record.name = name_bytes.to_vec();
                native.auxiliary_records.push(record);
            }
            _ => {
                let encoded_name =
                    encode_percent_name(name_bytes).map_err(|error| anyhow!(error))?;
                native.primary_pax_records.insert(
                    format!("LIBARCHIVE.xattr.{encoded_name}"),
                    canonical_base64_encode(&value),
                );
                inline_xattr_bytes = inline_xattr_bytes
                    .saturating_add(encoded_name.len())
                    .saturating_add(value.len().saturating_mul(4).div_ceil(3));
            }
        }
    }

    let acl = match capture_macos_acl(&file) {
        Ok(acl) => acl,
        Err(error)
            if device_without_metadata_api
                && error
                    .raw_os_error()
                    .is_some_and(|code| code == libc::EPERM || code == libc::ENOTSUP) =>
        {
            None
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to capture ACL for {}", input.display()));
        }
    };
    if let Some(acl) = acl {
        let mut record = NativeAuxiliaryMetadata::new(
            "macos.acl-native",
            "macos-backup-v1",
            RestoreClass::SameOs,
            acl,
        );
        record.meta.insert(
            "TZAP.aux.meta.acl-format".into(),
            b"darwin-acl-external-v1".to_vec(),
        );
        native.auxiliary_records.push(record);
        native
            .primary_pax_records
            .insert("TZAP.acl.projection".into(), b"none".to_vec());
    }

    native.auxiliary_records.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.name.cmp(&right.name))
    });
    native.required_profiles.push("macos-backup-v1".into());
    native.required_profiles.push("posix-backup-v1".into());
    native.required_profiles.sort();
    let final_identity =
        input_identity(&file.metadata().with_context(|| {
            format!("failed to reidentify metadata object {}", input.display())
        })?)?;
    if final_identity != identity {
        bail!("input changed during metadata capture: {}", input.display());
    }
    Ok(native)
}

#[cfg(target_os = "macos")]
fn capture_macos_symlink_metadata(
    input: &Path,
    identity: InputIdentity,
) -> Result<NativeFileMetadata> {
    use std::os::macos::fs::MetadataExt as _;
    use std::os::unix::ffi::OsStrExt as _;
    use xattr::FileExt as _;

    const INLINE_XATTR_BUDGET: usize = 32 * 1024 * 1024;
    let file = open_macos_symlink(input)
        .with_context(|| format!("failed to open symlink {}", input.display()))?;
    let current = file
        .metadata()
        .with_context(|| format!("failed to identify symlink {}", input.display()))?;
    if !current.file_type().is_symlink() || input_identity(&current)? != identity {
        bail!(
            "symlink changed before metadata capture: {}",
            input.display()
        );
    }

    let mut native = NativeFileMetadata::default();
    let mut inline_xattr_bytes = 0usize;
    native.primary_pax_records.insert(
        "TZAP.macos.st-flags".into(),
        format!("{:016x}", current.st_flags()).into_bytes(),
    );
    native.primary_pax_records.insert(
        "TZAP.unix.ctime-observed".into(),
        ArchiveTimestamp::new(
            identity.change_time_seconds,
            identity.change_time_nanoseconds as u32,
        )
        .canonical_pax_value()
        .map_err(|error| anyhow!(error))?,
    );
    if let Some(creation_time) = identity.creation_time {
        native.primary_pax_records.insert(
            "LIBARCHIVE.creationtime".into(),
            creation_time
                .canonical_pax_value()
                .map_err(|error| anyhow!(error))?,
        );
    }

    for name in file
        .list_xattr()
        .with_context(|| format!("failed to list symlink xattrs for {}", input.display()))?
    {
        let name_bytes = name.as_bytes();
        if name_bytes == b"com.apple.ResourceFork" {
            native.auxiliary_records.push(
                capture_macos_resource_fork(
                    MacosResourceForkSource::Symlink(file.try_clone()?),
                    identity,
                )
                .with_context(|| {
                    format!(
                        "failed to capture symlink resource fork for {}",
                        input.display()
                    )
                })?,
            );
            continue;
        }
        let Some(value) = file
            .get_xattr(&name)
            .with_context(|| format!("failed to read symlink xattr on {}", input.display()))?
        else {
            bail!("symlink xattr changed while scanning {}", input.display());
        };
        match name_bytes {
            b"com.apple.FinderInfo" => {
                if value.len() != 32 {
                    bail!("FinderInfo on {} is not exactly 32 bytes", input.display());
                }
                native.auxiliary_records.push(NativeAuxiliaryMetadata::new(
                    "macos.finder-info",
                    "macos-backup-v1",
                    RestoreClass::SameOs,
                    value,
                ));
            }
            _ if inline_xattr_bytes
                .saturating_add(name_bytes.len())
                .saturating_add(value.len().saturating_mul(4).div_ceil(3))
                > INLINE_XATTR_BUDGET =>
            {
                let profile = if name_bytes.starts_with(b"com.apple.") {
                    "macos-backup-v1"
                } else {
                    "posix-backup-v1"
                };
                let mut record = NativeAuxiliaryMetadata::new(
                    "generic.xattr",
                    profile,
                    if macos_system_xattr(name_bytes) {
                        RestoreClass::System
                    } else {
                        RestoreClass::SameOs
                    },
                    value,
                );
                record.name_encoding = NativeAuxiliaryNameEncoding::Bytes;
                record.name = name_bytes.to_vec();
                native.auxiliary_records.push(record);
            }
            _ => {
                let encoded_name =
                    encode_percent_name(name_bytes).map_err(|error| anyhow!(error))?;
                let encoded_value = canonical_base64_encode(&value);
                inline_xattr_bytes = inline_xattr_bytes
                    .saturating_add(encoded_name.len())
                    .saturating_add(encoded_value.len());
                native
                    .primary_pax_records
                    .insert(format!("LIBARCHIVE.xattr.{encoded_name}"), encoded_value);
            }
        }
    }

    if let Some(acl) = capture_macos_acl(&file)? {
        let mut record = NativeAuxiliaryMetadata::new(
            "macos.acl-native",
            "macos-backup-v1",
            RestoreClass::SameOs,
            acl,
        );
        record.meta.insert(
            "TZAP.aux.meta.acl-format".into(),
            b"darwin-acl-external-v1".to_vec(),
        );
        native.auxiliary_records.push(record);
        native
            .primary_pax_records
            .insert("TZAP.acl.projection".into(), b"none".to_vec());
    }
    native.required_profiles = vec!["macos-backup-v1".into(), "posix-backup-v1".into()];
    native.auxiliary_records.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.name.cmp(&right.name))
    });
    let final_metadata = file
        .metadata()
        .with_context(|| format!("failed to reidentify symlink {}", input.display()))?;
    if !final_metadata.file_type().is_symlink() || input_identity(&final_metadata)? != identity {
        bail!(
            "symlink changed during metadata capture: {}",
            input.display()
        );
    }
    Ok(native)
}

#[cfg(target_os = "macos")]
fn macos_system_xattr(name: &[u8]) -> bool {
    name.starts_with(b"security.") || name.starts_with(b"trusted.") || name.starts_with(b"system.")
}

#[cfg(target_os = "macos")]
fn capture_macos_resource_fork(
    source: MacosResourceForkSource,
    identity: InputIdentity,
) -> Result<NativeAuxiliaryMetadata> {
    use sha2::{Digest as _, Sha256};

    let mut reader = MacosResourceForkReader::new(source, identity, None)?;
    let logical_size = reader.logical_size;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(NativeAuxiliaryMetadata::new_streamed(
        "macos.resource-fork",
        "macos-backup-v1",
        RestoreClass::SameOs,
        logical_size,
        hasher.finalize().into(),
    ))
}

#[cfg(target_os = "macos")]
fn capture_macos_acl(file: &File) -> io::Result<Option<Vec<u8>>> {
    use std::os::fd::AsRawFd;
    use std::ptr;

    type Acl = *mut libc::c_void;
    type AclEntry = *mut libc::c_void;
    const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;
    const ACL_FIRST_ENTRY: libc::c_int = 0;

    extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, acl_type: libc::c_int) -> Acl;
        fn acl_get_entry(acl: Acl, entry_id: libc::c_int, entry: *mut AclEntry) -> libc::c_int;
        fn acl_size(acl: Acl) -> libc::ssize_t;
        fn acl_copy_ext(buffer: *mut libc::c_void, acl: Acl, size: libc::ssize_t) -> libc::ssize_t;
        fn acl_free(object: *mut libc::c_void) -> libc::c_int;
    }

    // SAFETY: `file` owns a live descriptor and the returned ACL is released on every path.
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ENOENT) {
            Ok(None)
        } else {
            Err(error)
        };
    }
    let result = (|| {
        let mut first: AclEntry = ptr::null_mut();
        // SAFETY: `acl` is valid and `first` points to writable storage for one entry pointer.
        match unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, &mut first) } {
            1 => return Ok(None),
            0 => {}
            _ => return Err(io::Error::last_os_error()),
        }
        // SAFETY: `acl` remains valid for the duration of this scope.
        let size = unsafe { acl_size(acl) };
        if size < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut external = vec![
            0u8;
            usize::try_from(size).map_err(|_| {
                io::Error::other("macOS ACL external form exceeds platform limits")
            })?
        ];
        // SAFETY: the destination has exactly `size` writable bytes and `acl` is valid.
        let copied = unsafe { acl_copy_ext(external.as_mut_ptr().cast(), acl, size) };
        if copied < 0 {
            return Err(io::Error::last_os_error());
        }
        external
            .truncate(usize::try_from(copied).map_err(|_| {
                io::Error::other("macOS ACL external form exceeds platform limits")
            })?);
        Ok(Some(external))
    })();
    // SAFETY: `acl` was returned by `acl_get_fd_np` and has not yet been freed.
    unsafe { acl_free(acl) };
    result
}

#[cfg(windows)]
fn capture_native_file_metadata(
    input: &Path,
    identity: InputIdentity,
) -> Result<NativeFileMetadata> {
    let file = open_windows_metadata_handle(input).with_context(|| {
        format!(
            "failed to open {} for Windows metadata capture",
            input.display()
        )
    })?;
    let mut native = NativeFileMetadata::default();
    native.primary_pax_records.insert(
        "TZAP.windows.file-attributes".into(),
        format!("{:08x}", identity.file_attributes).into_bytes(),
    );
    native.primary_pax_records.insert(
        "atime".into(),
        windows_filetime_timestamp(identity.last_access_time_100ns)?
            .canonical_pax_value()
            .map_err(|error| anyhow!(error))?,
    );
    native.primary_pax_records.insert(
        "LIBARCHIVE.creationtime".into(),
        windows_filetime_timestamp(identity.creation_time_100ns)?
            .canonical_pax_value()
            .map_err(|error| anyhow!(error))?,
    );
    native.primary_pax_records.insert(
        "TZAP.windows.change-time".into(),
        windows_filetime_timestamp(identity.change_time_100ns)?
            .canonical_pax_value()
            .map_err(|error| anyhow!(error))?,
    );
    let reparse_data = if identity.file_attributes & 0x0000_0400 != 0 {
        let data = query_windows_reparse_data(&file).with_context(|| {
            format!(
                "failed to read Windows reparse data for {}",
                input.display()
            )
        })?;
        validate_windows_known_reparse_data(&data).with_context(|| {
            format!(
                "failed to validate Windows reparse data for {}",
                input.display()
            )
        })?;
        let tag = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let mut record = NativeAuxiliaryMetadata::new(
            "windows.reparse-data",
            "windows-backup-v1",
            RestoreClass::System,
            data.clone(),
        );
        record.meta.insert(
            "TZAP.aux.meta.reparse-tag".into(),
            format!("{tag:08x}").into_bytes(),
        );
        native.auxiliary_records.push(record);
        Some(data)
    } else {
        None
    };
    native
        .auxiliary_records
        .push(capture_windows_security_descriptor(&file).with_context(|| {
            format!(
                "failed to capture Windows security descriptor for {}",
                input.display()
            )
        })?);
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
    if identity.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        if let Some(case_sensitive) = query_windows_directory_case_sensitive(&file)? {
            native.primary_pax_records.insert(
                "TZAP.windows.directory-case-sensitive".into(),
                if case_sensitive { b"1" } else { b"0" }.to_vec(),
            );
        }
    }
    const FILE_ATTRIBUTE_ENCRYPTED: u32 = 0x0000_4000;
    let (data_stream_attributes, mut streams) =
        capture_windows_backup_streams(input, &file, reparse_data.as_deref()).with_context(
            || {
                format!(
                    "failed to enumerate Windows streams for {}",
                    input.display()
                )
            },
        )?;
    if identity.file_attributes & FILE_ATTRIBUTE_ENCRYPTED != 0 {
        // The raw EFS APIs reject export while an ordinary handle to the encrypted file is open,
        // even when that handle permits all sharing modes. Enumerate every registered BackupRead
        // stream first, then release the handle before opening the raw export context.
        drop(file);
        native.auxiliary_records.push(
            capture_windows_efs_raw(input, identity).with_context(|| {
                format!("failed to capture raw EFS data for {}", input.display())
            })?,
        );
    }
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    if identity.file_attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) == 0 {
        native.primary_pax_records.insert(
            "TZAP.windows.data-stream-attributes".into(),
            format!("{data_stream_attributes:08x}").into_bytes(),
        );
    }
    native.auxiliary_records.append(&mut streams);
    native.auxiliary_records.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.name.cmp(&right.name))
    });
    native.required_profiles.push("windows-backup-v1".into());
    Ok(native)
}

#[cfg(windows)]
fn query_windows_directory_case_sensitive(file: &File) -> io::Result<Option<bool>> {
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{
        ERROR_INVALID_FUNCTION, ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FileCaseSensitiveInfo, GetFileInformationByHandleEx, FILE_CASE_SENSITIVE_INFO,
    };
    use windows_sys::Win32::System::SystemServices::FILE_CS_FLAG_CASE_SENSITIVE_DIR;

    let mut info = FILE_CASE_SENSITIVE_INFO::default();
    // SAFETY: the handle is live and `info` is a correctly sized writable structure.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle().cast(),
            FileCaseSensitiveInfo,
            (&mut info as *mut FILE_CASE_SENSITIVE_INFO).cast(),
            size_of::<FILE_CASE_SENSITIVE_INFO>() as u32,
        )
    } == 0
    {
        let error = io::Error::last_os_error();
        if matches!(
            error.raw_os_error(),
            Some(code)
                if code == ERROR_INVALID_FUNCTION as i32
                    || code == ERROR_INVALID_PARAMETER as i32
                    || code == ERROR_NOT_SUPPORTED as i32
        ) {
            return Ok(None);
        }
        return Err(error);
    }
    if info.Flags & !FILE_CS_FLAG_CASE_SENSITIVE_DIR != 0 {
        return Err(io::Error::other(
            "Windows returned unknown directory case-sensitivity flags",
        ));
    }
    Ok(Some(info.Flags & FILE_CS_FLAG_CASE_SENSITIVE_DIR != 0))
}

#[cfg(windows)]
fn windows_filetime_timestamp(value_100ns: u64) -> Result<ArchiveTimestamp> {
    const WINDOWS_TO_UNIX_EPOCH_100NS: i128 = 116_444_736_000_000_000;
    const TICKS_PER_SECOND: i128 = 10_000_000;
    let unix_100ns = i128::from(value_100ns) - WINDOWS_TO_UNIX_EPOCH_100NS;
    let seconds = i64::try_from(unix_100ns.div_euclid(TICKS_PER_SECOND))
        .map_err(|_| anyhow!("Windows timestamp exceeds revision-45 i64 range"))?;
    let nanoseconds = (unix_100ns.rem_euclid(TICKS_PER_SECOND) * 100) as u32;
    Ok(ArchiveTimestamp::new(seconds, nanoseconds))
}

#[cfg(windows)]
fn windows_sacl_capture_enabled() -> bool {
    use std::sync::OnceLock;
    use windows_sys::Win32::Security::SE_SECURITY_NAME;

    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| enable_windows_privilege(SE_SECURITY_NAME))
}

#[cfg(windows)]
fn windows_backup_capture_enabled() -> bool {
    use std::sync::OnceLock;
    use windows_sys::Win32::Security::SE_BACKUP_NAME;

    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| enable_windows_privilege(SE_BACKUP_NAME))
}

#[cfg(windows)]
fn enable_windows_privilege(name: *const u16) -> bool {
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, SetLastError, ERROR_SUCCESS};
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = ptr::null_mut();
    // SAFETY: `token` is a valid output pointer and the pseudo process handle is always live.
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
            &mut token,
        )
    } == 0
    {
        return false;
    }
    let enabled = {
        let mut privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            ..Default::default()
        };
        // SAFETY: the one-element privilege array provides a valid LUID output slot.
        if unsafe { LookupPrivilegeValueW(ptr::null(), name, &mut privileges.Privileges[0].Luid) }
            == 0
        {
            false
        } else {
            privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            unsafe { SetLastError(ERROR_SUCCESS) };
            // SAFETY: `token` is live and `privileges` is a valid one-entry input structure.
            unsafe {
                AdjustTokenPrivileges(token, 0, &privileges, 0, ptr::null_mut(), ptr::null_mut())
                    != 0
                    && GetLastError() == ERROR_SUCCESS
            }
        }
    };
    // SAFETY: `token` was returned by OpenProcessToken and is closed exactly once.
    unsafe { CloseHandle(token) };
    enabled
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
fn open_windows_raw_efs(path: &Path, flags: u32) -> io::Result<WindowsRawEfsContext> {
    use std::os::windows::ffi::OsStrExt as _;
    use std::ptr;
    use windows_sys::Win32::Storage::FileSystem::OpenEncryptedFileRawW;

    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut context = ptr::null_mut();
    // SAFETY: the path is NUL-terminated and `context` is a valid output pointer.
    let status = unsafe { OpenEncryptedFileRawW(wide.as_ptr(), flags, &mut context) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(WindowsRawEfsContext(context))
}

#[cfg(windows)]
struct WindowsRawEfsDigest {
    hasher: sha2::Sha256,
    size: u64,
}

#[cfg(windows)]
unsafe extern "system" fn hash_windows_raw_efs_callback(
    data: *const u8,
    context: *const std::ffi::c_void,
    length: u32,
) -> u32 {
    use sha2::Digest as _;
    use windows_sys::Win32::Foundation::{ERROR_ARITHMETIC_OVERFLOW, ERROR_SUCCESS};

    if length == 0 {
        return ERROR_SUCCESS;
    }
    if data.is_null() || context.is_null() {
        return windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER;
    }
    // SAFETY: EFS supplies `length` readable bytes and the caller supplied this digest context.
    let bytes = unsafe { std::slice::from_raw_parts(data, length as usize) };
    let state = unsafe { &mut *context.cast_mut().cast::<WindowsRawEfsDigest>() };
    let Some(size) = state.size.checked_add(u64::from(length)) else {
        return ERROR_ARITHMETIC_OVERFLOW;
    };
    state.hasher.update(bytes);
    state.size = size;
    ERROR_SUCCESS
}

#[cfg(windows)]
fn hash_windows_raw_efs(path: &Path) -> io::Result<(u64, [u8; 32])> {
    use sha2::Digest as _;
    use windows_sys::Win32::Storage::FileSystem::ReadEncryptedFileRaw;

    let _ = windows_backup_capture_enabled();
    let context = open_windows_raw_efs(path, 0)?;
    let mut state = WindowsRawEfsDigest {
        hasher: sha2::Sha256::new(),
        size: 0,
    };
    // SAFETY: callback state and raw EFS context remain live for the synchronous export.
    let status = unsafe {
        ReadEncryptedFileRaw(
            Some(hash_windows_raw_efs_callback),
            (&mut state as *mut WindowsRawEfsDigest).cast(),
            context.0,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok((state.size, state.hasher.finalize().into()))
}

#[cfg(windows)]
enum WindowsRawEfsMessage {
    Data(Vec<u8>),
    Done(io::Result<()>),
}

#[cfg(windows)]
struct WindowsRawEfsSendContext {
    sender: std::sync::mpsc::SyncSender<WindowsRawEfsMessage>,
}

#[cfg(windows)]
unsafe extern "system" fn send_windows_raw_efs_callback(
    data: *const u8,
    context: *const std::ffi::c_void,
    length: u32,
) -> u32 {
    use windows_sys::Win32::Foundation::{ERROR_INVALID_PARAMETER, ERROR_OPERATION_ABORTED};

    if length == 0 {
        return 0;
    }
    if data.is_null() || context.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    // SAFETY: EFS supplies readable callback bytes and the caller supplied this send context.
    let bytes = unsafe { std::slice::from_raw_parts(data, length as usize) };
    let state = unsafe { &*context.cast::<WindowsRawEfsSendContext>() };
    for chunk in bytes.chunks(64 * 1024) {
        if state
            .sender
            .send(WindowsRawEfsMessage::Data(chunk.to_vec()))
            .is_err()
        {
            return ERROR_OPERATION_ABORTED;
        }
    }
    0
}

#[cfg(windows)]
fn validate_windows_input_path_identity(path: &Path, expected: InputIdentity) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    let mut actual = input_identity(&metadata)?;
    let file = open_windows_metadata_handle(path)?;
    augment_windows_input_identity(&mut actual, &file)?;
    if input_identity_matches_after_read(expected, actual) {
        Ok(())
    } else {
        Err(io::Error::other(
            "Windows input changed during raw EFS export",
        ))
    }
}

#[cfg(windows)]
fn export_windows_raw_efs_to_sender(
    path: &Path,
    expected: InputIdentity,
    sender: std::sync::mpsc::SyncSender<WindowsRawEfsMessage>,
) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::ReadEncryptedFileRaw;

    validate_windows_input_path_identity(path, expected)?;
    let _ = windows_backup_capture_enabled();
    let context = open_windows_raw_efs(path, 0)?;
    let state = WindowsRawEfsSendContext { sender };
    // SAFETY: callback state and raw EFS context remain live for the synchronous export.
    let status = unsafe {
        ReadEncryptedFileRaw(
            Some(send_windows_raw_efs_callback),
            (&state as *const WindowsRawEfsSendContext).cast(),
            context.0,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    drop(context);
    validate_windows_input_path_identity(path, expected)
}

#[cfg(windows)]
struct WindowsRawEfsReader {
    receiver: Option<std::sync::mpsc::Receiver<WindowsRawEfsMessage>>,
    current: Vec<u8>,
    current_offset: usize,
    remaining: u64,
    finished: bool,
    pending_error: Option<io::Error>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(windows)]
impl WindowsRawEfsReader {
    fn spawn(path: PathBuf, expected: InputIdentity, size: u64) -> Self {
        let (sender, receiver) = std::sync::mpsc::sync_channel(2);
        let completion = sender.clone();
        let thread = std::thread::spawn(move || {
            let result = export_windows_raw_efs_to_sender(&path, expected, sender);
            let _ = completion.send(WindowsRawEfsMessage::Done(result));
        });
        Self {
            receiver: Some(receiver),
            current: Vec::new(),
            current_offset: 0,
            remaining: size,
            finished: false,
            pending_error: None,
            thread: Some(thread),
        }
    }
}

#[cfg(windows)]
impl Read for WindowsRawEfsReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if let Some(error) = self.pending_error.take() {
            return Err(error);
        }
        let mut written = 0usize;
        while written < out.len() {
            if self.current_offset < self.current.len() {
                let count = (self.current.len() - self.current_offset).min(out.len() - written);
                if count as u64 > self.remaining {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "raw EFS export exceeded its declared size",
                    ));
                }
                out[written..written + count].copy_from_slice(
                    &self.current[self.current_offset..self.current_offset + count],
                );
                self.current_offset += count;
                self.remaining -= count as u64;
                written += count;
                continue;
            }
            if self.finished {
                break;
            }
            let message = self
                .receiver
                .as_ref()
                .ok_or_else(|| io::Error::other("raw EFS export channel is closed"))?
                .recv()
                .map_err(|_| io::Error::other("raw EFS export terminated unexpectedly"))?;
            match message {
                WindowsRawEfsMessage::Data(bytes) => {
                    self.current = bytes;
                    self.current_offset = 0;
                }
                WindowsRawEfsMessage::Done(result) => {
                    self.finished = true;
                    if let Err(error) = result {
                        if written == 0 {
                            return Err(error);
                        }
                        self.pending_error = Some(error);
                    } else if self.remaining != 0 {
                        let error = io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "raw EFS export ended before its declared size",
                        );
                        if written == 0 {
                            return Err(error);
                        }
                        self.pending_error = Some(error);
                    }
                }
            }
        }
        Ok(written)
    }
}

#[cfg(windows)]
impl Drop for WindowsRawEfsReader {
    fn drop(&mut self) {
        self.receiver.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(windows)]
fn capture_windows_efs_raw(
    path: &Path,
    expected: InputIdentity,
) -> Result<NativeAuxiliaryMetadata> {
    validate_windows_input_path_identity(path, expected)?;
    let (size, sha256) = hash_windows_raw_efs(path)?;
    validate_windows_input_path_identity(path, expected)?;
    let mut record = NativeAuxiliaryMetadata::new_streamed(
        "windows.efs-raw",
        "windows-backup-v1",
        RestoreClass::System,
        size,
        sha256,
    );
    record
        .meta
        .insert("TZAP.aux.meta.efs-version".into(), b"1".to_vec());
    Ok(record)
}

#[cfg(windows)]
fn capture_windows_security_descriptor(file: &File) -> Result<NativeAuxiliaryMetadata> {
    use std::os::windows::io::AsRawHandle;
    use std::ptr;
    use windows_sys::Win32::Foundation::{
        CloseHandle, LocalFree, ERROR_SUCCESS, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorLength, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        PROTECTED_SACL_SECURITY_INFORMATION, SACL_SECURITY_INFORMATION,
        UNPROTECTED_DACL_SECURITY_INFORMATION, UNPROTECTED_SACL_SECURITY_INFORMATION,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        ReOpenFile, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL,
    };
    use windows_sys::Win32::System::SystemServices::ACCESS_SYSTEM_SECURITY;

    const BASE_SECURITY_INFORMATION: u32 =
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let original_handle = file.as_raw_handle().cast();
    let sacl_handle = if windows_sacl_capture_enabled() {
        // The handle returned by File::open has READ_CONTROL but not ACCESS_SYSTEM_SECURITY.
        // ReOpenFile preserves object identity while requesting the access needed for SACLs.
        // SAFETY: `original_handle` is live and all flags are valid for a regular file.
        let handle = unsafe {
            ReOpenFile(
                original_handle,
                READ_CONTROL | ACCESS_SYSTEM_SECURITY,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                0,
            )
        };
        (handle != INVALID_HANDLE_VALUE).then_some(handle)
    } else {
        None
    };
    let security_information = if sacl_handle.is_some() {
        BASE_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION
    } else {
        BASE_SECURITY_INFORMATION
    };
    let security_handle = sacl_handle.unwrap_or(original_handle);
    let mut descriptor = ptr::null_mut();
    // SAFETY: the file handle is live, optional component outputs are null, and the returned
    // descriptor is released with LocalFree below as required by GetSecurityInfo.
    let status = unsafe {
        GetSecurityInfo(
            security_handle,
            SE_FILE_OBJECT,
            security_information,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if let Some(handle) = sacl_handle {
        // SAFETY: `handle` was returned by ReOpenFile and is closed exactly once.
        unsafe { CloseHandle(handle) };
    }
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32).into());
    }
    if descriptor.is_null() {
        bail!("GetSecurityInfo returned an empty security descriptor");
    }
    // SAFETY: GetSecurityInfo returned a valid self-relative security descriptor.
    let length = unsafe { GetSecurityDescriptorLength(descriptor) } as usize;
    // SAFETY: `descriptor` references `length` readable bytes until LocalFree.
    let payload = unsafe { std::slice::from_raw_parts(descriptor.cast::<u8>(), length) }.to_vec();
    // SAFETY: `descriptor` was allocated by GetSecurityInfo and has not been freed.
    let free_result = unsafe { LocalFree(descriptor) };
    if !free_result.is_null() {
        bail!("failed to release Windows security descriptor");
    }
    if payload.len() < 20 {
        bail!("GetSecurityInfo returned a truncated self-relative descriptor");
    }
    let control = u16::from_le_bytes(payload[2..4].try_into().unwrap());
    let owner_offset = u32::from_le_bytes(payload[4..8].try_into().unwrap());
    let group_offset = u32::from_le_bytes(payload[8..12].try_into().unwrap());
    let mut captured_security_information = 0u32;
    if owner_offset != 0 {
        captured_security_information |= OWNER_SECURITY_INFORMATION;
    }
    if group_offset != 0 {
        captured_security_information |= GROUP_SECURITY_INFORMATION;
    }
    if control & 0x0004 != 0 {
        captured_security_information |= DACL_SECURITY_INFORMATION;
        captured_security_information |= if control & 0x1000 != 0 {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_DACL_SECURITY_INFORMATION
        };
    }
    if control & 0x0010 != 0 {
        captured_security_information |= SACL_SECURITY_INFORMATION;
        captured_security_information |= if control & 0x2000 != 0 {
            PROTECTED_SACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_SACL_SECURITY_INFORMATION
        };
    }
    let required_identity = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION;
    if captured_security_information & required_identity != required_identity {
        bail!("Windows security descriptor lacks requested owner or group metadata");
    }
    let mut auxiliary = NativeAuxiliaryMetadata::new(
        "windows.security-descriptor",
        "windows-backup-v1",
        RestoreClass::System,
        payload,
    );
    auxiliary.meta.insert(
        "TZAP.aux.meta.security-information".into(),
        format!("{captured_security_information:08x}").into_bytes(),
    );
    Ok(auxiliary)
}

#[cfg(windows)]
struct WindowsBackupReader {
    handle: windows_sys::Win32::Foundation::HANDLE,
    context: *mut std::ffi::c_void,
}

#[cfg(windows)]
impl WindowsBackupReader {
    fn new(file: &File) -> Self {
        use std::os::windows::io::AsRawHandle;
        Self {
            handle: file.as_raw_handle().cast(),
            context: std::ptr::null_mut(),
        }
    }

    fn read_optional_exact(&mut self, out: &mut [u8]) -> io::Result<bool> {
        use windows_sys::Win32::Storage::FileSystem::BackupRead;

        let mut offset = 0usize;
        while offset < out.len() {
            let mut read = 0u32;
            // SAFETY: the handle is live, the output slice is writable, and `context` is owned
            // by this reader until its Drop implementation aborts the backup operation.
            if unsafe {
                BackupRead(
                    self.handle,
                    out[offset..].as_mut_ptr(),
                    u32::try_from(out.len() - offset)
                        .map_err(|_| io::Error::other("BackupRead request exceeds u32"))?,
                    &mut read,
                    0,
                    0,
                    &mut self.context,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            if read == 0 {
                if offset == 0 {
                    return Ok(false);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Windows backup stream ended mid-record",
                ));
            }
            offset += read as usize;
        }
        Ok(true)
    }

    fn read_vec(&mut self, size: u64) -> io::Result<Vec<u8>> {
        let size = usize::try_from(size)
            .map_err(|_| io::Error::other("Windows backup stream exceeds address space"))?;
        let mut payload = vec![0u8; size];
        if size != 0 && !self.read_optional_exact(&mut payload)? {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Windows backup stream payload is missing",
            ));
        }
        Ok(payload)
    }

    fn read_sha256(&mut self, mut size: u64) -> io::Result<[u8; 32]> {
        use sha2::{Digest as _, Sha256};

        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        while size > 0 {
            let count = buffer
                .len()
                .min(usize::try_from(size).unwrap_or(usize::MAX));
            if !self.read_optional_exact(&mut buffer[..count])? {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Windows backup stream payload is missing",
                ));
            }
            hasher.update(&buffer[..count]);
            size -= count as u64;
        }
        Ok(hasher.finalize().into())
    }

    fn skip(&mut self, size: u64) -> io::Result<()> {
        use windows_sys::Win32::Storage::FileSystem::BackupSeek;

        let mut low = 0u32;
        let mut high = 0u32;
        // SAFETY: the handle and context belong to this backup operation and output counters
        // are valid writable pointers.
        if unsafe {
            BackupSeek(
                self.handle,
                size as u32,
                (size >> 32) as u32,
                &mut low,
                &mut high,
                &mut self.context,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let skipped = (u64::from(high) << 32) | u64::from(low);
        if skipped != size {
            return Err(io::Error::other(
                "Windows backup stream could not be skipped completely",
            ));
        }
        Ok(())
    }

    fn discard(&mut self, mut size: u64) -> io::Result<()> {
        let mut buffer = [0u8; 64 * 1024];
        while size > 0 {
            let take = size.min(buffer.len() as u64) as usize;
            if !self.read_optional_exact(&mut buffer[..take])? {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Windows backup stream payload is missing",
                ));
            }
            size -= take as u64;
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for WindowsBackupReader {
    fn drop(&mut self) {
        use windows_sys::Win32::Storage::FileSystem::BackupRead;

        let mut ignored = 0u32;
        // SAFETY: aborting with a null zero-length buffer releases the context owned here.
        unsafe {
            BackupRead(
                self.handle,
                std::ptr::null_mut(),
                0,
                &mut ignored,
                1,
                0,
                &mut self.context,
            );
        }
    }
}

#[cfg(windows)]
fn capture_windows_backup_streams(
    input: &Path,
    file: &File,
    expected_reparse_data: Option<&[u8]>,
) -> Result<(u32, Vec<NativeAuxiliaryMetadata>)> {
    use std::os::windows::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        BACKUP_ALTERNATE_DATA, BACKUP_DATA, BACKUP_EA_DATA, BACKUP_LINK, BACKUP_OBJECT_ID,
        BACKUP_PROPERTY_DATA, BACKUP_REPARSE_DATA, BACKUP_SECURITY_DATA, BACKUP_SPARSE_BLOCK,
        BACKUP_TXFS_DATA,
    };

    const FIXED_STREAM_HEADER_LEN: usize = 20;
    const MAX_RETAINED_BACKUP_STREAM: u64 = 64 * 1024 * 1024;
    const MAX_REPARSE_DATA_BUFFER_SIZE: u64 = 16 * 1024;
    const MAX_BACKUP_STREAM_NAME_SIZE: usize = 65_534;
    const STREAM_MODIFIED_WHEN_READ: u32 = 0x0000_0001;
    let mut reader = WindowsBackupReader::new(file);
    let mut data_stream_attributes = None;
    let mut auxiliary = Vec::new();
    let mut sparse_alternate = Vec::new();
    let mut active_sparse_alternate = None;
    loop {
        let mut header = [0u8; FIXED_STREAM_HEADER_LEN];
        if !reader.read_optional_exact(&mut header)? {
            break;
        }
        let stream_id = u32::from_le_bytes(header[0..4].try_into().unwrap());
        let attributes = u32::from_le_bytes(header[4..8].try_into().unwrap());
        if attributes & STREAM_MODIFIED_WHEN_READ != 0 {
            bail!(
                "Windows backup stream {stream_id} changes when read and cannot be captured consistently"
            );
        }
        let signed_size = i64::from_le_bytes(header[8..16].try_into().unwrap());
        if signed_size < 0 {
            bail!("Windows BackupRead returned a negative stream size");
        }
        let size = signed_size as u64;
        let name_size = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
        if name_size % 2 != 0 || name_size > MAX_BACKUP_STREAM_NAME_SIZE {
            bail!("Windows BackupRead returned an invalid UTF-16 stream-name length");
        }
        let name = reader.read_vec(name_size as u64)?;
        if stream_id != BACKUP_SPARSE_BLOCK {
            active_sparse_alternate = None;
        }
        match stream_id {
            BACKUP_DATA => {
                if data_stream_attributes.replace(attributes).is_some() {
                    bail!("Windows BackupRead returned duplicate default data streams");
                }
                if !name.is_empty() {
                    bail!("Windows default data stream unexpectedly has a name");
                }
                reader.skip(size).with_context(|| {
                    format!("failed to skip Windows default data stream ({size} bytes)")
                })?;
            }
            BACKUP_SECURITY_DATA => reader.skip(size).with_context(|| {
                format!("failed to skip Windows security stream ({size} bytes)")
            })?,
            BACKUP_ALTERNATE_DATA => {
                let restore_class = if attributes & 0x0000_0002 != 0 {
                    RestoreClass::System
                } else {
                    RestoreClass::SameOs
                };
                if attributes & 0x0000_0008 != 0 {
                    reader.skip(size).with_context(|| {
                        format!("failed to skip sparse Windows alternate stream ({size} bytes)")
                    })?;
                    sparse_alternate.push((name, attributes, restore_class, Vec::new()));
                    active_sparse_alternate = Some(sparse_alternate.len() - 1);
                    continue;
                }
                let sha256 = reader.read_sha256(size)?;
                let mut record = NativeAuxiliaryMetadata::new_streamed(
                    "windows.alternate-data",
                    "windows-backup-v1",
                    restore_class,
                    size,
                    sha256,
                );
                record.name_encoding = NativeAuxiliaryNameEncoding::Utf16Le;
                record.name = name;
                record
                    .meta
                    .insert("TZAP.aux.meta.stream-type".into(), b"00000004".to_vec());
                record.meta.insert(
                    "TZAP.aux.meta.stream-attributes".into(),
                    format!("{attributes:08x}").into_bytes(),
                );
                auxiliary.push(record);
            }
            BACKUP_EA_DATA | BACKUP_PROPERTY_DATA | BACKUP_OBJECT_ID => {
                if !name.is_empty() {
                    bail!("unnamed Windows backup stream unexpectedly has a name");
                }
                if stream_id == BACKUP_OBJECT_ID && size != 64 {
                    bail!("Windows object-ID backup stream is not exactly 64 bytes");
                }
                if size > MAX_RETAINED_BACKUP_STREAM {
                    bail!("Windows backup metadata stream exceeds the retained payload cap");
                }
                let payload = reader.read_vec(size)?;
                let (kind, stream_type, restore_class) = match stream_id {
                    BACKUP_EA_DATA => (
                        "windows.ea-data",
                        "00000002",
                        if attributes & 0x0000_0002 != 0 {
                            RestoreClass::System
                        } else {
                            RestoreClass::SameOs
                        },
                    ),
                    BACKUP_PROPERTY_DATA => (
                        "windows.property-data",
                        "00000006",
                        if attributes & 0x0000_0002 != 0 {
                            RestoreClass::System
                        } else {
                            RestoreClass::SameOs
                        },
                    ),
                    _ => ("windows.object-id", "00000007", RestoreClass::System),
                };
                let mut record =
                    NativeAuxiliaryMetadata::new(kind, "windows-backup-v1", restore_class, payload);
                record.meta.insert(
                    "TZAP.aux.meta.stream-type".into(),
                    stream_type.as_bytes().to_vec(),
                );
                record.meta.insert(
                    "TZAP.aux.meta.stream-attributes".into(),
                    format!("{attributes:08x}").into_bytes(),
                );
                if attributes & 0x0000_0008 != 0 {
                    bail!("Windows metadata stream carried an invalid sparse-data attribute");
                }
                auxiliary.push(record);
            }
            BACKUP_REPARSE_DATA => {
                if !name.is_empty() {
                    bail!("Windows reparse stream unexpectedly has a name");
                }
                if size > MAX_REPARSE_DATA_BUFFER_SIZE {
                    bail!("Windows reparse stream exceeds the platform buffer limit");
                }
                let payload = reader.read_vec(size)?;
                if expected_reparse_data != Some(payload.as_slice()) {
                    bail!("Windows reparse stream disagrees with FSCTL_GET_REPARSE_POINT");
                }
            }
            BACKUP_SPARSE_BLOCK => {
                if !name.is_empty() {
                    bail!("Windows sparse-block stream unexpectedly has a name");
                }
                if size < 8 {
                    bail!("Windows sparse-block stream is shorter than its offset (size={size})");
                }
                let offset = reader.read_vec(8)?;
                let offset = u64::from_le_bytes(offset.try_into().unwrap());
                let length = size - 8;
                reader.discard(length).with_context(|| {
                    format!("failed to discard Windows sparse-block data ({length} bytes)")
                })?;
                if length != 0 {
                    if let Some(index) = active_sparse_alternate {
                        push_windows_backup_sparse_extent(
                            &mut sparse_alternate[index].3,
                            offset,
                            length,
                        )?;
                    }
                }
            }
            BACKUP_LINK => {
                if !name.is_empty() {
                    bail!("Windows hardlink stream unexpectedly has a name");
                }
                reader.discard(size).with_context(|| {
                    format!("failed to discard Windows hardlink topology stream ({size} bytes)")
                })?;
            }
            BACKUP_TXFS_DATA => {
                bail!("Windows transactional backup streams are not representable in v45")
            }
            _ => bail!("Windows BackupRead returned unsupported stream id {stream_id}"),
        }
    }
    let file_metadata = file.metadata()?;
    let data_stream_attributes = match data_stream_attributes {
        Some(attributes) => attributes,
        // Raw EFS owns encrypted data streams, which BackupRead omits even when the logical file
        // is nonempty. FILE_ATTRIBUTE_SPARSE_FILE supplies the one independently observable
        // default-stream attribute represented by v45 sparse framing.
        None if file_metadata.file_attributes() & 0x0000_4000 != 0 => {
            if file_metadata.file_attributes() & 0x0000_0200 != 0 {
                0x0000_0008
            } else {
                0
            }
        }
        // BackupRead may omit BACKUP_DATA entirely for a zero-length unnamed stream. Successful
        // enumeration still proves there are no stream attributes to preserve in that case.
        None if file_metadata.len() == 0 => 0,
        None => bail!("Windows BackupRead did not return the default data stream"),
    };
    let sparse_layout_partial = !sparse_alternate.is_empty() && windows_file_system_is_refs(file)?;
    drop(reader);
    for (name, attributes, restore_class, mut extents) in sparse_alternate {
        let stream_path = windows_alternate_stream_path(input, &name)?;
        let mut stream = File::open(stream_path)?;
        let logical_size = stream.metadata()?.len();
        if sparse_layout_partial && logical_size != 0 {
            // ReFS does not expose an authoritative allocated-range map. Materialize every
            // logical byte even if BackupRead returned a non-empty but potentially incomplete
            // sparse-block list; the authenticated omission records layout degradation only.
            extents = vec![SparseExtent {
                offset: 0,
                length: logical_size,
            }];
        } else if extents.is_empty() && logical_size != 0 {
            extents = query_windows_allocated_ranges(&stream, logical_size)?;
        }
        if extents
            .last()
            .is_some_and(|extent| extent.offset + extent.length > logical_size)
        {
            bail!("Windows sparse-block stream exceeds its logical stream size");
        }
        let map = encode_v45_sparse_map(&extents, logical_size).map_err(|error| anyhow!(error))?;
        let sha256 =
            hash_windows_sparse_alternate_stream(&mut stream, &map, &extents, logical_size)?;
        let mut record = NativeAuxiliaryMetadata::new_streamed_sparse(
            "windows.alternate-data",
            "windows-backup-v1",
            restore_class,
            logical_size,
            extents,
            sha256,
        )
        .map_err(|error| anyhow!(error))?;
        record.name_encoding = NativeAuxiliaryNameEncoding::Utf16Le;
        record.name = name;
        record
            .meta
            .insert("TZAP.aux.meta.stream-type".into(), b"00000004".to_vec());
        record.meta.insert(
            "TZAP.aux.meta.stream-attributes".into(),
            format!("{attributes:08x}").into_bytes(),
        );
        auxiliary.push(record);
    }
    if sparse_layout_partial {
        let mut partial = NativeFileMetadata {
            auxiliary_records: auxiliary,
            ..NativeFileMetadata::default()
        };
        add_windows_refs_sparse_layout_omission(&mut partial);
        auxiliary = partial.auxiliary_records;
    }
    Ok((data_stream_attributes, auxiliary))
}

#[cfg(windows)]
fn push_windows_backup_sparse_extent(
    extents: &mut Vec<SparseExtent>,
    offset: u64,
    length: u64,
) -> Result<()> {
    const MAX_SPARSE_EXTENTS: usize = 1_048_576;
    let end = offset
        .checked_add(length)
        .ok_or_else(|| anyhow!("Windows sparse-block range overflow"))?;
    if let Some(previous) = extents.last_mut() {
        let previous_end = previous.offset + previous.length;
        if offset < previous_end {
            bail!("Windows sparse-block ranges overlap or are out of order");
        }
        if offset == previous_end {
            previous.length = end - previous.offset;
            return Ok(());
        }
    }
    if extents.len() >= MAX_SPARSE_EXTENTS {
        bail!("Windows sparse extent count exceeds the revision-45 limit");
    }
    extents.push(SparseExtent { offset, length });
    Ok(())
}

#[cfg(windows)]
fn hash_windows_sparse_alternate_stream(
    stream: &mut File,
    map: &[u8],
    extents: &[SparseExtent],
    logical_size: u64,
) -> Result<[u8; 32]> {
    use sha2::{Digest as _, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(map);
    let mut buffer = [0u8; 64 * 1024];
    for extent in extents {
        stream.seek(SeekFrom::Start(extent.offset))?;
        let mut remaining = extent.length;
        while remaining > 0 {
            let count = buffer
                .len()
                .min(usize::try_from(remaining).unwrap_or(usize::MAX));
            stream.read_exact(&mut buffer[..count])?;
            hasher.update(&buffer[..count]);
            remaining -= count as u64;
        }
    }
    if stream.metadata()?.len() != logical_size
        || query_windows_allocated_ranges(stream, logical_size)? != extents
    {
        bail!("Windows sparse alternate stream changed while hashing");
    }
    Ok(hasher.finalize().into())
}

#[cfg(all(not(target_os = "linux"), not(target_os = "macos"), not(windows)))]
fn capture_native_file_metadata(
    _input: &Path,
    _identity: InputIdentity,
) -> Result<NativeFileMetadata> {
    Ok(NativeFileMetadata::default())
}

#[cfg(target_os = "linux")]
fn capture_linux_inode_flags(file: &File, native: &mut NativeFileMetadata) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let mut flags: libc::c_long = 0;
    // SAFETY: the request writes one c_long to a valid pointer and observes a
    // live file descriptor owned by `file`.
    if unsafe { libc::ioctl(file.as_raw_fd(), libc::FS_IOC_GETFLAGS, &mut flags) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOTTY)
            || error.raw_os_error() == Some(libc::EOPNOTSUPP)
        {
            return Ok(());
        }
        return Err(error);
    }
    native.primary_pax_records.insert(
        "TZAP.linux.fsflags".into(),
        format!("{:016x}", flags as u64).into_bytes(),
    );
    native.required_profiles.push("linux-backup-v1".into());
    Ok(())
}

#[cfg(target_os = "linux")]
fn capture_linux_project_id(file: &File, native: &mut NativeFileMetadata) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    // All fields are integer/reserved storage, so an all-zero value is valid input.
    let mut attributes: linux_raw_sys::general::fsxattr = unsafe { std::mem::zeroed() };
    // SAFETY: the request writes one fsxattr through a valid pointer for a live descriptor.
    if unsafe {
        libc::ioctl(
            file.as_raw_fd(),
            linux_raw_sys::ioctl::FS_IOC_FSGETXATTR as libc::Ioctl,
            &mut attributes,
        )
    } != 0
    {
        let error = io::Error::last_os_error();
        if linux_project_id_ioctl_unavailable(&error) {
            return Ok(());
        }
        return Err(error);
    }
    if attributes.fsx_projid != 0 {
        native.primary_pax_records.insert(
            "TZAP.linux.project-id".into(),
            attributes.fsx_projid.to_string().into_bytes(),
        );
        native.required_profiles.push("linux-backup-v1".into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_project_id_ioctl_unavailable(error: &io::Error) -> bool {
    error.raw_os_error().is_some_and(|code| {
        code == libc::ENOTTY
            || code == libc::EOPNOTSUPP
            || code == libc::EINVAL
            || code == libc::ENOSYS
    })
}

fn source_os_label() -> &'static str {
    if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "freebsd") {
        "freebsd"
    } else if cfg!(target_os = "netbsd") {
        "netbsd"
    } else if cfg!(target_os = "openbsd") {
        "openbsd"
    } else if cfg!(target_os = "solaris") {
        "solaris"
    } else if cfg!(target_family = "unix") {
        "other-unix"
    } else {
        "other"
    }
}

fn portable_attributes(metadata: &fs::Metadata) -> Option<u32> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        let attributes = metadata.file_attributes();
        let mut projection = 0u32;
        projection |= u32::from(attributes & 0x0000_0001 != 0);
        projection |= u32::from(attributes & 0x0000_0002 != 0) << 1;
        projection |= u32::from(attributes & 0x0000_0004 != 0) << 2;
        projection |= u32::from(attributes & 0x0000_0020 != 0) << 3;
        Some(projection)
    }

    #[cfg(target_os = "macos")]
    {
        let _ = metadata;
        // Exact BSD flags are carried by TZAP.macos.st-flags. The portable
        // four-bit projection is Windows-specific and cannot be restored
        // faithfully on macOS.
        None
    }

    #[cfg(all(unix, not(target_os = "macos"), not(windows)))]
    {
        let _ = metadata;
        None
    }
}

fn write_archive_outputs(output: &str, volumes: &[Vec<u8>], force: bool) -> Result<()> {
    if volumes.is_empty() {
        bail!("writer returned no volumes");
    }
    let output_paths = create_output_paths(output, volumes.len());
    let mut temps = create_archive_output_temps(&output_paths)?;
    for ((temp, output_path), volume) in temps.iter_mut().zip(&output_paths).zip(volumes) {
        temp.as_file_mut().write_all(volume).with_context(|| {
            format!(
                "failed to write temporary archive volume for {}",
                output_path.display()
            )
        })?;
    }
    flush_archive_output_temps(&mut temps, &output_paths)?;
    publish_archive_output_temps(temps, &output_paths, force)?;
    Ok(())
}

fn write_archive_outputs_with_optional_bootstrap(
    output: &str,
    volumes: &[Vec<u8>],
    bootstrap_out: Option<&str>,
    bootstrap_sidecar: &[u8],
    force: bool,
) -> Result<()> {
    if bootstrap_out.is_some() && bootstrap_sidecar.is_empty() {
        return Err(FormatError::WriterUnsupported(
            "bootstrap output is unavailable for this archive shape",
        )
        .into());
    }

    write_archive_outputs(output, volumes, force)?;
    if let Some(path) = bootstrap_out {
        write_bootstrap_output_with_archive_rollback(
            path,
            bootstrap_sidecar,
            output,
            volumes.len(),
            force,
        )?;
    }
    Ok(())
}

fn write_bootstrap_output_with_archive_rollback(
    path: &str,
    bytes: &[u8],
    output: &str,
    volume_count: usize,
    force: bool,
) -> Result<()> {
    if let Err(err) = write_bootstrap_output(path, bytes, force) {
        for output_path in create_output_paths(output, volume_count) {
            let _ = fs::remove_file(output_path);
        }
        return Err(err).with_context(|| {
            "failed to publish bootstrap output; removed archive outputs published by this command"
        });
    }
    Ok(())
}

struct PathBackedArchiveSink<'a> {
    temps: &'a mut [tempfile::NamedTempFile],
    bootstrap_sidecar: Vec<u8>,
}

impl ArchiveWriteSink for PathBackedArchiveSink<'_> {
    fn begin_archive(&mut self, volume_count: usize) -> std::result::Result<(), ArchiveWriteError> {
        if volume_count != self.temps.len() {
            return Err(FormatError::WriterInvariant(
                "stdin file sink volume count does not match output paths",
            )
            .into());
        }
        for temp in self.temps.iter_mut() {
            let file = temp.as_file_mut();
            file.set_len(0).map_err(ArchiveWriteError::Io)?;
            file.seek(SeekFrom::Start(0))
                .map_err(ArchiveWriteError::Io)?;
        }
        self.bootstrap_sidecar.clear();
        Ok(())
    }

    fn write_volume(
        &mut self,
        volume_index: usize,
        bytes: &[u8],
    ) -> std::result::Result<(), ArchiveWriteError> {
        let temp = self
            .temps
            .get_mut(volume_index)
            .ok_or(FormatError::WriterInvariant(
                "stdin file sink volume index is out of bounds",
            ))?;
        temp.as_file_mut()
            .write_all(bytes)
            .map_err(ArchiveWriteError::Io)
    }

    fn write_bootstrap_sidecar(
        &mut self,
        bytes: &[u8],
    ) -> std::result::Result<(), ArchiveWriteError> {
        self.bootstrap_sidecar.extend_from_slice(bytes);
        Ok(())
    }
}

fn write_tar_stdin_archive_output(
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
        let mut authenticator =
            |request: &RootAuthSigningRequest| root_auth_authenticator_value(profile, request);
        return write_tar_stdin_archive_output_from_reader(
            output,
            &mut stdin_lock,
            key,
            options,
            Some(root_auth),
            Some(&mut authenticator),
            force,
        );
    }
    write_tar_stdin_archive_output_from_reader(
        output,
        &mut stdin_lock,
        key,
        options,
        None,
        None,
        force,
    )
}

fn write_tar_stdin_archive_output_from_reader<R: Read>(
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
        write_tar_stream_archive_to_sink_with_kdf_and_root_auth(
            reader,
            &key.master_key,
            options,
            &key.kdf_params,
            root_auth,
            authenticator,
            sink,
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn write_raw_stdin_archive_output<R: Read>(
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
        let mut authenticator =
            |request: &RootAuthSigningRequest| root_auth_authenticator_value(profile, request);
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
    write_raw_stdin_archive_output_from_reader(
        output,
        &mut reader,
        archive_path,
        input_size,
        key,
        options,
        None,
        None,
        force,
    )
}

fn write_file_inputs_ordered_parallel_to_output(
    output: &str,
    input_specs: &[InputSpec],
    key: &CreateKey,
    options: WriterOptions,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    root_auth_profile: Option<&CreateRootAuthProfile>,
    force: bool,
) -> Result<(WrittenArchiveSummary, Vec<u8>)> {
    if let (Some(profile), Some(root_auth)) = (root_auth_profile, root_auth) {
        let mut authenticator =
            |request: &RootAuthSigningRequest| root_auth_authenticator_value(profile, request);
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
    write_file_inputs_ordered_parallel_to_output_with_authenticator(
        output,
        input_specs,
        key,
        options,
        None,
        None,
        force,
    )
}

fn write_file_inputs_ordered_parallel_to_output_with_authenticator(
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
        write_archive_sources_to_sink_ordered_parallel(
            input_specs,
            &key.master_key,
            options,
            &key.kdf_params,
            root_auth,
            authenticator,
            sink,
        )
    })
}

fn write_file_inputs_ordered_parallel_recipient_wrap_to_output(
    output: &str,
    input_specs: &[InputSpec],
    master_key: &MasterKey,
    options: WriterOptions,
    recipient_record: tzap_core::wire::RecipientRecordV1,
    force: bool,
) -> Result<(WrittenArchiveSummary, Vec<u8>)> {
    let volume_count = options.stripe_width as usize;
    write_stdin_archive_output_with_sink(output, volume_count, force, |sink| {
        write_archive_sources_to_sink_ordered_parallel_with_recipient_wrap_records(
            input_specs,
            master_key,
            options,
            vec![recipient_record],
            None,
            None,
            sink,
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn write_raw_stdin_archive_output_from_reader<R: Read>(
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

fn write_stdin_archive_output_with_sink<T>(
    output: &str,
    volume_count: usize,
    force: bool,
    write_archive: impl FnOnce(
        &mut PathBackedArchiveSink<'_>,
    ) -> std::result::Result<T, ArchiveWriteError>,
) -> Result<(T, Vec<u8>)> {
    if volume_count == 0 {
        bail!("writer returned no volumes");
    }
    let output_paths = create_output_paths(output, volume_count);
    let mut temps = create_archive_output_temps(&output_paths)?;
    let (summary, bootstrap_sidecar) = {
        let mut sink = PathBackedArchiveSink {
            temps: temps.as_mut_slice(),
            bootstrap_sidecar: Vec::new(),
        };
        let summary = write_archive(&mut sink)?;
        (summary, sink.bootstrap_sidecar)
    };
    flush_archive_output_temps(&mut temps, &output_paths)?;
    publish_archive_output_temps(temps, &output_paths, force)?;
    Ok((summary, bootstrap_sidecar))
}

fn create_archive_output_temps(output_paths: &[PathBuf]) -> Result<Vec<tempfile::NamedTempFile>> {
    output_paths
        .iter()
        .map(|output_path| {
            let parent = output_path
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            tempfile::Builder::new()
                .prefix(".tzap-create-")
                .suffix(".partial")
                .tempfile_in(parent)
                .with_context(|| {
                    format!(
                        "failed to create temporary archive output in {}",
                        parent.display()
                    )
                })
        })
        .collect()
}

fn flush_archive_output_temps(
    temps: &mut [tempfile::NamedTempFile],
    output_paths: &[PathBuf],
) -> Result<()> {
    for (temp, output_path) in temps.iter_mut().zip(output_paths) {
        temp.as_file_mut().flush().with_context(|| {
            format!(
                "failed to flush temporary archive for {}",
                output_path.display()
            )
        })?;
        temp.as_file_mut().sync_all().with_context(|| {
            format!(
                "failed to sync temporary archive for {}",
                output_path.display()
            )
        })?;
    }
    Ok(())
}

fn publish_archive_output_temps(
    temps: Vec<tempfile::NamedTempFile>,
    output_paths: &[PathBuf],
    force: bool,
) -> Result<()> {
    let volume_count = output_paths.len();
    let publish_order = if volume_count == 1 {
        vec![0]
    } else {
        (1..volume_count).chain(std::iter::once(0)).collect()
    };
    let mut temp_slots = temps.into_iter().map(Some).collect::<Vec<_>>();
    let mut persisted_paths = Vec::new();
    for volume_index in publish_order {
        let temp = temp_slots[volume_index]
            .take()
            .ok_or_else(|| anyhow!("missing temporary archive volume {volume_index}"))?;
        let output_path = &output_paths[volume_index];
        let publish_result = if force {
            temp.persist(output_path)
        } else {
            temp.persist_noclobber(output_path)
        };
        if let Err(error) = publish_result {
            for path in &persisted_paths {
                let _ = fs::remove_file(path);
            }
            return Err(error.error)
                .with_context(|| format!("failed to publish archive {}", output_path.display()));
        }
        persisted_paths.push(output_path.clone());
    }
    Ok(())
}

fn write_bootstrap_output(path: &str, bytes: &[u8], force: bool) -> Result<()> {
    write_atomic_output_file("bootstrap output", Path::new(path), bytes, force)
}

fn reject_create_stdout_sentinels(output: &str, bootstrap_out: Option<&str>) -> Result<()> {
    if output == "-" {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "--output - is not archive stdout; create output must be a file path",
        )));
    }
    if matches!(bootstrap_out, Some("-")) {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "--bootstrap-out - is not sidecar stdout; sidecar output must be a file path",
        )));
    }
    Ok(())
}

fn validate_create_stdin_mode(args: CreateStdinArgs<'_>) -> Result<Option<CreateStdinMode>> {
    if args.tar_stdin && args.raw_stdin {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "--tar-stdin and --raw-stdin cannot be used together",
        )));
    }
    if args.spool_stdin && !args.raw_stdin {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "--spool-stdin requires --raw-stdin",
        )));
    }
    if args.stdin_name.is_some() && !args.raw_stdin {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "--stdin-name requires --raw-stdin",
        )));
    }
    if args.stdin_size.is_some() && !args.raw_stdin {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "--stdin-size requires --raw-stdin",
        )));
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
        return Err(anyhow!(FormatError::WriterUnsupported(
            "stdin create modes require exactly one archive input path: -",
        )));
    }
    if args.password_stdin {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "--password-stdin cannot be used when stdin carries archive payload bytes",
        )));
    }
    if args.password {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "--password cannot be used when stdin carries archive payload bytes",
        )));
    }
    if args.has_dictionary {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "--dictionary is not supported with stdin create modes",
        )));
    }
    if args.volume_size.is_some() {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "--volume-size is not supported with stdin create modes",
        )));
    }
    if args.volume_loss_tolerance.unwrap_or(0) != 0 {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "--volume-loss-tolerance > 0 is not supported with stdin create modes",
        )));
    }
    if matches!(args.volumes, Some(volumes) if volumes > 1)
        && !matches!(
            mode,
            CreateStdinMode::Tar | CreateStdinMode::RawKnownSize | CreateStdinMode::RawSpool
        )
    {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "--volumes > 1 is supported only with --tar-stdin, known-size --raw-stdin, or --raw-stdin --spool-stdin",
        )));
    }

    match mode {
        CreateStdinMode::Tar => {
            if args.stdin_name.is_some() || args.stdin_size.is_some() || args.spool_stdin {
                return Err(anyhow!(FormatError::WriterUnsupported(
                    "--stdin-name, --stdin-size, and --spool-stdin require --raw-stdin",
                )));
            }
        }
        CreateStdinMode::RawUnknownSize => {
            if args.stdin_name.is_none() {
                return Err(anyhow!(FormatError::WriterUnsupported(
                    "--raw-stdin requires --stdin-name PATH",
                )));
            }
        }
        CreateStdinMode::RawKnownSize => {
            if args.stdin_name.is_none() {
                return Err(anyhow!(FormatError::WriterUnsupported(
                    "--raw-stdin requires --stdin-name PATH",
                )));
            }
            parse_size(args.stdin_size.expect("checked raw known-size stdin"))
                .with_context(|| UsageError("invalid stdin-size"))?;
        }
        CreateStdinMode::RawSpool => {
            if args.stdin_name.is_none() {
                return Err(anyhow!(FormatError::WriterUnsupported(
                    "--raw-stdin requires --stdin-name PATH",
                )));
            }
            if args.stdin_size.is_some() {
                return Err(anyhow!(FormatError::WriterUnsupported(
                    "--spool-stdin is for unknown-size raw stdin; omit --stdin-size",
                )));
            }
        }
    }

    Ok(Some(mode))
}

fn ensure_create_output_paths_can_be_written(
    output: &str,
    volumes: Option<u32>,
    has_volume_size: bool,
    bootstrap_out: Option<&str>,
    force: bool,
) -> Result<()> {
    if let Some(path) = bootstrap_out {
        ensure_distinct_output_paths(
            "archive output",
            Path::new(output),
            "bootstrap output",
            Path::new(path),
        )?;
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

fn check_output_path_collisions_for_volume_size_output(output: &str) -> Result<()> {
    check_output_path_free("archive output", Path::new(output))?;
    let output_path = Path::new(output);
    let parent = output_path.parent().unwrap_or_else(|| Path::new("."));
    let base = multi_volume_base_name(output)?;
    let entries = match fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(err).with_context(|| {
                format!("failed to inspect output directory {}", parent.display())
            })
        }
    };
    for entry in entries.filter_map(|entry| entry.ok()) {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if looks_like_tzap_volume(&name, &base) {
            bail!(
                "output path collision: {base}.volNNN.tzap already exists; use --force to overwrite"
            );
        }
    }
    Ok(())
}

fn looks_like_tzap_volume(path_name: &str, base: &str) -> bool {
    let Some(rest) = path_name.strip_prefix(base) else {
        return false;
    };
    let Some(digits) = rest
        .strip_prefix(".vol")
        .and_then(|rest| rest.strip_suffix(".tzap"))
    else {
        return false;
    };
    !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
}

fn check_archive_paths_free_for_write(paths: &[PathBuf]) -> Result<()> {
    for path in paths {
        check_output_path_free("archive output", path)?;
    }
    Ok(())
}

fn ensure_distinct_output_paths(
    left_label: &str,
    left: &Path,
    right_label: &str,
    right: &Path,
) -> Result<()> {
    let left_identity = output_identity_path(left)?;
    let right_identity = output_identity_path(right)?;
    if left_identity == right_identity {
        bail!(
            "{left_label} and {right_label} must be different paths: {}",
            left.display()
        );
    }
    Ok(())
}

fn output_identity_path(path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("output path must include a file name: {}", path.display()))?;
    let parent = parent
        .canonicalize()
        .with_context(|| format!("failed to inspect output directory {}", parent.display()))?;
    Ok(parent.join(file_name))
}

fn resolve_create_volume_loss_tolerance(
    explicit: Option<u8>,
    volumes: Option<u32>,
    volume_size: Option<&str>,
    stdin_payload_mode_requested: bool,
) -> u8 {
    explicit.unwrap_or_else(|| {
        if stdin_payload_mode_requested || (volumes.unwrap_or(1) <= 1 && volume_size.is_none()) {
            0
        } else {
            1
        }
    })
}

fn validate_create_writer_options(options: &WriterOptions) -> Result<()> {
    if options.block_size < 4096 || options.block_size % 2 != 0 {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "writer requires an even block size of at least 4096",
        )));
    }
    if options.stripe_width == 0 {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "stripe_width must be non-zero",
        )));
    }
    let effective_stripe_width = if options.target_volume_size.is_some() {
        options
            .stripe_width
            .max(options.volume_loss_tolerance as u32 + 1)
    } else {
        options.stripe_width
    };
    if options.volume_loss_tolerance as u32 >= effective_stripe_width {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "volume_loss_tolerance must be less than stripe_width",
        )));
    }
    if effective_stripe_width == 1 && options.volume_loss_tolerance != 0 {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "single-volume archives cannot tolerate volume loss",
        )));
    }
    if matches!(options.target_volume_size, Some(0)) {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "target_volume_size must be non-zero",
        )));
    }
    if options.bit_rot_buffer_pct > 100 {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "bit_rot_buffer_pct must be at most 100",
        )));
    }
    if options.chunk_size == 0 || options.chunk_size > options.envelope_target_size {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "chunk_size must be non-zero and no larger than envelope_target_size",
        )));
    }
    Ok(())
}

fn check_output_path_free(label: &str, path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Ok(());
    }
    if path.exists() {
        bail!(
            "{label} already exists: {}; use --force to overwrite",
            path.display()
        );
    }
    Ok(())
}

fn create_output_paths(output: &str, volume_count: usize) -> Vec<PathBuf> {
    if volume_count == 1 {
        vec![PathBuf::from(output)]
    } else {
        (0..volume_count)
            .map(|index| create_volume_output_path(output, index))
            .collect()
    }
}

fn create_volume_output_path(output: &str, index: usize) -> PathBuf {
    let output_path = Path::new(output);
    let base = multi_volume_base_name(output).unwrap_or_else(|_| output.to_owned());
    let file_name = format!("{base}.vol{index:03}.tzap");
    match output_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(file_name),
        _ => PathBuf::from(file_name),
    }
}

fn multi_volume_base_name(output: &str) -> Result<String> {
    let file_name = Path::new(output)
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("output path has invalid UTF-8: {output}"))?;
    Ok(file_name
        .strip_suffix(".tzap")
        .unwrap_or(file_name)
        .to_owned())
}

fn create_dry_run_output_paths(
    output: &str,
    volumes: Option<u32>,
    has_volume_size: bool,
) -> Vec<String> {
    if let Some(volumes) = volumes {
        return create_output_paths(output, volumes as usize)
            .into_iter()
            .map(|path| path.display().to_string())
            .collect();
    }
    if has_volume_size {
        let first = create_volume_output_path(output, 0);
        let second = create_volume_output_path(output, 1);
        return vec![
            format!("{output} (if one volume is emitted)"),
            format!("{}, {}, ... (if split)", first.display(), second.display()),
        ];
    }
    vec![output.to_owned()]
}

fn describe_planned_volume_mode(volumes: Option<u32>, volume_size: Option<&str>) -> String {
    if let Some(volumes) = volumes {
        return format!("{volumes} explicit volume(s) requested");
    }
    if let Some(size) = volume_size {
        return format!("volume-size mode, target size {size}");
    }
    "single volume".to_string()
}

fn create_key_mode_label(
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

fn removed_insecure_zero_key_error() -> UsageError {
    UsageError("--insecure-zero-key was removed in v43; use --no-encryption for plaintext archives")
}

fn validate_create_key_source(
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
        return Err(UsageError(
            "no key source provided; use --password-stdin, --password, --keyfile PATH, --recipient-cert FILE, or --no-encryption",
        )
        .into());
    }
    if count > 1 {
        return Err(UsageError(
            "create accepts exactly one protection mode: --keyfile, --password, --password-stdin, --recipient-cert, or --no-encryption",
        )
        .into());
    }
    Ok(())
}

fn validate_create_recipient_wrap_scope(
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
        return Err(anyhow!(FormatError::WriterUnsupported(
            "--recipient-cert is currently supported only for file-backed create inputs",
        )));
    }
    if has_dictionary {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "--recipient-cert is not yet supported with --dictionary",
        )));
    }
    if has_root_auth {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "--recipient-cert is not yet supported with RootAuth signing flags",
        )));
    }
    if volumes.unwrap_or(1) != 1 || volume_size.is_some() {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "--recipient-cert is currently supported only for single-volume create",
        )));
    }
    Ok(())
}

fn create_root_auth_mode_label(signing_key: Option<&str>, signing_cert: Option<&str>) -> String {
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
            Self::Ed25519 {
                signer_identity, ..
            } => Ok(RootAuthWriterConfig {
                authenticator_id: ED25519_AUTHENTICATOR_ID,
                signer_identity_type: 1,
                signer_identity,
                authenticator_value_length: ED25519_AUTHENTICATOR_VALUE_LEN,
            }),
            Self::X509(signer) => signer.root_auth_writer_config().map_err(Into::into),
        }
    }
}

fn root_auth_authenticator_value(
    profile: &CreateRootAuthProfile,
    request: &RootAuthSigningRequest,
) -> Result<Vec<u8>, FormatError> {
    match profile {
        CreateRootAuthProfile::Ed25519 { signing_key, .. } => {
            Ok(ed25519_raw::authenticator_value_for_request(signing_key, request).to_vec())
        }
        CreateRootAuthProfile::X509(signer) => signer
            .authenticator_value_for_request(request)
            .map_err(|_| FormatError::WriterUnsupported("X.509 RootAuth signing failed")),
    }
}

#[derive(Debug, Clone)]
struct ArchiveInputSelection {
    paths: Vec<String>,
    autodiscovered: bool,
}

struct OpenedArchiveSelection {
    paths: Vec<String>,
    opened: OpenedArchive,
}

#[derive(Debug)]
struct CliRecipientPrivateKeyLookup {
    private_key_bytes: Vec<u8>,
    private_key_spki_der: Option<Vec<u8>>,
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
struct RecipientWrapOpenStats {
    records_seen: usize,
    no_matching_private_key: usize,
    invalid_record_or_unwrap: usize,
    unsupported_record: usize,
    candidate_count: usize,
}

struct RepairedArchiveOutput {
    path: String,
    volume_index: u32,
    repaired_block_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VolumePathPattern {
    base: String,
    volume_index: u32,
}

fn resolve_archive_input_paths(
    primary: &str,
    additional: &[String],
    allow_autodiscovery: bool,
) -> Result<ArchiveInputSelection> {
    let mut paths = Vec::with_capacity(additional.len() + 1);
    paths.push(primary.to_owned());
    paths.extend(additional.iter().cloned());
    if !allow_autodiscovery || !additional.is_empty() || primary == "-" {
        return Ok(ArchiveInputSelection {
            paths,
            autodiscovered: false,
        });
    }

    let Some(pattern) = parse_volume_path_pattern(Path::new(primary)) else {
        return Ok(ArchiveInputSelection {
            paths,
            autodiscovered: false,
        });
    };
    let discovered = discover_volume_siblings(Path::new(primary), &pattern)?;
    if discovered.is_empty() {
        return Ok(ArchiveInputSelection {
            paths,
            autodiscovered: false,
        });
    }
    Ok(ArchiveInputSelection {
        paths: discovered,
        autodiscovered: true,
    })
}

enum MappedVolumeInput {
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

fn map_volume_inputs_from_paths(paths: &[String]) -> Result<Vec<MappedVolumeInput>> {
    paths
        .iter()
        .map(|path| {
            let file =
                File::open(path).with_context(|| format!("failed to read archive {path}"))?;
            if file
                .metadata()
                .with_context(|| format!("failed to inspect archive {path}"))?
                .len()
                == 0
            {
                return Ok(MappedVolumeInput::Empty(Vec::new()));
            }
            // SAFETY: the mapping is read-only and retained while verifier slices are in use.
            let map = unsafe { Mmap::map(&file) }
                .with_context(|| format!("failed to map archive {path}"))?;
            Ok(MappedVolumeInput::Mapped(map))
        })
        .collect()
}

fn open_volume_inputs_from_paths(paths: &[String]) -> Result<Vec<File>> {
    paths
        .iter()
        .map(|path| File::open(path).with_context(|| format!("failed to read archive {path}")))
        .collect()
}

fn write_repaired_archive_copies(
    paths: &[String],
    opened: &OpenedArchive,
) -> Result<Vec<RepairedArchiveOutput>> {
    let patches = opened
        .repair_patches()
        .context("failed to prepare repaired archive output")?;
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
        patches_by_volume
            .entry(patch.volume_index)
            .or_default()
            .push(patch);
    }

    let mut jobs = Vec::new();
    for (volume_index, volume_patches) in patches_by_volume {
        let input_path = path_by_volume.get(&volume_index).ok_or_else(|| {
            anyhow!("repair output references unavailable volume index {volume_index}")
        })?;
        let output_path = repaired_archive_output_path(input_path)?;
        if output_path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("repaired output already exists: {}", output_path.display()),
            )
            .into());
        }
        jobs.push((
            volume_index,
            input_path.clone(),
            output_path,
            volume_patches,
        ));
    }

    let mut outputs: Vec<RepairedArchiveOutput> = Vec::new();
    for (volume_index, input_path, output_path, volume_patches) in jobs {
        let parent = output_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut temp = tempfile::Builder::new()
            .prefix(".tzap-repaired-")
            .suffix(".partial")
            .tempfile_in(parent)
            .with_context(|| {
                format!(
                    "failed to create temporary repaired output in {}",
                    parent.display()
                )
            })?;
        let mut input = File::open(&input_path)
            .with_context(|| format!("failed to open archive volume {}", input_path))?;
        io::copy(&mut input, temp.as_file_mut()).with_context(|| {
            format!(
                "failed to copy archive volume {} to {}",
                input_path,
                output_path.display()
            )
        })?;

        for patch in &volume_patches {
            temp.as_file_mut()
                .seek(SeekFrom::Start(patch.record_offset))
                .with_context(|| {
                    format!(
                        "failed to seek repaired output {} to offset {}",
                        output_path.display(),
                        patch.record_offset
                    )
                })?;
            temp.as_file_mut()
                .write_all(&patch.record_bytes)
                .with_context(|| {
                    format!(
                        "failed to write repaired block {} to {}",
                        patch.block_index,
                        output_path.display()
                    )
                })?;
        }
        temp.as_file_mut().flush().with_context(|| {
            format!("failed to flush repaired output {}", output_path.display())
        })?;
        temp.as_file_mut()
            .sync_all()
            .with_context(|| format!("failed to sync repaired output {}", output_path.display()))?;

        if let Err(error) = temp.persist_noclobber(&output_path) {
            for output in &outputs {
                let _ = fs::remove_file(&output.path);
            }
            return Err(error.error).with_context(|| {
                format!(
                    "failed to publish repaired output {}",
                    output_path.display()
                )
            });
        }
        outputs.push(RepairedArchiveOutput {
            path: output_path.to_string_lossy().into_owned(),
            volume_index,
            repaired_block_count: volume_patches.len(),
        });
    }

    Ok(outputs)
}

fn read_volume_index_from_path(path: &str) -> Result<u32> {
    let mut file = File::open(path).with_context(|| format!("failed to read archive {path}"))?;
    let mut header = [0u8; VOLUME_HEADER_LEN];
    file.read_exact(&mut header)
        .with_context(|| format!("failed to read archive header {path}"))?;
    Ok(VolumeHeader::parse(&header)
        .with_context(|| format!("failed to parse archive header {path}"))?
        .volume_index)
}

fn repaired_archive_output_path(input: &str) -> Result<PathBuf> {
    let path = Path::new(input);
    let file_name = path
        .file_name()
        .and_then(|file_name| file_name.to_str())
        .ok_or_else(|| anyhow!("archive path has no UTF-8 file name: {input}"))?;
    let repaired_name = if let Some(pattern) = parse_volume_file_name(file_name) {
        format!(
            "{}.repaired.vol{:03}.tzap",
            pattern.base, pattern.volume_index
        )
    } else if let Some(stem) = file_name.strip_suffix(".tzap") {
        format!("{stem}.repaired.tzap")
    } else {
        format!("{file_name}.repaired")
    };
    Ok(path.with_file_name(repaired_name))
}

fn parse_volume_path_pattern(path: &Path) -> Option<VolumePathPattern> {
    let file_name = path.file_name()?.to_str()?;
    parse_volume_file_name(file_name)
}

fn parse_volume_file_name(file_name: &str) -> Option<VolumePathPattern> {
    let stem = file_name.strip_suffix(".tzap")?;
    let (base, digits) = stem.rsplit_once(".vol")?;
    if base.is_empty() || digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(VolumePathPattern {
        base: base.to_owned(),
        volume_index: digits.parse().ok()?,
    })
}

fn discover_volume_siblings(primary: &Path, pattern: &VolumePathPattern) -> Result<Vec<String>> {
    let parent = primary.parent().unwrap_or_else(|| Path::new("."));
    let entries = match fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(err).with_context(|| {
                format!("failed to inspect archive directory {}", parent.display())
            })
        }
    };
    let mut discovered = Vec::new();
    for entry in entries.filter_map(|entry| entry.ok()) {
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        let Some(candidate) = parse_volume_file_name(file_name) else {
            continue;
        };
        if candidate.base != pattern.base {
            continue;
        }
        discovered.push((candidate.volume_index, entry.path()));
    }
    discovered.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    Ok(discovered
        .into_iter()
        .map(|(_, path)| path.to_string_lossy().into_owned())
        .collect())
}

fn reject_multi_volume_bootstrap(volume_count: usize, bootstrap: Option<&str>) -> Result<()> {
    if volume_count > 1 && bootstrap.is_some() {
        return Err(anyhow!(FormatError::ReaderUnsupported(
            "multi-volume inputs with --bootstrap are not supported; pass volume files without --bootstrap",
        )));
    }
    Ok(())
}

fn reject_stdout_extract_shape(stdout: bool, path_count: usize) -> Result<()> {
    if stdout && path_count != 1 {
        return Err(anyhow!(FormatError::ReaderUnsupported(
            "--stdout requires exactly one archive path",
        )));
    }
    Ok(())
}

struct ArchiveStdinOpenOptions<'a> {
    paths: &'a [String],
    stdout: bool,
    volumes: &'a [String],
    password_stdin: bool,
    password: bool,
    keyfile: Option<&'a str>,
    recipient_key: Option<&'a str>,
    insecure_zero_key: bool,
}

fn reject_archive_stdin_open_options(options: ArchiveStdinOpenOptions<'_>) -> Result<()> {
    if !options.volumes.is_empty() {
        return Err(anyhow!(FormatError::ReaderUnsupported(
            "archive stdin must be the only archive input",
        )));
    }
    if options.stdout {
        return Err(anyhow!(FormatError::ReaderUnsupported(
            "--stdout is not supported for archive stdin extraction",
        )));
    }
    if !options.paths.is_empty() {
        return Err(anyhow!(FormatError::ReaderUnsupported(
            "selected-path extraction is not supported for archive stdin",
        )));
    }
    reject_archive_stdin_key_options(
        options.password_stdin,
        options.password,
        options.keyfile,
        options.recipient_key,
        options.insecure_zero_key,
    )
}

fn reject_archive_stdin_list_options(
    volumes: &[String],
    password_stdin: bool,
    password: bool,
    keyfile: Option<&str>,
    recipient_key: Option<&str>,
    insecure_zero_key: bool,
) -> Result<()> {
    if !volumes.is_empty() {
        return Err(anyhow!(FormatError::ReaderUnsupported(
            "archive stdin must be the only archive input",
        )));
    }
    reject_archive_stdin_key_options(
        password_stdin,
        password,
        keyfile,
        recipient_key,
        insecure_zero_key,
    )
}

fn reject_archive_stdin_key_options(
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

fn load_archive_stdin_key(
    keyfile: Option<&str>,
    password_stdin: bool,
    password: bool,
    insecure_zero_key: bool,
) -> Result<MasterKey> {
    reject_archive_stdin_key_options(password_stdin, password, keyfile, None, insecure_zero_key)?;
    if keyfile.is_some() {
        return load_raw_master_key(keyfile);
    }
    Err(anyhow!(FormatError::KeyMaterialMismatch).context(
        "encrypted archive stdin requires --keyfile; unencrypted archive stdin uses no key source",
    ))
}

fn read_optional_bootstrap_sidecar(path: Option<&str>) -> Result<Option<Vec<u8>>> {
    path.map(|path| {
        fs::read(path).with_context(|| format!("failed to read bootstrap sidecar {path}"))
    })
    .transpose()
}

fn open_inputs_maybe_bootstrap(
    volume_files: Vec<File>,
    master_key: &MasterKey,
    bootstrap: Option<&str>,
    options: ReaderOptions,
) -> Result<OpenedArchive> {
    if volume_files.len() > 1 {
        reject_multi_volume_bootstrap(volume_files.len(), bootstrap)?;
        return OpenedArchive::open_seekable_volumes_with_options(
            volume_files,
            master_key,
            options,
        )
        .map_err(Into::into);
    }
    let volume_file = volume_files
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("at least one archive volume is required"))?;
    if let Some(path) = bootstrap {
        let sidecar =
            fs::read(path).with_context(|| format!("failed to read bootstrap sidecar {path}"))?;
        open_seekable_archive_with_bootstrap_sidecar_options(
            volume_file,
            &sidecar,
            master_key,
            options,
        )
        .map_err(Into::into)
    } else {
        OpenedArchive::open_seekable_volumes_with_options(vec![volume_file], master_key, options)
            .map_err(Into::into)
    }
}

fn open_selection_maybe_bootstrap(
    selection: &ArchiveInputSelection,
    master_key: &MasterKey,
    bootstrap: Option<&str>,
    options: ReaderOptions,
) -> Result<OpenedArchive> {
    Ok(open_selection_maybe_bootstrap_resolved(selection, master_key, bootstrap, options)?.opened)
}

fn open_selection_maybe_bootstrap_resolved(
    selection: &ArchiveInputSelection,
    master_key: &MasterKey,
    bootstrap: Option<&str>,
    options: ReaderOptions,
) -> Result<OpenedArchiveSelection> {
    let volume_files = open_volume_inputs_from_paths(&selection.paths)?;
    match open_inputs_maybe_bootstrap(volume_files, master_key, bootstrap, options) {
        Ok(opened) => Ok(OpenedArchiveSelection {
            paths: selection.paths.clone(),
            opened,
        }),
        Err(err)
            if selection.autodiscovered && bootstrap.is_none() && selection.paths.len() > 1 =>
        {
            let usable_paths =
                filter_usable_autodiscovered_volume_paths(&selection.paths, master_key)
                    .with_context(|| "failed to filter autodiscovered archive volumes")?;
            if usable_paths == selection.paths {
                return Err(err);
            }
            let volume_files = open_volume_inputs_from_paths(&usable_paths)?;
            let opened = open_inputs_maybe_bootstrap(volume_files, master_key, bootstrap, options)?;
            Ok(OpenedArchiveSelection {
                paths: usable_paths,
                opened,
            })
        }
        Err(err) => Err(err),
    }
}

fn open_selection_with_recipient_key(
    selection: &ArchiveInputSelection,
    recipient_key: &str,
    bootstrap: Option<&str>,
    options: ReaderOptions,
) -> Result<OpenedArchiveSelection> {
    if bootstrap.is_some() {
        return Err(anyhow!(FormatError::ReaderUnsupported(
            "--recipient-key is not currently supported with --bootstrap",
        )));
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
    Ok(OpenedArchiveSelection {
        paths: selection.paths.clone(),
        opened,
    })
}

fn recipient_wrap_candidates_for_record(
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
        KeyWrapOutcome::InvalidRecord | KeyWrapOutcome::CertificatePolicyRejected => {
            stats.invalid_record_or_unwrap += 1;
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

fn recipient_wrap_open_error(err: FormatError, stats: &RecipientWrapOpenStats) -> anyhow::Error {
    if !matches!(err, FormatError::KeyMaterialMismatch) {
        return anyhow!(err);
    }
    if stats.candidate_count > 0 {
        return anyhow!(err).context(
            "recipient private key unwrapped a candidate, but archive header_hmac did not verify",
        );
    }
    if stats.records_seen == 0 {
        return anyhow!(err).context("recipient-wrap archive has no recipient records");
    }
    if stats.no_matching_private_key > 0 && stats.invalid_record_or_unwrap == 0 {
        return anyhow!(err).context("no matching recipient private key for archive");
    }
    anyhow!(err).context(
        "recipient private key did not match any recipient record or failed recipient unwrap",
    )
}

fn filter_usable_autodiscovered_volume_paths(
    paths: &[String],
    master_key: &MasterKey,
) -> Result<Vec<String>> {
    let mut usable = Vec::new();
    let mut first_error = None;
    for path in paths {
        let file = match File::open(path) {
            Ok(file) => file,
            Err(err) => {
                if first_error.is_none() {
                    first_error =
                        Some(anyhow!(err).context(format!("failed to read archive {path}")));
                }
                continue;
            }
        };
        match open_seekable_archive(file, master_key) {
            Ok(_) => usable.push(path.clone()),
            Err(err) if is_single_volume_candidate_usable_error(&err) => usable.push(path.clone()),
            Err(err) => {
                if first_error.is_none() {
                    first_error =
                        Some(anyhow!(err).context(format!("failed to open archive {path}")));
                }
            }
        }
    }
    if usable.is_empty() {
        return Err(
            first_error.unwrap_or_else(|| anyhow!("no autodiscovered archive volumes found"))
        );
    }
    Ok(usable)
}

fn is_single_volume_candidate_usable_error(err: &FormatError) -> bool {
    matches!(err, FormatError::FecTooFewAvailableShards)
        || matches!(
            err,
            FormatError::InvalidArchive(message)
                if *message == "missing volume count exceeds volume_loss_tolerance"
        )
}

fn validate_verify_key_holding_key_source(
    keyfile: Option<&str>,
    recipient_key: Option<&str>,
    password_stdin: bool,
    password: bool,
    insecure_zero_key: bool,
) -> Result<()> {
    if insecure_zero_key {
        return Err(removed_insecure_zero_key_error().into());
    }
    let count = usize::from(keyfile.is_some())
        + usize::from(recipient_key.is_some())
        + usize::from(password_stdin)
        + usize::from(password);
    if count > 1 {
        return Err(UsageError(
            "verify accepts at most one key source: --keyfile, --recipient-key, --password, or --password-stdin",
        )
        .into());
    }
    Ok(())
}

struct PublicNoKeyVerifyRequest<'a> {
    archive_paths: &'a [String],
    trusted_public_key: Option<&'a str>,
    trusted_ca_cert: &'a [String],
    trusted_system_roots: bool,
    password_stdin: bool,
    password: bool,
    keyfile: Option<&'a str>,
    recipient_key: Option<&'a str>,
    insecure_zero_key: bool,
    bootstrap: Option<&'a str>,
    reader_options: ReaderOptions,
    quiet: bool,
    json: bool,
}

fn run_public_no_key_verify(request: PublicNoKeyVerifyRequest<'_>) -> Result<()> {
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
    Ok(())
}

fn load_public_no_key_trust(request: &PublicNoKeyVerifyRequest<'_>) -> Result<PublicNoKeyTrust> {
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
    })
}

fn verify_opened_root_auth_ed25519(
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

fn verify_opened_root_auth(
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

fn verify_opened_root_auth_x509(
    opened: &OpenedArchive,
    content_verification: &ArchiveContentVerification<'_>,
    trusted_roots_der: &[Vec<u8>],
    trusted_system_roots: bool,
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

fn revision_mode_label(volume_format_rev: u16) -> &'static str {
    match volume_format_rev {
        VOLUME_FORMAT_REV_45 => "v45",
        _ => "unsupported",
    }
}

fn key_access_status(opened: &OpenedArchive, used_recipient_key: bool) -> &'static str {
    if opened.crypto_header.aead_algo == AeadAlgo::None {
        "plaintext_opened"
    } else if used_recipient_key || opened.crypto_header.kdf_algo == KdfAlgo::RecipientWrap {
        "recipientwrap_opened"
    } else {
        "key_holding_decrypted"
    }
}

fn key_holding_status_json(
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

fn key_holding_root_auth_status(
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

fn key_holding_trust_policy_status(
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

fn verified_root_auth_status(root_auth: &VerifiedRootAuth) -> &'static str {
    match root_auth {
        VerifiedRootAuth::Ed25519(verification) => root_auth_status(verification),
        VerifiedRootAuth::X509 { verification, .. } => root_auth_status(verification),
    }
}

fn public_no_key_status_json(root_auth: &VerifiedPublicNoKeyRootAuth) -> serde_json::Value {
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

fn public_no_key_verification(root_auth: &VerifiedPublicNoKeyRootAuth) -> &PublicNoKeyVerification {
    match root_auth {
        VerifiedPublicNoKeyRootAuth::Ed25519(verification) => verification,
        VerifiedPublicNoKeyRootAuth::X509 { verification, .. } => verification,
    }
}

fn root_auth_json(root_auth: &VerifiedRootAuth) -> serde_json::Value {
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

fn root_auth_status(root_auth: &RootAuthVerification) -> &'static str {
    root_auth
        .diagnostics
        .first()
        .map(|diagnostic| diagnostic.label())
        .unwrap_or("root_auth_content_verified")
}

fn root_auth_diagnostic_labels(root_auth: &RootAuthVerification) -> Vec<&'static str> {
    root_auth
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.label())
        .collect()
}

fn emit_root_auth_stdout(quiet: bool, root_auth: &VerifiedRootAuth) -> io::Result<()> {
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

fn emit_root_auth_diagnostics_stdout(
    quiet: bool,
    verification: &RootAuthVerification,
) -> io::Result<()> {
    for diagnostic in &verification.diagnostics {
        emit_success_stdout(quiet, &format!("root-auth: {}", diagnostic.label()))?;
    }
    Ok(())
}

fn fast_verify_diagnostic_labels(opened: &OpenedArchive) -> Vec<&'static str> {
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

fn emit_fast_verify_diagnostics_stdout(quiet: bool, opened: &OpenedArchive) -> io::Result<()> {
    for diagnostic in fast_verify_diagnostic_labels(opened) {
        emit_success_stdout(quiet, &format!("fast-verify: {diagnostic}"))?;
    }
    Ok(())
}

fn public_no_key_root_auth_json(root_auth: &VerifiedPublicNoKeyRootAuth) -> serde_json::Value {
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

fn public_no_key_status(verification: &PublicNoKeyVerification) -> &'static str {
    verification
        .diagnostics
        .first()
        .map(|diagnostic| diagnostic.label())
        .unwrap_or("public_data_block_commitment_verified")
}

fn public_no_key_diagnostic_labels(verification: &PublicNoKeyVerification) -> Vec<&'static str> {
    verification
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.label())
        .collect()
}

fn public_no_key_diagnostic_labels_for_root_auth(
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

fn emit_public_no_key_root_auth_stdout(
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

fn public_no_key_total_data_block_count(root_auth: &VerifiedPublicNoKeyRootAuth) -> u64 {
    match root_auth {
        VerifiedPublicNoKeyRootAuth::Ed25519(verification) => verification.total_data_block_count,
        VerifiedPublicNoKeyRootAuth::X509 { verification, .. } => {
            verification.total_data_block_count
        }
    }
}

fn format_unix_timestamp(unix_seconds: i64) -> String {
    match OffsetDateTime::from_unix_timestamp(unix_seconds) {
        Ok(date_time) => date_time
            .format(&Rfc3339)
            .unwrap_or_else(|_| unix_seconds.to_string()),
        Err(_) => unix_seconds.to_string(),
    }
}

fn generate_random_key_material() -> Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    Ok(bytes)
}

fn generate_ed25519_signing_key() -> SigningKey {
    SigningKey::generate(&mut rand::rngs::OsRng)
}

fn write_keyfile(path: &str, key_hex: &str, force: bool) -> Result<()> {
    write_atomic_output_file("keyfile", Path::new(path), key_hex.as_bytes(), force)
}

struct AtomicOutput<'a> {
    label: &'a str,
    path: &'a Path,
    bytes: &'a [u8],
}

fn write_atomic_output_file(label: &str, path: &Path, bytes: &[u8], force: bool) -> Result<()> {
    write_atomic_output_files(&[AtomicOutput { label, path, bytes }], force)
}

fn write_atomic_output_files(outputs: &[AtomicOutput<'_>], force: bool) -> Result<()> {
    for (index, output) in outputs.iter().enumerate() {
        for previous in &outputs[..index] {
            ensure_distinct_output_paths(previous.label, previous.path, output.label, output.path)?;
        }
        if !force && output.path.exists() {
            bail!(
                "{} already exists: {}; use --force to overwrite",
                output.label,
                output.path.display()
            );
        }
    }

    let mut temps = Vec::with_capacity(outputs.len());
    for output in outputs {
        let parent = output
            .path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut temp = tempfile::Builder::new()
            .prefix(".tzap-write-")
            .suffix(".partial")
            .tempfile_in(parent)
            .with_context(|| {
                format!(
                    "failed to create temporary {} in {}",
                    output.label,
                    parent.display()
                )
            })?;
        temp.as_file_mut()
            .write_all(output.bytes)
            .with_context(|| {
                format!(
                    "failed to write temporary {} {}",
                    output.label,
                    output.path.display()
                )
            })?;
        temp.as_file_mut().flush().with_context(|| {
            format!(
                "failed to flush temporary {} {}",
                output.label,
                output.path.display()
            )
        })?;
        temp.as_file_mut().sync_all().with_context(|| {
            format!(
                "failed to sync temporary {} {}",
                output.label,
                output.path.display()
            )
        })?;
        temps.push(Some(temp));
    }

    let mut persisted_paths = Vec::new();
    for (index, output) in outputs.iter().enumerate() {
        let temp = temps[index]
            .take()
            .ok_or_else(|| anyhow!("missing temporary {}", output.label))?;
        let publish_result = if force {
            temp.persist(output.path)
        } else {
            temp.persist_noclobber(output.path)
        };
        match publish_result {
            Ok(_) => persisted_paths.push(output.path.to_path_buf()),
            Err(error) if !force && error.error.kind() == io::ErrorKind::AlreadyExists => {
                for path in &persisted_paths {
                    let _ = fs::remove_file(path);
                }
                bail!(
                    "{} already exists: {}; use --force to overwrite",
                    output.label,
                    output.path.display()
                );
            }
            Err(error) => {
                for path in &persisted_paths {
                    let _ = fs::remove_file(path);
                }
                return Err(error.error).with_context(|| {
                    format!(
                        "failed to publish {} {}",
                        output.label,
                        output.path.display()
                    )
                });
            }
        }
    }
    Ok(())
}

fn load_ed25519_signing_key(path: &str) -> Result<SigningKey> {
    let seed = load_32_byte_key_file("Ed25519 signing key seed", path)?;
    Ok(SigningKey::from_bytes(&seed))
}

fn load_create_root_auth_profile(
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
            Ok(Some(CreateRootAuthProfile::Ed25519 {
                signing_key,
                signer_identity,
            }))
        }
        (None, Some(cert_path), Some(private_key_path)) => {
            let cert = fs::read(cert_path)
                .with_context(|| format!("failed to read signing certificate {cert_path}"))?;
            let private_key = fs::read(private_key_path).with_context(|| {
                format!("failed to read signing private key {private_key_path}")
            })?;
            let chain_der = load_x509_certificate_files(signing_chain)?;
            let signed_at = current_unix_seconds()?;
            let signer = if let Some(scheme) = x509_signature_scheme {
                X509RootAuthSigner::from_pem_or_der_with_signature_scheme(
                    &cert,
                    &private_key,
                    chain_der,
                    signed_at,
                    scheme.to_plugin_scheme(),
                )
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
        _ => Err(UsageError(
            "create requires either --signing-key or --signing-cert with --signing-private-key",
        )
        .into()),
    }
}

fn load_ed25519_public_key(path: &str) -> Result<[u8; 32]> {
    load_32_byte_key_file("Ed25519 public key", path)
}

fn load_x509_certificate_files(paths: &[String]) -> Result<Vec<Vec<u8>>> {
    let mut certificates = Vec::new();
    for path in paths {
        let bytes = fs::read(path).with_context(|| format!("failed to read certificate {path}"))?;
        certificates.extend(
            x509_chain::certificates_der_from_pem_or_der(&bytes)
                .with_context(|| format!("failed to parse certificate {path}"))?,
        );
    }
    Ok(certificates)
}

fn load_x509_trusted_roots(
    paths: &[String],
    include_official_tzap_root: bool,
) -> Result<Vec<Vec<u8>>> {
    let mut certificates = Vec::new();
    if include_official_tzap_root {
        certificates.push(
            x509_chain::certificate_der_from_pem_or_der(OFFICIAL_TZAP_ROOT_CERT_PEM)
                .with_context(|| {
                    format!(
                        "failed to parse embedded TZAP root certificate {OFFICIAL_TZAP_ROOT_CERT_SHA256}"
                    )
                })?,
        );
    }
    certificates.extend(load_x509_certificate_files(paths)?);
    Ok(certificates)
}

fn load_single_x509_certificate_file(label: &'static str, path: &str) -> Result<Vec<u8>> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {label} {path}"))?;
    let certificates = x509_chain::certificates_der_from_pem_or_der(&bytes)
        .with_context(|| format!("failed to parse {label} {path}"))?;
    match certificates.as_slice() {
        [certificate] => Ok(certificate.clone()),
        [] => bail!("{label} must contain exactly one X.509 certificate"),
        _ => bail!("{label} must contain exactly one X.509 certificate"),
    }
}

fn load_recipient_private_key_lookup(path: &str) -> Result<CliRecipientPrivateKeyLookup> {
    let bytes = fs::read(path).with_context(|| format!("failed to read recipient key {path}"))?;
    if bytes.len() == 32 {
        return Ok(CliRecipientPrivateKeyLookup {
            private_key_bytes: bytes,
            private_key_spki_der: None,
        });
    }
    let private_key = if bytes.starts_with(b"-----BEGIN") {
        PKey::private_key_from_pem(&bytes)
            .with_context(|| format!("failed to parse recipient private key {path}"))?
    } else {
        PKey::private_key_from_der(&bytes)
            .with_context(|| format!("failed to parse recipient private key {path}"))?
    };
    let private_key_bytes = private_key
        .private_key_to_der()
        .with_context(|| format!("failed to normalize recipient private key {path}"))?;
    let private_key_spki_der = private_key.public_key_to_der().ok();
    Ok(CliRecipientPrivateKeyLookup {
        private_key_bytes,
        private_key_spki_der,
    })
}

fn generate_random_master_key() -> Result<MasterKey> {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    MasterKey::from_raw_key(&bytes).map_err(Into::into)
}

fn build_recipient_wrap_record(
    recipient_cert_path: &str,
    master_key: &MasterKey,
    options: &mut WriterOptions,
) -> Result<tzap_core::wire::RecipientRecordV1> {
    let recipient_certificate =
        load_single_x509_certificate_file("recipient certificate", recipient_cert_path)?;
    let archive_identity = recipient_wrap_archive_identity_for_writer(options);
    let master_key_bytes = master_key.0;
    for suite in [
        KeyWrapSuite::X25519HkdfSha256ChaCha20Poly1305,
        KeyWrapSuite::P256HkdfSha256Aes256Gcm,
    ] {
        match wrap_master_key_for_recipient(
            archive_identity.clone(),
            &recipient_certificate,
            &master_key_bytes,
            suite,
        ) {
            Ok(record) => return Ok(record),
            Err(KeyWrapOutcome::InvalidRecord) | Err(KeyWrapOutcome::UnsupportedSuite) => {}
            Err(outcome) => return Err(key_wrap_outcome_error(outcome)),
        }
    }
    Err(anyhow!(FormatError::WriterUnsupported(
        "recipient certificate is not supported by keywrap-v1 suites",
    )))
}

fn recipient_wrap_archive_identity_for_writer(
    options: &mut WriterOptions,
) -> KeyWrapArchiveIdentity {
    let archive_uuid = *options.archive_uuid.get_or_insert_with(random_16_bytes);
    let session_id = *options.session_id.get_or_insert_with(random_16_bytes);
    KeyWrapArchiveIdentity {
        archive_uuid,
        session_id,
        format_version: FORMAT_VERSION,
        volume_format_rev: VOLUME_FORMAT_REV_45,
    }
}

fn random_16_bytes() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

fn key_wrap_outcome_error(outcome: KeyWrapOutcome) -> anyhow::Error {
    match outcome {
        KeyWrapOutcome::UnsupportedProfileId => anyhow!(FormatError::ReaderUnsupported(
            "unsupported keywrap recipient profile",
        )),
        KeyWrapOutcome::UnsupportedArchiveIdentity => anyhow!(FormatError::ReaderUnsupported(
            "unsupported keywrap archive identity",
        )),
        KeyWrapOutcome::UnsupportedRecipientIdentity => anyhow!(FormatError::ReaderUnsupported(
            "unsupported keywrap recipient identity",
        )),
        KeyWrapOutcome::UnsupportedSuite => anyhow!(FormatError::ReaderUnsupported(
            "unsupported keywrap recipient suite",
        )),
        KeyWrapOutcome::CertificatePolicyRejected => anyhow!(FormatError::ReaderUnsupported(
            "recipient certificate policy rejected",
        )),
        KeyWrapOutcome::InvalidRecord => anyhow!(FormatError::InvalidArchive(
            "invalid keywrap recipient record",
        )),
        KeyWrapOutcome::NoMatchingPrivateKey => anyhow!(FormatError::KeyMaterialMismatch)
            .context("no matching recipient private key for archive"),
        KeyWrapOutcome::UnwrappedCandidateMasterKey { .. } => anyhow!(
            FormatError::WriterInvariant("keywrap success outcome cannot be converted to error",)
        ),
    }
}

fn current_unix_seconds() -> Result<i64> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    i64::try_from(seconds).context("current Unix timestamp exceeds i64")
}

fn load_32_byte_key_file(label: &'static str, path: &str) -> Result<[u8; 32]> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {label} {path}"))?;
    if bytes.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        return Ok(out);
    }

    let hex = std::str::from_utf8(&bytes)
        .with_context(|| format!("{label} must contain either 32 raw bytes or 64 hex characters"))?
        .trim();
    if hex.len() != 64 {
        bail!("{label} must contain either 32 raw bytes or 64 hex characters");
    }
    let mut out = [0u8; 32];
    for (idx, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        out[idx] = decode_hex_byte(chunk)?;
    }
    Ok(out)
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = std::fmt::Write::write_fmt(&mut output, format_args!("{:02x}", byte));
    }
    output
}

#[allow(clippy::too_many_arguments)]
fn load_create_key(
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
        let kdf_params = KdfParams::Argon2id {
            t_cost,
            m_cost_kib,
            parallelism,
            salt,
        };
        let master_key = MasterKey::derive_from_passphrase(&kdf_params, &passphrase)?;
        return Ok(CreateKey {
            master_key,
            kdf_params,
        });
    }
    if password {
        let passphrase = read_passphrase_interactive_create()?;
        validate_argon2_params(t_cost, m_cost_kib, parallelism)?;
        let mut salt = vec![0u8; DEFAULT_ARGON2_SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        let kdf_params = KdfParams::Argon2id {
            t_cost,
            m_cost_kib,
            parallelism,
            salt,
        };
        let master_key = MasterKey::derive_from_passphrase(&kdf_params, &passphrase)?;
        return Ok(CreateKey {
            master_key,
            kdf_params,
        });
    }
    if no_encryption {
        return Ok(CreateKey {
            master_key: insecure_zero_master_key()?,
            kdf_params: KdfParams::None,
        });
    }
    if insecure_zero_key {
        return Err(removed_insecure_zero_key_error().into());
    }
    Ok(CreateKey {
        master_key: load_raw_master_key(keyfile)?,
        kdf_params: KdfParams::Raw,
    })
}

fn load_open_key_from_paths(
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
    Err(anyhow!(FormatError::KeyMaterialMismatch)
        .context("encrypted archives require --keyfile, --password, or --password-stdin"))
}

fn insecure_zero_master_key() -> Result<MasterKey> {
    MasterKey::from_raw_key(&INSECURE_ZERO_KEY).map_err(Into::into)
}

fn derive_key_from_passphrase(kdf_params: &KdfParams, passphrase: &str) -> Result<MasterKey> {
    match kdf_params {
        KdfParams::Argon2id { .. } => {
            MasterKey::derive_from_passphrase(kdf_params, passphrase).map_err(Into::into)
        }
        KdfParams::Raw => Err(anyhow!(FormatError::KeyMaterialMismatch)
            .context("raw-key archives require --keyfile, not passphrase input")),
        KdfParams::RecipientWrap { .. } => Err(anyhow!(FormatError::KeyMaterialMismatch)
            .context("recipient-wrap archives require recipient key unwrap, not passphrase input")),
        KdfParams::None => Err(anyhow!(FormatError::KeyMaterialMismatch)
            .context("unencrypted archives do not use passphrase input")),
    }
}

fn validate_argon2_params(t_cost: u32, m_cost_kib: u32, parallelism: u32) -> Result<()> {
    if t_cost == 0 {
        return Err(anyhow!(FormatError::InvalidKdfParams(
            "argon2 t_cost must be at least 1",
        )));
    }
    if t_cost > READER_MAX_ARGON2ID_T_COST {
        return Err(anyhow!(FormatError::InvalidKdfParams(
            "argon2 t_cost exceeds reader maximum",
        )));
    }
    if parallelism == 0 {
        return Err(anyhow!(FormatError::InvalidKdfParams(
            "argon2 parallelism must be at least 1",
        )));
    }
    if parallelism > READER_MAX_ARGON2ID_PARALLELISM {
        return Err(anyhow!(FormatError::InvalidKdfParams(
            "argon2 parallelism exceeds reader maximum",
        )));
    }
    if m_cost_kib > READER_MAX_ARGON2ID_M_COST_KIB {
        return Err(anyhow!(FormatError::InvalidKdfParams(
            "argon2 memory cost exceeds reader maximum",
        )));
    }
    let min_memory = parallelism.checked_mul(8).ok_or_else(|| {
        anyhow!(FormatError::InvalidKdfParams(
            "argon2 memory per lane computation overflows",
        ))
    })?;
    if m_cost_kib < min_memory {
        return Err(anyhow!(FormatError::InvalidKdfParams(
            "argon2 memory must be at least 8 KiB per lane",
        )));
    }
    Ok(())
}

fn load_raw_master_key(keyfile: Option<&str>) -> Result<MasterKey> {
    let keyfile = keyfile.ok_or_else(|| {
        anyhow!(
            "no key source provided; use --password-stdin, --password, --keyfile PATH, --recipient-cert FILE, or --no-encryption for create"
        )
    })?;
    let bytes = fs::read(keyfile).with_context(|| format!("failed to read keyfile {keyfile}"))?;
    if bytes.len() == 32 {
        return MasterKey::from_raw_key(&bytes).map_err(Into::into);
    }

    let hex = std::str::from_utf8(&bytes)
        .context("keyfile must contain either 32 raw bytes or 64 hex characters")?
        .trim();
    if hex.len() != 64 {
        bail!("keyfile must contain either 32 raw bytes or 64 hex characters");
    }
    let mut raw = [0u8; 32];
    for (idx, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        raw[idx] = decode_hex_byte(chunk)?;
    }
    MasterKey::from_raw_key(&raw).map_err(Into::into)
}

fn read_passphrase_stdin() -> Result<String> {
    let mut passphrase = String::new();
    io::stdin()
        .read_to_string(&mut passphrase)
        .context("failed to read passphrase from stdin")?;
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

fn read_passphrase_interactive_create() -> Result<String> {
    loop {
        let first = read_passphrase_interactive("Passphrase: ")?;
        let second = read_passphrase_interactive("Confirm passphrase: ")?;
        if first == second {
            return Ok(first);
        }
        eprintln!("Passphrases do not match; try again.");
    }
}

fn read_passphrase_interactive_open() -> Result<String> {
    read_passphrase_interactive("Passphrase: ")
}

fn read_passphrase_interactive(prompt: &str) -> Result<String> {
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

fn read_non_empty_passphrase(passphrase: String) -> Result<String> {
    if passphrase.is_empty() {
        bail!("passphrase must not be empty");
    }
    Ok(passphrase)
}

fn read_passphrase_hidden(prompt: &str) -> Result<String> {
    Ok(rpassword::prompt_password(prompt)?)
}

fn read_passphrase_stdin_fallback() -> Result<String> {
    let mut passphrase = String::new();
    io::stdin()
        .read_line(&mut passphrase)
        .context("failed to read passphrase from stdin")?;
    if passphrase.ends_with('\n') {
        passphrase.pop();
        if passphrase.ends_with('\r') {
            passphrase.pop();
        }
    }
    Ok(passphrase)
}

#[cfg(test)]
fn read_kdf_params_from_volume(bytes: &[u8]) -> Result<KdfParams> {
    let header_bytes = bytes.get(..VOLUME_HEADER_LEN).ok_or_else(|| {
        anyhow!(FormatError::InvalidArchive(
            "volume is too short for VolumeHeader"
        ))
    })?;
    let volume_header = VolumeHeader::parse(header_bytes)?;
    let offset = volume_header.crypto_header_offset as usize;
    let length = volume_header.crypto_header_length as usize;
    let end = offset
        .checked_add(length)
        .ok_or_else(|| anyhow!(FormatError::InvalidArchive("CryptoHeader range overflow")))?;
    let crypto_header_bytes = bytes.get(offset..end).ok_or_else(|| {
        anyhow!(FormatError::InvalidArchive(
            "volume is too short for CryptoHeader"
        ))
    })?;
    Ok(read_archive_protection_from_headers(header_bytes, crypto_header_bytes)?.kdf_params)
}

fn read_kdf_params_from_volume_path(path: &str) -> Result<KdfParams> {
    Ok(read_archive_protection_from_volume_path(path)?.kdf_params)
}

#[derive(Debug)]
struct ArchiveProtection {
    aead_algo: AeadAlgo,
    kdf_algo: KdfAlgo,
    kdf_params: KdfParams,
}

fn read_archive_protection_from_volume_path(path: &str) -> Result<ArchiveProtection> {
    let mut file = File::open(path).with_context(|| format!("failed to open archive {path}"))?;
    let mut header_bytes = vec![0u8; VOLUME_HEADER_LEN];
    file.read_exact(&mut header_bytes)
        .with_context(|| format!("failed to read VolumeHeader from {path}"))?;
    let volume_header = VolumeHeader::parse(&header_bytes)?;
    let offset = volume_header.crypto_header_offset as u64;
    let length = volume_header.crypto_header_length as usize;
    file.seek(SeekFrom::Start(offset))
        .with_context(|| format!("failed to seek to CryptoHeader in {path}"))?;
    let mut crypto_header_bytes = vec![0u8; length];
    file.read_exact(&mut crypto_header_bytes)
        .with_context(|| format!("failed to read CryptoHeader from {path}"))?;
    read_archive_protection_from_headers(&header_bytes, &crypto_header_bytes)
}

fn read_kdf_params_from_any_volume_path(paths: &[String]) -> Result<KdfParams> {
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
    Err(first_error.unwrap_or_else(|| anyhow!("at least one archive volume is required")))
        .context("failed to read KDF parameters from any archive volume")
}

fn read_archive_protection_from_any_volume_path(paths: &[String]) -> Result<ArchiveProtection> {
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
    Err(first_error.unwrap_or_else(|| anyhow!("at least one archive volume is required")))
        .context("failed to read protection mode from any archive volume")
}

fn read_archive_protection_from_headers(
    header_bytes: &[u8],
    crypto_header_bytes: &[u8],
) -> Result<ArchiveProtection> {
    let volume_header = VolumeHeader::parse(header_bytes)?;
    let fixed_bytes = crypto_header_bytes
        .get(..CRYPTO_HEADER_FIXED_LEN)
        .ok_or_else(|| {
            anyhow!(FormatError::InvalidLength {
                structure: "CryptoHeaderFixed",
                expected: CRYPTO_HEADER_FIXED_LEN,
                actual: crypto_header_bytes.len(),
            })
        })?;
    let fixed = CryptoHeaderFixed::parse(fixed_bytes, volume_header.crypto_header_length)?;
    if fixed.stripe_width != volume_header.stripe_width {
        return Err(anyhow!(FormatError::InvalidArchive(
            "VolumeHeader and CryptoHeader stripe_width differ"
        )));
    }
    let crypto_header =
        CryptoHeader::parse(crypto_header_bytes, volume_header.crypto_header_length)?;
    Ok(ArchiveProtection {
        aead_algo: fixed.aead_algo,
        kdf_algo: fixed.kdf_algo,
        kdf_params: crypto_header.kdf_params,
    })
}

fn parse_size_u32(value: &str, name: &'static str) -> Result<u32> {
    let size = parse_size(value).with_context(|| format!("invalid {name}: {value}"))?;
    u32::try_from(size).with_context(|| format!("{name} exceeds u32"))
}

fn parse_size(value: &str) -> Result<u64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("size is empty");
    }
    let split_at = trimmed
        .find(|ch: char| !ch.is_ascii_digit())
        .unwrap_or(trimmed.len());
    let (digits, suffix) = trimmed.split_at(split_at);
    if digits.is_empty() {
        bail!("invalid size '{value}': missing size digits");
    }
    let number = digits
        .parse::<u64>()
        .with_context(|| format!("invalid size '{trimmed}': bad digit sequence"))?;
    let multiplier = match suffix.to_ascii_lowercase().as_str() {
        "" => 1,
        "k" | "kb" | "kib" => 1024,
        "m" | "mb" | "mib" => 1024 * 1024,
        "g" | "gb" | "gib" => 1024 * 1024 * 1024,
        _ => bail!(
            "invalid size '{trimmed}': unsupported suffix '{suffix}'; supported: K/KB/KiB, M/MB/MiB, G/GB/GiB"
        ),
    };
    number
        .checked_mul(multiplier)
        .ok_or_else(|| anyhow!("size overflow"))
}

fn decode_hex_byte(bytes: &[u8]) -> Result<u8> {
    Ok((decode_hex_nibble(bytes[0])? << 4) | decode_hex_nibble(bytes[1])?)
}

fn decode_hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => bail!("keyfile contains non-hex characters"),
    }
}

fn classify_error(err: &anyhow::Error) -> Diagnostic {
    if err.downcast_ref::<UsageError>().is_some() {
        return Diagnostic {
            label: "invalid-arguments",
            exit_code: EXIT_USAGE,
            action: "check command arguments",
        };
    }
    for cause in err.chain() {
        if let Some(usage) = cause.downcast_ref::<UsageError>() {
            let _ = usage;
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

fn classify_io_error(err: &io::Error) -> Diagnostic {
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

fn classify_format_error(err: &FormatError) -> Diagnostic {
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
                "check argon2 flags (--argon2-t-cost, --argon2-m-cost-kib, --argon2-parallelism)",
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;

    use tzap_core::format::MASTER_KEY_LEN;

    fn test_master_key() -> MasterKey {
        MasterKey::from_raw_key(&[0x42; MASTER_KEY_LEN]).unwrap()
    }

    #[cfg(windows)]
    fn windows_test_tempdir() -> tempfile::TempDir {
        let Some(root) = std::env::var_os("TZAP_WINDOWS_TEST_ROOT") else {
            return tempfile::tempdir().unwrap();
        };
        let root = PathBuf::from(root);
        fs::create_dir_all(&root).unwrap();
        tempfile::Builder::new()
            .prefix("tzap-windows-")
            .tempdir_in(root)
            .unwrap()
    }

    #[cfg(windows)]
    fn create_windows_relative_symlink(path: &Path, target: &str) -> bool {
        use std::os::windows::fs::OpenOptionsExt as _;
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::Foundation::ERROR_PRIVILEGE_NOT_HELD;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
        };
        use windows_sys::Win32::System::Ioctl::FSCTL_SET_REPARSE_POINT;
        use windows_sys::Win32::System::IO::DeviceIoControl;

        fs::write(path, []).unwrap();
        let target = target.encode_utf16().collect::<Vec<_>>();
        let target_bytes = target.len() * 2;
        let mut path_units = target.clone();
        path_units.push(0);
        path_units.extend_from_slice(&target);
        path_units.push(0);
        let payload_len = 12 + path_units.len() * 2;
        let mut reparse = Vec::with_capacity(8 + payload_len);
        reparse.extend_from_slice(&0xA000_000Cu32.to_le_bytes());
        reparse.extend_from_slice(&(payload_len as u16).to_le_bytes());
        reparse.extend_from_slice(&0u16.to_le_bytes());
        reparse.extend_from_slice(&0u16.to_le_bytes());
        reparse.extend_from_slice(&(target_bytes as u16).to_le_bytes());
        reparse.extend_from_slice(&((target_bytes + 2) as u16).to_le_bytes());
        reparse.extend_from_slice(&(target_bytes as u16).to_le_bytes());
        reparse.extend_from_slice(&1u32.to_le_bytes());
        for unit in path_units {
            reparse.extend_from_slice(&unit.to_le_bytes());
        }

        let file = fs::OpenOptions::new()
            .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .unwrap();
        let mut returned = 0u32;
        // SAFETY: the handle and complete relative-symlink reparse buffer remain live for the
        // synchronous call. Creating the fixture this way does not require symlink privilege.
        let result = unsafe {
            DeviceIoControl(
                file.as_raw_handle().cast(),
                FSCTL_SET_REPARSE_POINT,
                reparse.as_ptr().cast(),
                reparse.len() as u32,
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        let error = std::io::Error::last_os_error();
        if result == 0
            && error.raw_os_error().map(|code| code as u32) == Some(ERROR_PRIVILEGE_NOT_HELD)
        {
            return false;
        }
        assert_ne!(result, 0, "{error}");
        true
    }

    fn test_tar_stream(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (path, data) in entries {
            out.extend_from_slice(&test_tar_header(path.as_bytes(), b'0', data.len() as u64));
            out.extend_from_slice(data);
            out.resize(out.len() + test_tar_padding(data.len()), 0);
        }
        out.extend_from_slice(&[0u8; 1024]);
        out
    }

    fn test_tar_header(path: &[u8], kind: u8, size: u64) -> [u8; 512] {
        let mut header = [0u8; 512];
        header[..path.len()].copy_from_slice(path);
        test_tar_octal(&mut header[100..108], 0o644);
        test_tar_octal(&mut header[108..116], 0);
        test_tar_octal(&mut header[116..124], 0);
        test_tar_octal(&mut header[124..136], size);
        test_tar_octal(&mut header[136..148], 0);
        header[148..156].fill(b' ');
        header[156] = kind;
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum = header.iter().map(|byte| *byte as u64).sum::<u64>();
        test_tar_checksum(&mut header[148..156], checksum);
        header
    }

    fn test_tar_octal(field: &mut [u8], value: u64) {
        let digits = format!("{value:o}");
        field.fill(0);
        let start = field.len() - 1 - digits.len();
        field[..start].fill(b'0');
        field[start..start + digits.len()].copy_from_slice(digits.as_bytes());
    }

    fn test_tar_checksum(field: &mut [u8], value: u64) {
        let digits = format!("{value:06o}");
        field[0..6].copy_from_slice(digits.as_bytes());
        field[6] = 0;
        field[7] = b' ';
    }

    fn test_tar_padding(len: usize) -> usize {
        let remainder = len % 512;
        if remainder == 0 {
            0
        } else {
            512 - remainder
        }
    }

    #[test]
    fn create_layout_defaults_scale_by_input_size() {
        assert_eq!(
            default_create_layout(Some(LARGE_CREATE_LAYOUT_THRESHOLD)),
            CreateLayout {
                block_size: 64 * 1024,
                chunk_size: 256 * 1024,
                envelope_target_size: 1024 * 1024,
            }
        );
        assert_eq!(
            default_create_layout(Some(LARGE_CREATE_LAYOUT_THRESHOLD + 1)),
            CreateLayout {
                block_size: 1024 * 1024,
                chunk_size: 32 * 1024 * 1024,
                envelope_target_size: 64 * 1024 * 1024,
            }
        );
        assert_eq!(
            default_create_layout(None),
            default_create_layout(Some(LARGE_CREATE_LAYOUT_THRESHOLD + 1))
        );
    }

    #[test]
    fn create_layout_chunk_override_grows_implicit_envelope() {
        let layout = resolve_create_layout(
            CreateLayoutOverrides {
                chunk_size: Some("4M"),
                envelope_size: None,
                block_size: None,
            },
            Some(1024),
        )
        .unwrap();

        assert_eq!(layout.chunk_size, 4 * 1024 * 1024);
        assert_eq!(layout.envelope_target_size, 4 * 1024 * 1024);
        assert_eq!(layout.block_size, 64 * 1024);
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn create_groups_selected_hardlinks_under_deterministic_canonical_target() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("first.txt");
        let second = temp.path().join("second.txt");
        fs::write(&first, b"shared").unwrap();
        fs::hard_link(&first, &second).unwrap();

        let specs = collect_input_specs(&[
            first.to_string_lossy().into_owned(),
            second.to_string_lossy().into_owned(),
        ])
        .unwrap();

        assert_eq!(specs[0].entry_kind, SourceEntryKind::Regular);
        assert_eq!(specs[1].entry_kind, SourceEntryKind::Hardlink);
        assert_eq!(
            specs[1].link_target.as_deref(),
            Some(b"first.txt".as_slice())
        );
        assert_eq!(specs[1].size, 0);
        assert!(specs[1]
            .portable_metadata
            .native
            .auxiliary_records
            .is_empty());
    }

    #[test]
    fn tar_stdin_signer_failure_removes_temporary_archive_output() {
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("failed.tzap");
        let key = CreateKey {
            master_key: test_master_key(),
            kdf_params: KdfParams::Raw,
        };
        let root_auth = RootAuthWriterConfig {
            authenticator_id: 0x9001,
            signer_identity_type: 0x9002,
            signer_identity: b"test signer",
            authenticator_value_length: 64,
        };
        let mut authenticator = |_request: &RootAuthSigningRequest| {
            Err(FormatError::WriterUnsupported("test signer failed"))
        };
        let mut input = Cursor::new(test_tar_stream(&[("signed.txt", b"signed")]));

        let error = write_tar_stdin_archive_output_from_reader(
            output.to_str().unwrap(),
            &mut input,
            &key,
            WriterOptions {
                stripe_width: 1,
                volume_loss_tolerance: 0,
                bit_rot_buffer_pct: 0,
                ..WriterOptions::default()
            },
            Some(root_auth),
            Some(&mut authenticator),
            false,
        )
        .unwrap_err();

        assert!(error.to_string().contains("test signer failed"));
        assert!(!output.exists());
    }

    #[test]
    fn raw_spool_multi_volume_signer_failure_removes_temporary_archive_outputs_and_spool() {
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("failed-raw-spool.tzap");
        let volume_0 = create_output_paths(output.to_str().unwrap(), 3)[0].clone();
        let volume_1 = create_output_paths(output.to_str().unwrap(), 3)[1].clone();
        let volume_2 = create_output_paths(output.to_str().unwrap(), 3)[2].clone();
        let key = CreateKey {
            master_key: test_master_key(),
            kdf_params: KdfParams::Raw,
        };
        let root_auth = RootAuthWriterConfig {
            authenticator_id: 0x9001,
            signer_identity_type: 0x9002,
            signer_identity: b"test signer",
            authenticator_value_length: 64,
        };
        let mut authenticator = |_request: &RootAuthSigningRequest| {
            Err(FormatError::WriterUnsupported("test signer failed"))
        };
        let payload = (0..150_000)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let spool_path;

        {
            let spool = crate::plaintext_spool::spool_unknown_size_raw_stdin_in(
                Cursor::new(payload),
                temp.path(),
                u64::MAX,
                ExplicitPlaintextSpool::acknowledge_plaintext_spool(),
            )
            .unwrap();
            let known_size_source = spool.known_size_source();
            spool_path = spool.path().to_path_buf();
            let mut spool_reader = spool.reopen().unwrap();

            let error = write_raw_stdin_archive_output_from_reader(
                output.to_str().unwrap(),
                &mut spool_reader,
                "raw/spooled.bin",
                known_size_source.size(),
                &key,
                WriterOptions {
                    stripe_width: 3,
                    volume_loss_tolerance: 0,
                    bit_rot_buffer_pct: 0,
                    ..WriterOptions::default()
                },
                Some(root_auth),
                Some(&mut authenticator),
                false,
            )
            .unwrap_err();

            assert!(error.to_string().contains("test signer failed"));
            assert!(spool_path.exists());
        }

        assert!(!spool_path.exists());
        assert!(!output.exists());
        assert!(!volume_0.exists());
        assert!(!volume_1.exists());
        assert!(!volume_2.exists());
    }

    #[test]
    fn read_kdf_params_rejects_stripe_width_mismatch_before_returning_kdf() {
        let archive = write_archive_with_kdf(
            &[RegularFile::new("file.txt", b"contents")],
            &test_master_key(),
            WriterOptions {
                archive_uuid: Some([0x11; 16]),
                session_id: Some([0x22; 16]),
                bit_rot_buffer_pct: 0,
                ..WriterOptions::default()
            },
            &KdfParams::Argon2id {
                t_cost: 1,
                m_cost_kib: 8,
                parallelism: 1,
                salt: vec![0x33; 8],
            },
        )
        .unwrap();
        let mut bytes = archive.bytes;
        let mut volume_header = VolumeHeader::parse(&bytes[..VOLUME_HEADER_LEN]).unwrap();
        volume_header.stripe_width += 1;
        bytes[..VOLUME_HEADER_LEN].copy_from_slice(&volume_header.to_bytes());

        let err = read_kdf_params_from_volume(&bytes).unwrap_err();

        assert_eq!(
            err.downcast_ref::<FormatError>(),
            Some(&FormatError::InvalidArchive(
                "VolumeHeader and CryptoHeader stripe_width differ"
            ))
        );
    }

    #[test]
    fn unsupported_revision_errors_suggest_reader_upgrade() {
        for err in [
            FormatError::UnsupportedFormatVersion(2),
            FormatError::UnsupportedVolumeFormatRevision {
                format_version: 1,
                volume_format_rev: 44,
                reader_max_supported_revision: READER_MAX_SUPPORTED_VOLUME_FORMAT_REV,
            },
        ] {
            let diagnostic = classify_format_error(&err);

            assert_eq!(diagnostic.label, "unsupported-revision");
            assert_eq!(diagnostic.exit_code, EXIT_UNSUPPORTED_REVISION);
            assert_eq!(
                diagnostic.action,
                "upgrade tzap or use a reader that supports this archive revision"
            );
        }
    }

    #[test]
    fn reporting_unsupported_revision_json_has_observed_supported_action_only() {
        let err = anyhow!(FormatError::UnsupportedVolumeFormatRevision {
            format_version: 1,
            volume_format_rev: VOLUME_FORMAT_REV_45 + 1,
            reader_max_supported_revision: VOLUME_FORMAT_REV_45,
        });

        let payload = unsupported_revision_error_json(
            &err,
            "upgrade tzap or use a reader that supports this archive revision",
        );

        assert_eq!(payload["label"], "unsupported-revision");
        assert_eq!(
            payload["observed"]["format_version"],
            serde_json::json!(FORMAT_VERSION)
        );
        assert_eq!(
            payload["observed"]["volume_format_rev"],
            serde_json::json!(VOLUME_FORMAT_REV_45 + 1)
        );
        assert_eq!(
            payload["supported"]["max_volume_format_rev"],
            serde_json::json!(VOLUME_FORMAT_REV_45)
        );
        assert!(payload.get("root_auth").is_none());
        assert!(payload.get("decryption_keywrap").is_none());
    }

    #[test]
    fn reporting_public_no_key_status_is_metadata_only() {
        let root_auth = VerifiedPublicNoKeyRootAuth::Ed25519(PublicNoKeyVerification {
            format_version: FORMAT_VERSION,
            volume_format_rev: VOLUME_FORMAT_REV_45,
            archive_root: [1; 32],
            authenticator_id: ED25519_AUTHENTICATOR_ID,
            signer_identity_type: 1,
            signer_identity_bytes: [2; 32].to_vec(),
            total_data_block_count: 7,
            diagnostics: vec![
                tzap_core::reader::PublicNoKeyDiagnostic::PublicDataBlockCommitmentVerified,
                tzap_core::reader::PublicNoKeyDiagnostic::PublicPhysicalCompletenessUnverified,
            ],
        });

        let status = public_no_key_status_json(&root_auth);

        assert_eq!(status["revision_mode"], serde_json::json!("v45"));
        assert_eq!(status["decryption_keywrap"], serde_json::json!("not_used"));
        assert_eq!(
            status["trust_policy"],
            serde_json::json!("public_trust_matched")
        );
        assert_eq!(
            status["public_no_key_metadata_only"],
            serde_json::json!("metadata_commitments_verified")
        );
    }

    #[test]
    fn embedded_official_root_fingerprint_matches_certificate() {
        let der = x509_chain::certificate_der_from_pem_or_der(OFFICIAL_TZAP_ROOT_CERT_PEM).unwrap();
        let cert = X509::from_der(&der).unwrap();
        let digest = cert.digest(openssl::hash::MessageDigest::sha256()).unwrap();

        assert_eq!(
            OFFICIAL_TZAP_ROOT_CERT_SHA256,
            format!("sha256:{}", encode_hex(&digest))
        );
    }

    #[test]
    fn bootstrap_required_errors_keep_missing_bootstrap_diagnostic() {
        for err in [
            FormatError::ReaderUnsupported("dictionary bootstrap required"),
            FormatError::ReaderUnsupported(
                "dictionary bootstrap required for non-seekable sequential extraction",
            ),
            FormatError::ReaderUnsupported(
                "non-seekable random access requires a bootstrap sidecar",
            ),
            FormatError::WriterUnsupported("bootstrap sidecar required"),
        ] {
            let diagnostic = classify_format_error(&err);

            assert_eq!(diagnostic.label, "missing-bootstrap");
            assert_eq!(diagnostic.exit_code, EXIT_MISSING_BOOTSTRAP);
            assert_eq!(diagnostic.action, "use --bootstrap with a matching sidecar");
        }
    }

    #[test]
    fn missing_volume_errors_keep_stable_diagnostic() {
        let diagnostic = classify_format_error(&FormatError::InvalidArchive(
            "missing volume count exceeds volume_loss_tolerance",
        ));

        assert_eq!(diagnostic.label, "missing-volume");
        assert_eq!(diagnostic.exit_code, EXIT_CORRUPT_ARCHIVE);
        assert_eq!(
            diagnostic.action,
            "add the missing archive volume(s) or confirm volume-loss tolerance"
        );
    }

    #[test]
    fn metadata_diagnostic_lines_use_stable_cli_warning_prefix() {
        let line = metadata_diagnostic_line(
            "path/in/archive",
            &MetadataDiagnostic {
                path: b"path/in/archive".to_vec(),
                profile: "gnu-sparse".into(),
                metadata_class: "sparse-layout".into(),
                operation: MetadataOperation::Plan,
                status: MetadataDiagnosticStatus::Unsupported,
                message: "unsupported sparse-file PAX metadata was ignored".into(),
                restore_policy: None,
                restore_phase: None,
                native_host_error: None,
                bytes_staged: None,
                bytes_committed: None,
            },
        );

        assert_eq!(
            line,
            "tzap: degraded-metadata: path/in/archive: gnu-sparse: sparse-layout: Plan/Unsupported: unsupported sparse-file PAX metadata was ignored"
        );
    }

    #[test]
    fn selected_metadata_diagnostic_lines_filter_to_requested_paths() {
        let entries = vec![
            ArchiveEntry {
                path: "selected.txt".to_string(),
                file_data_size: 1,
                kind: TarEntryKind::Regular,
                mode: 0o644,
                mtime: ArchiveTimestamp::UNIX_EPOCH,
                diagnostics: vec![MetadataDiagnostic {
                    path: b"selected.txt".to_vec(),
                    profile: "pax-posix-2001".into(),
                    metadata_class: "pax-key".into(),
                    operation: MetadataOperation::Plan,
                    status: MetadataDiagnosticStatus::Unsupported,
                    message: "unsupported PAX key was ignored".into(),
                    restore_policy: None,
                    restore_phase: None,
                    native_host_error: None,
                    bytes_staged: None,
                    bytes_committed: None,
                }],
                link_target: None,
                created: None,
                accessed: None,
                attributes: None,
                uid: None,
                gid: None,
                uname: None,
                gname: None,
            },
            ArchiveEntry {
                path: "other.txt".to_string(),
                file_data_size: 1,
                kind: TarEntryKind::Regular,
                mode: 0o644,
                mtime: ArchiveTimestamp::UNIX_EPOCH,
                diagnostics: vec![MetadataDiagnostic {
                    path: b"other.txt".to_vec(),
                    profile: "gnu-sparse".into(),
                    metadata_class: "sparse-layout".into(),
                    operation: MetadataOperation::Plan,
                    status: MetadataDiagnosticStatus::Unsupported,
                    message: "unsupported sparse-file PAX metadata was ignored".into(),
                    restore_policy: None,
                    restore_phase: None,
                    native_host_error: None,
                    bytes_staged: None,
                    bytes_committed: None,
                }],
                link_target: None,
                created: None,
                accessed: None,
                attributes: None,
                uid: None,
                gid: None,
                uname: None,
                gname: None,
            },
        ];

        assert_eq!(
            metadata_diagnostic_lines_for_paths(&entries, &["selected.txt".to_string()]),
            vec![
                "tzap: degraded-metadata: selected.txt: pax-posix-2001: pax-key: Plan/Unsupported: unsupported PAX key was ignored"
                    .to_string()
            ]
        );
        assert_eq!(metadata_diagnostic_lines_for_entries(&entries).len(), 2);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn filesystem_scan_captures_linux_native_profile_and_user_xattr() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("native.txt");
        fs::write(&path, b"payload").unwrap();
        xattr::set(&path, "user.tzap-test", b"metadata").unwrap();
        let identity = input_identity(&fs::metadata(&path).unwrap()).unwrap();

        let native = capture_native_file_metadata(&path, identity).unwrap();
        let shared = tzap_core::macos_metadata::capture_macos_metadata(&path, false).unwrap();
        assert_eq!(
            shared.native, native,
            "CLI and reusable TZAP metadata capture must remain identical"
        );

        assert_eq!(
            native.required_profiles,
            vec!["linux-backup-v1", "posix-backup-v1"]
        );
        assert_eq!(
            native
                .primary_pax_records
                .get("LIBARCHIVE.xattr.user.tzap-test")
                .map(Vec::as_slice),
            Some(b"bWV0YWRhdGE".as_slice())
        );
        assert!(native
            .primary_pax_records
            .contains_key("TZAP.linux.fsflags"));
        assert!(native
            .primary_pax_records
            .contains_key("TZAP.unix.ctime-observed"));
        if identity.creation_time.is_some() {
            assert!(native
                .primary_pax_records
                .contains_key("LIBARCHIVE.creationtime"));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn filesystem_scan_and_restore_preserve_linux_fifo() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::fs::FileTypeExt as _;

        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("events.fifo");
        let source_c = CString::new(source.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(source_c.as_ptr(), 0o640) }, 0);
        let acl = [
            2, 0, 0, 0, // POSIX ACL xattr version
            1, 0, 6, 0, 0xff, 0xff, 0xff, 0xff, // owning user
            2, 0, 6, 0, 0x39, 0x30, 0, 0, // named user 12345
            4, 0, 4, 0, 0xff, 0xff, 0xff, 0xff, // owning group
            0x10, 0, 6, 0, 0xff, 0xff, 0xff, 0xff, // mask
            0x20, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, // other
        ];
        xattr::set(&source, "system.posix_acl_access", &acl).unwrap();
        let expected_acl = xattr::get(&source, "system.posix_acl_access")
            .unwrap()
            .unwrap();

        let specs = collect_input_specs(&[source.to_string_lossy().into_owned()]).unwrap();
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].entry_kind, SourceEntryKind::Fifo);
        assert_eq!(specs[0].size, 0);
        assert!(specs[0]
            .portable_metadata
            .native
            .primary_pax_records
            .contains_key("SCHILY.acl.access"));

        let key = MasterKey::from_raw_key(&[41u8; 32]).unwrap();
        let mut sink = MemoryArchiveSink::default();
        write_archive_sources_to_sink_ordered_parallel(
            &specs,
            &key,
            WriterOptions {
                stripe_width: 1,
                volume_loss_tolerance: 0,
                bit_rot_buffer_pct: 0,
                ..WriterOptions::default()
            },
            &KdfParams::Raw,
            None,
            None,
            &mut sink,
        )
        .unwrap();
        let opened = tzap_core::open_archive(&sink.volumes[0], &key).unwrap();
        opened.verify().unwrap();
        let output = temp.path().join("fifo-output");
        fs::create_dir(&output).unwrap();
        opened
            .extract_all_to(
                &output,
                SafeExtractionOptions {
                    restore_policy: RestorePolicy::System,
                    system_authorized: true,
                    // Linux exposes birth time on some filesystems but has no general API to
                    // restore it, so the unrelated FIFO recreation proceeds explicitly degraded.
                    allow_degraded: true,
                    ..SafeExtractionOptions::default()
                },
            )
            .unwrap();
        let restored = fs::symlink_metadata(output.join("events.fifo")).unwrap();
        assert!(restored.file_type().is_fifo());
        assert_eq!(readonly_mode(&restored) & 0o777, 0o660);
        assert_eq!(
            xattr::get(output.join("events.fifo"), "system.posix_acl_access")
                .unwrap()
                .unwrap(),
            expected_acl
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_project_id_capture_treats_missing_ioctl_as_unavailable() {
        for code in [libc::ENOTTY, libc::EOPNOTSUPP, libc::EINVAL, libc::ENOSYS] {
            assert!(linux_project_id_ioctl_unavailable(
                &io::Error::from_raw_os_error(code)
            ));
        }
        assert!(!linux_project_id_ioctl_unavailable(
            &io::Error::from_raw_os_error(libc::EIO)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn filesystem_scan_discovers_linux_sparse_extents() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("sparse.bin");
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&source)
            .unwrap();
        let logical_size = 512 * 1024u64;
        file.set_len(logical_size).unwrap();
        file.seek(SeekFrom::Start(64 * 1024)).unwrap();
        file.write_all(b"first extent").unwrap();
        file.seek(SeekFrom::Start(384 * 1024)).unwrap();
        file.write_all(b"last extent").unwrap();
        file.flush().unwrap();

        let specs = collect_input_specs(&[source.to_string_lossy().into_owned()]).unwrap();
        let extents = specs[0]
            .sparse_extents
            .as_ref()
            .expect("filesystem should expose SEEK_DATA/SEEK_HOLE");
        assert!(!extents.is_empty());
        assert!(extents.iter().map(|extent| extent.length).sum::<u64>() < logical_size);

        let key = MasterKey::from_raw_key(&[42u8; 32]).unwrap();
        let mut sink = MemoryArchiveSink::default();
        write_archive_sources_to_sink_ordered_parallel(
            &specs,
            &key,
            WriterOptions {
                stripe_width: 1,
                volume_loss_tolerance: 0,
                bit_rot_buffer_pct: 0,
                ..WriterOptions::default()
            },
            &KdfParams::Raw,
            None,
            None,
            &mut sink,
        )
        .unwrap();
        let opened = tzap_core::open_archive(&sink.volumes[0], &key).unwrap();
        let indexed = opened.lookup_index_entry("sparse.bin").unwrap().unwrap();
        assert_ne!(
            indexed.flags & (1 << 3),
            0,
            "archive index lost sparse metadata"
        );
        let output = temp.path().join("sparse-output");
        fs::create_dir(&output).unwrap();
        opened
            .extract_all_to(
                &output,
                SafeExtractionOptions {
                    restore_policy: RestorePolicy::SameOs,
                    // Linux exposes birth time but has no general API to assign it.
                    allow_degraded: true,
                    ..SafeExtractionOptions::default()
                },
            )
            .unwrap();
        let restored_path = output.join("sparse.bin");
        let restored = File::open(&restored_path).unwrap();
        assert_eq!(restored.metadata().unwrap().len(), logical_size);
        let restored_extents = query_linux_sparse_extents(&restored, logical_size).unwrap();
        use std::os::unix::fs::MetadataExt as _;
        assert!(
            restored_extents.is_some(),
            "restored output should remain sparse; source extents={extents:?}, blocks={}",
            restored.metadata().unwrap().blocks()
        );
        let restored_extents = restored_extents.unwrap();
        assert!(
            restored_extents
                .iter()
                .map(|extent| extent.length)
                .sum::<u64>()
                < logical_size
        );
        let bytes = fs::read(restored_path).unwrap();
        assert_eq!(&bytes[64 * 1024..64 * 1024 + 12], b"first extent");
        assert_eq!(&bytes[384 * 1024..384 * 1024 + 11], b"last extent");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn filesystem_scan_captures_macos_native_metadata_and_writes_valid_archive() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("native.txt");
        fs::write(&path, b"payload").unwrap();
        xattr::set(&path, "com.tzap.test", b"metadata").unwrap();
        xattr::set(&path, "com.apple.FinderInfo", &[0x5a; 32]).unwrap();
        xattr::set(&path, "com.apple.ResourceFork", b"resource fork").unwrap();
        let acl_status = std::process::Command::new("chmod")
            .arg("+a")
            .arg("everyone deny delete")
            .arg(&path)
            .status()
            .unwrap();
        assert!(acl_status.success());
        let identity = input_identity(&fs::metadata(&path).unwrap()).unwrap();

        let native = capture_native_file_metadata(&path, identity).unwrap();

        assert_eq!(
            native.required_profiles,
            vec!["macos-backup-v1", "posix-backup-v1"]
        );
        assert_eq!(
            native
                .primary_pax_records
                .get("LIBARCHIVE.xattr.com.tzap.test")
                .map(Vec::as_slice),
            Some(b"bWV0YWRhdGE".as_slice())
        );
        for key in [
            "LIBARCHIVE.creationtime",
            "TZAP.unix.ctime-observed",
            "TZAP.macos.st-flags",
            "TZAP.acl.projection",
        ] {
            assert!(native.primary_pax_records.contains_key(key), "{key}");
        }
        let finder_info = native
            .auxiliary_records
            .iter()
            .find(|record| record.kind == "macos.finder-info")
            .unwrap();
        assert_eq!(finder_info.payload, [0x5a; 32]);
        let resource_fork = native
            .auxiliary_records
            .iter()
            .find(|record| record.kind == "macos.resource-fork")
            .unwrap();
        assert!(resource_fork.is_streamed());
        assert!(resource_fork.payload.is_empty());
        assert_eq!(resource_fork.logical_size, b"resource fork".len() as u64);
        let acl = native
            .auxiliary_records
            .iter()
            .find(|record| record.kind == "macos.acl-native")
            .unwrap();
        assert!(!acl.payload.is_empty());
        assert_eq!(
            acl.meta.get("TZAP.aux.meta.acl-format").map(Vec::as_slice),
            Some(b"darwin-acl-external-v1".as_slice())
        );

        // `RegularFile` is the convenience in-memory source and cannot reopen a streamed
        // filesystem fork. Keep this parser/writer assertion independent from the InputSpec
        // streaming integration test by substituting the same bytes as an in-memory record.
        let mut archive_native = native.clone();
        let resource_index = archive_native
            .auxiliary_records
            .iter()
            .position(|record| record.kind == "macos.resource-fork")
            .unwrap();
        archive_native.auxiliary_records[resource_index] = NativeAuxiliaryMetadata::new(
            "macos.resource-fork",
            "macos-backup-v1",
            RestoreClass::SameOs,
            b"resource fork".to_vec(),
        );

        let archive = write_archive(
            &[RegularFile {
                path: "native.txt",
                contents: b"payload",
                mode: identity.mode,
                mtime: identity.mtime,
                portable_metadata: PortableFileMetadata {
                    source_os: "macos".into(),
                    source_filesystem: "unknown".into(),
                    mode_origin: PortableModeOrigin::Native,
                    posix_owner: Some(PortablePosixOwner {
                        uid: identity.uid,
                        gid: identity.gid,
                        uname: None,
                        gname: None,
                    }),
                    attributes: None,
                    created: None,
                    accessed: None,
                    native: archive_native,
                },
            }],
            &MasterKey::from_raw_key(&[7u8; 32]).unwrap(),
            WriterOptions {
                stripe_width: 1,
                volume_loss_tolerance: 0,
                bit_rot_buffer_pct: 0,
                ..WriterOptions::default()
            },
        )
        .unwrap();
        let opened = tzap_core::open_archive(
            &archive.bytes,
            &MasterKey::from_raw_key(&[7u8; 32]).unwrap(),
        )
        .unwrap();
        opened.verify().unwrap();
        let verification = opened.verify_content().unwrap();
        let report = verification.metadata_report().unwrap();
        assert_eq!(
            report.profiles_present,
            vec!["macos-backup-v1", "portable-v1", "posix-backup-v1"]
        );
        assert!(report
            .auxiliary_kinds_present
            .contains(&"macos.acl-native".to_string()));
        assert!(report
            .auxiliary_kinds_present
            .contains(&"macos.finder-info".to_string()));
        assert!(report
            .auxiliary_kinds_present
            .contains(&"macos.resource-fork".to_string()));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_metadata_capture_rejects_a_replaced_source_object() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("source.txt");
        let displaced = temp.path().join("displaced.txt");
        fs::write(&path, b"original").unwrap();
        let identity = input_identity(&fs::metadata(&path).unwrap()).unwrap();
        fs::rename(&path, &displaced).unwrap();
        fs::write(&path, b"replacement").unwrap();

        let error = capture_native_file_metadata(&path, identity).unwrap_err();
        assert!(error
            .to_string()
            .contains("changed before metadata capture"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_symlink_capture_rejects_a_replaced_link_object() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("source-link");
        let displaced = temp.path().join("displaced-link");
        symlink("original-target", &path).unwrap();
        let identity = input_identity(&fs::symlink_metadata(&path).unwrap()).unwrap();
        fs::rename(&path, &displaced).unwrap();
        symlink("replacement-target", &path).unwrap();

        let error = capture_macos_symlink_metadata(&path, identity).unwrap_err();
        assert!(error
            .to_string()
            .contains("changed before metadata capture"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_capture_rejects_metadata_classes_that_are_not_exactly_supported() {
        use std::os::windows::ffi::OsStrExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            GetFileAttributesW, SetFileAttributesW, FILE_ATTRIBUTE_OFFLINE,
        };

        for attributes in [0x0000_0400, 0x0000_1000] {
            assert!(unsupported_windows_file_attribute_reason(attributes).is_some());
        }
        assert_eq!(unsupported_windows_file_attribute_reason(0x0000_4000), None);
        assert_eq!(unsupported_windows_file_attribute_reason(0x0000_0200), None);
        assert_eq!(unsupported_windows_file_attribute_reason(0x20), None);

        let temp = windows_test_tempdir();
        let offline = temp.path().join("offline-placeholder.bin");
        fs::write(&offline, b"must not be read").unwrap();
        let wide = offline
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        // SAFETY: the path is NUL-terminated and remains live for both calls.
        let original = unsafe { GetFileAttributesW(wide.as_ptr()) };
        assert_ne!(original, u32::MAX);
        // SAFETY: as above; OFFLINE is a settable attribute on this ordinary fixture.
        assert_ne!(
            unsafe { SetFileAttributesW(wide.as_ptr(), original | FILE_ATTRIBUTE_OFFLINE) },
            0
        );
        let error = collect_input_specs(&[offline.to_string_lossy().into_owned()]).unwrap_err();
        assert!(format!("{error:#}").contains("explicit hydration policy"));
        // SAFETY: restore the original attributes so temporary-directory cleanup is ordinary.
        assert_ne!(unsafe { SetFileAttributesW(wide.as_ptr(), original) }, 0);
    }

    #[test]
    fn archive_timestamp_canonicalizes_fractional_pre_epoch_times() {
        assert_eq!(
            archive_timestamp(UNIX_EPOCH - Duration::new(0, 100)).unwrap(),
            ArchiveTimestamp::new(-1, 999_999_900)
        );
        assert_eq!(
            archive_timestamp(UNIX_EPOCH - Duration::new(1, 500_000_000)).unwrap(),
            ArchiveTimestamp::new(-2, 500_000_000)
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_filetime_conversion_preserves_100ns_precision() {
        const UNIX_EPOCH_FILETIME: u64 = 116_444_736_000_000_000;
        assert_eq!(
            windows_filetime_timestamp(UNIX_EPOCH_FILETIME + 12_345_678).unwrap(),
            ArchiveTimestamp::new(1, 234_567_800)
        );
        assert_eq!(
            windows_filetime_timestamp(UNIX_EPOCH_FILETIME - 1).unwrap(),
            ArchiveTimestamp::new(-1, 999_999_900)
        );
        assert_eq!(
            windows_filetime_timestamp(0).unwrap(),
            ArchiveTimestamp::new(-11_644_473_600, 0)
        );
    }

    #[cfg(windows)]
    #[test]
    fn filesystem_scan_captures_windows_scalars_security_and_alternate_data() {
        use std::os::windows::ffi::OsStrExt as _;
        use std::ptr;
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows_sys::Win32::Security::{
            SetFileSecurityW, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
            PROTECTED_SACL_SECURITY_INFORMATION, SACL_SECURITY_INFORMATION, SE_RESTORE_NAME,
        };

        let temp = windows_test_tempdir();
        let path = temp.path().join("native.txt");
        fs::write(&path, b"payload").unwrap();
        let sacl_available = windows_sacl_capture_enabled();
        let sddl = if sacl_available {
            "D:P(A;;FA;;;SY)(A;;FA;;;BA)S:P(AU;SAFA;FW;;;WD)"
        } else {
            "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
        }
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
        let mut descriptor = ptr::null_mut();
        // SAFETY: the SDDL is NUL-terminated and the descriptor output is released with LocalFree.
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    ptr::null_mut(),
                )
            },
            0
        );
        let path_wide = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        // SAFETY: the path and descriptor remain live and valid for the call.
        let security_information = DACL_SECURITY_INFORMATION
            | PROTECTED_DACL_SECURITY_INFORMATION
            | if sacl_available {
                SACL_SECURITY_INFORMATION | PROTECTED_SACL_SECURITY_INFORMATION
            } else {
                0
            };
        let set_security_ok = if sacl_available {
            // SAFETY: the path and descriptor remain live and valid for the call.
            unsafe { SetFileSecurityW(path_wide.as_ptr(), security_information, descriptor) }
        } else {
            // A filtered administrator token cannot restore this fixture DACL: replacing the
            // inherited descriptor with its SYSTEM/Administrators-only DACL would revoke this
            // test process's access before the ADS fixtures are created. The ordinary descriptor
            // still exercises owner/group/DACL capture in that environment.
            1
        };
        let set_security_error = std::io::Error::last_os_error();
        // SAFETY: the descriptor was allocated by the conversion API and is freed once.
        assert!(unsafe { LocalFree(descriptor) }.is_null());
        if sacl_available {
            assert_ne!(set_security_ok, 0, "{set_security_error}");
        }
        let alternate_path = PathBuf::from(format!("{}:tzap-test", path.display()));
        fs::write(&alternate_path, b"alternate metadata").unwrap();
        let unicode_alternate_path = PathBuf::from(format!("{}:元数据", path.display()));
        fs::write(&unicode_alternate_path, b"unicode alternate metadata").unwrap();
        let metadata = fs::metadata(&path).unwrap();
        let mut identity = input_identity(&metadata).unwrap();
        let file = File::open(&path).unwrap();
        augment_windows_input_identity(&mut identity, &file).unwrap();

        let native = capture_native_file_metadata(&path, identity).unwrap();

        assert_eq!(native.required_profiles, vec!["windows-backup-v1"]);
        for key in [
            "atime",
            "LIBARCHIVE.creationtime",
            "TZAP.windows.change-time",
            "TZAP.windows.file-attributes",
            "TZAP.windows.data-stream-attributes",
        ] {
            assert!(native.primary_pax_records.contains_key(key), "{key}");
        }
        let security = native
            .auxiliary_records
            .iter()
            .find(|record| record.kind == "windows.security-descriptor")
            .unwrap();
        let security_mask = u32::from_str_radix(
            std::str::from_utf8(&security.meta["TZAP.aux.meta.security-information"]).unwrap(),
            16,
        )
        .unwrap();
        assert_eq!(security_mask & 0xf, if sacl_available { 0xf } else { 0x7 });
        assert_eq!(security_mask & !0xf000_000f, 0);
        let security_control = u16::from_le_bytes([security.payload[2], security.payload[3]]);
        assert_eq!(
            security_mask & 0xa000_0000,
            if security_control & 0x1000 != 0 {
                0x8000_0000
            } else {
                0x2000_0000
            }
        );
        assert_eq!(
            security_mask & 0x5000_0000,
            if security_control & 0x0010 == 0 {
                0
            } else if security_control & 0x2000 != 0 {
                0x4000_0000
            } else {
                0x1000_0000
            }
        );
        let alternate = native
            .auxiliary_records
            .iter()
            .find(|record| {
                record.kind == "windows.alternate-data"
                    && record.name
                        == ":tzap-test:$DATA"
                            .encode_utf16()
                            .flat_map(u16::to_le_bytes)
                            .collect::<Vec<_>>()
            })
            .unwrap();
        assert!(alternate.payload.is_empty());
        assert!(alternate.is_streamed());
        assert_eq!(
            alternate.stored_payload_size(),
            b"alternate metadata".len() as u64
        );
        assert_eq!(
            alternate.name,
            ":tzap-test:$DATA"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>()
        );

        let specs = collect_input_specs(&[path.to_string_lossy().into_owned()])
            .unwrap_or_else(|error| panic!("{error:#}"));
        let mut checked_reader = specs[0].open().unwrap();
        let mut checked_payload = Vec::new();
        checked_reader.read_to_end(&mut checked_payload).unwrap();
        assert_eq!(checked_payload, b"payload");

        let master_key = MasterKey::from_raw_key(&[7u8; 32]).unwrap();
        let mut sink = MemoryArchiveSink::default();
        write_archive_sources_to_sink_ordered_parallel(
            &specs,
            &master_key,
            WriterOptions {
                stripe_width: 1,
                volume_loss_tolerance: 0,
                bit_rot_buffer_pct: 0,
                ..WriterOptions::default()
            },
            &KdfParams::Raw,
            None,
            None,
            &mut sink,
        )
        .unwrap();
        let opened = tzap_core::open_archive(&sink.volumes[0], &master_key).unwrap();
        opened.verify().unwrap();
        let output = temp.path().join("native-output");
        fs::create_dir(&output).unwrap();
        let restore_report = opened
            .extract_all_to(
                &output,
                SafeExtractionOptions {
                    restore_policy: RestorePolicy::SameOs,
                    ..SafeExtractionOptions::default()
                },
            )
            .unwrap();
        assert_eq!(fs::read(output.join("native.txt")).unwrap(), b"payload");
        assert_eq!(
            fs::read(PathBuf::from(format!(
                "{}:tzap-test",
                output.join("native.txt").display()
            )))
            .unwrap_or_else(|error| panic!("{error}; report={restore_report:#?}")),
            b"alternate metadata"
        );
        assert_eq!(
            fs::read(PathBuf::from(format!(
                "{}:元数据",
                output.join("native.txt").display()
            )))
            .unwrap(),
            b"unicode alternate metadata"
        );

        if !enable_windows_privilege(SE_RESTORE_NAME) {
            return;
        }

        let system_output = temp.path().join("native-system-output");
        fs::create_dir(&system_output).unwrap();
        opened
            .extract_all_to(
                &system_output,
                SafeExtractionOptions {
                    restore_policy: RestorePolicy::System,
                    system_authorized: true,
                    ..SafeExtractionOptions::default()
                },
            )
            .unwrap();
        let restored_file = File::open(system_output.join("native.txt")).unwrap();
        let restored_security = capture_windows_security_descriptor(&restored_file).unwrap();
        let expected_security = specs[0]
            .portable_metadata
            .native
            .auxiliary_records
            .iter()
            .find(|record| record.kind == "windows.security-descriptor")
            .unwrap();
        assert_eq!(restored_security.payload, expected_security.payload);
        assert_eq!(restored_security.meta, expected_security.meta);
    }

    #[cfg(windows)]
    #[test]
    fn windows_ea_backup_stream_round_trips_exactly() {
        fn write_backup_stream(file: &File, stream_id: u32, payload: &[u8]) -> io::Result<()> {
            use std::os::windows::io::AsRawHandle;
            use std::ptr;
            use windows_sys::Win32::Storage::FileSystem::BackupWrite;

            let mut bytes = Vec::with_capacity(20 + payload.len());
            bytes.extend_from_slice(&stream_id.to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&(payload.len() as i64).to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(payload);
            let mut context = ptr::null_mut();
            let result = (|| {
                let mut cursor = bytes.as_slice();
                while !cursor.is_empty() {
                    let mut written = 0u32;
                    // SAFETY: the file, context, and remaining input bytes live for this
                    // synchronous BackupWrite call.
                    if unsafe {
                        BackupWrite(
                            file.as_raw_handle().cast(),
                            cursor.as_ptr(),
                            cursor.len() as u32,
                            &mut written,
                            0,
                            0,
                            &mut context,
                        )
                    } == 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                    if written == 0 || written as usize > cursor.len() {
                        return Err(io::Error::other("BackupWrite made no progress"));
                    }
                    cursor = &cursor[written as usize..];
                }
                Ok(())
            })();
            let mut ignored = 0u32;
            // SAFETY: aborting with an empty buffer releases this context once.
            unsafe {
                BackupWrite(
                    file.as_raw_handle().cast(),
                    ptr::null(),
                    0,
                    &mut ignored,
                    1,
                    0,
                    &mut context,
                );
            }
            result
        }

        let temp = windows_test_tempdir();
        let source = temp.path().join("ea-source.bin");
        fs::write(&source, b"payload").unwrap();
        let source_file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&source)
            .unwrap();
        let ea_name = b"TZAP";
        let ea_value = b"exact-ea-value";
        let mut ea = Vec::new();
        ea.extend_from_slice(&0u32.to_le_bytes());
        ea.push(0);
        ea.push(ea_name.len() as u8);
        ea.extend_from_slice(&(ea_value.len() as u16).to_le_bytes());
        ea.extend_from_slice(ea_name);
        ea.push(0);
        ea.extend_from_slice(ea_value);
        write_backup_stream(&source_file, 2, &ea).unwrap();
        drop(source_file);

        let specs = collect_input_specs(&[source.to_string_lossy().into_owned()]).unwrap();
        let captured = specs[0]
            .portable_metadata
            .native
            .auxiliary_records
            .iter()
            .find(|record| record.kind == "windows.ea-data")
            .expect("EA backup stream was not captured");
        assert_eq!(captured.payload, ea);

        let master_key = MasterKey::from_raw_key(&[25u8; 32]).unwrap();
        let mut sink = MemoryArchiveSink::default();
        write_archive_sources_to_sink(
            &specs,
            &master_key,
            WriterOptions {
                stripe_width: 1,
                volume_loss_tolerance: 0,
                bit_rot_buffer_pct: 0,
                ..WriterOptions::default()
            },
            None,
            &KdfParams::Raw,
            None,
            None,
            &mut sink,
        )
        .unwrap();
        let opened = tzap_core::open_archive(&sink.volumes[0], &master_key).unwrap();
        opened.verify().unwrap();
        let output = temp.path().join("ea-output");
        fs::create_dir(&output).unwrap();
        opened
            .extract_all_to(
                &output,
                SafeExtractionOptions {
                    restore_policy: RestorePolicy::SameOs,
                    ..SafeExtractionOptions::default()
                },
            )
            .unwrap();
        let restored = output.join("ea-source.bin");
        let restored_specs =
            collect_input_specs(&[restored.to_string_lossy().into_owned()]).unwrap();
        let restored_ea = restored_specs[0]
            .portable_metadata
            .native
            .auxiliary_records
            .iter()
            .find(|record| record.kind == "windows.ea-data")
            .expect("restored EA backup stream was not captured");
        assert_eq!(restored_ea.payload, ea);
    }

    #[cfg(windows)]
    #[test]
    fn windows_object_id_backup_stream_round_trips_exactly() {
        use std::mem::size_of;
        use std::os::windows::io::AsRawHandle;
        use std::ptr;
        use windows_sys::Win32::System::Ioctl::{
            FILE_OBJECTID_BUFFER, FSCTL_CREATE_OR_GET_OBJECT_ID,
        };
        use windows_sys::Win32::System::IO::DeviceIoControl;

        let temp = windows_test_tempdir();
        let source = temp.path().join("object-id-source.bin");
        fs::write(&source, b"payload").unwrap();
        let source_file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&source)
            .unwrap();
        let mut object_id = FILE_OBJECTID_BUFFER::default();
        let mut returned = 0u32;
        // SAFETY: the live file handle and fixed output structure remain valid for the call.
        if unsafe {
            DeviceIoControl(
                source_file.as_raw_handle().cast(),
                FSCTL_CREATE_OR_GET_OBJECT_ID,
                ptr::null(),
                0,
                (&mut object_id as *mut FILE_OBJECTID_BUFFER).cast(),
                size_of::<FILE_OBJECTID_BUFFER>() as u32,
                &mut returned,
                ptr::null_mut(),
            )
        } == 0
        {
            // Object IDs are not exposed by every Windows filesystem configuration.
            return;
        }
        assert_eq!(returned as usize, size_of::<FILE_OBJECTID_BUFFER>());
        drop(source_file);

        let specs = collect_input_specs(&[source.to_string_lossy().into_owned()]).unwrap();
        let captured = specs[0]
            .portable_metadata
            .native
            .auxiliary_records
            .iter()
            .find(|record| record.kind == "windows.object-id")
            .expect("object-ID backup stream was not captured")
            .payload
            .clone();
        let master_key = MasterKey::from_raw_key(&[26u8; 32]).unwrap();
        let mut sink = MemoryArchiveSink::default();
        write_archive_sources_to_sink(
            &specs,
            &master_key,
            WriterOptions {
                stripe_width: 1,
                volume_loss_tolerance: 0,
                bit_rot_buffer_pct: 0,
                ..WriterOptions::default()
            },
            None,
            &KdfParams::Raw,
            None,
            None,
            &mut sink,
        )
        .unwrap();
        let opened = tzap_core::open_archive(&sink.volumes[0], &master_key).unwrap();
        opened.verify().unwrap();
        if !enable_windows_privilege(windows_sys::Win32::Security::SE_RESTORE_NAME) {
            return;
        }
        // Object IDs are volume-unique. Remove the source before restoring its exact ID on the
        // same volume so the filesystem can accept the archived identity.
        fs::remove_file(&source).unwrap();
        let output = temp.path().join("object-id-output");
        fs::create_dir(&output).unwrap();
        let diagnostics = opened
            .extract_all_to(
                &output,
                SafeExtractionOptions {
                    restore_policy: RestorePolicy::System,
                    system_authorized: true,
                    allow_degraded: true,
                    ..SafeExtractionOptions::default()
                },
            )
            .unwrap();
        assert!(
            !diagnostics
                .iter()
                .flat_map(|(_, diagnostics)| diagnostics)
                .any(|diagnostic| {
                    diagnostic.metadata_class == "windows.object-id"
                        && diagnostic.status == MetadataDiagnosticStatus::Failed
                }),
            "object-ID restoration degraded: {diagnostics:#?}"
        );
        let restored = output.join("object-id-source.bin");
        let restored_specs =
            collect_input_specs(&[restored.to_string_lossy().into_owned()]).unwrap();
        let restored_object_id = restored_specs[0]
            .portable_metadata
            .native
            .auxiliary_records
            .iter()
            .find(|record| record.kind == "windows.object-id")
            .expect("restored object-ID backup stream was not captured");
        assert_eq!(restored_object_id.payload, captured);
    }

    #[cfg(windows)]
    #[test]
    fn windows_raw_efs_round_trips_without_plaintext_substitution() {
        use std::os::windows::ffi::OsStrExt as _;
        use std::os::windows::fs::MetadataExt as _;
        use windows_sys::Win32::Foundation::{ERROR_FILE_SYSTEM_LIMITATION, ERROR_NOT_SUPPORTED};
        use windows_sys::Win32::Storage::FileSystem::EncryptFileW;

        const FILE_ATTRIBUTE_ENCRYPTED: u32 = 0x0000_4000;
        let temp = windows_test_tempdir();
        let source = temp.path().join("encrypted.txt");
        let plaintext = b"raw EFS must be archived and restored through the native callback APIs";
        fs::write(&source, plaintext).unwrap();
        let alternate_plaintext = b"encrypted alternate stream";
        fs::write(
            PathBuf::from(format!("{}:efs-alternate", source.display())),
            alternate_plaintext,
        )
        .unwrap();
        let source_wide = source
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        // SAFETY: the path is NUL-terminated and remains live for the synchronous call.
        if unsafe { EncryptFileW(source_wide.as_ptr()) } == 0 {
            let error = std::io::Error::last_os_error();
            if matches!(
                error.raw_os_error().map(|value| value as u32),
                Some(code) if code == ERROR_NOT_SUPPORTED || code == ERROR_FILE_SYSTEM_LIMITATION
            ) {
                return;
            }
            panic!("failed to create raw EFS fixture: {error}");
        }
        assert_ne!(
            fs::metadata(&source).unwrap().file_attributes() & FILE_ATTRIBUTE_ENCRYPTED,
            0
        );

        let specs = collect_input_specs(&[source.to_string_lossy().into_owned()])
            .unwrap_or_else(|error| panic!("{error:#}"));
        let raw = specs[0]
            .portable_metadata
            .native
            .auxiliary_records
            .iter()
            .find(|record| record.kind == "windows.efs-raw")
            .expect("encrypted input must retain a raw EFS record");
        assert!(raw.is_streamed());
        assert_eq!(raw.meta["TZAP.aux.meta.efs-version"], b"1");
        let (expected_raw_size, expected_raw_hash) = hash_windows_raw_efs(&source).unwrap();
        assert_eq!(raw.stored_payload_size(), expected_raw_size);

        let master_key = MasterKey::from_raw_key(&[19u8; 32]).unwrap();
        let mut sink = MemoryArchiveSink::default();
        write_archive_sources_to_sink_ordered_parallel(
            &specs,
            &master_key,
            WriterOptions {
                stripe_width: 1,
                volume_loss_tolerance: 0,
                bit_rot_buffer_pct: 0,
                ..WriterOptions::default()
            },
            &KdfParams::Raw,
            None,
            None,
            &mut sink,
        )
        .unwrap();
        let opened = tzap_core::open_archive(&sink.volumes[0], &master_key).unwrap();
        opened.verify().unwrap();
        let output = temp.path().join("efs-output");
        fs::create_dir(&output).unwrap();
        opened
            .extract_all_to(
                &output,
                SafeExtractionOptions {
                    restore_policy: RestorePolicy::System,
                    system_authorized: true,
                    allow_degraded: true,
                    ..SafeExtractionOptions::default()
                },
            )
            .unwrap();

        let restored = output.join("encrypted.txt");
        assert_eq!(fs::read(&restored).unwrap(), plaintext);
        assert_eq!(
            fs::read(PathBuf::from(format!(
                "{}:efs-alternate",
                restored.display()
            )))
            .unwrap(),
            alternate_plaintext
        );
        assert_ne!(
            fs::metadata(&restored).unwrap().file_attributes() & FILE_ATTRIBUTE_ENCRYPTED,
            0
        );
        assert_eq!(
            hash_windows_raw_efs(&restored).unwrap(),
            (expected_raw_size, expected_raw_hash)
        );

        let encrypted_directory = temp.path().join("encrypted-directory");
        fs::create_dir(&encrypted_directory).unwrap();
        let directory_wide = encrypted_directory
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        // SAFETY: the directory path is NUL-terminated and remains live for the call.
        assert_ne!(unsafe { EncryptFileW(directory_wide.as_ptr()) }, 0);
        let error =
            collect_input_specs(&[encrypted_directory.to_string_lossy().into_owned()]).unwrap_err();
        assert!(format!("{error:#}").contains("CREATE_FOR_DIR"));
    }

    #[cfg(windows)]
    #[test]
    fn standalone_windows_directory_alternate_data_round_trips() {
        let temp = windows_test_tempdir();
        let source = temp.path().join("native-directory");
        fs::create_dir(&source).unwrap();
        fs::write(
            PathBuf::from(format!("{}:tzap-directory", source.display())),
            b"directory alternate metadata",
        )
        .unwrap();

        let specs = collect_input_specs(&[source.to_string_lossy().into_owned()])
            .unwrap_or_else(|error| panic!("{error:#}"));
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].entry_kind, SourceEntryKind::Directory);
        assert!(specs[0]
            .portable_metadata
            .native
            .auxiliary_records
            .iter()
            .any(|record| record.kind == "windows.alternate-data"));

        let master_key = MasterKey::from_raw_key(&[11u8; 32]).unwrap();
        let mut sink = MemoryArchiveSink::default();
        write_archive_sources_to_sink_ordered_parallel(
            &specs,
            &master_key,
            WriterOptions {
                stripe_width: 1,
                volume_loss_tolerance: 0,
                bit_rot_buffer_pct: 0,
                ..WriterOptions::default()
            },
            &KdfParams::Raw,
            None,
            None,
            &mut sink,
        )
        .unwrap();
        let opened = tzap_core::open_archive(&sink.volumes[0], &master_key).unwrap();
        opened.verify().unwrap();
        let output = temp.path().join("directory-output");
        fs::create_dir(&output).unwrap();
        opened
            .extract_all_to(
                &output,
                SafeExtractionOptions {
                    restore_policy: RestorePolicy::SameOs,
                    ..SafeExtractionOptions::default()
                },
            )
            .unwrap();
        let restored = output.join("native-directory");
        assert!(restored.is_dir());
        assert_eq!(
            fs::read(PathBuf::from(format!(
                "{}:tzap-directory",
                restored.display()
            )))
            .unwrap(),
            b"directory alternate metadata"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_directory_case_sensitive_state_round_trips() {
        use std::mem::size_of;
        use std::os::windows::fs::OpenOptionsExt as _;
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::Storage::FileSystem::{
            FileCaseSensitiveInfo, SetFileInformationByHandle, FILE_CASE_SENSITIVE_INFO,
            FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, FILE_WRITE_ATTRIBUTES,
        };
        use windows_sys::Win32::System::SystemServices::FILE_CS_FLAG_CASE_SENSITIVE_DIR;

        let temp = windows_test_tempdir();
        let source = temp.path().join("case-sensitive-directory");
        fs::create_dir(&source).unwrap();
        let source_file = fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&source)
            .unwrap();
        let enabled = FILE_CASE_SENSITIVE_INFO {
            Flags: FILE_CS_FLAG_CASE_SENSITIVE_DIR,
        };
        // SAFETY: the directory handle is live and `enabled` is correctly sized and initialized.
        assert_ne!(
            unsafe {
                SetFileInformationByHandle(
                    source_file.as_raw_handle().cast(),
                    FileCaseSensitiveInfo,
                    (&enabled as *const FILE_CASE_SENSITIVE_INFO).cast(),
                    size_of::<FILE_CASE_SENSITIVE_INFO>() as u32,
                )
            },
            0,
            "{}",
            io::Error::last_os_error()
        );
        assert_eq!(
            query_windows_directory_case_sensitive(&source_file).unwrap(),
            Some(true)
        );
        drop(source_file);

        let specs = collect_input_specs(&[source.to_string_lossy().into_owned()]).unwrap();
        assert_eq!(
            specs[0]
                .portable_metadata
                .native
                .primary_pax_records
                .get("TZAP.windows.directory-case-sensitive")
                .map(Vec::as_slice),
            Some(b"1".as_slice())
        );
        let master_key = MasterKey::from_raw_key(&[24u8; 32]).unwrap();
        let mut sink = MemoryArchiveSink::default();
        write_archive_sources_to_sink(
            &specs,
            &master_key,
            WriterOptions {
                stripe_width: 1,
                volume_loss_tolerance: 0,
                bit_rot_buffer_pct: 0,
                ..WriterOptions::default()
            },
            None,
            &KdfParams::Raw,
            None,
            None,
            &mut sink,
        )
        .unwrap();
        let opened = tzap_core::open_archive(&sink.volumes[0], &master_key).unwrap();
        opened.verify().unwrap();
        let same_os_output = temp.path().join("case-same-os-output");
        fs::create_dir(&same_os_output).unwrap();
        let same_os_diagnostics = opened
            .extract_all_to(
                &same_os_output,
                SafeExtractionOptions {
                    restore_policy: RestorePolicy::SameOs,
                    allow_degraded: true,
                    ..SafeExtractionOptions::default()
                },
            )
            .unwrap();
        assert!(same_os_diagnostics
            .iter()
            .flat_map(|(_, diagnostics)| diagnostics)
            .any(|diagnostic| {
                diagnostic.metadata_class == "directory-case-sensitive"
                    && diagnostic.status == MetadataDiagnosticStatus::Unsupported
            }));
        let same_os_restored =
            open_windows_metadata_handle(&same_os_output.join("case-sensitive-directory")).unwrap();
        assert_eq!(
            query_windows_directory_case_sensitive(&same_os_restored).unwrap(),
            Some(false)
        );
        let output = temp.path().join("case-output");
        fs::create_dir(&output).unwrap();
        opened
            .extract_all_to(
                &output,
                SafeExtractionOptions {
                    restore_policy: RestorePolicy::System,
                    system_authorized: true,
                    allow_degraded: true,
                    ..SafeExtractionOptions::default()
                },
            )
            .unwrap();
        let restored =
            open_windows_metadata_handle(&output.join("case-sensitive-directory")).unwrap();
        assert_eq!(
            query_windows_directory_case_sensitive(&restored).unwrap(),
            Some(true)
        );
    }

    #[cfg(windows)]
    #[test]
    fn sparse_windows_alternate_data_round_trips_ranges_and_content() {
        use std::os::windows::io::AsRawHandle;
        use std::ptr;
        use windows_sys::Win32::System::Ioctl::FSCTL_SET_SPARSE;
        use windows_sys::Win32::System::IO::DeviceIoControl;

        let temp = windows_test_tempdir();
        let source = temp.path().join("sparse-ads.bin");
        fs::write(&source, b"base payload").unwrap();
        let stream_path = PathBuf::from(format!("{}:sparse-test", source.display()));
        let mut stream = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&stream_path)
            .unwrap();
        let mut bytes_returned = 0u32;
        // SAFETY: the stream handle is live and FSCTL_SET_SPARSE accepts empty buffers.
        assert_ne!(
            unsafe {
                DeviceIoControl(
                    stream.as_raw_handle().cast(),
                    FSCTL_SET_SPARSE,
                    ptr::null(),
                    0,
                    ptr::null_mut(),
                    0,
                    &mut bytes_returned,
                    ptr::null_mut(),
                )
            },
            0
        );
        let logical_size = 1024 * 1024u64;
        stream.set_len(logical_size).unwrap();
        stream.seek(SeekFrom::Start(64 * 1024)).unwrap();
        stream.write_all(b"sparse ADS leading extent").unwrap();
        stream.seek(SeekFrom::Start(logical_size - 4096)).unwrap();
        stream.write_all(b"sparse ADS trailing extent").unwrap();
        stream.flush().unwrap();
        let source_ranges = query_windows_allocated_ranges(&stream, logical_size).unwrap();
        drop(stream);

        let specs = collect_input_specs(&[source.to_string_lossy().into_owned()])
            .unwrap_or_else(|error| panic!("{error:#}"));
        let sparse_record = specs[0]
            .portable_metadata
            .native
            .auxiliary_records
            .iter()
            .find(|record| record.kind == "windows.alternate-data")
            .unwrap();
        assert!(sparse_record.is_streamed());
        assert_eq!(sparse_record.flags, 1);
        assert_eq!(sparse_record.logical_size, logical_size);
        let captured_ranges = sparse_record.streamed_sparse_extents().unwrap();
        assert!(!captured_ranges.is_empty());
        if !source_ranges.is_empty() {
            assert_eq!(captured_ranges, source_ranges);
        }

        let key = MasterKey::from_raw_key(&[19u8; 32]).unwrap();
        let mut sink = MemoryArchiveSink::default();
        write_archive_sources_to_sink_ordered_parallel(
            &specs,
            &key,
            WriterOptions {
                stripe_width: 1,
                volume_loss_tolerance: 0,
                bit_rot_buffer_pct: 0,
                ..WriterOptions::default()
            },
            &KdfParams::Raw,
            None,
            None,
            &mut sink,
        )
        .unwrap();
        let opened = tzap_core::open_archive(&sink.volumes[0], &key).unwrap();
        opened.verify().unwrap();
        let output = temp.path().join("sparse-ads-output");
        fs::create_dir(&output).unwrap();
        opened
            .extract_all_to(
                &output,
                SafeExtractionOptions {
                    restore_policy: RestorePolicy::SameOs,
                    allow_degraded: true,
                    ..SafeExtractionOptions::default()
                },
            )
            .unwrap();
        let restored_stream_path = PathBuf::from(format!(
            "{}:sparse-test",
            output.join("sparse-ads.bin").display()
        ));
        let restored_stream = File::open(&restored_stream_path).unwrap();
        assert_eq!(restored_stream.metadata().unwrap().len(), logical_size);
        let restored_ranges =
            query_windows_allocated_ranges(&restored_stream, logical_size).unwrap();
        if !restored_ranges.is_empty() {
            assert_eq!(restored_ranges, captured_ranges);
        }
        let logical = fs::read(restored_stream_path).unwrap();
        assert_eq!(
            &logical[64 * 1024..64 * 1024 + 25],
            b"sparse ADS leading extent"
        );
        assert_eq!(
            &logical[logical_size as usize - 4096..logical_size as usize - 4096 + 26],
            b"sparse ADS trailing extent"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_sparse_file_round_trips_logical_bytes_and_allocated_ranges() {
        use std::os::windows::io::AsRawHandle;
        use std::ptr;
        use windows_sys::Win32::System::Ioctl::FSCTL_SET_SPARSE;
        use windows_sys::Win32::System::IO::DeviceIoControl;

        let temp = windows_test_tempdir();
        let path = temp.path().join("sparse.bin");
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let mut bytes_returned = 0u32;
        // SAFETY: the file handle is live and FSCTL_SET_SPARSE accepts empty synchronous buffers.
        assert_ne!(
            unsafe {
                DeviceIoControl(
                    file.as_raw_handle().cast(),
                    FSCTL_SET_SPARSE,
                    ptr::null(),
                    0,
                    ptr::null_mut(),
                    0,
                    &mut bytes_returned,
                    ptr::null_mut(),
                )
            },
            0
        );
        let logical_size = 1024 * 1024u64;
        file.set_len(logical_size).unwrap();
        file.seek(SeekFrom::Start(64 * 1024)).unwrap();
        file.write_all(b"leading extent").unwrap();
        file.seek(SeekFrom::Start(logical_size - 4096)).unwrap();
        file.write_all(b"trailing extent").unwrap();
        file.flush().unwrap();
        let refs_sparse_fallback = windows_file_system_is_refs(&file).unwrap();
        let source_ranges = query_windows_allocated_ranges(&file, logical_size).unwrap();
        assert!(!source_ranges.is_empty());
        drop(file);

        let specs = collect_input_specs(&[path.to_string_lossy().into_owned()])
            .unwrap_or_else(|error| panic!("{error:#}"));
        assert_eq!(specs.len(), 1);
        assert_eq!(
            specs[0].sparse_extents.as_deref(),
            Some(source_ranges.as_slice())
        );
        let master_key = MasterKey::from_raw_key(&[9u8; 32]).unwrap();
        let mut sink = MemoryArchiveSink::default();
        write_archive_sources_to_sink(
            &specs,
            &master_key,
            WriterOptions {
                stripe_width: 1,
                volume_loss_tolerance: 0,
                bit_rot_buffer_pct: 0,
                ..WriterOptions::default()
            },
            None,
            &KdfParams::Raw,
            None,
            None,
            &mut sink,
        )
        .unwrap();
        let opened = tzap_core::open_archive(&sink.volumes[0], &master_key).unwrap();
        opened.verify().unwrap();
        let index = opened.lookup_index_entry("sparse.bin").unwrap().unwrap();
        assert_eq!(index.file_data_size, logical_size);

        let output = temp.path().join("output");
        fs::create_dir(&output).unwrap();
        opened
            .extract_all_to(
                &output,
                SafeExtractionOptions {
                    allow_degraded: refs_sparse_fallback,
                    ..SafeExtractionOptions::default()
                },
            )
            .unwrap();
        let restored_path = output.join("sparse.bin");
        let restored = File::open(&restored_path).unwrap();
        assert_eq!(restored.metadata().unwrap().len(), logical_size);
        assert_eq!(
            query_windows_allocated_ranges(&restored, logical_size).unwrap(),
            source_ranges
        );
        let logical = fs::read(restored_path).unwrap();
        assert_eq!(&logical[64 * 1024..64 * 1024 + 14], b"leading extent");
        assert_eq!(
            &logical[logical_size as usize - 4096..logical_size as usize - 4096 + 15],
            b"trailing extent"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_basic_attributes_and_all_four_times_round_trip() {
        use std::mem::size_of;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            FileBasicInfo, GetFileInformationByHandleEx, SetFileInformationByHandle,
            FILE_BASIC_INFO,
        };

        const READONLY: u32 = 0x0000_0001;
        const HIDDEN: u32 = 0x0000_0002;
        const SYSTEM: u32 = 0x0000_0004;
        const ARCHIVE: u32 = 0x0000_0020;
        const MUTABLE_MASK: u32 = READONLY | HIDDEN | SYSTEM | ARCHIVE | 0x100 | 0x2000;
        const WINDOWS_EPOCH_OFFSET: i64 = 116_444_736_000_000_000;

        let temp = windows_test_tempdir();
        let source = temp.path().join("basic.bin");
        fs::write(&source, b"windows basic metadata").unwrap();
        let source_file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&source)
            .unwrap();
        let expected = FILE_BASIC_INFO {
            CreationTime: WINDOWS_EPOCH_OFFSET - 12_345_678_000_000,
            LastAccessTime: WINDOWS_EPOCH_OFFSET - 11_111_111_000_000,
            LastWriteTime: WINDOWS_EPOCH_OFFSET - 9_876_543_000_000,
            ChangeTime: WINDOWS_EPOCH_OFFSET - 8_765_432_000_000,
            FileAttributes: HIDDEN | SYSTEM | ARCHIVE,
        };
        // SAFETY: the handle is live and `expected` is a correctly sized initialized structure.
        assert_ne!(
            unsafe {
                SetFileInformationByHandle(
                    source_file.as_raw_handle().cast(),
                    FileBasicInfo,
                    (&expected as *const FILE_BASIC_INFO).cast(),
                    size_of::<FILE_BASIC_INFO>() as u32,
                )
            },
            0
        );
        drop(source_file);

        let specs = collect_input_specs(&[source.to_string_lossy().into_owned()]).unwrap();
        let master_key = MasterKey::from_raw_key(&[10u8; 32]).unwrap();
        let mut sink = MemoryArchiveSink::default();
        write_archive_sources_to_sink(
            &specs,
            &master_key,
            WriterOptions {
                stripe_width: 1,
                volume_loss_tolerance: 0,
                bit_rot_buffer_pct: 0,
                ..WriterOptions::default()
            },
            None,
            &KdfParams::Raw,
            None,
            None,
            &mut sink,
        )
        .unwrap();
        let opened = tzap_core::open_archive(&sink.volumes[0], &master_key).unwrap();
        opened.verify().unwrap();
        let output = temp.path().join("basic-output");
        fs::create_dir(&output).unwrap();
        opened
            .extract_all_to(
                &output,
                SafeExtractionOptions {
                    restore_policy: RestorePolicy::SameOs,
                    allow_degraded: true,
                    ..SafeExtractionOptions::default()
                },
            )
            .unwrap();

        let restored = File::open(output.join("basic.bin")).unwrap();
        let mut actual = FILE_BASIC_INFO::default();
        // SAFETY: the handle is live and `actual` is a correctly sized writable structure.
        assert_ne!(
            unsafe {
                GetFileInformationByHandleEx(
                    restored.as_raw_handle().cast(),
                    FileBasicInfo,
                    (&mut actual as *mut FILE_BASIC_INFO).cast(),
                    size_of::<FILE_BASIC_INFO>() as u32,
                )
            },
            0
        );
        assert_eq!(actual.CreationTime, expected.CreationTime);
        assert_eq!(actual.LastAccessTime, expected.LastAccessTime);
        assert_eq!(actual.LastWriteTime, expected.LastWriteTime);
        assert_eq!(actual.ChangeTime, expected.ChangeTime);
        assert_eq!(
            actual.FileAttributes & MUTABLE_MASK,
            expected.FileAttributes & MUTABLE_MASK
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_native_compression_round_trips_on_supported_filesystems() {
        use std::mem::size_of;
        use std::os::windows::io::AsRawHandle;
        use std::ptr;
        use windows_sys::Win32::Storage::FileSystem::{
            FileBasicInfo, GetFileInformationByHandleEx, COMPRESSION_FORMAT_DEFAULT,
            FILE_BASIC_INFO,
        };
        use windows_sys::Win32::System::Ioctl::FSCTL_SET_COMPRESSION;
        use windows_sys::Win32::System::IO::DeviceIoControl;

        const FILE_ATTRIBUTE_COMPRESSED: u32 = 0x0000_0800;
        // Keep the source on NTFS. TZAP_WINDOWS_TEST_ROOT can independently direct the
        // destination to ReFS and exercise the required storage-layout degradation path.
        let source_temp = tempfile::tempdir().unwrap();
        let destination_temp = windows_test_tempdir();
        let source = source_temp.path().join("compressed.bin");
        fs::write(&source, vec![b'z'; 256 * 1024]).unwrap();
        let source_file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&source)
            .unwrap();
        let mut compression = COMPRESSION_FORMAT_DEFAULT;
        let mut returned = 0u32;
        // SAFETY: the live file handle and initialized two-byte format input remain valid.
        if unsafe {
            DeviceIoControl(
                source_file.as_raw_handle().cast(),
                FSCTL_SET_COMPRESSION,
                (&mut compression as *mut u16).cast(),
                size_of::<u16>() as u32,
                ptr::null_mut(),
                0,
                &mut returned,
                ptr::null_mut(),
            )
        } == 0
        {
            panic!(
                "NTFS compression fixture failed: {}",
                io::Error::last_os_error()
            );
        }
        let mut source_basic = FILE_BASIC_INFO::default();
        // SAFETY: the handle is live and `source_basic` is correctly sized and writable.
        assert_ne!(
            unsafe {
                GetFileInformationByHandleEx(
                    source_file.as_raw_handle().cast(),
                    FileBasicInfo,
                    (&mut source_basic as *mut FILE_BASIC_INFO).cast(),
                    size_of::<FILE_BASIC_INFO>() as u32,
                )
            },
            0
        );
        assert_ne!(source_basic.FileAttributes & FILE_ATTRIBUTE_COMPRESSED, 0);
        drop(source_file);

        let specs = collect_input_specs(&[source.to_string_lossy().into_owned()]).unwrap();
        let captured_attributes = specs[0]
            .portable_metadata
            .native
            .primary_pax_records
            .get("TZAP.windows.file-attributes")
            .unwrap();
        let captured_attributes =
            u32::from_str_radix(std::str::from_utf8(captured_attributes).unwrap(), 16).unwrap();
        assert_ne!(captured_attributes & FILE_ATTRIBUTE_COMPRESSED, 0);

        let master_key = MasterKey::from_raw_key(&[23u8; 32]).unwrap();
        let mut sink = MemoryArchiveSink::default();
        write_archive_sources_to_sink(
            &specs,
            &master_key,
            WriterOptions {
                stripe_width: 1,
                volume_loss_tolerance: 0,
                bit_rot_buffer_pct: 0,
                ..WriterOptions::default()
            },
            None,
            &KdfParams::Raw,
            None,
            None,
            &mut sink,
        )
        .unwrap();
        let opened = tzap_core::open_archive(&sink.volumes[0], &master_key).unwrap();
        opened.verify().unwrap();
        let destination_root = open_windows_metadata_handle(destination_temp.path()).unwrap();
        let destination_refs = windows_file_system_is_refs(&destination_root).unwrap();
        let output = destination_temp.path().join("compressed-output");
        fs::create_dir(&output).unwrap();
        opened
            .extract_all_to(
                &output,
                SafeExtractionOptions {
                    restore_policy: RestorePolicy::SameOs,
                    allow_degraded: destination_refs,
                    ..SafeExtractionOptions::default()
                },
            )
            .unwrap();
        let restored = File::open(output.join("compressed.bin")).unwrap();
        let mut restored_basic = FILE_BASIC_INFO::default();
        // SAFETY: the handle is live and `restored_basic` is correctly sized and writable.
        assert_ne!(
            unsafe {
                GetFileInformationByHandleEx(
                    restored.as_raw_handle().cast(),
                    FileBasicInfo,
                    (&mut restored_basic as *mut FILE_BASIC_INFO).cast(),
                    size_of::<FILE_BASIC_INFO>() as u32,
                )
            },
            0
        );
        assert_eq!(
            restored_basic.FileAttributes & FILE_ATTRIBUTE_COMPRESSED != 0,
            !destination_refs
        );
        assert_eq!(
            fs::read(output.join("compressed.bin")).unwrap(),
            vec![b'z'; 256 * 1024]
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_relative_symlink_round_trips_portable_and_exact_reparse_data() {
        let temp = windows_test_tempdir();
        fs::write(temp.path().join("target.txt"), b"target").unwrap();
        let source = temp.path().join("link.txt");
        if !create_windows_relative_symlink(&source, "target.txt") {
            return;
        }
        let source_handle = open_windows_metadata_handle(&source).unwrap();
        let expected_reparse = query_windows_reparse_data(&source_handle).unwrap();
        assert!(matches!(
            validate_windows_known_reparse_data(&expected_reparse).unwrap(),
            WindowsKnownReparse::RelativeSymlink { .. }
        ));

        let specs = collect_input_specs(&[source.to_string_lossy().into_owned()])
            .unwrap_or_else(|error| panic!("{error:#}"));
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].entry_kind, SourceEntryKind::Symlink);
        assert!(specs[0]
            .portable_metadata
            .native
            .auxiliary_records
            .iter()
            .any(|record| record.kind == "windows.reparse-data"
                && record.payload == expected_reparse));

        let master_key = MasterKey::from_raw_key(&[11u8; 32]).unwrap();
        let mut sink = MemoryArchiveSink::default();
        write_archive_sources_to_sink(
            &specs,
            &master_key,
            WriterOptions {
                stripe_width: 1,
                volume_loss_tolerance: 0,
                bit_rot_buffer_pct: 0,
                ..WriterOptions::default()
            },
            None,
            &KdfParams::Raw,
            None,
            None,
            &mut sink,
        )
        .unwrap();
        let opened = tzap_core::open_archive(&sink.volumes[0], &master_key).unwrap();
        opened.verify().unwrap();

        let portable_output = temp.path().join("portable-links");
        fs::create_dir(&portable_output).unwrap();
        opened
            .extract_all_to(&portable_output, SafeExtractionOptions::default())
            .unwrap();
        assert_eq!(
            fs::read_link(portable_output.join("link.txt")).unwrap(),
            PathBuf::from("target.txt")
        );

        let exact_output = temp.path().join("exact-links");
        fs::create_dir(&exact_output).unwrap();
        opened
            .extract_all_to(
                &exact_output,
                SafeExtractionOptions {
                    restore_policy: RestorePolicy::System,
                    allow_degraded: true,
                    system_authorized: true,
                    ..SafeExtractionOptions::default()
                },
            )
            .unwrap();
        let exact_handle = open_windows_metadata_handle(&exact_output.join("link.txt")).unwrap();
        assert_eq!(
            query_windows_reparse_data(&exact_handle).unwrap(),
            expected_reparse
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_junction_round_trips_as_skipped_placeholder_and_exact_reparse_data() {
        use std::os::windows::ffi::OsStrExt as _;
        use std::os::windows::fs::OpenOptionsExt as _;
        use std::os::windows::io::AsRawHandle as _;
        use std::ptr;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
            FILE_GENERIC_WRITE,
        };
        use windows_sys::Win32::System::Ioctl::FSCTL_SET_REPARSE_POINT;
        use windows_sys::Win32::System::IO::DeviceIoControl;

        let temp = windows_test_tempdir();
        let target = temp.path().join("junction-target");
        fs::create_dir(&target).unwrap();
        let junction = temp.path().join("junction");
        fs::create_dir(&junction).unwrap();

        let print = target.as_os_str().encode_wide().collect::<Vec<_>>();
        let mut substitute = "\\??\\".encode_utf16().collect::<Vec<_>>();
        substitute.extend_from_slice(&print);
        let substitute_bytes = substitute.len() * 2;
        let print_offset = substitute_bytes + 2;
        let mut path_units = substitute.clone();
        path_units.push(0);
        path_units.extend_from_slice(&print);
        path_units.push(0);
        let payload_len = 8 + path_units.len() * 2;
        let mut reparse = Vec::with_capacity(8 + payload_len);
        reparse.extend_from_slice(&0xA000_0003u32.to_le_bytes());
        reparse.extend_from_slice(&(payload_len as u16).to_le_bytes());
        reparse.extend_from_slice(&0u16.to_le_bytes());
        reparse.extend_from_slice(&0u16.to_le_bytes());
        reparse.extend_from_slice(&(substitute_bytes as u16).to_le_bytes());
        reparse.extend_from_slice(&(print_offset as u16).to_le_bytes());
        reparse.extend_from_slice(&((print.len() * 2) as u16).to_le_bytes());
        for unit in path_units {
            reparse.extend_from_slice(&unit.to_le_bytes());
        }
        let junction_handle = fs::OpenOptions::new()
            .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&junction)
            .unwrap();
        let mut returned = 0u32;
        // SAFETY: the handle and canonical mount-point payload remain live for the call.
        assert_ne!(
            unsafe {
                DeviceIoControl(
                    junction_handle.as_raw_handle().cast(),
                    FSCTL_SET_REPARSE_POINT,
                    reparse.as_ptr().cast(),
                    reparse.len() as u32,
                    ptr::null_mut(),
                    0,
                    &mut returned,
                    ptr::null_mut(),
                )
            },
            0
        );
        drop(junction_handle);
        let source_handle = open_windows_metadata_handle(&junction).unwrap();
        let expected_reparse = query_windows_reparse_data(&source_handle).unwrap();
        assert_eq!(expected_reparse, reparse);

        let specs = collect_input_specs(&[junction.to_string_lossy().into_owned()])
            .unwrap_or_else(|error| panic!("{error:#}"));
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].entry_kind, SourceEntryKind::ReparseDirectory);
        let master_key = MasterKey::from_raw_key(&[12u8; 32]).unwrap();
        let mut sink = MemoryArchiveSink::default();
        write_archive_sources_to_sink(
            &specs,
            &master_key,
            WriterOptions {
                stripe_width: 1,
                volume_loss_tolerance: 0,
                bit_rot_buffer_pct: 0,
                ..WriterOptions::default()
            },
            None,
            &KdfParams::Raw,
            None,
            None,
            &mut sink,
        )
        .unwrap();
        let opened = tzap_core::open_archive(&sink.volumes[0], &master_key).unwrap();
        opened.verify().unwrap();

        let portable_output = temp.path().join("portable-junction");
        fs::create_dir(&portable_output).unwrap();
        opened
            .extract_all_to(&portable_output, SafeExtractionOptions::default())
            .unwrap();
        assert!(!portable_output.join("junction").exists());

        let exact_output = temp.path().join("exact-junction");
        fs::create_dir(&exact_output).unwrap();
        let exact_report = opened
            .extract_all_to(
                &exact_output,
                SafeExtractionOptions {
                    restore_policy: RestorePolicy::System,
                    allow_degraded: true,
                    system_authorized: true,
                    ..SafeExtractionOptions::default()
                },
            )
            .unwrap();
        let exact_handle = open_windows_metadata_handle(&exact_output.join("junction"))
            .unwrap_or_else(|error| panic!("{error}; report={exact_report:#?}"));
        assert_eq!(
            query_windows_reparse_data(&exact_handle).unwrap(),
            expected_reparse
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_opaque_reparse_tag_round_trips_as_skipped_placeholder_and_exact_data() {
        use std::os::windows::fs::OpenOptionsExt as _;
        use std::os::windows::io::AsRawHandle as _;
        use std::ptr;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
        };
        use windows_sys::Win32::System::Ioctl::FSCTL_SET_REPARSE_POINT;
        use windows_sys::Win32::System::IO::DeviceIoControl;

        let temp = windows_test_tempdir();
        let source = temp.path().join("opaque-reparse.bin");
        fs::write(&source, b"").unwrap();
        // Non-Microsoft tags use REPARSE_GUID_DATA_BUFFER. ReparseDataLength includes the GUID
        // and the tag-specific bytes after the common eight-byte header.
        let mut reparse = Vec::new();
        reparse.extend_from_slice(&0x0000_0042u32.to_le_bytes());
        reparse.extend_from_slice(&4u16.to_le_bytes());
        reparse.extend_from_slice(&0u16.to_le_bytes());
        reparse.extend_from_slice(&[
            0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ]);
        reparse.extend_from_slice(b"tzap");
        let handle = fs::OpenOptions::new()
            .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&source)
            .unwrap();
        let mut returned = 0u32;
        // SAFETY: the handle and complete opaque GUID reparse buffer remain live for the call.
        assert_ne!(
            unsafe {
                DeviceIoControl(
                    handle.as_raw_handle().cast(),
                    FSCTL_SET_REPARSE_POINT,
                    reparse.as_ptr().cast(),
                    reparse.len() as u32,
                    ptr::null_mut(),
                    0,
                    &mut returned,
                    ptr::null_mut(),
                )
            },
            0,
            "{}",
            io::Error::last_os_error()
        );
        drop(handle);
        let source_handle = open_windows_metadata_handle(&source).unwrap();
        let expected_reparse = query_windows_reparse_data(&source_handle).unwrap();
        assert_eq!(expected_reparse, reparse);
        assert_eq!(
            validate_windows_known_reparse_data(&expected_reparse).unwrap(),
            WindowsKnownReparse::Opaque
        );

        let specs = collect_input_specs(&[source.to_string_lossy().into_owned()])
            .unwrap_or_else(|error| panic!("{error:#}"));
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].entry_kind, SourceEntryKind::ReparseRegular);
        let master_key = MasterKey::from_raw_key(&[22u8; 32]).unwrap();
        let mut sink = MemoryArchiveSink::default();
        write_archive_sources_to_sink(
            &specs,
            &master_key,
            WriterOptions {
                stripe_width: 1,
                volume_loss_tolerance: 0,
                bit_rot_buffer_pct: 0,
                ..WriterOptions::default()
            },
            None,
            &KdfParams::Raw,
            None,
            None,
            &mut sink,
        )
        .unwrap();
        let opened = tzap_core::open_archive(&sink.volumes[0], &master_key).unwrap();
        opened.verify().unwrap();

        let portable_output = temp.path().join("opaque-portable");
        fs::create_dir(&portable_output).unwrap();
        opened
            .extract_all_to(&portable_output, SafeExtractionOptions::default())
            .unwrap();
        assert!(!portable_output.join("opaque-reparse.bin").exists());

        let exact_output = temp.path().join("opaque-exact");
        fs::create_dir(&exact_output).unwrap();
        opened
            .extract_all_to(
                &exact_output,
                SafeExtractionOptions {
                    restore_policy: RestorePolicy::System,
                    allow_degraded: true,
                    system_authorized: true,
                    ..SafeExtractionOptions::default()
                },
            )
            .unwrap();
        let exact_handle =
            open_windows_metadata_handle(&exact_output.join("opaque-reparse.bin")).unwrap();
        assert_eq!(
            query_windows_reparse_data(&exact_handle).unwrap(),
            expected_reparse
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_selected_hardlinks_store_data_once_and_restore_shared_file_identity() {
        let temp = windows_test_tempdir();
        let alpha = temp.path().join("alpha.bin");
        let beta = temp.path().join("beta.bin");
        fs::write(&alpha, b"one physical file").unwrap();
        fs::hard_link(&alpha, &beta).unwrap();

        let specs = collect_input_specs(&[
            beta.to_string_lossy().into_owned(),
            alpha.to_string_lossy().into_owned(),
        ])
        .unwrap_or_else(|error| panic!("{error:#}"));
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].archive_path, "alpha.bin");
        assert_eq!(specs[0].entry_kind, SourceEntryKind::Regular);
        assert_eq!(specs[1].entry_kind, SourceEntryKind::Hardlink);
        assert_eq!(
            specs[1].link_target.as_deref(),
            Some(b"alpha.bin".as_slice())
        );

        let master_key = MasterKey::from_raw_key(&[13u8; 32]).unwrap();
        let mut sink = MemoryArchiveSink::default();
        write_archive_sources_to_sink(
            &specs,
            &master_key,
            WriterOptions {
                stripe_width: 1,
                volume_loss_tolerance: 0,
                bit_rot_buffer_pct: 0,
                ..WriterOptions::default()
            },
            None,
            &KdfParams::Raw,
            None,
            None,
            &mut sink,
        )
        .unwrap();
        let opened = tzap_core::open_archive(&sink.volumes[0], &master_key).unwrap();
        opened.verify().unwrap();
        assert_eq!(
            opened
                .lookup_index_entry("alpha.bin")
                .unwrap()
                .unwrap()
                .file_data_size,
            b"one physical file".len() as u64
        );
        assert_eq!(
            opened
                .lookup_index_entry("beta.bin")
                .unwrap()
                .unwrap()
                .file_data_size,
            0
        );

        let output = temp.path().join("hardlink-output");
        fs::create_dir(&output).unwrap();
        opened
            .extract_all_to(&output, SafeExtractionOptions::default())
            .unwrap();
        assert_eq!(
            fs::read(output.join("beta.bin")).unwrap(),
            b"one physical file"
        );
        let alpha_file = File::open(output.join("alpha.bin")).unwrap();
        let beta_file = File::open(output.join("beta.bin")).unwrap();
        let mut alpha_identity = input_identity(&alpha_file.metadata().unwrap()).unwrap();
        let mut beta_identity = input_identity(&beta_file.metadata().unwrap()).unwrap();
        augment_windows_input_identity(&mut alpha_identity, &alpha_file).unwrap();
        augment_windows_input_identity(&mut beta_identity, &beta_file).unwrap();
        assert_eq!(alpha_identity.volume_serial, beta_identity.volume_serial);
        assert_eq!(alpha_identity.file_index, beta_identity.file_index);
        assert_eq!(alpha_identity.link_count, 2);
        assert_eq!(beta_identity.link_count, 2);
    }
}
