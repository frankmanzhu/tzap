use super::*;

use clap::{ArgGroup, Parser, Subcommand, ValueEnum};
use tzap_core::RestorePolicy;
use tzap_plugin_signing::x509_chain::X509SignatureScheme;

#[derive(Debug, Parser)]
#[command(name = "tzap")]
#[command(version)]
#[command(about = "Create, list, verify, and extract v45 archives")]
#[command(
    long_about = "Create, list, verify, and extract v45 archives.\n\nCreate selects one protection mode: `--keyfile` for encrypted raw-key archives, `--password` or `--password-stdin` for encrypted passphrase archives, `--recipient-cert` for encrypted v45 RecipientWrap archives, or `--no-encryption` for explicit plaintext archives. Plaintext archives can be listed, verified, and extracted without a password or keyfile. RecipientWrap archives are opened with `--recipient-key`. The `verify --public-no-key` mode verifies signed public RootAuth commitments without the archive key.\n\nSize suffixes accepted by size flags:\n  0-9 (bytes), K/KB/KiB, M/MB/MiB, G/GB/GiB.\n\nMulti-volume output naming for this CLI:\n  - one volume: --output writes exactly that path\n  - multiple volumes: --output backup.tzap writes backup.vol000.tzap, backup.vol001.tzap, ...\n\nExit codes:\n  2  usage / argument error\n  3  I/O failure (missing file, permission denied, etc.)\n  10 wrong key\n  11 archive corruption or integrity mismatch\n  12 unsupported archive revision / format version\n  13 unsafe extraction attempt\n  14 missing required bootstrap metadata\n  16 unsupported feature in this CLI/core version\n  1  generic failure\n\nSubcommands:\n  create   Build a new archive\n  extract  Extract files from an archive\n  list     List archive contents\n  verify   Validate archive integrity\n  keygen   Generate a random raw keyfile\n  signing-keygen Generate an Ed25519 RootAuth signing keypair"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,

    #[arg(
        long = "quiet",
        global = true,
        help = "Suppress routine success output and non-fatal diagnostics; failures are still reported."
    )]
    pub(crate) quiet: bool,

    #[arg(long = "verbose", global = true, help = "Enable verbose diagnostics.")]
    pub(crate) verbose: bool,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
pub(crate) enum Command {
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

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum CliX509SignatureScheme {
    #[value(name = "rsa-pkcs1-sha256")]
    RsaPkcs1Sha256,
    #[value(name = "ecdsa-sha256-der")]
    EcdsaSha256Der,
    #[value(name = "rsa-pss-sha256")]
    RsaPssSha256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum CliRestorePolicy {
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
    pub(crate) fn to_plugin_scheme(self) -> X509SignatureScheme {
        match self {
            Self::RsaPkcs1Sha256 => X509SignatureScheme::RsaPkcs1Sha256,
            Self::EcdsaSha256Der => X509SignatureScheme::EcdsaSha256Der,
            Self::RsaPssSha256 => X509SignatureScheme::RsaPssSha256,
        }
    }
}
