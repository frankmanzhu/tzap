use thiserror::Error;

pub const FORMAT_VERSION: u16 = 1;
pub const VOLUME_FORMAT_REV_45: u16 = 45;
pub const READER_MAX_SUPPORTED_VOLUME_FORMAT_REV: u16 = VOLUME_FORMAT_REV_45;
pub const VOLUME_FORMAT_REV: u16 = VOLUME_FORMAT_REV_45;

pub const VOLUME_HEADER_LEN: usize = 128;
pub const CRYPTO_HEADER_FIXED_LEN: usize = 76;
pub const MANIFEST_FOOTER_LEN: usize = 136;
pub const VOLUME_TRAILER_LEN: usize = 128;
pub const ROOT_AUTH_FOOTER_FIXED_LEN: usize = 318;
pub const ROOT_AUTH_SPEC_ID_V45: [u8; 24] = *b"tzap-root-auth-v0.45\0\0\0\0";
pub const ROOT_AUTH_SPEC_ID: [u8; 24] = ROOT_AUTH_SPEC_ID_V45;
pub const CRITICAL_METADATA_IMAGE_FIXED_LEN: usize = 364;
pub const SERIALIZED_REGION_HEADER_LEN: usize = 16;
pub const IMAGE_CRC_LEN: usize = 4;
pub const CRITICAL_METADATA_RECOVERY_HEADER_LEN: usize = 116;
pub const CRITICAL_METADATA_RECOVERY_SHARD_HEADER_LEN: usize = 16;
pub const CRITICAL_RECOVERY_LOCATOR_LEN: usize = 128;
pub const LOCATOR_PAIR_LEN: usize = CRITICAL_RECOVERY_LOCATOR_LEN * 2;
pub const READER_MAX_ROOT_AUTH_FOOTER_LEN: u32 = 160 * 1024;
pub const READER_MAX_ROOT_AUTH_SIGNER_IDENTITY_LEN: u32 = 16 * 1024;
pub const READER_MAX_ROOT_AUTH_AUTHENTICATOR_VALUE_LEN: u32 = 128 * 1024;
pub const READER_MAX_KEY_WRAP_TABLE_LEN: u32 = 1024 * 1024;
pub const READER_MAX_KEY_WRAP_TABLE_RECIPIENT_RECORDS: u32 = 4096;
pub const READER_MAX_CMRA_PARITY_PCT: u32 = 100;
pub const BOOTSTRAP_SIDECAR_HEADER_LEN: usize = 128;
pub const BLOCK_RECORD_FRAMING_LEN: usize = 20;
pub const CRYPTO_HEADER_HMAC_LEN: usize = 32;
pub const CRYPTO_EXTENSION_HEADER_LEN: usize = 6;
pub const CRYPTO_EXTENSION_MAX_VALUE_LEN: u32 = 256;
pub const MASTER_KEY_LEN: usize = 32;
pub const SUBKEY_LEN: usize = 32;
pub const READER_MAX_ARGON2ID_M_COST_KIB: u32 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum VolumeFormatRevision {
    V45 = VOLUME_FORMAT_REV_45,
}

impl VolumeFormatRevision {
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            VOLUME_FORMAT_REV_45 => Some(Self::V45),
            _ => None,
        }
    }
}

#[derive(Debug, Error)]
pub enum ExtractError {
    #[error(transparent)]
    Format(#[from] FormatError),

    #[error("extraction output write failed")]
    Output(#[source] std::io::Error),
}

#[derive(Debug, Error)]
pub enum ArchiveWriteError {
    #[error(transparent)]
    Format(#[from] FormatError),

    #[error("archive I/O failed")]
    Io(#[source] std::io::Error),
}
pub const READER_MAX_ARGON2ID_T_COST: u32 = 100;
pub const READER_MAX_ARGON2ID_PARALLELISM: u32 = 64;
// Bound on m_cost_kib × t_cost (KiB·passes): KDF params are unauthenticated (they are
// needed to derive the key that authenticates everything else), so a crafted archive
// could otherwise force ~400 GiB of memory traffic per open. 16 GiB·passes allows
// RFC 9106's 64 MiB × 3 default with ~85× headroom (and even 4 GiB × 4 or 1 GiB × 16).
pub const READER_MAX_ARGON2ID_MEMORY_TIME_PRODUCT: u32 = 16 * 1024 * 1024;
pub const READER_MAX_CRYPTO_HEADER_LEN: u32 = 64 * 1024;
pub const READER_MAX_CHUNK_SIZE: u32 = 64 * 1024 * 1024;
pub const READER_MAX_ENVELOPE_TARGET_SIZE: u32 = 64 * 1024 * 1024;
pub const READER_MAX_METADATA_OBJECT_SIZE: u32 = 512 * 1024 * 1024;
pub const READER_MAX_BLOCK_SIZE: u32 = 1024 * 1024;
pub const READER_MAX_STRIPE_WIDTH: u32 = 4096;
pub const READER_MAX_FEC_CLASS_SHARDS: u32 = 4096;
// Lower local cap on the erasure-repair matrix size: inversion is O(n³) in GF(2^16), so
// the spec-permitted 4096-shard maximum costs minutes of CPU per crafted envelope on
// unauthenticated (plaintext) archives. 1024 is 4.5× the tzap writer's own default
// (224 data shards); envelopes above it fail repair with a resource-limit diagnostic
// per spec §13.3 ("A reader that uses a lower local cap may reject an otherwise valid
// archive with a resource-limit diagnostic").
pub const READER_MAX_REPAIR_TOTAL_SHARDS: u32 = 1024;
pub const READER_MAX_INDEX_FEC_CLASS_SHARDS: u32 = 4096;
pub const READER_MAX_INDEX_ROOT_FEC_CLASS_SHARDS: u32 = 131_070;
pub const READER_MAX_PATH_LENGTH: u32 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum CompressionAlgo {
    None = 0,
    ZstdFramed = 1,
}

impl TryFrom<u16> for CompressionAlgo {
    type Error = FormatError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::ZstdFramed),
            other => Err(FormatError::UnknownCompressionAlgo(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AeadAlgo {
    None = 0,
    AesGcmSiv256 = 1,
    XChaCha20Poly1305 = 2,
    AesGcm256 = 3,
}

impl TryFrom<u16> for AeadAlgo {
    type Error = FormatError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::AesGcmSiv256),
            2 => Ok(Self::XChaCha20Poly1305),
            3 => Ok(Self::AesGcm256),
            other => Err(FormatError::UnknownAeadAlgo(other)),
        }
    }
}

impl AeadAlgo {
    pub const fn nonce_len(self) -> usize {
        match self {
            Self::None => 0,
            Self::AesGcmSiv256 | Self::AesGcm256 => 12,
            Self::XChaCha20Poly1305 => 24,
        }
    }

    pub const fn tag_len(self) -> usize {
        match self {
            Self::None => 0,
            Self::AesGcmSiv256 | Self::XChaCha20Poly1305 | Self::AesGcm256 => 16,
        }
    }

    pub const fn is_encrypted(self) -> bool {
        !matches!(self, Self::None)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum FecAlgo {
    None = 0,
    ReedSolomonGF16 = 1,
    Wirehair = 2,
}

impl TryFrom<u16> for FecAlgo {
    type Error = FormatError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::ReedSolomonGF16),
            2 => Ok(Self::Wirehair),
            other => Err(FormatError::UnknownFecAlgo(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum KdfAlgo {
    Raw = 0,
    Argon2id = 1,
    None = 2,
    RecipientWrap = 3,
}

impl TryFrom<u16> for KdfAlgo {
    type Error = FormatError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Raw),
            1 => Ok(Self::Argon2id),
            2 => Ok(Self::None),
            3 => Ok(Self::RecipientWrap),
            other => Err(FormatError::UnknownKdfAlgo(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BlockKind {
    PayloadData = 0,
    PayloadParity = 1,
    IndexRootData = 2,
    IndexRootParity = 3,
    IndexShardData = 4,
    IndexShardParity = 5,
    DictionaryData = 6,
    DictionaryParity = 7,
    DirectoryHintData = 8,
    DirectoryHintParity = 9,
}

impl TryFrom<u8> for BlockKind {
    type Error = FormatError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::PayloadData),
            1 => Ok(Self::PayloadParity),
            2 => Ok(Self::IndexRootData),
            3 => Ok(Self::IndexRootParity),
            4 => Ok(Self::IndexShardData),
            5 => Ok(Self::IndexShardParity),
            6 => Ok(Self::DictionaryData),
            7 => Ok(Self::DictionaryParity),
            8 => Ok(Self::DirectoryHintData),
            9 => Ok(Self::DirectoryHintParity),
            other => Err(FormatError::UnknownBlockKind(other)),
        }
    }
}

impl BlockKind {
    pub const fn is_data(self) -> bool {
        matches!(self, Self::PayloadData | Self::IndexRootData | Self::IndexShardData | Self::DictionaryData | Self::DirectoryHintData)
    }

    pub const fn is_parity(self) -> bool {
        !self.is_data()
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum FormatError {
    #[error("unknown compression algorithm id {0}")]
    UnknownCompressionAlgo(u16),

    #[error("unknown AEAD algorithm id {0}")]
    UnknownAeadAlgo(u16),

    #[error("unknown FEC algorithm id {0}")]
    UnknownFecAlgo(u16),

    #[error("unknown KDF algorithm id {0}")]
    UnknownKdfAlgo(u16),

    #[error("unknown block kind {0}")]
    UnknownBlockKind(u8),

    #[error("invalid length for {structure}: expected {expected}, actual {actual}")]
    InvalidLength { structure: &'static str, expected: usize, actual: usize },

    #[error("bad magic for {structure}")]
    BadMagic { structure: &'static str },

    #[error("bad CRC32C for {structure}")]
    BadCrc { structure: &'static str },

    #[error("unsupported format version {0}")]
    UnsupportedFormatVersion(u16),

    #[error(
        "unsupported volume format revision {volume_format_rev} for format version {format_version}; reader supports up to {reader_max_supported_revision}"
    )]
    UnsupportedVolumeFormatRevision { format_version: u16, volume_format_rev: u16, reader_max_supported_revision: u16 },

    #[error("non-zero reserved bytes in {structure}")]
    NonZeroReserved { structure: &'static str },

    #[error("non-canonical CryptoHeader offset {0}")]
    NonCanonicalCryptoHeaderOffset(u32),

    #[error("stripe width must be non-zero")]
    ZeroStripeWidth,

    #[error("volume index {volume_index} is outside stripe width {stripe_width}")]
    VolumeIndexOutOfRange { volume_index: u32, stripe_width: u32 },

    #[error("CryptoHeader length mismatch: fixed header says {fixed}, volume header says {volume}")]
    CryptoHeaderLengthMismatch { fixed: u32, volume: u32 },

    #[error("compression algorithm {0:?} is not valid for v0.45")]
    UnsupportedCompression(CompressionAlgo),

    #[error("FEC algorithm {0:?} is not valid for v0.45")]
    UnsupportedFec(FecAlgo),

    #[error("invalid v0.45 protection mode: aead_algo={aead_algo:?}, kdf_algo={kdf_algo:?}")]
    InvalidProtectionMode { aead_algo: AeadAlgo, kdf_algo: KdfAlgo },

    #[error("invalid boolean field {field}={value}")]
    InvalidBoolean { field: &'static str, value: u8 },

    #[error("volume loss tolerance {volume_loss_tolerance} must be less than stripe width {stripe_width}")]
    VolumeLossToleranceOutOfRange { volume_loss_tolerance: u8, stripe_width: u32 },

    #[error("bit rot buffer pct {0} exceeds 100")]
    BitRotBufferPctTooLarge(u8),

    #[error("data shard maximum {field} must be non-zero")]
    ZeroDataShardMaximum { field: &'static str },

    #[error("chunk_size must be non-zero")]
    ZeroChunkSize,

    #[error("envelope_target_size must be non-zero")]
    ZeroEnvelopeTargetSize,

    #[error("chunk_size {chunk_size} exceeds envelope_target_size {envelope_target_size}")]
    ChunkSizeExceedsEnvelopeTarget { chunk_size: u32, envelope_target_size: u32 },

    #[error("block_size {0} is below the v0.45 minimum")]
    BlockSizeTooSmall(u32),

    #[error("block_size {0} must be even")]
    OddBlockSize(u32),

    #[error("reader resource cap exceeded for {field}: cap {cap}, actual {actual}")]
    ReaderResourceLimitExceeded { field: &'static str, cap: u64, actual: u64 },

    #[error("invalid block flags 0x{0:02x}")]
    InvalidBlockFlags(u8),

    #[error("parity block must not set the last-data flag")]
    ParityBlockHasLastDataFlag,

    #[error("invalid authoritative flag {0}")]
    InvalidAuthoritativeFlag(u8),

    #[error("invalid ManifestFooter length {0}")]
    InvalidManifestFooterLength(u32),

    #[error("IndexRoot encrypted size is not data_block_count * block_size")]
    IndexRootSizeMismatch,

    #[error("IndexRoot data block count and encrypted size must be non-zero")]
    EmptyIndexRootExtent,

    #[error("bootstrap sidecar version {0} is unsupported")]
    UnsupportedBootstrapSidecarVersion(u32),

    #[error("bootstrap sidecar has unknown flags 0x{0:08x}")]
    UnknownBootstrapSidecarFlags(u32),

    #[error("bootstrap sidecar present section has zero offset or length")]
    EmptyBootstrapSidecarSection,

    #[error("bootstrap sidecar absent section has non-zero offset or length")]
    NonZeroAbsentBootstrapSidecarSection,

    #[error("bootstrap sidecar sections are not packed canonically")]
    NonCanonicalBootstrapSidecarLayout,

    #[error("extension TLV header is truncated")]
    TruncatedExtensionHeader,

    #[error("extension TLV payload is truncated")]
    TruncatedExtensionPayload,

    #[error("extension TLV payload length {0} exceeds 256")]
    ExtensionPayloadTooLarge(u32),

    #[error("extension terminator is malformed")]
    MalformedExtensionTerminator,

    #[error("extension terminator is missing")]
    MissingExtensionTerminator,

    #[error("bytes follow extension terminator")]
    BytesAfterExtensionTerminator,

    #[error("CryptoHeader is too short: minimum {min}, actual {actual}")]
    CryptoHeaderTooShort { min: usize, actual: usize },

    #[error("KdfParams algo_tag {actual} does not match expected {expected}")]
    KdfAlgoTagMismatch { expected: u16, actual: u16 },

    #[error("KdfParams are truncated")]
    TruncatedKdfParams,

    #[error("invalid KdfParams: {0}")]
    InvalidKdfParams(&'static str),

    #[error("key material does not match KDF mode")]
    KeyMaterialMismatch,

    #[error("raw master key must be exactly 32 bytes")]
    InvalidRawMasterKeyLength,

    #[error("Argon2id derivation failed")]
    Argon2idFailure,

    #[error("HKDF expansion failed")]
    HkdfExpandFailure,

    #[error("HMAC verification failed for {structure}")]
    HmacMismatch { structure: &'static str },

    #[error("integrity digest verification failed for {structure}")]
    IntegrityDigestMismatch { structure: &'static str },

    #[error("forbidden CryptoHeader extension tag 0x{0:04x}")]
    ForbiddenExtensionTag(u16),

    #[error("unknown critical CryptoHeader extension tag 0x{0:04x}")]
    UnknownCriticalExtension(u16),

    #[error("duplicate known CryptoHeader extension tag 0x{0:04x}")]
    DuplicateKnownExtension(u16),

    #[error("malformed known CryptoHeader extension tag 0x{0:04x}")]
    MalformedKnownExtension(u16),

    #[error("padding input is empty")]
    EmptyPaddedPlaintext,

    #[error("invalid suffix padding")]
    InvalidSuffixPadding,

    #[error("non-zero suffix padding bytes")]
    NonZeroPaddingBytes,

    #[error("padding arithmetic overflow")]
    PaddingOverflow,

    #[error("AEAD operation failed")]
    AeadFailure,

    #[error("nonce/AAD domain is too long")]
    DomainTooLong,

    #[error("invalid nonce length for {algo:?}: expected {expected}, actual {actual}")]
    InvalidNonceLength { algo: AeadAlgo, expected: usize, actual: usize },

    #[error("invalid AEAD key length")]
    InvalidAeadKeyLength,

    #[error("zstd compression failed")]
    ZstdCompressionFailure,

    #[error("zstd frame is empty")]
    EmptyZstdFrame,

    #[error("zstd frame is not a standard non-skippable frame")]
    NotStandardZstdFrame,

    #[error("zstd frame is truncated or corrupt")]
    InvalidZstdFrame,

    #[error("zstd frame has trailing bytes after the first complete frame")]
    TrailingBytesAfterZstdFrame,

    #[error("zstd decompression failed")]
    ZstdDecompressionFailure,

    #[error("zstd decompressed size mismatch: expected {expected}, actual {actual}")]
    ZstdDecompressedSizeMismatch { expected: usize, actual: usize },

    #[error("FEC object must contain at least one data shard")]
    FecZeroDataShards,

    #[error("FEC object total shard count {0} exceeds ReedSolomonGF16 limit")]
    FecTooManyShards(usize),

    #[error("FEC shard size must be even")]
    FecOddShardSize,

    #[error("FEC shards have inconsistent sizes")]
    FecInconsistentShardSize,

    #[error("FEC repair has too few available shards")]
    FecTooFewAvailableShards,

    #[error("FEC repair matrix is singular")]
    FecSingularMatrix,

    #[error("invalid metadata in {structure}: {reason}")]
    InvalidMetadata { structure: &'static str, reason: &'static str },

    #[error("metadata arithmetic overflow in {structure}")]
    MetadataArithmeticOverflow { structure: &'static str },

    #[error("hash-prefix collision run exceeds resource caps")]
    HashPrefixCollisionRunExceeded,

    #[error("unsafe archive path")]
    UnsafeArchivePath,

    #[error("unsafe extraction overwrite")]
    UnsafeOverwrite,

    #[error("filesystem extraction failed: {0}")]
    FilesystemExtractionFailed(&'static str),

    #[error("writer unsupported case: {0}")]
    WriterUnsupported(&'static str),

    #[error("writer invariant failed: {0}")]
    WriterInvariant(&'static str),

    #[error("reader unsupported case: {0}")]
    ReaderUnsupported(&'static str),

    #[error("invalid archive: {0}")]
    InvalidArchive(&'static str),
}

pub fn root_auth_spec_id_for_revision(format_version: u16, volume_format_rev: u16) -> Result<[u8; 24], FormatError> {
    if format_version != FORMAT_VERSION {
        return Err(FormatError::UnsupportedFormatVersion(format_version));
    }
    match volume_format_rev {
        VOLUME_FORMAT_REV_45 => Ok(ROOT_AUTH_SPEC_ID_V45),
        other => Err(FormatError::UnsupportedVolumeFormatRevision {
            format_version,
            volume_format_rev: other,
            reader_max_supported_revision: READER_MAX_SUPPORTED_VOLUME_FORMAT_REV,
        }),
    }
}
