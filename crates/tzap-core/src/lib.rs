//! Core implementation surface for the tzap v0.45 archive format.
//!
//! This crate owns wire-format parsing, validation, crypto, compression, FEC,
//! and archive read/write primitives. The CLI stays intentionally thin.

pub mod compression;
pub mod crypto;
pub mod entry_metadata;
pub mod fec;
pub mod format;
#[cfg(target_os = "linux")]
pub mod linux_metadata;
#[cfg(target_os = "macos")]
pub mod macos_metadata;
pub mod metadata;
pub mod non_seekable_reader;
pub mod padding;
pub mod reader;
pub mod root_auth;
pub mod tar_model;
pub mod volume_file;
#[cfg(windows)]
pub mod windows_metadata;
pub mod wire;
pub mod writer;

mod raw_stream_profile;
mod streaming_writer;

pub use crypto::{HmacDomain, KdfParams, MasterKey, Subkeys};
pub use entry_metadata::{
    canonical_base64_encode, decode_percent_name, encode_percent_name, linux_posix_acl_xattr_to_schily, schily_posix_acl_to_linux_xattr, ArchiveTimestamp,
    RestoreClass, RestorePolicy, SparseExtent,
};
pub use format::{AeadAlgo, ArchiveWriteError, CompressionAlgo, ExtractError, FecAlgo, FormatError, KdfAlgo, FORMAT_VERSION, VOLUME_FORMAT_REV};
pub use non_seekable_reader::{
    extract_non_seekable_stream_to_dir, extract_non_seekable_stream_to_dir_with_bootstrap_sidecar,
    extract_non_seekable_stream_to_dir_with_recipient_wrap_resolver, extract_non_seekable_stream_to_dir_with_recipient_wrap_resolver_and_bootstrap_sidecar,
    extract_unencrypted_non_seekable_stream_to_dir, extract_unencrypted_non_seekable_stream_to_dir_with_bootstrap_sidecar, list_non_seekable_stream,
    list_non_seekable_stream_with_bootstrap_sidecar, list_non_seekable_stream_with_recipient_wrap_resolver,
    list_non_seekable_stream_with_recipient_wrap_resolver_and_bootstrap_sidecar, list_unencrypted_non_seekable_stream,
    list_unencrypted_non_seekable_stream_with_bootstrap_sidecar, verify_non_seekable_stream, verify_non_seekable_stream_with_bootstrap_sidecar,
    verify_non_seekable_stream_with_options, verify_non_seekable_stream_with_recipient_wrap_resolver_and_bootstrap_sidecar,
    verify_non_seekable_stream_with_recipient_wrap_resolver_options, verify_unencrypted_non_seekable_stream_with_bootstrap_sidecar,
    verify_unencrypted_non_seekable_stream_with_options, NonSeekableReaderOptions, SequentialExtractReport, SequentialListReport, SequentialRootAuthStatus,
    SequentialVerifyReport,
};
pub use reader::{
    open_archive, open_archive_unencrypted, open_archive_volumes, open_archive_volumes_unencrypted, open_archive_with_bootstrap_sidecar,
    open_archive_with_recipient_wrap_resolver, open_non_seekable_archive, open_seekable_archive, open_seekable_archive_volumes,
    open_seekable_archive_volumes_with_recipient_wrap_resolver_options, open_seekable_archive_with_bootstrap_sidecar,
    open_seekable_archive_with_bootstrap_sidecar_options, open_seekable_archive_with_recipient_wrap_resolver_options, public_no_key_inspect_footer,
    public_no_key_verify_archive_with, public_no_key_verify_readers_with, public_no_key_verify_readers_with_options, public_no_key_verify_volumes_with,
    public_no_key_verify_volumes_with_options, sequential_extract_tar_stream, validate_volume_set_member_metadata, ArchiveContentVerification, ArchiveEntry,
    ArchiveExtractProgressSink, ArchiveIndexEntry, ArchiveReadAt, ArchiveRepairPatch, OpenedArchive, PublicNoKeyDiagnostic, PublicNoKeyFooterInspection,
    PublicNoKeyFooterStatus, PublicNoKeyVerification, ReaderOptions, RecipientWrapArchiveIdentity, RecipientWrapCandidateMasterKey, RecipientWrapRecordContext,
    RootAuthDiagnostic, RootAuthVerification,
};
pub use streaming_writer::{
    write_sized_raw_member_archive_to_sink_with_kdf_and_root_auth, write_tar_stream_archive, write_tar_stream_archive_to_sink,
    write_tar_stream_archive_to_sink_with_kdf_and_root_auth, StreamingRawWriterSummary, StreamingTarWriterSummary,
};
pub use tar_model::{
    EntryMetadataVerification, MetadataDiagnostic, MetadataDiagnosticStatus, MetadataOperation, MetadataVerificationReport, RestorePolicyCapability,
    SafeExtractionOptions, TarEntryKind,
};
pub use writer::{
    encode_v45_sparse_map, write_archive, write_archive_sources_to_sink, write_archive_sources_to_sink_ordered_parallel,
    write_archive_sources_to_sink_ordered_parallel_with_progress, write_archive_sources_to_sink_ordered_parallel_with_recipient_wrap_records,
    write_archive_sources_to_sink_ordered_parallel_with_recipient_wrap_records_and_progress, write_archive_sources_to_sink_single_pass,
    write_archive_sources_to_sink_single_pass_with_progress, write_archive_sources_to_sink_single_pass_with_recipient_wrap_records,
    write_archive_sources_to_sink_with_progress, write_archive_unencrypted, write_archive_with_dictionary, write_archive_with_dictionary_and_kdf,
    write_archive_with_dictionary_and_root_auth, write_archive_with_dictionary_kdf_and_root_auth, write_archive_with_kdf,
    write_archive_with_recipient_wrap_records, write_archive_with_root_auth, write_archive_with_root_auth_and_kdf, write_empty_archive, ArchiveWritePhase,
    ArchiveWriteProgressSink, ArchiveWriteSink, KeyWrapRecordSource, MemoryArchiveSink, NativeAuxiliaryMetadata, NativeAuxiliaryNameEncoding,
    NativeFileMetadata, PortableFileMetadata, PortableModeOrigin, PortablePosixOwner, RegularFile, RegularFileSource, RootAuthSigningRequest,
    RootAuthWriterConfig, SourceEntryKind, WriterOptions, WriterTimings, WrittenArchiveSummary,
};
