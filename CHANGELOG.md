# Changelog

## Unreleased

## 0.2.2 - 2026-08-09

- Adds `tzap-plugin-signing::x509_chain::verify_root_auth_signature` — a
  trustless (no chain, no roots, no time) signature check over the recomputed
  archive root, with the `X509RootAuthSignatureReport` result. Consumers that
  only need to display certificate info can delegate to it instead of
  reimplementing scheme-1-only subset verification.

## 0.2.0 - 2026-08-04

- Updates the tzap format to the v45 specification, incorporating format-level
  improvements and spec refinements.
- Adds cross-platform native metadata capture and restore: Linux sparse files,
  xattrs, project IDs, FIFO/device descriptors, and whiteouts; macOS Darwin
  flags, ACLs, FinderInfo, resource forks, and creation time; Windows reparse
  points, security descriptors, and object IDs.
- Exposes the `list` function in the public API for downstream consumers.
- Fixes PAX column handling and closes metadata column gaps across the reader
  and writer stacks.
- Enhances the reader with indexed entry lookups, frame-based streaming, and
  richer index-only metadata in archive listings.
- Improves the writer with phase-native progress reporting for metadata-heavy
  archives.
- Adds a staging root CA certificate for development and testing workflows.
- Significantly expands CLI smoke test coverage.
- Applies code-review fixes and formatting cleanups.
- Fixes multiple CI pipeline stability issues.

## 0.1.12 - 2026-07-26

- Enables `--allow-absolute-symlinks` extraction toggle for absolute symlink recovery outside the destination directory.
- Fixes validation logic to correctly enforce NFC normalization on absolute symlink targets.
- Verifies implementation of PAX records such as `LIBARCHIVE.creationtime` and `atime` across the reader stack.
- Bumps protocol test coverage by renaming legacy v36 corpus structures to accurately map to v45 expectations.

## 0.1.11 - 2026-07-17

- Closes Linux revision-45 metadata gaps for sparse allocation, auxiliary
  xattrs, no-follow symlink metadata, project IDs, FIFO/device descriptors,
  whiteouts, and authorized native restoration.
- Captures macOS regular-file metadata, including Darwin flags, xattrs, native
  ACLs, FinderInfo, resource forks, creation time, and observed ctime.
- Replaces logical-source-only create progress with phase-native writer progress.
- Reports planning and emission source bytes separately for multi-pass writers.
- Exposes planning-payload, planning-metadata, emitting-payload, and
  emitting-metadata phase transitions for live progress and ETA consumers.

## 0.1.10

- Stores and exposes archive entry modified times in TZAP index metadata.
- Improves streamed list and frame lookup paths by using indexed entries.
- Exposes richer index-only metadata for archive listings.
- Removes legacy v43 parser support and tightens current-format handling.
- Hardens recovery and recipient-wrap paths.
- Updates the embedded TZAP production root.
- Fixes sink-backed create timing labels and CI fixture metadata expectations.
