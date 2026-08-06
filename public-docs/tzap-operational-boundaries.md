# tzap operational boundaries

This document keeps operator-facing boundary cases out of the project README.
The README is for the product promise, installation, and quick starts; this file
is for exact CLI behavior when a command asks for a shape outside the current
writer or reader path.

## Unsupported archive revision

Readers inspect the fixed archive header before applying revision-specific
layout rules. If an archive was written by a newer tzap format revision than
the installed reader supports, `tzap` exits with `12 unsupported-revision`
instead of reporting a wrong key or corrupt archive.

Example with a future archive revision:

```sh
tzap list --keyfile project.key future-v45.tzap
# exit 12: unsupported-revision
```

What to do:

- Upgrade tzap or use a reader that supports the archive's
  `volume_format_rev`.
- Do not repair, rewrite, or re-save the archive with the older reader.
- Treat this as a reader capability mismatch, not as evidence that the key,
  passphrase, or archive bytes are bad.
- Automation should key on exit code `12` / label `unsupported-revision` and
  surface the required reader upgrade action to the operator.
- `tzap verify --json` does not emit partial authentication, decryption, or
  RootAuth status fields for unsupported revisions. Its error object is limited
  to the observed revision, supported reader maximum, and upgrade action.

## Writer shape validation

The writer validates archive layout choices before writing bytes. If a request
cannot produce a valid v0.45 archive with this implementation, `tzap` exits with
`16 unsupported-feature`.

Examples:

```sh
tzap create --keyfile project.key --block-size 3 -o bad.tzap ./project
# exit 16: unsupported-feature
```

`--block-size` must be even and at least 4096 bytes.

```sh
tzap create \
  --keyfile project.key \
  --chunk-size 4M \
  --envelope-size 1M \
  -o bad.tzap \
  ./project
# exit 16: unsupported-feature
```

`--chunk-size` must be non-zero and no larger than `--envelope-size`.

```sh
tzap create \
  --keyfile project.key \
  --volume-size 1K \
  -o split.tzap \
  ./project
# exit 16: unsupported-feature
```

`--volume-size` must have room for per-volume metadata and at least one block.

What to do:

- Use the default `--block-size`, `--chunk-size`, and `--envelope-size` unless
  you need a specific profile.
- Keep `--chunk-size <= --envelope-size`.
- Increase very small `--volume-size` values.
- Large regular-file input sets are supported. The writer emits multiple
  IndexShard objects and directory-hint shards when the v0.45 layout requires
  them.
- If `tzap create` still returns `unsupported-feature`, check the exact resource
  choice in the diagnostic and the additional boundaries below.

## Bootstrap sidecars and multi-volume inputs

Bootstrap sidecars are created and consumed only with single-volume CLI paths:

```sh
tzap create \
  --keyfile project.key \
  --bootstrap-out archive.tzap.bootstrap \
  -o archive.tzap \
  ./project

tzap list \
  --keyfile project.key \
  --bootstrap archive.tzap.bootstrap \
  archive.tzap
```

Do not request `--bootstrap-out` while creating multi-volume output:

```sh
tzap create \
  --keyfile project.key \
  --volumes 2 \
  --bootstrap-out archive.tzap.bootstrap \
  -o archive.tzap \
  ./project
# exit 16: unsupported-feature
```

Do not combine `--bootstrap` with a multi-volume open input set:

```sh
tzap list \
  --keyfile project.key \
  --bootstrap archive.tzap.bootstrap \
  archive.vol000.tzap \
  --volume archive.vol001.tzap
# exit 16: unsupported-feature
```

This is a preflight CLI rejection: it happens before archive paths, sidecar
paths, or key material are read. The diagnostic says multi-volume inputs with
`--bootstrap` are unsupported and tells callers to pass volume files without the
sidecar.

What to do:

- For single-volume workflows, use `--bootstrap-out` on create and `--bootstrap`
  on list, verify, or extract when the sidecar is useful.
- For multi-volume workflows, pass the available volume files and omit
  `--bootstrap-out` and `--bootstrap`.

## Root-authenticated v45 archives

The core library and CLI can create and verify root-authenticated v45 archives
with the Ed25519 helper profile or an X.509 certificate profile. CLI Ed25519
signing uses a 32-byte signing seed and writes the derived 32-byte public key
through `signing-keygen`. CLI X.509 signing uses a leaf certificate plus its
private key, and verification uses supplied CA roots or OpenSSL default roots.

Example CLI flow:

```text
tzap signing-keygen \
  --secret-output root.signing.hex \
  --public-output root.public.hex

tzap create \
  --keyfile project.key \
  --signing-key root.signing.hex \
  -o archive.tzap \
  ./project

tzap create \
  --no-encryption \
  --signing-key root.signing.hex \
  -o public.tzap \
  ./project

tzap create \
  --keyfile project.key \
  --signing-cert signer.pem \
  --signing-private-key signer.key \
  --signing-chain intermediate.pem \
  -o archive-x509.tzap \
  ./project

tzap verify \
  --keyfile project.key \
  --trusted-public-key root.public.hex \
  archive.tzap

tzap verify \
  --public-no-key \
  --trusted-public-key root.public.hex \
  archive.tzap

tzap verify \
  --keyfile project.key \
  --trusted-ca-cert root-ca.pem \
  archive-x509.tzap
```

Operational shape:

- `--signing-key` may be combined with raw-key, passphrase,
  `--no-encryption`, dictionary, and normal volume options.
- `--signing-cert` uses the leaf certificate as signer identity and stores the
  RootAuth signature plus optional `--signing-chain` intermediates in the
  authenticator value.
- Key-holding RootAuth verification is requested by adding
  `--trusted-public-key` to ordinary `tzap verify`.
- X.509 RootAuth verification is requested by adding `--trusted-ca-cert` and/or
  `--trusted-system-roots` to ordinary `tzap verify`.
- X.509 verification reports the certificate subject, issuer, serial number,
  certificate SHA-256, verified chain subjects, trust anchor subject, signature
  scheme, signer-claimed signing time, chain validation time, and verifier
  policy labels.
- Public no-key verification is requested with `--public-no-key` plus
  `--trusted-public-key`, `--trusted-ca-cert`, or `--trusted-system-roots`. It
  does not use `--keyfile`, `--password`, `--password-stdin`, or `--bootstrap`.
- X.509 RootAuth signing time is a signer-claimed timestamp embedded in the
  authenticator. Verification uses verifier current time for certificate
  validity checks unless a future trusted-timestamp profile supplies separate
  evidence. The signer-claimed time is not a trusted timestamp token,
  transparency log proof, notarization receipt, or revocation proof.
- Successful public no-key verification reports
  `public_data_block_commitment_verified`,
  `public_physical_completeness_unverified`, and
  `public_recovery_margin_unchecked`.

### X.509 trust boundary

The v45 X.509 verification profile does not enforce KeyUsage or
ExtendedKeyUsage on the signing leaf. A certificate that chains to a trusted
root verifies as a signing leaf when it has the plain `digitalSignature`
KeyUsage bit, when it carries no KeyUsage at all, or when it is itself a
CA:true certificate. This is an operational boundary of the current profile,
not a configuration error.

Consequences:

- Under `--trusted-system-roots`, any holder of the private key of a
  non-expired certificate that chains to an OS root — including a free TLS
  server certificate or a subordinate CA certificate — can sign an archive
  that verifies as trusted.
- Verification still requires a valid chain to the trusted roots and validity
  at verifier current time, and signing still requires the leaf's private key.

What to do:

- Prefer `--trusted-ca-cert` pinned to a CA you control, and issue
  document-signing certificates with a constrained profile for signing
  identities.
- Treat `--trusted-system-roots` verification as a scope-of-trust statement:
  it proves "a private key chaining to an OS root signed this archive", not
  "a dedicated signing certificate signed this archive".
- Do not rely on a certificate's EKU (such as `serverAuth`) to exclude
  certificates from archive signing under the current profile.
- A future plugin-spec revision that mandates a document-signing EKU and/or
  rejects CA:true leaves will lift this boundary.

## Explicit plaintext archives

`--no-encryption` is the v45 mode for workflows that intentionally publish
archive payloads and metadata without archive key material. It sets
`aead_algo = None`, `kdf_algo = None`, and uses unkeyed v45 integrity digests
for fixed metadata instead of HMAC.

Example:

```text
tzap create \
  --no-encryption \
  --signing-key root.signing.hex \
  -o public.tzap \
  ./project

tzap verify \
  --trusted-public-key root.public.hex \
  public.tzap

tzap verify \
  --public-no-key \
  --trusted-public-key root.public.hex \
  public.tzap
```

Operational shape:

- `--no-encryption` provides no confidentiality. Anyone with the archive bytes
  can read payloads and metadata.
- RootAuth signing can still authenticate archive integrity and signer
  provenance for plaintext archives.
- `tzap list`, `tzap extract`, and ordinary `tzap verify` open unencrypted
  archives without `--keyfile`, `--password`, or `--password-stdin`.
- `--public-no-key` remains separate because it verifies public RootAuth
  commitments without opening archive contents.
- The old `--insecure-zero-key` flag is no longer supported and now exits with a
  usage error; use `--no-encryption` for plaintext archives.

## Archive stdin and file paths

For `verify`, `list`, and extract-all, `-` is archive stdin for the live
non-seekable profile: single-volume archive streams with a raw `--keyfile` or
no key for an unencrypted archive. Dictionary-compressed streams require a matching
`--bootstrap` sidecar. `--password-stdin` reads passphrases for file-backed
archives; it cannot share stdin with archive bytes.

Example:

```sh
cat archive.tzap | tzap verify --keyfile project.key -
cat archive.tzap | tzap list --keyfile project.key -
cat archive.tzap | tzap extract --keyfile project.key -C restored -
cat public.tzap | tzap verify -
cat dictionary.tzap | tzap verify --keyfile project.key --bootstrap dictionary.tzap.bootstrap -
```

Unsupported stdin combinations:

- Selected-path extraction from `-` rejects with `unsupported-feature`.
- `extract - --stdout` rejects with `unsupported-feature`.
- Additional `--volume` inputs, passphrase modes, RootAuth external
  verification, public no-key verification, and multi-volume recovery are
  file-backed only.
- A real file named `-` can still be addressed as `./-`.

## File-backed random access

Key-holding `list`, `extract`, and `verify` open archive paths through the core
file-backed `ArchiveReadAt` reader. Opening authenticates the fixed headers and
terminal metadata, then reads index objects through positional reads. It does
not copy the whole archive into memory before an operation starts.

Operational shape:

- Default `tzap list` reads terminal and encrypted index metadata only.
- `tzap extract archive.tzap path/in/archive` reads the selected member's index
  metadata and payload envelopes. Unselected payload envelopes are not read as
  part of that targeted extraction.
- `tzap verify` is intentionally a full archive walk: it reads all relevant
  payload and metadata blocks to validate integrity.
- Public no-key verification still needs a complete volume set and validates
  public RootAuth data-block commitments rather than providing keyed extraction.

Recovery order for the core file-backed key-holding reader is:

1. Locate enough layout authority from physical startup metadata, terminal CMRA,
   locators, or an allowed bootstrap authority.
2. Repair and validate critical metadata before trusting payload locations:
   startup headers, CMRA rows, terminal metadata, IndexRoot, index shards,
   directory hints, and dictionary metadata when present.
3. Build the archive map from the repaired metadata, including block size, slot
   boundaries, object extents, parity classes, and file indexes.
4. Repair the main payload objects within their object-local FEC budget, then
   authenticate/decrypt/decompress before data is returned or written.

This sequencing lives in `tzap-core`, not only the CLI wrapper. Downstream
projects using the normal key-holding open, verify, list, extract, and
file-backed `ArchiveReadAt` APIs benefit from the same repair behavior.

## Verify repaired copies

Key-holding `tzap verify` can write repaired sibling copies for volumes that
contain recoverable BlockRecord damage. For file-backed v45 inputs, this
includes CRC failures and malformed fixed slots such as a damaged `TZBK` marker
or reserved BlockRecord bytes after `tzap` has recovered the archive layout:

```sh
tzap verify --keyfile project.key --write-repaired archive.tzap
# writes archive.repaired.tzap when recoverable damage was found

tzap verify --keyfile project.key --write-repaired archive.vol003.tzap
# writes archive.repaired.vol003.tzap when that volume had recoverable damage
```

Operational shape:

- Original archive files are never modified.
- Only volumes with repaired BlockRecords are copied and patched.
- Existing repaired output paths are not overwritten.
- `--write-repaired` requires key-holding, file-backed verify.
- `--write-repaired` is rejected with archive stdin, `--public-no-key`, and
  `--bootstrap`.
- A complete volume set is required for repaired output. Missing-volume
  recovery can prove data is still recoverable, but it does not synthesize a
  replacement archive volume in this mode.

What to do:

- Run ordinary `tzap verify` first when you only need an integrity check.
- Add `--write-repaired` when verify succeeds through recovery and you want a
  clean sibling file to replace the damaged volume manually.
- For bootstrap-assisted single-volume damage, extract and recreate the archive
  until bootstrap repair output is added as a separate feature.

## Sequential reader and provisional output

The core reader exposes live `Read` APIs for single-volume archive streams:
`verify_non_seekable_stream`, `list_non_seekable_stream`,
`extract_non_seekable_stream_to_dir`, and bootstrap-sidecar variants for
dictionary streams. They authenticate payload envelopes as bytes arrive, retain
bounded metadata and terminal-tail state, and return only after terminal
metadata and index content conformance pass.

Live filesystem extraction stages output in a private directory under the
destination parent. The final destination is committed only after terminal
verification and metadata/content conformance succeed. On payload, metadata, or
terminal failure, staged output is removed and final paths are not published.

The older `sequential_extract_tar_stream` helper remains a whole-buffer
compatibility API for dictionary-free single-volume non-seekable archive images.
That helper returns decoded tar bytes only after the terminal ManifestFooter and
VolumeTrailer authenticate. It is not a live stdout or filesystem extraction
API, so callers do not receive provisional bytes.

`tzap extract --stdout` remains file-backed only. It first opens and
authenticates an archive from file paths, then writes one selected regular-file
member to stdout.

For opened file-backed archives, selected regular-file payloads are streamed
from the selected payload envelopes to stdout or a destination file. The core
keeps extraction memory bounded by the current envelope plaintext, current
decompressed frame, and small tar metadata buffers; it still reads/decrypts
whole payload envelopes because envelopes are the authenticated AEAD/FEC object.

Examples:

```sh
tzap extract --keyfile project.key --stdout project.tzap project/readme.txt
# stdout receives bytes only after project.tzap has opened and authenticated

tzap verify --keyfile project.key -
# reads a single-volume archive stream from stdin and reports after EOF
```

What to do:

- Use `tzap verify --keyfile project.key -`, `tzap list --keyfile project.key
  -`, `tzap extract --keyfile project.key -C restored -`, or omit the archive
  key flags for unencrypted live single-volume archive streams.
- Provide `--bootstrap <path>` for dictionary-compressed archive streams.
- Store archive bytes in files when you need selected-path extraction,
  `--stdout`, passphrase KDF discovery, public no-key verification,
  RootAuth external verification, or multi-volume recovery.

## Create outputs are archive files, not stdout

The convenience core writer APIs, such as `write_archive`, return completed
volume buffers. The lower-level core writer also exposes a sink API used by the
CLI's path-backed stdin create modes; those paths stream archive bytes into
temporary files and publish the final output path or volume set only after
terminal metadata and optional RootAuth signing finish. The CLI does not expose
archive stdout, multipart-upload sink, or pipe output modes for `tzap create`.
`-o -` is rejected instead of being treated as an archive stdout sentinel.

### Core writer progress phases

The file-backed core writer progress API is phase-native. Implementations of
`ArchiveWriteProgressSink` receive these phase transitions in the normal
sequence:

1. `PlanningPayload`: read and compress source payloads to determine the
   archive layout.
2. `PlanningMetadata`: build the index and metadata plan after payload layout
   is known.
3. `EmittingPayload`: read, compress, protect, and write payload blocks.
4. `EmittingMetadata`: protect and write indexes, recovery metadata, footers,
   and trailers.

Multi-pass writers report source bytes independently in `PlanningPayload` and
`EmittingPayload`. A caller must not treat completion of either source-byte
counter as completion of the archive. Single-pass and ordered-parallel writers
start at `EmittingPayload`. Archive publication or application-owned atomic
commit happens after the core writer returns and therefore remains the caller's
finalization phase.

When automatic volume sizing requires replanning, the writer reports one
`PlanningPayload` -> `PlanningMetadata` pair for each planning attempt before
moving to emission. Every `phase_started` callback begins a new phase
occurrence, even when the same phase was reported by an earlier attempt.
Consumers must reset phase-local counters for every occurrence; source-byte
caps apply per archive member and occurrence. This exposes the repeated reads
and compression work instead of hiding it from progress and ETA calculations.

`WriterTimings` provides the corresponding post-run timing breakdown for
diagnostics and estimator calibration. It is returned only after the writer
finishes and is not itself a live progress source.

Example:

```sh
tzap create --keyfile project.key -o - ./project
# exit 16: unsupported-feature
```

## Streaming create stdin modes

The CLI supports tar stdin create, known-size raw stdin create, and explicit
spooled raw stdin create with either one output file or a fixed `--volumes N`
output set. Unknown-size raw stdin is supported only through the explicit
plaintext spool path:

```sh
tar cf - ./project | tzap create --tar-stdin --keyfile project.key -o project.tzap -
tar cf - ./project | tzap create --tar-stdin --volumes 3 --keyfile project.key -o project.tzap -
cat disk.img | tzap create --raw-stdin --stdin-name disk.img --stdin-size "$(stat -c%s disk.img)" --keyfile project.key -o disk.tzap -
cat disk.img | tzap create --raw-stdin --stdin-name disk.img --stdin-size "$(stat -c%s disk.img)" --volumes 3 --keyfile project.key -o disk.tzap -
producer | tzap create --raw-stdin --stdin-name data/export.bin --spool-stdin --keyfile project.key -o export.tzap -
producer | tzap create --raw-stdin --stdin-name data/export.bin --spool-stdin --volumes 3 --keyfile project.key -o export.tzap -
```

Use a file-backed archive path with `-o`; `-o -` is not archive stdout. The
file-backed path is also much faster for later selected-file workflows because
seekable readers can use random access.

Known-size raw stdin (`--stdin-size`) is consumed once and archived as one
regular-file member in the standard tar-member v45 profile. With `--volumes N`,
the same member is striped across the fixed output volume set. Short stdin or
extra bytes after the declared size reject the create and remove the temporary
archive output or volume set.

Unknown-size raw stdin is supported only with explicit `--spool-stdin`. That
mode writes plaintext stdin to a restrictive temporary file, then archives that
file as a regular tar-member v45 member. With `--volumes N`, tzap waits for EOF,
uses the file-backed spool size as the known raw member size, and stripes the
member across the fixed output volume set. The spool is removed after normal
success or normal failure, but the plaintext exists on local disk while the
command is running. The current CLI has no `--max-spool-size` flag, so the OS
temp directory must be able to hold the full raw stream. A hard kill, process
abort, or host crash can leave the plaintext temp file behind in the OS temp
directory.

The no-spool unknown-size raw profile remains reserved for future support:

```sh
producer | tzap create --raw-stdin --stdin-name data/export.bin --keyfile project.key -o export.tzap -
```

That accepted-looking no-spool raw stdin shape exits with
`16 unsupported-feature` until `raw_stream_v1` lands. Adding `--volumes > 1`
does not change that; no-spool unknown-size raw multi-volume remains future
work.

The following combinations are rejected before stdin payload bytes, keyfiles,
dictionaries, or ordinary input paths are read:

- `--password` or `--password-stdin` with `--tar-stdin` or `--raw-stdin`
- `--dictionary` with `--tar-stdin` or `--raw-stdin`
- `--volumes > 1` with no-size/no-spool `--raw-stdin`
- `--volume-size` with stdin create modes
- `--volume-loss-tolerance > 0` with stdin create modes
- ordinary input paths mixed with stdin create modes; use exactly one input
  path, `-`
- `-o -`; create output must remain a path-backed archive file

Raw stdin stores one archive member and therefore requires `--stdin-name PATH`.
`--stdin-size SIZE` declares a known raw stdin length. `--spool-stdin` is valid
only with unknown-size `--raw-stdin`; combining it with `--stdin-size` rejects.

Sidecar output is also file-path based:

```sh
tzap create \
  --keyfile project.key \
  --bootstrap-out - \
  -o archive.tzap \
  ./project
# exit 16: unsupported-feature
```

What to do:

- Write archive volumes to file paths, then copy or upload those files with
  tooling appropriate for the destination.
- Treat true append-only or multipart create output as a future writer API
  feature, not as behavior of the current CLI.

## Empty directory inputs

The CLI scanner emits an explicit v45 directory member before descending into
each selected directory. Empty directories therefore remain in the archive,
and directory mode, mtime, ownership, ACLs, xattrs, and supported native fields
use the same authenticated primary/auxiliary metadata model as files.

Example:

```sh
mkdir -p project/empty
tzap create --keyfile project.key -o project.tzap ./project
tzap list --keyfile project.key project.tzap
# project and project/empty are both listed
```

## Tar metadata profile

The v0.45 CLI create path emits complete `portable-v1` regular-file,
directory, and safe symbolic-link member groups. After zero or more auxiliary
member pairs, every group ends with the
mandatory canonical `TZAP-PAX/PRIMARY` record followed by the primary ustar
entry. Archive paths
are normalized safe relative NFC UTF-8 paths using `/` separators. The writer
captures source mtimes as signed Unix seconds plus nanoseconds, uses canonical
PAX `mtime` whenever the value is pre-epoch, too large for ustar, or has a
fraction, and rechecks size, mode, and mtime after the final source read.
Filesystem inputs also preserve native-vs-projected mode origin, POSIX numeric
UID/GID where applicable, and the Windows readonly/hidden/system/archive
portable projection. Symbolic links preserve their validated relative target,
portable ownership fields, mode projection, and nanosecond mtime without
following the target. Windows relative symlinks additionally retain their exact
validated reparse buffer and native basic/security metadata. Native capture
currently has these platform boundaries:

| Capture host | Captured for accepted regular files and directories | Rejected or not captured |
|---|---|---|
| Linux | Numeric ownership; no-follow symlink ownership and readable xattrs; canonical POSIX.1e access/default ACLs; inline and auxiliary xattrs; observed ctime; available creation time; exact Linux inode flags; optional project IDs; sparse allocation; FIFO, character-device, block-device, and whiteout descriptors; and selected regular-file hardlink topology. | Live sockets, unreadable privileged namespaces, filesystem metadata hidden from the caller, and source objects that change during capture. Linux birth time is captured where exposed but cannot generally be assigned during restore. |
| Windows | Creation, access, write, and change times at 100-ns precision, including pre-1970 values; exact supported attributes; primary and alternate-stream sparse data; relative-symlink, junction, and opaque reparse buffers; directory case-sensitive state; selected hardlink topology; owner/group/DACL self-relative security descriptor plus SACL when available; raw EFS regular files where the Windows raw API accepts the source; native compression; and EA/property/object-ID backup streams when exposed. | Encrypted directories, offline/cloud placeholders without an explicit hydration policy, read-mutating streams, and transactional/ghosted or otherwise unregistered backup streams. These cases fail creation instead of silently discarding metadata. ReFS sparse layout is preserved logically but authenticated as partial because ReFS does not expose exact allocated ranges. |
| macOS | Numeric ownership; no-follow symlink ownership, xattrs, ACLs, flags, and timestamps; readable inline/auxiliary xattrs; recognized Darwin flags with unknown bits retained but not applied; observed ctime; available creation time; native ACL external form; FinderInfo; streamed resource forks; FIFO and device descriptors; and selected regular-file hardlink topology. | Live sockets, unreadable privileged metadata, APFS clone hints, and source objects or resource forks that change during capture. Device recreation and system Darwin flags require an authorized System restore with superuser privilege. |
| Other POSIX hosts | Portable regular-file, directory, and safe symlink fields. | Source-native profile capture is not yet implemented. |

Linux POSIX ACL backing xattrs are converted to canonical `SCHILY.acl.*`
records rather than duplicated as generic xattrs. Windows auxiliary payloads
are emitted as revision-45 `Z` members and hashed exactly; security descriptors
always use the captured `OWNER_SECURITY_INFORMATION`,
`GROUP_SECURITY_INFORMATION`, and `DACL_SECURITY_INFORMATION` mask and add
`SACL_SECURITY_INFORMATION` when the process can enable `SeSecurityPrivilege`
and reopen the same file object with `ACCESS_SYSTEM_SECURITY`.
Windows `LastAccessTime` is preserved
from the pre-content-read scan but is excluded from the final identity
comparison because the writer's own read may update it. Stable Windows identity
fields, including change time, attributes, file ID, link count, and volume
identity, are rechecked after the source read.
Ordinary alternate data streams are hashed during `BackupRead` enumeration,
then re-opened by their validated exact UTF-16 name during archive planning and
emission. Their bytes are streamed through bounded writer buffers rather than
retained in `NativeAuxiliaryMetadata`.
Encrypted Windows files accepted by the raw EFS API retain a portable decrypted primary projection and a
separate, hashed `windows.efs-raw` System record. Raw EFS bytes are exported
and imported through the Windows callback APIs without buffering the complete
payload. Authorized System restore imports into an unpublished temporary file,
re-exports and hash-verifies the native encrypted form, and only then publishes
the destination. The local Windows Server 2025 corpus exercises exact raw
export/import, including an encrypted alternate stream, on both NTFS and ReFS
under the owning EFS principal. Keyless import remains gated by
`SeRestorePrivilege` in the Windows API.

Library writers expose native primary-PAX and auxiliary records through
`NativeFileMetadata`, `NativeAuxiliaryMetadata`, and timestamps through
`ArchiveTimestamp`. The writer does not emit global PAX state, GNU long-name
records, legacy sparse formats, or the tar two-zero-block end marker. Tar-stdin
accepts canonical GNU sparse PAX 1.0 input and rewrites it to revision-45
canonical sparse framing. On Unix and Windows, selected regular-file aliases
are grouped by stable object identity: the lexicographically first selected
path owns data/native metadata and the remaining paths are zero-data aliases.

### Windows comparison with 7-Zip 26.01

The locally available 7-Zip 26.01 source is the reproducible Windows metadata
baseline for this review. The comparison follows its update scanner and
callbacks (`EnumDirItems`, `UpdateCallback`, `FileFind`, and
`ArchiveExtractCallback`) and its optional `-sns`, `-sni`, `-snh`, and `-snl`
paths. WinRAR is proprietary and no inspectable WinRAR source or test corpus was
provided, so this document does not claim an internal WinRAR equivalence.

| Windows capability | tzap create capture | 7-Zip 26.01 source baseline | Assessment |
|---|---|---|---|
| Regular-file times and attributes | Creation, access, write, and change times plus exact file and data-stream attributes | Creation, access, write times and Windows attributes | Meets or exceeds for accepted regular files; tzap additionally records change time and default-stream attributes. |
| NT security | Owner, group, and DACL; SACL when `SeSecurityPrivilege` can be enabled | Owner, group, and DACL with `-sni`; SACL under the same privilege condition | Capture parity. Authorized system restore applies and verifies descriptors only when `SeRestorePrivilege` and, for SACLs, `SeSecurityPrivilege` are available. |
| Alternate data streams | Exact UTF-16 stream name, streamed bytes, stream attributes, and sparse range maps | Named streams with `-sns` | Capture and restore parity for ordinary and sparse streams, including multiple and non-ASCII names. |
| Other backup streams | EA, property, and object-ID streams returned by `BackupRead`, restored with `BackupWrite` | No corresponding capture path identified in the reviewed scanner | Additional tzap capture/restore for streams exposed by the source filesystem. |
| Hard-link topology | Stores one canonical owner plus selected aliases, keyed by volume and file ID | Preserves topology with `-snh`, keyed by volume and file ID | Implemented for selected regular-file aliases; unselected aliases are outside capture scope. |
| Reparse points and symlinks | Portable relative-symlink projection plus exact symlink, junction, and opaque registered/user-defined reparse data | Stores exact reparse data with `-snl` | Implemented with safe skipped placeholders where no portable projection exists. |
| Standalone directories | Stores directory entries and their metadata, including junction placeholders | Stores directory entries and their metadata | Implemented with deepest-first finalization and on-host Windows coverage. |
| Sparse files, EFS, compression, and offline/cloud placeholders | Streams and natively restores NTFS sparse ranges; preserves ReFS logical sparse bytes with an authenticated `sparse-layout` omission; streams raw EFS; recreates native compression where supported; rejects offline/cloud inputs before any hydration-capable open | Not used as a parity claim here | Implemented with exact-versus-degraded results kept explicit. |

Consequently, tzap now reaches the reviewed 7-Zip metadata capture level for an
accepted ordinary Windows regular file, and captures some extra `BackupRead`
stream classes. Ordinary and sparse ADS and raw EFS are streamed during
capture, archive emission, and restoration and are verified byte-for-byte or
by authenticated size and SHA-256. Opaque reparse tags and registered
backup-stream classes are retained without semantic reinterpretation.
Structurally bounded auxiliary classes remain inline; large ADS and raw-EFS
records use the streamed auxiliary source contract.

The core reader implements the revision-45 member-group grammar for regular
files, directories, symlinks, hardlinks, character devices, block devices, and
FIFOs. It validates canonical primary and auxiliary PAX declarations, streamed
auxiliary hashes, sparse maps, capture reports, profile dependencies,
FileEntry flags, native-record framing, hardlink mirror metadata, and the final
selected path graph. Global PAX/GNU state, unregistered primary keys, legacy GNU
metadata records, and inconsistent profile cross-fields are malformed rather
than silently ignored.

Index-backed listing exposes authenticated FileEntry data without decoding
payload envelopes. `list_index_entries`, `lookup_index_entry`, and
`tzap list --json` include path, basename, logical payload size, revision-45
summary flags, member-group size, frame range, compressed frame size, and
touched envelope/block layout. Entry kind, mode, and mtime live in the
authenticated primary PAX/member header and are available from payload-decoding
list APIs and `tzap list --long`, not from the revision-45 FileEntry row. The
decoded mtime is an `ArchiveTimestamp`, so pre-epoch values and nanoseconds are
not truncated.

Extraction supports `--restore content` and the default `--restore portable`.
Content mode writes regular bytes and safe directories, skips symlinks and
special/reparse objects, and materializes hardlink aliases as independent
files. Portable mode additionally restores safe symlinks and hardlinks,
symbolic-link mtimes through no-follow APIs, and ordinary file and post-order
directory mode/mtime metadata. Same-OS restore applies ordinary inline and
auxiliary xattrs, canonical Linux POSIX ACLs, modifiable Linux inode flags,
native Linux sparse allocation, and native Windows sparse allocation,
alternate data streams (including sparse streams), and exact supported basic
attributes/timestamps.
On macOS, same-OS restore applies and verifies inline and auxiliary xattrs,
FinderInfo, resource forks, the native Darwin ACL external form, creation time,
and recognized ordinary Darwin flags for regular files, directories, and
symlinks without following symlink targets. Unknown Darwin flag bits remain
authenticated but are not applied; when such a bit belongs to a required
same-OS scalar, strict restore rejects it unless `--allow-degraded` is explicit.
Resource-fork capture and archive emission
are streamed, restoration uses the native named fork, and exact bytes are read
back before publication. Directory metadata is finalized after descendants.
System restore, after explicit authorization, also applies numeric UID/GID,
set-ID modes, privileged xattr namespaces, Linux project IDs,
immutable/append-only Linux flags, Linux FIFO/device/whiteout objects, macOS
FIFO/device objects, and macOS immutable/append/system flags when the process
has the required superuser privilege. On
Windows, authorized system restore also recreates validated symlink, junction,
and opaque reparse buffers, restores raw EFS, applies directory case-sensitive
state and object-ID streams, and applies security descriptors when required
privileges are present. Same-OS restoration recreates ADS, EA, property-data,
native compression, and ordinary basic metadata. Application is
descriptor-based and ordered as
ownership, mode, ACL, xattrs, timestamps/attributes, then no-change flags.
Directory metadata is finalized deepest-to-root after children and hardlinks.
Both modes preflight selected random-access
restores before destination changes; sequential restores remain provisional
until terminal verification and commit. `--restore system` requires explicit
authorization, while unsupported native application remains a hard error unless
`--allow-degraded` is explicitly selected.
The CLI diagnostic fields, restore-phase numbers, repeated per-member warning
behavior, and the common Linux creation-time limitation are explained in
[`tzap-cli-reference.md`](tzap-cli-reference.md#reading-degraded-metadata-diagnostics).

Authenticated metadata outside the chosen policy is enumerated through
structured diagnostics. A partial capture, unsupported required extension
profile, skipped native stream, reparse placeholder, special object, or
storage-layout materialization cannot be reported as full fidelity.
`ArchiveContentVerification::metadata_report()` and
`SequentialVerifyReport.metadata` separately report capture completeness,
profiles and auxiliary kinds, all four restore-policy capabilities,
full-fidelity possibility, skipped/conversion diagnostics, and storage-layout
degradation. CLI `verify --json` exposes the same structure.

Library callers that only need authenticated index metadata may use
`list_index_entries` or `lookup_index_entry`. Library callers that only need
bytes may use `extract_file`, which is explicitly payload-only. Callers that
surface tar metadata fidelity should use `list_files`, `extract_member`,
`extract_file_with_diagnostics`, or `extract_file_to`.

### Published revision-45 conformance classes

- `tzap-core`: revision-45 Core reader and physical archive reader/writer for
  the documented archive workflows.
- CLI/core writer: complete `portable-v1` regular-file, directory, and safe
  symlink emission plus the declared Linux native records and Windows
  primary/auxiliary records listed above. It does not yet claim every OS backup
  reader/writer class because privileged conformance corpora and several
  non-Linux specialist classes remain incomplete.
- `tzap-plugin-keywrap`: `x509-hpke-recipient-v1` for revision 45.
- `tzap-plugin-signing`: `ed25519-archiveroot-v1` and the revision-45 X.509
  RootAuth profile.
- POSIX, Linux, macOS, and Windows backup reader/writer classes are not yet
  advertised. Linux implementation paths now cover regular files, directories,
  symlinks, hardlinks, sparse allocation, inline/auxiliary xattrs, POSIX ACLs,
  inode flags, project IDs, FIFO/device descriptors, and whiteouts as described
  above. The Linux class remains pending a published privileged on-host corpus
  for nonzero project IDs, device recreation, privileged namespaces, labels,
  capabilities, and immutable/append-only flags. Windows ordinary regular-file metadata
  and registered backup streams are captured, authenticated, parsed, and
  preserved. Sparse/reparse/basic metadata, case-sensitive directories,
  compression, EAs, property data, object IDs, raw EFS, and privilege-gated
  security application are implemented. The remaining Windows limitation is
  evidence for privilege-only combinations and filesystem-exposed property
  streams, not a known code-path omission.
  macOS regular-file, directory, symlink, and FIFO flags, xattrs, ACLs,
  FinderInfo, resource forks, creation/modify times, and ownership-policy gates
  are captured, validated, applied, and verified on-host. Privileged System
  flags and character-device capture/recreation have elevated on-host evidence.
  Block-device capture/recreation also passed a strict, zero-degradation System
  restore from `/dev/disk0` in a Full-Disk-Access Terminal context, including
  exact type, device identifier, mode, ownership, flags, mtime, and birth time.

### Remaining native-platform implementation plan

No registered revision-45 Windows metadata class remains knowingly
unimplemented. Release evidence still needs elevated CI for SACL/security,
object-ID, and raw-EFS import combinations and a filesystem fixture that
actually exposes `BACKUP_PROPERTY_DATA`.

No required macOS metadata code path is knowingly unimplemented, and the
privileged on-host corpus now covers System flags, character devices, and block
devices. APFS clone hints remain an optional storage-layout
optimization rather than a logical or metadata-fidelity requirement.
The remaining POSIX/BSD writer work includes native symlink
ownership/ACL/xattr fields, devices, FIFOs, hardlink topology, NFSv4 ACL
implementations, native BSD flags, and
large-xattr auxiliary fallback. Those implementations require their matching
host CI or fixtures; Windows-only tests cannot establish their API fidelity.

## Cloud directory-prefix optimization

The legacy cloud/object-store spec defines a directory-prefix optimization mode
that requires directory hints even for small archives. The current CLI/API does
not expose that mode and does not claim optimized directory-prefix operations.
Directory hints are emitted automatically for large regular-file archives when
the legacy threshold requires them.

Example:

```sh
tzap create --keyfile project.key -o project.tzap ./project
# no --cloud-directory-prefix or forced-hints mode exists today
```

What to do:

- Use exact-path `list`, `verify`, and `extract` operations with the current
  CLI.
- Treat future cloud directory-prefix optimization as a separate product
  feature that must force directory hints below the large-archive threshold.

## Multi-volume recovery budget

Recovery capacity is chosen when the archive is created. A volume can be omitted
only when the archive was written with enough recovery budget for that loss.
The default reader behavior is strict about identity: it authenticates each
supplied volume, rejects duplicate authenticated `volume_index` values even when
the bytes are identical, and does not expose a duplicate-copy recovery mode.

Recovery modes in the current CLI/API are:

- Default strict open: recovery-enabled file-backed key-holding inputs recover
  startup metadata from terminal CMRA before trusting physical `VolumeHeader` or
  `CryptoHeader` copies; zero-budget archives keep strict physical-prefix error
  reporting. At least one terminal or CMRA-recovered ManifestFooter authority
  must authenticate for random-access bootstrap; BlockRecords must match their
  stripe position, and malformed known fixed slots are treated as repair
  erasures within the configured FEC budget; duplicate volume indexes reject.
- Missing-volume recovery: automatic only when the number of omitted volumes is
  no greater than `volume_loss_tolerance` and the per-object FEC records can
  repair the missing shards.
- Bit-rot repair: damaged physical headers on recovery-enabled archives, CMRA
  header/row slots, CRC-failed BlockRecords, and malformed known fixed
  BlockRecord slots are treated as erasures when an authenticated or CRC-valid
  recovery authority establishes the expected slot boundaries. Repair succeeds
  only while the affected object stays within its parity budget. Authenticated
  payload tamper with a recomputed CRC still fails AEAD/HMAC before plaintext is
  released.
- Duplicate-copy recovery: not implemented or claimed. Supply at most one file
  for each authenticated volume index.

Example with one recoverable missing volume:

```sh
tzap create \
  --keyfile project.key \
  --volumes 3 \
  --volume-loss-tolerance 1 \
  -o project.tzap \
  ./project

tzap verify --keyfile project.key project.vol000.tzap project.vol002.tzap
# success when the missing volume is within the configured tolerance
```

When the archive files use the CLI volume naming pattern, such as
`project.vol000.tzap`, passing any one volume discovers matching siblings in the
same directory. Use explicit additional archive paths when the volume files live
outside that directory or when you intentionally want a partial input set.

Example without enough recovery budget:

```sh
tzap create \
  --keyfile project.key \
  --volumes 2 \
  --volume-loss-tolerance 0 \
  --bit-rot-buffer-pct 0 \
  -o project.tzap \
  ./project

tzap extract \
  --keyfile project.key \
  --directory restored \
  project.vol001.tzap \
  project/file.txt
# exit 11: corrupt-archive, with a missing-volume diagnostic
```

What to do:

- Set `--volume-loss-tolerance N` to the number of whole volumes the archive
  should survive losing.
- File-backed multi-volume create defaults to `N = 1`; pass
  `--volume-loss-tolerance 0` when a striped archive should not spend parity on
  whole-volume loss.
- Keep at least `N + 1` volumes available for recovery.
- Do not pass duplicate volume files as a recovery strategy; keep one trusted
  copy per volume index.
- Use `tzap verify` after copying, uploading, or moving volume sets.

Single-volume trusted bootstrap sidecars can recover random-access metadata
authority when that archive's terminal ManifestFooter/VolumeTrailer material is
corrupt or absent. Without a trusted sidecar, corrupt or missing terminal
ManifestFooter copies are corruption, not a recoverable condition.
Multi-volume archives can use another authenticated ManifestFooter copy when
one volume's footer copy is corrupt.
