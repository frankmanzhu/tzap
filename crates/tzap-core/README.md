# tzap-core

`tzap-core` is the v45-compliant Rust reference library for documented
supported tzap archive workflows. Pre-v45 inputs fail closed with an
unsupported revision error. It owns wire
parsing, metadata validation, compression, optional encryption, FEC recovery
structures, archive writing, archive opening, and safe extraction primitives.

Use this crate as the direct Rust API for tzap archives in applications,
services, backup tools, and custom workflows. Add companion RootAuth signing
crates when origin-authenticated signatures are part of your product.

## Install

```toml
[dependencies]
tzap-core = "0.2.1"
```

## What It Provides

- v45 encrypted and explicit plaintext archive writing and opening
- AEAD encryption, HMAC authentication, unencrypted digest mode, and KDF handling
- zstd compression and dictionary support
- multi-volume layout and FEC recovery
- bootstrap sidecar parsing and verification
- rich index-only listing with path, size, v45 summary flags, compressed-frame, and layout metadata
- file-backed `ArchiveReadAt` opening for lazy random-access extraction
- safe extraction and tar metadata normalization
- RootAuth writer request, footer, and verifier callback surfaces
- RecipientWrap record parsing and HPKE dispatch surfaces

## Example

```rust
use tzap_core::{
    open_archive, open_archive_unencrypted, open_seekable_archive, write_archive,
    write_archive_unencrypted, ArchiveTimestamp, MasterKey, RegularFile, WriterOptions,
};
use std::fs::File;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = MasterKey::from_raw_key(&[0x42; 32])?;
    let mut file = RegularFile::new("notes/readme.txt", b"hello from tzap");
    file.mtime = ArchiveTimestamp::new(1_700_000_000, 123_456_789);
    let files = [file];

    let written = write_archive(&files, &key, WriterOptions::default())?;
    let opened = open_archive(&written.bytes, &key)?;

    assert_eq!(
        opened.extract_file("notes/readme.txt")?,
        Some(b"hello from tzap".to_vec())
    );

    std::fs::write("notes.tzap", &written.bytes)?;
    let opened_from_file = open_seekable_archive(File::open("notes.tzap")?, &key)?;
    assert_eq!(opened_from_file.list_index_entries()?.len(), 1);

    let public_written = write_archive_unencrypted(&files, WriterOptions::default())?;
    let public_opened = open_archive_unencrypted(&public_written.bytes)?;
    assert_eq!(public_opened.list_index_entries()?.len(), 1);

    Ok(())
}
```

`ArchiveTimestamp` and decoded `ArchiveEntry::mtime` preserve signed pre-epoch
seconds and nanosecond precision. Full verification exposes per-entry metadata
results through `ArchiveContentVerification::metadata_report()`. Custom
`RegularFileSource` implementations can return `PortableFileMetadata` to carry
mode origin, POSIX numeric ownership, portable attributes, and source identity.

## Companion Plugin Integration

`tzap-core` is the standalone archive foundation. It exposes writer request,
footer, and verification callback surfaces so signing and recipient key-wrap
profiles compose cleanly through companion crates:

- **RootAuth Signing**: Pair with [`tzap-plugin-signing`](https://crates.io/crates/tzap-plugin-signing) for Ed25519 or X.509 RootAuth profiles.
- **HPKE RecipientWrap**: Pair with [`tzap-plugin-keywrap`](https://crates.io/crates/tzap-plugin-keywrap) for multi-recipient HPKE key wrap profiles.

## More Information

- Repository: <https://github.com/tzap-org/tzap>
- Implemented format specification: <https://github.com/tzap-org/tzap/blob/main/specs/tzap-format-revisedv45.md>
- CLI crate: <https://crates.io/crates/tzap>
- Signing plugin: <https://crates.io/crates/tzap-plugin-signing>
- Keywrap plugin: <https://crates.io/crates/tzap-plugin-keywrap>

