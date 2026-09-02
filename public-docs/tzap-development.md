# tzap Development Guide

This document keeps contributor and implementation details out of the root
README.

## Project layout

```text
crates/tzap-core   Format parsing, validation, crypto, compression, FEC, reader,
                   writer, metadata, and safe extraction primitives.
crates/tzap-cli    Command-line interface for create, extract, list, and verify.
crates/tzap-plugin-signing
                   RootAuth signing profiles, including Ed25519 raw and X.509.
specs/             tzap archive format specification.
fuzz/              Parser fuzz targets, deterministic seeds, and fuzz smoke.
```

## Format overview

The archive pipeline is:

```text
tar member groups -> zstd frames -> pack -> pad -> optional AEAD -> FEC -> stripe -> split
```

The format stores payload objects, indexes, integrity-protected headers and
trailers, and enough metadata to support random access after the archive is
opened. The v0.45 spec defines the wire structures, optional-encryption
registry, integrity model, FEC layout, bootstrap behavior, and reader/writer
requirements.

The current reference implementation is v45-compliant for documented supported
writer, reader, recovery, RootAuth, and RecipientWrap workflows. Legacy
revisions are rejected as unsupported revisions.

## Library usage

`tzap-core` exposes the reference read/write primitives for applications that
want direct access to the format from application code.

```rust
use tzap_core::{
    open_archive, write_archive, ArchiveTimestamp, MasterKey, RegularFile, WriterOptions,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = MasterKey::from_raw_key(&[0x42; 32])?;
    let mut file = RegularFile::new("notes/readme.txt", b"hello from tzap");
    file.mtime = ArchiveTimestamp::new(1_700_000_000, 123_456_789);
    let files = [file];
    let options = WriterOptions {
        stripe_width: 1,
        volume_loss_tolerance: 0,
        ..WriterOptions::default()
    };

    let written = write_archive(&files, &key, options)?;
    let opened = open_archive(&written.bytes, &key)?;

    assert_eq!(
        opened.extract_file("notes/readme.txt")?,
        Some(b"hello from tzap".to_vec())
    );

    Ok(())
}
```

## Local development

Run the test suite:

```sh
cargo test
```

Run the CLI locally:

```sh
cargo run -p tzap -- --help
```

Run the bounded parser fuzz smoke:

```sh
cargo run --manifest-path fuzz/Cargo.toml --bin fuzz_smoke --locked
```

Run the deterministic workflow benchmark smoke after building a release binary:

```sh
cargo build --release -p tzap
python3 scripts/tzap_benchmark_smoke.py --tzap target/release/tzap
```

The smoke benchmark exercises create, list, verify, and extract against a
Unicode-heavy corpus and records timings without asserting a machine-specific
throughput threshold. The scheduled Quality workflow also enforces the
workspace coverage floor, checks dependency usage with `cargo-machete`, and
runs bounded libFuzzer jobs.

For a local coverage report, install `cargo-llvm-cov` and run:

```sh
cargo llvm-cov --workspace --all-features --summary-only
```

Nightly Rust is required for branch instrumentation. Scheduled quality runs
collect the branch summary with `cargo +nightly llvm-cov --branch`; the stable
gate enforces line, function, and region floors.

Run longer fuzz targets with `cargo-fuzz` installed:

```sh
cargo fuzz run --features libfuzzer parse_fixed_structures -- -max_total_time=60
cargo fuzz run --features libfuzzer parse_metadata -- -max_total_time=60
cargo fuzz run --features libfuzzer parse_compressed_and_padding -- -max_total_time=60
```
