# tzap v0.4.5 Code Modularization — Walkthrough

This document summarizes the 6-phase modularization of the tzap workspace,
the resulting module structure, and the verification metrics collected after
each phase. The work was driven by
`implementation-docs/tzap-v45-code-modularization-implementation-plan.md`.

## Mandate

- **100% public API preservation** — all public items remain exported at their
  current paths via `pub use` re-exports; nothing moved across crate boundaries.
- **Zero behavior mismatch** — CLI flags, subcommands, output formats, exit
  codes, and archive wire-format bytes are strictly unchanged.
- **Incremental verification** — `cargo check` and `cargo test` after every
  step, with a commit per phase.

## Phase Summary

| Phase | Scope | Monolith | Result | Commit |
|-------|-------|----------|--------|--------|
| 3 | `crates/tzap-core/src/reader.rs` | 20,063 lines | `reader/` module directory: `mod.rs`, `cmra.rs`, `sidecar.rs`, `validation.rs`, `volume.rs`, `tests.rs` | `ee5d94b` |
| 4 | `crates/tzap-cli/src/main.rs` | 12,666 lines | `cli.rs`, `commands/{mod,create,extract,keygen,list,verify}.rs`, `formatters.rs`, `os_input.rs`, `tests.rs` | `e8007a2` |
| 5 | `crates/tzap-cli/tests/cli_smoke.rs` | 10,078 lines | `tests/cli/{main,common,create,extract,verify,keywrap}.rs` + `tests/cli_errors.rs` | `bdb218e` |
| 6 | Final integration & verification | — | This artifact | — |

## Resulting Module Structure

```
crates/tzap-core/src/
  lib.rs                  (101)   crate root, re-exports
  reader/                 ~20.1k  tzap-core reader, split from reader.rs
    mod.rs               4,425   module root + shared reader machinery
    cmra.rs              2,756   critical-recovery and multi-volume readers
    sidecar.rs             505   bootstrap sidecar reader
    validation.rs        1,746   post-read validation
    volume.rs            1,444   single-volume reader
    tests.rs             9,312   reader unit tests
  ...writer/ etc. unchanged

crates/tzap-cli/src/
  main.rs                  539   crate root: CLI entry, dispatcher, diagnostics
  cli.rs                   764   Cli/Command definitions + clap surface
  commands/
    mod.rs               1,563   shared machinery + re-export globs
    create.rs            2,287   `tzap create` implementation
    extract.rs             299   `tzap extract` implementation
    list.rs                232   `tzap list` implementation
    verify.rs            1,365   `tzap verify` implementation
    keygen.rs              103   `tzap keygen` + `tzap signing keygen`
  formatters.rs            445   stdout/json output formatting
  os_input.rs            2,915   platform input inspection + metadata capture
  plaintext_spool.rs       244   raw-stdin spooling
  tests.rs               2,677   CLI unit tests

crates/tzap-cli/tests/
  cli/                            CLI integration tests (test binary "cli")
    main.rs             2,495   crate root: shared globs + cross-cutting tests
                                (help/aliases/jobs, dash-as-stdin, no-encryption,
                                 key-mode semantics, list command)
    common.rs              629   shared import surface (`pub use`) + helpers,
                                compiled into both test binaries via #[path]
    create.rs            2,941   create command tests (63)
    extract.rs           1,584   extract command tests (34)
    verify.rs              954   verify command tests (23)
    keywrap.rs           1,147   keygen/signing/keyfile/recipient-wrap/password (28)
  cli_errors.rs            359   standalone binary: stable error categories (10)
  public_docs.rs, release_workflows.rs, crates_io_metadata.rs  (unchanged)
```

Largest remaining file after all phases: `reader/tests.rs` at 9,312 lines
(unit-test content, deliberately not split further).

## Key Refactoring Techniques

- **Module splits preserve visibility** — in a binary crate, items private to a
  parent module remain glob-importable by child modules via `use super::*`,
  and private `use` imports of a parent are likewise visible to children. This
  let the splits happen without changing item privacy, then targeted items were
  promoted to `pub(crate)` only where siblings needed them.
- **Re-export globs** — `commands/mod.rs` re-exports child modules
  (`pub(crate) use create::*;` etc.) so the unit-test module's
  `use crate::commands::*` continues to resolve every name; `#[allow(unused_imports)]`
  on globs covers the bin-only build where tests are not compiled.
- **Shared test infrastructure** — `tests/cli/common.rs` holds the complete
  import surface as `pub use` plus all helpers/consts, and is compiled into
  both the `cli` binary (via `mod common;`) and the `cli_errors` binary
  (via `#[path = "cli/common.rs"] mod common;`), so no test helper is
  duplicated.
- **Test routing** — the 201 cli_smoke tests were routed per-test (brace-tracked,
  themes interleave in the original file): prefix-based (`cli_create_*`,
  `cli_extract_*`, `cli_verify_*`), keyword-based for key material
  (keygen/signing/keyfile/recipient_wrap/password/passphrase/argon2 → `keywrap.rs`),
  and explicit overrides for cross-cutting families (dash-as-stdin,
  no-encryption) → root.

## Verification Metrics

Gate run after every phase and at final integration:

| Metric | Phase 3 | Phase 4 | Phase 5 | Phase 6 (final) |
|--------|---------|---------|---------|------------------|
| `cargo check --workspace --tests` | 0 err / 0 warn | 0 err / 0 warn | 0 err / 0 warn | 0 err / 0 warn |
| `cargo test --workspace` | all pass | 757 pass | 757 pass | **757 pass / 0 fail** |

Final per-binary test totals (Phase 6):

```
tzap-cli unit tests           22
tzap-cli integration "cli"   185      (declared: 63 create + 34 extract + 23 verify
                                       + 28 keywrap + 43 cross-cutting/list;
                                       run: 60 + 34 + 23 + 28 + 40 = 185,
                                       6 platform-gated tests excluded on macOS)
tzap-cli integration cli_errors  10
tzap-cli crates_io_metadata    6
tzap-cli public_docs          11
tzap-cli release_workflows     7
tzap-core unit tests         441
tzap-core v45_corpus          24
tzap-plugin-keywrap unit      20
tzap-plugin-signing unit      31
TOTAL                        757
```

The pre-split cli_smoke binary ran 195 tests on macOS (201 declared, 6
platform-gated); post-split discovery is unchanged (185 + 10 = 195), so the
same tests execute under the same platform gates.

## Compatibility Notes

- No public API path changed: `tzap-core` crate-root re-exports and all
  public items in `tzap-core`/`tzap-cli` remain at their original paths.
- Wire format untouched: the v45 corpus fixture suite (`v45_corpus.rs`, 24
  tests) passes byte-for-byte, exercising the on-disk archive format.
- CLI surface untouched: `public_docs.rs` (11 tests) pins documented CLI
  behavior including help text, and the 185 cli integration tests pin flags,
  exit codes, and stdout/stderr byte streams.
