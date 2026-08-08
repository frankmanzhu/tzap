use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn read_workspace_file(path: &str) -> String {
    fs::read_to_string(workspace_root().join(path)).unwrap().replace("\r\n", "\n")
}

fn assert_contains_in_order(text: &str, labels: &[&str]) {
    let mut offset = 0usize;
    for label in labels {
        let relative = text[offset..]
            .find(label)
            .unwrap_or_else(|| panic!("missing {label:?} after byte offset {offset}"));
        offset += relative + label.len();
    }
}

#[test]
fn ci_workflow_has_cross_platform_matrix() {
    let workflow = read_workspace_file(".github/workflows/ci.yml");

    assert!(workflow.contains("include:"));
    assert!(workflow.contains("os: ubuntu-22.04"));
    assert!(workflow.contains("os: macos-15-intel"));
    assert!(workflow.contains("os: macos-14"));
    assert!(workflow.contains("os: windows-2022"));
    assert!(workflow.contains("release-artifacts:"));
    assert!(workflow.contains("Release artifact ${{ matrix.name }}"));
    assert!(workflow.contains("x86_64-unknown-linux-musl"));
    assert!(workflow.contains("aarch64-unknown-linux-musl"));
    assert!(workflow.contains("x86_64-pc-windows-msvc"));
    assert!(workflow.contains("aarch64-pc-windows-msvc"));
    assert!(workflow.contains("Install musl tools"));
    assert!(workflow.contains("CC_x86_64_unknown_linux_musl=musl-gcc"));
    assert!(workflow.contains("Install QEMU"));
    assert!(workflow.contains("qemu-aarch64-static"));
    assert!(workflow.contains("Install cross"));
    assert!(workflow.contains("cross build --locked --release -p tzap --target ${{ matrix.target }}"));
    assert!(workflow.contains("Smoke test release binary"));
    assert!(workflow.contains("matrix.run_fmt"));
    assert!(workflow.contains("cargo fmt --all -- --check"));
    assert!(workflow.contains("cargo check --workspace --all-targets --locked"));
    assert!(workflow.contains("cargo test --workspace --locked"));
    assert!(workflow.contains("cmp \"$WORKDIR/input.txt\" \"$WORKDIR/out/input.txt\""));
    assert!(!workflow.contains("ubuntu-latest"));
    assert!(!workflow.contains("macos-latest"));
    assert!(!workflow.contains("windows-latest"));
}

#[test]
fn release_workflow_has_all_release_archives() {
    let workflow = read_workspace_file(".github/workflows/release.yml");

    assert!(workflow.contains("tzap-${{ github.ref_name }}-linux-x86_64-musl.tar.gz"));
    assert!(workflow.contains("tzap-${{ github.ref_name }}-linux-aarch64-musl.tar.gz"));
    assert!(workflow.contains("tzap-${{ github.ref_name }}-macos-x86_64.tar.gz"));
    assert!(workflow.contains("tzap-${{ github.ref_name }}-macos-aarch64.tar.gz"));
    assert!(workflow.contains("tzap-${{ github.ref_name }}-windows-x86_64.zip"));
    assert!(workflow.contains("tzap-${{ github.ref_name }}-windows-aarch64.zip"));
    assert!(!workflow.contains("tzap-${{ github.ref_name }}-linux-x86_64.tar.gz"));
}

#[test]
fn release_workflow_targets_distinct_build_triples() {
    let workflow = read_workspace_file(".github/workflows/release.yml");

    assert!(workflow.contains("x86_64-unknown-linux-musl"));
    assert!(workflow.contains("aarch64-unknown-linux-musl"));
    assert!(workflow.contains("x86_64-apple-darwin"));
    assert!(workflow.contains("aarch64-apple-darwin"));
    assert!(workflow.contains("x86_64-pc-windows-msvc"));
    assert!(workflow.contains("aarch64-pc-windows-msvc"));
    assert!(!workflow.contains("x86_64-unknown-linux-gnu"));
}

#[test]
fn release_workflow_uses_pinned_baseline_runners() {
    let workflow = read_workspace_file(".github/workflows/release.yml");

    assert!(workflow.contains("os: ubuntu-22.04"));
    assert!(workflow.contains("os: macos-15-intel"));
    assert!(workflow.contains("os: macos-14"));
    assert!(workflow.contains("os: windows-2022"));
    assert!(workflow.contains("runs-on: ubuntu-22.04"));
    assert!(workflow.contains("MACOSX_DEPLOYMENT_TARGET"));
    assert!(workflow.contains(r#"macosx_deployment_target: "10.12""#));
    assert!(workflow.contains(r#"macosx_deployment_target: "11.0""#));
    assert!(workflow.contains("musl-tools"));
    assert!(workflow.contains("CC_x86_64_unknown_linux_musl=musl-gcc"));
    assert!(workflow.contains("qemu-user-static"));
    assert!(workflow.contains("cargo install cross --locked"));
    assert!(workflow.contains("target-feature=+crt-static"));
    assert!(!workflow.contains("ubuntu-latest"));
    assert!(!workflow.contains("macos-latest"));
    assert!(!workflow.contains("windows-latest"));
}

#[test]
fn release_workflow_has_smoke_checks() {
    let workflow = read_workspace_file(".github/workflows/release.yml");

    assert!(workflow.contains("preflight:"));
    assert!(workflow.contains("needs: preflight"));
    assert_eq!(workflow.matches("run_smoke: true").count(), 5);
    for command in [
        "cargo fmt --all -- --check",
        "cargo check --workspace --all-targets --locked",
        "cargo test --workspace --locked",
        "cargo clippy --workspace --all-targets -- -D warnings",
        "cargo run --manifest-path fuzz/Cargo.toml --bin fuzz_smoke --locked",
        "cargo check --manifest-path fuzz/Cargo.toml --bins --features libfuzzer --locked",
        "cargo install cargo-audit --locked",
        "cargo audit",
    ] {
        assert!(workflow.contains(command), "release workflow missing preflight command {command:?}");
    }

    assert!(workflow.contains("Smoke test artifact (Unix)"));
    assert!(workflow.contains("Smoke test artifact (Windows)"));
    assert!(workflow.contains("--version"));
    assert!(workflow.contains("--help"));
    assert!(workflow.contains("tzap.exe"));
    assert!(workflow.contains("tar -xzf \"dist/${{ matrix.archive }}\""));
    assert!(workflow.contains("Expand-Archive -Path \"dist/${{ matrix.archive }}\""));
    assert!(workflow.contains("create --password-stdin --argon2-t-cost 1 --argon2-m-cost-kib 8 --argon2-parallelism 1"));
    assert!(workflow.contains("list --password-stdin"));
    assert!(workflow.contains("verify --password-stdin"));
    assert!(workflow.contains("extract --password-stdin --directory"));
    assert!(workflow.contains("grep -F \"input.txt\""));
    assert!(workflow.contains("release smoke list output did not include input.txt"));
    assert!(workflow.contains("cmp \"$WORKDIR/input.txt\" \"$WORKDIR/out/input.txt\""));
    assert!(workflow.contains("release smoke payload mismatch"));
    assert!(!workflow.contains("Smoke test build"));
    assert_contains_in_order(
        &workflow,
        &[
            "Package Unix",
            "Smoke test artifact (Unix)",
            "Generate checksum (Unix)",
            "Package Windows",
            "Smoke test artifact (Windows)",
            "Generate checksum (Windows)",
            "Upload asset",
        ],
    );
}

#[test]
fn release_workflow_uploads_checksum_artifacts() {
    let workflow = read_workspace_file(".github/workflows/release.yml");

    assert!(workflow.contains("permissions:\n  contents: read\n\njobs:"));
    assert_contains_in_order(
        &workflow,
        &[
            "build:",
            "permissions:",
            "contents: read",
            "id-token: write",
            "attestations: write",
            "strategy:",
        ],
    );
    assert_contains_in_order(
        &workflow,
        &[
            "publish:",
            "permissions:",
            "contents: write",
            "id-token: write",
            "attestations: write",
            "steps:",
        ],
    );
    assert!(workflow.contains("id-token: write"));
    assert!(workflow.contains("attestations: write"));
    assert!(!workflow.contains("artifact-metadata: write"));
    assert!(workflow.contains("Generate checksum (Unix)"));
    assert!(workflow.contains("Generate checksum (Windows)"));
    assert!(workflow.contains("${{ matrix.archive }}.sha256"));
    assert!(workflow.contains("dist/${{ matrix.archive }}.sha256"));
    assert!(workflow.contains("Merge checksum manifest"));
    assert!(workflow.contains("SHA256SUMS"));
    assert!(workflow.contains("Attest release artifact"));
    assert!(workflow.contains("uses: actions/attest@v4"));
    assert!(workflow.contains("subject-path: dist/*"));
    assert!(workflow.contains("Install cosign"));
    assert!(workflow.contains("uses: sigstore/cosign-installer@v3"));
    assert!(workflow.contains("cosign sign-blob --yes --bundle SHA256SUMS.sigstore.json SHA256SUMS"));
    assert!(workflow.contains("Attest checksum manifest"));
    assert!(workflow.contains("subject-path: dist/SHA256SUMS"));
    assert_contains_in_order(&workflow, &["homebrew:", "needs: build", "brew install --formula"]);
    assert!(workflow.contains("tzap-org/tzap-release-test"));
    assert!(!workflow.contains("frankmanzhu/tzap-release-test"));
    assert!(workflow.contains("HOMEBREW_NO_SANDBOX_LINUX: 1"));
    assert_contains_in_order(
        &workflow,
        &[
            "publish:",
            "needs:",
            "- build",
            "- homebrew",
            "Merge checksum manifest",
            "Sign checksum manifest",
            "Attest checksum manifest",
            "Publish release",
        ],
    );
}

#[test]
fn internal_docs_are_not_public_release_inputs() {
    let gitignore = read_workspace_file(".gitignore");
    let workflow = read_workspace_file(".github/workflows/release.yml");

    assert!(gitignore.contains("/docs/"));
    assert!(gitignore.contains("/implementation-docs/"));
    assert!(!gitignore.contains("!/docs/"));
    assert!(!workflow.contains("docs/tzap-"));
}
