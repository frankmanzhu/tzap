#!/usr/bin/env bash
set -euo pipefail

# Ensure script is run from project root
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [ $# -ne 1 ]; then
    echo "Usage: $0 <new-version> (e.g. 0.2.3 or v0.2.3)"
    exit 1
fi

NEW_VERSION="${1#v}"

if ! [[ "$NEW_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
    echo "Error: Version '$NEW_VERSION' is not a valid SemVer string (e.g. 0.2.3)."
    exit 1
fi

echo "==> Bumping workspace version to ${NEW_VERSION}..."

# Update root Cargo.toml [workspace.package] version
sed -i.bak -E "s/^version = \"[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?\"/version = \"${NEW_VERSION}\"/" Cargo.toml
# Update workspace.dependencies version strings for inter-crate paths in Cargo.toml
sed -i.bak -E "s/(tzap-[a-z-]+ = \{ path = \"[^\"]+\", version = \")[^\"]+(\" \})/\1${NEW_VERSION}\2/g" Cargo.toml
rm -f Cargo.toml.bak

echo "==> Updating root Cargo.lock..."
cargo check --workspace

echo "==> Updating fuzz/Cargo.lock..."
cargo check --manifest-path fuzz/Cargo.toml

echo "==> Verifying --locked compatibility..."
cargo check --workspace --locked
cargo check --manifest-path fuzz/Cargo.toml --locked

echo "Successfully bumped workspace version to ${NEW_VERSION}!"
