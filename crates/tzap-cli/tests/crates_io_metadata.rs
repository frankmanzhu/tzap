use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn workspace_file(path: &str) -> PathBuf {
    workspace_root().join(path)
}

fn read_workspace_file(path: &str) -> String {
    fs::read_to_string(workspace_file(path))
        .unwrap()
        .replace("\r\n", "\n")
}

fn manifest_string_value(manifest: &str, key: &str) -> String {
    let prefix = format!("{key} = ");
    let line = manifest
        .lines()
        .find(|line| line.trim_start().starts_with(&prefix))
        .unwrap_or_else(|| panic!("missing manifest key `{key}`"));
    line.trim_start()
        .strip_prefix(&prefix)
        .unwrap()
        .trim()
        .trim_matches('"')
        .to_string()
}

fn manifest_array_values(manifest: &str, key: &str) -> Vec<String> {
    let prefix = format!("{key} = [");
    let start = manifest
        .find(&prefix)
        .unwrap_or_else(|| panic!("missing manifest array `{key}`"))
        + prefix.len();
    let end = manifest[start..]
        .find(']')
        .unwrap_or_else(|| panic!("unterminated manifest array `{key}`"))
        + start;

    manifest[start..end]
        .split(',')
        .map(|item| item.trim().trim_matches('"'))
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn assert_package_metadata(
    manifest_path: &str,
    crate_name: &str,
    expected_version: &str,
    docs_url: &str,
    expected_description_fragment: &str,
) {
    let manifest = read_workspace_file(manifest_path);

    assert!(manifest.contains(&format!("name = \"{crate_name}\"")));
    assert!(manifest.contains(&format!("version = \"{expected_version}\"")));
    assert!(manifest.contains("repository.workspace = true"));
    assert!(manifest.contains(&format!("documentation = \"{docs_url}\"")));
    assert_eq!(manifest_string_value(&manifest, "readme"), "README.md");

    let description = manifest_string_value(&manifest, "description");
    assert!(
        description.contains(expected_description_fragment),
        "description `{description}` should mention `{expected_description_fragment}`"
    );
    assert!(
        !manifest.contains("description.workspace = true"),
        "{crate_name} must use a package-specific description"
    );

    let readme = workspace_file(manifest_path)
        .parent()
        .unwrap()
        .join("README.md");
    assert!(readme.is_file(), "{crate_name} readme should exist");
}

#[test]
fn manifests_have_crates_io_metadata() {
    assert_package_metadata(
        "crates/tzap-core/Cargo.toml",
        "tzap-core",
        "0.2.0",
        "https://docs.rs/tzap-core",
        "Core library",
    );
    assert_package_metadata(
        "crates/tzap-cli/Cargo.toml",
        "tzap",
        "0.2.0",
        "https://docs.rs/tzap",
        "Fast encrypted archive CLI",
    );
    assert_package_metadata(
        "crates/tzap-plugin-signing/Cargo.toml",
        "tzap-plugin-signing",
        "0.2.0",
        "https://docs.rs/tzap-plugin-signing",
        "Signing profiles",
    );
    assert_package_metadata(
        "crates/tzap-plugin-keywrap/Cargo.toml",
        "tzap-plugin-keywrap",
        "0.2.0",
        "https://docs.rs/tzap-plugin-keywrap",
        "HPKE key-wrap",
    );
}

#[test]
fn publish_dependencies_are_versioned() {
    let manifest = read_workspace_file("crates/tzap-cli/Cargo.toml");
    let plugin_manifest = read_workspace_file("crates/tzap-plugin-signing/Cargo.toml");

    assert!(manifest.contains(r#"tzap-core = { path = "../tzap-core", version = "0.2.0" }"#));
    assert!(manifest.contains(
        r#"tzap-plugin-signing = { path = "../tzap-plugin-signing", version = "0.2.0" }"#
    ));
    assert!(manifest.contains(
        r#"tzap-plugin-keywrap = { path = "../tzap-plugin-keywrap", version = "0.2.0" }"#
    ));
    assert!(
        plugin_manifest.contains(r#"tzap-core = { path = "../tzap-core", version = "0.2.0" }"#)
    );

    let keywrap_manifest = read_workspace_file("crates/tzap-plugin-keywrap/Cargo.toml");
    assert!(
        keywrap_manifest.contains(r#"tzap-core = { path = "../tzap-core", version = "0.2.0" }"#)
    );
    assert!(keywrap_manifest.contains("x509-parser.workspace = true"));
}

#[test]
fn keywords_and_categories_fit_crates_io_limits() {
    for manifest_path in [
        "Cargo.toml",
        "crates/tzap-core/Cargo.toml",
        "crates/tzap-cli/Cargo.toml",
        "crates/tzap-plugin-signing/Cargo.toml",
        "crates/tzap-plugin-keywrap/Cargo.toml",
    ] {
        let manifest = read_workspace_file(manifest_path);
        let keywords = manifest_array_values(&manifest, "keywords");
        let categories = manifest_array_values(&manifest, "categories");

        assert!(
            !keywords.is_empty() && keywords.len() <= 5,
            "{manifest_path} should define one to five keywords"
        );
        assert!(
            !categories.is_empty() && categories.len() <= 5,
            "{manifest_path} should define one to five categories"
        );

        for keyword in keywords {
            assert!(
                keyword.len() <= 20
                    && keyword
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'),
                "`{keyword}` in {manifest_path} is not crates.io keyword-shaped"
            );
        }
    }
}

#[test]
fn package_readmes_render_without_workspace_paths() {
    let root_readme = read_workspace_file("README.md");
    let cli_readme = read_workspace_file("crates/tzap-cli/README.md");
    let core_readme = read_workspace_file("crates/tzap-core/README.md");
    let signing_readme = read_workspace_file("crates/tzap-plugin-signing/README.md");
    let keywrap_readme = read_workspace_file("crates/tzap-plugin-keywrap/README.md");

    assert!(root_readme.contains("cargo install tzap"));
    assert!(cli_readme.contains("# tzap"));
    assert!(cli_readme.contains("cargo install tzap"));
    assert!(cli_readme.contains("tzap create --keyfile"));
    assert!(core_readme.contains("# tzap-core"));
    assert!(core_readme.contains("use tzap_core::"));
    assert!(core_readme.contains("write_archive"));
    assert!(core_readme.contains("standalone archive foundation"));
    assert!(signing_readme.contains("# tzap-plugin-signing"));
    assert!(signing_readme.contains("tzap-plugin-signing = \"0.2.0\""));
    assert!(signing_readme.contains("authenticator_value_for_request"));
    assert!(keywrap_readme.contains("# tzap-plugin-keywrap"));
    assert!(keywrap_readme.contains("tzap-core"));
    assert!(keywrap_readme.contains("RecipientWrap"));

    for readme in [cli_readme, core_readme, signing_readme, keywrap_readme] {
        assert!(
            !readme.contains("../"),
            "package README should use publish-safe links"
        );
        assert!(
            readme.contains("https://github.com/tzap-org/tzap"),
            "package README should link to the repository"
        );
    }
}

#[test]
fn package_trees_are_small_and_focused() {
    for package_dir in [
        "crates/tzap-core",
        "crates/tzap-cli",
        "crates/tzap-plugin-signing",
        "crates/tzap-plugin-keywrap",
    ] {
        let package_dir = workspace_file(package_dir);
        let mut pending = vec![package_dir.clone()];
        while let Some(path) = pending.pop() {
            for entry in fs::read_dir(&path).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                let relative = path.strip_prefix(&package_dir).unwrap();
                let root_name = relative
                    .components()
                    .next()
                    .unwrap()
                    .as_os_str()
                    .to_string_lossy();

                assert!(
                    ["Cargo.toml", "README.md", "src", "tests"].contains(&root_name.as_ref()),
                    "unexpected package file: {}",
                    relative.display()
                );

                if path.is_dir() {
                    pending.push(path);
                } else {
                    let len = entry.metadata().unwrap().len();
                    assert!(
                        len < 1_000_000,
                        "package file {} is unexpectedly large ({len} bytes)",
                        relative.display()
                    );
                }
            }
        }
    }
}

#[test]
fn public_package_docs_do_not_link_private_docs() {
    let root_readme = read_workspace_file("README.md");
    let cli_readme = read_workspace_file("crates/tzap-cli/README.md");
    let signing_readme = read_workspace_file("crates/tzap-plugin-signing/README.md");
    let keywrap_readme = read_workspace_file("crates/tzap-plugin-keywrap/README.md");
    let root_manifest = read_workspace_file("Cargo.toml");

    assert!(root_manifest.contains(
        "documentation = \"https://github.com/tzap-org/tzap/blob/main/specs/tzap-format-revisedv45.md\""
    ));
    assert!(root_readme.contains("specs/tzap-format-revisedv45.md"));
    assert!(root_readme.contains("public-docs/tzap-cli-reference.md"));
    assert!(cli_readme.contains("specs/tzap-format-revisedv45.md"));
    assert!(cli_readme.contains("public-docs/tzap-cli-reference.md"));
    assert!(signing_readme.contains("specs/tzap-format-revisedv45.md"));
    assert!(keywrap_readme.contains("specs/tzap-format-revisedv45.md"));
    assert!(!root_readme.contains("](docs/"));
    assert!(!root_readme.contains("blob/main/docs/"));
    assert!(!cli_readme.contains("](docs/"));
    assert!(!cli_readme.contains("blob/main/docs/"));
    assert!(!signing_readme.contains("](docs/"));
    assert!(!signing_readme.contains("blob/main/docs/"));
    assert!(!keywrap_readme.contains("](docs/"));
    assert!(!keywrap_readme.contains("blob/main/docs/"));
}
