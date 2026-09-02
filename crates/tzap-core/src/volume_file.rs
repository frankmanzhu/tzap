//! On-disk volume file naming conventions and sibling discovery.
//!
//! A multi-volume archive is stored as one file per volume named
//! `{base}.vol{index}.tzap` with a zero-padded, three-digit index
//! (`backup.vol000.tzap`, `backup.vol001.tzap`, ...). Single-volume archives
//! are stored at the requested path with no volume suffix. This module is the
//! single owner of that convention: consumers (the CLI, zmanager, and any
//! other host) parse, format, and discover volume names through these helpers
//! instead of re-implementing the pattern.

use std::io;
use std::path::{Path, PathBuf};

/// The archive file extension, without the leading dot.
pub const TZAP_EXTENSION: &str = "tzap";
/// The archive file extension, with the leading dot.
pub const TZAP_EXTENSION_SUFFIX: &str = ".tzap";
/// Separator between the base name and the volume index in a volume file name.
pub const TZAP_VOLUME_MARKER: &str = ".vol";
/// Zero-padded width of the volume index in a volume file name.
pub const TZAP_VOLUME_INDEX_WIDTH: usize = 3;

/// A parsed `{base}.vol{index}.tzap` volume file name.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VolumeFileName {
    /// The archive base name (the `.vol{index}.tzap` suffix stripped).
    pub base: String,
    /// The zero-based volume index encoded in the file name.
    pub volume_index: usize,
}

/// Parses a volume file name (`{base}.vol{index}.tzap`) into its base and
/// index. The extension match is case-insensitive; the volume index must be a
/// non-empty run of ASCII digits.
pub fn parse_volume_file_name(file_name: &str) -> Option<VolumeFileName> {
    let stem = strip_case_insensitive_suffix(file_name, TZAP_EXTENSION_SUFFIX)?;
    let (base, digits) = stem.rsplit_once(TZAP_VOLUME_MARKER)?;
    if base.is_empty() || digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(VolumeFileName { base: base.to_owned(), volume_index: digits.parse().ok()? })
}

/// Returns the volume base name for a file name: the `.tzap` suffix is
/// stripped when present (case-insensitively), otherwise the name is returned
/// unchanged.
pub fn multi_volume_base_name(file_name: &str) -> String {
    strip_case_insensitive_suffix(file_name, TZAP_EXTENSION_SUFFIX).unwrap_or(file_name).to_owned()
}

/// Formats a volume file name for the given base and zero-based index, e.g.
/// `backup.vol001.tzap`.
#[must_use]
pub fn volume_file_name(base: &str, zero_based_index: usize) -> String {
    format!("{base}{TZAP_VOLUME_MARKER}{zero_based_index:0TZAP_VOLUME_INDEX_WIDTH$}{TZAP_EXTENSION_SUFFIX}")
}

/// Returns the output path for volume `zero_based_index` of the archive
/// addressed by `destination`, following the multi-volume naming convention.
pub fn volume_output_path(destination: &Path, zero_based_index: usize) -> PathBuf {
    let Some(file_name) = destination.file_name().and_then(|name| name.to_str()) else {
        let mut path = destination.as_os_str().to_os_string();
        path.push(volume_file_name("", zero_based_index));
        return PathBuf::from(path);
    };
    let base = multi_volume_base_name(file_name);
    match destination.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        Some(parent) => parent.join(volume_file_name(&base, zero_based_index)),
        None => PathBuf::from(volume_file_name(&base, zero_based_index)),
    }
}

/// Discovers sibling volume files for the given base name in `parent`,
/// ordered by volume index (then by path for deterministic ordering of
/// duplicate indexes).
///
/// Individual entries that cannot be read are skipped, matching how other
/// archive tools enumerate sibling volumes: an unreadable entry is not a
/// volume candidate, so it must not fail the discovery.
///
/// # Errors
///
/// Returns an error when the directory itself cannot be read.
pub fn discover_sibling_volume_paths(parent: &Path, base: &str) -> io::Result<Vec<PathBuf>> {
    let entries = std::fs::read_dir(parent)?;
    let mut paths = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else { continue };
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        if let Some(candidate) = parse_volume_file_name(file_name) {
            if candidate.base == base {
                paths.push((candidate.volume_index, entry.path()));
            }
        }
    }
    paths.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    Ok(paths.into_iter().map(|(_, path)| path).collect())
}

fn strip_case_insensitive_suffix<'a>(value: &'a str, suffix: &str) -> Option<&'a str> {
    if value.len() < suffix.len() {
        return None;
    }
    let split_at = value.len() - suffix.len();
    let (head, tail) = (value.get(..split_at)?, value.get(split_at..)?);
    if tail.eq_ignore_ascii_case(suffix) {
        Some(head)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{
        discover_sibling_volume_paths, multi_volume_base_name, parse_volume_file_name, volume_file_name, volume_output_path, TZAP_EXTENSION_SUFFIX,
        TZAP_VOLUME_INDEX_WIDTH, TZAP_VOLUME_MARKER,
    };
    use std::fs;
    use std::path::Path;

    #[test]
    fn parses_volume_file_names() {
        let pattern = parse_volume_file_name("backup.vol000.tzap").expect("parse");
        assert_eq!(pattern.base, "backup");
        assert_eq!(pattern.volume_index, 0);
        let pattern = parse_volume_file_name("backup.vol042.TZAP").expect("parse");
        assert_eq!(pattern.volume_index, 42);
        assert_eq!(parse_volume_file_name("backup.tzap"), None);
        assert_eq!(parse_volume_file_name("backup.vol.tzap"), None);
        assert_eq!(parse_volume_file_name("backup.vol00a.tzap"), None);
        assert_eq!(parse_volume_file_name("backup.zip.000"), None);
    }

    #[test]
    fn multi_volume_base_name_strips_extension_case_insensitively() {
        assert_eq!(multi_volume_base_name("backup.tzap"), "backup");
        assert_eq!(multi_volume_base_name("backup.TZAP"), "backup");
        assert_eq!(multi_volume_base_name("backup"), "backup");
    }

    #[test]
    fn non_tzap_unicode_names_do_not_panic_during_suffix_checks() {
        let name = "金庸-神雕侠侣txt精校版.txt";
        assert_eq!(parse_volume_file_name(name), None);
        assert_eq!(multi_volume_base_name(name), name);
    }

    #[test]
    fn formats_volume_file_names_with_zero_padded_width() {
        assert_eq!(volume_file_name("backup", 0), "backup.vol000.tzap");
        assert_eq!(volume_file_name("backup", 1), "backup.vol001.tzap");
        assert_eq!(volume_file_name("backup", 999), "backup.vol999.tzap");
    }

    #[test]
    fn volume_output_path_follows_destination_parent() {
        assert_eq!(volume_output_path(Path::new("dir/backup.tzap"), 1), Path::new("dir/backup.vol001.tzap"),);
        assert_eq!(volume_output_path(Path::new("backup"), 0), Path::new("backup.vol000.tzap"),);
        assert_eq!(volume_output_path(Path::new("backup.tzap"), 2), Path::new("backup.vol002.tzap"),);
    }

    #[test]
    fn discovers_sibling_volume_paths_sorted_by_index() {
        let temp = std::env::temp_dir().join(format!("tzap-volume-file-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp);
        fs::create_dir_all(&temp).expect("create temp dir");
        for name in ["backup.vol001.tzap", "backup.vol000.tzap", "backup.tzap", "other.vol000.tzap"] {
            fs::write(temp.join(name), []).expect("write fixture");
        }

        let discovered = discover_sibling_volume_paths(&temp, "backup").expect("discover");
        let names: Vec<String> = discovered.iter().map(|path| path.file_name().unwrap().to_string_lossy().into_owned()).collect();
        assert_eq!(names, ["backup.vol000.tzap", "backup.vol001.tzap"]);

        let _ = fs::remove_dir_all(&temp);
    }

    #[test]
    fn round_trips_marker_and_width_constants() {
        assert_eq!(TZAP_EXTENSION_SUFFIX, ".tzap");
        assert_eq!(TZAP_VOLUME_MARKER, ".vol");
        assert_eq!(TZAP_VOLUME_INDEX_WIDTH, 3);
    }
}
