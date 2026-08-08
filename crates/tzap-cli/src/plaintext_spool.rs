use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use rand::RngCore;

const SPOOL_PREFIX: &str = ".tzap-plaintext-spool-";
const COPY_BUFFER_LEN: usize = 64 * 1024;
const TEMP_NAME_ATTEMPTS: usize = 128;

#[derive(Debug, Clone, Copy)]
pub(crate) struct ExplicitPlaintextSpool;

impl ExplicitPlaintextSpool {
    pub(crate) fn acknowledge_plaintext_spool() -> Self {
        Self
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct KnownSizePlaintextSource {
    size: u64,
}

impl KnownSizePlaintextSource {
    pub(crate) fn size(&self) -> u64 {
        self.size
    }
}

#[derive(Debug)]
pub(crate) struct PlaintextSpool {
    path: PathBuf,
    file: Option<File>,
    size: u64,
}

impl PlaintextSpool {
    pub(crate) fn known_size_source(&self) -> KnownSizePlaintextSource {
        KnownSizePlaintextSource { size: self.size }
    }

    #[cfg(test)]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn reopen(&self) -> Result<File> {
        File::open(&self.path).with_context(|| format!("failed to reopen plaintext spool {}", self.path.display()))
    }
}

impl Drop for PlaintextSpool {
    fn drop(&mut self) {
        if let Some(mut file) = self.file.take() {
            let _ = file.flush();
            drop(file);
        }
        let _ = fs::remove_file(&self.path);
    }
}

pub(crate) fn spool_unknown_size_raw_stdin<R: Read>(reader: R, max_plaintext_bytes: u64, explicit: ExplicitPlaintextSpool) -> Result<PlaintextSpool> {
    spool_unknown_size_raw_stdin_in(reader, env::temp_dir(), max_plaintext_bytes, explicit)
}

pub(crate) fn spool_unknown_size_raw_stdin_in<R: Read>(
    mut reader: R,
    temp_dir: impl AsRef<Path>,
    max_plaintext_bytes: u64,
    _explicit: ExplicitPlaintextSpool,
) -> Result<PlaintextSpool> {
    let (path, file) = create_restrictive_temp_file(temp_dir.as_ref())?;
    let mut spool = PlaintextSpool {
        path,
        file: Some(file),
        size: 0,
    };
    let mut buffer = [0u8; COPY_BUFFER_LEN];

    loop {
        let read = reader.read(&mut buffer).context("failed to read raw stdin for plaintext spool")?;
        if read == 0 {
            break;
        }
        let read = read as u64;
        if read > max_plaintext_bytes.saturating_sub(spool.size) {
            bail!("plaintext spool cap exceeded: raw stdin is larger than {} bytes", max_plaintext_bytes);
        }
        spool
            .file
            .as_mut()
            .expect("spool file is present until drop")
            .write_all(&buffer[..read as usize])
            .context("failed to write plaintext spool")?;
        spool.size += read;
    }

    spool
        .file
        .as_mut()
        .expect("spool file is present until drop")
        .flush()
        .context("failed to flush plaintext spool")?;
    Ok(spool)
}

fn create_restrictive_temp_file(temp_dir: &Path) -> Result<(PathBuf, File)> {
    for _ in 0..TEMP_NAME_ATTEMPTS {
        let mut suffix = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut suffix);
        let mut name = format!("{SPOOL_PREFIX}{}-", std::process::id());
        for byte in suffix {
            let _ = std::fmt::Write::write_fmt(&mut name, format_args!("{byte:02x}"));
        }
        name.push_str(".tmp");
        let candidate = temp_dir.join(name);
        match open_restrictive_new_file(&candidate) {
            Ok(file) => return Ok((candidate, file)),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err).with_context(|| format!("failed to create plaintext spool {}", candidate.display()));
            }
        }
    }
    bail!("failed to reserve a unique plaintext spool path in {}", temp_dir.display())
}

fn open_restrictive_new_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    options.open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;

    use tempfile::tempdir;

    fn explicit() -> ExplicitPlaintextSpool {
        ExplicitPlaintextSpool::acknowledge_plaintext_spool()
    }

    #[test]
    fn spools_plaintext_to_known_size_source_and_removes_on_drop() {
        let tempdir = tempdir().unwrap();
        let spool = spool_unknown_size_raw_stdin_in(Cursor::new(b"raw stdin bytes".to_vec()), tempdir.path(), 1024, explicit()).unwrap();
        let source = spool.known_size_source();
        let spool_path = spool.path().to_path_buf();

        assert_eq!(source.size(), 15);
        assert!(spool_path.exists());
        assert_eq!(fs::read(&spool_path).unwrap(), b"raw stdin bytes");
        let mut reopened = Vec::new();
        spool.reopen().unwrap().read_to_end(&mut reopened).unwrap();
        assert_eq!(reopened, b"raw stdin bytes");

        drop(spool);

        assert!(!spool_path.exists());
    }

    #[test]
    fn cap_excess_returns_error_and_removes_partial_spool() {
        let tempdir = tempdir().unwrap();
        let err = spool_unknown_size_raw_stdin_in(Cursor::new(vec![0x5a; 10]), tempdir.path(), 9, explicit()).unwrap_err();

        assert!(err.to_string().contains("plaintext spool cap exceeded"));
        assert_eq!(fs::read_dir(tempdir.path()).unwrap().count(), 0);
    }

    #[test]
    fn zero_byte_cap_allows_empty_raw_stdin_only() {
        let tempdir = tempdir().unwrap();
        let empty = spool_unknown_size_raw_stdin_in(Cursor::new(Vec::new()), tempdir.path(), 0, explicit()).unwrap();
        assert_eq!(empty.known_size_source().size(), 0);
        drop(empty);

        let err = spool_unknown_size_raw_stdin_in(Cursor::new(vec![1]), tempdir.path(), 0, explicit()).unwrap_err();
        assert!(err.to_string().contains("plaintext spool cap exceeded"));
        assert_eq!(fs::read_dir(tempdir.path()).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn temp_file_uses_owner_only_permissions_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let tempdir = tempdir().unwrap();
        let spool = spool_unknown_size_raw_stdin_in(Cursor::new(vec![1, 2, 3]), tempdir.path(), 3, explicit()).unwrap();
        let mode = fs::metadata(spool.path()).unwrap().permissions().mode() & 0o777;

        assert_eq!(mode, 0o600);
    }
}
