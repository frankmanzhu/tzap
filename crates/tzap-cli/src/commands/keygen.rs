use super::*;

use std::io::{self, Write};
use std::path::Path;

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use rand::RngCore;

pub(crate) fn run_keygen(quiet: bool, args: KeygenArgs) -> Result<()> {
    let KeygenArgs { output, stdout, force } = args;

    let bytes = generate_random_key_material()?;
    let key_hex = format!("{}\n", encode_hex(&bytes));
    if stdout {
        print!("{}", key_hex);
        io::stdout().flush()?;
        return Ok(());
    }
    let output = output.expect("--output required by clap");
    write_keyfile(&output, &key_hex, force).context("failed to write keyfile")?;
    emit_success_summary(quiet, &format!("wrote keyfile to {}", output))?;
    Ok(())
}

pub(crate) fn run_signing_keygen(quiet: bool, args: SigningKeygenArgs) -> Result<()> {
    let SigningKeygenArgs {
        secret_output,
        public_output,
        force,
    } = args;

    ensure_distinct_output_paths(
        "signing secret output",
        Path::new(&secret_output),
        "signing public output",
        Path::new(&public_output),
    )?;
    if !force {
        check_output_path_free("signing secret output", Path::new(&secret_output))?;
        check_output_path_free("signing public output", Path::new(&public_output))?;
    }
    let signing_key = generate_ed25519_signing_key();
    let secret_hex = format!("{}\n", encode_hex(&signing_key.to_bytes()));
    let public_hex = format!("{}\n", encode_hex(&signing_key.verifying_key().to_bytes()));
    write_atomic_output_files(
        &[
            AtomicOutput {
                label: "signing secret",
                path: Path::new(&secret_output),
                bytes: secret_hex.as_bytes(),
            },
            AtomicOutput {
                label: "signing public key",
                path: Path::new(&public_output),
                bytes: public_hex.as_bytes(),
            },
        ],
        force,
    )?;
    emit_success_summary(quiet, &format!("wrote signing keypair to {secret_output} and {public_output}"))?;
    Ok(())
}

pub(crate) struct KeygenArgs {
    pub(crate) output: Option<String>,
    pub(crate) stdout: bool,
    pub(crate) force: bool,
}

pub(crate) struct SigningKeygenArgs {
    pub(crate) secret_output: String,
    pub(crate) public_output: String,
    pub(crate) force: bool,
}

pub(crate) fn generate_random_key_material() -> Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    Ok(bytes)
}

pub(crate) fn generate_ed25519_signing_key() -> SigningKey {
    SigningKey::generate(&mut rand::rngs::OsRng)
}

pub(crate) fn write_keyfile(path: &str, key_hex: &str, force: bool) -> Result<()> {
    write_atomic_output_file("keyfile", Path::new(path), key_hex.as_bytes(), force)
}
