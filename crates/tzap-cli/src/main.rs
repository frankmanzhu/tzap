use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;

mod plaintext_spool;

const DEFAULT_ARGON2_T_COST: u32 = 3;
const DEFAULT_ARGON2_M_COST_KIB: u32 = 262_144;
const DEFAULT_ARGON2_PARALLELISM: u32 = 4;
const DEFAULT_ARGON2_SALT_LEN: usize = 16;
const INSECURE_ZERO_KEY: [u8; 32] = [0; 32];
const LARGE_CREATE_LAYOUT_THRESHOLD: u64 = 100 * 1024 * 1024 * 1024;
const OFFICIAL_TZAP_ROOT_CERT_SHA256: &str = "sha256:d80d318f6cd6096dc791e314ec6f41434caa47feb75e85ad6f87d5bf72bbd53d";
const OFFICIAL_TZAP_ROOT_CERT_PEM: &[u8] = include_bytes!("trust/tzap-production-root-ca-2026.pem");

mod cli;
mod commands;
mod formatters;
mod os_input;

#[cfg(test)]
mod tests;

use cli::{Cli, Command};
use commands::{create, extract, keygen, list, verify};
use formatters::{classify_error, emit_trust_info, EXIT_USAGE};

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            let code = if err.use_stderr() { EXIT_USAGE } else { 0 };
            let _ = err.print();
            return ExitCode::from(code);
        }
    };
    let is_verify_json = matches!(&cli.command, Command::Verify { json: true, .. });

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let diagnostic = classify_error(&err);
            if !is_verify_json {
                if diagnostic.action.is_empty() {
                    eprintln!("tzap: {}: {err:#}", diagnostic.label);
                } else {
                    eprintln!("tzap: {}: {err:#}: {}", diagnostic.label, diagnostic.action);
                }
            }
            ExitCode::from(diagnostic.exit_code)
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    let quiet = cli.quiet;
    match cli.command {
        Command::Create {
            output,
            volumes,
            volume_size,
            volume_loss_tolerance,
            bit_rot_buffer_pct,
            password_stdin,
            password,
            keyfile,
            recipient_cert,
            no_encryption,
            insecure_zero_key,
            force,
            argon2_t_cost,
            argon2_m_cost_kib,
            argon2_parallelism,
            dictionary,
            signing_key,
            signing_cert,
            signing_private_key,
            signing_chain,
            x509_signature_scheme,
            bootstrap_out,
            tar_stdin,
            raw_stdin,
            stdin_name,
            stdin_size,
            spool_stdin,
            compression_level,
            chunk_size,
            envelope_size,
            block_size,
            jobs,
            timings,
            dry_run,
            paths,
        } => create::run_create(
            quiet,
            create::CreateArgs {
                output,
                volumes,
                volume_size,
                volume_loss_tolerance,
                bit_rot_buffer_pct,
                password_stdin,
                password,
                keyfile,
                recipient_cert,
                no_encryption,
                insecure_zero_key,
                force,
                argon2_t_cost,
                argon2_m_cost_kib,
                argon2_parallelism,
                dictionary,
                signing_key,
                signing_cert,
                signing_private_key,
                signing_chain,
                x509_signature_scheme,
                bootstrap_out,
                tar_stdin,
                raw_stdin,
                stdin_name,
                stdin_size,
                spool_stdin,
                compression_level,
                chunk_size,
                envelope_size,
                block_size,
                jobs,
                timings,
                dry_run,
                paths,
            },
        ),
        Command::Extract {
            archive,
            paths,
            directory,
            stdout,
            dry_run,
            overwrite,
            restore,
            allow_degraded,
            allow_absolute_symlinks,
            password_stdin,
            password,
            keyfile,
            recipient_key,
            insecure_zero_key,
            bootstrap,
            volumes,
            jobs,
        } => extract::run_extract(
            quiet,
            extract::ExtractArgs {
                archive,
                paths,
                directory,
                stdout,
                dry_run,
                overwrite,
                restore,
                allow_degraded,
                allow_absolute_symlinks,
                password_stdin,
                password,
                keyfile,
                recipient_key,
                insecure_zero_key,
                bootstrap,
                volumes,
                jobs,
            },
        ),
        Command::List { archive, password_stdin, password, keyfile, recipient_key, insecure_zero_key, bootstrap, volumes, long, json, jobs } => list::run_list(
            quiet,
            list::ListArgs { archive, password_stdin, password, keyfile, recipient_key, insecure_zero_key, bootstrap, volumes, long, json, jobs },
        ),
        Command::Verify {
            archives,
            password_stdin,
            password,
            keyfile,
            recipient_key,
            insecure_zero_key,
            trusted_public_key,
            trusted_ca_cert,
            trusted_system_roots,
            public_no_key,
            fast,
            bootstrap,
            json,
            write_repaired,
            jobs,
        } => verify::run_verify(
            quiet,
            verify::VerifyArgs {
                archives,
                password_stdin,
                password,
                keyfile,
                recipient_key,
                insecure_zero_key,
                trusted_public_key,
                trusted_ca_cert,
                trusted_system_roots,
                public_no_key,
                fast,
                bootstrap,
                json,
                write_repaired,
                jobs,
            },
        ),
        Command::Keygen { output, stdout, force } => keygen::run_keygen(quiet, keygen::KeygenArgs { output, stdout, force }),
        Command::SigningKeygen { secret_output, public_output, force } => {
            keygen::run_signing_keygen(quiet, keygen::SigningKeygenArgs { secret_output, public_output, force })
        }
        Command::TrustInfo { json } => emit_trust_info(json).map_err(Into::into),
    }
}
