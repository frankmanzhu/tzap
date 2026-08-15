//! X.509 chain path-validation — the single allow-listed OpenSSL surface of
//! this crate.
//!
//! The RustCrypto ecosystem does not yet provide an X.509 *path-validation*
//! engine: `x509-verify` verifies signatures over parsed certificates but has
//! no chain building, time policy, or trust-store machinery, and `aws-lc-rs`
//! has no X.509 module at all. Per the §6 decision recorded in
//! `implementation-docs/openssl-dependency-removal-plan.md`, chain
//! verification therefore stays on (vendored) OpenSSL until differential-test
//! parity exists on the TZAP fixture corpus. Everything else in this crate —
//! key parsing, signing, verification, certificate parsing, report
//! formatting — is pure RustCrypto.
//!
//! Do NOT add non-chain-verification OpenSSL calls to this module, and do not
//! import OpenSSL types anywhere else in this crate.

use super::X509RootAuthError;
use openssl::error::ErrorStack;
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::X509VerifyParam;
use openssl::x509::{X509NameRef, X509StoreContext, X509};

fn to_chain_error(error: ErrorStack) -> X509RootAuthError {
    X509RootAuthError::Chain(format!("{error}"))
}

/// Verifies `leaf_certificate_der` with `chain_certificate_der` against the
/// trusted roots (plus OpenSSL's system default paths when
/// `use_system_roots`), at `chain_validation_time_unix_seconds`.
///
/// Returns the verified chain's subjects, leaf first and ending at the trust
/// anchor, formatted like the pre-migration report (OpenSSL NID short names,
/// `key=value` joined by `", "`). An empty verified chain falls back to the
/// leaf subject, matching the pre-migration behavior.
pub(super) fn verify_certificate_chain(
    leaf_certificate_der: &[u8],
    chain_certificate_der: &[Vec<u8>],
    trusted_roots_der: &[Vec<u8>],
    use_system_roots: bool,
    chain_validation_time_unix_seconds: i64,
) -> Result<Vec<String>, X509RootAuthError> {
    let leaf_certificate = X509::from_der(leaf_certificate_der).map_err(to_chain_error)?;
    let mut store_builder = X509StoreBuilder::new().map_err(to_chain_error)?;
    for root_der in trusted_roots_der {
        let root = X509::from_der(root_der).map_err(to_chain_error)?;
        store_builder.add_cert(root).map_err(to_chain_error)?;
    }
    if use_system_roots {
        store_builder.set_default_paths().map_err(to_chain_error)?;
    }
    let mut params = X509VerifyParam::new().map_err(to_chain_error)?;
    params.set_time(chain_validation_time_unix_seconds as _);
    store_builder.set_param(&params).map_err(to_chain_error)?;
    let store = store_builder.build();

    let mut chain = Stack::new().map_err(to_chain_error)?;
    for cert_der in chain_certificate_der {
        chain.push(X509::from_der(cert_der).map_err(to_chain_error)?).map_err(to_chain_error)?;
    }
    let mut context = X509StoreContext::new().map_err(to_chain_error)?;
    let mut verify_error = None;
    let mut subjects = Vec::new();
    let verified = context
        .init(&store, &leaf_certificate, &chain, |ctx| {
            let ok = ctx.verify_cert()?;
            if ok {
                if let Some(chain) = ctx.chain() {
                    subjects = chain.iter().map(|cert| name_to_string(cert.subject_name())).collect();
                }
            } else {
                verify_error = Some(format!("{} at depth {}", ctx.error(), ctx.error_depth()));
            }
            Ok(ok)
        })
        .map_err(to_chain_error)?;
    if !verified {
        return Err(X509RootAuthError::UntrustedChain(
            verify_error.unwrap_or_else(|| "certificate chain verification failed".to_string()),
        ));
    }
    if subjects.is_empty() {
        subjects.push(name_to_string(leaf_certificate.subject_name()));
    }
    Ok(subjects)
}

fn name_to_string(name: &X509NameRef) -> String {
    let mut parts = Vec::new();
    for entry in name.entries() {
        let key = entry.object().nid().short_name().unwrap_or("OID");
        let value = entry.data().to_string().unwrap_or_else(|_| encode_hex(entry.data().as_slice()));
        parts.push(format!("{key}={value}"));
    }
    parts.join(", ")
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = std::fmt::Write::write_fmt(&mut output, format_args!("{:02x}", byte));
    }
    output
}
