//! Embedded TZAP root-of-trust certificates.
//!
//! These are the only copies of the official TZAP root certificates in the
//! `tzap`/`zmanager` workspaces. `tzap-cli` and downstream consumers (e.g.
//! `zmanager-core`) import them from here rather than embedding their own
//! copy or fetching one at runtime, so there is exactly one place these bytes
//! and their pinned fingerprints can drift apart.
//!
//! Only the root certificates live here. Platform intermediate certificates
//! are never pinned in client code: the server issues and rotates them
//! freely, and every chain is validated by checking it is properly signed by
//! one of these roots at verification time.

pub const OFFICIAL_TZAP_ROOT_CERT_SHA256: &str = "sha256:d80d318f6cd6096dc791e314ec6f41434caa47feb75e85ad6f87d5bf72bbd53d";
pub const OFFICIAL_TZAP_ROOT_CERT_PEM: &[u8] = include_bytes!("trust/tzap-production-root-ca-2026.pem");

pub const OFFICIAL_TZAP_STAGING_ROOT_SHA256: &str = "sha256:372ea5b33397e51ad76922338bb2613c822809d327d144d7974a99035006dc5a";
pub const OFFICIAL_TZAP_STAGING_ROOT_PEM: &[u8] = include_bytes!("trust/tzap-staging-root-ca-2026.pem");
