# tzap-plugin-signing

`tzap-plugin-signing` adds v45-compliant RootAuth signing profiles for
documented supported tzap workflows. It is the companion crate for applications
that want signed v45 RootAuth archives on top of the standalone `tzap-core`
archive foundation.

The `ed25519_raw` profile implements the Ed25519 RootAuth
authenticator (`authenticator_id = 0x0002`). The `x509_chain` profile adds an
OpenSSL-backed certificate verifier (`authenticator_id = 0x0003`) for leaf
certificates, optional intermediate chains, and trusted CA roots. Core provides
archive-root recomputation and verification gates; this crate provides the
signing profile logic.

## Install

```toml
[dependencies]
tzap-core = "0.2.3"
tzap-plugin-signing = "0.2.3"
```

## Architecture

`tzap-core` is the standalone archive foundation. Projects choose the compact
core surface for archive workflows, or add this companion crate for signed
RootAuth workflows and public no-key verification.

```text
tzap-core              archive format, RootAuth material, verifier gates
tzap-plugin-signing    Ed25519 and X.509 RootAuth profiles
tzap CLI               composes core plus signing plugin
```

Certificate profiles live in this crate as additional modules while keeping core
independent.

## Example

```rust
use ed25519_dalek::SigningKey;
use tzap_core::RootAuthSigningRequest;
use tzap_plugin_signing::ed25519_raw;

let signing_key = SigningKey::from_bytes(&[7; 32]);
let request = RootAuthSigningRequest {
    archive_uuid: [1; 16],
    session_id: [2; 16],
    archive_root: [3; 32],
};

let authenticator_value =
    ed25519_raw::authenticator_value_for_request(&signing_key, &request);

assert_eq!(
    authenticator_value.len(),
    ed25519_raw::ED25519_AUTHENTICATOR_VALUE_LEN as usize
);
```

## Ed25519 Raw Profile

The `ed25519_raw` module provides:

- `ED25519_AUTHENTICATOR_ID = 0x0002`
- `ED25519_AUTHENTICATOR_VALUE_LEN = 68`
- `authenticator_value_for_request` for core writer callbacks
- `verify_root_auth_footer` for core verifier callbacks
- distinct outcome types for profile data quality, reserved identity classes,
  self-signed consistency, key-holding RootAuth verification, and public no-key
  commitment verification

## X.509 Chain Profile

The `x509_chain` module provides:

- `X509_AUTHENTICATOR_ID = 0x0003`
- `X509_SIGNER_IDENTITY_TYPE_DER_CERT = 2`
- `X509RootAuthSigner` for core writer callbacks
- `verify_root_auth_footer` for core verifier callbacks
- reports with signer subject, issuer, serial number, certificate SHA-256,
  signature scheme, signer-claimed signing time, verifier-current chain
  validation time, policy labels, verified chain subjects, and trust anchor
  subject

## More Information

- Repository: <https://github.com/tzap-org/tzap>
- Core crate: <https://crates.io/crates/tzap-core>
- CLI crate: <https://crates.io/crates/tzap>
- Keywrap plugin crate: <https://crates.io/crates/tzap-plugin-keywrap>
- Implemented format specification: <https://github.com/tzap-org/tzap/blob/main/specs/tzap-format-revisedv45.md>
- v45 Ed25519 RootAuth spec: <https://github.com/tzap-org/tzap/blob/main/specs/plugin/tzap-plugin-signing-v6-proposed-v45.md>
- v45 X.509 RootAuth spec: <https://github.com/tzap-org/tzap/blob/main/specs/plugin/tzap-plugin-x509-chain-v2-proposed-v45.md>

