# tzap-plugin-keywrap

`tzap-plugin-keywrap` is the companion crate for v45-compliant RecipientWrap
workflows in documented supported tzap archives.

The crate provides HPKE recipient record generation, profile dispatch, X.509
recipient identity validation, and private-key lookup hooks for opening
RecipientWrap archives.

## Install

```toml
[dependencies]
tzap-core = "0.2.2"
tzap-plugin-keywrap = "0.2.2"
```

## Architecture

`tzap-core` owns the archive wire model and reader/writer surfaces. Projects
add this companion crate when they need v45 RecipientWrap records for
certificate-based archive access.

```text
tzap-core              archive format, recipient record wire types
tzap-plugin-keywrap    HPKE seal/open logic and certificate identity checks
tzap CLI               composes core plus keywrap plugin
```

The plugin keeps HPKE suite selection, X.509 recipient identity validation, and
caller-owned private-key lookup outside the compact core crate.

## Example

```rust,no_run
use tzap_plugin_keywrap::{
    wrap_master_key_for_recipient, ArchiveIdentity, KeyWrapSuite, KEYWRAP_PROFILE_ID,
};

let archive_identity = ArchiveIdentity::default();
let recipient_certificate_der = include_bytes!("recipient.der");
let master_key = [7u8; 32];

let record = wrap_master_key_for_recipient(
    archive_identity,
    recipient_certificate_der,
    &master_key,
    KeyWrapSuite::X25519HkdfSha256ChaCha20Poly1305,
)?;

assert_eq!(record.profile_id, KEYWRAP_PROFILE_ID);
# Ok::<(), tzap_plugin_keywrap::KeyWrapOutcome>(())
```

For opening RecipientWrap archives, callers implement `PrivateKeyLookup` and
pass `RecipientRecordInput` values to `dispatch_key_wrap_record`. Successful
dispatch returns `KeyWrapOutcome::UnwrappedCandidateMasterKey`.

## Supported Suites

The v45 key-wrap profile supports:

- `KeyWrapSuite::X25519HkdfSha256ChaCha20Poly1305`
- `KeyWrapSuite::P256HkdfSha256Aes256Gcm`

Recipient identities are DER-encoded X.509 leaf certificates
(`KEYWRAP_RECIPIENT_IDENTITY_TYPE_BYTES = 2`). Certificate acceptance policy is
caller-owned through `PrivateKeyLookup::is_recipient_certificate_accepted`.

## More Information

- Repository: <https://github.com/tzap-org/tzap>
- Core crate: <https://crates.io/crates/tzap-core>
- CLI crate: <https://crates.io/crates/tzap>
- Signing plugin crate: <https://crates.io/crates/tzap-plugin-signing>
- Implemented format specification: <https://github.com/tzap-org/tzap/blob/main/specs/tzap-format-revisedv45.md>
- v45 RecipientWrap spec: <https://github.com/tzap-org/tzap/blob/main/specs/plugin/tzap-plugin-keywrap-v1-proposed-v45.md>

