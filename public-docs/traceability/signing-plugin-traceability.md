# RootAuth signing plugin traceability

Source scope:

- `crates/tzap-plugin-signing`
- `crates/tzap-cli` RootAuth signing and verification integration
- v45 RootAuth carriage and verification APIs in `tzap-core`

This matrix covers the supported signing profiles. Timestamp authority,
transparency logs, revocation checking, EdDSA certificates in the X.509 profile,
and arbitrary third-party authenticator plugins are outside the current
supported surface unless a caller supplies its own core verifier callback.

| ID | Requirement | Status | Implementation | Evidence |
|---|---|---|---|---|
| SIGN-001 | Keep authenticator-profile behavior outside `tzap-core`; core owns RootAuth fields and archive-root inputs. | Implemented and tested | `crates/tzap-plugin-signing/src/lib.rs`; `crates/tzap-core/src/root_auth.rs`; `crates/tzap-core/src/reader/mod.rs` | Workspace package split; `reader::tests::root_auth_archive_round_trips_and_verifies_with_callback`; plugin unit tests |
| SIGN-002 | Ed25519 profile uses authenticator id `0x0002`, fixed authenticator value length, and strict RootAuth signing input. | Implemented and tested | `crates/tzap-plugin-signing/src/ed25519_raw.rs`; 
  `crates/tzap-cli/src/commands/mod.rs` | `ed25519_raw::tests::ed25519_authenticator_value_round_trips_strict_profile`; `cli_create_signed_archive_and_verify_root_auth_profiles` |
| SIGN-003 | Ed25519 verification distinguishes trusted-key matching, embedded identity, reserved identity classes, key-holding mode, and public no-key mode. | Implemented and tested | `crates/tzap-plugin-signing/src/ed25519_raw.rs` | `rejects_trusted_key_mismatch_with_embedded_identity`; `rejects_unsupported_identity_even_with_trusted_key`; `verifies_type_zero_only_with_trusted_key_and_empty_identity`; `root_auth_verifies_key_holding_and_public_no_key_modes` |
| SIGN-004 | X.509 profile uses authenticator id `0x0003` and DER certificate signer identity type `2`. | Implemented and tested | `crates/tzap-plugin-signing/src/x509_chain.rs`; CLI trust dispatch in `crates/tzap-cli/src/commands/verify.rs` | `x509_authenticator_round_trips_with_trusted_root`; `cli_create_x509_signed_archive_and_verify_certificate_details` |
| SIGN-005 | X.509 signer accepts PEM or DER certificate and key material, verifies private-key/certificate match, normalizes DER, and rejects unsupported EdDSA X.509 keys. | Implemented and tested | `X509RootAuthSigner::from_pem_or_der`; `X509RootAuthSigner::new`; `certificate_der_from_pem_or_der`; `private_key_from_pem_or_der` | `signer_rejects_invalid_chain_certificate_der`; CLI X.509 create smoke |
| SIGN-006 | X.509 signing input is domain separated and binds RootAuth spec id, archive identity, session id, archive root, signer-claimed signing time, and chain digest. | Implemented and tested | `x509_chain::signing_input`; `X509RootAuthSigner::authenticator_value_for_request` | `x509_authenticator_round_trips_with_trusted_root`; `rejects_wrong_trusted_root` |
| SIGN-007 | X.509 authenticator parser rejects bad magic, version, scheme, length overflows, truncated signatures, non-zero signature padding, chain truncation, trailing bytes, and chain-digest mismatch. | Implemented and tested | `parse_authenticator_value`; `authenticator_value_len`; checked length helpers in `x509_chain.rs` | `rejects_impossible_chain_count_without_large_allocation`; `x509_authenticator_round_trips_with_trusted_root`; fuzz-smoke fixed structure coverage for RootAuth footer carriage |
| SIGN-008 | X.509 verification requires explicit CA roots or system roots, verifies the signature, validates the certificate chain at verifier current time, enforces signing-capable leaf KeyUsage when present, and returns certificate policy report fields. | Implemented and tested | `verify_root_auth_footer`; `verify_certificate_chain`; `validate_leaf_key_usage`; `X509RootAuthReport` | `x509_authenticator_round_trips_with_trusted_root`; `chain_validation_uses_verifier_current_time_not_signer_claimed_time`; `rejects_leaf_key_usage_without_signature_or_content_commitment`; `cli_create_x509_signed_archive_and_verify_certificate_details` |
| SIGN-009 | CLI create exposes Ed25519 and X.509 RootAuth signing, including explicit X.509 signature-scheme selection, without mixing incompatible signing modes. | Implemented and tested | `CreateRootAuthProfile`; `load_create_root_auth_profile`; `--x509-signature-scheme`; create flags in `crates/tzap-cli/src/cli.rs` and `crates/tzap-cli/src/commands/create.rs` | `cli_create_signed_archive_and_verify_root_auth_profiles`; `cli_create_x509_signed_archive_and_verify_certificate_details`; CLI help tests |
| SIGN-010 | CLI key-holding verify can require Ed25519 public-key trust or X.509 CA/system-root trust after archive content verification. | Implemented and tested | `verify_opened_root_auth`; `verify_opened_root_auth_ed25519`; `verify_opened_root_auth_x509` | `cli_create_signed_archive_and_verify_root_auth_profiles`; `cli_create_x509_signed_archive_and_verify_certificate_details` |
| SIGN-011 | CLI public no-key verify supports Ed25519 or X.509 trust, rejects archive-key options, and reports public-scope diagnostics. | Implemented and tested | `run_public_no_key_verify`; `load_public_no_key_trust`; `public_no_key_root_auth_json` | `cli_create_signed_archive_and_verify_root_auth_profiles`; `cli_insecure_zero_key_signed_archive_round_trips_and_publicly_verifies`; `cli_create_x509_signed_archive_and_verify_certificate_details` |
| SIGN-012 | Human and JSON outputs include authenticator type, archive root, data-block count, diagnostics, and X.509 certificate report fields. | Implemented and tested | `root_auth_json`; `public_no_key_root_auth_json`; stdout emitters in `crates/tzap-cli/src/commands/verify.rs` and `crates/tzap-cli/src/formatters.rs` | `cli_verify_json_success_reports_machine_readable_summary`; `cli_create_x509_signed_archive_and_verify_certificate_details` |
| SIGN-013 | Unsupported authenticator selectors fail as unsupported verification profiles rather than corrupting core RootAuth wire parsing. | Implemented and tested | `verify_opened_root_auth`; `run_public_no_key_verify`; `RootAuthFooterV1` parser | `root_auth_verification_requires_authenticator_success`; CLI unsupported-feature tests |
| SIGN-014 | Signing plugin public package docs describe architecture, supported profiles, constants, and examples without depending on private docs. | Implemented and tested | `crates/tzap-plugin-signing/README.md`; package metadata | `crates_io_metadata::package_readmes_render_without_workspace_paths`; `crates_io_metadata::public_package_docs_do_not_link_private_docs` |

## Signing profile boundaries

- X.509 signing time is signer-claimed. The default verifier uses verifier
  current time for certificate validity checks; the signing time is not a
  trusted timestamp token.
- Revocation, certificate transparency, notarization, and external policy OIDs
  are not implemented by the profile.
- EdDSA X.509 keys are rejected by the current X.509 profile.
- Unknown RootAuth authenticator ids remain possible through the core callback
  API, but the bundled CLI only verifies the supported Ed25519 and X.509
  profiles.
