use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha512};
use tzap_core::format::{root_auth_spec_id_for_revision, ROOT_AUTH_SPEC_ID};
use tzap_core::reader::RootAuthVerification;
use tzap_core::wire::RootAuthFooterV1;
use tzap_core::writer::RootAuthSigningRequest;

pub const ED25519_AUTHENTICATOR_ID: u16 = 0x0002;
pub const ED25519_AUTHENTICATOR_VALUE_LEN: u32 = 68;

const ED25519_SIG_SCHEME_PURE: u16 = 1;
const ED25519_SIGNING_DOMAIN: &[u8] = b"tzap-sig-ed25519-v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ed25519VerificationMode {
    KeyHoldingRootAuth,
    PublicNoKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ed25519RootAuthOutcome {
    Invalid,
    UnsupportedIdentity,
    SelfSignedConsistent,
    RootAuthContentVerified { key_id: [u8; 32] },
    PublicDataBlockCommitmentVerified { key_id: [u8; 32] },
}

#[derive(Debug, Clone, Copy)]
pub struct Ed25519RootAuthVerifierInput<'a> {
    pub signing_input: &'a [u8; 64],
    pub authenticator_id: u16,
    pub signer_identity_type: u16,
    pub signer_identity_bytes: &'a [u8],
    pub authenticator_value: &'a [u8],
}

pub fn signing_input(
    archive_uuid: &[u8; 16],
    session_id: &[u8; 16],
    archive_root: &[u8; 32],
) -> [u8; 64] {
    signing_input_for_root_auth_spec_id(&ROOT_AUTH_SPEC_ID, archive_uuid, session_id, archive_root)
}

pub fn signing_input_for_root_auth_spec_id(
    root_auth_spec_id: &[u8; 24],
    archive_uuid: &[u8; 16],
    session_id: &[u8; 16],
    archive_root: &[u8; 32],
) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(ED25519_SIGNING_DOMAIN);
    hasher.update(root_auth_spec_id);
    hasher.update(archive_uuid);
    hasher.update(session_id);
    hasher.update(archive_root);
    let digest = hasher.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    out
}

pub fn authenticator_value(
    signing_key: &SigningKey,
    signing_input: &[u8; 64],
) -> [u8; ED25519_AUTHENTICATOR_VALUE_LEN as usize] {
    let signature: Signature = signing_key.sign(signing_input);
    let mut out = [0u8; ED25519_AUTHENTICATOR_VALUE_LEN as usize];
    out[0..2].copy_from_slice(&ED25519_SIG_SCHEME_PURE.to_le_bytes());
    out[4..68].copy_from_slice(&signature.to_bytes());
    out
}

pub fn authenticator_value_for_request(
    signing_key: &SigningKey,
    request: &RootAuthSigningRequest,
) -> [u8; ED25519_AUTHENTICATOR_VALUE_LEN as usize] {
    let signing_input = signing_input_for_root_auth_spec_id(
        &request.root_auth_spec_id,
        &request.archive_uuid,
        &request.session_id,
        &request.archive_root,
    );
    authenticator_value(signing_key, &signing_input)
}

pub fn verify_root_auth(
    input: Ed25519RootAuthVerifierInput<'_>,
    trusted_public_key: Option<[u8; 32]>,
    mode: Ed25519VerificationMode,
) -> Ed25519RootAuthOutcome {
    if input.authenticator_id != ED25519_AUTHENTICATOR_ID {
        return Ed25519RootAuthOutcome::UnsupportedIdentity;
    }
    let Some(signature) = parse_authenticator_value(input.authenticator_value) else {
        return Ed25519RootAuthOutcome::Invalid;
    };

    let (verifying_key, trusted) = match (trusted_public_key, input.signer_identity_type) {
        (Some(key_bytes), 0) => {
            if !input.signer_identity_bytes.is_empty() {
                return Ed25519RootAuthOutcome::Invalid;
            }
            let Ok(key) = VerifyingKey::from_bytes(&key_bytes) else {
                return Ed25519RootAuthOutcome::Invalid;
            };
            (key, true)
        }
        (Some(key_bytes), 1) => {
            if input.signer_identity_bytes.len() != 32 || input.signer_identity_bytes != key_bytes {
                return Ed25519RootAuthOutcome::Invalid;
            }
            let Ok(key) = VerifyingKey::from_bytes(&key_bytes) else {
                return Ed25519RootAuthOutcome::Invalid;
            };
            (key, true)
        }
        (Some(_), _) => return Ed25519RootAuthOutcome::UnsupportedIdentity,
        (None, 1) => {
            if input.signer_identity_bytes.len() != 32 {
                return Ed25519RootAuthOutcome::Invalid;
            }
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(input.signer_identity_bytes);
            let Ok(key) = VerifyingKey::from_bytes(&key_bytes) else {
                return Ed25519RootAuthOutcome::Invalid;
            };
            (key, false)
        }
        (None, _) => return Ed25519RootAuthOutcome::UnsupportedIdentity,
    };

    if verifying_key
        .verify_strict(input.signing_input, &signature)
        .is_err()
    {
        return Ed25519RootAuthOutcome::Invalid;
    }

    if !trusted {
        return Ed25519RootAuthOutcome::SelfSignedConsistent;
    }
    let key_id = verifying_key.to_bytes();
    match mode {
        Ed25519VerificationMode::KeyHoldingRootAuth => {
            Ed25519RootAuthOutcome::RootAuthContentVerified { key_id }
        }
        Ed25519VerificationMode::PublicNoKey => {
            Ed25519RootAuthOutcome::PublicDataBlockCommitmentVerified { key_id }
        }
    }
}

pub fn verify_root_auth_footer(
    footer: &RootAuthFooterV1,
    archive_root: &[u8; 32],
    trusted_public_key: Option<[u8; 32]>,
    mode: Ed25519VerificationMode,
) -> Ed25519RootAuthOutcome {
    let Ok(root_auth_spec_id) =
        root_auth_spec_id_for_revision(footer.format_version, footer.volume_format_rev)
    else {
        return Ed25519RootAuthOutcome::Invalid;
    };
    let signing_input = signing_input_for_root_auth_spec_id(
        &root_auth_spec_id,
        &footer.archive_uuid,
        &footer.session_id,
        archive_root,
    );
    verify_root_auth(
        Ed25519RootAuthVerifierInput {
            signing_input: &signing_input,
            authenticator_id: footer.authenticator_id,
            signer_identity_type: footer.signer_identity_type,
            signer_identity_bytes: &footer.signer_identity_bytes,
            authenticator_value: &footer.authenticator_value,
        },
        trusted_public_key,
        mode,
    )
}

pub fn verify_after_root_auth(
    verification: &RootAuthVerification,
    footer: &RootAuthFooterV1,
    trusted_public_key: Option<[u8; 32]>,
) -> Ed25519RootAuthOutcome {
    verify_root_auth_footer(
        footer,
        &verification.archive_root,
        trusted_public_key,
        Ed25519VerificationMode::KeyHoldingRootAuth,
    )
}

fn parse_authenticator_value(value: &[u8]) -> Option<Signature> {
    if value.len() != ED25519_AUTHENTICATOR_VALUE_LEN as usize {
        return None;
    }
    let sig_scheme = u16::from_le_bytes([value[0], value[1]]);
    let reserved = u16::from_le_bytes([value[2], value[3]]);
    if sig_scheme != ED25519_SIG_SCHEME_PURE || reserved != 0 {
        return None;
    }
    Signature::from_slice(&value[4..68]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use tzap_core::format::{
        FORMAT_VERSION, ROOT_AUTH_SPEC_ID, ROOT_AUTH_SPEC_ID_V45, VOLUME_FORMAT_REV,
        VOLUME_FORMAT_REV_45,
    };

    #[test]
    fn ed25519_authenticator_value_round_trips_strict_profile() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes();
        let signing_input = [7u8; 64];
        let value = authenticator_value(&signing_key, &signing_input);
        let input = Ed25519RootAuthVerifierInput {
            signing_input: &signing_input,
            authenticator_id: ED25519_AUTHENTICATOR_ID,
            signer_identity_type: 1,
            signer_identity_bytes: &public_key,
            authenticator_value: &value,
        };

        assert_eq!(
            verify_root_auth(
                input,
                Some(public_key),
                Ed25519VerificationMode::KeyHoldingRootAuth,
            ),
            Ed25519RootAuthOutcome::RootAuthContentVerified { key_id: public_key }
        );
        assert_eq!(
            verify_root_auth(input, None, Ed25519VerificationMode::KeyHoldingRootAuth),
            Ed25519RootAuthOutcome::SelfSignedConsistent
        );
        assert_eq!(
            verify_root_auth(
                input,
                Some(public_key),
                Ed25519VerificationMode::PublicNoKey,
            ),
            Ed25519RootAuthOutcome::PublicDataBlockCommitmentVerified { key_id: public_key }
        );
    }

    #[test]
    fn typed_core_bridge_round_trips_footer() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes();
        let request = RootAuthSigningRequest {
            root_auth_spec_id: ROOT_AUTH_SPEC_ID,
            archive_uuid: [1; 16],
            session_id: [2; 16],
            archive_root: [3; 32],
        };
        let value = authenticator_value_for_request(&signing_key, &request);
        let footer = RootAuthFooterV1 {
            archive_uuid: request.archive_uuid,
            session_id: request.session_id,
            format_version: FORMAT_VERSION,
            volume_format_rev: VOLUME_FORMAT_REV,
            authenticator_id: ED25519_AUTHENTICATOR_ID,
            signer_identity_type: 1,
            signer_identity_bytes: public_key.to_vec(),
            authenticator_value: value.to_vec(),
            total_data_block_count: 0,
            critical_metadata_digest: [0; 32],
            index_digest: [0; 32],
            fec_layout_digest: [0; 32],
            data_block_merkle_root: [0; 32],
            signer_identity_digest: [0; 32],
            archive_root: request.archive_root,
            footer_crc32c: 0,
        };

        assert_eq!(
            verify_root_auth_footer(
                &footer,
                &request.archive_root,
                Some(public_key),
                Ed25519VerificationMode::KeyHoldingRootAuth,
            ),
            Ed25519RootAuthOutcome::RootAuthContentVerified { key_id: public_key }
        );
    }

    fn footer_for_request(
        signing_key: &SigningKey,
        request: &RootAuthSigningRequest,
    ) -> RootAuthFooterV1 {
        let public_key = signing_key.verifying_key().to_bytes();
        let value = authenticator_value_for_request(signing_key, request);
        RootAuthFooterV1 {
            archive_uuid: request.archive_uuid,
            session_id: request.session_id,
            format_version: FORMAT_VERSION,
            volume_format_rev: VOLUME_FORMAT_REV,
            authenticator_id: ED25519_AUTHENTICATOR_ID,
            signer_identity_type: 1,
            signer_identity_bytes: public_key.to_vec(),
            authenticator_value: value.to_vec(),
            total_data_block_count: 0,
            critical_metadata_digest: [0; 32],
            index_digest: [0; 32],
            fec_layout_digest: [0; 32],
            data_block_merkle_root: [0; 32],
            signer_identity_digest: [0; 32],
            archive_root: request.archive_root,
            footer_crc32c: 0,
        }
    }

    #[test]
    fn strict_profile_negatives_all_rejected_as_invalid() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes();
        let request = RootAuthSigningRequest {
            root_auth_spec_id: ROOT_AUTH_SPEC_ID,
            archive_uuid: [1; 16],
            session_id: [2; 16],
            archive_root: [3; 32],
        };
        let footer = footer_for_request(&signing_key, &request);

        // Non-canonical trusted key (sign bit set) -> Invalid.
        assert_eq!(
            verify_root_auth_footer(
                &footer,
                &request.archive_root,
                Some([0xFF; 32]),
                Ed25519VerificationMode::KeyHoldingRootAuth,
            ),
            Ed25519RootAuthOutcome::Invalid
        );

        // Small-order trusted key (identity point, y=1) -> Invalid.
        let mut small_order = [0u8; 32];
        small_order[0] = 1;
        assert_eq!(
            verify_root_auth_footer(
                &footer,
                &request.archive_root,
                Some(small_order),
                Ed25519VerificationMode::KeyHoldingRootAuth,
            ),
            Ed25519RootAuthOutcome::Invalid
        );

        // Flipped archive_root: footer signed for root A, verified with root B.
        let mut wrong_root = request.archive_root;
        wrong_root[0] ^= 0x01;
        assert_eq!(
            verify_root_auth_footer(
                &footer,
                &wrong_root,
                Some(public_key),
                Ed25519VerificationMode::KeyHoldingRootAuth,
            ),
            Ed25519RootAuthOutcome::Invalid
        );

        // Non-canonical R (first 32 bytes of the signature set to 0xFF).
        let mut bad_r_footer = footer.clone();
        bad_r_footer.authenticator_value[4..36].copy_from_slice(&[0xFF; 32]);
        assert_eq!(
            verify_root_auth_footer(
                &bad_r_footer,
                &request.archive_root,
                Some(public_key),
                Ed25519VerificationMode::KeyHoldingRootAuth,
            ),
            Ed25519RootAuthOutcome::Invalid
        );

        // Non-canonical S (last 32 bytes of the signature set to 0xFF, >= L).
        let mut bad_s_footer = footer.clone();
        bad_s_footer.authenticator_value[36..68].copy_from_slice(&[0xFF; 32]);
        assert_eq!(
            verify_root_auth_footer(
                &bad_s_footer,
                &request.archive_root,
                Some(public_key),
                Ed25519VerificationMode::KeyHoldingRootAuth,
            ),
            Ed25519RootAuthOutcome::Invalid
        );
    }

    #[test]
    fn type_one_identity_length_mismatch_is_invalid() {
        // §10.6: signer_identity_type 1 requires exactly 32 identity bytes.
        let signing_key = SigningKey::generate(&mut OsRng);
        let request = RootAuthSigningRequest {
            root_auth_spec_id: ROOT_AUTH_SPEC_ID,
            archive_uuid: [1; 16],
            session_id: [2; 16],
            archive_root: [3; 32],
        };
        let mut footer = footer_for_request(&signing_key, &request);
        footer.signer_identity_bytes = vec![0x42; 16];
        assert_eq!(
            verify_root_auth_footer(
                &footer,
                &request.archive_root,
                None,
                Ed25519VerificationMode::KeyHoldingRootAuth,
            ),
            Ed25519RootAuthOutcome::Invalid
        );
    }

    #[test]
    fn v45_footer_uses_core_archive_root_and_rejects_wrong_spec_id() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes();
        let request = RootAuthSigningRequest {
            root_auth_spec_id: ROOT_AUTH_SPEC_ID_V45,
            archive_uuid: [1; 16],
            session_id: [2; 16],
            archive_root: [3; 32],
        };
        let value = authenticator_value_for_request(&signing_key, &request);
        let footer = RootAuthFooterV1 {
            archive_uuid: request.archive_uuid,
            session_id: request.session_id,
            format_version: FORMAT_VERSION,
            volume_format_rev: VOLUME_FORMAT_REV_45,
            authenticator_id: ED25519_AUTHENTICATOR_ID,
            signer_identity_type: 1,
            signer_identity_bytes: public_key.to_vec(),
            authenticator_value: value.to_vec(),
            total_data_block_count: 0,
            critical_metadata_digest: [0; 32],
            index_digest: [0; 32],
            fec_layout_digest: [0; 32],
            data_block_merkle_root: [0; 32],
            signer_identity_digest: [0; 32],
            archive_root: [9; 32],
            footer_crc32c: 0,
        };

        assert_eq!(
            verify_root_auth_footer(
                &footer,
                &request.archive_root,
                Some(public_key),
                Ed25519VerificationMode::KeyHoldingRootAuth,
            ),
            Ed25519RootAuthOutcome::RootAuthContentVerified { key_id: public_key }
        );

        let mut revision_44_spec_id = [0u8; 24];
        revision_44_spec_id[..20].copy_from_slice(b"tzap-root-auth-v0.44");
        let wrong_spec_request = RootAuthSigningRequest {
            root_auth_spec_id: revision_44_spec_id,
            ..request
        };
        let mut wrong_spec_footer = footer;
        wrong_spec_footer.authenticator_value =
            authenticator_value_for_request(&signing_key, &wrong_spec_request).to_vec();

        assert_eq!(
            verify_root_auth_footer(
                &wrong_spec_footer,
                &request.archive_root,
                Some(public_key),
                Ed25519VerificationMode::KeyHoldingRootAuth,
            ),
            Ed25519RootAuthOutcome::Invalid
        );
    }

    #[test]
    fn rejects_malformed_authenticator_value() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes();
        let signing_input = [9u8; 64];
        let mut value = authenticator_value(&signing_key, &signing_input);
        value[2] = 1;
        let input = Ed25519RootAuthVerifierInput {
            signing_input: &signing_input,
            authenticator_id: ED25519_AUTHENTICATOR_ID,
            signer_identity_type: 1,
            signer_identity_bytes: &public_key,
            authenticator_value: &value,
        };

        assert_eq!(
            verify_root_auth(
                input,
                Some(public_key),
                Ed25519VerificationMode::KeyHoldingRootAuth,
            ),
            Ed25519RootAuthOutcome::Invalid
        );

        let wrong_length = &value[..value.len() - 1];
        let input = Ed25519RootAuthVerifierInput {
            authenticator_value: wrong_length,
            ..input
        };
        assert_eq!(
            verify_root_auth(
                input,
                Some(public_key),
                Ed25519VerificationMode::KeyHoldingRootAuth,
            ),
            Ed25519RootAuthOutcome::Invalid
        );
    }

    #[test]
    fn rejects_trusted_key_mismatch_with_embedded_identity() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes();
        let other_key = SigningKey::generate(&mut OsRng);
        let signing_input = [11u8; 64];
        let value = authenticator_value(&signing_key, &signing_input);
        let input = Ed25519RootAuthVerifierInput {
            signing_input: &signing_input,
            authenticator_id: ED25519_AUTHENTICATOR_ID,
            signer_identity_type: 1,
            signer_identity_bytes: &public_key,
            authenticator_value: &value,
        };

        assert_eq!(
            verify_root_auth(
                input,
                Some(other_key.verifying_key().to_bytes()),
                Ed25519VerificationMode::KeyHoldingRootAuth,
            ),
            Ed25519RootAuthOutcome::Invalid
        );
    }

    #[test]
    fn verifies_type_zero_only_with_trusted_key_and_empty_identity() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes();
        let signing_input = [13u8; 64];
        let value = authenticator_value(&signing_key, &signing_input);
        let input = Ed25519RootAuthVerifierInput {
            signing_input: &signing_input,
            authenticator_id: ED25519_AUTHENTICATOR_ID,
            signer_identity_type: 0,
            signer_identity_bytes: &[],
            authenticator_value: &value,
        };

        assert_eq!(
            verify_root_auth(
                input,
                Some(public_key),
                Ed25519VerificationMode::KeyHoldingRootAuth,
            ),
            Ed25519RootAuthOutcome::RootAuthContentVerified { key_id: public_key }
        );
        assert_eq!(
            verify_root_auth(input, None, Ed25519VerificationMode::KeyHoldingRootAuth),
            Ed25519RootAuthOutcome::UnsupportedIdentity
        );

        let nonempty_identity = [1u8];
        let input = Ed25519RootAuthVerifierInput {
            signer_identity_bytes: &nonempty_identity,
            ..input
        };
        assert_eq!(
            verify_root_auth(
                input,
                Some(public_key),
                Ed25519VerificationMode::KeyHoldingRootAuth,
            ),
            Ed25519RootAuthOutcome::Invalid
        );
    }

    #[test]
    fn rejects_unsupported_identity_even_with_trusted_key() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes();
        let signing_input = [15u8; 64];
        let value = authenticator_value(&signing_key, &signing_input);
        let input = Ed25519RootAuthVerifierInput {
            signing_input: &signing_input,
            authenticator_id: ED25519_AUTHENTICATOR_ID,
            signer_identity_type: 2,
            signer_identity_bytes: &[],
            authenticator_value: &value,
        };

        assert_eq!(
            verify_root_auth(
                input,
                Some(public_key),
                Ed25519VerificationMode::KeyHoldingRootAuth,
            ),
            Ed25519RootAuthOutcome::UnsupportedIdentity
        );
    }
}
