#![forbid(unsafe_code)]

use hpke::{
    aead::{AesGcm256, ChaCha20Poly1305},
    kdf::HkdfSha256,
    kem::{DhP256HkdfSha256, X25519HkdfSha256},
    Deserializable, Kem as HpkeKem, OpModeR, OpModeS, Serializable,
};
use openssl::{bn::BigNumContext, ec::PointConversionForm, nid::Nid, pkey::PKey, x509::X509};
use rand_core::{OsRng, UnwrapErr};
use sha2::{Digest, Sha256};
use tzap_core::format::{FORMAT_VERSION, VOLUME_FORMAT_REV_45};
use tzap_core::wire::RecipientRecordV1;
use x509_parser::parse_x509_certificate;

/// Profile identifier for key-wrap v1 recipient records.
pub const KEYWRAP_PROFILE_ID: u16 = 0x0001;

/// Recipient identity type for a DER-encoded x509 leaf certificate.
pub const KEYWRAP_RECIPIENT_IDENTITY_TYPE_BYTES: u16 = 2;

const KEYWRAP_PROFILE_PAYLOAD_HEADER_LEN: usize = 64;
pub const KEYWRAP_PAYLOAD_VERSION: u16 = 1;
const KEY_WRAP_CONTEXT_DOMAIN: &[u8] = b"tzap-keywrap-x509-hpke-v1-context\0";
const HPKE_INFO_DOMAIN: &[u8] = b"tzap-x509-hpke-recipient-v1\0";
const HPKE_AAD_DOMAIN: &[u8] = b"tzap-keywrap-master-key-v45\0";

const X25519_KEM_ID: u16 = 0x0020;
const P256_KEM_ID: u16 = 0x0010;
const HKDF_SHA256_KDF_ID: u16 = 0x0001;
const CHACHA20POLY1305_AEAD_ID: u16 = 0x0003;
const AES256GCM_AEAD_ID: u16 = 0x0002;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HpkeSuite {
    kem_id: u16,
    kdf_id: u16,
    aead_id: u16,
    enc_length: usize,
    ciphertext_length: usize,
}

impl HpkeSuite {
    fn for_profile(hpke_kem_id: u16, hpke_kdf_id: u16, hpke_aead_id: u16) -> Option<Self> {
        let suites = [
            Self {
                kem_id: X25519_KEM_ID,
                kdf_id: HKDF_SHA256_KDF_ID,
                aead_id: CHACHA20POLY1305_AEAD_ID,
                enc_length: 32,
                ciphertext_length: 48,
            },
            Self {
                kem_id: P256_KEM_ID,
                kdf_id: HKDF_SHA256_KDF_ID,
                aead_id: AES256GCM_AEAD_ID,
                enc_length: 65,
                ciphertext_length: 48,
            },
        ];

        suites.into_iter().find(|suite| {
            suite.kem_id == hpke_kem_id
                && suite.kdf_id == hpke_kdf_id
                && suite.aead_id == hpke_aead_id
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyWrapSuite {
    X25519HkdfSha256ChaCha20Poly1305,
    P256HkdfSha256Aes256Gcm,
}

impl KeyWrapSuite {
    fn hpke_suite(self) -> HpkeSuite {
        match self {
            Self::X25519HkdfSha256ChaCha20Poly1305 => HpkeSuite {
                kem_id: X25519_KEM_ID,
                kdf_id: HKDF_SHA256_KDF_ID,
                aead_id: CHACHA20POLY1305_AEAD_ID,
                enc_length: 32,
                ciphertext_length: 48,
            },
            Self::P256HkdfSha256Aes256Gcm => HpkeSuite {
                kem_id: P256_KEM_ID,
                kdf_id: HKDF_SHA256_KDF_ID,
                aead_id: AES256GCM_AEAD_ID,
                enc_length: 65,
                ciphertext_length: 48,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveIdentity {
    pub archive_uuid: [u8; 16],
    pub session_id: [u8; 16],
    pub format_version: u16,
    pub volume_format_rev: u16,
}

impl Default for ArchiveIdentity {
    fn default() -> Self {
        Self {
            archive_uuid: [0u8; 16],
            session_id: [0u8; 16],
            format_version: FORMAT_VERSION,
            volume_format_rev: VOLUME_FORMAT_REV_45,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientRecordMetadata {
    pub profile_id: u16,
    pub recipient_identity_type: u16,
    pub recipient_identity_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientRecordInput {
    pub archive_identity: ArchiveIdentity,
    pub metadata: RecipientRecordMetadata,
    pub recipient_identity_bytes: Vec<u8>,
    pub profile_payload_bytes: Vec<u8>,
}

/// Abstraction for locating a private key for profile-specific decryption.
pub trait PrivateKeyLookup {
    fn lookup_private_key(
        &self,
        archive_identity: &ArchiveIdentity,
        metadata: &RecipientRecordMetadata,
        recipient_identity_bytes: &[u8],
    ) -> Option<Vec<u8>>;

    fn is_recipient_certificate_accepted(
        &self,
        _archive_identity: &ArchiveIdentity,
        _metadata: &RecipientRecordMetadata,
        _recipient_identity_bytes: &[u8],
        _recipient_spki_digest: &[u8; 32],
    ) -> bool {
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyWrapOutcome {
    UnsupportedProfileId,
    UnsupportedArchiveIdentity,
    UnsupportedRecipientIdentity,
    UnsupportedSuite,
    CertificatePolicyRejected,
    InvalidRecord,
    NoMatchingPrivateKey,
    UnwrappedCandidateMasterKey {
        master_key: [u8; 32],
        recipient_spki_digest: [u8; 32],
    },
}

#[derive(Debug, Clone)]
struct ParsedRecipientIdentity {
    recipient_identity_digest: [u8; 32],
    recipient_spki_digest: [u8; 32],
}

#[derive(Debug, Clone)]
struct ParsedProfilePayload {
    suite: HpkeSuite,
    enc: Vec<u8>,
    ciphertext: Vec<u8>,
    key_wrap_context_digest: [u8; 32],
}

/// Dispatch a single key-wrap recipient record to the profile parser.
///
/// For `profile_id == KEYWRAP_PROFILE_ID`, this validates:
/// - recipient identity parsing for X.509 type=2 records
/// - profile payload framing
/// - context digest computation
/// - supported HPKE suites and fixed lengths
///
/// It then asks the caller for a matching private key and attempts HPKE Open.
pub fn dispatch_key_wrap_record<L>(
    input: RecipientRecordInput,
    private_key_lookup: &L,
) -> KeyWrapOutcome
where
    L: PrivateKeyLookup + ?Sized,
{
    if input.archive_identity.format_version != FORMAT_VERSION
        || input.archive_identity.volume_format_rev != VOLUME_FORMAT_REV_45
    {
        return KeyWrapOutcome::UnsupportedArchiveIdentity;
    }

    if input.metadata.profile_id != KEYWRAP_PROFILE_ID {
        return KeyWrapOutcome::UnsupportedProfileId;
    }

    if input.metadata.recipient_identity_type != KEYWRAP_RECIPIENT_IDENTITY_TYPE_BYTES {
        return KeyWrapOutcome::UnsupportedRecipientIdentity;
    }

    let parsed_identity = match parse_x509_recipient_identity(&input.recipient_identity_bytes) {
        Ok(identity) => identity,
        Err(outcome) => return outcome,
    };

    if parsed_identity.recipient_identity_digest != input.metadata.recipient_identity_digest {
        return KeyWrapOutcome::InvalidRecord;
    }

    let payload = match parse_profile_payload(&input.profile_payload_bytes) {
        Ok(payload) => payload,
        Err(outcome) => return outcome,
    };

    if let Err(outcome) =
        validate_recipient_public_key_matches_suite(&input.recipient_identity_bytes, payload.suite)
    {
        return outcome;
    }

    let private_key = match private_key_lookup.lookup_private_key(
        &input.archive_identity,
        &input.metadata,
        &input.recipient_identity_bytes,
    ) {
        Some(private_key) => private_key,
        None => return KeyWrapOutcome::NoMatchingPrivateKey,
    };

    if !private_key_lookup.is_recipient_certificate_accepted(
        &input.archive_identity,
        &input.metadata,
        &input.recipient_identity_bytes,
        &parsed_identity.recipient_spki_digest,
    ) {
        return KeyWrapOutcome::CertificatePolicyRejected;
    }

    let expected_context_digest = compute_key_wrap_context_digest(
        &input.archive_identity,
        &input.metadata,
        &parsed_identity,
        payload.suite,
    );
    if payload.key_wrap_context_digest != expected_context_digest {
        return KeyWrapOutcome::InvalidRecord;
    }

    match hpke_open_candidate_master_key(&payload, &private_key) {
        Ok(master_key) => KeyWrapOutcome::UnwrappedCandidateMasterKey {
            master_key,
            recipient_spki_digest: parsed_identity.recipient_spki_digest,
        },
        Err(outcome) => outcome,
    }
}

pub fn wrap_master_key_for_recipient(
    archive_identity: ArchiveIdentity,
    recipient_certificate_der: &[u8],
    master_key: &[u8; 32],
    suite: KeyWrapSuite,
) -> Result<RecipientRecordV1, KeyWrapOutcome> {
    if archive_identity.format_version != FORMAT_VERSION
        || archive_identity.volume_format_rev != VOLUME_FORMAT_REV_45
    {
        return Err(KeyWrapOutcome::UnsupportedArchiveIdentity);
    }

    let identity = parse_x509_recipient_identity(recipient_certificate_der)?;
    let metadata = RecipientRecordMetadata {
        profile_id: KEYWRAP_PROFILE_ID,
        recipient_identity_type: KEYWRAP_RECIPIENT_IDENTITY_TYPE_BYTES,
        recipient_identity_digest: identity.recipient_identity_digest,
    };
    let profile_payload_bytes = hpke_seal_master_key(
        recipient_certificate_der,
        &archive_identity,
        &metadata,
        &identity,
        master_key,
        suite.hpke_suite(),
    )?;

    Ok(RecipientRecordV1 {
        record_length: 0,
        profile_id: KEYWRAP_PROFILE_ID,
        recipient_identity_type: KEYWRAP_RECIPIENT_IDENTITY_TYPE_BYTES,
        flags: 0,
        recipient_identity_length: recipient_certificate_der.len() as u32,
        profile_payload_length: profile_payload_bytes.len() as u32,
        recipient_identity_digest: identity.recipient_identity_digest,
        recipient_identity_bytes: recipient_certificate_der.to_vec(),
        profile_payload_bytes,
    })
}

fn hpke_seal_master_key(
    recipient_certificate_der: &[u8],
    archive_identity: &ArchiveIdentity,
    metadata: &RecipientRecordMetadata,
    identity: &ParsedRecipientIdentity,
    master_key: &[u8; 32],
    suite: HpkeSuite,
) -> Result<Vec<u8>, KeyWrapOutcome> {
    hpke_seal_master_key_with_aad_domain(
        recipient_certificate_der,
        archive_identity,
        metadata,
        identity,
        master_key,
        suite,
        HPKE_AAD_DOMAIN,
    )
}

fn hpke_seal_master_key_with_aad_domain(
    recipient_certificate_der: &[u8],
    archive_identity: &ArchiveIdentity,
    metadata: &RecipientRecordMetadata,
    identity: &ParsedRecipientIdentity,
    master_key: &[u8; 32],
    suite: HpkeSuite,
    aad_domain: &[u8],
) -> Result<Vec<u8>, KeyWrapOutcome> {
    let key_wrap_context_digest =
        compute_key_wrap_context_digest(archive_identity, metadata, identity, suite);
    let info = hpke_info(&key_wrap_context_digest);
    let aad = hpke_aad_with_domain(aad_domain, &key_wrap_context_digest);
    let (enc, ciphertext) = match (suite.kem_id, suite.aead_id) {
        (X25519_KEM_ID, CHACHA20POLY1305_AEAD_ID) => {
            let public_key = x25519_public_key_from_certificate(recipient_certificate_der)
                .map_err(|_| KeyWrapOutcome::UnsupportedSuite)?;
            let mut rng = UnwrapErr(OsRng);
            let (enc, ciphertext) =
                hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256, _>(
                    &OpModeS::Base,
                    &public_key,
                    &info,
                    master_key,
                    &aad,
                    &mut rng,
                )
                .map_err(|_| KeyWrapOutcome::InvalidRecord)?;
            (enc.to_bytes().to_vec(), ciphertext)
        }
        (P256_KEM_ID, AES256GCM_AEAD_ID) => {
            let public_key = p256_public_key_from_certificate(recipient_certificate_der)
                .map_err(|_| KeyWrapOutcome::UnsupportedSuite)?;
            let mut rng = UnwrapErr(OsRng);
            let (enc, ciphertext) =
                hpke::single_shot_seal::<AesGcm256, HkdfSha256, DhP256HkdfSha256, _>(
                    &OpModeS::Base,
                    &public_key,
                    &info,
                    master_key,
                    &aad,
                    &mut rng,
                )
                .map_err(|_| KeyWrapOutcome::InvalidRecord)?;
            (enc.to_bytes().to_vec(), ciphertext)
        }
        _ => return Err(KeyWrapOutcome::UnsupportedSuite),
    };

    if enc.len() != suite.enc_length || ciphertext.len() != suite.ciphertext_length {
        return Err(KeyWrapOutcome::InvalidRecord);
    }

    Ok(build_profile_payload(
        suite,
        &key_wrap_context_digest,
        &enc,
        &ciphertext,
    ))
}

fn hpke_open_candidate_master_key(
    payload: &ParsedProfilePayload,
    private_key_bytes: &[u8],
) -> Result<[u8; 32], KeyWrapOutcome> {
    let info = hpke_info(&payload.key_wrap_context_digest);
    let aad = hpke_aad(&payload.key_wrap_context_digest);
    let plaintext = match (payload.suite.kem_id, payload.suite.aead_id) {
        (X25519_KEM_ID, CHACHA20POLY1305_AEAD_ID) => {
            let private_key = x25519_private_key_from_bytes(private_key_bytes)?;
            let encapped_key = <X25519HkdfSha256 as HpkeKem>::EncappedKey::from_bytes(&payload.enc)
                .map_err(|_| KeyWrapOutcome::InvalidRecord)?;
            hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
                &OpModeR::Base,
                &private_key,
                &encapped_key,
                &info,
                &payload.ciphertext,
                &aad,
            )
            .map_err(|_| KeyWrapOutcome::InvalidRecord)?
        }
        (P256_KEM_ID, AES256GCM_AEAD_ID) => {
            let private_key = p256_private_key_from_bytes(private_key_bytes)?;
            let encapped_key = <DhP256HkdfSha256 as HpkeKem>::EncappedKey::from_bytes(&payload.enc)
                .map_err(|_| KeyWrapOutcome::InvalidRecord)?;
            hpke::single_shot_open::<AesGcm256, HkdfSha256, DhP256HkdfSha256>(
                &OpModeR::Base,
                &private_key,
                &encapped_key,
                &info,
                &payload.ciphertext,
                &aad,
            )
            .map_err(|_| KeyWrapOutcome::InvalidRecord)?
        }
        _ => return Err(KeyWrapOutcome::UnsupportedSuite),
    };

    if plaintext.len() != 32 {
        return Err(KeyWrapOutcome::InvalidRecord);
    }
    let mut master_key = [0u8; 32];
    master_key.copy_from_slice(&plaintext);
    Ok(master_key)
}

fn build_profile_payload(
    suite: HpkeSuite,
    key_wrap_context_digest: &[u8; 32],
    enc: &[u8],
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut payload = vec![0u8; KEYWRAP_PROFILE_PAYLOAD_HEADER_LEN + enc.len() + ciphertext.len()];
    payload[0..2].copy_from_slice(&KEYWRAP_PAYLOAD_VERSION.to_le_bytes());
    payload[2..4].copy_from_slice(&suite.kem_id.to_le_bytes());
    payload[4..6].copy_from_slice(&suite.kdf_id.to_le_bytes());
    payload[6..8].copy_from_slice(&suite.aead_id.to_le_bytes());
    payload[8..10].copy_from_slice(&(enc.len() as u16).to_le_bytes());
    payload[10..12].copy_from_slice(&(ciphertext.len() as u16).to_le_bytes());
    payload[16..48].copy_from_slice(key_wrap_context_digest);
    payload[KEYWRAP_PROFILE_PAYLOAD_HEADER_LEN..KEYWRAP_PROFILE_PAYLOAD_HEADER_LEN + enc.len()]
        .copy_from_slice(enc);
    payload[KEYWRAP_PROFILE_PAYLOAD_HEADER_LEN + enc.len()..].copy_from_slice(ciphertext);
    payload
}

fn parse_x509_recipient_identity(
    recipient_identity_bytes: &[u8],
) -> Result<ParsedRecipientIdentity, KeyWrapOutcome> {
    let (remaining, parsed_cert) = parse_x509_certificate(recipient_identity_bytes)
        .map_err(|_error| KeyWrapOutcome::InvalidRecord)?;

    if !remaining.is_empty() {
        return Err(KeyWrapOutcome::InvalidRecord);
    }

    match parsed_cert.key_usage() {
        Ok(Some(key_usage)) => {
            if !key_usage.value.key_agreement() {
                return Err(KeyWrapOutcome::InvalidRecord);
            }
        }
        Ok(None) => {}
        Err(_) => {
            return Err(KeyWrapOutcome::InvalidRecord);
        }
    }

    let openssl_cert =
        X509::from_der(recipient_identity_bytes).map_err(|_| KeyWrapOutcome::InvalidRecord)?;
    let openssl_public_key: PKey<_> = openssl_cert
        .public_key()
        .map_err(|_| KeyWrapOutcome::InvalidRecord)?;
    let spki_der = openssl_public_key
        .public_key_to_der()
        .map_err(|_| KeyWrapOutcome::InvalidRecord)?;
    let recipient_identity_digest = sha256_digest(recipient_identity_bytes);
    let recipient_spki_digest = sha256_digest(&spki_der);

    Ok(ParsedRecipientIdentity {
        recipient_identity_digest,
        recipient_spki_digest,
    })
}

fn parse_profile_payload(
    profile_payload_bytes: &[u8],
) -> Result<ParsedProfilePayload, KeyWrapOutcome> {
    if profile_payload_bytes.len() < KEYWRAP_PROFILE_PAYLOAD_HEADER_LEN {
        return Err(KeyWrapOutcome::InvalidRecord);
    }

    let payload_version = read_u16(profile_payload_bytes, 0)?;
    let hpke_kem_id = read_u16(profile_payload_bytes, 2)?;
    let hpke_kdf_id = read_u16(profile_payload_bytes, 4)?;
    let hpke_aead_id = read_u16(profile_payload_bytes, 6)?;
    let enc_length = usize::from(read_u16(profile_payload_bytes, 8)?);
    let ciphertext_length = usize::from(read_u16(profile_payload_bytes, 10)?);
    let flags = read_u32(profile_payload_bytes, 12)?;
    let key_wrap_context_digest = read_array_32(profile_payload_bytes, 16)?;

    if flags != 0 {
        return Err(KeyWrapOutcome::InvalidRecord);
    }

    if !profile_payload_bytes[48..KEYWRAP_PROFILE_PAYLOAD_HEADER_LEN]
        .iter()
        .all(|value| *value == 0)
    {
        return Err(KeyWrapOutcome::InvalidRecord);
    }

    if payload_version != KEYWRAP_PAYLOAD_VERSION {
        return Err(KeyWrapOutcome::InvalidRecord);
    }

    let suite = HpkeSuite::for_profile(hpke_kem_id, hpke_kdf_id, hpke_aead_id)
        .ok_or(KeyWrapOutcome::UnsupportedSuite)?;

    if enc_length != suite.enc_length || ciphertext_length != suite.ciphertext_length {
        return Err(KeyWrapOutcome::InvalidRecord);
    }

    let expected_length = KEYWRAP_PROFILE_PAYLOAD_HEADER_LEN
        .checked_add(enc_length)
        .and_then(|value| value.checked_add(ciphertext_length))
        .ok_or(KeyWrapOutcome::InvalidRecord)?;

    if profile_payload_bytes.len() != expected_length {
        return Err(KeyWrapOutcome::InvalidRecord);
    }

    let enc_start = KEYWRAP_PROFILE_PAYLOAD_HEADER_LEN;
    let ciphertext_start = enc_start + enc_length;
    let enc = profile_payload_bytes[enc_start..ciphertext_start].to_vec();
    let ciphertext =
        profile_payload_bytes[ciphertext_start..ciphertext_start + ciphertext_length].to_vec();

    Ok(ParsedProfilePayload {
        suite,
        enc,
        ciphertext,
        key_wrap_context_digest,
    })
}

fn validate_recipient_public_key_matches_suite(
    recipient_certificate_der: &[u8],
    suite: HpkeSuite,
) -> Result<(), KeyWrapOutcome> {
    match suite.kem_id {
        X25519_KEM_ID => x25519_public_key_from_certificate(recipient_certificate_der)
            .map(|_| ())
            .map_err(|_| KeyWrapOutcome::UnsupportedSuite),
        P256_KEM_ID => p256_public_key_from_certificate(recipient_certificate_der)
            .map(|_| ())
            .map_err(|_| KeyWrapOutcome::UnsupportedSuite),
        _ => Err(KeyWrapOutcome::UnsupportedSuite),
    }
}

fn compute_key_wrap_context_digest(
    archive_identity: &ArchiveIdentity,
    metadata: &RecipientRecordMetadata,
    identity: &ParsedRecipientIdentity,
    suite: HpkeSuite,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(KEY_WRAP_CONTEXT_DOMAIN);
    hasher.update(archive_identity.archive_uuid);
    hasher.update(archive_identity.session_id);
    hasher.update(archive_identity.format_version.to_le_bytes());
    hasher.update(archive_identity.volume_format_rev.to_le_bytes());
    hasher.update(metadata.profile_id.to_le_bytes());
    hasher.update(metadata.recipient_identity_type.to_le_bytes());
    hasher.update(identity.recipient_identity_digest);
    hasher.update(identity.recipient_spki_digest);
    hasher.update(suite.kem_id.to_le_bytes());
    hasher.update(suite.kdf_id.to_le_bytes());
    hasher.update(suite.aead_id.to_le_bytes());

    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn hpke_info(key_wrap_context_digest: &[u8; 32]) -> Vec<u8> {
    let mut info = Vec::with_capacity(HPKE_INFO_DOMAIN.len() + key_wrap_context_digest.len());
    info.extend_from_slice(HPKE_INFO_DOMAIN);
    info.extend_from_slice(key_wrap_context_digest);
    info
}

fn hpke_aad(key_wrap_context_digest: &[u8; 32]) -> Vec<u8> {
    hpke_aad_with_domain(HPKE_AAD_DOMAIN, key_wrap_context_digest)
}

fn hpke_aad_with_domain(domain: &[u8], key_wrap_context_digest: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(domain.len() + key_wrap_context_digest.len());
    aad.extend_from_slice(domain);
    aad.extend_from_slice(key_wrap_context_digest);
    aad
}

fn x25519_public_key_from_certificate(
    recipient_certificate_der: &[u8],
) -> Result<<X25519HkdfSha256 as HpkeKem>::PublicKey, KeyWrapOutcome> {
    let certificate =
        X509::from_der(recipient_certificate_der).map_err(|_| KeyWrapOutcome::InvalidRecord)?;
    let public_key = certificate
        .public_key()
        .map_err(|_| KeyWrapOutcome::InvalidRecord)?;
    let raw = public_key
        .raw_public_key()
        .map_err(|_| KeyWrapOutcome::InvalidRecord)?;
    if raw.len() != 32 {
        return Err(KeyWrapOutcome::InvalidRecord);
    }
    <X25519HkdfSha256 as HpkeKem>::PublicKey::from_bytes(&raw)
        .map_err(|_| KeyWrapOutcome::InvalidRecord)
}

fn p256_public_key_from_certificate(
    recipient_certificate_der: &[u8],
) -> Result<<DhP256HkdfSha256 as HpkeKem>::PublicKey, KeyWrapOutcome> {
    let certificate =
        X509::from_der(recipient_certificate_der).map_err(|_| KeyWrapOutcome::InvalidRecord)?;
    let public_key = certificate
        .public_key()
        .map_err(|_| KeyWrapOutcome::InvalidRecord)?;
    let ec_key = public_key
        .ec_key()
        .map_err(|_| KeyWrapOutcome::InvalidRecord)?;
    if ec_key.group().curve_name() != Some(Nid::X9_62_PRIME256V1) {
        return Err(KeyWrapOutcome::InvalidRecord);
    }
    let mut context = BigNumContext::new().map_err(|_| KeyWrapOutcome::InvalidRecord)?;
    let encoded = ec_key
        .public_key()
        .to_bytes(
            ec_key.group(),
            PointConversionForm::UNCOMPRESSED,
            &mut context,
        )
        .map_err(|_| KeyWrapOutcome::InvalidRecord)?;
    if encoded.len() != 65 {
        return Err(KeyWrapOutcome::InvalidRecord);
    }
    <DhP256HkdfSha256 as HpkeKem>::PublicKey::from_bytes(&encoded)
        .map_err(|_| KeyWrapOutcome::InvalidRecord)
}

fn x25519_private_key_from_bytes(
    private_key_bytes: &[u8],
) -> Result<<X25519HkdfSha256 as HpkeKem>::PrivateKey, KeyWrapOutcome> {
    let raw = if private_key_bytes.len() == 32 {
        private_key_bytes.to_vec()
    } else {
        let private_key = PKey::private_key_from_der(private_key_bytes)
            .map_err(|_| KeyWrapOutcome::InvalidRecord)?;
        private_key
            .raw_private_key()
            .map_err(|_| KeyWrapOutcome::InvalidRecord)?
    };
    if raw.len() != 32 {
        return Err(KeyWrapOutcome::InvalidRecord);
    }
    <X25519HkdfSha256 as HpkeKem>::PrivateKey::from_bytes(&raw)
        .map_err(|_| KeyWrapOutcome::InvalidRecord)
}

fn p256_private_key_from_bytes(
    private_key_bytes: &[u8],
) -> Result<<DhP256HkdfSha256 as HpkeKem>::PrivateKey, KeyWrapOutcome> {
    let raw = if private_key_bytes.len() == 32 {
        private_key_bytes.to_vec()
    } else {
        let private_key = PKey::private_key_from_der(private_key_bytes)
            .map_err(|_| KeyWrapOutcome::InvalidRecord)?;
        let ec_key = private_key
            .ec_key()
            .map_err(|_| KeyWrapOutcome::InvalidRecord)?;
        ec_key
            .private_key()
            .to_vec_padded(32)
            .map_err(|_| KeyWrapOutcome::InvalidRecord)?
    };
    if raw.len() != 32 {
        return Err(KeyWrapOutcome::InvalidRecord);
    }
    <DhP256HkdfSha256 as HpkeKem>::PrivateKey::from_bytes(&raw)
        .map_err(|_| KeyWrapOutcome::InvalidRecord)
}

fn sha256_digest(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, KeyWrapOutcome> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or(KeyWrapOutcome::InvalidRecord)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, KeyWrapOutcome> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or(KeyWrapOutcome::InvalidRecord)?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_array_32(bytes: &[u8], offset: usize) -> Result<[u8; 32], KeyWrapOutcome> {
    let value = bytes
        .get(offset..offset + 32)
        .ok_or(KeyWrapOutcome::InvalidRecord)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(value);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    use openssl::{
        asn1::{Asn1Object, Asn1OctetString, Asn1Time},
        bn::{BigNum, MsbOption},
        ec::{EcGroup, EcKey},
        hash::MessageDigest,
        nid::Nid,
        pkey::{PKey, Private},
        rand::rand_bytes,
        rsa::Rsa,
        x509::{
            extension::BasicConstraints, extension::KeyUsage, X509Extension, X509NameBuilder, X509,
        },
    };

    #[derive(Debug)]
    struct NoMatchLookup;

    impl PrivateKeyLookup for NoMatchLookup {
        fn lookup_private_key(
            &self,
            _: &ArchiveIdentity,
            _: &RecipientRecordMetadata,
            _: &[u8],
        ) -> Option<Vec<u8>> {
            None
        }
    }

    #[derive(Debug)]
    struct StaticLookup {
        private_key: Vec<u8>,
    }

    impl PrivateKeyLookup for StaticLookup {
        fn lookup_private_key(
            &self,
            _: &ArchiveIdentity,
            _: &RecipientRecordMetadata,
            _: &[u8],
        ) -> Option<Vec<u8>> {
            Some(self.private_key.clone())
        }
    }

    #[derive(Debug)]
    struct RejectLookup;

    impl PrivateKeyLookup for RejectLookup {
        fn lookup_private_key(
            &self,
            _: &ArchiveIdentity,
            _: &RecipientRecordMetadata,
            _: &[u8],
        ) -> Option<Vec<u8>> {
            Some(vec![0xAA; 32])
        }

        fn is_recipient_certificate_accepted(
            &self,
            _: &ArchiveIdentity,
            _: &RecipientRecordMetadata,
            _: &[u8],
            _: &[u8; 32],
        ) -> bool {
            false
        }
    }

    #[derive(Debug)]
    struct MatchingLookup {
        matches: Vec<(Vec<u8>, Vec<u8>)>,
    }

    impl PrivateKeyLookup for MatchingLookup {
        fn lookup_private_key(
            &self,
            _: &ArchiveIdentity,
            _: &RecipientRecordMetadata,
            recipient_identity_bytes: &[u8],
        ) -> Option<Vec<u8>> {
            self.matches
                .iter()
                .find(|(identity, _)| identity.as_slice() == recipient_identity_bytes)
                .map(|(_, private_key)| private_key.clone())
        }
    }

    fn archive_identity() -> ArchiveIdentity {
        let mut archive_uuid = [0u8; 16];
        let mut session_id = [0u8; 16];
        rand_bytes(&mut archive_uuid).unwrap();
        rand_bytes(&mut session_id).unwrap();

        ArchiveIdentity {
            archive_uuid,
            session_id,
            format_version: FORMAT_VERSION,
            volume_format_rev: VOLUME_FORMAT_REV_45,
        }
    }

    fn test_certificate_der() -> Vec<u8> {
        make_self_signed_certificate(None)
    }

    fn test_certificate_der_with_bad_key_usage() -> Vec<u8> {
        let key_usage = KeyUsage::new()
            .critical()
            .digital_signature()
            .build()
            .unwrap();
        make_self_signed_certificate(Some(key_usage)).to_vec()
    }

    fn test_certificate_der_with_malformed_key_usage() -> Vec<u8> {
        let recipient_key = PKey::generate_x25519().unwrap();
        let key_usage = X509Extension::new_from_der(
            &Asn1Object::from_str("2.5.29.15").unwrap(),
            true,
            &Asn1OctetString::new_from_bytes(b"\x05\x00").unwrap(),
        )
        .unwrap();
        make_certificate_for_subject(&recipient_key, Some(key_usage))
    }

    fn x25519_recipient_material() -> (Vec<u8>, Vec<u8>) {
        let recipient_key = PKey::generate_x25519().unwrap();
        let key_usage = KeyUsage::new().critical().key_agreement().build().unwrap();
        (
            make_certificate_for_subject(&recipient_key, Some(key_usage)),
            recipient_key.raw_private_key().unwrap(),
        )
    }

    fn p256_recipient_material() -> (Vec<u8>, Vec<u8>) {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let recipient_key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let key_usage = KeyUsage::new().critical().key_agreement().build().unwrap();
        (
            make_certificate_for_subject(&recipient_key, Some(key_usage)),
            recipient_key.private_key_to_der().unwrap(),
        )
    }

    fn p384_recipient_certificate() -> Vec<u8> {
        let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        let recipient_key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let key_usage = KeyUsage::new().critical().key_agreement().build().unwrap();
        make_certificate_for_subject(&recipient_key, Some(key_usage))
    }

    fn make_self_signed_certificate(
        key_usage_ext: Option<openssl::x509::X509Extension>,
    ) -> Vec<u8> {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "tzap-keywrap-test")
            .unwrap();
        let name = name.build();

        let mut certificate = X509::builder().unwrap();
        certificate.set_version(2).unwrap();
        certificate
            .set_serial_number(&random_serial_number())
            .unwrap();
        certificate.set_subject_name(&name).unwrap();
        certificate.set_issuer_name(&name).unwrap();
        certificate.set_pubkey(&key).unwrap();
        certificate
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        certificate
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        certificate
            .append_extension(BasicConstraints::new().build().unwrap())
            .unwrap();
        if let Some(key_usage_ext) = key_usage_ext {
            certificate.append_extension(key_usage_ext).unwrap();
        }
        certificate.sign(&key, MessageDigest::sha256()).unwrap();

        certificate.build().to_der().unwrap()
    }

    fn make_certificate_for_subject(
        subject_key: &PKey<Private>,
        key_usage_ext: Option<openssl::x509::X509Extension>,
    ) -> Vec<u8> {
        let signer_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "tzap-keywrap-recipient")
            .unwrap();
        let name = name.build();

        let mut certificate = X509::builder().unwrap();
        certificate.set_version(2).unwrap();
        certificate
            .set_serial_number(&random_serial_number())
            .unwrap();
        certificate.set_subject_name(&name).unwrap();
        certificate.set_issuer_name(&name).unwrap();
        certificate.set_pubkey(subject_key).unwrap();
        certificate
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        certificate
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        certificate
            .append_extension(BasicConstraints::new().build().unwrap())
            .unwrap();
        if let Some(key_usage_ext) = key_usage_ext {
            certificate.append_extension(key_usage_ext).unwrap();
        }
        certificate
            .sign(&signer_key, MessageDigest::sha256())
            .unwrap();

        certificate.build().to_der().unwrap()
    }

    fn random_serial_number() -> openssl::asn1::Asn1Integer {
        let mut serial = BigNum::new().unwrap();
        serial.rand(159, MsbOption::MAYBE_ZERO, false).unwrap();
        serial.to_asn1_integer().unwrap()
    }

    fn make_payload(
        archive_identity: &ArchiveIdentity,
        metadata: &RecipientRecordMetadata,
        identity: &ParsedRecipientIdentity,
        suite: HpkeSuite,
    ) -> Vec<u8> {
        make_payload_with_lengths(
            archive_identity,
            metadata,
            identity,
            suite,
            suite.enc_length,
            suite.ciphertext_length,
        )
    }

    fn make_payload_with_lengths(
        archive_identity: &ArchiveIdentity,
        metadata: &RecipientRecordMetadata,
        identity: &ParsedRecipientIdentity,
        suite: HpkeSuite,
        enc_len: usize,
        ciphertext_len: usize,
    ) -> Vec<u8> {
        let mut payload = vec![0u8; KEYWRAP_PROFILE_PAYLOAD_HEADER_LEN + enc_len + ciphertext_len];
        payload[0..2].copy_from_slice(&KEYWRAP_PAYLOAD_VERSION.to_le_bytes());
        payload[2..4].copy_from_slice(&suite.kem_id.to_le_bytes());
        payload[4..6].copy_from_slice(&suite.kdf_id.to_le_bytes());
        payload[6..8].copy_from_slice(&suite.aead_id.to_le_bytes());
        payload[8..10].copy_from_slice(&u16::try_from(enc_len).unwrap().to_le_bytes());
        payload[10..12].copy_from_slice(&u16::try_from(ciphertext_len).unwrap().to_le_bytes());
        payload[16..48].copy_from_slice(&compute_key_wrap_context_digest(
            archive_identity,
            metadata,
            identity,
            suite,
        ));

        let enc_start = KEYWRAP_PROFILE_PAYLOAD_HEADER_LEN;
        let enc_end = enc_start + enc_len;
        let ct_end = enc_end + ciphertext_len;
        for value in payload[enc_start..enc_end].iter_mut() {
            *value = 0xAA;
        }
        for value in payload[enc_end..ct_end].iter_mut() {
            *value = 0x55;
        }

        payload
    }

    fn recipient_record_input_with_payload(
        profile_payload: Vec<u8>,
        cert_der: &[u8],
    ) -> RecipientRecordInput {
        let identity_digest = sha256_digest(cert_der);
        RecipientRecordInput {
            archive_identity: archive_identity(),
            metadata: RecipientRecordMetadata {
                profile_id: KEYWRAP_PROFILE_ID,
                recipient_identity_type: KEYWRAP_RECIPIENT_IDENTITY_TYPE_BYTES,
                recipient_identity_digest: identity_digest,
            },
            recipient_identity_bytes: cert_der.to_vec(),
            profile_payload_bytes: profile_payload,
        }
    }

    fn recipient_record_input_for_suite(cert_der: &[u8], suite: HpkeSuite) -> RecipientRecordInput {
        let identity = parse_x509_recipient_identity(cert_der).unwrap();
        let archive_identity = archive_identity();
        let metadata = RecipientRecordMetadata {
            profile_id: KEYWRAP_PROFILE_ID,
            recipient_identity_type: KEYWRAP_RECIPIENT_IDENTITY_TYPE_BYTES,
            recipient_identity_digest: identity.recipient_identity_digest,
        };
        let payload = make_payload(&archive_identity, &metadata, &identity, suite);
        RecipientRecordInput {
            archive_identity,
            metadata,
            recipient_identity_bytes: cert_der.to_vec(),
            profile_payload_bytes: payload,
        }
    }

    fn recipient_record_input_from_record(
        archive_identity: ArchiveIdentity,
        record: RecipientRecordV1,
    ) -> RecipientRecordInput {
        RecipientRecordInput {
            archive_identity,
            metadata: RecipientRecordMetadata {
                profile_id: record.profile_id,
                recipient_identity_type: record.recipient_identity_type,
                recipient_identity_digest: record.recipient_identity_digest,
            },
            recipient_identity_bytes: record.recipient_identity_bytes,
            profile_payload_bytes: record.profile_payload_bytes,
        }
    }

    #[test]
    fn malformed_recipient_identity_is_invalid() {
        let cert_der = b"not-a-certificate".to_vec();
        let profile_payload = vec![0u8; KEYWRAP_PROFILE_PAYLOAD_HEADER_LEN];

        let input = recipient_record_input_with_payload(profile_payload, &cert_der);
        let result = dispatch_key_wrap_record(input, &NoMatchLookup);

        assert!(matches!(result, KeyWrapOutcome::InvalidRecord));
    }

    #[test]
    fn unsupported_identity_type_is_returned() {
        let cert_der = test_certificate_der();
        let identity = parse_x509_recipient_identity(&cert_der).unwrap();

        let archive_identity = archive_identity();
        let suite =
            HpkeSuite::for_profile(X25519_KEM_ID, HKDF_SHA256_KDF_ID, CHACHA20POLY1305_AEAD_ID)
                .unwrap();
        let payload = make_payload(
            &archive_identity,
            &RecipientRecordMetadata {
                profile_id: KEYWRAP_PROFILE_ID,
                recipient_identity_type: KEYWRAP_RECIPIENT_IDENTITY_TYPE_BYTES,
                recipient_identity_digest: identity.recipient_identity_digest,
            },
            &identity,
            suite,
        );
        let mut input = recipient_record_input_with_payload(payload, &cert_der);
        input.metadata.recipient_identity_type = 0;

        let result = dispatch_key_wrap_record(input, &NoMatchLookup);

        assert!(matches!(
            result,
            KeyWrapOutcome::UnsupportedRecipientIdentity
        ));
    }

    #[test]
    fn unsupported_suite_is_invalid() {
        let cert_der = test_certificate_der();
        let identity = parse_x509_recipient_identity(&cert_der).unwrap();
        let archive_identity = archive_identity();
        let metadata = RecipientRecordMetadata {
            profile_id: KEYWRAP_PROFILE_ID,
            recipient_identity_type: KEYWRAP_RECIPIENT_IDENTITY_TYPE_BYTES,
            recipient_identity_digest: identity.recipient_identity_digest,
        };

        let unsupported_suite = HpkeSuite {
            kem_id: 0x00ff,
            kdf_id: 0x00ff,
            aead_id: 0x00ff,
            enc_length: 0,
            ciphertext_length: 0,
        };

        let payload = make_payload_with_lengths(
            &archive_identity,
            &metadata,
            &identity,
            unsupported_suite,
            0,
            0,
        );

        let input = recipient_record_input_with_payload(payload, &cert_der);
        let result = dispatch_key_wrap_record(input, &NoMatchLookup);

        assert!(matches!(result, KeyWrapOutcome::UnsupportedSuite));
    }

    #[test]
    fn wrong_lengths_rejected_as_invalid_record() {
        let cert_der = test_certificate_der();
        let identity = parse_x509_recipient_identity(&cert_der).unwrap();
        let archive_identity = archive_identity();
        let metadata = RecipientRecordMetadata {
            profile_id: KEYWRAP_PROFILE_ID,
            recipient_identity_type: KEYWRAP_RECIPIENT_IDENTITY_TYPE_BYTES,
            recipient_identity_digest: identity.recipient_identity_digest,
        };
        let suite =
            HpkeSuite::for_profile(X25519_KEM_ID, HKDF_SHA256_KDF_ID, CHACHA20POLY1305_AEAD_ID)
                .unwrap();

        let payload = make_payload_with_lengths(
            &archive_identity,
            &metadata,
            &identity,
            suite,
            suite.enc_length - 1,
            suite.ciphertext_length,
        );
        let input = recipient_record_input_with_payload(payload, &cert_der);

        let result = dispatch_key_wrap_record(input, &NoMatchLookup);

        assert!(matches!(result, KeyWrapOutcome::InvalidRecord));
    }

    #[test]
    fn header_field_mutations_rejected_as_invalid_record() {
        // §8 profile-payload header negatives: wrong version, non-zero flags,
        // and non-zero reserved bytes must all be rejected as InvalidRecord.
        let cert_der = test_certificate_der();
        let identity = parse_x509_recipient_identity(&cert_der).unwrap();
        let archive_identity = archive_identity();
        let metadata = RecipientRecordMetadata {
            profile_id: KEYWRAP_PROFILE_ID,
            recipient_identity_type: KEYWRAP_RECIPIENT_IDENTITY_TYPE_BYTES,
            recipient_identity_digest: identity.recipient_identity_digest,
        };
        let suite =
            HpkeSuite::for_profile(X25519_KEM_ID, HKDF_SHA256_KDF_ID, CHACHA20POLY1305_AEAD_ID)
                .unwrap();

        // payload_version != 1 (bytes 0..2)
        let mut payload = make_payload(&archive_identity, &metadata, &identity, suite);
        payload[0..2].copy_from_slice(&2u16.to_le_bytes());
        assert!(matches!(
            dispatch_key_wrap_record(
                recipient_record_input_with_payload(payload, &cert_der),
                &NoMatchLookup
            ),
            KeyWrapOutcome::InvalidRecord
        ));

        // flags != 0 (bytes 12..16)
        let mut payload = make_payload(&archive_identity, &metadata, &identity, suite);
        payload[12..16].copy_from_slice(&1u32.to_le_bytes());
        assert!(matches!(
            dispatch_key_wrap_record(
                recipient_record_input_with_payload(payload, &cert_der),
                &NoMatchLookup
            ),
            KeyWrapOutcome::InvalidRecord
        ));

        // reserved bytes 48..64 non-zero
        let mut payload = make_payload(&archive_identity, &metadata, &identity, suite);
        payload[48] = 0x01;
        assert!(matches!(
            dispatch_key_wrap_record(
                recipient_record_input_with_payload(payload, &cert_der),
                &NoMatchLookup
            ),
            KeyWrapOutcome::InvalidRecord
        ));
    }

    #[test]
    fn concatenated_certificate_bytes_rejected_as_invalid_record() {
        // §13 v8 multi-certificate recipient identity: concatenated DER
        // certificates must be rejected, not silently interpreted.
        let cert_der = test_certificate_der();
        let mut concatenated = cert_der.clone();
        concatenated.extend_from_slice(&test_certificate_der());
        let identity_digest = sha256_digest(&concatenated);
        let archive_identity = archive_identity();
        let metadata = RecipientRecordMetadata {
            profile_id: KEYWRAP_PROFILE_ID,
            recipient_identity_type: KEYWRAP_RECIPIENT_IDENTITY_TYPE_BYTES,
            recipient_identity_digest: identity_digest,
        };
        let identity = parse_x509_recipient_identity(&cert_der).unwrap();
        let suite =
            HpkeSuite::for_profile(X25519_KEM_ID, HKDF_SHA256_KDF_ID, CHACHA20POLY1305_AEAD_ID)
                .unwrap();
        let payload = make_payload(&archive_identity, &metadata, &identity, suite);
        let input = RecipientRecordInput {
            archive_identity,
            metadata,
            recipient_identity_bytes: concatenated,
            profile_payload_bytes: payload,
        };

        let result = dispatch_key_wrap_record(input, &NoMatchLookup);

        assert!(matches!(result, KeyWrapOutcome::InvalidRecord));
    }

    #[test]
    fn wrong_context_digest_is_invalid_record() {
        let (cert_der, private_key) = x25519_recipient_material();
        let identity = parse_x509_recipient_identity(&cert_der).unwrap();
        let archive_identity = archive_identity();
        let metadata = RecipientRecordMetadata {
            profile_id: KEYWRAP_PROFILE_ID,
            recipient_identity_type: KEYWRAP_RECIPIENT_IDENTITY_TYPE_BYTES,
            recipient_identity_digest: identity.recipient_identity_digest,
        };
        let suite =
            HpkeSuite::for_profile(X25519_KEM_ID, HKDF_SHA256_KDF_ID, CHACHA20POLY1305_AEAD_ID)
                .unwrap();
        let mut payload = make_payload(&archive_identity, &metadata, &identity, suite);
        payload[16] ^= 0xFF;

        let input = recipient_record_input_with_payload(payload, &cert_der);
        let result = dispatch_key_wrap_record(input, &StaticLookup { private_key });

        assert!(matches!(result, KeyWrapOutcome::InvalidRecord));
    }

    #[test]
    fn revision_45_never_retries_revision_44_hpke_aad() {
        let (cert_der, private_key) = x25519_recipient_material();
        let identity = parse_x509_recipient_identity(&cert_der).unwrap();
        let archive_identity = archive_identity();
        let metadata = RecipientRecordMetadata {
            profile_id: KEYWRAP_PROFILE_ID,
            recipient_identity_type: KEYWRAP_RECIPIENT_IDENTITY_TYPE_BYTES,
            recipient_identity_digest: identity.recipient_identity_digest,
        };
        let suite =
            HpkeSuite::for_profile(X25519_KEM_ID, HKDF_SHA256_KDF_ID, CHACHA20POLY1305_AEAD_ID)
                .unwrap();
        let payload = hpke_seal_master_key_with_aad_domain(
            &cert_der,
            &archive_identity,
            &metadata,
            &identity,
            &[0x42; 32],
            suite,
            b"tzap-keywrap-master-key-v44\0",
        )
        .unwrap();
        let input = RecipientRecordInput {
            archive_identity,
            metadata,
            recipient_identity_bytes: cert_der,
            profile_payload_bytes: payload,
        };

        assert!(matches!(
            dispatch_key_wrap_record(input, &StaticLookup { private_key }),
            KeyWrapOutcome::InvalidRecord
        ));
    }

    #[test]
    fn revision_44_archive_identity_is_rejected_without_compatibility_dispatch() {
        let (cert_der, _) = x25519_recipient_material();
        let mut identity = archive_identity();
        identity.volume_format_rev = 44;
        assert!(matches!(
            wrap_master_key_for_recipient(
                identity,
                &cert_der,
                &[0x42; 32],
                KeyWrapSuite::X25519HkdfSha256ChaCha20Poly1305,
            ),
            Err(KeyWrapOutcome::UnsupportedArchiveIdentity)
        ));
    }

    #[test]
    fn no_matching_private_key_precedes_context_digest_check() {
        let (cert_der, _) = x25519_recipient_material();
        let identity = parse_x509_recipient_identity(&cert_der).unwrap();
        let archive_identity = archive_identity();
        let metadata = RecipientRecordMetadata {
            profile_id: KEYWRAP_PROFILE_ID,
            recipient_identity_type: KEYWRAP_RECIPIENT_IDENTITY_TYPE_BYTES,
            recipient_identity_digest: identity.recipient_identity_digest,
        };
        let suite =
            HpkeSuite::for_profile(X25519_KEM_ID, HKDF_SHA256_KDF_ID, CHACHA20POLY1305_AEAD_ID)
                .unwrap();
        let mut payload = make_payload(&archive_identity, &metadata, &identity, suite);
        payload[16] ^= 0xFF;

        let input = recipient_record_input_with_payload(payload, &cert_der);
        let result = dispatch_key_wrap_record(input, &NoMatchLookup);

        assert!(matches!(result, KeyWrapOutcome::NoMatchingPrivateKey));
    }

    #[test]
    fn certificate_policy_rejection_precedes_context_digest_check() {
        let (cert_der, _) = x25519_recipient_material();
        let identity = parse_x509_recipient_identity(&cert_der).unwrap();
        let archive_identity = archive_identity();
        let metadata = RecipientRecordMetadata {
            profile_id: KEYWRAP_PROFILE_ID,
            recipient_identity_type: KEYWRAP_RECIPIENT_IDENTITY_TYPE_BYTES,
            recipient_identity_digest: identity.recipient_identity_digest,
        };
        let suite =
            HpkeSuite::for_profile(X25519_KEM_ID, HKDF_SHA256_KDF_ID, CHACHA20POLY1305_AEAD_ID)
                .unwrap();
        let mut payload = make_payload(&archive_identity, &metadata, &identity, suite);
        payload[16] ^= 0xFF;

        let input = recipient_record_input_with_payload(payload, &cert_der);
        let result = dispatch_key_wrap_record(input, &RejectLookup);

        assert!(matches!(result, KeyWrapOutcome::CertificatePolicyRejected));
    }

    #[test]
    fn valid_structure_with_no_matching_private_key_is_no_matching() {
        let archive_identity = archive_identity();
        let (cert_der, _) = x25519_recipient_material();
        let master_key = [0x42u8; 32];
        let record = wrap_master_key_for_recipient(
            archive_identity.clone(),
            &cert_der,
            &master_key,
            KeyWrapSuite::X25519HkdfSha256ChaCha20Poly1305,
        )
        .unwrap();
        let input = recipient_record_input_from_record(archive_identity, record);

        let result = dispatch_key_wrap_record(input, &NoMatchLookup);

        assert!(matches!(result, KeyWrapOutcome::NoMatchingPrivateKey));
    }

    #[test]
    fn key_usage_without_key_agreement_is_invalid_record() {
        let cert_der = test_certificate_der_with_bad_key_usage();
        let payload = vec![0u8; KEYWRAP_PROFILE_PAYLOAD_HEADER_LEN];
        let input = recipient_record_input_with_payload(payload, &cert_der);

        let result = dispatch_key_wrap_record(input, &NoMatchLookup);

        assert!(matches!(result, KeyWrapOutcome::InvalidRecord));
    }

    #[test]
    fn malformed_key_usage_extension_is_invalid_record() {
        let cert_der = test_certificate_der_with_malformed_key_usage();
        let payload = vec![0u8; KEYWRAP_PROFILE_PAYLOAD_HEADER_LEN];
        let input = recipient_record_input_with_payload(payload, &cert_der);

        let result = dispatch_key_wrap_record(input, &NoMatchLookup);

        assert!(matches!(result, KeyWrapOutcome::InvalidRecord));
    }

    #[test]
    fn certificate_policy_rejection_is_reported() {
        let archive_identity = archive_identity();
        let (cert_der, _) = x25519_recipient_material();
        let master_key = [0x42u8; 32];
        let record = wrap_master_key_for_recipient(
            archive_identity.clone(),
            &cert_der,
            &master_key,
            KeyWrapSuite::X25519HkdfSha256ChaCha20Poly1305,
        )
        .unwrap();
        let input = recipient_record_input_from_record(archive_identity, record);

        let result = dispatch_key_wrap_record(input, &RejectLookup);

        assert!(matches!(result, KeyWrapOutcome::CertificatePolicyRejected));
    }

    #[test]
    fn suite_certificate_mismatch_is_unsupported_before_private_key_lookup() {
        let (p256_cert_der, _) = p256_recipient_material();
        let x25519_suite =
            HpkeSuite::for_profile(X25519_KEM_ID, HKDF_SHA256_KDF_ID, CHACHA20POLY1305_AEAD_ID)
                .unwrap();
        let result = dispatch_key_wrap_record(
            recipient_record_input_for_suite(&p256_cert_der, x25519_suite),
            &NoMatchLookup,
        );
        assert!(matches!(result, KeyWrapOutcome::UnsupportedSuite));

        let (x25519_cert_der, _) = x25519_recipient_material();
        let p256_suite =
            HpkeSuite::for_profile(P256_KEM_ID, HKDF_SHA256_KDF_ID, AES256GCM_AEAD_ID).unwrap();
        let result = dispatch_key_wrap_record(
            recipient_record_input_for_suite(&x25519_cert_der, p256_suite),
            &NoMatchLookup,
        );
        assert!(matches!(result, KeyWrapOutcome::UnsupportedSuite));

        let p384_cert_der = p384_recipient_certificate();
        let result = dispatch_key_wrap_record(
            recipient_record_input_for_suite(&p384_cert_der, p256_suite),
            &NoMatchLookup,
        );
        assert!(matches!(result, KeyWrapOutcome::UnsupportedSuite));
    }

    #[test]
    fn writer_reports_unsupported_suite_for_certificate_mismatch() {
        let master_key = [0x42u8; 32];
        let (p256_cert_der, _) = p256_recipient_material();
        let result = wrap_master_key_for_recipient(
            archive_identity(),
            &p256_cert_der,
            &master_key,
            KeyWrapSuite::X25519HkdfSha256ChaCha20Poly1305,
        );
        assert!(matches!(result, Err(KeyWrapOutcome::UnsupportedSuite)));

        let (x25519_cert_der, _) = x25519_recipient_material();
        let result = wrap_master_key_for_recipient(
            archive_identity(),
            &x25519_cert_der,
            &master_key,
            KeyWrapSuite::P256HkdfSha256Aes256Gcm,
        );
        assert!(matches!(result, Err(KeyWrapOutcome::UnsupportedSuite)));
    }

    #[test]
    fn x25519_wrap_unwrap_returns_candidate_master_key() {
        let (cert_der, private_key) = x25519_recipient_material();
        let identity = parse_x509_recipient_identity(&cert_der).unwrap();
        let archive_identity = archive_identity();
        let master_key = [0x42u8; 32];
        let record = wrap_master_key_for_recipient(
            archive_identity.clone(),
            &cert_der,
            &master_key,
            KeyWrapSuite::X25519HkdfSha256ChaCha20Poly1305,
        )
        .unwrap();
        let input = recipient_record_input_from_record(archive_identity, record);

        let result = dispatch_key_wrap_record(input, &StaticLookup { private_key });

        assert!(matches!(
            result,
            KeyWrapOutcome::UnwrappedCandidateMasterKey {
                master_key: actual_master_key,
                recipient_spki_digest: actual_digest
            } if actual_master_key == master_key && actual_digest == identity.recipient_spki_digest
        ));
    }

    #[test]
    fn p256_wrap_unwrap_returns_candidate_master_key() {
        let (cert_der, private_key) = p256_recipient_material();
        let identity = parse_x509_recipient_identity(&cert_der).unwrap();
        let archive_identity = archive_identity();
        let master_key = [0x24u8; 32];
        let record = wrap_master_key_for_recipient(
            archive_identity.clone(),
            &cert_der,
            &master_key,
            KeyWrapSuite::P256HkdfSha256Aes256Gcm,
        )
        .unwrap();
        let input = recipient_record_input_from_record(archive_identity, record);

        let result = dispatch_key_wrap_record(input, &StaticLookup { private_key });

        assert!(matches!(
            result,
            KeyWrapOutcome::UnwrappedCandidateMasterKey {
                master_key: actual_master_key,
                recipient_spki_digest: actual_digest
            } if actual_master_key == master_key && actual_digest == identity.recipient_spki_digest
        ));
    }

    #[test]
    fn multi_recipient_records_open_independently_with_matching_private_key() {
        let archive_identity = archive_identity();
        let master_key = [0x33u8; 32];
        let (bob_cert, bob_key) = x25519_recipient_material();
        let (carol_cert, carol_key) = p256_recipient_material();
        let (ops_cert, ops_key) = x25519_recipient_material();
        let recipients = [
            (
                bob_cert,
                bob_key,
                KeyWrapSuite::X25519HkdfSha256ChaCha20Poly1305,
            ),
            (carol_cert, carol_key, KeyWrapSuite::P256HkdfSha256Aes256Gcm),
            (
                ops_cert,
                ops_key,
                KeyWrapSuite::X25519HkdfSha256ChaCha20Poly1305,
            ),
        ];
        let records = recipients
            .iter()
            .map(|(cert_der, _, suite)| {
                wrap_master_key_for_recipient(
                    archive_identity.clone(),
                    cert_der,
                    &master_key,
                    *suite,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        for (cert_der, private_key, _) in recipients {
            let lookup = MatchingLookup {
                matches: vec![(cert_der.clone(), private_key)],
            };
            let unwrapped = records
                .clone()
                .into_iter()
                .filter_map(|record| {
                    let input =
                        recipient_record_input_from_record(archive_identity.clone(), record);
                    match dispatch_key_wrap_record(input, &lookup) {
                        KeyWrapOutcome::UnwrappedCandidateMasterKey {
                            master_key: candidate,
                            ..
                        } => Some(candidate),
                        KeyWrapOutcome::NoMatchingPrivateKey => None,
                        other => panic!("unexpected key-wrap outcome: {other:?}"),
                    }
                })
                .collect::<Vec<_>>();

            assert_eq!(unwrapped, vec![master_key]);
        }
    }

    #[test]
    fn wrong_private_key_is_invalid_record() {
        let (cert_der, _private_key) = x25519_recipient_material();
        let (_wrong_cert_der, wrong_private_key) = x25519_recipient_material();
        let archive_identity = archive_identity();
        let master_key = [0x5au8; 32];
        let record = wrap_master_key_for_recipient(
            archive_identity.clone(),
            &cert_der,
            &master_key,
            KeyWrapSuite::X25519HkdfSha256ChaCha20Poly1305,
        )
        .unwrap();
        let input = recipient_record_input_from_record(archive_identity, record);

        let result = dispatch_key_wrap_record(
            input,
            &StaticLookup {
                private_key: wrong_private_key,
            },
        );

        assert!(matches!(result, KeyWrapOutcome::InvalidRecord));
    }

    #[test]
    fn signing_certificate_key_usage_does_not_satisfy_recipient_wrap() {
        let cert_der = test_certificate_der_with_bad_key_usage();
        let master_key = [0x42u8; 32];

        let result = wrap_master_key_for_recipient(
            archive_identity(),
            &cert_der,
            &master_key,
            KeyWrapSuite::X25519HkdfSha256ChaCha20Poly1305,
        );

        assert!(matches!(result, Err(KeyWrapOutcome::InvalidRecord)));
    }
}
