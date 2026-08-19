use std::time::{SystemTime, UNIX_EPOCH};
use std::{cmp::Ordering, fmt};

use openssl::bn::{BigNum, BigNumContext, BigNumRef};
use openssl::ecdsa::EcdsaSig;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{HasParams, HasPublic, Id, PKey, PKeyRef, Private};
use openssl::rsa::Padding;
use openssl::sign::{RsaPssSaltlen, Signer, Verifier};
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::X509VerifyParam;
use openssl::x509::{X509NameRef, X509StoreContext, X509};
use sha2::{Digest, Sha256, Sha512};
use tzap_core::format::{root_auth_spec_id_for_revision, ROOT_AUTH_SPEC_ID};
use tzap_core::wire::RootAuthFooterV1;
use tzap_core::writer::{RootAuthSigningRequest, RootAuthWriterConfig};
use x509_parser::prelude::FromDer;
use x509_parser::signature_algorithm::{RsaSsaPssParams, SignatureAlgorithm};
use x509_parser::x509::AlgorithmIdentifier;

pub const X509_AUTHENTICATOR_ID: u16 = 0x0003;
pub const X509_SIGNER_IDENTITY_TYPE_DER_CERT: u16 = 2;

const MAGIC: &[u8; 4] = b"TZXC";
const VERSION: u16 = 1;
const SIG_SCHEME_RSA_PKCS1_SHA256: u16 = 1;
const SIG_SCHEME_ECDSA_SHA256_DER: u16 = 2;
const SIG_SCHEME_RSA_PSS_SHA256: u16 = 3;
const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const OID_RSASSA_PSS: &str = "1.2.840.113549.1.1.10";
const OID_MGF1: &str = "1.2.840.113549.1.1.8";
const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
const X509_SIGNING_DOMAIN: &[u8] = b"tzap-sig-x509-v1\0";
const X509_CHAIN_DOMAIN: &[u8] = b"tzap-x509-chain-v1\0";
const AUTHENTICATOR_FIXED_LEN: usize = 60;
const SHA256_LEN: usize = 32;

#[derive(Debug)]
pub enum X509RootAuthError {
    Invalid(&'static str),
    UnsupportedIdentity,
    MissingTrustPolicy,
    UntrustedChain(String),
    Crypto(ErrorStack),
    Chain(String),
}

impl fmt::Display for X509RootAuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => formatter.write_str(message),
            Self::UnsupportedIdentity => formatter.write_str("unsupported signer identity type"),
            Self::MissingTrustPolicy => formatter.write_str("X.509 verification requires trusted roots"),
            Self::UntrustedChain(message) => formatter.write_str(message),
            Self::Crypto(err) => write!(formatter, "{err}"),
            Self::Chain(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for X509RootAuthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Crypto(err) => Some(err),
            _ => None,
        }
    }
}

impl From<ErrorStack> for X509RootAuthError {
    fn from(err: ErrorStack) -> Self {
        Self::Crypto(err)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509RootAuthReport {
    pub signed_at_unix_seconds: i64,
    pub signature_scheme: &'static str,
    pub chain_validation_time_unix_seconds: i64,
    pub trust_store_policy: &'static str,
    pub x509_time_policy: &'static str,
    pub chain_time_basis: &'static str,
    pub trusted_timestamp: bool,
    pub revocation_checked: bool,
    pub key_usage_policy: &'static str,
    pub eku_policy: &'static str,
    pub subject: String,
    pub issuer: String,
    pub serial_number_hex: String,
    pub certificate_sha256: [u8; SHA256_LEN],
    pub verified_chain_subjects: Vec<String>,
    pub trust_anchor_subject: Option<String>,
}

#[derive(Debug)]
pub struct X509RootAuthSigner {
    leaf_certificate_der: Vec<u8>,
    private_key: PKey<Private>,
    chain_certificate_der: Vec<Vec<u8>>,
    signed_at_unix_seconds: i64,
    signature_capacity: usize,
    sig_scheme: u16,
}

impl X509RootAuthSigner {
    pub fn from_pem_or_der(
        leaf_certificate_bytes: &[u8],
        private_key_bytes: &[u8],
        chain_certificate_der: Vec<Vec<u8>>,
        signed_at_unix_seconds: i64,
    ) -> Result<Self, X509RootAuthError> {
        let leaf_certificate_der = certificate_der_from_pem_or_der(leaf_certificate_bytes)?;
        let private_key = private_key_from_pem_or_der(private_key_bytes)?;
        Self::new(leaf_certificate_der, private_key, chain_certificate_der, signed_at_unix_seconds)
    }

    pub fn from_pem_or_der_with_signature_scheme(
        leaf_certificate_bytes: &[u8],
        private_key_bytes: &[u8],
        chain_certificate_der: Vec<Vec<u8>>,
        signed_at_unix_seconds: i64,
        signature_scheme: X509SignatureScheme,
    ) -> Result<Self, X509RootAuthError> {
        let leaf_certificate_der = certificate_der_from_pem_or_der(leaf_certificate_bytes)?;
        let private_key = private_key_from_pem_or_der(private_key_bytes)?;
        Self::new_with_signature_scheme(leaf_certificate_der, private_key, chain_certificate_der, signed_at_unix_seconds, Some(signature_scheme))
    }

    pub fn new(
        leaf_certificate_der: Vec<u8>,
        private_key: PKey<Private>,
        chain_certificate_der: Vec<Vec<u8>>,
        signed_at_unix_seconds: i64,
    ) -> Result<Self, X509RootAuthError> {
        Self::new_with_signature_scheme(leaf_certificate_der, private_key, chain_certificate_der, signed_at_unix_seconds, None)
    }

    pub fn new_with_signature_scheme(
        leaf_certificate_der: Vec<u8>,
        private_key: PKey<Private>,
        chain_certificate_der: Vec<Vec<u8>>,
        signed_at_unix_seconds: i64,
        signature_scheme: Option<X509SignatureScheme>,
    ) -> Result<Self, X509RootAuthError> {
        let leaf_certificate = X509::from_der(&leaf_certificate_der)?;
        let leaf_certificate_der = leaf_certificate.to_der()?;
        let leaf_public_key = leaf_certificate.public_key()?;
        if !leaf_public_key.public_eq(&private_key) {
            return Err(X509RootAuthError::Invalid("certificate public key does not match private key"));
        }
        if matches!(private_key.id(), Id::ED25519 | Id::ED448) {
            return Err(X509RootAuthError::Invalid("EdDSA X.509 keys are not supported by this RootAuth profile"));
        }
        let sig_scheme = match signature_scheme {
            Some(scheme) => {
                validate_private_key_matches_scheme(scheme.wire_id(), &private_key)?;
                scheme.wire_id()
            }
            None => signature_scheme_for_private_key(&private_key)?,
        };
        validate_rsa_spki_signature_scheme(sig_scheme, &leaf_certificate_der)?;
        let chain_certificate_der = normalize_certificate_der_chain(chain_certificate_der)?;
        let signature_capacity = private_key.size();
        let signer = Self { leaf_certificate_der, private_key, chain_certificate_der, signed_at_unix_seconds, signature_capacity, sig_scheme };
        signer.authenticator_value_length()?;
        Ok(signer)
    }

    pub fn signer_identity(&self) -> &[u8] {
        &self.leaf_certificate_der
    }

    pub fn authenticator_value_length(&self) -> Result<u32, X509RootAuthError> {
        authenticator_value_len(self.signature_capacity, &self.chain_certificate_der)
    }

    pub fn root_auth_writer_config(&self) -> Result<RootAuthWriterConfig<'_>, X509RootAuthError> {
        Ok(RootAuthWriterConfig {
            authenticator_id: X509_AUTHENTICATOR_ID,
            signer_identity_type: X509_SIGNER_IDENTITY_TYPE_DER_CERT,
            signer_identity: self.signer_identity(),
            authenticator_value_length: self.authenticator_value_length()?,
        })
    }

    pub fn authenticator_value_for_request(&self, request: &RootAuthSigningRequest) -> Result<Vec<u8>, X509RootAuthError> {
        let chain_digest = chain_digest(&self.chain_certificate_der)?;
        let signing_input = signing_input_for_root_auth_spec_id(
            &request.root_auth_spec_id,
            &request.archive_uuid,
            &request.session_id,
            &request.archive_root,
            self.signed_at_unix_seconds,
            &chain_digest,
        );
        let mut signer = signer_for_scheme(self.sig_scheme, &self.private_key)?;
        signer.update(&signing_input)?;
        let signature = normalize_signature_for_scheme(self.sig_scheme, &self.private_key, signer.sign_to_vec()?)?;
        if signature.len() > self.signature_capacity {
            return Err(X509RootAuthError::Invalid("signature exceeded reserved authenticator capacity"));
        }

        let mut out = Vec::with_capacity(self.authenticator_value_length()? as usize);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&self.sig_scheme.to_le_bytes());
        out.extend_from_slice(&self.signed_at_unix_seconds.to_le_bytes());
        out.extend_from_slice(&chain_digest);
        out.extend_from_slice(&u32_len(signature.len(), "signature length")?.to_le_bytes());
        out.extend_from_slice(&u32_len(self.signature_capacity, "signature capacity")?.to_le_bytes());
        out.extend_from_slice(&u32_len(self.chain_certificate_der.len(), "chain count")?.to_le_bytes());
        out.extend_from_slice(&signature);
        out.resize(out.len() + (self.signature_capacity - signature.len()), 0);
        for cert_der in &self.chain_certificate_der {
            out.extend_from_slice(&u32_len(cert_der.len(), "chain certificate length")?.to_le_bytes());
            out.extend_from_slice(cert_der);
        }
        Ok(out)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X509SignatureScheme {
    RsaPkcs1Sha256,
    EcdsaSha256Der,
    RsaPssSha256,
}

impl X509SignatureScheme {
    fn wire_id(self) -> u16 {
        match self {
            Self::RsaPkcs1Sha256 => SIG_SCHEME_RSA_PKCS1_SHA256,
            Self::EcdsaSha256Der => SIG_SCHEME_ECDSA_SHA256_DER,
            Self::RsaPssSha256 => SIG_SCHEME_RSA_PSS_SHA256,
        }
    }
}

pub fn signing_input(
    archive_uuid: &[u8; 16],
    session_id: &[u8; 16],
    archive_root: &[u8; 32],
    signed_at_unix_seconds: i64,
    chain_digest: &[u8; SHA256_LEN],
) -> [u8; 64] {
    signing_input_for_root_auth_spec_id(&ROOT_AUTH_SPEC_ID, archive_uuid, session_id, archive_root, signed_at_unix_seconds, chain_digest)
}

pub fn signing_input_for_root_auth_spec_id(
    root_auth_spec_id: &[u8; 24],
    archive_uuid: &[u8; 16],
    session_id: &[u8; 16],
    archive_root: &[u8; 32],
    signed_at_unix_seconds: i64,
    chain_digest: &[u8; SHA256_LEN],
) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(X509_SIGNING_DOMAIN);
    hasher.update(root_auth_spec_id);
    hasher.update(archive_uuid);
    hasher.update(session_id);
    hasher.update(archive_root);
    hasher.update(signed_at_unix_seconds.to_le_bytes());
    hasher.update(chain_digest);
    let digest = hasher.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    out
}

pub fn certificate_der_from_pem_or_der(bytes: &[u8]) -> Result<Vec<u8>, X509RootAuthError> {
    if let Ok(cert) = X509::from_pem(bytes) {
        return Ok(cert.to_der()?);
    }
    Ok(X509::from_der(bytes)?.to_der()?)
}

pub fn certificates_der_from_pem_or_der(bytes: &[u8]) -> Result<Vec<Vec<u8>>, X509RootAuthError> {
    if let Ok(certs) = X509::stack_from_pem(bytes) {
        if certs.is_empty() {
            return Err(X509RootAuthError::Invalid("certificate PEM file is empty"));
        }
        return certs.into_iter().map(|cert| cert.to_der().map_err(Into::into)).collect();
    }
    Ok(vec![X509::from_der(bytes)?.to_der()?])
}

fn normalize_certificate_der_chain(chain_certificate_der: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>, X509RootAuthError> {
    chain_certificate_der.into_iter().map(|cert_der| Ok(X509::from_der(&cert_der)?.to_der()?)).collect()
}

pub fn verify_root_auth_footer(
    footer: &RootAuthFooterV1,
    archive_root: &[u8; 32],
    trusted_roots_der: &[Vec<u8>],
    use_system_roots: bool,
    include_official_tzap_root: bool,
) -> Result<X509RootAuthReport, X509RootAuthError> {
    if footer.authenticator_id != X509_AUTHENTICATOR_ID {
        return Err(X509RootAuthError::Invalid("unsupported authenticator id"));
    }
    if footer.signer_identity_type != X509_SIGNER_IDENTITY_TYPE_DER_CERT {
        return Err(X509RootAuthError::UnsupportedIdentity);
    }

    let leaf_certificate = X509::from_der(&footer.signer_identity_bytes).map_err(|_| X509RootAuthError::Invalid("invalid X.509 signer identity"))?;
    let parsed = parse_authenticator_value(&footer.authenticator_value)?;
    let root_auth_spec_id = root_auth_spec_id_for_revision(footer.format_version, footer.volume_format_rev)
        .map_err(|_| X509RootAuthError::Invalid("unsupported RootAuthFooter root_auth_spec_id"))?;
    let signing_input = signing_input_for_root_auth_spec_id(
        &root_auth_spec_id,
        &footer.archive_uuid,
        &footer.session_id,
        archive_root,
        parsed.signed_at_unix_seconds,
        &parsed.chain_digest,
    );
    let leaf_public_key = leaf_certificate.public_key()?;
    validate_rsa_spki_signature_scheme(parsed.sig_scheme, footer.signer_identity_bytes.as_slice())?;
    validate_public_key_matches_scheme(parsed.sig_scheme, &leaf_public_key)?;
    validate_signature_for_scheme(parsed.sig_scheme, &leaf_public_key, &parsed.signature)?;
    let mut verifier = verifier_for_scheme(parsed.sig_scheme, &leaf_public_key)?;
    verifier.update(&signing_input)?;
    if !verifier.verify(&parsed.signature)? {
        return Err(X509RootAuthError::Invalid("X.509 RootAuth signature failed"));
    }
    validate_leaf_key_usage(&footer.signer_identity_bytes)?;
    if trusted_roots_der.is_empty() && !use_system_roots {
        return Err(X509RootAuthError::MissingTrustPolicy);
    }

    let chain_validation_time_unix_seconds = current_unix_seconds()?;
    let verified_chain_subjects =
        verify_certificate_chain(&leaf_certificate, &parsed.chain_certificate_der, trusted_roots_der, use_system_roots, chain_validation_time_unix_seconds)?;
    let fingerprint = leaf_certificate.digest(MessageDigest::sha256())?;
    let mut certificate_sha256 = [0u8; SHA256_LEN];
    certificate_sha256.copy_from_slice(&fingerprint);
    let trust_anchor_subject = verified_chain_subjects.last().cloned();

    Ok(X509RootAuthReport {
        signed_at_unix_seconds: parsed.signed_at_unix_seconds,
        signature_scheme: signature_scheme_name(parsed.sig_scheme),
        chain_validation_time_unix_seconds,
        trust_store_policy: trust_store_policy_label(trusted_roots_der, use_system_roots, include_official_tzap_root),
        x509_time_policy: "verifier_current_time",
        chain_time_basis: "verifier_current_time",
        trusted_timestamp: false,
        revocation_checked: false,
        key_usage_policy: "archive_signature_minimal",
        eku_policy: "none",
        subject: name_to_string(leaf_certificate.subject_name()),
        issuer: name_to_string(leaf_certificate.issuer_name()),
        serial_number_hex: leaf_certificate.serial_number().to_bn()?.to_hex_str()?.to_string(),
        certificate_sha256,
        verified_chain_subjects,
        trust_anchor_subject,
    })
}

/// Report for the trustless assertion-1 check: the embedded leaf key really
/// signed the footer over the recomputed `archive_root`.
///
/// This report intentionally carries NO trust-derived fields: consumers must
/// not render a "verified/trusted" verdict from it. Pair with
/// `verify_root_auth_footer` whenever chain/trust/time claims are required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509RootAuthSignatureReport {
    /// Signature scheme (same values as `X509RootAuthReport`):
    /// `"rsa-pkcs1-sha256"`, `"ecdsa-sha256-der"`, or `"rsa-pss-sha256"`.
    pub signature_scheme: String,
    /// Signer-claimed Unix seconds, from the authenticator envelope
    /// (offset 8..16, little-endian).
    pub signed_at_unix_seconds: i64,
    /// SHA-256 digest of the embedded leaf certificate (DER).
    pub certificate_sha256: [u8; SHA256_LEN],
}

/// Verify that the embedded X.509 leaf key really signed this footer over
/// `archive_root` — a standalone signature check with NO trust evaluation:
/// no chain verification, no trusted roots, no time or revocation checks.
///
/// Callers MUST pass the *recomputed* archive root (e.g. the one returned by
/// `tzap_core::reader::public_no_key_inspect_footer`, which validates the
/// recompute against the stored value), never a raw stored value — the
/// signing input binds the recomputed root, not an untrusted stored one.
///
/// Any `Err` means "not authentic". A signature mismatch yields exactly
/// `Invalid("X.509 RootAuth signature failed")`, distinct from parse errors.
pub fn verify_root_auth_signature(footer: &RootAuthFooterV1, archive_root: &[u8; 32]) -> Result<X509RootAuthSignatureReport, X509RootAuthError> {
    if footer.authenticator_id != X509_AUTHENTICATOR_ID {
        return Err(X509RootAuthError::Invalid("unsupported authenticator id"));
    }
    if footer.signer_identity_type != X509_SIGNER_IDENTITY_TYPE_DER_CERT {
        return Err(X509RootAuthError::UnsupportedIdentity);
    }

    let leaf_certificate = X509::from_der(&footer.signer_identity_bytes).map_err(|_| X509RootAuthError::Invalid("invalid X.509 signer identity"))?;
    let parsed = parse_authenticator_value(&footer.authenticator_value)?;
    let root_auth_spec_id = root_auth_spec_id_for_revision(footer.format_version, footer.volume_format_rev)
        .map_err(|_| X509RootAuthError::Invalid("unsupported RootAuthFooter root_auth_spec_id"))?;
    let signing_input = signing_input_for_root_auth_spec_id(
        &root_auth_spec_id,
        &footer.archive_uuid,
        &footer.session_id,
        archive_root,
        parsed.signed_at_unix_seconds,
        &parsed.chain_digest,
    );
    let leaf_public_key = leaf_certificate.public_key()?;
    validate_rsa_spki_signature_scheme(parsed.sig_scheme, footer.signer_identity_bytes.as_slice())?;
    validate_public_key_matches_scheme(parsed.sig_scheme, &leaf_public_key)?;
    validate_signature_for_scheme(parsed.sig_scheme, &leaf_public_key, &parsed.signature)?;
    let mut verifier = verifier_for_scheme(parsed.sig_scheme, &leaf_public_key)?;
    verifier.update(&signing_input)?;
    if !verifier.verify(&parsed.signature)? {
        return Err(X509RootAuthError::Invalid("X.509 RootAuth signature failed"));
    }
    validate_leaf_key_usage(&footer.signer_identity_bytes)?;

    let fingerprint = leaf_certificate.digest(MessageDigest::sha256())?;
    let mut certificate_sha256 = [0u8; SHA256_LEN];
    certificate_sha256.copy_from_slice(&fingerprint);

    Ok(X509RootAuthSignatureReport {
        signature_scheme: signature_scheme_name(parsed.sig_scheme).to_string(),
        signed_at_unix_seconds: parsed.signed_at_unix_seconds,
        certificate_sha256,
    })
}

fn validate_rsa_spki_signature_scheme(sig_scheme: u16, leaf_certificate_bytes: &[u8]) -> Result<(), X509RootAuthError> {
    let (remaining, certificate) = x509_parser::certificate::X509Certificate::from_der(leaf_certificate_bytes)
        .map_err(|_| X509RootAuthError::Invalid("failed to parse leaf certificate"))?;
    if !remaining.is_empty() {
        return Err(X509RootAuthError::Invalid("leaf certificate has trailing data"));
    }

    validate_rsa_spki_algorithm_for_scheme(sig_scheme, &certificate.tbs_certificate.subject_pki.algorithm)
}

fn validate_rsa_spki_algorithm_for_scheme(sig_scheme: u16, spki_algorithm: &AlgorithmIdentifier<'_>) -> Result<(), X509RootAuthError> {
    let spki_oid = spki_algorithm.algorithm.to_id_string();
    match sig_scheme {
        SIG_SCHEME_RSA_PKCS1_SHA256 if spki_oid != OID_RSA_ENCRYPTION => {
            return Err(X509RootAuthError::Invalid("rsa-pkcs1-sha256 requires unconstrained rsaEncryption SubjectPublicKeyInfo"));
        }
        SIG_SCHEME_RSA_PSS_SHA256 => {
            if spki_oid == OID_RSA_ENCRYPTION {
                return Ok(());
            }
            if spki_oid != OID_RSASSA_PSS {
                return Err(X509RootAuthError::Invalid("rsa-pss-sha256 requires RSA SubjectPublicKeyInfo"));
            }

            let signature_algorithm = SignatureAlgorithm::try_from(spki_algorithm)
                .map_err(|_| X509RootAuthError::Invalid("unsupported leaf SubjectPublicKeyInfo RSA-PSS parameters"))?;
            let SignatureAlgorithm::RSASSA_PSS(params) = signature_algorithm else {
                return Err(X509RootAuthError::Invalid("rsa-pss-sha256 requires RSA-PSS SubjectPublicKeyInfo parameters"));
            };
            validate_rsa_pss_params(params.as_ref())?;
        }
        _ => {}
    }

    Ok(())
}

fn validate_rsa_pss_params(params: &RsaSsaPssParams<'_>) -> Result<(), X509RootAuthError> {
    let hash_algorithm = params.hash_algorithm_oid();
    if hash_algorithm.to_id_string() != OID_SHA256 {
        return Err(X509RootAuthError::Invalid("leaf RSA-PSS SubjectPublicKeyInfo must use SHA-256"));
    }

    let mask_generation =
        params.mask_gen_algorithm().map_err(|_| X509RootAuthError::Invalid("leaf RSA-PSS SubjectPublicKeyInfo is missing mask generation parameters"))?;
    if mask_generation.mgf.to_id_string() != OID_MGF1 {
        return Err(X509RootAuthError::Invalid("leaf RSA-PSS SubjectPublicKeyInfo must use MGF1"));
    }
    if mask_generation.hash.to_id_string() != OID_SHA256 {
        return Err(X509RootAuthError::Invalid("leaf RSA-PSS SubjectPublicKeyInfo must use SHA-256 as MGF1 digest"));
    }

    let salt_length = params.salt_length();
    if salt_length != 32 {
        return Err(X509RootAuthError::Invalid("leaf RSA-PSS SubjectPublicKeyInfo must use saltLength=32"));
    }

    let trailer = params.trailer_field();
    if trailer != 1 {
        return Err(X509RootAuthError::Invalid("leaf RSA-PSS SubjectPublicKeyInfo must use trailerField=1"));
    }

    Ok(())
}

#[derive(Debug)]
struct ParsedAuthenticator {
    sig_scheme: u16,
    signed_at_unix_seconds: i64,
    chain_digest: [u8; SHA256_LEN],
    signature: Vec<u8>,
    chain_certificate_der: Vec<Vec<u8>>,
}

fn private_key_from_pem_or_der(bytes: &[u8]) -> Result<PKey<Private>, X509RootAuthError> {
    if let Ok(key) = PKey::private_key_from_pem(bytes) {
        return Ok(key);
    }
    Ok(PKey::private_key_from_der(bytes)?)
}

fn signature_scheme_for_private_key(private_key: &PKeyRef<Private>) -> Result<u16, X509RootAuthError> {
    match private_key.id() {
        Id::RSA => Ok(SIG_SCHEME_RSA_PKCS1_SHA256),
        Id::RSA_PSS => Err(X509RootAuthError::Invalid("RSASSA-PSS X.509 keys require explicit rsa-pss-sha256 signature scheme")),
        Id::EC => {
            validate_allowed_ec_curve(private_key)?;
            Ok(SIG_SCHEME_ECDSA_SHA256_DER)
        }
        _ => Err(X509RootAuthError::Invalid("unsupported X.509 signature key type")),
    }
}

fn signature_scheme_name(sig_scheme: u16) -> &'static str {
    match sig_scheme {
        SIG_SCHEME_RSA_PKCS1_SHA256 => "rsa-pkcs1-sha256",
        SIG_SCHEME_ECDSA_SHA256_DER => "ecdsa-sha256-der",
        SIG_SCHEME_RSA_PSS_SHA256 => "rsa-pss-sha256",
        _ => "unknown",
    }
}

fn trust_store_policy_label(trusted_roots_der: &[Vec<u8>], use_system_roots: bool, include_official_tzap_root: bool) -> &'static str {
    match (trusted_roots_der.is_empty(), use_system_roots, include_official_tzap_root) {
        (false, false, true) => "official_tzap_root_plus_caller_roots",
        (false, true, true) => "official_tzap_root_plus_caller_roots_plus_openssl_default_roots",
        (true, false, true) => "official_tzap_root",
        (true, true, true) => "official_tzap_root_plus_openssl_default_roots",
        (false, false, false) => "caller_roots",
        (false, true, false) => "caller_roots_plus_openssl_default_roots",
        (true, true, false) => "openssl_default_roots",
        (true, false, false) => "none",
    }
}

fn validate_private_key_matches_scheme(sig_scheme: u16, private_key: &PKeyRef<Private>) -> Result<(), X509RootAuthError> {
    validate_public_key_matches_scheme(sig_scheme, private_key)
}

fn signer_for_scheme<'a>(sig_scheme: u16, private_key: &'a PKeyRef<Private>) -> Result<Signer<'a>, X509RootAuthError> {
    let mut signer = Signer::new(MessageDigest::sha256(), private_key)?;
    match sig_scheme {
        SIG_SCHEME_RSA_PKCS1_SHA256 => {
            signer.set_rsa_padding(Padding::PKCS1)?;
        }
        SIG_SCHEME_RSA_PSS_SHA256 => {
            signer.set_rsa_padding(Padding::PKCS1_PSS)?;
            signer.set_rsa_mgf1_md(MessageDigest::sha256())?;
            signer.set_rsa_pss_saltlen(RsaPssSaltlen::custom(32))?;
        }
        SIG_SCHEME_ECDSA_SHA256_DER => {}
        _ => {
            return Err(X509RootAuthError::Invalid("unsupported X.509 signature scheme"));
        }
    }
    Ok(signer)
}

fn verifier_for_scheme<'a, T>(sig_scheme: u16, public_key: &'a PKeyRef<T>) -> Result<Verifier<'a>, X509RootAuthError>
where
    T: HasPublic,
{
    let mut verifier = Verifier::new(MessageDigest::sha256(), public_key)?;
    match sig_scheme {
        SIG_SCHEME_RSA_PKCS1_SHA256 => {
            verifier.set_rsa_padding(Padding::PKCS1)?;
        }
        SIG_SCHEME_RSA_PSS_SHA256 => {
            verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
            verifier.set_rsa_mgf1_md(MessageDigest::sha256())?;
            verifier.set_rsa_pss_saltlen(RsaPssSaltlen::custom(32))?;
        }
        SIG_SCHEME_ECDSA_SHA256_DER => {}
        _ => {
            return Err(X509RootAuthError::Invalid("unsupported X.509 signature scheme"));
        }
    }
    Ok(verifier)
}

fn validate_public_key_matches_scheme<T>(sig_scheme: u16, public_key: &PKeyRef<T>) -> Result<(), X509RootAuthError>
where
    T: HasParams,
{
    match sig_scheme {
        SIG_SCHEME_RSA_PKCS1_SHA256 => {
            if public_key.id() != Id::RSA {
                return Err(X509RootAuthError::Invalid("X.509 signature scheme/key mismatch"));
            }
        }
        SIG_SCHEME_ECDSA_SHA256_DER => {
            if public_key.id() != Id::EC {
                return Err(X509RootAuthError::Invalid("X.509 signature scheme/key mismatch"));
            }
            validate_allowed_ec_curve(public_key)?;
        }
        SIG_SCHEME_RSA_PSS_SHA256 => {
            if !matches!(public_key.id(), Id::RSA | Id::RSA_PSS) {
                return Err(X509RootAuthError::Invalid("X.509 signature scheme/key mismatch"));
            }
        }
        _ => {
            return Err(X509RootAuthError::Invalid("unsupported X.509 signature scheme"));
        }
    }
    Ok(())
}

fn validate_leaf_key_usage(leaf_certificate_der: &[u8]) -> Result<(), X509RootAuthError> {
    let (remaining, parsed_certificate) = x509_parser::certificate::X509Certificate::from_der(leaf_certificate_der)
        .map_err(|_| X509RootAuthError::Invalid("failed to parse leaf certificate KeyUsage"))?;
    if !remaining.is_empty() {
        return Err(X509RootAuthError::Invalid("leaf certificate DER has trailing bytes"));
    }
    let Some(key_usage) = parsed_certificate.key_usage().map_err(|_| X509RootAuthError::Invalid("failed to parse leaf certificate KeyUsage"))? else {
        return Ok(());
    };
    if key_usage.value.digital_signature() || key_usage.value.non_repudiation() {
        return Ok(());
    }
    Err(X509RootAuthError::Invalid("leaf certificate KeyUsage does not allow archive signing"))
}

fn validate_signature_for_scheme<T>(sig_scheme: u16, public_key: &PKeyRef<T>, signature: &[u8]) -> Result<(), X509RootAuthError>
where
    T: HasParams,
{
    match sig_scheme {
        SIG_SCHEME_RSA_PKCS1_SHA256 | SIG_SCHEME_RSA_PSS_SHA256 => {
            if signature.len() != public_key.size() {
                return Err(X509RootAuthError::Invalid("X.509 RSA signature length does not match modulus"));
            }
        }
        SIG_SCHEME_ECDSA_SHA256_DER => {
            validate_ecdsa_der_low_s(public_key, signature)?;
        }
        _ => {
            return Err(X509RootAuthError::Invalid("unsupported X.509 signature scheme"));
        }
    }
    Ok(())
}

fn normalize_signature_for_scheme(sig_scheme: u16, private_key: &PKeyRef<Private>, signature: Vec<u8>) -> Result<Vec<u8>, X509RootAuthError> {
    if sig_scheme != SIG_SCHEME_ECDSA_SHA256_DER {
        return Ok(signature);
    }
    let sig = EcdsaSig::from_der(&signature)?;
    let (_, order, half_order) = ec_curve_order(private_key)?;
    if sig.s().ucmp(&half_order) != Ordering::Greater {
        return Ok(signature);
    }
    let mut low_s = BigNum::new()?;
    low_s.checked_sub(&order, sig.s())?;
    let normalized = EcdsaSig::from_private_components(sig.r().to_owned()?, low_s)?;
    Ok(normalized.to_der()?)
}

fn validate_ecdsa_der_low_s<T>(public_key: &PKeyRef<T>, signature: &[u8]) -> Result<(), X509RootAuthError>
where
    T: HasParams,
{
    let sig = EcdsaSig::from_der(signature).map_err(|_| X509RootAuthError::Invalid("X.509 ECDSA signature is not valid DER"))?;
    let canonical = sig.to_der().map_err(|_| X509RootAuthError::Invalid("X.509 ECDSA signature is not canonical DER"))?;
    if canonical != signature {
        return Err(X509RootAuthError::Invalid("X.509 ECDSA signature is not canonical DER"));
    }
    let (zero, order, half_order) = ec_curve_order(public_key)?;
    validate_positive_scalar(sig.r(), &zero, &order)?;
    validate_positive_scalar(sig.s(), &zero, &order)?;
    if sig.s().ucmp(&half_order) == Ordering::Greater {
        return Err(X509RootAuthError::Invalid("X.509 ECDSA signature is high-S"));
    }
    Ok(())
}

fn validate_positive_scalar(value: &BigNumRef, zero: &BigNumRef, order: &BigNumRef) -> Result<(), X509RootAuthError> {
    if value.is_negative() || value.ucmp(zero) != Ordering::Greater || value.ucmp(order) != Ordering::Less {
        return Err(X509RootAuthError::Invalid("X.509 ECDSA signature scalar is out of range"));
    }
    Ok(())
}

fn validate_allowed_ec_curve<T>(key: &PKeyRef<T>) -> Result<(), X509RootAuthError>
where
    T: HasParams,
{
    let curve = key.ec_key()?.group().curve_name().ok_or(X509RootAuthError::Invalid("X.509 ECDSA key must use a named curve"))?;
    if !matches!(curve, Nid::X9_62_PRIME256V1 | Nid::SECP384R1 | Nid::SECP521R1) {
        return Err(X509RootAuthError::Invalid("unsupported X.509 ECDSA curve"));
    }
    Ok(())
}

fn ec_curve_order<T>(key: &PKeyRef<T>) -> Result<(BigNum, BigNum, BigNum), X509RootAuthError>
where
    T: HasParams,
{
    let ec_key = key.ec_key()?;
    let mut ctx = BigNumContext::new()?;
    let mut order = BigNum::new()?;
    ec_key.group().order(&mut order, &mut ctx)?;
    let zero = BigNum::from_u32(0)?;
    let mut half_order = BigNum::new()?;
    half_order.rshift1(&order)?;
    Ok((zero, order, half_order))
}

fn parse_authenticator_value(value: &[u8]) -> Result<ParsedAuthenticator, X509RootAuthError> {
    if value.len() < AUTHENTICATOR_FIXED_LEN {
        return Err(X509RootAuthError::Invalid("X.509 authenticator is too short"));
    }
    if &value[0..4] != MAGIC {
        return Err(X509RootAuthError::Invalid("X.509 authenticator magic mismatch"));
    }
    if read_u16(value, 4)? != VERSION {
        return Err(X509RootAuthError::Invalid("unsupported X.509 authenticator version"));
    }
    let sig_scheme = read_u16(value, 6)?;
    if !matches!(sig_scheme, SIG_SCHEME_RSA_PKCS1_SHA256 | SIG_SCHEME_ECDSA_SHA256_DER | SIG_SCHEME_RSA_PSS_SHA256) {
        return Err(X509RootAuthError::Invalid("unsupported X.509 signature scheme"));
    }
    let signed_at_unix_seconds = read_i64(value, 8)?;
    let mut parsed_chain_digest = [0u8; SHA256_LEN];
    parsed_chain_digest.copy_from_slice(&value[16..48]);
    let signature_len = read_u32(value, 48)? as usize;
    let signature_capacity = read_u32(value, 52)? as usize;
    let chain_count = read_u32(value, 56)? as usize;
    if signature_len == 0 {
        return Err(X509RootAuthError::Invalid("X.509 signature length must be nonzero"));
    }
    if signature_len > signature_capacity {
        return Err(X509RootAuthError::Invalid("X.509 signature length exceeds capacity"));
    }
    let mut offset = AUTHENTICATOR_FIXED_LEN.checked_add(signature_capacity).ok_or(X509RootAuthError::Invalid("X.509 authenticator length overflow"))?;
    if value.len() < offset {
        return Err(X509RootAuthError::Invalid("X.509 authenticator signature is truncated"));
    }
    if chain_count > value.len().saturating_sub(offset) / 4 {
        return Err(X509RootAuthError::Invalid("X.509 authenticator chain count exceeds payload"));
    }
    let signature_start = AUTHENTICATOR_FIXED_LEN;
    let signature_end = signature_start + signature_len;
    if value[signature_end..offset].iter().any(|byte| *byte != 0) {
        return Err(X509RootAuthError::Invalid("X.509 authenticator signature padding is non-zero"));
    }
    let signature = value[signature_start..signature_end].to_vec();
    let mut chain_certificate_der = Vec::new();
    for _ in 0..chain_count {
        let cert_len = read_u32(value, offset)? as usize;
        offset = offset.checked_add(4).ok_or(X509RootAuthError::Invalid("X.509 authenticator length overflow"))?;
        let cert_end = offset.checked_add(cert_len).ok_or(X509RootAuthError::Invalid("X.509 authenticator length overflow"))?;
        if cert_end > value.len() {
            return Err(X509RootAuthError::Invalid("X.509 authenticator certificate chain is truncated"));
        }
        let cert_der = value[offset..cert_end].to_vec();
        let (remaining, _) =
            x509_parser::certificate::X509Certificate::from_der(&cert_der).map_err(|_| X509RootAuthError::Invalid("invalid X.509 chain certificate"))?;
        if !remaining.is_empty() {
            return Err(X509RootAuthError::Invalid("X.509 chain certificate DER has trailing bytes"));
        }
        chain_certificate_der.push(cert_der);
        offset = cert_end;
    }
    if offset != value.len() {
        return Err(X509RootAuthError::Invalid("X.509 authenticator has trailing bytes"));
    }
    if chain_digest(&chain_certificate_der)? != parsed_chain_digest {
        return Err(X509RootAuthError::Invalid("X.509 authenticator chain digest mismatch"));
    }
    Ok(ParsedAuthenticator { sig_scheme, signed_at_unix_seconds, chain_digest: parsed_chain_digest, signature, chain_certificate_der })
}

fn verify_certificate_chain(
    leaf_certificate: &X509,
    chain_certificate_der: &[Vec<u8>],
    trusted_roots_der: &[Vec<u8>],
    use_system_roots: bool,
    chain_validation_time_unix_seconds: i64,
) -> Result<Vec<String>, X509RootAuthError> {
    let mut store_builder = X509StoreBuilder::new()?;
    for root_der in trusted_roots_der {
        store_builder.add_cert(X509::from_der(root_der)?)?;
    }
    if use_system_roots {
        store_builder.set_default_paths()?;
    }
    let mut params = X509VerifyParam::new()?;
    params.set_time(chain_validation_time_unix_seconds as _);
    store_builder.set_param(&params)?;
    let store = store_builder.build();

    let mut chain = Stack::new()?;
    for cert_der in chain_certificate_der {
        chain.push(X509::from_der(cert_der)?)?;
    }
    let mut context = X509StoreContext::new()?;
    let mut verify_error = None;
    let mut subjects = Vec::new();
    let verified = context.init(&store, leaf_certificate, &chain, |ctx| {
        let ok = ctx.verify_cert()?;
        if ok {
            if let Some(chain) = ctx.chain() {
                subjects = chain.iter().map(|cert| name_to_string(cert.subject_name())).collect();
            }
        } else {
            verify_error = Some(format!("{} at depth {}", ctx.error(), ctx.error_depth()));
        }
        Ok(ok)
    })?;
    if !verified {
        return Err(X509RootAuthError::UntrustedChain(verify_error.unwrap_or_else(|| "certificate chain verification failed".to_string())));
    }
    if subjects.is_empty() {
        subjects.push(name_to_string(leaf_certificate.subject_name()));
    }
    Ok(subjects)
}

fn current_unix_seconds() -> Result<i64, X509RootAuthError> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| X509RootAuthError::Invalid("system clock is before Unix epoch"))?;
    i64::try_from(duration.as_secs()).map_err(|_| X509RootAuthError::Invalid("system clock exceeds i64 Unix seconds"))
}

fn chain_digest(chain_certificate_der: &[Vec<u8>]) -> Result<[u8; SHA256_LEN], X509RootAuthError> {
    let mut hasher = Sha256::new();
    hasher.update(X509_CHAIN_DOMAIN);
    hasher.update(u32_len(chain_certificate_der.len(), "chain count")?.to_le_bytes());
    for cert_der in chain_certificate_der {
        hasher.update(u32_len(cert_der.len(), "chain certificate length")?.to_le_bytes());
        hasher.update(cert_der);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; SHA256_LEN];
    out.copy_from_slice(&digest);
    Ok(out)
}

fn authenticator_value_len(signature_capacity: usize, chain_certificate_der: &[Vec<u8>]) -> Result<u32, X509RootAuthError> {
    let chain_len = chain_certificate_der.iter().try_fold(0usize, |acc, cert_der| {
        acc.checked_add(4).and_then(|value| value.checked_add(cert_der.len())).ok_or(X509RootAuthError::Invalid("X.509 authenticator length overflow"))
    })?;
    let total = AUTHENTICATOR_FIXED_LEN
        .checked_add(signature_capacity)
        .and_then(|value| value.checked_add(chain_len))
        .ok_or(X509RootAuthError::Invalid("X.509 authenticator length overflow"))?;
    u32_len(total, "authenticator value length")
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

fn read_u16(value: &[u8], offset: usize) -> Result<u16, X509RootAuthError> {
    let bytes = value.get(offset..offset + 2).ok_or(X509RootAuthError::Invalid("X.509 authenticator is truncated"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(value: &[u8], offset: usize) -> Result<u32, X509RootAuthError> {
    let bytes = value.get(offset..offset + 4).ok_or(X509RootAuthError::Invalid("X.509 authenticator is truncated"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_i64(value: &[u8], offset: usize) -> Result<i64, X509RootAuthError> {
    let bytes = value.get(offset..offset + 8).ok_or(X509RootAuthError::Invalid("X.509 authenticator is truncated"))?;
    Ok(i64::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]]))
}

fn u32_len(len: usize, field: &'static str) -> Result<u32, X509RootAuthError> {
    u32::try_from(len).map_err(|_| match field {
        "signature length" => X509RootAuthError::Invalid("X.509 signature length overflow"),
        "signature capacity" => X509RootAuthError::Invalid("X.509 signature capacity overflow"),
        "chain count" => X509RootAuthError::Invalid("X.509 chain count overflow"),
        "chain certificate length" => X509RootAuthError::Invalid("X.509 chain certificate length overflow"),
        _ => X509RootAuthError::Invalid("X.509 authenticator length overflow"),
    })
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = fmt::Write::write_fmt(&mut output, format_args!("{:02x}", byte));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::bn::{BigNum, MsbOption};
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKeyRef;
    use openssl::rsa::Rsa;
    use openssl::x509::extension::{BasicConstraints, KeyUsage};
    use openssl::x509::{X509NameBuilder, X509Ref};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tzap_core::format::{FORMAT_VERSION, ROOT_AUTH_SPEC_ID, ROOT_AUTH_SPEC_ID_V45, VOLUME_FORMAT_REV, VOLUME_FORMAT_REV_45};

    fn signed_footer_for_request(signer: &X509RootAuthSigner, leaf_cert: &X509, request: &RootAuthSigningRequest, volume_format_rev: u16) -> RootAuthFooterV1 {
        RootAuthFooterV1 {
            archive_uuid: request.archive_uuid,
            session_id: request.session_id,
            format_version: FORMAT_VERSION,
            volume_format_rev,
            authenticator_id: X509_AUTHENTICATOR_ID,
            signer_identity_type: X509_SIGNER_IDENTITY_TYPE_DER_CERT,
            signer_identity_bytes: leaf_cert.to_der().unwrap(),
            authenticator_value: signer.authenticator_value_for_request(request).unwrap(),
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
    fn x509_authenticator_round_trips_with_trusted_root() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signed_at = now_unix_seconds();
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), signed_at).unwrap();
        let request = RootAuthSigningRequest { root_auth_spec_id: ROOT_AUTH_SPEC_ID, archive_uuid: [1; 16], session_id: [2; 16], archive_root: [3; 32] };
        let value = signer.authenticator_value_for_request(&request).unwrap();
        let footer = RootAuthFooterV1 {
            archive_uuid: request.archive_uuid,
            session_id: request.session_id,
            format_version: FORMAT_VERSION,
            volume_format_rev: VOLUME_FORMAT_REV,
            authenticator_id: X509_AUTHENTICATOR_ID,
            signer_identity_type: X509_SIGNER_IDENTITY_TYPE_DER_CERT,
            signer_identity_bytes: leaf_cert.to_der().unwrap(),
            authenticator_value: value,
            total_data_block_count: 0,
            critical_metadata_digest: [0; 32],
            index_digest: [0; 32],
            fec_layout_digest: [0; 32],
            data_block_merkle_root: [0; 32],
            signer_identity_digest: [0; 32],
            archive_root: request.archive_root,
            footer_crc32c: 0,
        };

        let report = verify_root_auth_footer(&footer, &request.archive_root, &[root_cert.to_der().unwrap()], false, false).unwrap();

        assert_eq!(report.signed_at_unix_seconds, signed_at);
        assert_eq!(report.signature_scheme, "rsa-pkcs1-sha256");
        assert_eq!(report.trust_store_policy, "caller_roots");
        assert_eq!(report.x509_time_policy, "verifier_current_time");
        assert_eq!(report.chain_time_basis, "verifier_current_time");
        assert!(!report.trusted_timestamp);
        assert!(!report.revocation_checked);
        assert!(report.chain_validation_time_unix_seconds >= signed_at - 5);
        assert!(report.subject.contains("CN=Acme Release Signing"));
        assert!(report.issuer.contains("CN=Acme Test Root CA"));
        assert_eq!(report.trust_anchor_subject.as_deref(), Some("CN=Acme Test Root CA"));

        let combined_report = verify_root_auth_footer(&footer, &request.archive_root, &[root_cert.to_der().unwrap()], true, false).unwrap();
        assert_eq!(combined_report.trust_store_policy, "caller_roots_plus_openssl_default_roots");

        let official_report = verify_root_auth_footer(&footer, &request.archive_root, &[root_cert.to_der().unwrap()], false, true).unwrap();
        assert_eq!(official_report.trust_store_policy, "official_tzap_root_plus_caller_roots");
    }

    fn verify_error_message(footer: &RootAuthFooterV1, archive_root: &[u8; 32], trusted_roots_der: &[Vec<u8>]) -> String {
        let err = verify_root_auth_footer(footer, archive_root, trusted_roots_der, false, false).unwrap_err();
        match err {
            X509RootAuthError::Invalid(message) => message.to_string(),
            X509RootAuthError::UntrustedChain(message) => message,
            other => format!("unexpected error: {other:?}"),
        }
    }

    fn signature_error_message(footer: &RootAuthFooterV1, archive_root: &[u8; 32]) -> String {
        let err = verify_root_auth_signature(footer, archive_root).unwrap_err();
        match err {
            X509RootAuthError::Invalid(message) => message.to_string(),
            other => format!("unexpected error: {other:?}"),
        }
    }

    fn default_signing_request() -> RootAuthSigningRequest {
        RootAuthSigningRequest { root_auth_spec_id: ROOT_AUTH_SPEC_ID_V45, archive_uuid: [1; 16], session_id: [2; 16], archive_root: [3; 32] }
    }

    #[test]
    fn verify_root_auth_signature_scheme1_valid_report() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signed_at = now_unix_seconds();
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), signed_at).unwrap();
        let request = default_signing_request();
        let footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);

        let report = verify_root_auth_signature(&footer, &request.archive_root).unwrap();

        assert_eq!(report.signature_scheme, "rsa-pkcs1-sha256");
        assert_eq!(report.signed_at_unix_seconds, signed_at);
        let mut expected_digest = [0u8; SHA256_LEN];
        expected_digest.copy_from_slice(&leaf_cert.digest(MessageDigest::sha256()).unwrap());
        assert_eq!(report.certificate_sha256, expected_digest);

        // The trustless report fields must agree with the full-verify report.
        let full_report = verify_root_auth_footer(&footer, &request.archive_root, &[root_cert.to_der().unwrap()], false, false).unwrap();
        assert_eq!(report.signature_scheme, full_report.signature_scheme);
        assert_eq!(report.signed_at_unix_seconds, full_report.signed_at_unix_seconds);
        assert_eq!(report.certificate_sha256, full_report.certificate_sha256);
    }

    #[test]
    fn verify_root_auth_signature_scheme2_ecdsa_valid_report() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_ec_leaf_cert("Acme EC Release Signing", root_cert.as_ref(), root_key.as_ref(), Nid::X9_62_PRIME256V1);
        let signed_at = now_unix_seconds();
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), signed_at).unwrap();
        let request = default_signing_request();
        let footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);

        let report = verify_root_auth_signature(&footer, &request.archive_root).unwrap();

        assert_eq!(report.signature_scheme, "ecdsa-sha256-der");
        assert_eq!(report.signed_at_unix_seconds, signed_at);
        let mut expected_digest = [0u8; SHA256_LEN];
        expected_digest.copy_from_slice(&leaf_cert.digest(MessageDigest::sha256()).unwrap());
        assert_eq!(report.certificate_sha256, expected_digest);
    }

    #[test]
    fn verify_root_auth_signature_scheme3_rsa_pss_valid_report() {
        // Regression for the false-tamper-alarm bug: scheme 3 archives that
        // full verification accepts must also pass the trustless check.
        let (leaf_cert, leaf_key) = rsa_pss_leaf_cert_and_key();
        let signed_at = now_unix_seconds();
        let signer = X509RootAuthSigner::new_with_signature_scheme(
            leaf_cert.to_der().unwrap(),
            leaf_key,
            Vec::new(),
            signed_at,
            Some(X509SignatureScheme::RsaPssSha256),
        )
        .unwrap();
        let request = default_signing_request();
        let footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);

        let report = verify_root_auth_signature(&footer, &request.archive_root).unwrap();

        assert_eq!(report.signature_scheme, "rsa-pss-sha256");
        assert_eq!(report.signed_at_unix_seconds, signed_at);
        let mut expected_digest = [0u8; SHA256_LEN];
        expected_digest.copy_from_slice(&leaf_cert.digest(MessageDigest::sha256()).unwrap());
        assert_eq!(report.certificate_sha256, expected_digest);
    }

    #[test]
    fn verify_root_auth_signature_accepts_without_roots_or_time_basis() {
        // Contract boundary: an expired leaf with no trusted roots still
        // passes the trustless check (the signature is time-independent),
        // while the full verify path rejects it for chain-time.
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_expired_leaf_cert("Acme Expired Signing", root_cert.as_ref(), root_key.as_ref());
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), now_unix_seconds() - 3600).unwrap();
        let request = default_signing_request();
        let footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);

        assert!(verify_root_auth_signature(&footer, &request.archive_root).is_ok());

        // No roots: the full path never gets to chain-time checks.
        let no_roots_err = verify_root_auth_footer(&footer, &request.archive_root, &[], false, false).unwrap_err();
        assert!(matches!(no_roots_err, X509RootAuthError::MissingTrustPolicy));
        // With roots, the full path rejects the expired leaf at current time.
        let full_err = verify_root_auth_footer(&footer, &request.archive_root, &[root_cert.to_der().unwrap()], false, false).unwrap_err();
        assert!(matches!(full_err, X509RootAuthError::UntrustedChain(message) if message.contains("certificate has expired")));
    }

    #[test]
    fn verify_root_auth_signature_accepts_embedded_chain() {
        // An embedded chain must parse and its digest must match, but the
        // report digest is the leaf certificate only.
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, vec![root_cert.to_der().unwrap()], now_unix_seconds()).unwrap();
        let request = default_signing_request();
        let footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);

        let report = verify_root_auth_signature(&footer, &request.archive_root).unwrap();

        let mut expected_digest = [0u8; SHA256_LEN];
        expected_digest.copy_from_slice(&leaf_cert.digest(MessageDigest::sha256()).unwrap());
        assert_eq!(report.certificate_sha256, expected_digest);
    }

    #[test]
    fn verify_root_auth_signature_rejects_wrong_archive_root() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), now_unix_seconds()).unwrap();
        let request = default_signing_request();
        let footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);
        let mut wrong_root = request.archive_root;
        wrong_root[0] ^= 0x01;

        // Must be a VERIFY error, not a parse error.
        assert_eq!(signature_error_message(&footer, &wrong_root), "X.509 RootAuth signature failed");
    }

    #[test]
    fn verify_root_auth_signature_rejects_wrong_signing_key() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), now_unix_seconds()).unwrap();
        let request = default_signing_request();
        let mut footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);

        // Same envelope (signed by the first key) but a different identity cert.
        let (other_cert, _) = test_leaf_cert("Other Signing", root_cert.as_ref(), root_key.as_ref());
        footer.signer_identity_bytes = other_cert.to_der().unwrap();

        assert_eq!(signature_error_message(&footer, &request.archive_root), "X.509 RootAuth signature failed");
    }

    #[test]
    fn verify_root_auth_signature_rejects_nonzero_signature_padding() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_ec_leaf_cert("Acme EC Release Signing", root_cert.as_ref(), root_key.as_ref(), Nid::X9_62_PRIME256V1);
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), now_unix_seconds()).unwrap();
        let request = default_signing_request();
        let mut footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);
        let signature_len = read_u32(&footer.authenticator_value, 48).unwrap() as usize;
        footer.authenticator_value[AUTHENTICATOR_FIXED_LEN + signature_len] = 0xFF;

        assert_eq!(signature_error_message(&footer, &request.archive_root), "X.509 authenticator signature padding is non-zero");
    }

    #[test]
    fn verify_root_auth_signature_rejects_trailing_bytes() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), now_unix_seconds()).unwrap();
        let request = default_signing_request();
        let mut footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);
        footer.authenticator_value.push(0x00);

        assert_eq!(signature_error_message(&footer, &request.archive_root), "X.509 authenticator has trailing bytes");
    }

    #[test]
    fn verify_root_auth_signature_rejects_truncated_envelope() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), now_unix_seconds()).unwrap();
        let request = default_signing_request();
        let mut footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);
        footer.authenticator_value.truncate(footer.authenticator_value.len() - 1);

        assert_eq!(signature_error_message(&footer, &request.archive_root), "X.509 authenticator signature is truncated");
    }

    #[test]
    fn verify_root_auth_signature_rejects_short_envelope() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), now_unix_seconds()).unwrap();
        let request = default_signing_request();
        let mut footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);
        footer.authenticator_value.clear();

        assert_eq!(signature_error_message(&footer, &request.archive_root), "X.509 authenticator is too short");
    }

    #[test]
    fn verify_root_auth_signature_rejects_chain_digest_mismatch() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), now_unix_seconds()).unwrap();
        let request = default_signing_request();
        let mut footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);
        footer.authenticator_value[16] ^= 0x01;

        assert_eq!(signature_error_message(&footer, &request.archive_root), "X.509 authenticator chain digest mismatch");
    }

    #[test]
    fn verify_root_auth_signature_rejects_bad_magic() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), now_unix_seconds()).unwrap();
        let request = default_signing_request();
        let mut footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);
        footer.authenticator_value[0] ^= 0xFF;

        // Same parse error as the full verify path, byte for byte.
        assert_eq!(signature_error_message(&footer, &request.archive_root), "X.509 authenticator magic mismatch");
        assert_eq!(verify_error_message(&footer, &request.archive_root, &[root_cert.to_der().unwrap()]), "X.509 authenticator magic mismatch");
    }

    #[test]
    fn verify_root_auth_signature_rejects_non_x509_authenticator_id() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), now_unix_seconds()).unwrap();
        let request = default_signing_request();
        let mut footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);
        footer.authenticator_id = 0x0002; // Ed25519 authenticator id

        assert_eq!(signature_error_message(&footer, &request.archive_root), "unsupported authenticator id");
    }

    #[test]
    fn verify_root_auth_signature_rejects_unsupported_identity_type() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), now_unix_seconds()).unwrap();
        let request = default_signing_request();
        let mut footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);
        footer.signer_identity_type = 0xFFFF;

        assert!(matches!(verify_root_auth_signature(&footer, &request.archive_root).unwrap_err(), X509RootAuthError::UnsupportedIdentity));
    }

    #[test]
    fn verify_root_auth_signature_rejects_key_scheme_mismatch() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), now_unix_seconds()).unwrap();
        let request = default_signing_request();
        let mut footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);
        footer.authenticator_value[6..8].copy_from_slice(&SIG_SCHEME_ECDSA_SHA256_DER.to_le_bytes());

        assert_eq!(signature_error_message(&footer, &request.archive_root), "X.509 signature scheme/key mismatch");
    }

    #[test]
    fn verify_root_auth_signature_rejects_unsupported_scheme_id() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), now_unix_seconds()).unwrap();
        let request = default_signing_request();
        let mut footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);
        footer.authenticator_value[6..8].copy_from_slice(&0xFFFFu16.to_le_bytes());

        assert_eq!(signature_error_message(&footer, &request.archive_root), "unsupported X.509 signature scheme");
    }

    #[test]
    fn verify_root_auth_signature_rejects_future_volume_format_rev() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), now_unix_seconds()).unwrap();
        let request = default_signing_request();
        let footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45 + 1);

        // Must fail at root_auth_spec_id_for_revision, not silently default.
        assert_eq!(signature_error_message(&footer, &request.archive_root), "unsupported RootAuthFooter root_auth_spec_id");
    }

    #[test]
    fn verify_root_auth_signature_rejects_key_usage_not_allowing_signing() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) =
            test_leaf_cert_with_usage("Acme Key Encipherment Only", root_cert.as_ref(), root_key.as_ref(), LeafKeyUsage::KeyEnciphermentOnly);
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), now_unix_seconds()).unwrap();
        let request = default_signing_request();
        let footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);

        assert_eq!(signature_error_message(&footer, &request.archive_root), "leaf certificate KeyUsage does not allow archive signing");
    }

    #[test]
    fn verify_root_auth_signature_rejects_invalid_leaf_der() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), now_unix_seconds()).unwrap();
        let request = default_signing_request();
        let mut footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);
        footer.signer_identity_bytes = vec![0xDE, 0xAD];

        assert_eq!(signature_error_message(&footer, &request.archive_root), "invalid X.509 signer identity");
    }

    #[test]
    fn verify_root_auth_signature_rejects_unsupported_envelope_version() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), now_unix_seconds()).unwrap();
        let request = default_signing_request();
        let mut footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);
        footer.authenticator_value[4..6].copy_from_slice(&2u16.to_le_bytes());

        assert_eq!(signature_error_message(&footer, &request.archive_root), "unsupported X.509 authenticator version");
    }

    #[test]
    fn verify_root_auth_signature_rejects_zero_signature_length() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), now_unix_seconds()).unwrap();
        let request = default_signing_request();
        let mut footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);
        footer.authenticator_value[48..52].copy_from_slice(&0u32.to_le_bytes());

        assert_eq!(signature_error_message(&footer, &request.archive_root), "X.509 signature length must be nonzero");
    }

    #[test]
    fn verify_root_auth_signature_rejects_signature_length_exceeding_capacity() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), now_unix_seconds()).unwrap();
        let request = default_signing_request();
        let mut footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);
        let signature_capacity = read_u32(&footer.authenticator_value, 52).unwrap();
        footer.authenticator_value[48..52].copy_from_slice(&(signature_capacity + 1).to_le_bytes());

        assert_eq!(signature_error_message(&footer, &request.archive_root), "X.509 signature length exceeds capacity");
    }

    #[test]
    fn verify_root_auth_signature_rejects_impossible_chain_count() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), now_unix_seconds()).unwrap();
        let request = default_signing_request();
        let mut footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);
        footer.authenticator_value[56..60].copy_from_slice(&u32::MAX.to_le_bytes());

        assert_eq!(signature_error_message(&footer, &request.archive_root), "X.509 authenticator chain count exceeds payload");
    }

    #[test]
    fn verify_root_auth_signature_rejects_malformed_chain_certificate() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, vec![root_cert.to_der().unwrap()], now_unix_seconds()).unwrap();
        let request = default_signing_request();
        let mut footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);
        let signature_capacity = read_u32(&footer.authenticator_value, 52).unwrap() as usize;
        let first_cert_start = AUTHENTICATOR_FIXED_LEN + signature_capacity + 4;
        // Corrupt the DER SEQUENCE tag so the chain certificate no longer parses.
        footer.authenticator_value[first_cert_start] = 0xFF;

        assert_eq!(signature_error_message(&footer, &request.archive_root), "invalid X.509 chain certificate");
    }

    #[test]
    fn verify_root_auth_signature_rejects_noncanonical_ecdsa_der() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_ec_leaf_cert("Acme EC Release Signing", root_cert.as_ref(), root_key.as_ref(), Nid::X9_62_PRIME256V1);
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), now_unix_seconds()).unwrap();
        let request = default_signing_request();
        let mut footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);
        let nonminimal = nonminimal_ecdsa_integer_encoding(x509_signature_bytes(&footer.authenticator_value));
        replace_x509_signature(&mut footer.authenticator_value, &nonminimal);

        let message = signature_error_message(&footer, &request.archive_root);
        assert!(message.contains("canonical DER") || message.contains("valid DER"), "{message}");
    }

    #[test]
    fn authenticator_negative_vectors_all_rejected() {
        // §14.4 strict negative vectors on a valid signed footer.
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), 1).unwrap();
        let request = RootAuthSigningRequest { root_auth_spec_id: ROOT_AUTH_SPEC_ID, archive_uuid: [1; 16], session_id: [2; 16], archive_root: [3; 32] };
        let footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV);
        let roots = vec![root_cert.to_der().unwrap()];

        // Baseline: the unmodified footer verifies.
        verify_root_auth_footer(&footer, &request.archive_root, &roots, false, false).unwrap();

        // Flipped archive_root: footer signed for root A, verified with root B.
        let mut wrong_root = request.archive_root;
        wrong_root[0] ^= 0x01;
        assert_eq!(verify_error_message(&footer, &wrong_root, &roots), "X.509 RootAuth signature failed");

        // Wrong cert key: identity cert does not hold the signing key.
        let (other_cert, _) = test_leaf_cert("Other Signing", root_cert.as_ref(), root_key.as_ref());
        let mut wrong_key_footer = footer.clone();
        wrong_key_footer.signer_identity_bytes = other_cert.to_der().unwrap();
        assert_eq!(verify_error_message(&wrong_key_footer, &request.archive_root, &roots), "X.509 RootAuth signature failed");

        // Non-zero signature padding byte: ECDSA DER signatures are shorter than
        // the reserved capacity, leaving a padding region between signature end
        // and the chain section.
        let (ec_leaf_cert, ec_leaf_key) = test_ec_leaf_cert("Acme EC Release Signing", root_cert.as_ref(), root_key.as_ref(), Nid::X9_62_PRIME256V1);
        let ec_signer = X509RootAuthSigner::new(ec_leaf_cert.to_der().unwrap(), ec_leaf_key, Vec::new(), 1).unwrap();
        let ec_footer = signed_footer_for_request(&ec_signer, &ec_leaf_cert, &request, VOLUME_FORMAT_REV);
        let signature_len = read_u32(&ec_footer.authenticator_value, 48).unwrap() as usize;
        let signature_capacity = read_u32(&ec_footer.authenticator_value, 52).unwrap() as usize;
        assert!(signature_capacity > signature_len);
        let mut padded_footer = ec_footer;
        padded_footer.authenticator_value[AUTHENTICATOR_FIXED_LEN + signature_len] = 0xFF;
        assert_eq!(verify_error_message(&padded_footer, &request.archive_root, &roots), "X.509 authenticator signature padding is non-zero");

        // Chain digest mismatch: mutate the parsed chain digest field.
        let mut digest_footer = footer.clone();
        digest_footer.authenticator_value[16] ^= 0x01;
        assert_eq!(verify_error_message(&digest_footer, &request.archive_root, &roots), "X.509 authenticator chain digest mismatch");

        // Trailing bytes after the authenticator payload.
        let mut trailing_footer = footer.clone();
        trailing_footer.authenticator_value.push(0x00);
        assert_eq!(verify_error_message(&trailing_footer, &request.archive_root, &roots), "X.509 authenticator has trailing bytes");
    }

    #[test]
    fn declared_scheme_must_match_key_material() {
        // §14.8: declaring an ECDSA scheme while the identity cert holds an RSA
        // key must be rejected as Invalid.
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), 1).unwrap();
        let request = RootAuthSigningRequest { root_auth_spec_id: ROOT_AUTH_SPEC_ID, archive_uuid: [1; 16], session_id: [2; 16], archive_root: [3; 32] };
        let mut footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV);
        footer.authenticator_value[6..8].copy_from_slice(&SIG_SCHEME_ECDSA_SHA256_DER.to_le_bytes());
        let roots = vec![root_cert.to_der().unwrap()];
        let err = verify_root_auth_footer(&footer, &request.archive_root, &roots, false, false).unwrap_err();
        assert!(matches!(err, X509RootAuthError::Invalid("X.509 signature scheme/key mismatch")));
    }

    #[test]
    fn expired_leaf_certificate_rejected_at_current_time() {
        // §14.9: chain validation uses the verifier's current time, so a leaf
        // that has already expired fails even when signed_at is in the past.
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_expired_leaf_cert("Acme Expired Signing", root_cert.as_ref(), root_key.as_ref());
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), 1).unwrap();
        let request = RootAuthSigningRequest { root_auth_spec_id: ROOT_AUTH_SPEC_ID, archive_uuid: [1; 16], session_id: [2; 16], archive_root: [3; 32] };
        let footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV);
        let roots = vec![root_cert.to_der().unwrap()];
        let err = verify_root_auth_footer(&footer, &request.archive_root, &roots, false, false).unwrap_err();
        assert!(matches!(err, X509RootAuthError::UntrustedChain(message) if message.contains("certificate has expired")));
    }

    #[test]
    fn no_key_usage_leaf_verifies_with_minimal_policy_report() {
        // §14.10: a leaf with no KeyUsage extension at all is accepted, and the
        // report pins the minimal policies.
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert_no_key_usage("Acme No Usage Signing", root_cert.as_ref(), root_key.as_ref());
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), 1).unwrap();
        let request = RootAuthSigningRequest { root_auth_spec_id: ROOT_AUTH_SPEC_ID, archive_uuid: [1; 16], session_id: [2; 16], archive_root: [3; 32] };
        let footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV);
        let roots = vec![root_cert.to_der().unwrap()];
        let report = verify_root_auth_footer(&footer, &request.archive_root, &roots, false, false).unwrap();
        assert_eq!(report.key_usage_policy, "archive_signature_minimal");
        assert_eq!(report.eku_policy, "none");
    }

    #[test]
    fn unsupported_identity_is_distinct_from_invalid() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), 1).unwrap();
        let request = RootAuthSigningRequest { root_auth_spec_id: ROOT_AUTH_SPEC_ID_V45, archive_uuid: [1; 16], session_id: [2; 16], archive_root: [3; 32] };
        let mut footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);
        footer.signer_identity_type = 0xFFFF;

        let err = verify_root_auth_footer(&footer, &request.archive_root, &[root_cert.to_der().unwrap()], false, false).unwrap_err();

        assert!(matches!(err, X509RootAuthError::UnsupportedIdentity));
    }

    #[test]
    fn missing_trust_policy_is_distinct_after_footer_validation() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), 1).unwrap();
        let request = RootAuthSigningRequest { root_auth_spec_id: ROOT_AUTH_SPEC_ID_V45, archive_uuid: [1; 16], session_id: [2; 16], archive_root: [3; 32] };
        let footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);

        let err = verify_root_auth_footer(&footer, &request.archive_root, &[], false, false).unwrap_err();

        assert!(matches!(err, X509RootAuthError::MissingTrustPolicy));
    }

    #[test]
    fn zero_signature_length_is_invalid_before_missing_trust_policy() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), 1).unwrap();
        let request = RootAuthSigningRequest { root_auth_spec_id: ROOT_AUTH_SPEC_ID_V45, archive_uuid: [1; 16], session_id: [2; 16], archive_root: [3; 32] };
        let mut footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);
        let signature_capacity = u32::from_le_bytes(footer.authenticator_value[52..56].try_into().unwrap()) as usize;
        footer.authenticator_value[48..52].copy_from_slice(&0u32.to_le_bytes());
        footer.authenticator_value[AUTHENTICATOR_FIXED_LEN..AUTHENTICATOR_FIXED_LEN + signature_capacity].fill(0);

        let err = verify_root_auth_footer(&footer, &request.archive_root, &[], false, false).unwrap_err();

        assert!(matches!(err, X509RootAuthError::Invalid(_)));
        assert!(err.to_string().contains("signature length"));
    }

    #[test]
    fn malformed_chain_certificate_is_invalid_before_missing_trust_policy() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, vec![root_cert.to_der().unwrap()], 1).unwrap();
        let request = RootAuthSigningRequest { root_auth_spec_id: ROOT_AUTH_SPEC_ID_V45, archive_uuid: [1; 16], session_id: [2; 16], archive_root: [3; 32] };
        let mut footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);
        let signature_capacity = u32::from_le_bytes(footer.authenticator_value[52..56].try_into().unwrap()) as usize;
        let cert_len_offset = AUTHENTICATOR_FIXED_LEN + signature_capacity;
        let bad_cert = b"not a DER certificate".to_vec();
        let mut value = footer.authenticator_value[..cert_len_offset].to_vec();
        value.extend_from_slice(&(bad_cert.len() as u32).to_le_bytes());
        value.extend_from_slice(&bad_cert);
        let digest = chain_digest(&[bad_cert]).unwrap();
        value[16..48].copy_from_slice(&digest);
        footer.authenticator_value = value;

        let err = verify_root_auth_footer(&footer, &request.archive_root, &[], false, false).unwrap_err();

        assert!(matches!(err, X509RootAuthError::Invalid(_)));
        assert!(err.to_string().contains("chain certificate"));
    }

    #[test]
    fn invalid_footer_precedes_missing_trust_policy() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), 1).unwrap();
        let request = RootAuthSigningRequest { root_auth_spec_id: ROOT_AUTH_SPEC_ID_V45, archive_uuid: [1; 16], session_id: [2; 16], archive_root: [3; 32] };
        let mut footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);
        footer.authenticator_value[0] ^= 0xFF;

        let err = verify_root_auth_footer(&footer, &request.archive_root, &[], false, false).unwrap_err();

        assert!(matches!(err, X509RootAuthError::Invalid(_)));
    }

    #[test]
    fn chain_validation_uses_verifier_current_time_not_signer_claimed_time() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signed_at = now_unix_seconds() + 10 * 365 * 24 * 60 * 60;
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), signed_at).unwrap();
        let request = RootAuthSigningRequest { root_auth_spec_id: ROOT_AUTH_SPEC_ID, archive_uuid: [1; 16], session_id: [2; 16], archive_root: [3; 32] };
        let footer = RootAuthFooterV1 {
            archive_uuid: request.archive_uuid,
            session_id: request.session_id,
            format_version: FORMAT_VERSION,
            volume_format_rev: VOLUME_FORMAT_REV,
            authenticator_id: X509_AUTHENTICATOR_ID,
            signer_identity_type: X509_SIGNER_IDENTITY_TYPE_DER_CERT,
            signer_identity_bytes: leaf_cert.to_der().unwrap(),
            authenticator_value: signer.authenticator_value_for_request(&request).unwrap(),
            total_data_block_count: 0,
            critical_metadata_digest: [0; 32],
            index_digest: [0; 32],
            fec_layout_digest: [0; 32],
            data_block_merkle_root: [0; 32],
            signer_identity_digest: [0; 32],
            archive_root: request.archive_root,
            footer_crc32c: 0,
        };

        let report = verify_root_auth_footer(&footer, &request.archive_root, &[root_cert.to_der().unwrap()], false, false).unwrap();

        assert_eq!(report.signed_at_unix_seconds, signed_at);
        assert!(report.chain_validation_time_unix_seconds < signed_at);
    }

    #[test]
    fn rejects_leaf_key_usage_without_signature_or_content_commitment() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) =
            test_leaf_cert_with_usage("Acme Encipherment Only", root_cert.as_ref(), root_key.as_ref(), LeafKeyUsage::KeyEnciphermentOnly);
        let signed_at = now_unix_seconds();
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), signed_at).unwrap();
        let request = RootAuthSigningRequest { root_auth_spec_id: ROOT_AUTH_SPEC_ID, archive_uuid: [1; 16], session_id: [2; 16], archive_root: [3; 32] };
        let footer = RootAuthFooterV1 {
            archive_uuid: request.archive_uuid,
            session_id: request.session_id,
            format_version: FORMAT_VERSION,
            volume_format_rev: VOLUME_FORMAT_REV,
            authenticator_id: X509_AUTHENTICATOR_ID,
            signer_identity_type: X509_SIGNER_IDENTITY_TYPE_DER_CERT,
            signer_identity_bytes: leaf_cert.to_der().unwrap(),
            authenticator_value: signer.authenticator_value_for_request(&request).unwrap(),
            total_data_block_count: 0,
            critical_metadata_digest: [0; 32],
            index_digest: [0; 32],
            fec_layout_digest: [0; 32],
            data_block_merkle_root: [0; 32],
            signer_identity_digest: [0; 32],
            archive_root: request.archive_root,
            footer_crc32c: 0,
        };

        let err = verify_root_auth_footer(&footer, &request.archive_root, &[root_cert.to_der().unwrap()], false, false).unwrap_err();

        assert!(err.to_string().contains("KeyUsage"));
    }

    #[test]
    fn ecdsa_authenticator_round_trips_on_all_registered_curves() {
        for (curve, label) in [(Nid::X9_62_PRIME256V1, "P-256"), (Nid::SECP384R1, "P-384"), (Nid::SECP521R1, "P-521")] {
            let (root_cert, root_key) = test_ca_cert(&format!("{label} Test Root CA"));
            let (leaf_cert, leaf_key) = test_ec_leaf_cert(&format!("{label} EC Release Signing"), root_cert.as_ref(), root_key.as_ref(), curve);
            let signed_at = now_unix_seconds();
            let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), signed_at).unwrap();
            let request =
                RootAuthSigningRequest { root_auth_spec_id: ROOT_AUTH_SPEC_ID_V45, archive_uuid: [1; 16], session_id: [2; 16], archive_root: [3; 32] };
            let value = signer.authenticator_value_for_request(&request).unwrap();
            assert_eq!(u16::from_le_bytes([value[6], value[7]]), SIG_SCHEME_ECDSA_SHA256_DER);
            let footer = RootAuthFooterV1 {
                archive_uuid: request.archive_uuid,
                session_id: request.session_id,
                format_version: FORMAT_VERSION,
                volume_format_rev: VOLUME_FORMAT_REV_45,
                authenticator_id: X509_AUTHENTICATOR_ID,
                signer_identity_type: X509_SIGNER_IDENTITY_TYPE_DER_CERT,
                signer_identity_bytes: leaf_cert.to_der().unwrap(),
                authenticator_value: value,
                total_data_block_count: 0,
                critical_metadata_digest: [0; 32],
                index_digest: [0; 32],
                fec_layout_digest: [0; 32],
                data_block_merkle_root: [0; 32],
                signer_identity_digest: [0; 32],
                archive_root: request.archive_root,
                footer_crc32c: 0,
            };

            verify_root_auth_footer(&footer, &request.archive_root, &[root_cert.to_der().unwrap()], false, false).unwrap();
        }
    }

    #[test]
    fn ecdsa_verifier_rejects_high_s_signature_variant() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_ec_leaf_cert("Acme EC Release Signing", root_cert.as_ref(), root_key.as_ref(), Nid::SECP384R1);
        let signed_at = now_unix_seconds();
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), signed_at).unwrap();
        let request = RootAuthSigningRequest { root_auth_spec_id: ROOT_AUTH_SPEC_ID_V45, archive_uuid: [1; 16], session_id: [2; 16], archive_root: [3; 32] };
        let mut footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);
        let leaf_public_key = leaf_cert.public_key().unwrap();
        let signature = x509_signature_bytes(&footer.authenticator_value);
        let high_s = high_s_ecdsa_signature(signature, &leaf_public_key);
        replace_x509_signature(&mut footer.authenticator_value, &high_s);

        let err = verify_root_auth_footer(&footer, &request.archive_root, &[root_cert.to_der().unwrap()], false, false).unwrap_err();

        assert!(err.to_string().contains("high-S"));
    }

    #[test]
    fn ecdsa_verifier_rejects_noncanonical_and_trailing_der_signatures() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_ec_leaf_cert("Acme EC Release Signing", root_cert.as_ref(), root_key.as_ref(), Nid::SECP384R1);
        let signed_at = now_unix_seconds();
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), signed_at).unwrap();
        let request = RootAuthSigningRequest { root_auth_spec_id: ROOT_AUTH_SPEC_ID_V45, archive_uuid: [1; 16], session_id: [2; 16], archive_root: [3; 32] };
        let footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);

        let mut nonminimal_footer = footer.clone();
        let nonminimal = nonminimal_ecdsa_integer_encoding(x509_signature_bytes(&nonminimal_footer.authenticator_value));
        replace_x509_signature(&mut nonminimal_footer.authenticator_value, &nonminimal);
        let err = verify_root_auth_footer(&nonminimal_footer, &request.archive_root, &[root_cert.to_der().unwrap()], false, false).unwrap_err();
        assert!(err.to_string().contains("canonical DER") || err.to_string().contains("valid DER"));

        let mut trailing_footer = footer;
        let mut trailing = x509_signature_bytes(&trailing_footer.authenticator_value).to_vec();
        trailing.push(0);
        replace_x509_signature(&mut trailing_footer.authenticator_value, &trailing);
        let err = verify_root_auth_footer(&trailing_footer, &request.archive_root, &[root_cert.to_der().unwrap()], false, false).unwrap_err();
        assert!(err.to_string().contains("canonical DER") || err.to_string().contains("valid DER"));
    }

    #[test]
    fn signer_honors_explicit_rsa_pss_scheme() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme RSA PSS Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signed_at = now_unix_seconds();
        let signer = X509RootAuthSigner::new_with_signature_scheme(
            leaf_cert.to_der().unwrap(),
            leaf_key,
            Vec::new(),
            signed_at,
            Some(X509SignatureScheme::RsaPssSha256),
        )
        .unwrap();
        let request = RootAuthSigningRequest { root_auth_spec_id: ROOT_AUTH_SPEC_ID_V45, archive_uuid: [1; 16], session_id: [2; 16], archive_root: [3; 32] };
        let value = signer.authenticator_value_for_request(&request).unwrap();
        assert_eq!(u16::from_le_bytes([value[6], value[7]]), SIG_SCHEME_RSA_PSS_SHA256);
        let footer = RootAuthFooterV1 {
            archive_uuid: request.archive_uuid,
            session_id: request.session_id,
            format_version: FORMAT_VERSION,
            volume_format_rev: VOLUME_FORMAT_REV_45,
            authenticator_id: X509_AUTHENTICATOR_ID,
            signer_identity_type: X509_SIGNER_IDENTITY_TYPE_DER_CERT,
            signer_identity_bytes: leaf_cert.to_der().unwrap(),
            authenticator_value: value,
            total_data_block_count: 0,
            critical_metadata_digest: [0; 32],
            index_digest: [0; 32],
            fec_layout_digest: [0; 32],
            data_block_merkle_root: [0; 32],
            signer_identity_digest: [0; 32],
            archive_root: request.archive_root,
            footer_crc32c: 0,
        };

        let report = verify_root_auth_footer(&footer, &request.archive_root, &[root_cert.to_der().unwrap()], false, false).unwrap();

        assert_eq!(report.signature_scheme, "rsa-pss-sha256");
    }

    #[test]
    fn rsa_pss_constrained_spki_verifies_through_footer_path() {
        let (leaf_cert, leaf_key) = rsa_pss_leaf_cert_and_key();
        let signed_at = now_unix_seconds();
        let signer = X509RootAuthSigner::new_with_signature_scheme(
            leaf_cert.to_der().unwrap(),
            leaf_key,
            Vec::new(),
            signed_at,
            Some(X509SignatureScheme::RsaPssSha256),
        )
        .unwrap();
        let request = RootAuthSigningRequest { root_auth_spec_id: ROOT_AUTH_SPEC_ID_V45, archive_uuid: [1; 16], session_id: [2; 16], archive_root: [3; 32] };
        let footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);

        let report = verify_root_auth_footer(&footer, &request.archive_root, &[leaf_cert.to_der().unwrap()], false, false).unwrap();

        assert_eq!(report.signature_scheme, "rsa-pss-sha256");
    }

    #[test]
    fn rsa_verifier_rejects_pss_spki_mismatch_through_footer_path() {
        let (leaf_cert, leaf_key) = rsa_pss_leaf_cert_and_key();
        let signer = X509RootAuthSigner::new_with_signature_scheme(
            leaf_cert.to_der().unwrap(),
            leaf_key,
            Vec::new(),
            now_unix_seconds(),
            Some(X509SignatureScheme::RsaPssSha256),
        )
        .unwrap();
        let request = RootAuthSigningRequest { root_auth_spec_id: ROOT_AUTH_SPEC_ID_V45, archive_uuid: [1; 16], session_id: [2; 16], archive_root: [3; 32] };
        let mut footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);

        footer.authenticator_value[6..8].copy_from_slice(&SIG_SCHEME_RSA_PKCS1_SHA256.to_le_bytes());
        let err = verify_root_auth_footer(&footer, &request.archive_root, &[leaf_cert.to_der().unwrap()], false, false).unwrap_err();
        assert!(err.to_string().contains("requires unconstrained rsaEncryption"));

        footer.authenticator_value[6..8].copy_from_slice(&SIG_SCHEME_RSA_PSS_SHA256.to_le_bytes());
        footer.signer_identity_bytes =
            replace_nth_subsequence(&footer.signer_identity_bytes, &RSA_PSS_SHA256_SALT32_ALGORITHM, &RSA_PSS_SHA256_SALT20_ALGORITHM, 1).unwrap();
        let err = verify_root_auth_footer(&footer, &request.archive_root, &[leaf_cert.to_der().unwrap()], false, false).unwrap_err();
        assert!(err.to_string().contains("saltLength=32"));
    }

    #[test]
    fn signer_rejects_nonstandard_rsa_pss_spki_parameters() {
        let (leaf_cert, leaf_key) = rsa_pss_leaf_cert_and_key();
        let nonstandard_leaf_der =
            replace_nth_subsequence(&leaf_cert.to_der().unwrap(), &RSA_PSS_SHA256_SALT32_ALGORITHM, &RSA_PSS_SHA256_SALT20_ALGORITHM, 1).unwrap();

        let err = X509RootAuthSigner::new_with_signature_scheme(
            nonstandard_leaf_der,
            leaf_key,
            Vec::new(),
            now_unix_seconds(),
            Some(X509SignatureScheme::RsaPssSha256),
        )
        .unwrap_err();

        assert!(err.to_string().contains("saltLength=32"), "{err}");
    }

    #[test]
    fn rsa_pkcs1_scheme_rejects_pss_constrained_spki() {
        let pss_algorithm = parse_algorithm_identifier(&RSA_PSS_SHA256_SALT32_ALGORITHM);

        let err = validate_rsa_spki_algorithm_for_scheme(SIG_SCHEME_RSA_PKCS1_SHA256, &pss_algorithm).unwrap_err();

        assert!(err.to_string().contains("requires unconstrained rsaEncryption"));
    }

    #[test]
    fn rsa_pss_scheme_accepts_unconstrained_rsa_spki() {
        let rsa_algorithm = parse_algorithm_identifier(&RSA_ENCRYPTION_ALGORITHM);

        validate_rsa_spki_algorithm_for_scheme(SIG_SCHEME_RSA_PSS_SHA256, &rsa_algorithm).unwrap();
    }

    #[test]
    fn rsa_pss_scheme_accepts_matching_pss_spki_parameters() {
        let pss_algorithm = parse_algorithm_identifier(&RSA_PSS_SHA256_SALT32_ALGORITHM);

        validate_rsa_spki_algorithm_for_scheme(SIG_SCHEME_RSA_PSS_SHA256, &pss_algorithm).unwrap();
    }

    #[test]
    fn rsa_pss_scheme_rejects_nonstandard_pss_spki_parameters() {
        let pss_algorithm = parse_algorithm_identifier(&RSA_PSS_SHA256_SALT20_ALGORITHM);

        let err = validate_rsa_spki_algorithm_for_scheme(SIG_SCHEME_RSA_PSS_SHA256, &pss_algorithm).unwrap_err();

        assert!(err.to_string().contains("saltLength=32"));
    }

    #[test]
    fn signer_rejects_unsupported_ec_curve() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_ec_leaf_cert("Acme Unsupported EC Signing", root_cert.as_ref(), root_key.as_ref(), Nid::SECP256K1);

        let err = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), 1).unwrap_err();

        assert!(err.to_string().contains("unsupported X.509 ECDSA curve"));
    }

    #[test]
    fn v45_footer_uses_core_archive_root_and_rejects_wrong_spec_id() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signed_at = now_unix_seconds();
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), signed_at).unwrap();
        let request = RootAuthSigningRequest { root_auth_spec_id: ROOT_AUTH_SPEC_ID_V45, archive_uuid: [1; 16], session_id: [2; 16], archive_root: [3; 32] };
        let footer = RootAuthFooterV1 {
            archive_uuid: request.archive_uuid,
            session_id: request.session_id,
            format_version: FORMAT_VERSION,
            volume_format_rev: VOLUME_FORMAT_REV_45,
            authenticator_id: X509_AUTHENTICATOR_ID,
            signer_identity_type: X509_SIGNER_IDENTITY_TYPE_DER_CERT,
            signer_identity_bytes: leaf_cert.to_der().unwrap(),
            authenticator_value: signer.authenticator_value_for_request(&request).unwrap(),
            total_data_block_count: 0,
            critical_metadata_digest: [0; 32],
            index_digest: [0; 32],
            fec_layout_digest: [0; 32],
            data_block_merkle_root: [0; 32],
            signer_identity_digest: [0; 32],
            archive_root: [9; 32],
            footer_crc32c: 0,
        };

        verify_root_auth_footer(&footer, &request.archive_root, &[root_cert.to_der().unwrap()], false, false).unwrap();

        let mut revision_44_spec_id = [0u8; 24];
        revision_44_spec_id[..20].copy_from_slice(b"tzap-root-auth-v0.44");
        let wrong_spec_request = RootAuthSigningRequest { root_auth_spec_id: revision_44_spec_id, ..request };
        let mut wrong_spec_footer = footer;
        wrong_spec_footer.authenticator_value = signer.authenticator_value_for_request(&wrong_spec_request).unwrap();
        let err = verify_root_auth_footer(&wrong_spec_footer, &request.archive_root, &[root_cert.to_der().unwrap()], false, false).unwrap_err();

        assert!(err.to_string().contains("signature"));
    }

    #[test]
    fn rejects_wrong_trusted_root() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (wrong_root_cert, _) = test_ca_cert("Wrong Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signed_at = now_unix_seconds();
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), signed_at).unwrap();
        let request = RootAuthSigningRequest { root_auth_spec_id: ROOT_AUTH_SPEC_ID, archive_uuid: [1; 16], session_id: [2; 16], archive_root: [3; 32] };
        let footer = RootAuthFooterV1 {
            archive_uuid: request.archive_uuid,
            session_id: request.session_id,
            format_version: FORMAT_VERSION,
            volume_format_rev: VOLUME_FORMAT_REV,
            authenticator_id: X509_AUTHENTICATOR_ID,
            signer_identity_type: X509_SIGNER_IDENTITY_TYPE_DER_CERT,
            signer_identity_bytes: leaf_cert.to_der().unwrap(),
            authenticator_value: signer.authenticator_value_for_request(&request).unwrap(),
            total_data_block_count: 0,
            critical_metadata_digest: [0; 32],
            index_digest: [0; 32],
            fec_layout_digest: [0; 32],
            data_block_merkle_root: [0; 32],
            signer_identity_digest: [0; 32],
            archive_root: request.archive_root,
            footer_crc32c: 0,
        };

        let err = verify_root_auth_footer(&footer, &request.archive_root, &[wrong_root_cert.to_der().unwrap()], false, false).unwrap_err();

        assert!(matches!(err, X509RootAuthError::UntrustedChain(_)));
    }

    #[test]
    fn signer_rejects_invalid_chain_certificate_der() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let err = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, vec![b"not a DER certificate".to_vec()], now_unix_seconds()).unwrap_err();

        assert!(matches!(err, X509RootAuthError::Crypto(_)));
    }

    #[test]
    fn rejects_impossible_chain_count_without_large_allocation() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signed_at = now_unix_seconds();
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), signed_at).unwrap();
        let request = RootAuthSigningRequest { root_auth_spec_id: ROOT_AUTH_SPEC_ID, archive_uuid: [1; 16], session_id: [2; 16], archive_root: [3; 32] };
        let mut value = signer.authenticator_value_for_request(&request).unwrap();
        value[56..60].copy_from_slice(&u32::MAX.to_le_bytes());
        let footer = RootAuthFooterV1 {
            archive_uuid: request.archive_uuid,
            session_id: request.session_id,
            format_version: FORMAT_VERSION,
            volume_format_rev: VOLUME_FORMAT_REV,
            authenticator_id: X509_AUTHENTICATOR_ID,
            signer_identity_type: X509_SIGNER_IDENTITY_TYPE_DER_CERT,
            signer_identity_bytes: leaf_cert.to_der().unwrap(),
            authenticator_value: value,
            total_data_block_count: 0,
            critical_metadata_digest: [0; 32],
            index_digest: [0; 32],
            fec_layout_digest: [0; 32],
            data_block_merkle_root: [0; 32],
            signer_identity_digest: [0; 32],
            archive_root: request.archive_root,
            footer_crc32c: 0,
        };

        let err = verify_root_auth_footer(&footer, &request.archive_root, &[root_cert.to_der().unwrap()], false, false).unwrap_err();

        assert!(err.to_string().contains("chain count"));
    }

    const RSA_ENCRYPTION_ALGORITHM: [u8; 15] = [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00];
    const RSA_PSS_SHA256_SALT32_ALGORITHM: [u8; 67] = [
        0x30, 0x41, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A, 0x30, 0x34, 0xA0, 0x0F, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
        0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0xA1, 0x1C, 0x30, 0x1A, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08, 0x30, 0x0D, 0x06,
        0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0xA2, 0x03, 0x02, 0x01, 0x20,
    ];
    const RSA_PSS_SHA256_SALT20_ALGORITHM: [u8; 67] = [
        0x30, 0x41, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A, 0x30, 0x34, 0xA0, 0x0F, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
        0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0xA1, 0x1C, 0x30, 0x1A, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08, 0x30, 0x0D, 0x06,
        0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0xA2, 0x03, 0x02, 0x01, 0x14,
    ];

    fn parse_algorithm_identifier(bytes: &[u8]) -> AlgorithmIdentifier<'_> {
        let (remaining, algorithm) = AlgorithmIdentifier::from_der(bytes).unwrap();
        assert!(remaining.is_empty());
        algorithm
    }

    fn x509_signature_bytes(authenticator_value: &[u8]) -> &[u8] {
        let signature_len = u32::from_le_bytes(authenticator_value[48..52].try_into().unwrap()) as usize;
        &authenticator_value[AUTHENTICATOR_FIXED_LEN..AUTHENTICATOR_FIXED_LEN + signature_len]
    }

    fn replace_x509_signature(authenticator_value: &mut [u8], signature: &[u8]) {
        let signature_capacity = u32::from_le_bytes(authenticator_value[52..56].try_into().unwrap()) as usize;
        assert!(signature.len() <= signature_capacity);
        authenticator_value[48..52].copy_from_slice(&(signature.len() as u32).to_le_bytes());
        let signature_start = AUTHENTICATOR_FIXED_LEN;
        let signature_end = signature_start + signature_capacity;
        authenticator_value[signature_start..signature_end].fill(0);
        authenticator_value[signature_start..signature_start + signature.len()].copy_from_slice(signature);
    }

    fn high_s_ecdsa_signature<T>(signature: &[u8], public_key: &PKeyRef<T>) -> Vec<u8>
    where
        T: HasParams,
    {
        let sig = EcdsaSig::from_der(signature).unwrap();
        let (_, order, half_order) = ec_curve_order(public_key).unwrap();
        let mut high_s = BigNum::new().unwrap();
        high_s.checked_sub(&order, sig.s()).unwrap();
        assert_eq!(high_s.ucmp(&half_order), Ordering::Greater);
        EcdsaSig::from_private_components(sig.r().to_owned().unwrap(), high_s).unwrap().to_der().unwrap()
    }

    fn nonminimal_ecdsa_integer_encoding(signature: &[u8]) -> Vec<u8> {
        assert_eq!(signature[0], 0x30);
        assert_eq!(signature[2], 0x02);
        assert!(signature[1] < 0x80);
        assert!(signature[3] < 0x80);
        let mut out = signature.to_vec();
        out[1] += 1;
        out[3] += 1;
        out.insert(4, 0);
        out
    }

    fn replace_nth_subsequence(haystack: &[u8], needle: &[u8], replacement: &[u8], nth_zero_based: usize) -> Option<Vec<u8>> {
        if needle.is_empty() {
            return None;
        }
        let mut seen = 0usize;
        for found in 0..=haystack.len().saturating_sub(needle.len()) {
            if &haystack[found..found + needle.len()] == needle {
                if seen == nth_zero_based {
                    let mut output = Vec::with_capacity(haystack.len() - needle.len() + replacement.len());
                    output.extend_from_slice(&haystack[..found]);
                    output.extend_from_slice(replacement);
                    output.extend_from_slice(&haystack[found + needle.len()..]);
                    return Some(output);
                }
                seen += 1;
            }
        }
        None
    }

    fn rsa_pss_leaf_cert_and_key() -> (X509, PKey<Private>) {
        const CERT_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----\n\
MIIDszCCAmegAwIBAgIUPv/ZXhnr0d/fIsy7XZNStUFzFoUwQQYJKoZIhvcNAQEK\n\
MDSgDzANBglghkgBZQMEAgEFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgEF\n\
AKIDAgEgMBMxETAPBgNVBAMMCFBTUyBUZXN0MB4XDTI2MDYxOTA5MDEwOVoXDTM2\n\
MDYxNjA5MDEwOVowEzERMA8GA1UEAwwIUFNTIFRlc3QwggFWMEEGCSqGSIb3DQEB\n\
CjA0oA8wDQYJYIZIAWUDBAIBBQChHDAaBgkqhkiG9w0BAQgwDQYJYIZIAWUDBAIB\n\
BQCiAwIBIAOCAQ8AMIIBCgKCAQEAqbR7puu5pPH9QXREJYqeIMeCfiZcdxshMkUV\n\
U6ga3oV1082Hu71v65gep1ld9TAUx+qTf7eOWhnnGVwr4KiWnaA3UnrUW9N/AxA3\n\
0ag7OrjPAO0EsFyqqmTz2LfK/QI/yjqF+fLT8f2LerJg/K/nI0tytk51f0MOXHGO\n\
BB6HhQ9wbzKsVWyXB5EcfVarSzOVls3ANp72MXZqZ6e0LNyFt7GYmxZbNCCt/1+a\n\
vW+IlTkJ8Qf/MOpoIBtbxXOvHJn9vL84e3l8RXMTe6P/rrVodu6E7+U/mO6TDJOi\n\
RbrXSI3d9tp/JK3BJnfxoNwFPZivcoaLlkQ32ea6cozdunw0yQIDAQABo2MwYTAd\n\
BgNVHQ4EFgQUQ3i67w0yj6iaLNye7CUJwnzAnfEwHwYDVR0jBBgwFoAUQ3i67w0y\n\
j6iaLNye7CUJwnzAnfEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAoQw\n\
QQYJKoZIhvcNAQEKMDSgDzANBglghkgBZQMEAgEFAKEcMBoGCSqGSIb3DQEBCDAN\n\
BglghkgBZQMEAgEFAKIDAgEgA4IBAQAhKtXhU7fGxr9I8EjnLJ5h2/KEKZOs+ZeR\n\
GGV83xp5IQGni2D9XdsOo9NVQHPXsgz8U+b+9+JbzAUCLQM2JOQxCxodyIhSIULS\n\
1xR5OjcANPHe0eQyWNXhD67jqLF46IyQ5RMW07t/cs9a2Y5tWNAVfF/4xL2v0SF3\n\
ufyMkxPU1eC8Rc8g3faaDFkrkoL1HxXaI7lygw9YdNyKZwMOOod87VZF8SxoBgZo\n\
UDRz5eKKcZBZML3nXWgqidPnDWf+XIq++nTpewW7cxZREGO8IjaWCEegsJ/fNqCc\n\
jY2ZKxwTG9mQLube2UA9t0QHyJA1jpfBOI4GB3spRuCEInPhbXa4\n\
-----END CERTIFICATE-----\n";
        const KEY_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----\n\
MIIE8QIBADBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAQUAoRwwGgYJKoZI\n\
hvcNAQEIMA0GCWCGSAFlAwQCAQUAogMCASAEggSnMIIEowIBAAKCAQEAqbR7puu5\n\
pPH9QXREJYqeIMeCfiZcdxshMkUVU6ga3oV1082Hu71v65gep1ld9TAUx+qTf7eO\n\
WhnnGVwr4KiWnaA3UnrUW9N/AxA30ag7OrjPAO0EsFyqqmTz2LfK/QI/yjqF+fLT\n\
8f2LerJg/K/nI0tytk51f0MOXHGOBB6HhQ9wbzKsVWyXB5EcfVarSzOVls3ANp72\n\
MXZqZ6e0LNyFt7GYmxZbNCCt/1+avW+IlTkJ8Qf/MOpoIBtbxXOvHJn9vL84e3l8\n\
RXMTe6P/rrVodu6E7+U/mO6TDJOiRbrXSI3d9tp/JK3BJnfxoNwFPZivcoaLlkQ3\n\
2ea6cozdunw0yQIDAQABAoIBAARd5ewlxutDBFGnupyuMFM22wlgtpKkhrJG042J\n\
ZvaYn89tS5u1vFBnQ8up2ah2XiSGSVkZGa9BGSCejez8HZMNBTtouHfr7WngZBVP\n\
o0WHraDwGGWq3sPfcORf11fzE73iC2JDALfqfqkvt53s71FJztf41R5rFO6lR+Kc\n\
f/95G1PRrH0V8wbdykT27+OrO2YadoSc/hreu6IaFDou+sQ2cWL/exfiqJ8RHRDr\n\
OZX+Cr+zXhGMbQf+3uAwQKwYw2CHUcflke/18l99vyG2BkvJNLopETPAs9cbSSjL\n\
9f/kMfKktgnKleDAnjjVyq58TXICjPhynbOTsJMtkrVn/GECgYEA5fcNU+Xujn3x\n\
YfL44gAIy6xZHdJp08IZuhc8SgghqzPT5uq7rDJ85WLPuoUQk70ZNG2vEypiTuVR\n\
TFLySRQEWp44leKalANM10zLgtf8nDGiQsebIj2vwLHkpJmPiZZnyP5UdRuh+kt6\n\
IKpvfddN8q2VWpX0RZyeVLWfOZU+sCkCgYEAvOryuo6Vc34/VLd1gk8J6aYqFGeB\n\
+Lp9/Y0NapjUSdqSXWOjD81mTTeE6CDMBwv7+LHqMkRa4vPMJfGCPFQ7Kloi7aHB\n\
Rgf82wSuwrahHYPcNJdT+99xqYdaHE49lsZAmKXq56uNqHsqTIn1Dk/iWBNBTzXs\n\
mvD13k9lxiclc6ECgYEA0tzGtsBmDvhCpnrBZZF8fy1ohaTTbt1S88SsfoGYRcB/\n\
NATW0x10Um1ZZoDu41kITH+qghtiC0/QTPjdus6E84aTAjTHYqLoCZ8cGLztn1cP\n\
nsYiZLJFfp5fteIssI9eWPmD/eG5k6UztdIx6yTKD5TFF0vasR3cPHZRKt7DnYkC\n\
gYAM0987b6cSOoZOWE6wVHGV3eSJkiWvH+qiJsu8azgu85pwoO1Xi1jg8V4i7Oct\n\
q1CmqF4An8eUFX3NLcLsGcQSsiAhBpS7DpvKu1yqeAAkoul24LehKKDtI/Woal+g\n\
N0H3m3yB0pJB2Gsc21k6aY4y8MvEdyLjumzXdYixlcLjQQKBgCYL845ZwI2aa0SG\n\
UYmOb4/v/bM2BnDhU6S083QojMs7wNTPJ5UvDv9f6YflMj0nR1qpNuuQY7c8bVrU\n\
5giem1/deEviE8uzTJHzIKCWjJy3K08bFaK4Apn8A1mrElj6WCrmdsZJVCGZvAwz\n\
4pTHYNm4Z32/udjVnPLQxkN0iicu\n\
-----END PRIVATE KEY-----\n";
        (X509::from_pem(CERT_PEM).unwrap(), PKey::private_key_from_pem(KEY_PEM).unwrap())
    }

    fn test_ca_cert(cn: &str) -> (X509, PKey<Private>) {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", cn).unwrap();
        let name = name.build();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_serial_number(&random_serial_number()).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        builder.set_not_after(&Asn1Time::days_from_now(365).unwrap()).unwrap();
        builder.append_extension(BasicConstraints::new().critical().ca().build().unwrap()).unwrap();
        builder.append_extension(KeyUsage::new().critical().key_cert_sign().crl_sign().build().unwrap()).unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        (builder.build(), key)
    }

    fn test_leaf_cert(cn: &str, ca_cert: &X509Ref, ca_key: &PKeyRef<Private>) -> (X509, PKey<Private>) {
        test_leaf_cert_with_usage(cn, ca_cert, ca_key, LeafKeyUsage::DigitalSignature)
    }

    #[derive(Clone, Copy)]
    enum LeafKeyUsage {
        DigitalSignature,
        KeyEnciphermentOnly,
    }

    fn test_leaf_cert_with_usage(cn: &str, ca_cert: &X509Ref, ca_key: &PKeyRef<Private>, key_usage: LeafKeyUsage) -> (X509, PKey<Private>) {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", cn).unwrap();
        let name = name.build();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_serial_number(&random_serial_number()).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(ca_cert.subject_name()).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        builder.set_not_after(&Asn1Time::days_from_now(365).unwrap()).unwrap();
        builder.append_extension(BasicConstraints::new().build().unwrap()).unwrap();
        let mut usage = KeyUsage::new();
        usage.critical();
        match key_usage {
            LeafKeyUsage::DigitalSignature => {
                usage.digital_signature();
            }
            LeafKeyUsage::KeyEnciphermentOnly => {
                usage.key_encipherment();
            }
        }
        builder.append_extension(usage.build().unwrap()).unwrap();
        builder.sign(ca_key, MessageDigest::sha256()).unwrap();
        (builder.build(), key)
    }

    fn test_leaf_cert_no_key_usage(cn: &str, ca_cert: &X509Ref, ca_key: &PKeyRef<Private>) -> (X509, PKey<Private>) {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", cn).unwrap();
        let name = name.build();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_serial_number(&random_serial_number()).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(ca_cert.subject_name()).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        builder.set_not_after(&Asn1Time::days_from_now(365).unwrap()).unwrap();
        builder.append_extension(BasicConstraints::new().build().unwrap()).unwrap();
        builder.sign(ca_key, MessageDigest::sha256()).unwrap();
        (builder.build(), key)
    }

    fn test_expired_leaf_cert(cn: &str, ca_cert: &X509Ref, ca_key: &PKeyRef<Private>) -> (X509, PKey<Private>) {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", cn).unwrap();
        let name = name.build();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_serial_number(&random_serial_number()).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(ca_cert.subject_name()).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder.set_not_before(&Asn1Time::from_unix(0).unwrap()).unwrap();
        builder.set_not_after(&Asn1Time::from_unix(now_unix_seconds() - 3600).unwrap()).unwrap();
        builder.append_extension(BasicConstraints::new().build().unwrap()).unwrap();
        builder.append_extension(KeyUsage::new().critical().digital_signature().build().unwrap()).unwrap();
        builder.sign(ca_key, MessageDigest::sha256()).unwrap();
        (builder.build(), key)
    }

    fn test_ec_leaf_cert(cn: &str, ca_cert: &X509Ref, ca_key: &PKeyRef<Private>, curve: Nid) -> (X509, PKey<Private>) {
        let group = EcGroup::from_curve_name(curve).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", cn).unwrap();
        let name = name.build();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_serial_number(&random_serial_number()).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(ca_cert.subject_name()).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        builder.set_not_after(&Asn1Time::days_from_now(365).unwrap()).unwrap();
        builder.append_extension(BasicConstraints::new().build().unwrap()).unwrap();
        builder.append_extension(KeyUsage::new().critical().digital_signature().build().unwrap()).unwrap();
        builder.sign(ca_key, MessageDigest::sha256()).unwrap();
        (builder.build(), key)
    }

    fn random_serial_number() -> openssl::asn1::Asn1Integer {
        let mut serial = BigNum::new().unwrap();
        serial.rand(159, MsbOption::MAYBE_ZERO, false).unwrap();
        serial.to_asn1_integer().unwrap()
    }

    fn now_unix_seconds() -> i64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
    }
}
