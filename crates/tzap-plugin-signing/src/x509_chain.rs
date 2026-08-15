use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::traits::PublicKeyParts;
// pkcs8 0.10 for RSA's pkcs8 integration and PrivateKeyInfo parsing;
// pkcs8 0.11 for the elliptic-curve 0.14 key decoding traits.
use base64::Engine;
use ecdsa::elliptic_curve::scalar::IsHigh as _;
use pkcs8::DecodePrivateKey;
use pkcs8_010::der::Decode;
use pkcs8_010::DecodePrivateKey as _;
use rand_core::OsRng;
use rsa::pkcs1v15;
use rsa::pss;
use sha2::{Digest, Sha256, Sha512};
// rsa 0.9 implements the signature 2.x traits; ecdsa 0.17 implements the
// signature 3.x traits. Import both (the 3.x ones anonymously so the two
// same-named traits do not collide).
use signature::{DigestSigner, DigestVerifier, RandomizedDigestSigner, SignatureEncoding};
use signature3::hazmat::{PrehashSigner as _, PrehashVerifier as _};
use signature3::SignatureEncoding as _;
use tzap_core::format::{root_auth_spec_id_for_revision, ROOT_AUTH_SPEC_ID};
use tzap_core::wire::RootAuthFooterV1;
use tzap_core::writer::{RootAuthSigningRequest, RootAuthWriterConfig};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;
use x509_parser::signature_algorithm::{RsaSsaPssParams, SignatureAlgorithm};
use x509_parser::x509::{AlgorithmIdentifier, X509Name};

// Chain path-validation allow-list: OpenSSL's X509StoreContext is the one
// piece that has no RustCrypto equivalent yet (see the module docs there and
// implementation-docs/openssl-dependency-removal-plan.md §6).
mod x509_chain_verify_openssl;

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
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_EC_P256: &str = "1.2.840.10045.3.1.7";
const OID_EC_P384: &str = "1.3.132.0.34";
const OID_EC_P521: &str = "1.3.132.0.35";
const OID_ED25519: &str = "1.3.101.112";
const OID_ED448: &str = "1.3.101.113";
const X509_SIGNING_DOMAIN: &[u8] = b"tzap-sig-x509-v1\0";
const X509_CHAIN_DOMAIN: &[u8] = b"tzap-x509-chain-v1\0";
const AUTHENTICATOR_FIXED_LEN: usize = 60;
const SHA256_LEN: usize = 32;

/// Authenticator signature capacities for EC keys, measured from OpenSSL's
/// `EVP_PKEY_size` (which the pre-migration signer used): 72/104/139 for
/// P-256/P-384/P-521. These are upper bounds on the DER signature size, so
/// a one-byte difference from another derivation is still safe.
const ECDSA_SIG_MAX_P256: usize = 72;
const ECDSA_SIG_MAX_P384: usize = 104;
const ECDSA_SIG_MAX_P521: usize = 139;

#[derive(Debug)]
pub enum X509RootAuthError {
    Invalid(&'static str),
    UnsupportedIdentity,
    MissingTrustPolicy,
    UntrustedChain(String),
    Chain(String),
}

impl fmt::Display for X509RootAuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => formatter.write_str(message),
            Self::UnsupportedIdentity => formatter.write_str("unsupported signer identity type"),
            Self::MissingTrustPolicy => formatter.write_str("X.509 verification requires trusted roots"),
            Self::UntrustedChain(message) => formatter.write_str(message),
            Self::Chain(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for X509RootAuthError {}

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

/// Signing key material accepted by the X.509 RootAuth profile.
///
/// The RustCrypto replacement for the OpenSSL `PKey<Private>` this type used
/// to hold. Parsed from PEM or DER (PKCS#8, PKCS#1 for RSA, SEC1 for EC):
/// RSA keys (including RSA-PSS-restricted keys, which require an explicit
/// signature scheme) and P-256/P-384/P-521 ECDSA keys are supported.
#[derive(Debug, Clone)]
pub enum X509SigningKey {
    Rsa(rsa::RsaPrivateKey),
    RsaPss(rsa::RsaPrivateKey),
    EcP256(ecdsa::SigningKey<p256::NistP256>),
    EcP384(ecdsa::SigningKey<p384::NistP384>),
    EcP521(ecdsa::SigningKey<p521::NistP521>),
}

impl X509SigningKey {
    pub fn from_pem_or_der(bytes: &[u8]) -> Result<Self, X509RootAuthError> {
        if looks_like_pem(bytes) {
            let der = pem_payload_der(bytes).ok_or(X509RootAuthError::Invalid("failed to parse PEM private key"))?;
            return Self::from_der(&der);
        }
        Self::from_der(bytes)
    }

    pub fn from_der(bytes: &[u8]) -> Result<Self, X509RootAuthError> {
        if let Ok(key) = rsa::RsaPrivateKey::from_pkcs8_der(bytes) {
            return Ok(Self::Rsa(key));
        }
        if let Ok(info) = pkcs8_010::PrivateKeyInfo::from_der(bytes) {
            // rsa's `from_pkcs8_der` requires NULL parameters; OpenSSL also
            // accepted absent parameters for rsaEncryption, so that form is
            // parsed directly from the inner PKCS#1 structure.
            if info.algorithm.oid == pkcs8_010::ObjectIdentifier::new_unwrap(OID_RSA_ENCRYPTION) && info.algorithm.parameters.is_none() {
                if let Ok(key) = rsa::RsaPrivateKey::from_pkcs1_der(info.private_key) {
                    return Ok(Self::Rsa(key));
                }
            }
            if info.algorithm.oid == pkcs8_010::ObjectIdentifier::new_unwrap(OID_RSASSA_PSS) {
                // RSA-PSS-restricted keys parse, but cannot pick a scheme on
                // their own (matches the OpenSSL Id::RSA_PSS behavior).
                return rsa::RsaPrivateKey::from_pkcs1_der(info.private_key)
                    .map(Self::RsaPss)
                    .map_err(|_| X509RootAuthError::Invalid("failed to parse RSA-PSS private key"));
            }
        }
        if let Ok(key) = rsa::RsaPrivateKey::from_pkcs1_der(bytes) {
            return Ok(Self::Rsa(key));
        }
        if let Ok(key) = p256::SecretKey::from_pkcs8_der(bytes) {
            return Ok(Self::EcP256(key.into()));
        }
        if let Ok(key) = p384::SecretKey::from_pkcs8_der(bytes) {
            return Ok(Self::EcP384(key.into()));
        }
        if let Ok(key) = p521::SecretKey::from_pkcs8_der(bytes) {
            return Ok(Self::EcP521(key.into()));
        }
        if let Ok(key) = p256::SecretKey::from_sec1_der(bytes) {
            // SEC1 keys with an explicit [0] namedCurve must name the same
            // curve (OpenSSL's d2i_ECPrivateKey used that group).
            if sec1_curve_matches(bytes, OID_EC_P256) {
                return Ok(Self::EcP256(key.into()));
            }
            return Err(X509RootAuthError::Invalid("unsupported X.509 ECDSA curve"));
        }
        if let Ok(key) = p384::SecretKey::from_sec1_der(bytes) {
            if sec1_curve_matches(bytes, OID_EC_P384) {
                return Ok(Self::EcP384(key.into()));
            }
            return Err(X509RootAuthError::Invalid("unsupported X.509 ECDSA curve"));
        }
        if let Ok(key) = p521::SecretKey::from_sec1_der(bytes) {
            if sec1_curve_matches(bytes, OID_EC_P521) {
                return Ok(Self::EcP521(key.into()));
            }
            return Err(X509RootAuthError::Invalid("unsupported X.509 ECDSA curve"));
        }
        if let Ok(info) = pkcs8_010::PrivateKeyInfo::from_der(bytes) {
            let algorithm_oid = info.algorithm.oid.to_string();
            if algorithm_oid == OID_ED25519 || algorithm_oid == OID_ED448 {
                return Err(X509RootAuthError::Invalid("EdDSA X.509 keys are not supported by this RootAuth profile"));
            }
        }
        if ec_key_with_unsupported_curve(bytes) {
            return Err(X509RootAuthError::Invalid("unsupported X.509 ECDSA curve"));
        }
        Err(X509RootAuthError::Invalid("unsupported X.509 signature key type"))
    }
}

/// Parsed public key material from a leaf certificate SPKI.
enum X509PublicKey {
    Rsa(rsa::RsaPublicKey),
    RsaPss(rsa::RsaPublicKey),
    EcP256(ecdsa::VerifyingKey<p256::NistP256>),
    EcP384(ecdsa::VerifyingKey<p384::NistP384>),
    EcP521(ecdsa::VerifyingKey<p521::NistP521>),
}

impl X509PublicKey {
    fn from_certificate(certificate: &X509Certificate<'_>) -> Result<Self, X509RootAuthError> {
        let spki = &certificate.tbs_certificate.subject_pki;
        match spki.algorithm.algorithm.to_id_string().as_str() {
            OID_RSA_ENCRYPTION => rsa::RsaPublicKey::from_pkcs1_der(spki.subject_public_key.data.as_ref())
                .map(Self::Rsa)
                .map_err(|_| X509RootAuthError::Invalid("unsupported RSA SubjectPublicKeyInfo")),
            OID_RSASSA_PSS => rsa::RsaPublicKey::from_pkcs1_der(spki.subject_public_key.data.as_ref())
                .map(Self::RsaPss)
                .map_err(|_| X509RootAuthError::Invalid("unsupported RSA-PSS SubjectPublicKeyInfo")),
            OID_EC_PUBLIC_KEY => {
                let parameters_oid = spki
                    .algorithm
                    .parameters
                    .as_ref()
                    .and_then(|parameters| parameters.as_oid().ok().map(|oid| oid.to_id_string()));
                let point = spki.subject_public_key.data.as_ref();
                match parameters_oid.as_deref() {
                    Some(OID_EC_P256) => p256::PublicKey::from_sec1_bytes(point)
                        .map(|key| Self::EcP256(key.into()))
                        .map_err(|_| X509RootAuthError::Invalid("invalid P-256 SubjectPublicKeyInfo")),
                    Some(OID_EC_P384) => p384::PublicKey::from_sec1_bytes(point)
                        .map(|key| Self::EcP384(key.into()))
                        .map_err(|_| X509RootAuthError::Invalid("invalid P-384 SubjectPublicKeyInfo")),
                    Some(OID_EC_P521) => p521::PublicKey::from_sec1_bytes(point)
                        .map(|key| Self::EcP521(key.into()))
                        .map_err(|_| X509RootAuthError::Invalid("invalid P-521 SubjectPublicKeyInfo")),
                    _ => Err(X509RootAuthError::Invalid("unsupported X.509 ECDSA curve")),
                }
            }
            _ => Err(X509RootAuthError::Invalid("unsupported X.509 public key type")),
        }
    }

    fn matches_private_key(&self, private_key: &X509SigningKey) -> bool {
        match (self, private_key) {
            (Self::Rsa(public), X509SigningKey::Rsa(private))
            | (Self::Rsa(public), X509SigningKey::RsaPss(private))
            | (Self::RsaPss(public), X509SigningKey::Rsa(private))
            | (Self::RsaPss(public), X509SigningKey::RsaPss(private)) => public.n() == private.n() && public.e() == private.e(),
            (Self::EcP256(public), X509SigningKey::EcP256(private)) => public.to_sec1_point(false) == private.verifying_key().to_sec1_point(false),
            (Self::EcP384(public), X509SigningKey::EcP384(private)) => public.to_sec1_point(false) == private.verifying_key().to_sec1_point(false),
            (Self::EcP521(public), X509SigningKey::EcP521(private)) => public.to_sec1_point(false) == private.verifying_key().to_sec1_point(false),
            _ => false,
        }
    }
}

fn signature_scheme_for_private_key(private_key: &X509SigningKey) -> Result<u16, X509RootAuthError> {
    match private_key {
        X509SigningKey::Rsa(_) => Ok(SIG_SCHEME_RSA_PKCS1_SHA256),
        X509SigningKey::RsaPss(_) => Err(X509RootAuthError::Invalid(
            "RSASSA-PSS X.509 keys require explicit rsa-pss-sha256 signature scheme",
        )),
        X509SigningKey::EcP256(_) | X509SigningKey::EcP384(_) | X509SigningKey::EcP521(_) => Ok(SIG_SCHEME_ECDSA_SHA256_DER),
    }
}

#[derive(Debug)]
pub struct X509RootAuthSigner {
    leaf_certificate_der: Vec<u8>,
    private_key: X509SigningKey,
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
        let private_key = X509SigningKey::from_pem_or_der(private_key_bytes)?;
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
        let private_key = X509SigningKey::from_pem_or_der(private_key_bytes)?;
        Self::new_with_signature_scheme(
            leaf_certificate_der,
            private_key,
            chain_certificate_der,
            signed_at_unix_seconds,
            Some(signature_scheme),
        )
    }

    pub fn new(
        leaf_certificate_der: Vec<u8>,
        private_key: impl Into<X509SigningKey>,
        chain_certificate_der: Vec<Vec<u8>>,
        signed_at_unix_seconds: i64,
    ) -> Result<Self, X509RootAuthError> {
        Self::new_with_signature_scheme(leaf_certificate_der, private_key, chain_certificate_der, signed_at_unix_seconds, None)
    }

    pub fn new_with_signature_scheme(
        leaf_certificate_der: Vec<u8>,
        private_key: impl Into<X509SigningKey>,
        chain_certificate_der: Vec<Vec<u8>>,
        signed_at_unix_seconds: i64,
        signature_scheme: Option<X509SignatureScheme>,
    ) -> Result<Self, X509RootAuthError> {
        let private_key = private_key.into();
        let (remaining, leaf_certificate) =
            X509Certificate::from_der(&leaf_certificate_der).map_err(|_| X509RootAuthError::Invalid("invalid leaf certificate DER"))?;
        if !remaining.is_empty() {
            return Err(X509RootAuthError::Invalid("leaf certificate DER has trailing bytes"));
        }
        let leaf_public_key = X509PublicKey::from_certificate(&leaf_certificate)?;
        if !leaf_public_key.matches_private_key(&private_key) {
            return Err(X509RootAuthError::Invalid("certificate public key does not match private key"));
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
        let signature_capacity = private_key.signature_capacity();
        let signer = Self {
            leaf_certificate_der,
            private_key,
            chain_certificate_der,
            signed_at_unix_seconds,
            signature_capacity,
            sig_scheme,
        };
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
        let signature = sign_input_for_scheme(self.sig_scheme, &self.private_key, &signing_input)?;
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

impl X509SigningKey {
    /// Authenticator signature capacity: RSA modulus size, or the maximum
    /// DER-encoded ECDSA signature size (OpenSSL `EVP_PKEY_size` parity).
    fn signature_capacity(&self) -> usize {
        match self {
            Self::Rsa(key) | Self::RsaPss(key) => key.size(),
            Self::EcP256(_) => ECDSA_SIG_MAX_P256,
            Self::EcP384(_) => ECDSA_SIG_MAX_P384,
            Self::EcP521(_) => ECDSA_SIG_MAX_P521,
        }
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
    let mut certificates = certificates_der_from_pem_or_der(bytes)?;
    match certificates.as_slice() {
        [certificate] => Ok(certificate.clone()),
        [] => Err(X509RootAuthError::Invalid("certificate PEM file is empty")),
        [_, ..] => Ok(certificates.remove(0)),
    }
}

pub fn certificates_der_from_pem_or_der(bytes: &[u8]) -> Result<Vec<Vec<u8>>, X509RootAuthError> {
    if looks_like_pem(bytes) {
        let mut certificates = Vec::new();
        for pem in x509_parser::pem::Pem::iter_from_buffer(bytes) {
            let pem = pem.map_err(|_| X509RootAuthError::Invalid("failed to parse certificate PEM"))?;
            if pem.label != "CERTIFICATE" {
                continue;
            }
            let (remaining, _) = X509Certificate::from_der(&pem.contents).map_err(|_| X509RootAuthError::Invalid("invalid X.509 certificate"))?;
            if !remaining.is_empty() {
                return Err(X509RootAuthError::Invalid("X.509 certificate DER has trailing bytes"));
            }
            certificates.push(pem.contents);
        }
        if certificates.is_empty() {
            return Err(X509RootAuthError::Invalid("certificate PEM file is empty"));
        }
        Ok(certificates)
    } else {
        let (remaining, _) = X509Certificate::from_der(bytes).map_err(|_| X509RootAuthError::Invalid("invalid X.509 certificate"))?;
        if !remaining.is_empty() {
            return Err(X509RootAuthError::Invalid("X.509 certificate DER has trailing bytes"));
        }
        Ok(vec![bytes.to_vec()])
    }
}

fn normalize_certificate_der_chain(chain_certificate_der: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>, X509RootAuthError> {
    chain_certificate_der
        .into_iter()
        .map(|cert_der| {
            let (remaining, _) = X509Certificate::from_der(&cert_der).map_err(|_| X509RootAuthError::Invalid("invalid X.509 chain certificate"))?;
            if !remaining.is_empty() {
                return Err(X509RootAuthError::Invalid("X.509 chain certificate DER has trailing bytes"));
            }
            Ok(cert_der)
        })
        .collect()
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

    let (remaining, leaf_certificate) =
        X509Certificate::from_der(&footer.signer_identity_bytes).map_err(|_| X509RootAuthError::Invalid("invalid X.509 signer identity"))?;
    if !remaining.is_empty() {
        return Err(X509RootAuthError::Invalid("invalid X.509 signer identity"));
    }
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
    let leaf_public_key = X509PublicKey::from_certificate(&leaf_certificate)?;
    validate_rsa_spki_signature_scheme(parsed.sig_scheme, footer.signer_identity_bytes.as_slice())?;
    validate_public_key_matches_scheme(parsed.sig_scheme, &leaf_public_key)?;
    validate_signature_for_scheme(parsed.sig_scheme, &leaf_public_key, &parsed.signature)?;
    if !verify_input_for_scheme(parsed.sig_scheme, &leaf_public_key, &signing_input, &parsed.signature)? {
        return Err(X509RootAuthError::Invalid("X.509 RootAuth signature failed"));
    }
    validate_leaf_key_usage(&footer.signer_identity_bytes)?;
    if trusted_roots_der.is_empty() && !use_system_roots {
        return Err(X509RootAuthError::MissingTrustPolicy);
    }

    let chain_validation_time_unix_seconds = current_unix_seconds()?;
    let verified_chain_der = x509_chain_verify_openssl::verify_certificate_chain(
        &footer.signer_identity_bytes,
        &parsed.chain_certificate_der,
        trusted_roots_der,
        use_system_roots,
        chain_validation_time_unix_seconds,
    )?;
    // Subjects are formatted with the same `x509_name_to_string` as the leaf
    // report fields, so one certificate renders identically everywhere.
    let verified_chain_subjects: Vec<String> = verified_chain_der
        .iter()
        .map(|der| {
            X509Certificate::from_der(der)
                .ok()
                .filter(|(remaining, _)| remaining.is_empty())
                .map(|(_, certificate)| x509_name_to_string(certificate.subject()))
                .unwrap_or_default()
        })
        .collect();
    let fingerprint = Sha256::digest(&footer.signer_identity_bytes);
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
        subject: x509_name_to_string(leaf_certificate.subject()),
        issuer: x509_name_to_string(leaf_certificate.issuer()),
        // BN::to_hex_str parity: uppercase, no leading zeros.
        serial_number_hex: leaf_certificate.serial.to_str_radix(16).to_uppercase(),
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

    let (remaining, leaf_certificate) =
        X509Certificate::from_der(&footer.signer_identity_bytes).map_err(|_| X509RootAuthError::Invalid("invalid X.509 signer identity"))?;
    if !remaining.is_empty() {
        return Err(X509RootAuthError::Invalid("invalid X.509 signer identity"));
    }
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
    let leaf_public_key = X509PublicKey::from_certificate(&leaf_certificate)?;
    validate_rsa_spki_signature_scheme(parsed.sig_scheme, footer.signer_identity_bytes.as_slice())?;
    validate_public_key_matches_scheme(parsed.sig_scheme, &leaf_public_key)?;
    validate_signature_for_scheme(parsed.sig_scheme, &leaf_public_key, &parsed.signature)?;
    if !verify_input_for_scheme(parsed.sig_scheme, &leaf_public_key, &signing_input, &parsed.signature)? {
        return Err(X509RootAuthError::Invalid("X.509 RootAuth signature failed"));
    }
    validate_leaf_key_usage(&footer.signer_identity_bytes)?;

    let fingerprint = Sha256::digest(&footer.signer_identity_bytes);
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
            return Err(X509RootAuthError::Invalid(
                "rsa-pkcs1-sha256 requires unconstrained rsaEncryption SubjectPublicKeyInfo",
            ));
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

    let mask_generation = params
        .mask_gen_algorithm()
        .map_err(|_| X509RootAuthError::Invalid("leaf RSA-PSS SubjectPublicKeyInfo is missing mask generation parameters"))?;
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

fn validate_private_key_matches_scheme(sig_scheme: u16, private_key: &X509SigningKey) -> Result<(), X509RootAuthError> {
    match (sig_scheme, private_key) {
        (SIG_SCHEME_RSA_PKCS1_SHA256, X509SigningKey::Rsa(_)) => Ok(()),
        (SIG_SCHEME_RSA_PSS_SHA256, X509SigningKey::Rsa(_) | X509SigningKey::RsaPss(_)) => Ok(()),
        (SIG_SCHEME_ECDSA_SHA256_DER, X509SigningKey::EcP256(_) | X509SigningKey::EcP384(_) | X509SigningKey::EcP521(_)) => Ok(()),
        _ => Err(X509RootAuthError::Invalid("X.509 signature scheme/key mismatch")),
    }
}

fn validate_public_key_matches_scheme(sig_scheme: u16, public_key: &X509PublicKey) -> Result<(), X509RootAuthError> {
    match (sig_scheme, public_key) {
        (SIG_SCHEME_RSA_PKCS1_SHA256, X509PublicKey::Rsa(_)) => Ok(()),
        (SIG_SCHEME_RSA_PSS_SHA256, X509PublicKey::Rsa(_) | X509PublicKey::RsaPss(_)) => Ok(()),
        (SIG_SCHEME_ECDSA_SHA256_DER, X509PublicKey::EcP256(_) | X509PublicKey::EcP384(_) | X509PublicKey::EcP521(_)) => Ok(()),
        _ => Err(X509RootAuthError::Invalid("X.509 signature scheme/key mismatch")),
    }
}

/// Signs `input` with SHA-256 as the message digest, producing the
/// on-the-wire signature for each scheme (fixed-width RSA, low-S canonical
/// DER for ECDSA — the OpenSSL `Signer`/`normalize_signature_for_scheme`
/// equivalent).
fn sign_input_for_scheme(sig_scheme: u16, private_key: &X509SigningKey, input: &[u8]) -> Result<Vec<u8>, X509RootAuthError> {
    match (sig_scheme, private_key) {
        (SIG_SCHEME_RSA_PKCS1_SHA256, X509SigningKey::Rsa(key)) => {
            let signing_key = pkcs1v15::SigningKey::<Sha256>::new(key.clone());
            let signature: rsa::pkcs1v15::Signature = signing_key.sign_digest(Sha256::new_with_prefix(input));
            Ok(signature.to_vec())
        }
        (SIG_SCHEME_RSA_PSS_SHA256, X509SigningKey::Rsa(key) | X509SigningKey::RsaPss(key)) => {
            let signing_key = pss::SigningKey::<Sha256>::new_with_salt_len(key.clone(), 32);
            let signature: rsa::pss::Signature = signing_key.sign_digest_with_rng(&mut OsRng, Sha256::new_with_prefix(input));
            Ok(signature.to_vec())
        }
        (SIG_SCHEME_ECDSA_SHA256_DER, X509SigningKey::EcP256(key)) => {
            let fixed: ecdsa::Signature<p256::NistP256> = key
                .clone()
                .sign_prehash(&Sha256::digest(input))
                .map_err(|_| X509RootAuthError::Invalid("X.509 ECDSA signing failed"))?;
            Ok(ecdsa::der::Signature::<p256::NistP256>::from(fixed.normalize_s()).to_vec())
        }
        (SIG_SCHEME_ECDSA_SHA256_DER, X509SigningKey::EcP384(key)) => {
            let fixed: ecdsa::Signature<p384::NistP384> = key
                .clone()
                .sign_prehash(&Sha256::digest(input))
                .map_err(|_| X509RootAuthError::Invalid("X.509 ECDSA signing failed"))?;
            Ok(ecdsa::der::Signature::<p384::NistP384>::from(fixed.normalize_s()).to_vec())
        }
        (SIG_SCHEME_ECDSA_SHA256_DER, X509SigningKey::EcP521(key)) => {
            let fixed: ecdsa::Signature<p521::NistP521> = key
                .clone()
                .sign_prehash(&Sha256::digest(input))
                .map_err(|_| X509RootAuthError::Invalid("X.509 ECDSA signing failed"))?;
            Ok(ecdsa::der::Signature::<p521::NistP521>::from(fixed.normalize_s()).to_vec())
        }
        _ => Err(X509RootAuthError::Invalid("unsupported X.509 signature scheme")),
    }
}

fn verify_input_for_scheme(sig_scheme: u16, public_key: &X509PublicKey, input: &[u8], signature: &[u8]) -> Result<bool, X509RootAuthError> {
    match (sig_scheme, public_key) {
        (SIG_SCHEME_RSA_PKCS1_SHA256, X509PublicKey::Rsa(key)) => {
            let verifying_key = pkcs1v15::VerifyingKey::<Sha256>::new(key.clone());
            let signature =
                rsa::pkcs1v15::Signature::try_from(signature).map_err(|_| X509RootAuthError::Invalid("X.509 RSA signature length does not match modulus"))?;
            Ok(verifying_key.verify_digest(Sha256::new_with_prefix(input), &signature).is_ok())
        }
        (SIG_SCHEME_RSA_PSS_SHA256, X509PublicKey::Rsa(key) | X509PublicKey::RsaPss(key)) => {
            let verifying_key = pss::VerifyingKey::<Sha256>::new_with_salt_len(key.clone(), 32);
            let signature =
                rsa::pss::Signature::try_from(signature).map_err(|_| X509RootAuthError::Invalid("X.509 RSA signature length does not match modulus"))?;
            Ok(verifying_key.verify_digest(Sha256::new_with_prefix(input), &signature).is_ok())
        }
        (SIG_SCHEME_ECDSA_SHA256_DER, X509PublicKey::EcP256(key)) => {
            let signature = ecdsa::der::Signature::<p256::NistP256>::try_from(signature)
                .map_err(|_| X509RootAuthError::Invalid("X.509 ECDSA signature is not valid DER"))?;
            Ok(key.verify_prehash(&Sha256::digest(input), &signature).is_ok())
        }
        (SIG_SCHEME_ECDSA_SHA256_DER, X509PublicKey::EcP384(key)) => {
            let signature = ecdsa::der::Signature::<p384::NistP384>::try_from(signature)
                .map_err(|_| X509RootAuthError::Invalid("X.509 ECDSA signature is not valid DER"))?;
            Ok(key.verify_prehash(&Sha256::digest(input), &signature).is_ok())
        }
        (SIG_SCHEME_ECDSA_SHA256_DER, X509PublicKey::EcP521(key)) => {
            let signature = ecdsa::der::Signature::<p521::NistP521>::try_from(signature)
                .map_err(|_| X509RootAuthError::Invalid("X.509 ECDSA signature is not valid DER"))?;
            Ok(key.verify_prehash(&Sha256::digest(input), &signature).is_ok())
        }
        _ => Err(X509RootAuthError::Invalid("unsupported X.509 signature scheme")),
    }
}

fn validate_leaf_key_usage(leaf_certificate_der: &[u8]) -> Result<(), X509RootAuthError> {
    let (remaining, parsed_certificate) = x509_parser::certificate::X509Certificate::from_der(leaf_certificate_der)
        .map_err(|_| X509RootAuthError::Invalid("failed to parse leaf certificate KeyUsage"))?;
    if !remaining.is_empty() {
        return Err(X509RootAuthError::Invalid("leaf certificate DER has trailing bytes"));
    }
    let Some(key_usage) = parsed_certificate
        .key_usage()
        .map_err(|_| X509RootAuthError::Invalid("failed to parse leaf certificate KeyUsage"))?
    else {
        return Ok(());
    };
    if key_usage.value.digital_signature() || key_usage.value.non_repudiation() {
        return Ok(());
    }
    Err(X509RootAuthError::Invalid("leaf certificate KeyUsage does not allow archive signing"))
}

fn validate_signature_for_scheme(sig_scheme: u16, public_key: &X509PublicKey, signature: &[u8]) -> Result<(), X509RootAuthError> {
    match sig_scheme {
        SIG_SCHEME_RSA_PKCS1_SHA256 | SIG_SCHEME_RSA_PSS_SHA256 => {
            let modulus_len = match public_key {
                X509PublicKey::Rsa(key) | X509PublicKey::RsaPss(key) => key.size(),
                _ => return Err(X509RootAuthError::Invalid("X.509 signature scheme/key mismatch")),
            };
            if signature.len() != modulus_len {
                return Err(X509RootAuthError::Invalid("X.509 RSA signature length does not match modulus"));
            }
            Ok(())
        }
        SIG_SCHEME_ECDSA_SHA256_DER => validate_ecdsa_der_low_s(public_key, signature),
        _ => Err(X509RootAuthError::Invalid("unsupported X.509 signature scheme")),
    }
}

/// ECDSA canonical low-S validation: strict DER parse, canonical re-encoding,
/// positive in-range scalars (enforced by the scalar types), and s <= n/2.
fn validate_ecdsa_der_low_s(public_key: &X509PublicKey, signature: &[u8]) -> Result<(), X509RootAuthError> {
    match public_key {
        X509PublicKey::EcP256(_) => {
            let der_signature = ecdsa::der::Signature::<p256::NistP256>::try_from(signature)
                .map_err(|_| X509RootAuthError::Invalid("X.509 ECDSA signature is not valid DER"))?;
            let canonical = der_signature.to_vec();
            if canonical != signature {
                return Err(X509RootAuthError::Invalid("X.509 ECDSA signature is not canonical DER"));
            }
            let fixed: ecdsa::Signature<p256::NistP256> = der_signature
                .try_into()
                .map_err(|_| X509RootAuthError::Invalid("X.509 ECDSA signature is not valid DER"))?;
            if fixed.s().is_high().into() {
                return Err(X509RootAuthError::Invalid("X.509 ECDSA signature is high-S"));
            }
            Ok(())
        }
        X509PublicKey::EcP384(_) => {
            let der_signature = ecdsa::der::Signature::<p384::NistP384>::try_from(signature)
                .map_err(|_| X509RootAuthError::Invalid("X.509 ECDSA signature is not valid DER"))?;
            let canonical = der_signature.to_vec();
            if canonical != signature {
                return Err(X509RootAuthError::Invalid("X.509 ECDSA signature is not canonical DER"));
            }
            let fixed: ecdsa::Signature<p384::NistP384> = der_signature
                .try_into()
                .map_err(|_| X509RootAuthError::Invalid("X.509 ECDSA signature is not valid DER"))?;
            if fixed.s().is_high().into() {
                return Err(X509RootAuthError::Invalid("X.509 ECDSA signature is high-S"));
            }
            Ok(())
        }
        X509PublicKey::EcP521(_) => {
            let der_signature = ecdsa::der::Signature::<p521::NistP521>::try_from(signature)
                .map_err(|_| X509RootAuthError::Invalid("X.509 ECDSA signature is not valid DER"))?;
            let canonical = der_signature.to_vec();
            if canonical != signature {
                return Err(X509RootAuthError::Invalid("X.509 ECDSA signature is not canonical DER"));
            }
            let fixed: ecdsa::Signature<p521::NistP521> = der_signature
                .try_into()
                .map_err(|_| X509RootAuthError::Invalid("X.509 ECDSA signature is not valid DER"))?;
            if fixed.s().is_high().into() {
                return Err(X509RootAuthError::Invalid("X.509 ECDSA signature is high-S"));
            }
            Ok(())
        }
        _ => Err(X509RootAuthError::Invalid("X.509 signature scheme/key mismatch")),
    }
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
    if !matches!(
        sig_scheme,
        SIG_SCHEME_RSA_PKCS1_SHA256 | SIG_SCHEME_ECDSA_SHA256_DER | SIG_SCHEME_RSA_PSS_SHA256
    ) {
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
    let mut offset = AUTHENTICATOR_FIXED_LEN
        .checked_add(signature_capacity)
        .ok_or(X509RootAuthError::Invalid("X.509 authenticator length overflow"))?;
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
        let cert_end = offset
            .checked_add(cert_len)
            .ok_or(X509RootAuthError::Invalid("X.509 authenticator length overflow"))?;
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
    Ok(ParsedAuthenticator {
        sig_scheme,
        signed_at_unix_seconds,
        chain_digest: parsed_chain_digest,
        signature,
        chain_certificate_der,
    })
}

fn current_unix_seconds() -> Result<i64, X509RootAuthError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| X509RootAuthError::Invalid("system clock is before Unix epoch"))?;
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
        acc.checked_add(4)
            .and_then(|value| value.checked_add(cert_der.len()))
            .ok_or(X509RootAuthError::Invalid("X.509 authenticator length overflow"))
    })?;
    let total = AUTHENTICATOR_FIXED_LEN
        .checked_add(signature_capacity)
        .and_then(|value| value.checked_add(chain_len))
        .ok_or(X509RootAuthError::Invalid("X.509 authenticator length overflow"))?;
    u32_len(total, "authenticator value length")
}

/// Formats an X.509 distinguished name the way the pre-migration OpenSSL
/// code did: `short_name=value` entries joined by `", "`, in encoding order
/// (empirically identical to `X509NameRef::entries()`), with unknown OIDs
/// falling back to `OID` and non-string values hex-encoded. Beyond the string
/// types `x509-parser` decodes natively, BMPString (UTF-16BE) and
/// TeletexString (Latin-1, OpenSSL's `ASN1_STRING_to_UTF8` treatment) are
/// decoded manually so reports match the OpenSSL-formatted chain subjects.
fn x509_name_to_string(name: &X509Name<'_>) -> String {
    let mut parts = Vec::new();
    for attribute in name.iter_attributes() {
        let key = oid_short_name(attribute.attr_type().to_id_string().as_str()).unwrap_or("OID");
        let value = attribute_string_value(attribute).unwrap_or_else(|| encode_hex(attribute.as_slice()));
        parts.push(format!("{key}={value}"));
    }
    parts.join(", ")
}

fn attribute_string_value(attribute: &x509_parser::x509::AttributeTypeAndValue<'_>) -> Option<String> {
    if let Ok(value) = attribute.as_str() {
        return Some(value.to_owned());
    }
    let any = attribute.attr_value();
    match any.tag() {
        x509_parser::asn1_rs::Tag::BmpString => decode_bmp_string(any.data),
        x509_parser::asn1_rs::Tag::TeletexString => Some(String::from_utf8_lossy(any.data).into_owned()),
        _ => None,
    }
}

/// Decodes a BMPString (big-endian UTF-16 code units), skipping unpaired
/// surrogates the way OpenSSL's UTF-8 conversion does.
fn decode_bmp_string(bytes: &[u8]) -> Option<String> {
    let mut units = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        units.push(u16::from_be_bytes([pair[0], pair[1]]));
    }
    String::from_utf16(&units).ok()
}

/// OpenSSL NID short names for the common DN attribute OIDs.
fn oid_short_name(oid: &str) -> Option<&'static str> {
    Some(match oid {
        "2.5.4.3" => "CN",
        "2.5.4.4" => "SN",
        "2.5.4.5" => "serialNumber",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.9" => "STREET",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.12" => "title",
        "2.5.4.13" => "description",
        "2.5.4.15" => "businessCategory",
        "2.5.4.17" => "postalCode",
        "2.5.4.42" => "GN",
        "2.5.4.43" => "initials",
        "2.5.4.44" => "generationQualifier",
        "2.5.4.46" => "dnQualifier",
        "2.5.4.65" => "pseudonym",
        "2.5.4.97" => "organizationIdentifier",
        "0.9.2342.19200300.100.1.1" => "UID",
        "0.9.2342.19200300.100.1.25" => "DC",
        "1.2.840.113549.1.9.1" => "emailAddress",
        "1.2.840.113549.1.9.2" => "unstructuredName",
        "1.3.6.1.4.1.311.60.2.1.1" => "jurisdictionLocalityName",
        "1.3.6.1.4.1.311.60.2.1.2" => "jurisdictionStateOrProvinceName",
        "1.3.6.1.4.1.311.60.2.1.3" => "jurisdictionCountryName",
        _ => return None,
    })
}

/// True when a SEC1 ECPrivateKey's explicit [0] namedCurve equals the
/// expected curve OID (absent [0] means the key is used as parsed).
fn sec1_curve_matches(bytes: &[u8], expected_oid: &str) -> bool {
    // DER content bytes of the namedCurve OIDs (encoded once, avoids an OID
    // parser round-trip).
    let expected = match expected_oid {
        OID_EC_P256 => &P256_OID_CONTENT[..],
        OID_EC_P384 => &P384_OID_CONTENT[..],
        OID_EC_P521 => &P521_OID_CONTENT[..],
        _ => return false,
    };
    sec1_named_curve_oid(bytes).is_none_or(|oid| oid.as_slice() == expected)
}

const P256_OID_CONTENT: [u8; 8] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const P384_OID_CONTENT: [u8; 5] = [0x2b, 0x81, 0x04, 0x00, 0x22];
const P521_OID_CONTENT: [u8; 5] = [0x2b, 0x81, 0x04, 0x00, 0x23];

/// True when the input is an EC key whose curve was not among the allowed
/// set — the parser tried P-256/P-384/P-521 above, so anything EC-shaped
/// here is an unsupported curve (OpenSSL's `curve_name` check equivalent).
fn ec_key_with_unsupported_curve(bytes: &[u8]) -> bool {
    if let Ok(info) = pkcs8_010::PrivateKeyInfo::from_der(bytes) {
        if info.algorithm.oid == pkcs8_010::ObjectIdentifier::new_unwrap(OID_EC_PUBLIC_KEY) {
            let parameters_oid = info.algorithm.parameters_oid().ok().map(|oid| oid.to_string());
            return !matches!(parameters_oid.as_deref(), Some(OID_EC_P256) | Some(OID_EC_P384) | Some(OID_EC_P521));
        }
        return false;
    }
    sec1_named_curve_oid(bytes).is_some()
}

/// Extracts the [0] namedCurve OID from a SEC1 ECPrivateKey structure.
fn sec1_named_curve_oid(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.first() != Some(&0x30) {
        return None;
    }
    let (content_len, len_bytes) = der_length(&bytes[1..])?;
    let content = bytes.get(1 + len_bytes..1 + len_bytes + content_len)?;
    // INTEGER version
    if content.first() != Some(&0x02) {
        return None;
    }
    let (integer_len, integer_len_bytes) = der_length(&content[1..])?;
    let mut cursor = &content[1 + integer_len_bytes + integer_len..];
    // OCTET STRING scalar
    if cursor.first() != Some(&0x04) {
        return None;
    }
    let (scalar_len, scalar_len_bytes) = der_length(&cursor[1..])?;
    cursor = &cursor[1 + scalar_len_bytes + scalar_len..];
    // [0] EXPLICIT parameters
    if cursor.first() != Some(&0xA0) {
        return None;
    }
    let (params_len, params_len_bytes) = der_length(&cursor[1..])?;
    let params = cursor.get(1 + params_len_bytes..1 + params_len_bytes + params_len)?;
    if params.first() != Some(&0x06) {
        return None;
    }
    let (oid_len, oid_len_bytes) = der_length(&params[1..])?;
    Some(params.get(1 + oid_len_bytes..1 + oid_len_bytes + oid_len)?.to_vec())
}

fn der_length(bytes: &[u8]) -> Option<(usize, usize)> {
    let first = *bytes.first()?;
    if first < 0x80 {
        return Some((first as usize, 1));
    }
    let length_bytes = (first & 0x7f) as usize;
    if length_bytes == 0 || length_bytes > 4 || bytes.len() < 1 + length_bytes {
        return None;
    }
    let mut length = 0usize;
    for byte in &bytes[1..1 + length_bytes] {
        length = (length << 8) | usize::from(*byte);
    }
    Some((length, 1 + length_bytes))
}

fn looks_like_pem(bytes: &[u8]) -> bool {
    bytes.windows(b"-----BEGIN".len()).any(|window| window == b"-----BEGIN")
}

/// Decodes the first PEM block of the input to its DER payload.
fn pem_payload_der(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut rest = bytes;
    while let Some(start) = rest.windows(b"-----BEGIN".len()).position(|window| window == b"-----BEGIN") {
        let block = &rest[start..];
        let end = block.windows(b"-----END".len()).position(|window| window == b"-----END")?;
        // Skip the `-----BEGIN <label>-----` header line itself: only the
        // lines between it and the footer are base64 payload.
        let body_start = block[..end].iter().position(|byte| *byte == b'\n').map_or(0, |position| position + 1);
        let body = &block[body_start..end];
        let encoded: Vec<u8> = body.iter().copied().filter(|byte| !byte.is_ascii_whitespace()).collect();
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&encoded) {
            return Some(decoded);
        }
        rest = &block[end + b"-----END".len()..];
    }
    None
}

fn read_u16(value: &[u8], offset: usize) -> Result<u16, X509RootAuthError> {
    let bytes = value
        .get(offset..offset + 2)
        .ok_or(X509RootAuthError::Invalid("X.509 authenticator is truncated"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(value: &[u8], offset: usize) -> Result<u32, X509RootAuthError> {
    let bytes = value
        .get(offset..offset + 4)
        .ok_or(X509RootAuthError::Invalid("X.509 authenticator is truncated"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_i64(value: &[u8], offset: usize) -> Result<i64, X509RootAuthError> {
    let bytes = value
        .get(offset..offset + 8)
        .ok_or(X509RootAuthError::Invalid("X.509 authenticator is truncated"))?;
    Ok(i64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
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
    use openssl::bn::{BigNum, BigNumContext, MsbOption};
    use openssl::ec::{EcGroup, EcKey};
    use openssl::ecdsa::EcdsaSig;
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::{HasParams, PKey, PKeyRef, Private};
    use openssl::rsa::Rsa;
    use openssl::x509::extension::{BasicConstraints, KeyUsage};
    use openssl::x509::{X509NameBuilder, X509Ref, X509};
    use std::cmp::Ordering;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tzap_core::format::{FORMAT_VERSION, ROOT_AUTH_SPEC_ID, ROOT_AUTH_SPEC_ID_V45, VOLUME_FORMAT_REV, VOLUME_FORMAT_REV_45};

    /// Test-side adapter so the openssl-generated fixture keys feed the new
    /// RustCrypto `X509SigningKey` through the same DER path production
    /// PKCS#12 loading will use (differential coverage for free).
    impl From<PKey<Private>> for X509SigningKey {
        fn from(key: PKey<Private>) -> Self {
            X509SigningKey::from_der(&key.private_key_to_der().unwrap()).unwrap()
        }
    }

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
        let request = RootAuthSigningRequest {
            root_auth_spec_id: ROOT_AUTH_SPEC_ID,
            archive_uuid: [1; 16],
            session_id: [2; 16],
            archive_root: [3; 32],
        };
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
        RootAuthSigningRequest {
            root_auth_spec_id: ROOT_AUTH_SPEC_ID_V45,
            archive_uuid: [1; 16],
            session_id: [2; 16],
            archive_root: [3; 32],
        }
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

        assert_eq!(
            signature_error_message(&footer, &request.archive_root),
            "X.509 authenticator signature padding is non-zero"
        );
    }

    #[test]
    fn verify_root_auth_signature_rejects_trailing_bytes() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), now_unix_seconds()).unwrap();
        let request = default_signing_request();
        let mut footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);
        footer.authenticator_value.push(0x00);

        assert_eq!(
            signature_error_message(&footer, &request.archive_root),
            "X.509 authenticator has trailing bytes"
        );
    }

    #[test]
    fn verify_root_auth_signature_rejects_truncated_envelope() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), now_unix_seconds()).unwrap();
        let request = default_signing_request();
        let mut footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);
        footer.authenticator_value.truncate(footer.authenticator_value.len() - 1);

        assert_eq!(
            signature_error_message(&footer, &request.archive_root),
            "X.509 authenticator signature is truncated"
        );
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

        assert_eq!(
            signature_error_message(&footer, &request.archive_root),
            "X.509 authenticator chain digest mismatch"
        );
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
        assert_eq!(
            verify_error_message(&footer, &request.archive_root, &[root_cert.to_der().unwrap()]),
            "X.509 authenticator magic mismatch"
        );
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

        assert!(matches!(
            verify_root_auth_signature(&footer, &request.archive_root).unwrap_err(),
            X509RootAuthError::UnsupportedIdentity
        ));
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
        assert_eq!(
            signature_error_message(&footer, &request.archive_root),
            "unsupported RootAuthFooter root_auth_spec_id"
        );
    }

    #[test]
    fn verify_root_auth_signature_rejects_key_usage_not_allowing_signing() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert_with_usage(
            "Acme Key Encipherment Only",
            root_cert.as_ref(),
            root_key.as_ref(),
            LeafKeyUsage::KeyEnciphermentOnly,
        );
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), now_unix_seconds()).unwrap();
        let request = default_signing_request();
        let footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);

        assert_eq!(
            signature_error_message(&footer, &request.archive_root),
            "leaf certificate KeyUsage does not allow archive signing"
        );
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

        assert_eq!(
            signature_error_message(&footer, &request.archive_root),
            "unsupported X.509 authenticator version"
        );
    }

    #[test]
    fn verify_root_auth_signature_rejects_zero_signature_length() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), now_unix_seconds()).unwrap();
        let request = default_signing_request();
        let mut footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);
        footer.authenticator_value[48..52].copy_from_slice(&0u32.to_le_bytes());

        assert_eq!(
            signature_error_message(&footer, &request.archive_root),
            "X.509 signature length must be nonzero"
        );
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

        assert_eq!(
            signature_error_message(&footer, &request.archive_root),
            "X.509 signature length exceeds capacity"
        );
    }

    #[test]
    fn verify_root_auth_signature_rejects_impossible_chain_count() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), now_unix_seconds()).unwrap();
        let request = default_signing_request();
        let mut footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);
        footer.authenticator_value[56..60].copy_from_slice(&u32::MAX.to_le_bytes());

        assert_eq!(
            signature_error_message(&footer, &request.archive_root),
            "X.509 authenticator chain count exceeds payload"
        );
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
        let request = RootAuthSigningRequest {
            root_auth_spec_id: ROOT_AUTH_SPEC_ID,
            archive_uuid: [1; 16],
            session_id: [2; 16],
            archive_root: [3; 32],
        };
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
        assert_eq!(
            verify_error_message(&wrong_key_footer, &request.archive_root, &roots),
            "X.509 RootAuth signature failed"
        );

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
        assert_eq!(
            verify_error_message(&padded_footer, &request.archive_root, &roots),
            "X.509 authenticator signature padding is non-zero"
        );

        // Chain digest mismatch: mutate the parsed chain digest field.
        let mut digest_footer = footer.clone();
        digest_footer.authenticator_value[16] ^= 0x01;
        assert_eq!(
            verify_error_message(&digest_footer, &request.archive_root, &roots),
            "X.509 authenticator chain digest mismatch"
        );

        // Trailing bytes after the authenticator payload.
        let mut trailing_footer = footer.clone();
        trailing_footer.authenticator_value.push(0x00);
        assert_eq!(
            verify_error_message(&trailing_footer, &request.archive_root, &roots),
            "X.509 authenticator has trailing bytes"
        );
    }

    #[test]
    fn declared_scheme_must_match_key_material() {
        // §14.8: declaring an ECDSA scheme while the identity cert holds an RSA
        // key must be rejected as Invalid.
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), 1).unwrap();
        let request = RootAuthSigningRequest {
            root_auth_spec_id: ROOT_AUTH_SPEC_ID,
            archive_uuid: [1; 16],
            session_id: [2; 16],
            archive_root: [3; 32],
        };
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
        let request = RootAuthSigningRequest {
            root_auth_spec_id: ROOT_AUTH_SPEC_ID,
            archive_uuid: [1; 16],
            session_id: [2; 16],
            archive_root: [3; 32],
        };
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
        let request = RootAuthSigningRequest {
            root_auth_spec_id: ROOT_AUTH_SPEC_ID,
            archive_uuid: [1; 16],
            session_id: [2; 16],
            archive_root: [3; 32],
        };
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
        let request = RootAuthSigningRequest {
            root_auth_spec_id: ROOT_AUTH_SPEC_ID_V45,
            archive_uuid: [1; 16],
            session_id: [2; 16],
            archive_root: [3; 32],
        };
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
        let request = RootAuthSigningRequest {
            root_auth_spec_id: ROOT_AUTH_SPEC_ID_V45,
            archive_uuid: [1; 16],
            session_id: [2; 16],
            archive_root: [3; 32],
        };
        let footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);

        let err = verify_root_auth_footer(&footer, &request.archive_root, &[], false, false).unwrap_err();

        assert!(matches!(err, X509RootAuthError::MissingTrustPolicy));
    }

    #[test]
    fn zero_signature_length_is_invalid_before_missing_trust_policy() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), 1).unwrap();
        let request = RootAuthSigningRequest {
            root_auth_spec_id: ROOT_AUTH_SPEC_ID_V45,
            archive_uuid: [1; 16],
            session_id: [2; 16],
            archive_root: [3; 32],
        };
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
        let request = RootAuthSigningRequest {
            root_auth_spec_id: ROOT_AUTH_SPEC_ID_V45,
            archive_uuid: [1; 16],
            session_id: [2; 16],
            archive_root: [3; 32],
        };
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
        let request = RootAuthSigningRequest {
            root_auth_spec_id: ROOT_AUTH_SPEC_ID_V45,
            archive_uuid: [1; 16],
            session_id: [2; 16],
            archive_root: [3; 32],
        };
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
        let request = RootAuthSigningRequest {
            root_auth_spec_id: ROOT_AUTH_SPEC_ID,
            archive_uuid: [1; 16],
            session_id: [2; 16],
            archive_root: [3; 32],
        };
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
        let (leaf_cert, leaf_key) = test_leaf_cert_with_usage(
            "Acme Encipherment Only",
            root_cert.as_ref(),
            root_key.as_ref(),
            LeafKeyUsage::KeyEnciphermentOnly,
        );
        let signed_at = now_unix_seconds();
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), signed_at).unwrap();
        let request = RootAuthSigningRequest {
            root_auth_spec_id: ROOT_AUTH_SPEC_ID,
            archive_uuid: [1; 16],
            session_id: [2; 16],
            archive_root: [3; 32],
        };
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
            let request = RootAuthSigningRequest {
                root_auth_spec_id: ROOT_AUTH_SPEC_ID_V45,
                archive_uuid: [1; 16],
                session_id: [2; 16],
                archive_root: [3; 32],
            };
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
        let request = RootAuthSigningRequest {
            root_auth_spec_id: ROOT_AUTH_SPEC_ID_V45,
            archive_uuid: [1; 16],
            session_id: [2; 16],
            archive_root: [3; 32],
        };
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
        let request = RootAuthSigningRequest {
            root_auth_spec_id: ROOT_AUTH_SPEC_ID_V45,
            archive_uuid: [1; 16],
            session_id: [2; 16],
            archive_root: [3; 32],
        };
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
        let request = RootAuthSigningRequest {
            root_auth_spec_id: ROOT_AUTH_SPEC_ID_V45,
            archive_uuid: [1; 16],
            session_id: [2; 16],
            archive_root: [3; 32],
        };
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
        let request = RootAuthSigningRequest {
            root_auth_spec_id: ROOT_AUTH_SPEC_ID_V45,
            archive_uuid: [1; 16],
            session_id: [2; 16],
            archive_root: [3; 32],
        };
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
        let request = RootAuthSigningRequest {
            root_auth_spec_id: ROOT_AUTH_SPEC_ID_V45,
            archive_uuid: [1; 16],
            session_id: [2; 16],
            archive_root: [3; 32],
        };
        let mut footer = signed_footer_for_request(&signer, &leaf_cert, &request, VOLUME_FORMAT_REV_45);

        footer.authenticator_value[6..8].copy_from_slice(&SIG_SCHEME_RSA_PKCS1_SHA256.to_le_bytes());
        let err = verify_root_auth_footer(&footer, &request.archive_root, &[leaf_cert.to_der().unwrap()], false, false).unwrap_err();
        assert!(err.to_string().contains("requires unconstrained rsaEncryption"));

        footer.authenticator_value[6..8].copy_from_slice(&SIG_SCHEME_RSA_PSS_SHA256.to_le_bytes());
        footer.signer_identity_bytes = replace_nth_subsequence(
            &footer.signer_identity_bytes,
            &RSA_PSS_SHA256_SALT32_ALGORITHM,
            &RSA_PSS_SHA256_SALT20_ALGORITHM,
            1,
        )
        .unwrap();
        let err = verify_root_auth_footer(&footer, &request.archive_root, &[leaf_cert.to_der().unwrap()], false, false).unwrap_err();
        assert!(err.to_string().contains("saltLength=32"));
    }

    #[test]
    fn signer_rejects_nonstandard_rsa_pss_spki_parameters() {
        let (leaf_cert, leaf_key) = rsa_pss_leaf_cert_and_key();
        let nonstandard_leaf_der = replace_nth_subsequence(
            &leaf_cert.to_der().unwrap(),
            &RSA_PSS_SHA256_SALT32_ALGORITHM,
            &RSA_PSS_SHA256_SALT20_ALGORITHM,
            1,
        )
        .unwrap();

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
        let (_leaf_cert, leaf_key) = test_ec_leaf_cert("Acme Unsupported EC Signing", root_cert.as_ref(), root_key.as_ref(), Nid::SECP256K1);

        // The curve check moved from scheme detection into key parsing
        // (RustCrypto `X509SigningKey::from_der`): only P-256/P-384/P-521
        // keys can be constructed, so the signer can never hold a
        // secp256k1 key in the first place.
        let err = X509SigningKey::from_der(&leaf_key.private_key_to_der().unwrap()).unwrap_err();

        assert!(err.to_string().contains("unsupported X.509 ECDSA curve"));
    }

    #[test]
    fn v45_footer_uses_core_archive_root_and_rejects_wrong_spec_id() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signed_at = now_unix_seconds();
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), signed_at).unwrap();
        let request = RootAuthSigningRequest {
            root_auth_spec_id: ROOT_AUTH_SPEC_ID_V45,
            archive_uuid: [1; 16],
            session_id: [2; 16],
            archive_root: [3; 32],
        };
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
        let wrong_spec_request = RootAuthSigningRequest {
            root_auth_spec_id: revision_44_spec_id,
            ..request
        };
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
        let request = RootAuthSigningRequest {
            root_auth_spec_id: ROOT_AUTH_SPEC_ID,
            archive_uuid: [1; 16],
            session_id: [2; 16],
            archive_root: [3; 32],
        };
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
        let err = X509RootAuthSigner::new(
            leaf_cert.to_der().unwrap(),
            leaf_key,
            vec![b"not a DER certificate".to_vec()],
            now_unix_seconds(),
        )
        .unwrap_err();

        assert!(matches!(err, X509RootAuthError::Invalid(_)));
    }

    #[test]
    fn rejects_impossible_chain_count_without_large_allocation() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert("Acme Release Signing", root_cert.as_ref(), root_key.as_ref());
        let signed_at = now_unix_seconds();
        let signer = X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), signed_at).unwrap();
        let request = RootAuthSigningRequest {
            root_auth_spec_id: ROOT_AUTH_SPEC_ID,
            archive_uuid: [1; 16],
            session_id: [2; 16],
            archive_root: [3; 32],
        };
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
        // Test-side group-order helper: the production `ec_curve_order` moved
        // to RustCrypto scalar types; the openssl dev-dependency still
        // computes the order here to build the high-S mutation vector.
        let sig = EcdsaSig::from_der(signature).unwrap();
        let ec_key = public_key.ec_key().unwrap();
        let mut context = BigNumContext::new().unwrap();
        let mut order = BigNum::new().unwrap();
        ec_key.group().order(&mut order, &mut context).unwrap();
        let mut half_order = BigNum::new().unwrap();
        half_order.rshift1(&order).unwrap();
        let mut high_s = BigNum::new().unwrap();
        high_s.checked_sub(&order, sig.s()).unwrap();
        assert_eq!(high_s.ucmp(&half_order), Ordering::Greater);
        EcdsaSig::from_private_components(sig.r().to_owned().unwrap(), high_s)
            .unwrap()
            .to_der()
            .unwrap()
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
        builder
            .append_extension(KeyUsage::new().critical().key_cert_sign().crl_sign().build().unwrap())
            .unwrap();
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
        builder
            .append_extension(KeyUsage::new().critical().digital_signature().build().unwrap())
            .unwrap();
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
        builder
            .append_extension(KeyUsage::new().critical().digital_signature().build().unwrap())
            .unwrap();
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
