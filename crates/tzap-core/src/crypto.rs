use aes_gcm::Aes256Gcm;
use aes_gcm_siv::Aes256GcmSiv;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::XChaCha20Poly1305;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, ZeroizeOnDrop};

use aes_gcm_siv::aead::{Aead, KeyInit as AeadKeyInit, Payload};

use crate::format::{
    AeadAlgo, FormatError, KdfAlgo, MASTER_KEY_LEN, READER_MAX_ARGON2ID_M_COST_KIB,
    READER_MAX_ARGON2ID_PARALLELISM, READER_MAX_ARGON2ID_T_COST, READER_MAX_KEY_WRAP_TABLE_LEN,
    READER_MAX_KEY_WRAP_TABLE_RECIPIENT_RECORDS, SUBKEY_LEN,
};
use crate::padding::{depad_suffix_padding, suffix_pad_for_aead};

type HmacSha256 = Hmac<Sha256>;

const HKDF_SALT_DOMAIN: &[u8] = b"tzap-v1-subkeys";
const CRYPTO_HEADER_HMAC_DOMAIN: &[u8] = b"tzap-v1-crypto-header";
const MANIFEST_FOOTER_HMAC_DOMAIN: &[u8] = b"tzap-v1-manifest-footer";
const VOLUME_TRAILER_HMAC_DOMAIN: &[u8] = b"tzap-v1-volume-trailer";
const BOOTSTRAP_SIDECAR_HMAC_DOMAIN: &[u8] = b"tzap-v1-sidecar";
const CRYPTO_HEADER_DIGEST_DOMAIN_V45: &[u8] = b"tzap-header-v45";
const MANIFEST_FOOTER_DIGEST_DOMAIN_V45: &[u8] = b"tzap-manifest-v45";
const VOLUME_TRAILER_DIGEST_DOMAIN_V45: &[u8] = b"tzap-trailer-v45";
const BOOTSTRAP_SIDECAR_DIGEST_DOMAIN_V45: &[u8] = b"tzap-sidecar-v45";

const RAW_KDF_PARAMS_LEN: usize = 2;
const NONE_KDF_PARAMS_LEN: usize = 2;
const ARGON2ID_FIXED_PARAMS_LEN: usize = 16;
const RECIPIENT_WRAP_KDF_PARAMS_LEN: usize = 46;
const ARGON2ID_MIN_SALT_LEN: u16 = 8;
const ARGON2ID_MAX_SALT_LEN: u16 = 64;
const RECIPIENT_WRAP_TABLE_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KdfParams {
    None,
    Raw,
    Argon2id {
        t_cost: u32,
        m_cost_kib: u32,
        parallelism: u32,
        salt: Vec<u8>,
    },
    RecipientWrap {
        key_wrap_table_length: u32,
        key_wrap_table_record_count: u32,
        key_wrap_table_version: u16,
        key_wrap_table_digest: [u8; 32],
    },
}

impl KdfParams {
    pub fn parse(algo: KdfAlgo, bytes: &[u8]) -> Result<(Self, usize), FormatError> {
        match algo {
            KdfAlgo::Raw => parse_raw_kdf_params(bytes),
            KdfAlgo::Argon2id => parse_argon2id_kdf_params(bytes),
            KdfAlgo::None => parse_none_kdf_params(bytes),
            KdfAlgo::RecipientWrap => parse_recipient_wrap_kdf_params(bytes),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey(pub [u8; MASTER_KEY_LEN]);

impl MasterKey {
    pub fn from_raw_key(raw_key: &[u8]) -> Result<Self, FormatError> {
        if raw_key.len() != MASTER_KEY_LEN {
            return Err(FormatError::InvalidRawMasterKeyLength);
        }
        let mut key = [0u8; MASTER_KEY_LEN];
        key.copy_from_slice(raw_key);
        Ok(Self(key))
    }

    pub fn derive_from_passphrase(
        params: &KdfParams,
        passphrase: &str,
    ) -> Result<Self, FormatError> {
        let KdfParams::Argon2id {
            t_cost,
            m_cost_kib,
            parallelism,
            salt,
        } = params
        else {
            return Err(FormatError::KeyMaterialMismatch);
        };

        let salt_length = u16::try_from(salt.len()).map_err(|_| {
            FormatError::InvalidKdfParams("argon2id salt length must be 8..64 bytes")
        })?;
        validate_argon2id_bounds(*t_cost, *m_cost_kib, *parallelism, salt_length)?;
        let params = Params::new(*m_cost_kib, *t_cost, *parallelism, Some(MASTER_KEY_LEN))
            .map_err(|_| FormatError::InvalidKdfParams("argon2 params rejected"))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut output = [0u8; MASTER_KEY_LEN];
        let mut passphrase_bytes = normalize_passphrase_nfc(passphrase);
        let result = argon2.hash_password_into(&passphrase_bytes, salt, &mut output);
        passphrase_bytes.zeroize();
        result.map_err(|_| FormatError::Argon2idFailure)?;
        Ok(Self(output))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Subkeys {
    pub enc_key: [u8; SUBKEY_LEN],
    pub mac_key: [u8; SUBKEY_LEN],
    pub nonce_seed: [u8; SUBKEY_LEN],
    pub index_root_key: [u8; SUBKEY_LEN],
    pub index_shard_key: [u8; SUBKEY_LEN],
    pub dictionary_key: [u8; SUBKEY_LEN],
    pub dir_hint_key: [u8; SUBKEY_LEN],
    pub index_nonce_seed: [u8; SUBKEY_LEN],
}

impl Subkeys {
    pub(crate) fn unencrypted_placeholder() -> Self {
        Self {
            enc_key: [0; SUBKEY_LEN],
            mac_key: [0; SUBKEY_LEN],
            nonce_seed: [0; SUBKEY_LEN],
            index_root_key: [0; SUBKEY_LEN],
            index_shard_key: [0; SUBKEY_LEN],
            dictionary_key: [0; SUBKEY_LEN],
            dir_hint_key: [0; SUBKEY_LEN],
            index_nonce_seed: [0; SUBKEY_LEN],
        }
    }

    pub fn derive(
        master_key: &MasterKey,
        archive_uuid: &[u8; 16],
        session_id: &[u8; 16],
    ) -> Result<Self, FormatError> {
        let mut salt = Vec::with_capacity(HKDF_SALT_DOMAIN.len() + 32);
        salt.extend_from_slice(HKDF_SALT_DOMAIN);
        salt.extend_from_slice(archive_uuid);
        salt.extend_from_slice(session_id);
        let hk = Hkdf::<Sha256>::new(Some(&salt), &master_key.0);
        salt.zeroize();

        Ok(Self {
            enc_key: expand_subkey(&hk, b"tzap-v1-enc")?,
            mac_key: expand_subkey(&hk, b"tzap-v1-mac")?,
            nonce_seed: expand_subkey(&hk, b"tzap-v1-nonce")?,
            index_root_key: expand_subkey(&hk, b"tzap-v1-idxroot")?,
            index_shard_key: expand_subkey(&hk, b"tzap-v1-idxshard")?,
            dictionary_key: expand_subkey(&hk, b"tzap-v1-dict")?,
            dir_hint_key: expand_subkey(&hk, b"tzap-v1-dirhint")?,
            index_nonce_seed: expand_subkey(&hk, b"tzap-v1-idxnonce")?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HmacDomain {
    CryptoHeader,
    ManifestFooter,
    VolumeTrailer,
    BootstrapSidecar,
}

impl HmacDomain {
    pub fn structure_name(self) -> &'static str {
        match self {
            Self::CryptoHeader => "CryptoHeader",
            Self::ManifestFooter => "ManifestFooter",
            Self::VolumeTrailer => "VolumeTrailer",
            Self::BootstrapSidecar => "BootstrapSidecarHeader",
        }
    }

    fn domain_bytes(self) -> &'static [u8] {
        match self {
            Self::CryptoHeader => CRYPTO_HEADER_HMAC_DOMAIN,
            Self::ManifestFooter => MANIFEST_FOOTER_HMAC_DOMAIN,
            Self::VolumeTrailer => VOLUME_TRAILER_HMAC_DOMAIN,
            Self::BootstrapSidecar => BOOTSTRAP_SIDECAR_HMAC_DOMAIN,
        }
    }

    fn digest_domain_bytes(self) -> &'static [u8] {
        match self {
            Self::CryptoHeader => CRYPTO_HEADER_DIGEST_DOMAIN_V45,
            Self::ManifestFooter => MANIFEST_FOOTER_DIGEST_DOMAIN_V45,
            Self::VolumeTrailer => VOLUME_TRAILER_DIGEST_DOMAIN_V45,
            Self::BootstrapSidecar => BOOTSTRAP_SIDECAR_DIGEST_DOMAIN_V45,
        }
    }
}

pub fn compute_hmac(
    domain: HmacDomain,
    mac_key: &[u8; SUBKEY_LEN],
    archive_uuid: &[u8; 16],
    session_id: &[u8; 16],
    covered_bytes: &[u8],
) -> [u8; SUBKEY_LEN] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(mac_key).expect("HMAC accepts any key length");
    mac.update(domain.domain_bytes());
    mac.update(archive_uuid);
    mac.update(session_id);
    mac.update(covered_bytes);
    let digest = mac.finalize().into_bytes();
    let mut output = [0u8; SUBKEY_LEN];
    output.copy_from_slice(&digest);
    output
}

pub fn verify_hmac(
    domain: HmacDomain,
    mac_key: &[u8; SUBKEY_LEN],
    archive_uuid: &[u8; 16],
    session_id: &[u8; 16],
    covered_bytes: &[u8],
    expected_hmac: &[u8],
) -> Result<(), FormatError> {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(mac_key).expect("HMAC accepts any key length");
    mac.update(domain.domain_bytes());
    mac.update(archive_uuid);
    mac.update(session_id);
    mac.update(covered_bytes);
    mac.verify_slice(expected_hmac)
        .map_err(|_| FormatError::HmacMismatch {
            structure: domain.structure_name(),
        })
}

pub fn compute_integrity_tag(
    domain: HmacDomain,
    aead_algo: AeadAlgo,
    _volume_format_rev: u16,
    mac_key: Option<&[u8; SUBKEY_LEN]>,
    archive_uuid: &[u8; 16],
    session_id: &[u8; 16],
    covered_bytes: &[u8],
) -> Result<[u8; SUBKEY_LEN], FormatError> {
    if aead_algo.is_encrypted() {
        return Ok(compute_hmac(
            domain,
            mac_key.ok_or(FormatError::KeyMaterialMismatch)?,
            archive_uuid,
            session_id,
            covered_bytes,
        ));
    }

    let mut hasher = Sha256::new();
    hasher.update(domain.digest_domain_bytes());
    hasher.update(archive_uuid);
    hasher.update(session_id);
    hasher.update(covered_bytes);
    let digest = hasher.finalize();
    let mut output = [0u8; SUBKEY_LEN];
    output.copy_from_slice(&digest);
    Ok(output)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_integrity_tag(
    domain: HmacDomain,
    aead_algo: AeadAlgo,
    volume_format_rev: u16,
    mac_key: Option<&[u8; SUBKEY_LEN]>,
    archive_uuid: &[u8; 16],
    session_id: &[u8; 16],
    covered_bytes: &[u8],
    expected_tag: &[u8],
) -> Result<(), FormatError> {
    if aead_algo.is_encrypted() {
        return verify_hmac(
            domain,
            mac_key.ok_or(FormatError::KeyMaterialMismatch)?,
            archive_uuid,
            session_id,
            covered_bytes,
            expected_tag,
        );
    }

    let actual = compute_integrity_tag(
        domain,
        aead_algo,
        volume_format_rev,
        None,
        archive_uuid,
        session_id,
        covered_bytes,
    )?;
    if expected_tag == actual {
        Ok(())
    } else {
        Err(FormatError::IntegrityDigestMismatch {
            structure: domain.structure_name(),
        })
    }
}

pub fn normalize_passphrase_nfc(passphrase: &str) -> Vec<u8> {
    passphrase.nfc().collect::<String>().into_bytes()
}

pub fn derive_nonce(
    seed: &[u8; SUBKEY_LEN],
    domain: &[u8],
    archive_uuid: &[u8; 16],
    session_id: &[u8; 16],
    counter: u64,
    len: usize,
) -> Result<Vec<u8>, FormatError> {
    let info = nonce_or_aad_info(b"tzap-v1-nonce", domain, archive_uuid, session_id, counter)?;
    let hk = Hkdf::<Sha256>::from_prk(seed)
        .map_err(|_| FormatError::InvalidKdfParams("bad nonce seed"))?;
    let mut nonce = vec![0u8; len];
    hk.expand(&info, &mut nonce)
        .map_err(|_| FormatError::HkdfExpandFailure)?;
    Ok(nonce)
}

pub fn build_aad(
    domain: &[u8],
    archive_uuid: &[u8; 16],
    session_id: &[u8; 16],
    counter: u64,
) -> Result<Vec<u8>, FormatError> {
    nonce_or_aad_info(b"tzap-v1-aad", domain, archive_uuid, session_id, counter)
}

pub fn aead_encrypt(
    algo: AeadAlgo,
    key: &[u8; SUBKEY_LEN],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, FormatError> {
    validate_nonce_len(algo, nonce)?;
    match algo {
        AeadAlgo::None => Ok(plaintext.to_vec()),
        AeadAlgo::AesGcmSiv256 => {
            let cipher =
                Aes256GcmSiv::new_from_slice(key).map_err(|_| FormatError::InvalidAeadKeyLength)?;
            cipher
                .encrypt(
                    aes_gcm_siv::Nonce::from_slice(nonce),
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| FormatError::AeadFailure)
        }
        AeadAlgo::XChaCha20Poly1305 => {
            let cipher = XChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| FormatError::InvalidAeadKeyLength)?;
            cipher
                .encrypt(
                    chacha20poly1305::XNonce::from_slice(nonce),
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| FormatError::AeadFailure)
        }
        AeadAlgo::AesGcm256 => {
            let cipher =
                Aes256Gcm::new_from_slice(key).map_err(|_| FormatError::InvalidAeadKeyLength)?;
            cipher
                .encrypt(
                    aes_gcm::Nonce::from_slice(nonce),
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| FormatError::AeadFailure)
        }
    }
}

pub fn aead_decrypt(
    algo: AeadAlgo,
    key: &[u8; SUBKEY_LEN],
    nonce: &[u8],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>, FormatError> {
    validate_nonce_len(algo, nonce)?;
    match algo {
        AeadAlgo::None => Ok(ciphertext_and_tag.to_vec()),
        AeadAlgo::AesGcmSiv256 => {
            let cipher =
                Aes256GcmSiv::new_from_slice(key).map_err(|_| FormatError::InvalidAeadKeyLength)?;
            cipher
                .decrypt(
                    aes_gcm_siv::Nonce::from_slice(nonce),
                    Payload {
                        msg: ciphertext_and_tag,
                        aad,
                    },
                )
                .map_err(|_| FormatError::AeadFailure)
        }
        AeadAlgo::XChaCha20Poly1305 => {
            let cipher = XChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| FormatError::InvalidAeadKeyLength)?;
            cipher
                .decrypt(
                    chacha20poly1305::XNonce::from_slice(nonce),
                    Payload {
                        msg: ciphertext_and_tag,
                        aad,
                    },
                )
                .map_err(|_| FormatError::AeadFailure)
        }
        AeadAlgo::AesGcm256 => {
            let cipher =
                Aes256Gcm::new_from_slice(key).map_err(|_| FormatError::InvalidAeadKeyLength)?;
            cipher
                .decrypt(
                    aes_gcm::Nonce::from_slice(nonce),
                    Payload {
                        msg: ciphertext_and_tag,
                        aad,
                    },
                )
                .map_err(|_| FormatError::AeadFailure)
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AeadObjectContext<'a> {
    pub algo: AeadAlgo,
    pub key: &'a [u8; SUBKEY_LEN],
    pub nonce_seed: &'a [u8; SUBKEY_LEN],
    pub domain: &'a [u8],
    pub archive_uuid: &'a [u8; 16],
    pub session_id: &'a [u8; 16],
    pub counter: u64,
}

pub fn encrypt_padded_aead_object(
    context: AeadObjectContext<'_>,
    block_size: usize,
    payload: &[u8],
) -> Result<Vec<u8>, FormatError> {
    let nonce = derive_nonce(
        context.nonce_seed,
        context.domain,
        context.archive_uuid,
        context.session_id,
        context.counter,
        context.algo.nonce_len(),
    )?;
    let aad = build_aad(
        context.domain,
        context.archive_uuid,
        context.session_id,
        context.counter,
    )?;
    let padded = suffix_pad_for_aead(payload, context.algo.tag_len(), block_size)?;
    aead_encrypt(context.algo, context.key, &nonce, &aad, &padded)
}

pub fn decrypt_padded_aead_object(
    context: AeadObjectContext<'_>,
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>, FormatError> {
    let nonce = derive_nonce(
        context.nonce_seed,
        context.domain,
        context.archive_uuid,
        context.session_id,
        context.counter,
        context.algo.nonce_len(),
    )?;
    let aad = build_aad(
        context.domain,
        context.archive_uuid,
        context.session_id,
        context.counter,
    )?;
    let padded = aead_decrypt(context.algo, context.key, &nonce, &aad, ciphertext_and_tag)?;
    Ok(depad_suffix_padding(&padded)?.to_vec())
}

fn parse_raw_kdf_params(bytes: &[u8]) -> Result<(KdfParams, usize), FormatError> {
    if bytes.len() < RAW_KDF_PARAMS_LEN {
        return Err(FormatError::TruncatedKdfParams);
    }
    let algo_tag = read_u16(bytes, 0)?;
    if algo_tag != KdfAlgo::Raw as u16 {
        return Err(FormatError::KdfAlgoTagMismatch {
            expected: KdfAlgo::Raw as u16,
            actual: algo_tag,
        });
    }
    Ok((KdfParams::Raw, RAW_KDF_PARAMS_LEN))
}

fn parse_none_kdf_params(bytes: &[u8]) -> Result<(KdfParams, usize), FormatError> {
    if bytes.len() < NONE_KDF_PARAMS_LEN {
        return Err(FormatError::TruncatedKdfParams);
    }
    let algo_tag = read_u16(bytes, 0)?;
    if algo_tag != KdfAlgo::None as u16 {
        return Err(FormatError::KdfAlgoTagMismatch {
            expected: KdfAlgo::None as u16,
            actual: algo_tag,
        });
    }
    Ok((KdfParams::None, NONE_KDF_PARAMS_LEN))
}

fn parse_argon2id_kdf_params(bytes: &[u8]) -> Result<(KdfParams, usize), FormatError> {
    if bytes.len() < ARGON2ID_FIXED_PARAMS_LEN {
        return Err(FormatError::TruncatedKdfParams);
    }
    let algo_tag = read_u16(bytes, 0)?;
    if algo_tag != KdfAlgo::Argon2id as u16 {
        return Err(FormatError::KdfAlgoTagMismatch {
            expected: KdfAlgo::Argon2id as u16,
            actual: algo_tag,
        });
    }
    let t_cost = read_u32(bytes, 2)?;
    let m_cost_kib = read_u32(bytes, 6)?;
    let parallelism = read_u32(bytes, 10)?;
    let salt_length = read_u16(bytes, 14)?;
    if !(ARGON2ID_MIN_SALT_LEN..=ARGON2ID_MAX_SALT_LEN).contains(&salt_length) {
        return Err(FormatError::InvalidKdfParams(
            "argon2id salt length must be 8..64 bytes",
        ));
    }
    if t_cost == 0 {
        return Err(FormatError::InvalidKdfParams(
            "argon2id t_cost must be non-zero",
        ));
    }
    if parallelism == 0 {
        return Err(FormatError::InvalidKdfParams(
            "argon2id parallelism must be non-zero",
        ));
    }
    validate_argon2id_bounds(t_cost, m_cost_kib, parallelism, salt_length)?;

    let total_len = ARGON2ID_FIXED_PARAMS_LEN + salt_length as usize;
    if bytes.len() < total_len {
        return Err(FormatError::TruncatedKdfParams);
    }
    Ok((
        KdfParams::Argon2id {
            t_cost,
            m_cost_kib,
            parallelism,
            salt: bytes[ARGON2ID_FIXED_PARAMS_LEN..total_len].to_vec(),
        },
        total_len,
    ))
}

fn parse_recipient_wrap_kdf_params(bytes: &[u8]) -> Result<(KdfParams, usize), FormatError> {
    if bytes.len() < RECIPIENT_WRAP_KDF_PARAMS_LEN {
        return Err(FormatError::TruncatedKdfParams);
    }
    let algo_tag = read_u16(bytes, 0)?;
    if algo_tag != KdfAlgo::RecipientWrap as u16 {
        return Err(FormatError::KdfAlgoTagMismatch {
            expected: KdfAlgo::RecipientWrap as u16,
            actual: algo_tag,
        });
    }
    let key_wrap_table_length = read_u32(bytes, 2)?;
    let key_wrap_table_record_count = read_u32(bytes, 6)?;
    let table_version = read_u16(bytes, 10)?;
    if key_wrap_table_length == 0 {
        return Err(FormatError::InvalidKdfParams(
            "recipient-wrap key_wrap_table_length must be non-zero",
        ));
    }
    if key_wrap_table_length > READER_MAX_KEY_WRAP_TABLE_LEN {
        return Err(FormatError::ReaderResourceLimitExceeded {
            field: "KeyWrapTableV1 length",
            cap: READER_MAX_KEY_WRAP_TABLE_LEN as u64,
            actual: key_wrap_table_length as u64,
        });
    }
    if key_wrap_table_record_count > READER_MAX_KEY_WRAP_TABLE_RECIPIENT_RECORDS {
        return Err(FormatError::ReaderResourceLimitExceeded {
            field: "KeyWrapTableV1 recipient_record_count",
            cap: READER_MAX_KEY_WRAP_TABLE_RECIPIENT_RECORDS as u64,
            actual: key_wrap_table_record_count as u64,
        });
    }
    if table_version != RECIPIENT_WRAP_TABLE_VERSION {
        return Err(FormatError::InvalidKdfParams(
            "recipient-wrap table version must be 1",
        ));
    }
    let reserved = read_u16(bytes, 12)?;
    if reserved != 0 {
        return Err(FormatError::InvalidKdfParams(
            "recipient-wrap reserved bytes must be zero",
        ));
    }
    let mut key_wrap_table_digest = [0u8; 32];
    key_wrap_table_digest.copy_from_slice(&bytes[14..RECIPIENT_WRAP_KDF_PARAMS_LEN]);
    Ok((
        KdfParams::RecipientWrap {
            key_wrap_table_length,
            key_wrap_table_record_count,
            key_wrap_table_version: table_version,
            key_wrap_table_digest,
        },
        RECIPIENT_WRAP_KDF_PARAMS_LEN,
    ))
}

fn validate_argon2id_bounds(
    t_cost: u32,
    m_cost_kib: u32,
    parallelism: u32,
    salt_length: u16,
) -> Result<(), FormatError> {
    if !(ARGON2ID_MIN_SALT_LEN..=ARGON2ID_MAX_SALT_LEN).contains(&salt_length) {
        return Err(FormatError::InvalidKdfParams(
            "argon2id salt length must be 8..64 bytes",
        ));
    }
    if t_cost == 0 {
        return Err(FormatError::InvalidKdfParams(
            "argon2id t_cost must be non-zero",
        ));
    }
    if t_cost > READER_MAX_ARGON2ID_T_COST {
        return Err(FormatError::ReaderResourceLimitExceeded {
            field: "argon2id t_cost",
            cap: READER_MAX_ARGON2ID_T_COST as u64,
            actual: t_cost as u64,
        });
    }
    if parallelism == 0 {
        return Err(FormatError::InvalidKdfParams(
            "argon2id parallelism must be non-zero",
        ));
    }
    if parallelism > READER_MAX_ARGON2ID_PARALLELISM {
        return Err(FormatError::ReaderResourceLimitExceeded {
            field: "argon2id parallelism",
            cap: READER_MAX_ARGON2ID_PARALLELISM as u64,
            actual: parallelism as u64,
        });
    }
    if m_cost_kib > READER_MAX_ARGON2ID_M_COST_KIB {
        return Err(FormatError::ReaderResourceLimitExceeded {
            field: "argon2id m_cost_kib",
            cap: READER_MAX_ARGON2ID_M_COST_KIB as u64,
            actual: m_cost_kib as u64,
        });
    }
    let min_memory = parallelism
        .checked_mul(8)
        .ok_or(FormatError::InvalidKdfParams(
            "argon2id memory requirement overflow",
        ))?;
    if m_cost_kib < min_memory {
        return Err(FormatError::InvalidKdfParams(
            "argon2id memory must be at least 8 KiB per lane",
        ));
    }
    Ok(())
}

fn expand_subkey(hk: &Hkdf<Sha256>, info: &[u8]) -> Result<[u8; SUBKEY_LEN], FormatError> {
    let mut output = [0u8; SUBKEY_LEN];
    hk.expand(info, &mut output)
        .map_err(|_| FormatError::HkdfExpandFailure)?;
    Ok(output)
}

fn nonce_or_aad_info(
    prefix: &[u8],
    domain: &[u8],
    archive_uuid: &[u8; 16],
    session_id: &[u8; 16],
    counter: u64,
) -> Result<Vec<u8>, FormatError> {
    let domain_len = u16::try_from(domain.len()).map_err(|_| FormatError::DomainTooLong)?;
    let mut info = Vec::with_capacity(prefix.len() + 2 + domain.len() + 16 + 16 + 8);
    info.extend_from_slice(prefix);
    info.extend_from_slice(&domain_len.to_le_bytes());
    info.extend_from_slice(domain);
    info.extend_from_slice(archive_uuid);
    info.extend_from_slice(session_id);
    info.extend_from_slice(&counter.to_le_bytes());
    Ok(info)
}

fn validate_nonce_len(algo: AeadAlgo, nonce: &[u8]) -> Result<(), FormatError> {
    let expected = algo.nonce_len();
    if nonce.len() != expected {
        return Err(FormatError::InvalidNonceLength {
            algo,
            expected,
            actual: nonce.len(),
        });
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, FormatError> {
    let array: [u8; 2] = bytes
        .get(offset..offset + 2)
        .ok_or(FormatError::InvalidLength {
            structure: "u16",
            expected: offset + 2,
            actual: bytes.len(),
        })?
        .try_into()
        .expect("slice length checked");
    Ok(u16::from_le_bytes(array))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, FormatError> {
    let array: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or(FormatError::InvalidLength {
            structure: "u32",
            expected: offset + 4,
            actual: bytes.len(),
        })?
        .try_into()
        .expect("slice length checked");
    Ok(u32::from_le_bytes(array))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::VOLUME_FORMAT_REV_45;

    fn uuid() -> [u8; 16] {
        [0x11; 16]
    }

    fn session() -> [u8; 16] {
        [0x22; 16]
    }

    fn legacy_nonce_info(
        domain: &[u8],
        archive_uuid: &[u8; 16],
        session_id: &[u8; 16],
        counter: u64,
    ) -> Vec<u8> {
        let mut info = Vec::with_capacity(b"tzap-v1-nonce".len() + domain.len() + 16 + 16 + 8);
        info.extend_from_slice(b"tzap-v1-nonce");
        info.extend_from_slice(domain);
        info.extend_from_slice(archive_uuid);
        info.extend_from_slice(session_id);
        info.extend_from_slice(&counter.to_le_bytes());
        info
    }

    #[test]
    fn parses_raw_kdf_params() {
        let (params, consumed) = KdfParams::parse(KdfAlgo::Raw, &0u16.to_le_bytes()).unwrap();
        assert_eq!(params, KdfParams::Raw);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn parses_none_kdf_params() {
        let (params, consumed) =
            KdfParams::parse(KdfAlgo::None, &(KdfAlgo::None as u16).to_le_bytes()).unwrap();
        assert_eq!(params, KdfParams::None);
        assert_eq!(consumed, 2);

        assert_eq!(
            KdfParams::parse(KdfAlgo::None, &(KdfAlgo::Raw as u16).to_le_bytes()).unwrap_err(),
            FormatError::KdfAlgoTagMismatch {
                expected: KdfAlgo::None as u16,
                actual: KdfAlgo::Raw as u16,
            }
        );
    }

    #[test]
    fn parses_argon2id_kdf_params() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(KdfAlgo::Argon2id as u16).to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&8u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&8u16.to_le_bytes());
        bytes.extend_from_slice(b"12345678");

        let (params, consumed) = KdfParams::parse(KdfAlgo::Argon2id, &bytes).unwrap();
        assert_eq!(consumed, 24);
        assert_eq!(
            params,
            KdfParams::Argon2id {
                t_cost: 1,
                m_cost_kib: 8,
                parallelism: 1,
                salt: b"12345678".to_vec()
            }
        );
    }

    #[test]
    fn parses_recipient_wrap_kdf_params() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(KdfAlgo::RecipientWrap as u16).to_le_bytes());
        bytes.extend_from_slice(&16u32.to_le_bytes());
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&[0xaau8; 32]);

        let (params, consumed) = KdfParams::parse(KdfAlgo::RecipientWrap, &bytes).unwrap();
        assert_eq!(consumed, 46);
        assert_eq!(
            params,
            KdfParams::RecipientWrap {
                key_wrap_table_length: 16,
                key_wrap_table_record_count: 4,
                key_wrap_table_version: 1,
                key_wrap_table_digest: [0xaau8; 32]
            }
        );
    }

    #[test]
    fn rejects_invalid_recipient_wrap_kdf_params_fields() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(KdfAlgo::RecipientWrap as u16).to_le_bytes());
        bytes.extend_from_slice(&16u32.to_le_bytes());
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(&2u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&[0xaau8; 32]);
        assert_eq!(
            KdfParams::parse(KdfAlgo::RecipientWrap, &bytes).unwrap_err(),
            FormatError::InvalidKdfParams("recipient-wrap table version must be 1")
        );

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(KdfAlgo::RecipientWrap as u16).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 32]);
        assert_eq!(
            KdfParams::parse(KdfAlgo::RecipientWrap, &bytes).unwrap_err(),
            FormatError::InvalidKdfParams("recipient-wrap key_wrap_table_length must be non-zero"),
        );

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(KdfAlgo::RecipientWrap as u16).to_le_bytes());
        bytes.extend_from_slice(&(READER_MAX_KEY_WRAP_TABLE_LEN + 1).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 32]);
        assert_eq!(
            KdfParams::parse(KdfAlgo::RecipientWrap, &bytes).unwrap_err(),
            FormatError::ReaderResourceLimitExceeded {
                field: "KeyWrapTableV1 length",
                cap: READER_MAX_KEY_WRAP_TABLE_LEN as u64,
                actual: (READER_MAX_KEY_WRAP_TABLE_LEN + 1) as u64,
            },
        );

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(KdfAlgo::RecipientWrap as u16).to_le_bytes());
        bytes.extend_from_slice(&16u32.to_le_bytes());
        bytes.extend_from_slice(&(READER_MAX_KEY_WRAP_TABLE_RECIPIENT_RECORDS + 1).to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 32]);
        assert_eq!(
            KdfParams::parse(KdfAlgo::RecipientWrap, &bytes).unwrap_err(),
            FormatError::ReaderResourceLimitExceeded {
                field: "KeyWrapTableV1 recipient_record_count",
                cap: READER_MAX_KEY_WRAP_TABLE_RECIPIENT_RECORDS as u64,
                actual: (READER_MAX_KEY_WRAP_TABLE_RECIPIENT_RECORDS + 1) as u64,
            },
        );
    }

    #[test]
    fn rejects_argon2id_params_above_reader_caps() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(KdfAlgo::Argon2id as u16).to_le_bytes());
        bytes.extend_from_slice(&(READER_MAX_ARGON2ID_T_COST + 1).to_le_bytes());
        bytes.extend_from_slice(&8u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&8u16.to_le_bytes());
        bytes.extend_from_slice(b"12345678");

        assert_eq!(
            KdfParams::parse(KdfAlgo::Argon2id, &bytes).unwrap_err(),
            FormatError::ReaderResourceLimitExceeded {
                field: "argon2id t_cost",
                cap: READER_MAX_ARGON2ID_T_COST as u64,
                actual: (READER_MAX_ARGON2ID_T_COST + 1) as u64,
            }
        );

        let err = MasterKey::derive_from_passphrase(
            &KdfParams::Argon2id {
                t_cost: 1,
                m_cost_kib: READER_MAX_ARGON2ID_M_COST_KIB + 1,
                parallelism: 1,
                salt: b"12345678".to_vec(),
            },
            "passphrase",
        )
        .unwrap_err();
        assert_eq!(
            err,
            FormatError::ReaderResourceLimitExceeded {
                field: "argon2id m_cost_kib",
                cap: READER_MAX_ARGON2ID_M_COST_KIB as u64,
                actual: (READER_MAX_ARGON2ID_M_COST_KIB + 1) as u64,
            }
        );
    }

    #[test]
    fn rejects_argon2id_salt_bounds_and_raw_kdf_truncation() {
        fn argon_bytes(salt_len: u16, actual_salt: &[u8]) -> Vec<u8> {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&(KdfAlgo::Argon2id as u16).to_le_bytes());
            bytes.extend_from_slice(&1u32.to_le_bytes());
            bytes.extend_from_slice(&8u32.to_le_bytes());
            bytes.extend_from_slice(&1u32.to_le_bytes());
            bytes.extend_from_slice(&salt_len.to_le_bytes());
            bytes.extend_from_slice(actual_salt);
            bytes
        }

        assert_eq!(
            KdfParams::parse(KdfAlgo::Raw, &[]).unwrap_err(),
            FormatError::TruncatedKdfParams
        );
        assert_eq!(
            KdfParams::parse(KdfAlgo::Argon2id, &argon_bytes(7, b"1234567")).unwrap_err(),
            FormatError::InvalidKdfParams("argon2id salt length must be 8..64 bytes")
        );
        assert!(matches!(
            KdfParams::parse(KdfAlgo::Argon2id, &argon_bytes(8, b"12345678")).unwrap(),
            (KdfParams::Argon2id { .. }, 24)
        ));
        assert!(matches!(
            KdfParams::parse(KdfAlgo::Argon2id, &argon_bytes(64, &[0x5a; 64])).unwrap(),
            (KdfParams::Argon2id { .. }, 80)
        ));
        assert_eq!(
            KdfParams::parse(KdfAlgo::Argon2id, &argon_bytes(65, &[0x5a; 65])).unwrap_err(),
            FormatError::InvalidKdfParams("argon2id salt length must be 8..64 bytes")
        );
        assert_eq!(
            KdfParams::parse(KdfAlgo::Argon2id, &argon_bytes(64, &[0x5a; 63])).unwrap_err(),
            FormatError::TruncatedKdfParams
        );
    }

    #[test]
    fn rejects_kdf_algo_tag_mismatch() {
        assert_eq!(
            KdfParams::parse(KdfAlgo::Raw, &(KdfAlgo::Argon2id as u16).to_le_bytes()).unwrap_err(),
            FormatError::KdfAlgoTagMismatch {
                expected: 0,
                actual: 1
            }
        );
    }

    #[test]
    fn passphrase_normalization_preserves_archive_semantics() {
        assert_eq!(normalize_passphrase_nfc("e\u{301}\n\0"), "é\n\0".as_bytes());
    }

    #[test]
    fn argon2id_passphrase_edge_vectors_are_literal() {
        let params = KdfParams::Argon2id {
            t_cost: 1,
            m_cost_kib: 8,
            parallelism: 1,
            salt: b"12345678".to_vec(),
        };
        let cases = [
            (
                "trailing newline",
                "pass\n",
                "f63027356e6da90a4f6c81af70b9e6f1b1967ab684ecda8257cb7d21de760623",
            ),
            (
                "embedded nul",
                "pass\0word",
                "23db596ddbaa8f3f36d653f456dd9819e342aad4e30224008a22f1fb7648780e",
            ),
            (
                "leading bom",
                "\u{feff}pass",
                "d493645da269dce9b0ab6d39367d94c1896b0f4a2c3ca486c775d7275b8558da",
            ),
        ];

        for (name, passphrase, expected_hex) in cases {
            let master = MasterKey::derive_from_passphrase(&params, passphrase).unwrap();
            assert_eq!(hex::encode(master.0), expected_hex, "{name}");
        }

        let without_newline = MasterKey::derive_from_passphrase(&params, "pass").unwrap();
        let with_newline = MasterKey::derive_from_passphrase(&params, "pass\n").unwrap();
        assert_ne!(without_newline, with_newline);
    }

    #[test]
    fn argon2id_profile_rejects_alternate_version_vector() {
        let params = KdfParams::Argon2id {
            t_cost: 1,
            m_cost_kib: 8,
            parallelism: 1,
            salt: b"12345678".to_vec(),
        };
        let current = MasterKey::derive_from_passphrase(&params, "e\u{301}").unwrap();

        let argon_params = Params::new(8, 1, 1, Some(MASTER_KEY_LEN)).unwrap();
        let old_argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x10, argon_params);
        let mut old_output = [0u8; MASTER_KEY_LEN];
        let passphrase = normalize_passphrase_nfc("e\u{301}");
        old_argon2
            .hash_password_into(&passphrase, b"12345678", &mut old_output)
            .unwrap();

        assert_eq!(
            hex::encode(current.0),
            "24709642204c04bf88fb36550c478769eb10a0400c0493c9695d30fbf7082241"
        );
        assert_ne!(old_output, current.0);
    }

    #[test]
    fn derives_argon2id_master_key_from_nfc_passphrase() {
        let params = KdfParams::Argon2id {
            t_cost: 1,
            m_cost_kib: 8,
            parallelism: 1,
            salt: b"12345678".to_vec(),
        };
        let one = MasterKey::derive_from_passphrase(&params, "e\u{301}").unwrap();
        let two = MasterKey::derive_from_passphrase(&params, "é").unwrap();
        assert_eq!(one.0, two.0);
        assert_ne!(one.0, [0u8; MASTER_KEY_LEN]);
    }

    #[test]
    fn derives_stable_distinct_subkeys() {
        let master = MasterKey::from_raw_key(&[0x33; MASTER_KEY_LEN]).unwrap();
        let subkeys = Subkeys::derive(&master, &uuid(), &session()).unwrap();
        assert_ne!(subkeys.enc_key, subkeys.mac_key);
        assert_ne!(subkeys.index_root_key, subkeys.index_shard_key);

        let repeat = Subkeys::derive(&master, &uuid(), &session()).unwrap();
        assert_eq!(subkeys, repeat);
    }

    #[test]
    fn hkdf_passphrase_and_identity_vectors_are_literal() {
        let params = KdfParams::Argon2id {
            t_cost: 1,
            m_cost_kib: 8,
            parallelism: 1,
            salt: b"saltsalt".to_vec(),
        };
        let archive_uuid = core::array::from_fn::<_, 16, _>(|idx| 0x30 + idx as u8);
        let session_id = core::array::from_fn::<_, 16, _>(|idx| 0xc0 + idx as u8);
        let master = MasterKey::derive_from_passphrase(&params, "correct horse\n").unwrap();
        let subkeys = Subkeys::derive(&master, &archive_uuid, &session_id).unwrap();

        assert_eq!(
            hex::encode(master.0),
            "c58d65c836c8a590c0d34fcc0907d876e969d72c51a267cad2518cfee8eb2a21"
        );
        assert_eq!(
            hex::encode(subkeys.enc_key),
            "786001f513f99062c7c7ef72c978847a7c2daa452f363177839ce2ed3ecfd5df"
        );
        assert_eq!(
            hex::encode(subkeys.mac_key),
            "024f2737f6db8aa03d3ce241d25c26fcc18bbcf4af242614c3d703224cd82b74"
        );
        assert_eq!(
            hex::encode(subkeys.index_nonce_seed),
            "5d51a19bf7f6d77ce7945517ce95837a089f8d1cd20aea43cbcb8d745c0668ee"
        );

        let different_session = Subkeys::derive(&master, &archive_uuid, &[0xc1; 16]).unwrap();
        let different_archive = Subkeys::derive(&master, &[0x31; 16], &session_id).unwrap();
        assert_ne!(subkeys.enc_key, different_session.enc_key);
        assert_ne!(subkeys.enc_key, different_archive.enc_key);
    }

    #[test]
    fn computes_and_verifies_hmac_domains() {
        let key = [0x44; SUBKEY_LEN];
        let covered = b"covered bytes";
        let tag = compute_hmac(HmacDomain::CryptoHeader, &key, &uuid(), &session(), covered);
        verify_hmac(
            HmacDomain::CryptoHeader,
            &key,
            &uuid(),
            &session(),
            covered,
            &tag,
        )
        .unwrap();

        assert_eq!(
            verify_hmac(
                HmacDomain::ManifestFooter,
                &key,
                &uuid(),
                &session(),
                covered,
                &tag,
            )
            .unwrap_err(),
            FormatError::HmacMismatch {
                structure: "ManifestFooter"
            }
        );
    }

    #[test]
    fn computes_and_verifies_unkeyed_integrity_domains() {
        let covered = b"covered bytes";
        let tag_v45 = compute_integrity_tag(
            HmacDomain::CryptoHeader,
            AeadAlgo::None,
            VOLUME_FORMAT_REV_45,
            None,
            &uuid(),
            &session(),
            covered,
        )
        .unwrap();

        verify_integrity_tag(
            HmacDomain::CryptoHeader,
            AeadAlgo::None,
            VOLUME_FORMAT_REV_45,
            None,
            &uuid(),
            &session(),
            covered,
            &tag_v45,
        )
        .unwrap();

        assert_eq!(
            verify_integrity_tag(
                HmacDomain::ManifestFooter,
                AeadAlgo::None,
                VOLUME_FORMAT_REV_45,
                None,
                &uuid(),
                &session(),
                covered,
                &tag_v45,
            )
            .unwrap_err(),
            FormatError::IntegrityDigestMismatch {
                structure: "ManifestFooter"
            }
        );

        let manifest_tag_v45 = compute_integrity_tag(
            HmacDomain::ManifestFooter,
            AeadAlgo::None,
            VOLUME_FORMAT_REV_45,
            None,
            &uuid(),
            &session(),
            covered,
        )
        .unwrap();
        assert_eq!(
            verify_integrity_tag(
                HmacDomain::ManifestFooter,
                AeadAlgo::None,
                VOLUME_FORMAT_REV_45,
                None,
                &uuid(),
                &session(),
                covered,
                &manifest_tag_v45,
            )
            .unwrap(),
            ()
        );
        assert_ne!(
            tag_v45,
            compute_integrity_tag(
                HmacDomain::ManifestFooter,
                AeadAlgo::None,
                VOLUME_FORMAT_REV_45,
                None,
                &uuid(),
                &session(),
                covered,
            )
            .unwrap()
        );
    }

    #[test]
    fn hmac_sidecar_domain_vector_and_boundary_bytes_are_literal() {
        let key = [0x44; SUBKEY_LEN];
        let covered = b"covered bytes";
        let tag = compute_hmac(
            HmacDomain::BootstrapSidecar,
            &key,
            &uuid(),
            &session(),
            covered,
        );
        assert_eq!(
            hex::encode(tag),
            "1ecc9e0c5c9079b6824e16c4468ac9df22ca50fa2a924d21a91aab33c3721d51"
        );
        verify_hmac(
            HmacDomain::BootstrapSidecar,
            &key,
            &uuid(),
            &session(),
            covered,
            &tag,
        )
        .unwrap();

        for mutate_index in [0, covered.len() - 1] {
            let mut mutated = covered.to_vec();
            mutated[mutate_index] ^= 0x01;
            assert_eq!(
                verify_hmac(
                    HmacDomain::BootstrapSidecar,
                    &key,
                    &uuid(),
                    &session(),
                    &mutated,
                    &tag,
                )
                .unwrap_err(),
                FormatError::HmacMismatch {
                    structure: "BootstrapSidecarHeader"
                }
            );
        }

        for mutate_index in [0, tag.len() - 1] {
            let mut mutated_tag = tag;
            mutated_tag[mutate_index] ^= 0x01;
            assert_eq!(
                verify_hmac(
                    HmacDomain::BootstrapSidecar,
                    &key,
                    &uuid(),
                    &session(),
                    covered,
                    &mutated_tag,
                )
                .unwrap_err(),
                FormatError::HmacMismatch {
                    structure: "BootstrapSidecarHeader"
                }
            );
        }
    }

    #[test]
    fn derives_nonce_and_aad_with_domain_separation() {
        let seed = [0x55; SUBKEY_LEN];
        let nonce = derive_nonce(&seed, b"envelope", &uuid(), &session(), 7, 12).unwrap();
        let other = derive_nonce(&seed, b"idxroot", &uuid(), &session(), 7, 12).unwrap();
        assert_eq!(nonce.len(), 12);
        assert_ne!(nonce, other);

        let aad = build_aad(b"envelope", &uuid(), &session(), 7).unwrap();
        assert!(aad.starts_with(b"tzap-v1-aad"));
        assert_ne!(aad, nonce);
    }

    #[test]
    fn rejects_old_nonce_info_without_domain_length() {
        let key = [0x66; SUBKEY_LEN];
        let nonce_seed = [0x77; SUBKEY_LEN];
        let uuid = uuid();
        let session = session();
        let counter = 7u64;
        let domain = b"idxroot";

        let ciphertext = encrypt_padded_aead_object(
            AeadObjectContext {
                algo: AeadAlgo::AesGcmSiv256,
                key: &key,
                nonce_seed: &nonce_seed,
                domain,
                archive_uuid: &uuid,
                session_id: &session,
                counter,
            },
            4096,
            b"index-root",
        )
        .unwrap();
        let mut legacy_nonce = vec![0u8; AeadAlgo::AesGcmSiv256.nonce_len()];
        Hkdf::<Sha256>::from_prk(&nonce_seed)
            .unwrap()
            .expand(
                &legacy_nonce_info(domain, &uuid, &session, counter),
                &mut legacy_nonce,
            )
            .unwrap();
        let aad = build_aad(domain, &uuid, &session, counter).unwrap();

        assert_ne!(
            legacy_nonce,
            derive_nonce(
                &nonce_seed,
                domain,
                &uuid,
                &session,
                counter,
                AeadAlgo::AesGcmSiv256.nonce_len()
            )
            .unwrap(),
            "legacy nonce info encoding must differ from current encoding"
        );

        assert_eq!(
            aead_decrypt(
                AeadAlgo::AesGcmSiv256,
                &key,
                &legacy_nonce,
                &aad,
                &ciphertext,
            )
            .unwrap_err(),
            FormatError::AeadFailure
        );
    }

    #[test]
    fn aead_round_trips_all_registered_algorithms() {
        for algo in [
            AeadAlgo::AesGcmSiv256,
            AeadAlgo::XChaCha20Poly1305,
            AeadAlgo::AesGcm256,
        ] {
            let key = [0x66; SUBKEY_LEN];
            let nonce = derive_nonce(
                &[0x77; SUBKEY_LEN],
                b"envelope",
                &uuid(),
                &session(),
                0,
                algo.nonce_len(),
            )
            .unwrap();
            let aad = build_aad(b"envelope", &uuid(), &session(), 0).unwrap();
            let ciphertext = aead_encrypt(algo, &key, &nonce, &aad, b"plaintext").unwrap();
            assert_ne!(ciphertext, b"plaintext");
            let plaintext = aead_decrypt(algo, &key, &nonce, &aad, &ciphertext).unwrap();
            assert_eq!(plaintext, b"plaintext");

            let mut tampered = ciphertext;
            tampered[0] ^= 1;
            assert_eq!(
                aead_decrypt(algo, &key, &nonce, &aad, &tampered).unwrap_err(),
                FormatError::AeadFailure
            );
        }
    }

    #[test]
    fn aead_none_passes_plaintext_through() {
        let ciphertext =
            aead_encrypt(AeadAlgo::None, &[0; SUBKEY_LEN], &[], b"aad", b"plaintext").unwrap();
        assert_eq!(ciphertext, b"plaintext");
        assert_eq!(
            aead_decrypt(AeadAlgo::None, &[0; SUBKEY_LEN], &[], b"aad", &ciphertext).unwrap(),
            b"plaintext"
        );
        assert_eq!(AeadAlgo::None.nonce_len(), 0);
        assert_eq!(AeadAlgo::None.tag_len(), 0);
    }

    #[test]
    fn aead_rejects_wrong_nonce_length() {
        assert_eq!(
            aead_encrypt(AeadAlgo::AesGcmSiv256, &[0; SUBKEY_LEN], &[0; 11], b"", b"").unwrap_err(),
            FormatError::InvalidNonceLength {
                algo: AeadAlgo::AesGcmSiv256,
                expected: 12,
                actual: 11
            }
        );
    }

    #[test]
    fn padded_aead_object_round_trips_with_derived_nonce_and_aad() {
        let key = [0x66; SUBKEY_LEN];
        let nonce_seed = [0x77; SUBKEY_LEN];
        let uuid = uuid();
        let session = session();
        let context = AeadObjectContext {
            algo: AeadAlgo::AesGcmSiv256,
            key: &key,
            nonce_seed: &nonce_seed,
            domain: b"envelope",
            archive_uuid: &uuid,
            session_id: &session,
            counter: 3,
        };
        let ciphertext = encrypt_padded_aead_object(context, 4096, b"packed frames").unwrap();
        assert_eq!(ciphertext.len() % 4096, 0);

        let plaintext = decrypt_padded_aead_object(context, &ciphertext).unwrap();
        assert_eq!(plaintext, b"packed frames");

        assert_eq!(
            decrypt_padded_aead_object(
                AeadObjectContext {
                    domain: b"idxroot",
                    ..context
                },
                &ciphertext,
            )
            .unwrap_err(),
            FormatError::AeadFailure
        );
    }

    #[test]
    fn rejects_index_root_aad_counter_mismatch() {
        let key = [0x99; SUBKEY_LEN];
        let nonce_seed = [0x88; SUBKEY_LEN];
        let uuid = uuid();
        let session = session();

        let ciphertext = encrypt_padded_aead_object(
            AeadObjectContext {
                algo: AeadAlgo::AesGcmSiv256,
                key: &key,
                nonce_seed: &nonce_seed,
                domain: b"idxroot",
                archive_uuid: &uuid,
                session_id: &session,
                counter: 0,
            },
            4096,
            b"index-root-meta",
        )
        .unwrap();

        let nonce = derive_nonce(
            &nonce_seed,
            b"idxroot",
            &uuid,
            &session,
            0,
            AeadAlgo::AesGcmSiv256.nonce_len(),
        )
        .unwrap();
        let mismatched_aad = build_aad(b"idxroot", &uuid, &session, 1).unwrap();

        assert_eq!(
            aead_decrypt(
                AeadAlgo::AesGcmSiv256,
                &key,
                &nonce,
                &mismatched_aad,
                &ciphertext,
            )
            .unwrap_err(),
            FormatError::AeadFailure
        );
    }
}
