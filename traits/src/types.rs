//! # OpenMLS Types
//!
//! This module holds a number of types that are needed by the traits.
//!
//! ## Draft vs. final IANA codepoints
//!
//! Some ciphersuites, KEM types, and signature schemes in this module are
//! defined against **draft** or **private** codepoints. These codepoints are
//! placeholders allocated for ongoing IETF / NIST drafts (e.g. X-Wing,
//! ML-KEM, ML-DSA, the IETF MLS PQ ciphersuite draft) and **will change**
//! once IANA assigns final values.
//!
//! Wire-level interop with future deployments therefore requires migrating
//! from draft codepoints to their final IANA-assigned values — silently
//! reusing a draft value as if it were final is a downgrade hazard. To make
//! this distinction visible at the type level, the [`Ciphersuite`],
//! [`HpkeKemType`], and [`SignatureScheme`] enums each expose an
//! `is_draft_codepoint()` method that returns `true` for any variant whose
//! numeric value is still provisional. Callers that need final-only behaviour
//! (production deployments, no-downgrade enforcement, telemetry that flags
//! draft suites) should consult these methods.
//!
//! See [`PROGRESS.md`](https://github.com/kennguy3n/openmls/blob/main/PROGRESS.md)
//! and [`ARCHITECTURE.md`](https://github.com/kennguy3n/openmls/blob/main/ARCHITECTURE.md)
//! for the migration plan and the current set of draft suites.

use std::ops::Deref;

use serde::{Deserialize, Serialize};
use tls_codec::{
    SecretVLBytes, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSerializeBytes, TlsSize,
    VLBytes,
};

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
#[repr(u16)]
/// AEAD types
pub enum AeadType {
    /// AES GCM 128
    Aes128Gcm = 0x0001,

    /// AES GCM 256
    Aes256Gcm = 0x0002,

    /// ChaCha20 Poly1305
    ChaCha20Poly1305 = 0x0003,
}

impl AeadType {
    /// Get the tag size of the [`AeadType`] in bytes.
    pub const fn tag_size(&self) -> usize {
        match self {
            AeadType::Aes128Gcm => 16,
            AeadType::Aes256Gcm => 16,
            AeadType::ChaCha20Poly1305 => 16,
        }
    }

    /// Get the key size of the [`AeadType`] in bytes.
    pub const fn key_size(&self) -> usize {
        match self {
            AeadType::Aes128Gcm => 16,
            AeadType::Aes256Gcm => 32,
            AeadType::ChaCha20Poly1305 => 32,
        }
    }

    /// Get the nonce size of the [`AeadType`] in bytes.
    pub const fn nonce_size(&self) -> usize {
        match self {
            AeadType::Aes128Gcm | AeadType::Aes256Gcm | AeadType::ChaCha20Poly1305 => 12,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
#[allow(non_camel_case_types)]
/// Hash types
pub enum HashType {
    Sha2_256 = 0x04,
    Sha2_384 = 0x05,
    Sha2_512 = 0x06,
}

impl HashType {
    /// Returns the output size of a hash by [`HashType`].
    #[inline]
    pub const fn size(&self) -> usize {
        match self {
            HashType::Sha2_256 => 32,
            HashType::Sha2_384 => 48,
            HashType::Sha2_512 => 64,
        }
    }
}

/// SignatureScheme according to IANA TLS parameters
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
#[derive(
    Copy,
    Hash,
    Eq,
    PartialEq,
    Clone,
    Debug,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsSerializeBytes,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
#[repr(u16)]
pub enum SignatureScheme {
    /// ECDSA_SECP256R1_SHA256
    ECDSA_SECP256R1_SHA256 = 0x0403,
    /// ECDSA_SECP384R1_SHA384
    ECDSA_SECP384R1_SHA384 = 0x0503,
    /// ECDSA_SECP521R1_SHA512
    ECDSA_SECP521R1_SHA512 = 0x0603,
    /// ED25519
    ED25519 = 0x0807,
    /// ED448
    ED448 = 0x0808,
    /// ML-DSA-44 (FIPS 204) — post-quantum digital signature, security level 2.
    ///
    /// **DRAFT** — codepoint `0x0904` is a private/experimental value used as
    /// a placeholder until IANA assigns a final value for ML-DSA in the
    /// IETF MLS PQ ciphersuite draft. Migrate consumers to the final
    /// codepoint once it is published.
    MLDSA44 = 0x0904,
    /// ML-DSA-65 (FIPS 204) — post-quantum digital signature, security level 3.
    ///
    /// **DRAFT** — codepoint `0x0905` is a private/experimental value used as
    /// a placeholder until IANA assigns a final value for ML-DSA in the
    /// IETF MLS PQ ciphersuite draft. Migrate consumers to the final
    /// codepoint once it is published.
    MLDSA65 = 0x0905,
    /// ML-DSA-87 (FIPS 204) — post-quantum digital signature, security level 5.
    ///
    /// **DRAFT** — codepoint `0x0906` is a private/experimental value used as
    /// a placeholder until IANA assigns a final value for ML-DSA in the
    /// IETF MLS PQ ciphersuite draft. Migrate consumers to the final
    /// codepoint once it is published.
    MLDSA87 = 0x0906,
}

impl SignatureScheme {
    /// Returns `true` if this signature scheme uses a draft / private
    /// codepoint that has not yet been assigned a final IANA value.
    ///
    /// Draft codepoints MUST be migrated to their final values once IANA
    /// assigns them; deployments that treat a draft codepoint as final risk
    /// silent interop / downgrade failures.
    pub const fn is_draft_codepoint(&self) -> bool {
        matches!(
            self,
            SignatureScheme::MLDSA44 | SignatureScheme::MLDSA65 | SignatureScheme::MLDSA87
        )
    }

    /// Returns `true` if this signature scheme is a post-quantum scheme.
    ///
    /// Currently this is the ML-DSA family (FIPS 204).
    pub const fn is_post_quantum(&self) -> bool {
        matches!(
            self,
            SignatureScheme::MLDSA44 | SignatureScheme::MLDSA65 | SignatureScheme::MLDSA87
        )
    }
}

impl TryFrom<u16> for SignatureScheme {
    type Error = String;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0403 => Ok(SignatureScheme::ECDSA_SECP256R1_SHA256),
            0x0503 => Ok(SignatureScheme::ECDSA_SECP384R1_SHA384),
            0x0603 => Ok(SignatureScheme::ECDSA_SECP521R1_SHA512),
            0x0807 => Ok(SignatureScheme::ED25519),
            0x0808 => Ok(SignatureScheme::ED448),
            0x0904 => Ok(SignatureScheme::MLDSA44),
            0x0905 => Ok(SignatureScheme::MLDSA65),
            0x0906 => Ok(SignatureScheme::MLDSA87),
            _ => Err(format!("Unsupported SignatureScheme: {value}")),
        }
    }
}

/// Crypto errors.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CryptoError {
    CryptoLibraryError,
    AeadDecryptionError,
    HpkeDecryptionError,
    HpkeEncryptionError,
    UnsupportedSignatureScheme,
    KdfLabelTooLarge,
    KdfSerializationError,
    HkdfOutputLengthInvalid,
    InsufficientRandomness,
    InvalidSignature,
    UnsupportedAeadAlgorithm,
    UnsupportedKdf,
    InvalidLength,
    UnsupportedHashAlgorithm,
    SignatureEncodingError,
    SignatureDecodingError,
    SenderSetupError,
    ReceiverSetupError,
    ExporterError,
    UnsupportedCiphersuite,
    TlsSerializationError,
    TooMuchData,
    SigningError,
    InvalidPublicKey,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for CryptoError {}

// === HPKE === //

/// Convenience tuple struct for an HPKE configuration.
#[derive(Debug)]
pub struct HpkeConfig(pub HpkeKemType, pub HpkeKdfType, pub HpkeAeadType);

/// KEM Types for HPKE
#[derive(PartialEq, Eq, Copy, Clone, Debug, Serialize, Deserialize)]
#[repr(u16)]
pub enum HpkeKemType {
    /// DH KEM on P256
    DhKemP256 = 0x0010,

    /// DH KEM on P384
    DhKemP384 = 0x0011,

    /// DH KEM on P521
    DhKemP521 = 0x0012,

    /// DH KEM on x25519
    DhKem25519 = 0x0020,

    /// DH KEM on x448
    DhKem448 = 0x0021,

    /// **DRAFT** — X-Wing combiner for ML-KEM-768 and X25519.
    ///
    /// Codepoint `0x004D` is a draft value (see
    /// [`draft-connolly-cfrg-xwing-kem`](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/))
    /// and **will change** when IANA assigns the final codepoint. Wire-level
    /// interop with future deployments requires migrating to that final
    /// value.
    XWingKemDraft6 = 0x004D,

    /// **DRAFT** — Hybrid combiner for ML-KEM-768 and X25519.
    ///
    /// Codepoint `0xFE01` is a private-use draft value tracking the IETF
    /// MLS PQ ciphersuite draft (March 2026). It will be reassigned to a
    /// final IANA codepoint once the draft is published.
    MlKem768X25519Draft = 0xFE01,

    /// **DRAFT** — Pure ML-KEM-768 (no classical hybridization).
    ///
    /// Codepoint `0xFE02` is a private-use draft value tracking the IETF
    /// MLS PQ ciphersuite draft (March 2026). Pure ML-KEM-768 is offered
    /// for deployments that already accept the harvest-now / decrypt-later
    /// model and prefer to drop the classical curve KEM entirely. It uses
    /// the same ML-KEM module as [`HpkeKemType::MlKem768X25519Draft`] but
    /// without the X25519 combiner.
    MlKem768Draft = 0xFE02,

    /// **DRAFT** — Pure ML-KEM-1024 (no classical hybridization).
    ///
    /// Codepoint `0xFE03` is a private-use draft value tracking the IETF
    /// MLS PQ ciphersuite draft (March 2026). Pure-PQ KEM ciphersuites
    /// are intended for high-risk deployments that prefer to drop the
    /// classical KEM rather than hybridize.
    MlKem1024Draft = 0xFE03,
}

impl HpkeKemType {
    /// Returns `true` if this KEM type uses a draft / private codepoint
    /// that has not yet been assigned a final IANA value.
    ///
    /// Draft codepoints MUST be migrated to their final values once IANA
    /// assigns them; deployments that treat a draft codepoint as final risk
    /// silent interop / downgrade failures.
    pub const fn is_draft_codepoint(&self) -> bool {
        matches!(
            self,
            HpkeKemType::XWingKemDraft6
                | HpkeKemType::MlKem768X25519Draft
                | HpkeKemType::MlKem768Draft
                | HpkeKemType::MlKem1024Draft
        )
    }

    /// Returns `true` if this KEM type is post-quantum or hybrid
    /// (post-quantum + classical) rather than purely classical.
    ///
    /// Currently this matches every draft codepoint; the helper is kept
    /// as a separate method so callers that want to express "do not allow
    /// purely classical KEMs in this code path" can do so without coupling
    /// to draft-codepoint accounting.
    pub const fn is_post_quantum(&self) -> bool {
        matches!(
            self,
            HpkeKemType::XWingKemDraft6
                | HpkeKemType::MlKem768X25519Draft
                | HpkeKemType::MlKem768Draft
                | HpkeKemType::MlKem1024Draft
        )
    }
}

/// KDF Types for HPKE
#[derive(PartialEq, Eq, Copy, Clone, Debug, Serialize, Deserialize)]
#[repr(u16)]
pub enum HpkeKdfType {
    /// HKDF SHA 256
    HkdfSha256 = 0x0001,

    /// HKDF SHA 384
    HkdfSha384 = 0x0002,

    /// HKDF SHA 512
    HkdfSha512 = 0x0003,
}

/// AEAD Types for HPKE.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum HpkeAeadType {
    /// AES GCM 128
    AesGcm128 = 0x0001,

    /// AES GCM 256
    AesGcm256 = 0x0002,

    /// ChaCha20 Poly1305
    ChaCha20Poly1305 = 0x0003,

    /// Export-only
    Export = 0xFFFF,
}

/// 7.7. Update Paths
///
/// ```text
/// struct {
///     opaque kem_output<V>;
///     opaque ciphertext<V>;
/// } HPKECiphertext;
/// ```
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct HpkeCiphertext {
    pub kem_output: VLBytes,
    pub ciphertext: VLBytes,
}

/// A simple type for HPKE private keys.
#[derive(
    Debug,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
#[cfg_attr(feature = "test-utils", derive(PartialEq, Eq))]
#[serde(transparent)]
pub struct HpkePrivateKey(SecretVLBytes);

impl From<Vec<u8>> for HpkePrivateKey {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes.into())
    }
}

impl From<&[u8]> for HpkePrivateKey {
    fn from(bytes: &[u8]) -> Self {
        Self(bytes.into())
    }
}

impl std::ops::Deref for HpkePrivateKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

/// Helper holding a (private, public) key pair as byte vectors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HpkeKeyPair {
    pub private: HpkePrivateKey,
    pub public: Vec<u8>,
}

pub type KemOutput = Vec<u8>;
#[derive(Clone, Debug)]
pub struct ExporterSecret(SecretVLBytes);

impl Deref for ExporterSecret {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

impl From<Vec<u8>> for ExporterSecret {
    fn from(secret: Vec<u8>) -> Self {
        Self(secret.into())
    }
}

/// A currently unknown ciphersuite.
///
/// Used to accept unknown values, e.g., in `Capabilities`.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct VerifiableCiphersuite(u16);

impl VerifiableCiphersuite {
    pub fn new(value: u16) -> Self {
        Self(value)
    }

    /// Returns the raw u16 value of this ciphersuite.
    pub fn value(&self) -> u16 {
        self.0
    }

    /// Returns true if this is a GREASE ciphersuite value.
    ///
    /// GREASE values are used to ensure implementations properly handle unknown
    /// ciphersuites. See [RFC 9420 Section 13.5](https://www.rfc-editor.org/rfc/rfc9420.html#section-13.5).
    ///
    /// GREASE ciphersuites cannot be used for actual cryptographic operations.
    pub fn is_grease(&self) -> bool {
        crate::grease::is_grease_value(self.0)
    }
}

impl From<Ciphersuite> for VerifiableCiphersuite {
    fn from(value: Ciphersuite) -> Self {
        Self(value as u16)
    }
}

impl TryFrom<VerifiableCiphersuite> for Ciphersuite {
    type Error = tls_codec::Error;

    fn try_from(value: VerifiableCiphersuite) -> Result<Self, Self::Error> {
        Ciphersuite::try_from(value.0)
    }
}

/// MLS ciphersuites.
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerialize,
    TlsSize,
)]
#[repr(u16)]
pub enum Ciphersuite {
    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | Ed25519
    MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 = 0x0001,

    /// DH KEM P256 | AES-GCM 128 | SHA2-256 | EcDSA P256
    MLS_128_DHKEMP256_AES128GCM_SHA256_P256 = 0x0002,

    /// DH KEM x25519 | Chacha20Poly1305 | SHA2-256 | Ed25519
    MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 = 0x0003,

    /// DH KEM x448 | AES-GCM 256 | SHA2-512 | Ed448
    MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 = 0x0004,

    /// DH KEM P521 | AES-GCM 256 | SHA2-512 | EcDSA P521
    MLS_256_DHKEMP521_AES256GCM_SHA512_P521 = 0x0005,

    /// DH KEM x448 | Chacha20Poly1305 | SHA2-512 | Ed448
    MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 = 0x0006,

    /// DH KEM P384 | AES-GCM 256 | SHA2-384 | EcDSA P384
    MLS_256_DHKEMP384_AES256GCM_SHA384_P384 = 0x0007,

    /// **DRAFT** — X-Wing KEM (ML-KEM-768 + X25519) | Chacha20Poly1305 | SHA2-256 | Ed25519.
    ///
    /// Codepoint `0x004D` is a draft value used while the IETF MLS PQ
    /// ciphersuite draft and the X-Wing combiner draft are still in flight,
    /// and **will change** when IANA assigns the final codepoint. Wire-level
    /// interop with future deployments requires migrating to that final
    /// value.
    MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 = 0x004D,

    /// **DRAFT** — Hybrid ML-KEM-768 + X25519 | AES-GCM 256 | SHA2-384 | Ed25519.
    ///
    /// Tracks the IETF MLS PQ ciphersuite draft (March 2026). Codepoint
    /// `0xFE01` is a private-use value and **will change** when IANA
    /// assigns the final codepoint. The PQ KEM is hybridized with X25519;
    /// signatures remain classical (Ed25519), so the security mode
    /// implied by this suite is
    /// [`SecurityMode::PqConfidentiality`].
    MLS_256_MLKEM768_X25519_AES256GCM_SHA384_Ed25519 = 0xFE01,

    /// **DRAFT** — Hybrid ML-KEM-768 + X25519 | Chacha20Poly1305 | SHA2-256 | Ed25519.
    ///
    /// Tracks the IETF MLS PQ ciphersuite draft (March 2026). Codepoint
    /// `0xFE02` is a private-use value and **will change** when IANA
    /// assigns the final codepoint. Same KEM/signature shape as the
    /// `0xFE01` variant; differs only in the AEAD/hash combination.
    MLS_256_MLKEM768_X25519_CHACHA20POLY1305_SHA256_Ed25519 = 0xFE02,

    /// **DRAFT** — Pure ML-KEM-1024 | AES-GCM 256 | SHA2-512 | Ed448.
    ///
    /// Tracks the IETF MLS PQ ciphersuite draft (March 2026). Codepoint
    /// `0xFE03` is a private-use value and **will change** when IANA
    /// assigns the final codepoint. Pure-PQ KEM (no classical
    /// hybridization); signatures are classical Ed448, so the security
    /// mode is [`SecurityMode::PqConfidentiality`].
    MLS_256_MLKEM1024_AES256GCM_SHA512_Ed448 = 0xFE03,

    /// **DRAFT** — Pure ML-KEM-768 | AES-GCM 256 | SHA2-384 | Ed25519.
    ///
    /// Tracks the IETF MLS PQ ciphersuite draft (March 2026). Codepoint
    /// `0xFE04` is a private-use value and **will change** when IANA
    /// assigns the final codepoint. Pure ML-KEM-768 (no X25519
    /// hybridization); signatures are classical Ed25519, so the security
    /// mode is [`SecurityMode::PqConfidentiality`].
    MLS_256_MLKEM768_AES256GCM_SHA384_Ed25519 = 0xFE04,

    /// **DRAFT** — Hybrid ML-KEM-768 + X25519 | AES-GCM 256 | SHA2-384 | ML-DSA-65.
    ///
    /// Tracks the IETF MLS PQ ciphersuite draft (March 2026). Codepoint
    /// `0xFE05` is a private-use value and **will change** when IANA
    /// assigns the final codepoint. Hybrid PQ KEM **and** ML-DSA-65
    /// signatures, so the security mode is
    /// [`SecurityMode::PqAuthenticity`].
    MLS_256_MLKEM768_X25519_AES256GCM_SHA384_MLDSA65 = 0xFE05,

    /// **DRAFT** — Pure ML-KEM-768 | AES-GCM 256 | SHA2-384 | ML-DSA-65.
    ///
    /// Tracks the IETF MLS PQ ciphersuite draft (March 2026). Codepoint
    /// `0xFE06` is a private-use value and **will change** when IANA
    /// assigns the final codepoint. Pure ML-KEM-768 KEM and ML-DSA-65
    /// signatures, so the security mode is
    /// [`SecurityMode::PqAuthenticity`].
    MLS_256_MLKEM768_AES256GCM_SHA384_MLDSA65 = 0xFE06,
}

impl Ciphersuite {
    /// Returns `true` if this ciphersuite uses a draft / private codepoint
    /// that has not yet been assigned a final IANA value.
    ///
    /// Draft codepoints MUST be migrated to their final values once IANA
    /// assigns them; deployments that treat a draft codepoint as final risk
    /// silent interop / downgrade failures.
    pub const fn is_draft_codepoint(&self) -> bool {
        matches!(
            self,
            Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519
                | Ciphersuite::MLS_256_MLKEM768_X25519_AES256GCM_SHA384_Ed25519
                | Ciphersuite::MLS_256_MLKEM768_X25519_CHACHA20POLY1305_SHA256_Ed25519
                | Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_Ed448
                | Ciphersuite::MLS_256_MLKEM768_AES256GCM_SHA384_Ed25519
                | Ciphersuite::MLS_256_MLKEM768_X25519_AES256GCM_SHA384_MLDSA65
                | Ciphersuite::MLS_256_MLKEM768_AES256GCM_SHA384_MLDSA65
        )
    }
}

impl core::fmt::Display for Ciphersuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl From<Ciphersuite> for u16 {
    #[inline(always)]
    fn from(s: Ciphersuite) -> u16 {
        s as u16
    }
}

impl From<&Ciphersuite> for u16 {
    #[inline(always)]
    fn from(s: &Ciphersuite) -> u16 {
        *s as u16
    }
}

impl TryFrom<u16> for Ciphersuite {
    type Error = tls_codec::Error;

    #[inline(always)]
    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            0x0001 => Ok(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519),
            0x0002 => Ok(Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256),
            0x0003 => Ok(Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519),
            0x0004 => Ok(Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448),
            0x0005 => Ok(Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521),
            0x0006 => Ok(Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448),
            0x0007 => Ok(Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384),
            0x004D => Ok(Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519),
            0xFE01 => Ok(Ciphersuite::MLS_256_MLKEM768_X25519_AES256GCM_SHA384_Ed25519),
            0xFE02 => Ok(Ciphersuite::MLS_256_MLKEM768_X25519_CHACHA20POLY1305_SHA256_Ed25519),
            0xFE03 => Ok(Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_Ed448),
            0xFE04 => Ok(Ciphersuite::MLS_256_MLKEM768_AES256GCM_SHA384_Ed25519),
            0xFE05 => Ok(Ciphersuite::MLS_256_MLKEM768_X25519_AES256GCM_SHA384_MLDSA65),
            0xFE06 => Ok(Ciphersuite::MLS_256_MLKEM768_AES256GCM_SHA384_MLDSA65),
            _ => Err(Self::Error::DecodingError(format!(
                "{v} is not a valid ciphersuite value"
            ))),
        }
    }
}

impl From<Ciphersuite> for SignatureScheme {
    #[inline(always)]
    fn from(ciphersuite_name: Ciphersuite) -> Self {
        ciphersuite_name.signature_algorithm()
    }
}

impl From<Ciphersuite> for AeadType {
    #[inline(always)]
    fn from(ciphersuite_name: Ciphersuite) -> Self {
        ciphersuite_name.aead_algorithm()
    }
}

impl From<Ciphersuite> for HpkeKemType {
    #[inline(always)]
    fn from(ciphersuite_name: Ciphersuite) -> Self {
        ciphersuite_name.hpke_kem_algorithm()
    }
}

impl From<Ciphersuite> for HpkeAeadType {
    #[inline(always)]
    fn from(ciphersuite_name: Ciphersuite) -> Self {
        ciphersuite_name.hpke_aead_algorithm()
    }
}

impl From<Ciphersuite> for HpkeKdfType {
    #[inline(always)]
    fn from(ciphersuite_name: Ciphersuite) -> Self {
        ciphersuite_name.hpke_kdf_algorithm()
    }
}

impl From<Ciphersuite> for HashType {
    #[inline(always)]
    fn from(ciphersuite_name: Ciphersuite) -> Self {
        ciphersuite_name.hash_algorithm()
    }
}

impl Ciphersuite {
    /// Get the [`HashType`] for this [`Ciphersuite`]
    #[inline]
    pub const fn hash_algorithm(&self) -> HashType {
        match self {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
            | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_256_MLKEM768_X25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                HashType::Sha2_256
            }
            Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384
            | Ciphersuite::MLS_256_MLKEM768_X25519_AES256GCM_SHA384_Ed25519
            | Ciphersuite::MLS_256_MLKEM768_AES256GCM_SHA384_Ed25519
            | Ciphersuite::MLS_256_MLKEM768_X25519_AES256GCM_SHA384_MLDSA65
            | Ciphersuite::MLS_256_MLKEM768_AES256GCM_SHA384_MLDSA65 => HashType::Sha2_384,
            Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
            | Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448
            | Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_Ed448 => HashType::Sha2_512,
        }
    }

    /// Get the [`SignatureScheme`] for this [`Ciphersuite`].
    #[inline]
    pub const fn signature_algorithm(&self) -> SignatureScheme {
        match self {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_256_MLKEM768_X25519_AES256GCM_SHA384_Ed25519
            | Ciphersuite::MLS_256_MLKEM768_X25519_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_256_MLKEM768_AES256GCM_SHA384_Ed25519 => SignatureScheme::ED25519,
            Ciphersuite::MLS_256_MLKEM768_X25519_AES256GCM_SHA384_MLDSA65
            | Ciphersuite::MLS_256_MLKEM768_AES256GCM_SHA384_MLDSA65 => SignatureScheme::MLDSA65,
            Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => {
                SignatureScheme::ECDSA_SECP256R1_SHA256
            }
            Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521 => {
                SignatureScheme::ECDSA_SECP521R1_SHA512
            }
            Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448
            | Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_Ed448 => SignatureScheme::ED448,
            Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => {
                SignatureScheme::ECDSA_SECP384R1_SHA384
            }
        }
    }

    /// Get the [`AeadType`] for this [`Ciphersuite`].
    #[inline]
    pub const fn aead_algorithm(&self) -> AeadType {
        match self {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => AeadType::Aes128Gcm,
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448
            | Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_256_MLKEM768_X25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                AeadType::ChaCha20Poly1305
            }
            Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
            | Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384
            | Ciphersuite::MLS_256_MLKEM768_X25519_AES256GCM_SHA384_Ed25519
            | Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_Ed448
            | Ciphersuite::MLS_256_MLKEM768_AES256GCM_SHA384_Ed25519
            | Ciphersuite::MLS_256_MLKEM768_X25519_AES256GCM_SHA384_MLDSA65
            | Ciphersuite::MLS_256_MLKEM768_AES256GCM_SHA384_MLDSA65 => AeadType::Aes256Gcm,
        }
    }

    /// Get the [`HpkeKdfType`] for this [`Ciphersuite`].
    #[inline]
    pub const fn hpke_kdf_algorithm(&self) -> HpkeKdfType {
        match self {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
            | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Self::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_256_MLKEM768_X25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                HpkeKdfType::HkdfSha256
            }
            Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384
            | Ciphersuite::MLS_256_MLKEM768_X25519_AES256GCM_SHA384_Ed25519
            | Ciphersuite::MLS_256_MLKEM768_AES256GCM_SHA384_Ed25519
            | Ciphersuite::MLS_256_MLKEM768_X25519_AES256GCM_SHA384_MLDSA65
            | Ciphersuite::MLS_256_MLKEM768_AES256GCM_SHA384_MLDSA65 => HpkeKdfType::HkdfSha384,
            Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
            | Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448
            | Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_Ed448 => HpkeKdfType::HkdfSha512,
        }
    }

    /// Get the [`HpkeKemType`] for this [`Ciphersuite`].
    #[inline]
    pub const fn hpke_kem_algorithm(&self) -> HpkeKemType {
        match self {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                HpkeKemType::DhKem25519
            }
            Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => HpkeKemType::DhKemP256,
            Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => HpkeKemType::DhKem448,
            Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => HpkeKemType::DhKemP384,
            Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521 => HpkeKemType::DhKemP521,
            Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => {
                HpkeKemType::XWingKemDraft6
            }
            Ciphersuite::MLS_256_MLKEM768_X25519_AES256GCM_SHA384_Ed25519
            | Ciphersuite::MLS_256_MLKEM768_X25519_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_256_MLKEM768_X25519_AES256GCM_SHA384_MLDSA65 => {
                HpkeKemType::MlKem768X25519Draft
            }
            Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_Ed448 => HpkeKemType::MlKem1024Draft,
            Ciphersuite::MLS_256_MLKEM768_AES256GCM_SHA384_Ed25519
            | Ciphersuite::MLS_256_MLKEM768_AES256GCM_SHA384_MLDSA65 => HpkeKemType::MlKem768Draft,
        }
    }

    /// Get the [`HpkeAeadType`] for this [`Ciphersuite`].
    #[inline]
    pub const fn hpke_aead_algorithm(&self) -> HpkeAeadType {
        match self {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => HpkeAeadType::AesGcm128,
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_256_MLKEM768_X25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                HpkeAeadType::ChaCha20Poly1305
            }
            Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384
            | Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
            | Ciphersuite::MLS_256_MLKEM768_X25519_AES256GCM_SHA384_Ed25519
            | Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_Ed448
            | Ciphersuite::MLS_256_MLKEM768_AES256GCM_SHA384_Ed25519
            | Ciphersuite::MLS_256_MLKEM768_X25519_AES256GCM_SHA384_MLDSA65
            | Ciphersuite::MLS_256_MLKEM768_AES256GCM_SHA384_MLDSA65 => HpkeAeadType::AesGcm256,
            Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
                HpkeAeadType::ChaCha20Poly1305
            }
        }
    }

    /// Get the [`HpkeConfig`] for this [`Ciphersuite`].
    #[inline]
    pub const fn hpke_config(&self) -> HpkeConfig {
        HpkeConfig(
            self.hpke_kem_algorithm(),
            self.hpke_kdf_algorithm(),
            self.hpke_aead_algorithm(),
        )
    }

    /// Get the length of the used hash algorithm.
    #[inline]
    pub const fn hash_length(&self) -> usize {
        self.hash_algorithm().size()
    }

    /// Get the length of the AEAD tag.
    #[inline]
    pub const fn mac_length(&self) -> usize {
        self.aead_algorithm().tag_size()
    }

    /// Returns the key size of the used AEAD.
    #[inline]
    pub const fn aead_key_length(&self) -> usize {
        self.aead_algorithm().key_size()
    }

    /// Returns the length of the nonce of the AEAD.
    #[inline]
    pub const fn aead_nonce_length(&self) -> usize {
        self.aead_algorithm().nonce_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------- Ciphersuite::is_draft_codepoint -------

    #[test]
    fn test_xwing_is_draft() {
        assert!(
            Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519.is_draft_codepoint(),
            "X-Wing must report as a draft codepoint"
        );
    }

    #[test]
    fn test_classical_not_draft() {
        let classical = [
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,
            Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
            Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448,
            Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
        ];
        for suite in classical {
            assert!(
                !suite.is_draft_codepoint(),
                "Classical ciphersuite {suite:?} must not report as a draft codepoint"
            );
        }
    }

    // ------- HpkeKemType::is_draft_codepoint -------

    #[test]
    fn test_xwing_kem_is_draft() {
        assert!(
            HpkeKemType::XWingKemDraft6.is_draft_codepoint(),
            "XWingKemDraft6 must report as a draft codepoint"
        );
    }

    #[test]
    fn test_classical_kem_not_draft() {
        let classical = [
            HpkeKemType::DhKemP256,
            HpkeKemType::DhKemP384,
            HpkeKemType::DhKemP521,
            HpkeKemType::DhKem25519,
            HpkeKemType::DhKem448,
        ];
        for kem in classical {
            assert!(
                !kem.is_draft_codepoint(),
                "Classical KEM {kem:?} must not report as a draft codepoint"
            );
        }
    }

    // ------- SignatureScheme: ML-DSA -------

    #[test]
    fn test_mldsa_signature_schemes_exist() {
        assert_eq!(SignatureScheme::MLDSA44 as u16, 0x0904);
        assert_eq!(SignatureScheme::MLDSA65 as u16, 0x0905);
        assert_eq!(SignatureScheme::MLDSA87 as u16, 0x0906);
    }

    #[test]
    fn test_mldsa_try_from_u16() {
        assert_eq!(
            SignatureScheme::try_from(0x0904u16).unwrap(),
            SignatureScheme::MLDSA44
        );
        assert_eq!(
            SignatureScheme::try_from(0x0905u16).unwrap(),
            SignatureScheme::MLDSA65
        );
        assert_eq!(
            SignatureScheme::try_from(0x0906u16).unwrap(),
            SignatureScheme::MLDSA87
        );
    }

    #[test]
    fn test_mldsa_is_draft() {
        for scheme in [
            SignatureScheme::MLDSA44,
            SignatureScheme::MLDSA65,
            SignatureScheme::MLDSA87,
        ] {
            assert!(
                scheme.is_draft_codepoint(),
                "ML-DSA scheme {scheme:?} must report as a draft codepoint"
            );
        }
    }

    #[test]
    fn test_mldsa_is_post_quantum() {
        for scheme in [
            SignatureScheme::MLDSA44,
            SignatureScheme::MLDSA65,
            SignatureScheme::MLDSA87,
        ] {
            assert!(
                scheme.is_post_quantum(),
                "ML-DSA scheme {scheme:?} must report as post-quantum"
            );
        }
    }

    #[test]
    fn test_classical_signature_schemes_not_draft_or_pq() {
        let classical = [
            SignatureScheme::ECDSA_SECP256R1_SHA256,
            SignatureScheme::ECDSA_SECP384R1_SHA384,
            SignatureScheme::ECDSA_SECP521R1_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ];
        for scheme in classical {
            assert!(
                !scheme.is_draft_codepoint(),
                "Classical signature scheme {scheme:?} must not be draft"
            );
            assert!(
                !scheme.is_post_quantum(),
                "Classical signature scheme {scheme:?} must not be post-quantum"
            );
        }
    }

    // ------- IETF MLS PQ ML-KEM draft ciphersuites -------

    fn ml_kem_draft_ciphersuites() -> [Ciphersuite; 3] {
        [
            Ciphersuite::MLS_256_MLKEM768_X25519_AES256GCM_SHA384_Ed25519,
            Ciphersuite::MLS_256_MLKEM768_X25519_CHACHA20POLY1305_SHA256_Ed25519,
            Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_Ed448,
        ]
    }

    #[test]
    fn ml_kem_ciphersuite_codepoints_are_in_private_use_range() {
        // Codepoints must live in the private-use 0xFE00–0xFEFF range so
        // they can't collide with anything IANA assigns.
        assert_eq!(
            Ciphersuite::MLS_256_MLKEM768_X25519_AES256GCM_SHA384_Ed25519 as u16,
            0xFE01
        );
        assert_eq!(
            Ciphersuite::MLS_256_MLKEM768_X25519_CHACHA20POLY1305_SHA256_Ed25519 as u16,
            0xFE02
        );
        assert_eq!(
            Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_Ed448 as u16,
            0xFE03
        );
    }

    #[test]
    fn ml_kem_ciphersuites_report_as_draft() {
        for cs in ml_kem_draft_ciphersuites() {
            assert!(
                cs.is_draft_codepoint(),
                "ML-KEM draft ciphersuite {cs:?} must report as a draft codepoint"
            );
        }
    }

    #[test]
    fn ml_kem_ciphersuites_round_trip_via_try_from_u16() {
        for cs in ml_kem_draft_ciphersuites() {
            let raw: u16 = cs.into();
            let back = Ciphersuite::try_from(raw).expect("round-trip");
            assert_eq!(back, cs, "round-trip failed for {cs:?}");
        }
    }

    #[test]
    fn ml_kem_ciphersuites_have_expected_signature_schemes() {
        // Hybrid ML-KEM-768+X25519 stays on Ed25519. Pure ML-KEM-1024
        // is paired with Ed448.
        assert_eq!(
            Ciphersuite::MLS_256_MLKEM768_X25519_AES256GCM_SHA384_Ed25519.signature_algorithm(),
            SignatureScheme::ED25519
        );
        assert_eq!(
            Ciphersuite::MLS_256_MLKEM768_X25519_CHACHA20POLY1305_SHA256_Ed25519
                .signature_algorithm(),
            SignatureScheme::ED25519
        );
        assert_eq!(
            Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_Ed448.signature_algorithm(),
            SignatureScheme::ED448
        );
    }

    #[test]
    fn ml_kem_kem_types_are_draft() {
        assert!(HpkeKemType::MlKem768X25519Draft.is_draft_codepoint());
        assert!(HpkeKemType::MlKem1024Draft.is_draft_codepoint());
    }

    #[test]
    fn ml_kem_ciphersuites_map_to_pq_kem_types() {
        assert_eq!(
            Ciphersuite::MLS_256_MLKEM768_X25519_AES256GCM_SHA384_Ed25519.hpke_kem_algorithm(),
            HpkeKemType::MlKem768X25519Draft
        );
        assert_eq!(
            Ciphersuite::MLS_256_MLKEM768_X25519_CHACHA20POLY1305_SHA256_Ed25519
                .hpke_kem_algorithm(),
            HpkeKemType::MlKem768X25519Draft
        );
        assert_eq!(
            Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_Ed448.hpke_kem_algorithm(),
            HpkeKemType::MlKem1024Draft
        );
    }

    // ------- PQ batch 4: pure ML-KEM-768 + ML-DSA-65 ciphersuites -------

    fn ml_kem_pq_batch4_ciphersuites() -> [Ciphersuite; 3] {
        [
            Ciphersuite::MLS_256_MLKEM768_AES256GCM_SHA384_Ed25519,
            Ciphersuite::MLS_256_MLKEM768_X25519_AES256GCM_SHA384_MLDSA65,
            Ciphersuite::MLS_256_MLKEM768_AES256GCM_SHA384_MLDSA65,
        ]
    }

    #[test]
    fn pq_batch4_ciphersuite_codepoints_in_private_use_range() {
        assert_eq!(
            Ciphersuite::MLS_256_MLKEM768_AES256GCM_SHA384_Ed25519 as u16,
            0xFE04
        );
        assert_eq!(
            Ciphersuite::MLS_256_MLKEM768_X25519_AES256GCM_SHA384_MLDSA65 as u16,
            0xFE05
        );
        assert_eq!(
            Ciphersuite::MLS_256_MLKEM768_AES256GCM_SHA384_MLDSA65 as u16,
            0xFE06
        );
    }

    #[test]
    fn pq_batch4_ciphersuites_report_as_draft() {
        for cs in ml_kem_pq_batch4_ciphersuites() {
            assert!(
                cs.is_draft_codepoint(),
                "ML-KEM PQ-batch-4 ciphersuite {cs:?} must report as a draft codepoint"
            );
        }
    }

    #[test]
    fn pq_batch4_ciphersuites_round_trip_via_try_from_u16() {
        for cs in ml_kem_pq_batch4_ciphersuites() {
            let raw: u16 = cs.into();
            let back = Ciphersuite::try_from(raw).expect("round-trip");
            assert_eq!(back, cs, "round-trip failed for {cs:?}");
        }
    }

    #[test]
    fn pure_mlkem768_uses_pure_ml_kem_kem_type() {
        // The pure ML-KEM-768 ciphersuite (no X25519 hybridization)
        // must dispatch to the new `MlKem768Draft` KEM type.
        assert_eq!(
            Ciphersuite::MLS_256_MLKEM768_AES256GCM_SHA384_Ed25519.hpke_kem_algorithm(),
            HpkeKemType::MlKem768Draft
        );
        assert_eq!(
            Ciphersuite::MLS_256_MLKEM768_AES256GCM_SHA384_MLDSA65.hpke_kem_algorithm(),
            HpkeKemType::MlKem768Draft
        );
    }

    #[test]
    fn ml_dsa_ciphersuites_use_ml_dsa_signature_scheme() {
        assert_eq!(
            Ciphersuite::MLS_256_MLKEM768_X25519_AES256GCM_SHA384_MLDSA65.signature_algorithm(),
            SignatureScheme::MLDSA65
        );
        assert_eq!(
            Ciphersuite::MLS_256_MLKEM768_AES256GCM_SHA384_MLDSA65.signature_algorithm(),
            SignatureScheme::MLDSA65
        );
    }

    #[test]
    fn pure_mlkem768_with_ed25519_keeps_classical_signature() {
        assert_eq!(
            Ciphersuite::MLS_256_MLKEM768_AES256GCM_SHA384_Ed25519.signature_algorithm(),
            SignatureScheme::ED25519
        );
    }

    #[test]
    fn ml_kem_768_pure_kem_type_is_draft_and_pq() {
        assert!(HpkeKemType::MlKem768Draft.is_draft_codepoint());
        assert!(HpkeKemType::MlKem768Draft.is_post_quantum());
    }

    #[test]
    fn ml_kem_kem_types_are_post_quantum() {
        for kem in [
            HpkeKemType::XWingKemDraft6,
            HpkeKemType::MlKem768X25519Draft,
            HpkeKemType::MlKem768Draft,
            HpkeKemType::MlKem1024Draft,
        ] {
            assert!(
                kem.is_post_quantum(),
                "{kem:?} must report as post-quantum / hybrid"
            );
        }
    }

    #[test]
    fn classical_kem_types_are_not_post_quantum() {
        for kem in [
            HpkeKemType::DhKemP256,
            HpkeKemType::DhKemP384,
            HpkeKemType::DhKemP521,
            HpkeKemType::DhKem25519,
            HpkeKemType::DhKem448,
        ] {
            assert!(
                !kem.is_post_quantum(),
                "{kem:?} must not report as post-quantum"
            );
        }
    }
}
