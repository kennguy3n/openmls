//! # Device capability advertisement (KChat orchestration layer)
//!
//! `DeviceCapability` is a signed, TLS-encoded blob a KChat device publishes
//! so peers (and the server-side capability registry) can decide which MLS
//! ciphersuite a conversation should use without trusting the server.
//!
//! It carries:
//!
//! - the MLS protocol version the device speaks,
//! - the classical and post-quantum ciphersuites the device supports,
//! - whether the device participates in APQ orchestration,
//! - whether the device can run the `PQ_AUTHENTICITY` mode (ML-DSA signatures),
//! - a free-form `provider_id` string identifying which crypto provider the
//!   device uses (e.g. `"libcrux"`, `"rustcrypto"`),
//! - an Ed25519 / ML-DSA signature over everything above.
//!
//! The signature is computed over the TLS encoding of *everything except the
//! signature itself* (the [`DeviceCapability::serializable_payload`] output).
//! That payload is also what is sent over the wire — devices serialize the
//! full struct including `capability_signature`, but the signature is bound
//! only to the rest of the fields, so callers can forward, dedupe, or cache
//! capability blobs without re-signing.
//!
//! See [`PHASES.md`](../../../PHASES.md) (Phase 0) and
//! [`ARCHITECTURE.md`](../../../ARCHITECTURE.md) (KChat Orchestration Layer)
//! for how this struct fits into the larger PQ migration plan.

use std::io::{Read, Write};

use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{Ciphersuite, CryptoError, SignatureScheme},
};
use serde::{Deserialize, Serialize};
use tls_codec::{
    Deserialize as TlsDeserializeTrait, DeserializeBytes as TlsDeserializeBytesTrait,
    Error as TlsError, Serialize as TlsSerializeTrait, Size as TlsSizeTrait, VLBytes,
};

use super::errors::CredentialError;

/// Signed capability advertisement for a single KChat device.
///
/// Devices publish one of these to the capability registry so peers can pick
/// a ciphersuite that all participants actually support. The signature
/// covers every field *except* `capability_signature` itself (see
/// [`Self::serializable_payload`]); that lets a device sign once and have the
/// blob safely re-fan-out by the server without giving the server the ability
/// to upgrade or downgrade the device's claimed capabilities.
///
/// ## TLS encoding
///
/// `tls_codec` does not have built-in encodings for `bool` / `String`, so the
/// TLS impl is hand-written:
///
/// - `bool` is encoded as a single `u8` (`0` or `1`); any other value is
///   rejected on decode.
/// - `String` is encoded as a length-prefixed `VLBytes` of its UTF-8 bytes.
/// - All other fields use the default `tls_codec` derive encoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCapability {
    /// MLS protocol version the device speaks (e.g. `1` for MLS 1.0).
    pub mls_version: u16,
    /// Classical ciphersuites this device can speak (RFC 9420 §17.1).
    pub classical_ciphersuites: Vec<Ciphersuite>,
    /// Post-quantum / hybrid ciphersuites this device can speak. May contain
    /// draft codepoints (see [`Ciphersuite::is_draft_codepoint`]).
    pub pq_ciphersuites: Vec<Ciphersuite>,
    /// `true` if the device can participate in APQ orchestration (T + PQ
    /// dual-session).
    pub apq_supported: bool,
    /// `true` if the device can sign with a PQ signature scheme (ML-DSA), i.e.
    /// can run in `PQ_AUTHENTICITY` mode.
    pub pq_auth_supported: bool,
    /// Free-form crypto provider identifier (e.g. `"libcrux"`,
    /// `"rustcrypto"`). Used for telemetry and for ruling out devices stuck on
    /// providers known to lack a particular suite.
    pub provider_id: String,
    /// Signature over [`Self::serializable_payload`], using the device's
    /// identity key. Empty until [`Self::sign`] has been called.
    pub capability_signature: VLBytes,
}

impl DeviceCapability {
    /// Construct a new, **unsigned** capability advertisement.
    ///
    /// Call [`Self::sign`] before publishing.
    pub fn new(
        mls_version: u16,
        classical_ciphersuites: Vec<Ciphersuite>,
        pq_ciphersuites: Vec<Ciphersuite>,
        apq_supported: bool,
        pq_auth_supported: bool,
        provider_id: String,
    ) -> Self {
        Self {
            mls_version,
            classical_ciphersuites,
            pq_ciphersuites,
            apq_supported,
            pq_auth_supported,
            provider_id,
            capability_signature: Vec::new().into(),
        }
    }

    /// TLS-serialize every field *except* `capability_signature`.
    ///
    /// This is the byte string the device signs over and the byte string that
    /// the server / peers verify against. Adding a new field to
    /// `DeviceCapability` is therefore a hard fork of the signing format and
    /// must be tied to a `mls_version` bump.
    pub fn serializable_payload(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.payload_tls_serialized_len());
        // All `unwrap`s here are over an in-memory `Vec`, which can never
        // fail to write.
        self.mls_version.tls_serialize(&mut buf).unwrap();
        self.classical_ciphersuites.tls_serialize(&mut buf).unwrap();
        self.pq_ciphersuites.tls_serialize(&mut buf).unwrap();
        let apq_byte: u8 = self.apq_supported.into();
        apq_byte.tls_serialize(&mut buf).unwrap();
        let pq_auth_byte: u8 = self.pq_auth_supported.into();
        pq_auth_byte.tls_serialize(&mut buf).unwrap();
        let provider: VLBytes = self.provider_id.as_bytes().to_vec().into();
        provider.tls_serialize(&mut buf).unwrap();
        buf
    }

    fn payload_tls_serialized_len(&self) -> usize {
        let provider_bytes_len = self.provider_id.len();
        let provider: VLBytes = vec![0u8; provider_bytes_len].into();
        self.mls_version.tls_serialized_len()
            + self.classical_ciphersuites.tls_serialized_len()
            + self.pq_ciphersuites.tls_serialized_len()
            + 1 // apq_supported
            + 1 // pq_auth_supported
            + provider.tls_serialized_len()
    }

    /// Returns `true` if the device advertised at least one PQ / hybrid
    /// ciphersuite.
    pub fn supports_pq(&self) -> bool {
        !self.pq_ciphersuites.is_empty()
    }

    /// Returns `true` if the device advertised APQ support.
    pub fn supports_apq(&self) -> bool {
        self.apq_supported
    }

    /// Returns `true` if the capability advertisement has a non-empty
    /// signature. This is **not** a verification check — call [`Self::verify`]
    /// for that.
    pub fn is_signed(&self) -> bool {
        !self.capability_signature.as_slice().is_empty()
    }

    /// Sign the [`Self::serializable_payload`] with `signing_key` under
    /// `signature_scheme`, populating `capability_signature` in place.
    ///
    /// Returns an error if the underlying provider rejects the scheme or
    /// fails to sign.
    pub fn sign(
        &mut self,
        signature_scheme: SignatureScheme,
        signing_key: &[u8],
        crypto: &impl OpenMlsCrypto,
    ) -> Result<(), CredentialError> {
        let payload = self.serializable_payload();
        let signature = crypto
            .sign(signature_scheme, &payload, signing_key)
            .map_err(map_crypto_error)?;
        self.capability_signature = signature.into();
        Ok(())
    }

    /// Verify `capability_signature` against `public_key` under
    /// `signature_scheme`, recomputing the payload from the current field
    /// values.
    ///
    /// Returns `Err(CredentialError::InvalidSignature)` if the signature is
    /// missing, malformed, or does not match.
    pub fn verify(
        &self,
        signature_scheme: SignatureScheme,
        public_key: &[u8],
        crypto: &impl OpenMlsCrypto,
    ) -> Result<(), CredentialError> {
        if !self.is_signed() {
            return Err(CredentialError::InvalidSignature);
        }
        let payload = self.serializable_payload();
        crypto
            .verify_signature(
                signature_scheme,
                &payload,
                public_key,
                self.capability_signature.as_slice(),
            )
            .map_err(map_crypto_error)
    }

    /// Pick the best ciphersuite that all `peers` (and `self`) support.
    ///
    /// Selection order:
    ///
    /// 1. PQ / hybrid suites that every peer lists in `pq_ciphersuites`.
    /// 2. Classical suites that every peer lists in `classical_ciphersuites`.
    ///
    /// Within a tier, the suite is picked by iterating over `self`'s lists in
    /// order, so callers can express their preference by ordering their own
    /// capability lists.
    ///
    /// `peers` may be empty, in which case `self`'s top-priority suite is
    /// returned (PQ first, then classical).
    pub fn best_common_ciphersuite(peers: &[&DeviceCapability]) -> Option<Ciphersuite> {
        let (anchor, rest) = peers.split_first()?;

        // Try PQ suites first.
        for suite in &anchor.pq_ciphersuites {
            if rest.iter().all(|peer| peer.pq_ciphersuites.contains(suite)) {
                return Some(*suite);
            }
        }

        // Fall back to classical suites.
        for suite in &anchor.classical_ciphersuites {
            if rest
                .iter()
                .all(|peer| peer.classical_ciphersuites.contains(suite))
            {
                return Some(*suite);
            }
        }

        None
    }
}

fn map_crypto_error(err: CryptoError) -> CredentialError {
    match err {
        CryptoError::InvalidSignature => CredentialError::InvalidSignature,
        _ => CredentialError::InvalidSignature,
    }
}

// === TLS codec impls ===
//
// Hand-rolled because `tls_codec` does not provide encodings for `bool` or
// `String`; we encode `bool` as `u8` and `String` as a length-prefixed
// `VLBytes` of UTF-8 bytes.

impl TlsSizeTrait for DeviceCapability {
    fn tls_serialized_len(&self) -> usize {
        self.payload_tls_serialized_len() + self.capability_signature.tls_serialized_len()
    }
}

impl TlsSerializeTrait for DeviceCapability {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, TlsError> {
        let mut written = 0;
        written += self.mls_version.tls_serialize(writer)?;
        written += self.classical_ciphersuites.tls_serialize(writer)?;
        written += self.pq_ciphersuites.tls_serialize(writer)?;
        let apq_byte: u8 = self.apq_supported.into();
        written += apq_byte.tls_serialize(writer)?;
        let pq_auth_byte: u8 = self.pq_auth_supported.into();
        written += pq_auth_byte.tls_serialize(writer)?;
        let provider: VLBytes = self.provider_id.as_bytes().to_vec().into();
        written += provider.tls_serialize(writer)?;
        written += self.capability_signature.tls_serialize(writer)?;
        Ok(written)
    }
}

impl TlsDeserializeTrait for DeviceCapability {
    fn tls_deserialize<R: Read>(reader: &mut R) -> Result<Self, TlsError>
    where
        Self: Sized,
    {
        let mls_version = u16::tls_deserialize(reader)?;
        let classical_ciphersuites = Vec::<Ciphersuite>::tls_deserialize(reader)?;
        let pq_ciphersuites = Vec::<Ciphersuite>::tls_deserialize(reader)?;
        let apq_byte = u8::tls_deserialize(reader)?;
        let apq_supported = decode_bool(apq_byte)?;
        let pq_auth_byte = u8::tls_deserialize(reader)?;
        let pq_auth_supported = decode_bool(pq_auth_byte)?;
        let provider_bytes = VLBytes::tls_deserialize(reader)?;
        let provider_id = String::from_utf8(provider_bytes.as_slice().to_vec())
            .map_err(|_| TlsError::DecodingError("provider_id is not valid UTF-8".to_string()))?;
        let capability_signature = VLBytes::tls_deserialize(reader)?;
        Ok(Self {
            mls_version,
            classical_ciphersuites,
            pq_ciphersuites,
            apq_supported,
            pq_auth_supported,
            provider_id,
            capability_signature,
        })
    }
}

impl TlsDeserializeBytesTrait for DeviceCapability {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), TlsError>
    where
        Self: Sized,
    {
        let (mls_version, bytes) = u16::tls_deserialize_bytes(bytes)?;
        let (classical_ciphersuites, bytes) = Vec::<Ciphersuite>::tls_deserialize_bytes(bytes)?;
        let (pq_ciphersuites, bytes) = Vec::<Ciphersuite>::tls_deserialize_bytes(bytes)?;
        let (apq_byte, bytes) = u8::tls_deserialize_bytes(bytes)?;
        let apq_supported = decode_bool(apq_byte)?;
        let (pq_auth_byte, bytes) = u8::tls_deserialize_bytes(bytes)?;
        let pq_auth_supported = decode_bool(pq_auth_byte)?;
        let (provider_bytes, bytes) = VLBytes::tls_deserialize_bytes(bytes)?;
        let provider_id = String::from_utf8(provider_bytes.as_slice().to_vec())
            .map_err(|_| TlsError::DecodingError("provider_id is not valid UTF-8".to_string()))?;
        let (capability_signature, bytes) = VLBytes::tls_deserialize_bytes(bytes)?;
        Ok((
            Self {
                mls_version,
                classical_ciphersuites,
                pq_ciphersuites,
                apq_supported,
                pq_auth_supported,
                provider_id,
                capability_signature,
            },
            bytes,
        ))
    }
}

fn decode_bool(b: u8) -> Result<bool, TlsError> {
    match b {
        0 => Ok(false),
        1 => Ok(true),
        other => Err(TlsError::DecodingError(format!(
            "invalid bool byte 0x{other:02x}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openmls_rust_crypto::RustCrypto;

    fn sample_capability() -> DeviceCapability {
        DeviceCapability::new(
            1,
            vec![
                Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            ],
            vec![Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519],
            true,
            false,
            "libcrux".to_string(),
        )
    }

    #[test]
    fn payload_does_not_include_signature() {
        let mut cap = sample_capability();
        let payload_unsigned = cap.serializable_payload();
        cap.capability_signature = vec![0xAB, 0xCD, 0xEF].into();
        let payload_signed = cap.serializable_payload();
        assert_eq!(
            payload_unsigned, payload_signed,
            "serializable_payload must not depend on capability_signature"
        );
    }

    #[test]
    fn supports_pq_and_apq() {
        let cap = sample_capability();
        assert!(cap.supports_pq());
        assert!(cap.supports_apq());

        let classical_only = DeviceCapability::new(
            1,
            vec![Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519],
            vec![],
            false,
            false,
            "rustcrypto".to_string(),
        );
        assert!(!classical_only.supports_pq());
        assert!(!classical_only.supports_apq());
    }

    #[test]
    fn tls_roundtrip() {
        let cap = sample_capability();
        let bytes = cap.tls_serialize_detached().expect("serialize");
        let decoded = DeviceCapability::tls_deserialize_exact(&bytes).expect("deserialize");
        assert_eq!(cap, decoded);
    }

    #[test]
    fn invalid_bool_rejected() {
        let mut cap = sample_capability();
        // Force apq_supported byte to a non-{0,1} value by mutating the
        // serialized bytes directly.
        let mut bytes = cap.tls_serialize_detached().expect("serialize");
        // Find a likely position of the apq byte: after the two Vec<Ciphersuite> blocks.
        // We know mls_version is 2 bytes; after the two lists, the next byte is apq.
        let prefix_len = 2
            + cap.classical_ciphersuites.tls_serialized_len()
            + cap.pq_ciphersuites.tls_serialized_len();
        bytes[prefix_len] = 0xFF;
        assert!(DeviceCapability::tls_deserialize_exact(&bytes).is_err());

        // self should still be valid (we only mutated `bytes`).
        cap.capability_signature = Vec::new().into();
    }

    #[test]
    fn sign_is_signed_verify() {
        let crypto = RustCrypto::default();
        let (private, public) = crypto
            .signature_key_gen(SignatureScheme::ED25519)
            .expect("keygen");

        let mut cap = sample_capability();
        assert!(!cap.is_signed());
        cap.sign(SignatureScheme::ED25519, &private, &crypto)
            .expect("sign");
        assert!(cap.is_signed());
        cap.verify(SignatureScheme::ED25519, &public, &crypto)
            .expect("verify");
    }

    #[test]
    fn verify_rejects_unsigned() {
        let crypto = RustCrypto::default();
        let (_, public) = crypto
            .signature_key_gen(SignatureScheme::ED25519)
            .expect("keygen");

        let cap = sample_capability();
        assert!(matches!(
            cap.verify(SignatureScheme::ED25519, &public, &crypto),
            Err(CredentialError::InvalidSignature)
        ));
    }

    #[test]
    fn best_common_ciphersuite_prefers_pq() {
        let a = sample_capability();
        let b = sample_capability();
        let chosen = DeviceCapability::best_common_ciphersuite(&[&a, &b]);
        assert_eq!(
            chosen,
            Some(Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519)
        );
    }

    #[test]
    fn best_common_ciphersuite_falls_back_to_classical() {
        let a = sample_capability();
        let classical_only = DeviceCapability::new(
            1,
            vec![
                Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            ],
            vec![],
            false,
            false,
            "rustcrypto".to_string(),
        );
        let chosen = DeviceCapability::best_common_ciphersuite(&[&a, &classical_only]);
        assert_eq!(
            chosen,
            Some(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
        );
    }

    #[test]
    fn best_common_ciphersuite_disjoint_returns_none() {
        let a = DeviceCapability::new(
            1,
            vec![Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519],
            vec![],
            false,
            false,
            "a".to_string(),
        );
        let b = DeviceCapability::new(
            1,
            vec![Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256],
            vec![],
            false,
            false,
            "b".to_string(),
        );
        assert!(DeviceCapability::best_common_ciphersuite(&[&a, &b]).is_none());
    }
}
