use hpke_rs_libcrux::HpkeLibcrux;

use std::sync::{Mutex, MutexGuard};

use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::{
    AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeAeadType, HpkeCiphertext,
    HpkeConfig, HpkeKdfType, HpkeKemType, HpkeKeyPair, KemOutput, SignatureScheme,
};

use rand::{rngs::OsRng, rngs::ReseedingRng, CryptoRng, RngCore};
use rand_chacha::ChaCha20Core;

use tls_codec::SecretVLBytes;

/// The libcrux-backed cryptography provider for OpenMLS
pub struct CryptoProvider {
    pub(super) rng: Mutex<ReseedingRng<ChaCha20Core, OsRng>>,
}

impl CryptoProvider {
    /// Instantiate a libcrux-based CryptoProvider
    pub fn new() -> Result<Self, CryptoError> {
        let reseeding_rng = ReseedingRng::<ChaCha20Core, _>::new(0x100000000, OsRng)
            .map_err(|_| CryptoError::InsufficientRandomness)?;

        Ok(Self {
            rng: Mutex::new(reseeding_rng),
        })
    }
}

impl OpenMlsCrypto for CryptoProvider {
    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        // The X-Wing hybrid KEM ciphersuite is gated behind the `xwing`
        // feature flag because it still rides a draft codepoint (0x004D).
        // Without `xwing` enabled, refuse to advertise support so callers
        // never accidentally pin a group to a draft suite.
        #[cfg(not(feature = "xwing"))]
        if matches!(
            ciphersuite,
            Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519
        ) {
            return Err(CryptoError::UnsupportedCiphersuite);
        }

        match ciphersuite.aead_algorithm() {
            AeadType::ChaCha20Poly1305 | AeadType::Aes128Gcm | AeadType::Aes256Gcm => Ok(()),
        }?;

        match ciphersuite.signature_algorithm() {
            SignatureScheme::ED25519 => Ok(()),
            _ => Err(CryptoError::UnsupportedCiphersuite),
        }?;

        match ciphersuite.hash_algorithm() {
            HashType::Sha2_256 | HashType::Sha2_384 | HashType::Sha2_512 => Ok(()),
        }?;

        match ciphersuite.hpke_aead_algorithm() {
            HpkeAeadType::ChaCha20Poly1305 => Ok(()),
            _ => Err(CryptoError::UnsupportedCiphersuite),
        }?;

        Ok(())
    }

    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        // The `mut` is only used when the `xwing` feature is enabled, but
        // `let mut` is the cleanest way to express the conditional push
        // without duplicating the vec literal across two `cfg` arms.
        #[cfg_attr(not(feature = "xwing"), allow(unused_mut))]
        let mut suites = vec![
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            // TODO: enable
            //Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
        ];
        #[cfg(feature = "xwing")]
        suites.push(Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519);
        suites
    }

    fn hkdf_extract(
        &self,
        hash_type: HashType,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        let alg = hkdf_alg(hash_type);

        let mut prk = vec![0u8; alg.hash_len()];

        libcrux_hkdf::extract(alg, &mut prk, salt, ikm)
            .map_err(|e| match e {
                libcrux_hkdf::ExtractError::ArgumentTooLong => CryptoError::InvalidLength,
                _ => CryptoError::CryptoLibraryError,
            })
            .map(|_| prk.into())
    }

    fn hmac(
        &self,
        hash_type: HashType,
        key: &[u8],
        message: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        let alg = hash_alg(hash_type);
        let out = libcrux_hmac::hmac(alg, key, message, None);
        Ok(out.into())
    }

    fn hkdf_expand(
        &self,
        hash_type: HashType,
        prk: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<SecretVLBytes, CryptoError> {
        let alg = hkdf_alg(hash_type);

        let mut okm = vec![0u8; okm_len];

        libcrux_hkdf::expand(alg, &mut okm, prk, info)
            .map_err(|e| match e {
                libcrux_hkdf::ExpandError::OutputTooLong => CryptoError::HkdfOutputLengthInvalid,
                libcrux_hkdf::ExpandError::ArgumentTooLong => CryptoError::InvalidLength,
                // TODO: Potentially extend `CryptoError` with a variant for the `PrkTooShort` case
                libcrux_hkdf::ExpandError::PrkTooShort => CryptoError::InvalidLength,
                libcrux_hkdf::ExpandError::Unknown => CryptoError::CryptoLibraryError,
            })
            .map(|_| okm.into())
    }

    fn hash(&self, hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let out = match hash_type {
            HashType::Sha2_256 => libcrux_sha2::sha256(data).to_vec(),
            HashType::Sha2_384 => libcrux_sha2::sha384(data).to_vec(),
            HashType::Sha2_512 => libcrux_sha2::sha512(data).to_vec(),
        };

        Ok(out)
    }

    fn aead_encrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        data: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let alg = aead_alg(alg);

        use libcrux_traits::aead::typed_refs::Aead as _;

        // set up buffers for ptxt, ctxt and tag
        let mut msg_ctxt: Vec<u8> = vec![0; data.len() + alg.tag_len()];
        let (msg, tag) = msg_ctxt.split_at_mut(data.len());

        // set up nonce
        let nonce = alg
            .new_nonce(nonce)
            .map_err(|_| CryptoError::InvalidLength)?;

        // set up key
        let key = alg.new_key(key).map_err(|_| CryptoError::InvalidLength)?;

        // set up tag
        let tag = alg
            .new_tag_mut(tag)
            .map_err(|_| CryptoError::InvalidLength)?;

        key.encrypt(msg, tag, nonce, aad, data)
            .map_err(|_| CryptoError::CryptoLibraryError)?;

        Ok(msg_ctxt)
    }

    fn aead_decrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        ct_tag: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let alg = aead_alg(alg);

        use libcrux_traits::aead::typed_refs::{Aead as _, DecryptError};

        if ct_tag.len() < alg.tag_len() {
            return Err(CryptoError::InvalidLength);
        }

        let boundary = ct_tag.len() - alg.tag_len();

        // set up buffers for ptext, ctext, and tag
        let mut ptext = vec![0; boundary];
        let (ctext, tag) = ct_tag.split_at(boundary);

        // set up nonce
        let nonce = alg
            .new_nonce(nonce)
            .map_err(|_| CryptoError::InvalidLength)?;

        // set up key
        let key = alg.new_key(key).map_err(|_| CryptoError::InvalidLength)?;

        // set up tag
        let tag = alg.new_tag(tag).map_err(|_| CryptoError::InvalidLength)?;

        key.decrypt(&mut ptext, nonce, aad, ctext, tag)
            .map_err(|e| match e {
                DecryptError::InvalidTag => CryptoError::AeadDecryptionError,
                DecryptError::AadTooLong => CryptoError::InvalidLength,

                _ => CryptoError::CryptoLibraryError,
            })?;

        Ok(ptext)
    }

    fn signature_key_gen(&self, alg: SignatureScheme) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        if !matches!(alg, SignatureScheme::ED25519) {
            return Err(CryptoError::UnsupportedSignatureScheme);
        }

        let mut rng = self
            .rng
            .lock()
            .map_err(|_| CryptoError::CryptoLibraryError)
            .map(GuardedRng)?;

        libcrux_ed25519::generate_key_pair(&mut rng)
            .map_err(|_| CryptoError::SigningError)
            .map(|(signing_key, verification_key)| {
                (
                    signing_key.into_bytes().to_vec(),
                    verification_key.into_bytes().to_vec(),
                )
            })
    }

    fn verify_signature(
        &self,
        alg: SignatureScheme,
        data: &[u8],
        pk: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        if !matches!(alg, SignatureScheme::ED25519) {
            return Err(CryptoError::UnsupportedSignatureScheme);
        }

        let pk = <&[u8; 32]>::try_from(pk).map_err(|_| CryptoError::InvalidLength)?;
        let sk = <&[u8; 64]>::try_from(signature).map_err(|_| CryptoError::InvalidLength)?;

        libcrux_ed25519::verify(data, pk, sk).map_err(|e| match e {
            libcrux_ed25519::Error::InvalidSignature => CryptoError::InvalidSignature,
            _ => CryptoError::SigningError,
        })
    }

    fn sign(&self, alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if !matches!(alg, SignatureScheme::ED25519) {
            return Err(CryptoError::UnsupportedSignatureScheme);
        }

        let key = <&[u8; 32]>::try_from(key).map_err(|_| CryptoError::InvalidLength)?;
        libcrux_ed25519::sign(data, key)
            .map_err(|_| CryptoError::SigningError)
            .map(|sig| sig.to_vec())
    }

    fn hpke_seal(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> Result<HpkeCiphertext, CryptoError> {
        let mut config = hpke_config(config)?;

        let pk_r = hpke_rs::HpkePublicKey::new(pk_r.to_vec());

        let (kem_output, ciphertext) = config
            .seal(&pk_r, info, aad, ptxt, None, None, None)
            .map_err(|e| match e {
                hpke_rs::HpkeError::InvalidConfig => CryptoError::SenderSetupError,
                _ => CryptoError::HpkeEncryptionError,
            })?;

        let kem_output = kem_output.into();
        let ciphertext = ciphertext.into();

        Ok(HpkeCiphertext {
            kem_output,
            ciphertext,
        })
    }

    fn hpke_open(
        &self,
        config: HpkeConfig,
        input: &HpkeCiphertext,
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let config = hpke_config(config)?;

        let sk_r = hpke_rs::HpkePrivateKey::new(sk_r.to_vec());

        config
            .open(
                input.kem_output.as_ref(),
                &sk_r,
                info,
                aad,
                input.ciphertext.as_ref(),
                None,
                None,
                None,
            )
            .map_err(|e| match e {
                hpke_rs::HpkeError::InvalidConfig => CryptoError::ReceiverSetupError,
                _ => CryptoError::HpkeDecryptionError,
            })
    }

    fn hpke_setup_sender_and_export(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<(KemOutput, ExporterSecret), CryptoError> {
        let mut config = hpke_config(config)?;

        let pk_r = hpke_rs::HpkePublicKey::new(pk_r.to_vec());

        let (enc, ctx) = config
            .setup_sender(&pk_r, info, None, None, None)
            .map_err(|_| CryptoError::SenderSetupError)?;

        ctx.export(exporter_context, exporter_length)
            .map_err(|_| CryptoError::ExporterError)
            .map(|exported| (enc, exported.into()))
    }

    fn hpke_setup_receiver_and_export(
        &self,
        config: HpkeConfig,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<ExporterSecret, CryptoError> {
        let config = hpke_config(config)?;

        let sk_r = hpke_rs::HpkePrivateKey::new(sk_r.to_vec());

        let ctx = config
            .setup_receiver(enc, &sk_r, info, None, None, None)
            .map_err(|_| CryptoError::ReceiverSetupError)?;

        ctx.export(exporter_context, exporter_length)
            .map_err(|_| CryptoError::ExporterError)
            .map(ExporterSecret::from)
    }

    fn derive_hpke_keypair(
        &self,
        config: HpkeConfig,
        ikm: &[u8],
    ) -> Result<HpkeKeyPair, CryptoError> {
        let config = hpke_config(config)?;

        let key_pair: hpke_rs::HpkeKeyPair = config.derive_key_pair(ikm).map_err(|e| match e {
            hpke_rs::HpkeError::InvalidConfig => CryptoError::InvalidLength,
            _ => CryptoError::CryptoLibraryError,
        })?;

        let (sk, pk) = key_pair.into_keys();

        Ok(HpkeKeyPair {
            private: sk.as_slice().to_vec().into(),
            public: pk.as_slice().to_vec(),
        })
    }
}

fn hpke_config(config: HpkeConfig) -> Result<hpke_rs::Hpke<HpkeLibcrux>, CryptoError> {
    let kem = hpke_kem(config.0)?;
    let kdf = hpke_kdf(config.1);
    let aead = hpke_aead(config.2);

    Ok(hpke_rs::Hpke::new(hpke_rs::Mode::Base, kem, kdf, aead))
}

fn hpke_kdf(kdf: HpkeKdfType) -> hpke_rs_crypto::types::KdfAlgorithm {
    match kdf {
        HpkeKdfType::HkdfSha256 => hpke_rs_crypto::types::KdfAlgorithm::HkdfSha256,
        HpkeKdfType::HkdfSha384 => hpke_rs_crypto::types::KdfAlgorithm::HkdfSha384,
        HpkeKdfType::HkdfSha512 => hpke_rs_crypto::types::KdfAlgorithm::HkdfSha512,
    }
}

fn hpke_kem(kem: HpkeKemType) -> Result<hpke_rs_crypto::types::KemAlgorithm, CryptoError> {
    match kem {
        HpkeKemType::DhKemP256 => Ok(hpke_rs_crypto::types::KemAlgorithm::DhKemP256),
        HpkeKemType::DhKemP384 => Ok(hpke_rs_crypto::types::KemAlgorithm::DhKemP384),
        HpkeKemType::DhKemP521 => Ok(hpke_rs_crypto::types::KemAlgorithm::DhKemP521),
        HpkeKemType::DhKem25519 => Ok(hpke_rs_crypto::types::KemAlgorithm::DhKem25519),
        HpkeKemType::DhKem448 => Ok(hpke_rs_crypto::types::KemAlgorithm::DhKem448),
        #[cfg(feature = "xwing")]
        HpkeKemType::XWingKemDraft6 => Ok(hpke_rs_crypto::types::KemAlgorithm::XWingDraft06),
        #[cfg(not(feature = "xwing"))]
        HpkeKemType::XWingKemDraft6 => Err(CryptoError::UnsupportedCiphersuite),
        // ML-KEM draft suites are not yet wired through to the
        // libcrux HPKE backend; reject explicitly so callers see the
        // same `UnsupportedCiphersuite` signal they would for any
        // other suite this provider does not speak.
        HpkeKemType::MlKem768X25519Draft
        | HpkeKemType::MlKem768Draft
        | HpkeKemType::MlKem1024Draft => Err(CryptoError::UnsupportedCiphersuite),
    }
}

fn hpke_aead(aead: HpkeAeadType) -> hpke_rs_crypto::types::AeadAlgorithm {
    match aead {
        HpkeAeadType::AesGcm128 => hpke_rs_crypto::types::AeadAlgorithm::Aes128Gcm,
        HpkeAeadType::AesGcm256 => hpke_rs_crypto::types::AeadAlgorithm::Aes256Gcm,
        HpkeAeadType::ChaCha20Poly1305 => hpke_rs_crypto::types::AeadAlgorithm::ChaCha20Poly1305,
        HpkeAeadType::Export => hpke_rs_crypto::types::AeadAlgorithm::HpkeExport,
    }
}

fn hkdf_alg(hash_type: HashType) -> libcrux_hkdf::Algorithm {
    match hash_type {
        HashType::Sha2_256 => libcrux_hkdf::Algorithm::Sha256,
        HashType::Sha2_384 => libcrux_hkdf::Algorithm::Sha384,
        HashType::Sha2_512 => libcrux_hkdf::Algorithm::Sha512,
    }
}

fn hash_alg(hash_type: HashType) -> libcrux_hmac::Algorithm {
    match hash_type {
        HashType::Sha2_256 => libcrux_hmac::Algorithm::Sha256,
        HashType::Sha2_384 => libcrux_hmac::Algorithm::Sha384,
        HashType::Sha2_512 => libcrux_hmac::Algorithm::Sha512,
    }
}

fn aead_alg(alg_type: AeadType) -> libcrux_aead::Aead {
    match alg_type {
        AeadType::ChaCha20Poly1305 => libcrux_aead::Aead::ChaCha20Poly1305,
        AeadType::Aes128Gcm => libcrux_aead::Aead::AesGcm128,
        AeadType::Aes256Gcm => libcrux_aead::Aead::AesGcm256,
    }
}

struct GuardedRng<'a, Rng: RngCore>(MutexGuard<'a, Rng>);

impl<Rng: RngCore> RngCore for GuardedRng<'_, Rng> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }
}

impl<Rng: RngCore + CryptoRng> CryptoRng for GuardedRng<'_, Rng> {}

#[cfg(test)]
mod tests {
    use super::*;
    use openmls_traits::types::Ciphersuite;

    #[cfg(not(feature = "xwing"))]
    #[test]
    fn test_xwing_gated_by_feature() {
        let provider = CryptoProvider::new().expect("crypto provider");
        assert_eq!(
            provider.supports(Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519),
            Err(CryptoError::UnsupportedCiphersuite),
            "X-Wing must not be supported when the `xwing` feature is disabled",
        );
        let suites = provider.supported_ciphersuites();
        assert!(
            !suites.contains(&Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519),
            "supported_ciphersuites() must not list X-Wing without `xwing` feature, got {suites:?}",
        );
    }

    #[cfg(feature = "xwing")]
    #[test]
    fn test_xwing_available_with_feature() {
        let provider = CryptoProvider::new().expect("crypto provider");
        assert_eq!(
            provider.supports(Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519),
            Ok(()),
            "X-Wing must be supported when the `xwing` feature is enabled",
        );
        let suites = provider.supported_ciphersuites();
        assert!(
            suites.contains(&Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519),
            "supported_ciphersuites() must list X-Wing when `xwing` is enabled, got {suites:?}",
        );
    }

    #[test]
    fn test_classical_chacha20_supported_regardless_of_xwing() {
        // The libcrux provider's `supports()` requires HPKE AEAD =
        // ChaCha20Poly1305, so this is the only fully-classical suite the
        // provider claims today. The point of the test is to confirm the
        // X-Wing feature gate doesn't affect classical support either way.
        let provider = CryptoProvider::new().expect("crypto provider");
        assert_eq!(
            provider.supports(Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519),
            Ok(()),
            "libcrux provider must support classical ChaCha20Poly1305 ciphersuite",
        );
    }

    #[test]
    fn test_libcrux_rejects_mldsa() {
        let provider = CryptoProvider::new().expect("crypto provider");
        for scheme in [
            SignatureScheme::MLDSA44,
            SignatureScheme::MLDSA65,
            SignatureScheme::MLDSA87,
        ] {
            assert_eq!(
                provider.signature_key_gen(scheme).err(),
                Some(CryptoError::UnsupportedSignatureScheme),
                "libcrux provider must not implement ML-DSA scheme {scheme:?}"
            );
        }
    }
}
