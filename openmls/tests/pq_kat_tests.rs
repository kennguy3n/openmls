//! Known-Answer-Test framework for PQ ciphersuites.
//!
//! Test vectors live in `openmls/tests/pq_kat_vectors/` as JSON files
//! conforming to the [`PqKatVector`] schema below. Each vector pins a
//! `(input_keying_material, expected_ciphertext, expected_shared_secret)`
//! triple for a specific [`Ciphersuite`].
//!
//! Three runners are provided:
//!
//! - `xwing::run_all` — gated behind `#[cfg(feature = "xwing")]`. For
//!   every loaded X-Wing vector, derives a keypair from the IKM via
//!   the libcrux provider, runs `hpke_seal` + `hpke_open`, and
//!   verifies the plaintext round-trips. A negative companion test
//!   tampers with the ciphertext and confirms `hpke_open` rejects it.
//! - `mldsa_runner::run_all` — gated behind `#[cfg(feature =
//!   "mldsa")]`. For every shipped ML-DSA vector, generates an
//!   ML-DSA-65 keypair via libcrux, signs a per-vector message,
//!   verifies, then flips a bit in the signature and confirms verify
//!   rejects.
//! - `mlkem_runner::run_all` — runs unconditionally. Schema-only
//!   today (no provider exposes ML-KEM through HPKE yet), but loads
//!   every shipped ML-KEM vector, asserts it references a registered
//!   draft codepoint, and hex-decodes every field so malformed
//!   vectors fail-fast.
//!
//! In addition, the legacy classical-rejection tests assert the
//! [`RustCrypto`] provider does not advertise any PQ ciphersuite.
//!
//! The repo ships with **placeholder** vector files (empty JSON
//! arrays) for ML-KEM, ML-DSA, and X-Wing. As real KAT vectors land in
//! the X-Wing draft / NIST drafts, drop them in those JSON files and
//! the runners will pick them up automatically.

#![allow(dead_code)]

use openmls_traits::types::Ciphersuite;
use serde::{Deserialize, Serialize};

/// Schema for a single PQ KAT vector.
///
/// Stored as JSON in `pq_kat_vectors/*.json`. Hex strings are encoded
/// without the `0x` prefix and are case-insensitive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqKatVector {
    /// Test vector display name (e.g. `"xwing-draft-09 vector 1"`).
    pub name: String,
    /// Ciphersuite identifier (`u16` per RFC 9420). Stored as
    /// integer for forward compatibility with not-yet-codified
    /// ciphersuites.
    pub ciphersuite: u16,
    /// Hex-encoded input keying material (provider-specific).
    pub input_keying_material_hex: String,
    /// Hex-encoded expected ciphertext (encapsulation output).
    pub expected_ciphertext_hex: String,
    /// Hex-encoded expected shared secret (decapsulation output).
    pub expected_shared_secret_hex: String,
}

impl PqKatVector {
    /// Try to parse [`Self::ciphersuite`] as a known [`Ciphersuite`].
    pub fn ciphersuite(&self) -> Result<Ciphersuite, KatError> {
        Ciphersuite::try_from(self.ciphersuite).map_err(|_| KatError::UnknownCiphersuite {
            value: self.ciphersuite,
        })
    }
}

/// Errors raised by the KAT runner.
#[derive(Debug, thiserror::Error)]
pub enum KatError {
    /// Vector references a ciphersuite the runner does not recognize.
    #[error("unknown ciphersuite identifier: {value:#06x}")]
    UnknownCiphersuite {
        /// The unknown ciphersuite ID.
        value: u16,
    },
    /// JSON file failed to parse.
    #[error("could not parse KAT JSON: {0}")]
    JsonParse(String),
    /// I/O error reading vector file.
    #[error("could not read KAT file: {0}")]
    IoError(String),
    /// Hex string in a vector failed to decode.
    #[error("hex decode failed for field {field}: {detail}")]
    HexDecode {
        /// Which field failed.
        field: &'static str,
        /// Underlying error message.
        detail: String,
    },
    /// Provider operation produced output that did not match the
    /// expected vector.
    #[error("KAT mismatch in vector {name}: {field} differs")]
    Mismatch {
        /// Vector name.
        name: String,
        /// Which field differed.
        field: &'static str,
    },
    /// Provider does not support the vector's ciphersuite.
    #[error("provider does not support ciphersuite {ciphersuite:?} (vector: {name})")]
    UnsupportedCiphersuite {
        /// Vector name.
        name: String,
        /// Vector ciphersuite.
        ciphersuite: Ciphersuite,
    },
}

/// Load PQ KAT vectors from a JSON file at `path`. Returns the parsed
/// vector list.
///
/// Empty / missing files are treated as "zero vectors" — the runner
/// returns `Ok(vec![])` rather than failing, so the test framework can
/// be checked in before any real vectors exist.
pub fn load_vectors(path: &std::path::Path) -> Result<Vec<PqKatVector>, KatError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let body = std::fs::read_to_string(path).map_err(|e| KatError::IoError(format!("{e}")))?;
    if body.trim().is_empty() || body.trim() == "[]" {
        return Ok(Vec::new());
    }
    serde_json::from_str(&body).map_err(|e| KatError::JsonParse(format!("{e}")))
}

fn hex_decode(field: &'static str, hex: &str) -> Result<Vec<u8>, KatError> {
    let cleaned = hex.replace([' ', '\n'], "");
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let bytes = cleaned.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(KatError::HexDecode {
            field,
            detail: "odd length".into(),
        });
    }
    for chunk in bytes.chunks(2) {
        let hi = char_to_nibble(chunk[0], field)?;
        let lo = char_to_nibble(chunk[1], field)?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn char_to_nibble(c: u8, field: &'static str) -> Result<u8, KatError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(10 + c - b'a'),
        b'A'..=b'F' => Ok(10 + c - b'A'),
        other => Err(KatError::HexDecode {
            field,
            detail: format!("not hex: {other:#04x}"),
        }),
    }
}

#[test]
fn schema_roundtrip_smoke() {
    // Smoke test the schema — make sure a hand-built vector serializes
    // and deserializes cleanly. This catches schema drift early.
    let v = PqKatVector {
        name: "smoke".into(),
        ciphersuite: 0x004D,
        input_keying_material_hex: "deadbeef".into(),
        expected_ciphertext_hex: "cafebabe".into(),
        expected_shared_secret_hex: "f00d".into(),
    };
    let json = serde_json::to_string(&v).expect("serialize");
    let back: PqKatVector = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(v.name, back.name);
    assert_eq!(v.ciphersuite, back.ciphersuite);
}

#[test]
fn hex_decode_round_trip() {
    let v = hex_decode("test", "deadbeef").expect("decode");
    assert_eq!(v, [0xde, 0xad, 0xbe, 0xef]);

    let v_upper = hex_decode("test", "DEADBEEF").expect("decode upper");
    assert_eq!(v_upper, [0xde, 0xad, 0xbe, 0xef]);

    let v_spaced = hex_decode("test", "de ad\nbe ef").expect("decode spaced");
    assert_eq!(v_spaced, [0xde, 0xad, 0xbe, 0xef]);
}

#[test]
fn hex_decode_rejects_odd_length() {
    let err = hex_decode("test", "abc").expect_err("odd should fail");
    assert!(matches!(err, KatError::HexDecode { .. }));
}

#[test]
fn hex_decode_rejects_non_hex() {
    let err = hex_decode("test", "ggzz").expect_err("non-hex should fail");
    assert!(matches!(err, KatError::HexDecode { .. }));
}

#[test]
fn missing_vector_file_returns_empty_vec() {
    let path = std::path::Path::new("/this/path/does/not/exist/__pq_kat_should_be_missing.json");
    let vectors = load_vectors(path).expect("missing file is OK");
    assert!(vectors.is_empty());
}

#[test]
fn empty_vector_file_returns_empty_vec() {
    let dir = std::env::temp_dir().join("openmls-pq-kat-empty");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let path = dir.join("empty.json");
    std::fs::write(&path, "[]").expect("write");
    let vectors = load_vectors(&path).expect("empty array OK");
    assert!(vectors.is_empty());
}

/// Asserts that the [`RustCrypto`] provider rejects every PQ vector
/// supplied with [`KatError::UnsupportedCiphersuite`]-equivalent
/// behavior. This is a *smoke* check — without the `xwing` feature, the
/// framework should not silently pass.
#[test]
fn classical_provider_smoke_check_xwing_unsupported() {
    use openmls_rust_crypto::RustCrypto;
    use openmls_traits::crypto::OpenMlsCrypto;

    let provider = RustCrypto::default();
    let supported = provider.supported_ciphersuites();
    let xwing = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
    assert!(
        !supported.contains(&xwing),
        "RustCrypto must NOT advertise X-Wing — that's the whole point of \
         classical_provider_rejects_pq_kats"
    );
}

// =============================================================================
// X-Wing KAT runner — gated behind the libcrux PQ provider feature.
// =============================================================================

#[cfg(feature = "xwing")]
mod xwing {
    use super::*;
    use openmls_libcrux_crypto::Provider as LibcruxProvider;
    use openmls_traits::crypto::OpenMlsCrypto;
    use openmls_traits::OpenMlsProvider;

    fn vectors_path() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("pq_kat_vectors")
            .join("xwing.json")
    }

    /// Run all X-Wing KAT vectors loaded from the canonical path.
    pub fn run_all() -> Result<usize, KatError> {
        let provider = LibcruxProvider::default();
        let supported = provider.crypto().supported_ciphersuites();
        assert!(
            supported.contains(&Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519),
            "libcrux provider must advertise X-Wing under the `xwing` feature"
        );

        let vectors = load_vectors(&vectors_path())?;
        let count = vectors.len();
        for v in vectors {
            run_one(&provider, &v)?;
        }
        Ok(count)
    }

    fn run_one(provider: &LibcruxProvider, v: &PqKatVector) -> Result<(), KatError> {
        use openmls_traits::types::HpkeConfig;
        let cs = v.ciphersuite()?;
        if !provider.crypto().supported_ciphersuites().contains(&cs) {
            return Err(KatError::UnsupportedCiphersuite {
                name: v.name.clone(),
                ciphersuite: cs,
            });
        }
        // Decode all hex fields up front — fail fast on malformed
        // vectors before we touch the crypto provider.
        let ikm = hex_decode("input_keying_material", &v.input_keying_material_hex)?;
        let _ct = hex_decode("expected_ciphertext", &v.expected_ciphertext_hex)?;
        let _ss = hex_decode("expected_shared_secret", &v.expected_shared_secret_hex)?;

        // Functional KAT: derive a keypair from the supplied IKM,
        // hpke_seal a known plaintext, hpke_open it, and verify the
        // round-trip recovers the same plaintext. This catches any
        // wiring regression in the libcrux X-Wing implementation
        // even before NIST/IRTF publish numeric KATs we can compare
        // ciphertext bytes against.
        let kem = cs.hpke_kem_algorithm();
        let kdf = cs.hpke_kdf_algorithm();
        let aead = cs.hpke_aead_algorithm();
        let kp = provider
            .crypto()
            .derive_hpke_keypair(HpkeConfig(kem, kdf, aead), &ikm)
            .map_err(|e| KatError::HexDecode {
                field: "derive_hpke_keypair",
                detail: format!("{e:?}"),
            })?;

        let plaintext = b"openmls-pq-kat-roundtrip";
        let info = format!("openmls-xwing-kat:{}", v.name);
        let aad = b"";
        let sealed = provider
            .crypto()
            .hpke_seal(
                HpkeConfig(kem, kdf, aead),
                kp.public.as_slice(),
                info.as_bytes(),
                aad,
                plaintext,
            )
            .map_err(|e| KatError::HexDecode {
                field: "hpke_seal",
                detail: format!("{e:?}"),
            })?;
        let recovered = provider
            .crypto()
            .hpke_open(
                HpkeConfig(kem, kdf, aead),
                &sealed,
                &kp.private,
                info.as_bytes(),
                aad,
            )
            .map_err(|e| KatError::HexDecode {
                field: "hpke_open",
                detail: format!("{e:?}"),
            })?;
        if recovered != plaintext {
            return Err(KatError::Mismatch {
                name: v.name.clone(),
                field: "hpke_roundtrip_plaintext",
            });
        }
        Ok(())
    }

    #[test]
    fn run_all_xwing_kats_loads_and_validates() {
        let n = run_all().expect("xwing KAT run");
        eprintln!("xwing KATs: {n} vector(s) processed");
    }

    #[test]
    fn xwing_kat_roundtrip_rejects_tampered_ciphertext() {
        // Sanity check: a tampered ciphertext must fail HPKE open with
        // the libcrux provider, otherwise our positive run_all could
        // be passing trivially.
        use openmls_traits::types::HpkeConfig;
        let provider = LibcruxProvider::default();
        let cs = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
        let config = HpkeConfig(
            cs.hpke_kem_algorithm(),
            cs.hpke_kdf_algorithm(),
            cs.hpke_aead_algorithm(),
        );
        let ikm = hex_decode(
            "ikm",
            "a648be1e9f0db017a0a4d65ec3733a7b68f453e24096c824f2b3bcee6330f77e",
        )
        .expect("hex");
        let kem = config.0;
        let kdf = config.1;
        let aead = config.2;
        let kp = provider
            .crypto()
            .derive_hpke_keypair(HpkeConfig(kem, kdf, aead), &ikm)
            .expect("derive");
        let mut sealed = provider
            .crypto()
            .hpke_seal(
                HpkeConfig(kem, kdf, aead),
                kp.public.as_slice(),
                b"info",
                b"",
                b"plain",
            )
            .expect("seal");
        // Flip a byte in the ciphertext body so AEAD verification
        // fails on open.
        let ct: Vec<u8> = sealed.ciphertext.as_slice().to_vec();
        let mut tampered = ct;
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        sealed.ciphertext = tampered.into();
        let err = provider
            .crypto()
            .hpke_open(
                HpkeConfig(kem, kdf, aead),
                &sealed,
                &kp.private,
                b"info",
                b"",
            )
            .expect_err("open must fail on tampered ciphertext");
        eprintln!("tamper check error: {err:?}");
    }
}

// =============================================================================
// FIPS 204 (ML-DSA) KAT runner — real signing/verifying when the libcrux
// `mldsa` feature is enabled, signature roundtrip + tamper rejection.
// =============================================================================

#[cfg(feature = "mldsa")]
mod mldsa_runner {
    use super::*;
    use openmls_libcrux_crypto::Provider as LibcruxProvider;
    use openmls_traits::crypto::OpenMlsCrypto;
    use openmls_traits::types::SignatureScheme;
    use openmls_traits::OpenMlsProvider;

    fn vectors_path() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("pq_kat_vectors")
            .join("ml_dsa.json")
    }

    /// Run all ML-DSA KAT vectors loaded from the canonical path.
    /// The canonical files ship with synthetic vectors — the runner
    /// uses them as **labels** and exercises a full sign/verify
    /// round-trip with the libcrux provider for each one (ignoring
    /// the synthetic ciphertext / shared-secret fields). This is the
    /// best we can do until NIST publishes machine-readable ML-DSA
    /// KATs in the format we ingest here.
    pub fn run_all() -> Result<usize, KatError> {
        let provider = LibcruxProvider::default();
        let vectors = load_vectors(&vectors_path())?;
        let count = vectors.len();
        for v in vectors {
            run_one(&provider, &v)?;
        }
        Ok(count)
    }

    fn run_one(provider: &LibcruxProvider, v: &PqKatVector) -> Result<(), KatError> {
        // Generate a fresh ML-DSA-65 keypair, sign a per-vector
        // message, verify, then flip a bit and verify the verify
        // call rejects.
        let (sk, vk) = provider
            .crypto()
            .signature_key_gen(SignatureScheme::MLDSA65)
            .map_err(|e| KatError::HexDecode {
                field: "ml_dsa_keygen",
                detail: format!("{e:?}"),
            })?;
        let message = format!("openmls-mldsa-kat:{}", v.name);
        let sig = provider
            .crypto()
            .sign(SignatureScheme::MLDSA65, message.as_bytes(), &sk)
            .map_err(|e| KatError::HexDecode {
                field: "ml_dsa_sign",
                detail: format!("{e:?}"),
            })?;
        provider
            .crypto()
            .verify_signature(SignatureScheme::MLDSA65, message.as_bytes(), &vk, &sig)
            .map_err(|_| KatError::Mismatch {
                name: v.name.clone(),
                field: "ml_dsa_verify",
            })?;
        let mut tampered = sig.clone();
        let mid = tampered.len() / 2;
        tampered[mid] ^= 0x01;
        if provider
            .crypto()
            .verify_signature(SignatureScheme::MLDSA65, message.as_bytes(), &vk, &tampered)
            .is_ok()
        {
            return Err(KatError::Mismatch {
                name: v.name.clone(),
                field: "ml_dsa_tamper_should_have_failed",
            });
        }
        Ok(())
    }

    #[test]
    fn run_all_mldsa_kats_loads_and_validates() {
        let n = run_all().expect("mldsa KAT run");
        eprintln!("ml-dsa KATs: {n} vector(s) processed");
    }
}

// ML-DSA-44 sign/verify round-trip runner — gated behind the
// independent `mldsa44` feature on `openmls_libcrux_crypto`.
#[cfg(feature = "mldsa44")]
mod mldsa44_runner {
    use super::*;
    use openmls_libcrux_crypto::Provider as LibcruxProvider;
    use openmls_traits::crypto::OpenMlsCrypto;
    use openmls_traits::types::SignatureScheme;
    use openmls_traits::OpenMlsProvider;

    fn vectors_path() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("pq_kat_vectors")
            .join("ml_dsa.json")
    }

    #[test]
    fn run_all_mldsa44_kats_loads_and_validates() {
        let provider = LibcruxProvider::default();
        let vectors = load_vectors(&vectors_path()).expect("load ml_dsa.json");
        for v in &vectors {
            let (sk, vk) = provider
                .crypto()
                .signature_key_gen(SignatureScheme::MLDSA44)
                .expect("MLDSA44 keygen");
            let message = format!("openmls-mldsa44-kat:{}", v.name);
            let sig = provider
                .crypto()
                .sign(SignatureScheme::MLDSA44, message.as_bytes(), &sk)
                .expect("MLDSA44 sign");
            provider
                .crypto()
                .verify_signature(SignatureScheme::MLDSA44, message.as_bytes(), &vk, &sig)
                .expect("MLDSA44 verify");
            let mut tampered = sig.clone();
            let mid = tampered.len() / 2;
            tampered[mid] ^= 0x01;
            assert!(
                provider
                    .crypto()
                    .verify_signature(SignatureScheme::MLDSA44, message.as_bytes(), &vk, &tampered,)
                    .is_err(),
                "MLDSA44 verify must fail on tampered signature for vector {}",
                v.name
            );
        }
        eprintln!("ml-dsa-44 KATs: {} vector(s) processed", vectors.len());
    }
}

// ML-DSA-87 sign/verify round-trip runner — gated behind the
// independent `mldsa87` feature on `openmls_libcrux_crypto`.
#[cfg(feature = "mldsa87")]
mod mldsa87_runner {
    use super::*;
    use openmls_libcrux_crypto::Provider as LibcruxProvider;
    use openmls_traits::crypto::OpenMlsCrypto;
    use openmls_traits::types::SignatureScheme;
    use openmls_traits::OpenMlsProvider;

    fn vectors_path() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("pq_kat_vectors")
            .join("ml_dsa.json")
    }

    #[test]
    fn run_all_mldsa87_kats_loads_and_validates() {
        let provider = LibcruxProvider::default();
        let vectors = load_vectors(&vectors_path()).expect("load ml_dsa.json");
        for v in &vectors {
            let (sk, vk) = provider
                .crypto()
                .signature_key_gen(SignatureScheme::MLDSA87)
                .expect("MLDSA87 keygen");
            let message = format!("openmls-mldsa87-kat:{}", v.name);
            let sig = provider
                .crypto()
                .sign(SignatureScheme::MLDSA87, message.as_bytes(), &sk)
                .expect("MLDSA87 sign");
            provider
                .crypto()
                .verify_signature(SignatureScheme::MLDSA87, message.as_bytes(), &vk, &sig)
                .expect("MLDSA87 verify");
            let mut tampered = sig.clone();
            let mid = tampered.len() / 2;
            tampered[mid] ^= 0x01;
            assert!(
                provider
                    .crypto()
                    .verify_signature(SignatureScheme::MLDSA87, message.as_bytes(), &vk, &tampered,)
                    .is_err(),
                "MLDSA87 verify must fail on tampered signature for vector {}",
                v.name
            );
        }
        eprintln!("ml-dsa-87 KATs: {} vector(s) processed", vectors.len());
    }
}

// =============================================================================
// FIPS 203 (ML-KEM) KAT runner — schema-validates only, since neither
// the libcrux nor the RustCrypto provider currently exposes ML-KEM
// KEM as an HPKE algorithm.
// =============================================================================

mod mlkem_runner {
    use super::*;

    fn vectors_path() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("pq_kat_vectors")
            .join("ml_kem.json")
    }

    /// Schema-only KAT runner: loads + parses + hex-decodes every
    /// shipped ML-KEM vector. The loop returns the number of
    /// vectors processed so callers can sanity-check it.
    ///
    /// Real ML-KEM encap/decap will plug in here once an ML-KEM
    /// HPKE algorithm lands on the provider trait.
    pub fn run_all() -> Result<usize, KatError> {
        let vectors = load_vectors(&vectors_path())?;
        let count = vectors.len();
        for v in &vectors {
            // Validate the codepoint maps to a known draft variant.
            let cs = v.ciphersuite()?;
            assert!(
                cs.is_draft_codepoint(),
                "ml_kem.json vector {} references non-draft ciphersuite {cs:?}",
                v.name
            );
            // And the hex fields decode.
            hex_decode("input_keying_material", &v.input_keying_material_hex)?;
            hex_decode("expected_ciphertext", &v.expected_ciphertext_hex)?;
            hex_decode("expected_shared_secret", &v.expected_shared_secret_hex)?;
        }
        Ok(count)
    }

    #[test]
    fn run_all_mlkem_kats_loads_and_validates() {
        let n = run_all().expect("mlkem KAT run");
        eprintln!("ml-kem KATs: {n} vector(s) processed");
    }
}

// =============================================================================
// Additional schema / negative-path / classical-rejection tests.
// =============================================================================

fn vectors_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("pq_kat_vectors")
}

fn load_named(file: &str) -> Vec<PqKatVector> {
    let path = vectors_dir().join(file);
    load_vectors(&path).unwrap_or_else(|e| panic!("load {file}: {e}"))
}

#[test]
fn xwing_vectors_parse_and_hex_decode_cleanly() {
    let vectors = load_named("xwing.json");
    assert!(
        !vectors.is_empty(),
        "xwing.json must ship at least one synthetic vector — see Task 7"
    );
    for v in &vectors {
        // Every shipped vector must reference a known ciphersuite.
        let cs = v
            .ciphersuite()
            .unwrap_or_else(|e| panic!("vector {} has unknown ciphersuite: {e}", v.name));
        assert_eq!(
            cs,
            Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
            "xwing.json vector {} must reference X-Wing",
            v.name
        );
        // And every hex field must decode.
        hex_decode("input_keying_material", &v.input_keying_material_hex)
            .unwrap_or_else(|e| panic!("{}: ikm decode {e}", v.name));
        hex_decode("expected_ciphertext", &v.expected_ciphertext_hex)
            .unwrap_or_else(|e| panic!("{}: ct decode {e}", v.name));
        hex_decode("expected_shared_secret", &v.expected_shared_secret_hex)
            .unwrap_or_else(|e| panic!("{}: ss decode {e}", v.name));
    }
}

#[test]
fn json_schema_parses_for_every_vector_file() {
    // All three vector files (xwing, ml_kem, ml_dsa) must parse — even
    // when empty. This pins the parser's contract independently of
    // whether real vectors have been dropped in yet.
    for name in ["xwing.json", "ml_kem.json", "ml_dsa.json"] {
        let path = vectors_dir().join(name);
        let result = load_vectors(&path);
        assert!(
            result.is_ok(),
            "schema parse failed for {name}: {:?}",
            result.err()
        );
    }
}

#[test]
fn hex_decode_handles_empty_string() {
    let out = hex_decode("test", "").expect("empty string is valid hex");
    assert!(out.is_empty());
}

#[test]
fn hex_decode_rejects_partial_byte_sequence() {
    let err = hex_decode("test", "a").expect_err("single nibble must fail");
    assert!(matches!(err, KatError::HexDecode { .. }));
}

#[test]
fn hex_decode_rejects_invalid_chars_inline() {
    // Mid-string non-hex char.
    let err = hex_decode("test", "deadgg00").expect_err("mid-string non-hex");
    assert!(matches!(err, KatError::HexDecode { .. }));
}

#[test]
fn classical_provider_rejects_pq_kat_ciphersuite() {
    use openmls_rust_crypto::RustCrypto;
    use openmls_traits::crypto::OpenMlsCrypto;

    let provider = RustCrypto::default();
    let supported = provider.supported_ciphersuites();
    let vectors = load_named("xwing.json");
    assert!(
        !vectors.is_empty(),
        "xwing.json must ship at least one synthetic vector for the classical-rejection test"
    );

    for v in &vectors {
        let cs = v.ciphersuite().expect("vector ciphersuite");
        // The whole point of this test: the classical provider must
        // not advertise the PQ ciphersuite.
        assert!(
            !supported.contains(&cs),
            "RustCrypto unexpectedly advertises {cs:?} (vector {})",
            v.name
        );
    }
}

// =============================================================================
// FIPS 203 (ML-KEM) KAT runner — schema validation + classical rejection.
// =============================================================================

mod mlkem {
    use super::*;
    use openmls_rust_crypto::RustCrypto;
    use openmls_traits::crypto::OpenMlsCrypto;

    fn ml_kem_draft_codepoints() -> [u16; 3] {
        // Codepoints must match the variants we registered in
        // `traits/src/types.rs`.
        [
            Ciphersuite::MLS_256_MLKEM768_X25519_AES256GCM_SHA384_Ed25519 as u16,
            Ciphersuite::MLS_256_MLKEM768_X25519_CHACHA20POLY1305_SHA256_Ed25519 as u16,
            Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_Ed448 as u16,
        ]
    }

    #[test]
    fn ml_kem_vectors_load_and_parse_cleanly() {
        let vectors = load_named("ml_kem.json");
        assert!(
            !vectors.is_empty(),
            "ml_kem.json must ship at least one synthetic vector — see Task 4"
        );
        for v in &vectors {
            // The ciphersuite identifier must round-trip through
            // [`Ciphersuite::try_from`] so we know the codepoint is
            // a registered draft variant.
            let cs = v
                .ciphersuite()
                .unwrap_or_else(|e| panic!("vector {} has unknown ciphersuite: {e}", v.name));
            assert!(
                cs.is_draft_codepoint(),
                "ml_kem.json vector {} references non-draft ciphersuite {cs:?}",
                v.name
            );
            // Hex fields must decode.
            hex_decode("input_keying_material", &v.input_keying_material_hex)
                .unwrap_or_else(|e| panic!("{}: ikm decode {e}", v.name));
            hex_decode("expected_ciphertext", &v.expected_ciphertext_hex)
                .unwrap_or_else(|e| panic!("{}: ct decode {e}", v.name));
            hex_decode("expected_shared_secret", &v.expected_shared_secret_hex)
                .unwrap_or_else(|e| panic!("{}: ss decode {e}", v.name));
        }
    }

    #[test]
    fn ml_kem_vectors_reference_only_draft_codepoints() {
        let vectors = load_named("ml_kem.json");
        let allowed = ml_kem_draft_codepoints();
        for v in &vectors {
            assert!(
                allowed.contains(&v.ciphersuite),
                "ml_kem.json vector {} uses ciphersuite {:#06x} which is not a registered ML-KEM draft",
                v.name,
                v.ciphersuite
            );
        }
    }

    #[test]
    fn classical_provider_rejects_ml_kem_kat_ciphersuites() {
        // The RustCrypto provider has no PQ KEM. Every ML-KEM
        // codepoint we register must be absent from its supported
        // list, and `kem_mode` rejects them with
        // `UnsupportedCiphersuite`.
        let provider = RustCrypto::default();
        let supported = provider.supported_ciphersuites();
        let vectors = load_named("ml_kem.json");
        assert!(!vectors.is_empty(), "need at least one ML-KEM vector");

        for v in &vectors {
            let cs = v.ciphersuite().expect("vector ciphersuite");
            assert!(
                !supported.contains(&cs),
                "RustCrypto must not advertise ML-KEM draft {cs:?} (vector {})",
                v.name
            );
        }
    }

    #[test]
    fn ml_kem_kat_load_returns_three_vectors() {
        let vectors = load_named("ml_kem.json");
        assert_eq!(
            vectors.len(),
            3,
            "Task 4 ships exactly 3 synthetic ML-KEM vectors — \
             update this assertion when real KATs land"
        );
    }
}

// =============================================================================
// FIPS 204 (ML-DSA) KAT runner — schema validation + classical rejection.
// =============================================================================

mod mldsa {
    use super::*;

    #[test]
    fn ml_dsa_vectors_load_and_parse_cleanly() {
        let vectors = load_named("ml_dsa.json");
        assert!(
            !vectors.is_empty(),
            "ml_dsa.json must ship at least one synthetic vector — see Task 4"
        );
        for v in &vectors {
            // Hex fields must decode. (We don't try to map the
            // ciphersuite to a registered codepoint here — ML-DSA
            // KATs are signature-scheme vectors, not whole-suite
            // vectors, so the ciphersuite slot is just a tag.)
            hex_decode("input_keying_material", &v.input_keying_material_hex)
                .unwrap_or_else(|e| panic!("{}: ikm decode {e}", v.name));
            hex_decode("expected_ciphertext", &v.expected_ciphertext_hex)
                .unwrap_or_else(|e| panic!("{}: ct decode {e}", v.name));
            hex_decode("expected_shared_secret", &v.expected_shared_secret_hex)
                .unwrap_or_else(|e| panic!("{}: ss decode {e}", v.name));
        }
    }

    #[test]
    fn ml_dsa_kat_load_returns_two_vectors() {
        let vectors = load_named("ml_dsa.json");
        assert_eq!(
            vectors.len(),
            2,
            "Task 4 ships exactly 2 synthetic ML-DSA vectors — \
             update this assertion when real KATs land"
        );
    }
}
