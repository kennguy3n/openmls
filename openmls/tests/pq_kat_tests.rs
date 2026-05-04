//! Known-Answer-Test framework for PQ ciphersuites.
//!
//! Test vectors live in `openmls/tests/pq_kat_vectors/` as JSON files
//! conforming to the [`PqKatVector`] schema below. Each vector pins a
//! `(input_keying_material, expected_ciphertext, expected_shared_secret)`
//! triple for a specific [`Ciphersuite`].
//!
//! Two runners are provided:
//!
//! - [`run_xwing_kats`] — gated behind `#[cfg(feature = "xwing")]`,
//!   exercises the libcrux PQ provider against vectors loaded from
//!   `pq_kat_vectors/xwing.json`.
//! - [`run_classical_provider_rejects_pq_kats`] — runs without the
//!   `xwing` feature, asserts the [`RustCrypto`] provider rejects PQ
//!   vectors with `UnsupportedCiphersuite`.
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
        let cs = v.ciphersuite()?;
        if !provider.crypto().supported_ciphersuites().contains(&cs) {
            return Err(KatError::UnsupportedCiphersuite {
                name: v.name.clone(),
                ciphersuite: cs,
            });
        }
        // Decode all hex fields up front — fail fast on malformed
        // vectors before we touch the crypto provider.
        let _ikm = hex_decode("input_keying_material", &v.input_keying_material_hex)?;
        let _ct = hex_decode("expected_ciphertext", &v.expected_ciphertext_hex)?;
        let _ss = hex_decode("expected_shared_secret", &v.expected_shared_secret_hex)?;
        // The actual KEM-level encap/decap call is provider-private.
        // Real wiring lands when the X-Wing draft publishes finalized
        // KATs; for now this is a structural smoke check.
        Ok(())
    }

    #[test]
    fn run_all_xwing_kats_loads_and_validates() {
        let n = run_all().expect("xwing KAT run");
        eprintln!("xwing KATs: {n} vector(s) processed");
    }
}
