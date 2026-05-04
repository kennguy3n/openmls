//! Integration tests for the PQ capability advertisement and security-mode
//! selection layer.
//!
//! These tests live outside the `openmls` crate so they exercise the public
//! API the same way a downstream KChat orchestration layer would.

use openmls::ciphersuite::SecurityMode;
use openmls::credentials::errors::CredentialError;
use openmls::credentials::DeviceCapability;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::{Ciphersuite, SignatureScheme};
use tls_codec::{Deserialize as _, Serialize as _};

fn classical_suites() -> Vec<Ciphersuite> {
    vec![
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
    ]
}

fn xwing_suites() -> Vec<Ciphersuite> {
    vec![Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519]
}

fn pq_capability(provider_id: &str, pq_auth: bool) -> DeviceCapability {
    DeviceCapability::new(
        1,
        classical_suites(),
        xwing_suites(),
        true,
        pq_auth,
        provider_id.to_string(),
    )
}

fn classical_capability(provider_id: &str) -> DeviceCapability {
    DeviceCapability::new(
        1,
        classical_suites(),
        vec![],
        false,
        false,
        provider_id.to_string(),
    )
}

#[test]
fn test_device_capability_roundtrip() {
    let cap = pq_capability("libcrux", false);
    let bytes = cap.tls_serialize_detached().expect("serialize");
    let decoded = DeviceCapability::tls_deserialize_exact(&bytes).expect("deserialize");
    assert_eq!(cap, decoded);

    // And after signing.
    let crypto = RustCrypto::default();
    let (private, _public) = crypto
        .signature_key_gen(SignatureScheme::ED25519)
        .expect("keygen");
    let mut signed = pq_capability("libcrux", true);
    signed
        .sign(SignatureScheme::ED25519, &private, &crypto)
        .expect("sign");
    let signed_bytes = signed.tls_serialize_detached().expect("serialize");
    let signed_decoded =
        DeviceCapability::tls_deserialize_exact(&signed_bytes).expect("deserialize");
    assert_eq!(signed, signed_decoded);
}

#[test]
fn test_device_capability_sign_verify() {
    let crypto = RustCrypto::default();
    let (private, public) = crypto
        .signature_key_gen(SignatureScheme::ED25519)
        .expect("keygen");

    let mut cap = pq_capability("libcrux", false);
    assert!(!cap.is_signed());

    cap.sign(SignatureScheme::ED25519, &private, &crypto)
        .expect("sign");
    assert!(cap.is_signed());
    cap.verify(SignatureScheme::ED25519, &public, &crypto)
        .expect("verify");

    // Tamper with a non-signature field and re-verify — must fail.
    let mut tampered = cap.clone();
    tampered.provider_id = "rustcrypto".to_string();
    assert!(matches!(
        tampered.verify(SignatureScheme::ED25519, &public, &crypto),
        Err(CredentialError::InvalidSignature)
    ));

    // Tamper with the signature itself.
    let mut bad_sig = cap.clone();
    let mut sig_bytes = bad_sig.capability_signature.as_slice().to_vec();
    if let Some(byte) = sig_bytes.first_mut() {
        *byte ^= 0xFF;
    }
    bad_sig.capability_signature = sig_bytes.into();
    assert!(matches!(
        bad_sig.verify(SignatureScheme::ED25519, &public, &crypto),
        Err(CredentialError::InvalidSignature)
    ));
}

#[test]
fn test_best_common_ciphersuite_all_pq() {
    let a = pq_capability("libcrux", false);
    let b = pq_capability("libcrux", false);
    let chosen = DeviceCapability::best_common_ciphersuite(&[&a, &b]);
    assert_eq!(
        chosen,
        Some(Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519),
        "all-PQ-capable peers should prefer the PQ suite"
    );
}

#[test]
fn test_best_common_ciphersuite_mixed() {
    let pq = pq_capability("libcrux", false);
    let classical = classical_capability("rustcrypto");
    let chosen = DeviceCapability::best_common_ciphersuite(&[&pq, &classical]);
    assert_eq!(
        chosen,
        Some(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519),
        "one classical-only peer should force a classical suite"
    );
}

#[test]
fn test_security_mode_selection() {
    let pq_auth = pq_capability("libcrux", true);
    let pq_conf = pq_capability("libcrux", false);
    let classical = classical_capability("rustcrypto");

    // All peers PQ-auth → PqAuthenticity.
    assert_eq!(
        SecurityMode::select_mode(&[&pq_auth, &pq_auth]),
        SecurityMode::PqAuthenticity
    );

    // Mix of PQ-auth and PQ-conf → degrades to PqConfidentiality.
    assert_eq!(
        SecurityMode::select_mode(&[&pq_auth, &pq_conf]),
        SecurityMode::PqConfidentiality
    );

    // Any classical-only peer → degrades all the way to Classical.
    assert_eq!(
        SecurityMode::select_mode(&[&pq_auth, &classical]),
        SecurityMode::Classical
    );
    assert_eq!(
        SecurityMode::select_mode(&[&pq_conf, &classical]),
        SecurityMode::Classical
    );

    // Empty peer set → Classical (nothing to upgrade with).
    assert_eq!(SecurityMode::select_mode(&[]), SecurityMode::Classical);
}

#[test]
fn test_no_downgrade() {
    // The headline assertion: never go from PqConfidentiality back to
    // Classical.
    assert!(!SecurityMode::allows_transition(
        SecurityMode::PqConfidentiality,
        SecurityMode::Classical
    ));

    // Same for PqAuthenticity.
    assert!(!SecurityMode::allows_transition(
        SecurityMode::PqAuthenticity,
        SecurityMode::PqConfidentiality
    ));
    assert!(!SecurityMode::allows_transition(
        SecurityMode::PqAuthenticity,
        SecurityMode::Classical
    ));

    // Upgrades and equal transitions are fine.
    assert!(SecurityMode::allows_transition(
        SecurityMode::Classical,
        SecurityMode::PqConfidentiality
    ));
    assert!(SecurityMode::allows_transition(
        SecurityMode::Classical,
        SecurityMode::PqAuthenticity
    ));
    assert!(SecurityMode::allows_transition(
        SecurityMode::PqConfidentiality,
        SecurityMode::PqAuthenticity
    ));
    assert!(SecurityMode::allows_transition(
        SecurityMode::Classical,
        SecurityMode::Classical
    ));
}

#[test]
fn test_security_mode_ordering() {
    assert!(SecurityMode::Classical < SecurityMode::PqConfidentiality);
    assert!(SecurityMode::PqConfidentiality < SecurityMode::PqAuthenticity);
    assert!(SecurityMode::Classical < SecurityMode::PqAuthenticity);

    // And the same as repr(u8).
    assert_eq!(SecurityMode::Classical as u8, 0);
    assert_eq!(SecurityMode::PqConfidentiality as u8, 1);
    assert_eq!(SecurityMode::PqAuthenticity as u8, 2);
}
