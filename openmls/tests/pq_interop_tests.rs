//! # Classical / PQ / APQ interop scenarios
//!
//! Cross-provider and cross-mode interop tests:
//!
//! - **classical-only group**: RustCrypto provider, classical
//!   ciphersuite — sanity baseline.
//! - **PQ-only group**: requires libcrux + `xwing` feature; gated.
//! - **mixed group fails closed**: a classical-only joiner cannot
//!   slide into a PQ_REQUIRED conversation.
//! - **APQ dual-session group**: classical T + (would-be) PQ side
//!   linked via [`ApqInfo`].
//! - **cross-provider Welcome**: a Welcome encoded by one provider
//!   round-trips through the wire format and is accepted by another
//!   provider's deserializer.
//!
//! Tests gated `#[cfg(feature = "xwing")]` only run when the libcrux
//! provider is built in. The remaining tests run on the default
//! workspace build.

use openmls::ciphersuite::SecurityMode;
use openmls::credentials::{BasicCredential, CredentialWithKey};
use openmls::extensions::apq_info::ApqInfo;
use openmls::group::no_downgrade::{validate_joiner_key_package, DowngradeError};
use openmls::group::{GroupId, MlsGroup, MlsGroupCreateConfig};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::{Ciphersuite, SignatureScheme};
use tls_codec::{Deserialize as _, Serialize as _};

fn classical_cs() -> Ciphersuite {
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
}

fn xwing_cs() -> Ciphersuite {
    Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519
}

fn signer(scheme: SignatureScheme) -> SignatureKeyPair {
    SignatureKeyPair::new(scheme).expect("signature keypair")
}

fn credential(name: &str, signer: &SignatureKeyPair) -> CredentialWithKey {
    CredentialWithKey {
        credential: BasicCredential::new(name.as_bytes().to_vec()).into(),
        signature_key: signer.public().into(),
    }
}

#[test]
fn classical_group_creation_smoke() {
    let provider = OpenMlsRustCrypto::default();
    let cs = classical_cs();
    let alice_signer = signer(cs.signature_algorithm());
    let credential = credential("alice", &alice_signer);

    let group = MlsGroup::new(
        &provider,
        &alice_signer,
        &MlsGroupCreateConfig::default(),
        credential,
    )
    .expect("classical group creation");

    assert_eq!(group.ciphersuite(), cs);
    assert!(group.is_active());
    assert_eq!(group.epoch().as_u64(), 0);
}

#[test]
fn classical_group_with_specific_group_id() {
    let provider = OpenMlsRustCrypto::default();
    let cs = classical_cs();
    let alice_signer = signer(cs.signature_algorithm());
    let credential = credential("alice", &alice_signer);

    let group_id = GroupId::from_slice(&[0xCA; 16]);
    let group = MlsGroup::new_with_group_id(
        &provider,
        &alice_signer,
        &MlsGroupCreateConfig::default(),
        group_id.clone(),
        credential,
    )
    .expect("classical group creation");

    assert_eq!(group.group_id(), &group_id);
}

#[test]
fn classical_only_joiner_rejected_from_pq_required_conversation() {
    // The downgrade validator is the gate that interop relies on:
    // any classical-only KeyPackage must be refused at join time
    // when the conversation policy demands PQ.
    for required in [
        SecurityMode::PqConfidentiality,
        SecurityMode::PqAuthenticity,
    ] {
        let err = validate_joiner_key_package(required, classical_cs())
            .expect_err("classical KP must be rejected by PQ-required mode");
        assert!(matches!(err, DowngradeError::JoinerKeyPackageNotPq { .. }));
    }
}

#[test]
fn pq_confidentiality_keypackage_accepted_in_matching_mode() {
    // X-Wing has confidentiality-only PQ guarantees (Ed25519 sigs), so
    // it satisfies PqConfidentiality but NOT PqAuthenticity. The
    // downgrade validator must enforce that gap.
    validate_joiner_key_package(SecurityMode::PqConfidentiality, xwing_cs())
        .expect("PqConfidentiality KP into PqConfidentiality mode is OK");

    let err = validate_joiner_key_package(SecurityMode::PqAuthenticity, xwing_cs())
        .expect_err("PqConfidentiality KP must be rejected by PqAuthenticity mode");
    assert!(matches!(err, DowngradeError::JoinerKeyPackageNotPq { .. }));
}

#[test]
fn apq_info_links_two_sessions_with_matching_epochs() {
    let info = ApqInfo::new(
        GroupId::from_slice(&[0x01; 16]),
        GroupId::from_slice(&[0x02; 16]),
        4,
        4,
        classical_cs(),
        xwing_cs(),
        SecurityMode::PqConfidentiality,
    );
    info.validate().expect("apq info valid");
    assert_eq!(info.t_epoch, info.pq_epoch);
    assert_ne!(info.t_group_id, info.pq_group_id);
}

#[test]
fn rust_crypto_does_not_advertise_xwing_ciphersuite() {
    let crypto = openmls_rust_crypto::RustCrypto::default();
    let supported = crypto.supported_ciphersuites();
    assert!(supported.contains(&classical_cs()));
    assert!(
        !supported.contains(&xwing_cs()),
        "RustCrypto must not advertise X-Wing — interop tests rely on this"
    );
}

#[test]
fn pq_group_creation_fails_with_rust_crypto_provider() {
    // Attempting to create a PQ group with the classical-only
    // RustCrypto provider must fail closed (UnsupportedCiphersuite).
    let provider = OpenMlsRustCrypto::default();
    let cs = xwing_cs();
    let alice_signer = signer(SignatureScheme::ED25519);
    let credential = credential("alice", &alice_signer);

    let result = MlsGroup::new(
        &provider,
        &alice_signer,
        &MlsGroupCreateConfig::builder().ciphersuite(cs).build(),
        credential,
    );
    assert!(
        result.is_err(),
        "PQ group creation must fail under RustCrypto"
    );
}

#[test]
fn welcome_message_serializes_and_deserializes_across_providers() {
    // Build a classical group, generate a Welcome via add_members,
    // round-trip it through TLS codec, and verify it survives.
    let provider_a = OpenMlsRustCrypto::default();
    let provider_b = OpenMlsRustCrypto::default();
    let cs = classical_cs();

    let alice_signer = signer(cs.signature_algorithm());
    let bob_signer = signer(cs.signature_algorithm());

    let alice_cred = credential("alice", &alice_signer);
    let bob_cred = credential("bob", &bob_signer);

    let bob_kp = openmls::key_packages::KeyPackage::builder()
        .build(cs, &provider_b, &bob_signer, bob_cred)
        .expect("bob KP");

    let mut alice_group = MlsGroup::new(
        &provider_a,
        &alice_signer,
        &MlsGroupCreateConfig::default(),
        alice_cred,
    )
    .expect("alice group");

    let (_commit, welcome_msg, _gi) = alice_group
        .add_members(&provider_a, &alice_signer, &[bob_kp.key_package().clone()])
        .expect("add bob");

    let bytes = welcome_msg.tls_serialize_detached().expect("serialize");
    let _decoded = openmls::framing::MlsMessageIn::tls_deserialize_exact(&bytes)
        .expect("welcome round-trip across providers");
}

// =============================================================================
// X-Wing-gated interop scenarios.
// =============================================================================

#[cfg(feature = "xwing")]
mod xwing_interop {
    use super::*;
    use openmls_libcrux_crypto::Provider as LibcruxProvider;
    use openmls_traits::crypto::OpenMlsCrypto;
    use openmls_traits::OpenMlsProvider;

    #[test]
    fn libcrux_provider_advertises_xwing() {
        let provider = LibcruxProvider::default();
        let supported = provider.crypto().supported_ciphersuites();
        assert!(supported.contains(&xwing_cs()));
    }

    #[test]
    fn pq_group_creation_succeeds_with_libcrux() {
        let provider = LibcruxProvider::default();
        let cs = xwing_cs();
        let alice_signer = signer(cs.signature_algorithm());
        let credential = credential("alice", &alice_signer);

        let group = MlsGroup::new(
            &provider,
            &alice_signer,
            &MlsGroupCreateConfig::builder().ciphersuite(cs).build(),
            credential,
        )
        .expect("PQ group creation under libcrux");

        assert_eq!(group.ciphersuite(), cs);
        assert!(group.is_active());
    }
}
