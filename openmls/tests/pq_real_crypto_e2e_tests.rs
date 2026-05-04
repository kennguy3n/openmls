//! End-to-end APQ orchestration tests using **real** PQ crypto from
//! the libcrux provider with the `xwing` feature.
//!
//! Unlike `pq_apq_e2e_tests.rs` (which uses RustCrypto + classical
//! ciphersuites in both T and PQ slots to exercise the orchestration
//! contract), this file actually drives an X-Wing-backed PQ
//! `MlsGroup` so the full crypto path — KeyPackage generation,
//! Welcome encryption with a hybrid KEM, and ratchet tree progression
//! — is exercised.
//!
//! The whole file is gated behind `#[cfg(feature = "xwing")]` so it
//! only runs when the libcrux PQ provider is available. CI invokes it
//! via:
//!
//! ```text
//! cargo test -p openmls --features xwing,libcrux-provider \
//!     --test pq_real_crypto_e2e_tests
//! ```
//!
//! Coverage:
//!
//! - Classical + PQ KeyPackages can be generated for an X-Wing-capable
//!   capability through the public `MultiCiphersuiteKeyPackages` API.
//! - A two-member classical `MlsGroup` can be bootstrapped to APQ
//!   with an X-Wing PQ `MlsGroup`, producing a valid
//!   [`KChatMlsConversation::is_apq`] state.
//! - [`detect_desync`] returns [`DesyncStatus::InSync`] on the freshly
//!   bootstrapped conversation.
//! - The pinned-ciphersuite no-downgrade validator accepts the
//!   PQ-mode ciphersuite of the just-bootstrapped APQ session.

#![cfg(feature = "xwing")]

use openmls::ciphersuite::SecurityMode;
use openmls::credentials::{BasicCredential, CredentialWithKey, DeviceCapability};
use openmls::group::apq_resync::{detect_desync, DesyncStatus};
use openmls::group::kchat_conversation::KChatMlsConversation;
use openmls::group::pq_policy::PqPolicy;
use openmls::group::{validate_ciphersuite_pin, ConversationSecurityState};
use openmls::group::{MlsGroup, MlsGroupCreateConfig};
use openmls::key_packages::multi_ciphersuite::MultiCiphersuiteKeyPackages;
use openmls_basic_credential::SignatureKeyPair;
use openmls_libcrux_crypto::Provider as LibcruxProvider;
use openmls_traits::types::{Ciphersuite, SignatureScheme};

const CLASSICAL_CS: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const PQ_CS: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

fn signer() -> SignatureKeyPair {
    SignatureKeyPair::new(SignatureScheme::ED25519).expect("ED25519 keypair")
}

fn credential(name: &[u8], signer: &SignatureKeyPair) -> CredentialWithKey {
    CredentialWithKey {
        credential: BasicCredential::new(name.to_vec()).into(),
        signature_key: signer.public().into(),
    }
}

fn pq_capability() -> DeviceCapability {
    DeviceCapability::new(
        1,
        vec![CLASSICAL_CS],
        vec![PQ_CS],
        true,
        false,
        "libcrux-real-e2e".into(),
    )
}

#[test]
fn libcrux_xwing_generates_multi_ciphersuite_bundle() {
    // Sanity gate: the same public API a KChat orchestration layer
    // would call must produce a usable bundle on the libcrux provider
    // with the xwing feature.
    let provider = LibcruxProvider::default();
    let s = signer();
    let cred = credential(b"alice", &s);
    let bundle = MultiCiphersuiteKeyPackages::generate_for_capability(
        &pq_capability(),
        &provider,
        &cred,
        &s,
    )
    .expect("multi-ciphersuite bundle generation must succeed under libcrux+xwing");

    assert_eq!(bundle.classical_packages().len(), 1);
    assert_eq!(bundle.pq_packages().len(), 1);
    assert!(bundle.key_package(PQ_CS).is_some());
    assert!(bundle.key_package(CLASSICAL_CS).is_some());
}

/// Helper: build a fresh `MlsGroup` for `name` on the libcrux provider
/// at `ciphersuite` with the given signer.
fn build_group(
    provider: &LibcruxProvider,
    s: &SignatureKeyPair,
    name: &[u8],
    ciphersuite: Ciphersuite,
) -> MlsGroup {
    let cred = credential(name, s);
    MlsGroup::new(
        provider,
        s,
        &MlsGroupCreateConfig::builder()
            .ciphersuite(ciphersuite)
            .use_ratchet_tree_extension(true)
            .build(),
        cred,
    )
    .expect("group creation under libcrux")
}

#[test]
fn libcrux_xwing_bootstrap_apq_round_trip() {
    // The full happy path: alice creates a classical T group with
    // bob, then a PQ X-Wing group with bob, then bootstraps APQ. The
    // orchestration must accept the X-Wing PQ side, transition the
    // conversation to APQ mode, and report InSync afterwards.
    let provider = LibcruxProvider::default();
    let alice_signer = signer();
    let bob_signer = signer();

    // -------- Classical T group with two members --------
    let mut alice_t = build_group(&provider, &alice_signer, b"alice", CLASSICAL_CS);

    let bob_cred = credential(b"bob", &bob_signer);
    let bob_t_kp = openmls::key_packages::KeyPackage::builder()
        .build(CLASSICAL_CS, &provider, &bob_signer, bob_cred.clone())
        .expect("bob T key package")
        .key_package()
        .clone();
    let (_, _welcome, _) = alice_t
        .add_members(&provider, &alice_signer, &[bob_t_kp])
        .expect("alice add bob to T group");
    alice_t
        .merge_pending_commit(&provider)
        .expect("alice merge T add commit");

    // -------- PQ X-Wing group with the same two members --------
    let alice_pq = build_group(&provider, &alice_signer, b"alice", PQ_CS);

    let bob_pq_kp = openmls::key_packages::KeyPackage::builder()
        .build(PQ_CS, &provider, &bob_signer, bob_cred)
        .expect("bob PQ key package")
        .key_package()
        .clone();

    // -------- Bootstrap APQ --------
    let mut convo = KChatMlsConversation::new_classical(b"convo-real-pq".to_vec(), alice_t)
        .expect("classical conversation");

    // The bootstrap helper takes the PQ key packages for *every other*
    // member, then internally adds them and merges the commit on the
    // PQ group. Alice is already its sole member.
    let _apq_welcome = convo
        .bootstrap_apq(
            alice_pq,
            vec![bob_pq_kp.clone()],
            SecurityMode::PqConfidentiality,
            PqPolicy::PqConfidentiality,
            &provider,
            &alice_signer,
        )
        .expect("bootstrap_apq must succeed under libcrux+xwing");

    // -------- Post-bootstrap invariants --------
    assert!(
        convo.is_apq(),
        "conversation must report APQ after successful bootstrap"
    );
    assert!(
        !convo.is_classical(),
        "conversation must no longer report classical after bootstrap"
    );

    // detect_desync sees no commit drift — both T and PQ are at the
    // same epoch, since the bootstrap merges the PQ add commit before
    // returning.
    let report = detect_desync(&convo);
    assert!(
        matches!(report.status, DesyncStatus::InSync),
        "freshly bootstrapped APQ conversation must be InSync, got {:?}",
        report.status
    );

    // The pinned-ciphersuite validator (one of the no-downgrade
    // validators) must accept the just-pinned PQ ciphersuite. We
    // mirror what the orchestration layer would do in steady state.
    let mut state = ConversationSecurityState::new(SecurityMode::PqConfidentiality);
    state.pinned_ciphersuite = Some(PQ_CS);
    validate_ciphersuite_pin(&state, PQ_CS)
        .expect("pinned X-Wing ciphersuite must pass the validator");
}
