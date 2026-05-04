//! # ReInit upgrade end-to-end coverage
//!
//! Exercises the public ReInit flow ([`propose_reinit`],
//! [`commit_reinit`], [`complete_reinit`]) using **classical**
//! [`MlsGroup`] instances under the RustCrypto provider.
//!
//! ReInit is a ciphersuite-change flow; the mode-downgrade rejection path
//! requires building a PQ group as the old group (so the downgrade is
//! `PQ → Classical`), which we can only do under the `xwing` feature.
//! The remaining error / flow paths can be exercised by going from one
//! classical ciphersuite to another (e.g.
//! `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` →
//! `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`).
//!
//! See [`PHASES.md`](../../../PHASES.md) Phase 3 for the upgrade
//! contract.

use openmls::credentials::{BasicCredential, CredentialWithKey};
use openmls::group::reinit_upgrade::{
    commit_reinit, complete_reinit, propose_reinit, ReInitError, ReInitPlan,
};
use openmls::group::{GroupId, MlsGroup, MlsGroupCreateConfig};
use openmls::messages::proposals::Proposal;
use openmls::schedule::psk::ResumptionPskUsage;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::types::{Ciphersuite, SignatureScheme};

fn classical_aes() -> Ciphersuite {
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
}

fn classical_chacha() -> Ciphersuite {
    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
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

fn classical_group_with_cs(
    provider: &OpenMlsRustCrypto,
    name: &str,
    cs: Ciphersuite,
) -> (MlsGroup, SignatureKeyPair) {
    let s = signer(cs.signature_algorithm());
    let cred = credential(name, &s);
    let config = MlsGroupCreateConfig::builder().ciphersuite(cs).build();
    let group =
        MlsGroup::new(provider, &s, &config, cred).expect("classical group creation with cs");
    (group, s)
}

#[test]
fn propose_reinit_with_same_ciphersuite_returns_target_same_as_old_error() {
    let provider = OpenMlsRustCrypto::default();
    let (alice_group, _signer) = classical_group_with_cs(&provider, "alice", classical_aes());

    // Same ciphersuite as old group → must fail with the dedicated
    // error variant.
    let plan = ReInitPlan::new(GroupId::from_slice(&[7u8; 16]), classical_aes());
    let err = propose_reinit(&alice_group, &plan).expect_err("same-cs must fail");
    match err {
        ReInitError::TargetCiphersuiteSameAsOld { got } => {
            assert_eq!(got, classical_aes());
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn propose_reinit_with_different_classical_cs_succeeds() {
    let provider = OpenMlsRustCrypto::default();
    let (alice_group, _signer) = classical_group_with_cs(&provider, "alice", classical_aes());

    let plan = ReInitPlan::new(GroupId::from_slice(&[7u8; 16]), classical_chacha());
    let proposal = propose_reinit(&alice_group, &plan).expect("classical → classical ok");
    // The returned proposal must be a ReInit. The proposal's internal
    // fields are crate-private; pinning the variant is enough to
    // confirm propose_reinit packaged the plan correctly.
    assert!(
        matches!(proposal, Proposal::ReInit(_)),
        "expected ReInit, got {proposal:?}"
    );
}

#[test]
fn commit_reinit_transitions_old_group_to_inactive_and_returns_commit() {
    let provider = OpenMlsRustCrypto::default();
    let (mut alice_group, alice_signer) =
        classical_group_with_cs(&provider, "alice", classical_aes());
    assert!(alice_group.is_active());

    let new_group_id = GroupId::from_slice(&[0xC0; 16]);
    let plan = ReInitPlan::new(new_group_id.clone(), classical_chacha());

    let bundle =
        commit_reinit(&mut alice_group, &plan, &provider, &alice_signer).expect("commit_reinit ok");
    // The commit message is produced; ReInit does not generate a
    // Welcome (no joiners).
    assert!(bundle.welcome.is_none());

    // After commit_reinit the old group is sealed and no longer active.
    assert!(
        !alice_group.is_active(),
        "old group must be Inactive after ReInit commit"
    );
}

#[test]
fn complete_reinit_on_active_group_returns_resumption_psk_with_reinit_usage() {
    // `complete_reinit` is a pure export + persist operation; it does
    // not require `commit_reinit` to have run first. We exercise it
    // here against a group at epoch 0 to lock down the PSK ID shape.
    // The integration story (commit_reinit → complete_reinit) is
    // documented in `commit_reinit_then_complete_reinit_documents_seal_order`.
    let provider = OpenMlsRustCrypto::default();
    let (alice_group, _signer) = classical_group_with_cs(&provider, "alice", classical_aes());
    let old_group_id = alice_group.group_id().clone();

    let resumption = complete_reinit(&alice_group, &provider).expect("complete_reinit ok");
    assert_eq!(resumption.old_group_id, old_group_id);
    assert_eq!(resumption.old_ciphersuite, classical_aes());

    // resumption PSK ID has Reinit usage and references the old
    // group's epoch.
    let psk = resumption.resumption_psk_id.psk();
    let resumption_payload = match psk {
        openmls::schedule::psk::Psk::Resumption(r) => r,
        other => panic!("expected resumption PSK, got {other:?}"),
    };
    assert_eq!(resumption_payload.usage(), ResumptionPskUsage::Reinit);
    assert_eq!(
        resumption_payload.psk_group_id().as_slice(),
        old_group_id.as_slice()
    );
}

#[test]
fn commit_reinit_then_complete_reinit_documents_seal_order() {
    // `commit_reinit` calls `set_inactive` after merging the ReInit
    // commit, and an inactive group's `export_secret` returns
    // `UseAfterEviction`. This test pins down the current contract so
    // a future fix that lets the orchestration call
    // `complete_reinit` after `commit_reinit` does not regress
    // silently.
    let provider = OpenMlsRustCrypto::default();
    let (mut alice_group, alice_signer) =
        classical_group_with_cs(&provider, "alice", classical_aes());
    let plan = ReInitPlan::new(GroupId::from_slice(&[0xC0; 16]), classical_chacha());
    commit_reinit(&mut alice_group, &plan, &provider, &alice_signer).expect("commit ok");

    // After the seal, complete_reinit cannot derive the PSK because
    // the group is inactive. The orchestration layer is expected to
    // call complete_reinit *before* commit_reinit's seal moment in a
    // future revision; for now this is the observable behaviour.
    let err = complete_reinit(&alice_group, &provider)
        .expect_err("export_secret on sealed group must fail");
    assert!(matches!(err, ReInitError::ExportSecretFailed(_)));
}

#[test]
fn commit_reinit_on_inactive_group_returns_old_group_inactive() {
    let provider = OpenMlsRustCrypto::default();
    let (mut alice_group, alice_signer) =
        classical_group_with_cs(&provider, "alice", classical_aes());
    let plan = ReInitPlan::new(GroupId::from_slice(&[0xC0; 16]), classical_chacha());

    // First ReInit transitions to inactive.
    commit_reinit(&mut alice_group, &plan, &provider, &alice_signer).expect("first reinit ok");
    assert!(!alice_group.is_active());

    // A second ReInit attempt on the now-inactive group must fail
    // cleanly.
    let err = commit_reinit(&mut alice_group, &plan, &provider, &alice_signer)
        .expect_err("second reinit on inactive must fail");
    assert!(matches!(err, ReInitError::OldGroupInactive));
}

#[test]
fn commit_reinit_with_same_ciphersuite_propagates_target_same_as_old_error() {
    let provider = OpenMlsRustCrypto::default();
    let (mut alice_group, alice_signer) =
        classical_group_with_cs(&provider, "alice", classical_aes());

    // commit_reinit calls propose_reinit internally, so the same-cs
    // error path is exercised end-to-end via commit_reinit.
    let plan = ReInitPlan::new(GroupId::from_slice(&[0xC0; 16]), classical_aes());
    let err = commit_reinit(&mut alice_group, &plan, &provider, &alice_signer)
        .expect_err("same-cs must propagate");
    assert!(matches!(
        err,
        ReInitError::TargetCiphersuiteSameAsOld { .. }
    ));
    // And the old group must still be active — we never touched it.
    assert!(alice_group.is_active());
}

#[test]
fn complete_reinit_is_idempotent_on_active_group() {
    let provider = OpenMlsRustCrypto::default();
    let (alice_group, _signer) = classical_group_with_cs(&provider, "alice", classical_aes());

    let r1 = complete_reinit(&alice_group, &provider).expect("complete 1");
    let r2 = complete_reinit(&alice_group, &provider).expect("complete 2");
    // Both calls observe the same old-group epoch and ciphersuite —
    // the only thing that differs is the random PSK nonce.
    assert_eq!(r1.old_group_id, r2.old_group_id);
    assert_eq!(r1.old_ciphersuite, r2.old_ciphersuite);
    assert_eq!(r1.old_group_epoch, r2.old_group_epoch);
}

// ---------------------------------------------------------------------------
// Mode-downgrade test — gated behind the xwing feature because we need a
// real PQ group on the old side. Without xwing this path is unreachable
// from tests (RustCrypto does not advertise X-Wing).
// ---------------------------------------------------------------------------

#[cfg(feature = "xwing")]
#[test]
fn propose_reinit_pq_to_classical_returns_downgrade_attempt() {
    use openmls_libcrux_crypto::Provider as LibcruxProvider;

    let provider = LibcruxProvider::default();
    let cs = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
    let s = signer(cs.signature_algorithm());
    let cred = credential("alice", &s);
    let mut config = MlsGroupCreateConfig::default();
    config.set_ciphersuite(cs);
    let alice_group =
        MlsGroup::new(&provider, &s, &config, cred).expect("PQ group creation under xwing");

    let plan = ReInitPlan::new(GroupId::from_slice(&[7u8; 16]), classical_aes());
    let err = propose_reinit(&alice_group, &plan).expect_err("PQ→Classical must downgrade");
    assert!(matches!(err, ReInitError::DowngradeAttempt { .. }));
}
