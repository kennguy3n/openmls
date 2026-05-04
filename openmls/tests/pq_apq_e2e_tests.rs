//! # APQ orchestration end-to-end coverage
//!
//! These tests exercise the public APQ orchestration entrypoints
//! ([`KChatMlsConversation::bootstrap_apq`], [`prepare_full_commit`],
//! [`detect_desync`], [`PqPolicy`]) using **classical** [`MlsGroup`]
//! instances under the RustCrypto provider. We can't drive a real PQ
//! group through libcrux without the `xwing` feature, so the tests
//! deliberately use classical groups in both T and PQ slots and assert:
//!
//! - The bootstrap rejects a classical-ciphersuite "PQ" group (the
//!   sanity gate that prevents accidental classical-as-PQ wiring).
//! - The policy engine returns FULL for the triggers that *must* be
//!   FULL.
//! - `detect_desync` reports `InSync` on a freshly-built classical
//!   conversation (no PQ side, no commit drift).
//! - `prepare_full_commit` rejects a non-APQ conversation cleanly.
//!
//! Together with `pq_lifecycle_tests` (constructor invariants),
//! `pq_downgrade_tests` (no-downgrade validators), and
//! `pq_interop_tests` (cross-provider Welcome/KP shape), these tests
//! pin down the orchestration layer's public contract.

use openmls::ciphersuite::SecurityMode;
use openmls::credentials::{BasicCredential, CredentialWithKey};
use openmls::extensions::apq_info::ApqInfo;
use openmls::group::apq_commit::{prepare_full_commit, ApqCommitError};
use openmls::group::apq_resync::{detect_desync, DesyncStatus};
use openmls::group::kchat_conversation::{ApqBootstrapError, KChatMlsConversation};
use openmls::group::pq_policy::{CommitTrigger, CommitType, PqPolicy};
use openmls::group::{GroupId, MlsGroup, MlsGroupCreateConfig};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::types::{Ciphersuite, SignatureScheme};

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

fn classical_group(provider: &OpenMlsRustCrypto, name: &str) -> (MlsGroup, SignatureKeyPair) {
    let cs = classical_cs();
    let s = signer(cs.signature_algorithm());
    let cred = credential(name, &s);
    let group = MlsGroup::new(provider, &s, &MlsGroupCreateConfig::default(), cred)
        .expect("classical group creation");
    (group, s)
}

#[test]
fn bootstrap_apq_rejects_classical_ciphersuite_pq_group() {
    // Build a classical conversation backed by a real classical
    // MlsGroup, then attempt to bootstrap APQ with another *classical*
    // group as the PQ side. The orchestration must reject this with
    // the dedicated `PqGroupHasClassicalCiphersuite` error rather
    // than silently treating a classical group as PQ.
    let provider = OpenMlsRustCrypto::default();
    let (alice_t_group, alice_signer) = classical_group(&provider, "alice");
    let mut convo =
        KChatMlsConversation::new_classical(b"conv-1".to_vec(), alice_t_group).expect("classical");

    let (alice_pq_group, _alice_pq_signer) = classical_group(&provider, "alice-pq");

    // Bootstrap APQ — must fail because the PQ group's ciphersuite
    // is classical.
    let err = convo
        .bootstrap_apq(
            alice_pq_group,
            vec![],
            SecurityMode::PqConfidentiality,
            PqPolicy::PqConfidentiality,
            &provider,
            &alice_signer,
        )
        .expect_err("classical PQ side must be rejected");

    match err {
        ApqBootstrapError::PqGroupHasClassicalCiphersuite { ciphersuite } => {
            assert_eq!(ciphersuite, classical_cs());
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn bootstrap_apq_rejects_classical_apq_mode() {
    let provider = OpenMlsRustCrypto::default();
    let (alice_t_group, alice_signer) = classical_group(&provider, "alice");
    let mut convo =
        KChatMlsConversation::new_classical(b"conv-1".to_vec(), alice_t_group).expect("classical");
    let (alice_pq_group, _) = classical_group(&provider, "alice-pq");

    let err = convo
        .bootstrap_apq(
            alice_pq_group,
            vec![],
            SecurityMode::Classical,
            PqPolicy::PqConfidentiality,
            &provider,
            &alice_signer,
        )
        .expect_err("classical apq_mode must be rejected");
    assert!(matches!(err, ApqBootstrapError::ClassicalApqMode));
}

#[test]
fn bootstrap_apq_on_already_apq_conversation_rejected() {
    let provider = OpenMlsRustCrypto::default();
    let (t_group, signer) = classical_group(&provider, "alice");
    let (pq_group, _) = classical_group(&provider, "alice-pq");

    let info = ApqInfo::new(
        GroupId::from_slice(&[0xAA; 16]),
        GroupId::from_slice(&[0xBB; 16]),
        0,
        0,
        classical_cs(),
        xwing_cs(),
        SecurityMode::PqConfidentiality,
    );
    let mut convo = KChatMlsConversation::new_apq(
        b"conv-1".to_vec(),
        SecurityMode::PqConfidentiality,
        t_group,
        pq_group,
        info,
        PqPolicy::PqConfidentiality,
    )
    .expect("apq convo");

    let (extra_pq_group, _) = classical_group(&provider, "alice-pq2");
    let err = convo
        .bootstrap_apq(
            extra_pq_group,
            vec![],
            SecurityMode::PqConfidentiality,
            PqPolicy::PqConfidentiality,
            &provider,
            &signer,
        )
        .expect_err("already-APQ must be rejected");
    assert!(matches!(err, ApqBootstrapError::AlreadyApq));
}

#[test]
fn pq_policy_required_commit_type_for_each_trigger() {
    // The FULL/PARTIAL policy is the contract callers depend on most
    // — verify the table for every currently-defined trigger under
    // PqConfidentiality and PqRequired policies.
    for policy in [PqPolicy::PqConfidentiality, PqPolicy::PqRequired] {
        for trigger in [
            CommitTrigger::AddMember,
            CommitTrigger::RemoveMember,
            CommitTrigger::ExternalJoin,
            CommitTrigger::CredentialRotation,
            CommitTrigger::SecurityLevelIncrease,
        ] {
            assert_eq!(
                policy.required_commit_type(trigger),
                CommitType::Full,
                "policy {policy:?} / trigger {trigger:?} must be FULL"
            );
        }
    }
}

#[test]
fn pq_policy_normal_send_never_commits() {
    for policy in [
        PqPolicy::Classical,
        PqPolicy::PqConfidentiality,
        PqPolicy::PqRequired,
    ] {
        assert_eq!(
            policy.required_commit_type(CommitTrigger::NormalMessage),
            CommitType::None,
            "policy {policy:?} / NormalMessage must be None"
        );
    }
}

#[test]
fn detect_desync_reports_in_sync_for_fresh_classical_conversation() {
    let provider = OpenMlsRustCrypto::default();
    let (group, _signer) = classical_group(&provider, "alice");
    let convo =
        KChatMlsConversation::new_classical(b"conv-1".to_vec(), group).expect("classical convo");

    let report = detect_desync(&convo);
    assert!(matches!(report.status, DesyncStatus::InSync));
    assert!(!report.pending_full_commit);
}

#[test]
fn detect_desync_reports_in_sync_for_fresh_apq_conversation() {
    let provider = OpenMlsRustCrypto::default();
    let (t_group, _) = classical_group(&provider, "alice-t");
    let (pq_group, _) = classical_group(&provider, "alice-pq");
    let info = ApqInfo::new(
        GroupId::from_slice(&[0xAA; 16]),
        GroupId::from_slice(&[0xBB; 16]),
        0,
        0,
        classical_cs(),
        xwing_cs(),
        SecurityMode::PqConfidentiality,
    );
    let convo = KChatMlsConversation::new_apq(
        b"conv-apq".to_vec(),
        SecurityMode::PqConfidentiality,
        t_group,
        pq_group,
        info,
        PqPolicy::PqConfidentiality,
    )
    .expect("apq");

    let report = detect_desync(&convo);
    assert!(matches!(report.status, DesyncStatus::InSync));
    assert_eq!(report.t_epoch, Some(0));
    assert_eq!(report.pq_epoch, Some(0));
    assert!(!report.pending_full_commit);
}

#[test]
fn prepare_full_commit_rejects_non_apq_conversation() {
    let provider = OpenMlsRustCrypto::default();
    let (group, signer) = classical_group(&provider, "alice");
    let mut convo =
        KChatMlsConversation::new_classical(b"conv-1".to_vec(), group).expect("classical");

    let err = prepare_full_commit(
        &mut convo,
        CommitTrigger::AddMember,
        Vec::new(),
        &provider,
        &signer,
    )
    .expect_err("non-APQ FULL commit must fail");

    assert!(matches!(err, ApqCommitError::NotApqConversation));
}

#[test]
fn prepare_full_commit_rejects_direct_pq_conversation() {
    // DIRECT_PQ stores the sole session under t_group and is *not*
    // APQ — the FULL commit gate must reject it.
    let provider = OpenMlsRustCrypto::default();
    let (group, signer) = classical_group(&provider, "alice");
    let mut convo = KChatMlsConversation::new_direct_pq(
        b"conv-direct".to_vec(),
        SecurityMode::PqConfidentiality,
        group,
        PqPolicy::PqConfidentiality,
    )
    .expect("direct-pq");
    let err = prepare_full_commit(
        &mut convo,
        CommitTrigger::AddMember,
        Vec::new(),
        &provider,
        &signer,
    )
    .expect_err("direct-pq FULL commit must fail");
    assert!(matches!(err, ApqCommitError::NotApqConversation));
}

#[test]
fn classical_conversation_t_group_accessor_round_trips() {
    let provider = OpenMlsRustCrypto::default();
    let (group, _signer) = classical_group(&provider, "alice");
    let group_id = group.group_id().clone();

    let mut convo =
        KChatMlsConversation::new_classical(b"conv-1".to_vec(), group).expect("classical");
    assert_eq!(convo.t_group().unwrap().group_id(), &group_id);
    assert_eq!(convo.t_group_mut().unwrap().group_id(), &group_id);
    assert!(convo.pq_group().is_none());
    assert!(convo.pq_group_mut().is_none());
}

#[test]
fn apq_conversation_apq_info_round_trip() {
    let provider = OpenMlsRustCrypto::default();
    let (t_group, _) = classical_group(&provider, "alice-t");
    let (pq_group, _) = classical_group(&provider, "alice-pq");
    let info = ApqInfo::new(
        GroupId::from_slice(&[0xAA; 16]),
        GroupId::from_slice(&[0xBB; 16]),
        0,
        0,
        classical_cs(),
        xwing_cs(),
        SecurityMode::PqConfidentiality,
    );
    let convo = KChatMlsConversation::new_apq(
        b"conv-apq".to_vec(),
        SecurityMode::PqConfidentiality,
        t_group,
        pq_group,
        info.clone(),
        PqPolicy::PqConfidentiality,
    )
    .expect("apq");
    assert_eq!(convo.apq_info(), Some(&info));
    assert!(convo.is_apq());
}
