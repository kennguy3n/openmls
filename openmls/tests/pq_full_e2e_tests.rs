//! # Full lifecycle e2e tests for the PQ orchestration layer
//!
//! These tests drive the *complete* lifecycle of a PQ-orchestration
//! conversation — creation, member adds, capability registration,
//! mode selection, KP publish/fetch/expire, ReInit proposal, no-downgrade
//! validators, conversation metadata service, and rate limiter — using
//! the **RustCrypto provider with classical ciphersuites**. We can't
//! drive a real PQ group without the `xwing` feature, but every
//! orchestration entry point exercised here is *ciphersuite-agnostic*
//! at its public boundary.
//!
//! The point is to pin a single, comprehensive integration scenario
//! against the public API so refactors that break the orchestration
//! contract surface in one place rather than as a hundred small
//! per-test failures.

use openmls::credentials::capability_registry::CapabilityRegistry;
use openmls::credentials::{BasicCredential, CredentialWithKey, DeviceCapability};
use openmls::extensions::apq_info::ApqInfo;
use openmls::group::apq_resync::{detect_desync, DesyncStatus};
use openmls::group::conversation_metadata::{ConversationMetadata, ConversationMetadataService};
use openmls::group::conversation_upgrade::{select_conversation_mode, ConversationUpgradeError};
use openmls::group::kchat_conversation::KChatMlsConversation;
use openmls::group::migration_state::{MigrationEvent, MigrationStateMachine};
use openmls::group::no_downgrade::{
    validate_apq_info_change, validate_joiner_key_package, validate_mode_change,
    ConversationSecurityState, DowngradeError,
};
use openmls::group::pq_policy::{CommitTrigger, CommitType, PqPolicy};
use openmls::group::reinit_upgrade::{propose_reinit, ReInitPlan};
use openmls::group::{GroupId, MlsGroup, MlsGroupCreateConfig};
use openmls::key_packages::key_package_service::{KeyPackageEntry, KeyPackageService};
use openmls::key_packages::rate_limiter::{KeyPackageFetchRateLimiter, RateLimitError};
use openmls::key_packages::KeyPackage;
use openmls::messages::proposals::Proposal;
use openmls::prelude::SecurityMode;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::types::Ciphersuite;
use openmls_traits::OpenMlsProvider;

const CS_AES: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const CS_CHA: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
const XWING_CS: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

fn signer(cs: Ciphersuite) -> SignatureKeyPair {
    SignatureKeyPair::new(cs.signature_algorithm()).expect("signer")
}

fn credential(name: &str, s: &SignatureKeyPair) -> CredentialWithKey {
    CredentialWithKey {
        credential: BasicCredential::new(name.as_bytes().to_vec()).into(),
        signature_key: s.public().into(),
    }
}

fn group_for(
    provider: &OpenMlsRustCrypto,
    name: &str,
    cs: Ciphersuite,
) -> (MlsGroup, SignatureKeyPair) {
    let s = signer(cs);
    let cred = credential(name, &s);
    let cfg = MlsGroupCreateConfig::builder().ciphersuite(cs).build();
    (MlsGroup::new(provider, &s, &cfg, cred).expect("group"), s)
}

fn key_package(
    provider: &OpenMlsRustCrypto,
    name: &str,
    cs: Ciphersuite,
) -> (KeyPackage, SignatureKeyPair) {
    let s = signer(cs);
    let cred = credential(name, &s);
    let kpb = KeyPackage::builder()
        .build(cs, provider, &s, cred)
        .expect("kp build");
    (kpb.key_package().clone(), s)
}

fn build_pq_capable_capability(
    provider: &OpenMlsRustCrypto,
    s: &SignatureKeyPair,
    apq: bool,
    pq_auth: bool,
) -> DeviceCapability {
    let mut cap = DeviceCapability::new(
        1,
        vec![CS_AES, CS_CHA],
        vec![XWING_CS],
        apq,
        pq_auth,
        "rustcrypto".into(),
    );
    cap.sign(CS_AES.signature_algorithm(), s.private(), provider.crypto())
        .expect("sign capability");
    cap
}

#[test]
fn alice_creates_classical_group_and_bob_charlie_join_via_welcome() {
    // Step 1–2: Alice builds a classical group. Bob and Charlie join
    // via the standard Welcome path (single add_members).
    let provider = OpenMlsRustCrypto::default();
    let (mut alice_group, alice_signer) = group_for(&provider, "alice", CS_AES);
    let (bob_kp, _bob_signer) = key_package(&provider, "bob", CS_AES);
    let (charlie_kp, _charlie_signer) = key_package(&provider, "charlie", CS_AES);

    let (_commit, welcome, _gi) = alice_group
        .add_members(&provider, &alice_signer, &[bob_kp, charlie_kp])
        .expect("add_members");
    alice_group.merge_pending_commit(&provider).expect("merge");

    // Welcome must be present; group must now have three members.
    assert!(matches!(
        welcome.body(),
        openmls::framing::MlsMessageBodyOut::Welcome(_)
    ));
    assert_eq!(alice_group.members().count(), 3);
    assert!(alice_group.is_active());
}

#[test]
fn select_conversation_mode_picks_apq_for_full_pq_capable_peer_set() {
    let provider = OpenMlsRustCrypto::default();
    let s_alice = signer(CS_AES);
    let s_bob = signer(CS_AES);

    let alice_cap = build_pq_capable_capability(&provider, &s_alice, true, false);
    let bob_cap = build_pq_capable_capability(&provider, &s_bob, true, false);
    let caps = vec![&alice_cap, &bob_cap];

    let (mode, cs) = select_conversation_mode(&caps).expect("PQ-capable peers must select PQ");
    assert_eq!(mode, SecurityMode::PqConfidentiality);
    // Selected suite must be the X-Wing PQ suite advertised by both peers.
    assert_eq!(cs, XWING_CS);
}

#[test]
fn select_conversation_mode_falls_back_to_classical_for_classical_only_peers() {
    let provider = OpenMlsRustCrypto::default();
    let s_alice = signer(CS_AES);
    let s_bob = signer(CS_AES);
    let mut alice_cap = DeviceCapability::new(
        1,
        vec![CS_AES, CS_CHA],
        vec![],
        false,
        false,
        "rustcrypto".into(),
    );
    alice_cap
        .sign(
            CS_AES.signature_algorithm(),
            s_alice.private(),
            provider.crypto(),
        )
        .unwrap();
    let mut bob_cap = alice_cap.clone();
    // Re-sign with bob's key (different signer; this is fine — the
    // `select_conversation_mode` function doesn't verify signatures).
    bob_cap
        .sign(
            CS_AES.signature_algorithm(),
            s_bob.private(),
            provider.crypto(),
        )
        .unwrap();
    let caps = vec![&alice_cap, &bob_cap];

    let (mode, _cs) = select_conversation_mode(&caps).expect("classical peers OK");
    assert_eq!(mode, SecurityMode::Classical);
}

#[test]
fn pq_required_peer_with_no_common_pq_suite_is_rejected() {
    // A peer set where every device claims PQ support but advertises
    // *disjoint* PQ suites must be rejected fail-closed.
    let provider = OpenMlsRustCrypto::default();
    let s_alice = signer(CS_AES);
    let s_bob = signer(CS_AES);
    let mut alice_cap = DeviceCapability::new(
        1,
        vec![CS_AES],
        vec![XWING_CS],
        true,
        false,
        "rustcrypto".into(),
    );
    let mut bob_cap = DeviceCapability::new(
        1,
        vec![CS_AES],
        // Distinct, never-real PQ suite (use the draft codepoint
        // that no provider supports).
        vec![Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_Ed448],
        true,
        false,
        "rustcrypto".into(),
    );
    alice_cap
        .sign(
            CS_AES.signature_algorithm(),
            s_alice.private(),
            provider.crypto(),
        )
        .unwrap();
    bob_cap
        .sign(
            CS_AES.signature_algorithm(),
            s_bob.private(),
            provider.crypto(),
        )
        .unwrap();
    let caps = vec![&alice_cap, &bob_cap];

    let err = select_conversation_mode(&caps).expect_err("disjoint PQ suites must fail");
    assert!(matches!(
        err,
        ConversationUpgradeError::NoCommonCiphersuite { .. }
    ));
}

#[test]
fn classical_kchat_conversation_reports_in_sync_with_no_pq_side() {
    // detect_desync on a classical conversation (no PQ side) must
    // report InSync regardless of T epoch — there is no PQ side to be
    // out of sync with.
    let provider = OpenMlsRustCrypto::default();
    let (alice_group, _alice_signer) = group_for(&provider, "alice", CS_AES);
    let convo =
        KChatMlsConversation::new_classical(b"conv-1".to_vec(), alice_group).expect("classical");
    let report = detect_desync(&convo);
    assert!(matches!(report.status, DesyncStatus::InSync));
}

#[test]
fn propose_reinit_packages_a_valid_reinit_proposal() {
    // Alice on a classical AES group proposes a ReInit to ChaCha.
    // The returned proposal must be a `Proposal::ReInit(_)` (see
    // `pq_reinit_e2e_tests` for the full commit/complete flow).
    let provider = OpenMlsRustCrypto::default();
    let (alice_group, _alice_signer) = group_for(&provider, "alice", CS_AES);

    let plan = ReInitPlan::new(GroupId::from_slice(&[0xAA; 16]), CS_CHA);
    let proposal = propose_reinit(&alice_group, &plan).expect("ok");
    assert!(matches!(proposal, Proposal::ReInit(_)));
}

#[test]
fn pq_policy_returns_full_for_security_level_increase() {
    // PqPolicy::PqConfidentiality must classify a SecurityLevelIncrease
    // trigger as a FULL commit. (Pin the *triggers that must be FULL*
    // contract.)
    let policy = PqPolicy::PqConfidentiality;
    let kind = policy.required_commit_type(CommitTrigger::SecurityLevelIncrease);
    assert_eq!(kind, CommitType::Full);
}

#[test]
fn no_downgrade_validator_rejects_pq_to_classical_transition() {
    // A direct PQ → Classical mode transition must be rejected.
    let mut state = ConversationSecurityState::new(SecurityMode::PqConfidentiality);
    state.highest_mode_ever = SecurityMode::PqConfidentiality;

    let err = validate_mode_change(&state, SecurityMode::Classical)
        .expect_err("PQ→Classical must be rejected");
    assert!(matches!(err, DowngradeError::ModeDowngrade { .. }));
}

#[test]
fn no_downgrade_validator_rejects_classical_kp_for_pq_required_conversation() {
    // A PQ-required conversation must reject a classical-only joiner KP.
    let err = validate_joiner_key_package(SecurityMode::PqConfidentiality, CS_AES)
        .expect_err("classical KP into PQ conv must fail");
    assert!(matches!(err, DowngradeError::JoinerKeyPackageNotPq { .. }));
}

#[test]
fn no_downgrade_validator_rejects_apq_info_mode_downgrade() {
    let g_t = GroupId::from_slice(&[0xAA; 16]);
    let g_pq = GroupId::from_slice(&[0xBB; 16]);
    let old = ApqInfo::new(
        g_t.clone(),
        g_pq.clone(),
        0,
        0,
        CS_AES,
        XWING_CS,
        SecurityMode::PqAuthenticity,
    );
    let new = ApqInfo::new(
        g_t,
        g_pq,
        0,
        0,
        CS_AES,
        XWING_CS,
        SecurityMode::PqConfidentiality,
    );
    let err = validate_apq_info_change(Some(&old), Some(&new)).expect_err("downgrade rejected");
    assert!(matches!(err, DowngradeError::ApqInfoModeDowngrade { .. }));
}

#[test]
fn conversation_metadata_service_round_trip() {
    let mut svc = ConversationMetadataService::new();
    let meta = ConversationMetadata::new(
        b"conv-1".to_vec(),
        ConversationSecurityState::new(SecurityMode::Classical),
        Some(GroupId::from_slice(&[0xAA; 16])),
        None,
        None,
        7,
    );
    svc.register(meta.clone()).expect("register");

    let fetched = svc.get(b"conv-1").expect("present");
    assert_eq!(fetched, &meta);
    assert_eq!(svc.len(), 1);

    // A duplicate registration must be rejected.
    let dup = ConversationMetadata::new(
        b"conv-1".to_vec(),
        ConversationSecurityState::new(SecurityMode::Classical),
        None,
        None,
        None,
        99,
    );
    assert!(svc.register(dup).is_err());
}

#[test]
fn capability_registry_stores_and_retrieves_signed_capability() {
    let provider = OpenMlsRustCrypto::default();
    let s = signer(CS_AES);
    let cap = build_pq_capable_capability(&provider, &s, true, false);

    let mut reg = CapabilityRegistry::new();
    reg.store(
        b"alice".to_vec(),
        b"phone".to_vec(),
        cap.clone(),
        CS_AES.signature_algorithm(),
        s.public(),
        provider.crypto(),
    )
    .expect("store");
    assert_eq!(reg.len(), 1);

    let fetched = reg.fetch(b"alice", b"phone").expect("present");
    assert_eq!(fetched, &cap);
}

#[test]
fn key_package_service_publish_fetch_and_expire_cycle() {
    let provider = OpenMlsRustCrypto::default();
    let mut svc = KeyPackageService::new();

    let (kp, _s) = key_package(&provider, "alice", CS_AES);
    svc.publish(
        b"alice".to_vec(),
        b"phone".to_vec(),
        KeyPackageEntry::new(kp, 1, /* expiry */ 100, false),
    )
    .expect("publish");
    assert_eq!(svc.count_for_device(b"alice", b"phone"), 1);

    // Fetch consumes the standard KP.
    let entry = svc
        .fetch(b"alice", b"phone", CS_AES)
        .expect("fetch present");
    assert_eq!(entry.ciphersuite(), CS_AES);
    assert_eq!(svc.count_for_device(b"alice", b"phone"), 0);

    // After consumption, the slot is empty.
    assert!(svc.fetch(b"alice", b"phone", CS_AES).is_none());

    // Republish + expire: expire_before drops anything with `expiry < t`.
    let (kp2, _s2) = key_package(&provider, "alice", CS_AES);
    svc.publish(
        b"alice".to_vec(),
        b"phone".to_vec(),
        KeyPackageEntry::new(kp2, 1, /* expiry */ 50, false),
    )
    .unwrap();
    let dropped = svc.expire_before(100);
    assert_eq!(dropped, 1);
    assert_eq!(svc.count_for_device(b"alice", b"phone"), 0);
}

#[test]
fn key_package_fetch_rate_limiter_enforces_per_device_cap() {
    let mut rl = KeyPackageFetchRateLimiter::new(3, 60);
    for t in 0..3u64 {
        rl.check_and_record(b"alice", b"phone", t * 5).unwrap();
    }
    let err = rl
        .check_and_record(b"alice", b"phone", 30)
        .expect_err("over limit");
    assert!(matches!(err, RateLimitError::Exceeded { .. }));
    // A different device must NOT be rate-limited by alice's history.
    rl.check_and_record(b"alice", b"laptop", 30)
        .expect("different device under its own counter");
}

#[test]
fn migration_state_machine_drives_a_full_lifecycle_alongside_the_orchestration() {
    // Pin that the migration state machine can be driven through a
    // full lifecycle in lock-step with the orchestration calls.
    let provider = OpenMlsRustCrypto::default();
    let (mut alice_group, alice_signer) = group_for(&provider, "alice", CS_AES);

    let mut sm = MigrationStateMachine::new(b"conv-mig-1".to_vec());

    // Capabilities → KeyPackages
    sm.advance(MigrationEvent::CapabilitiesReady).unwrap();
    sm.advance(MigrationEvent::KeyPackagesReady).unwrap();

    // Mode selected (classical for this test)
    sm.advance(MigrationEvent::ModeSelected(SecurityMode::Classical))
        .unwrap();
    assert_eq!(sm.target_mode(), Some(SecurityMode::Classical));

    // Bootstrap "started" (no real APQ bootstrap — classical-only test)
    sm.advance(MigrationEvent::BootstrapStarted).unwrap();
    sm.advance(MigrationEvent::BootstrapDone).unwrap();

    // Drive a real add_members against the underlying T group to
    // simulate the first FULL commit landing.
    let (bob_kp, _bob_signer) = key_package(&provider, "bob", CS_AES);
    let (_commit, _welcome, _gi) = alice_group
        .add_members(&provider, &alice_signer, &[bob_kp])
        .unwrap();
    alice_group.merge_pending_commit(&provider).unwrap();

    sm.advance(MigrationEvent::FirstFullCommitDone).unwrap();
    // One more event auto-advances to Operational.
    sm.advance(MigrationEvent::FirstFullCommitDone).unwrap();
    assert!(sm.is_terminal());
}
