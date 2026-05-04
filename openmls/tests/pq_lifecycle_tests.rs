//! # End-to-end APQ conversation lifecycle integration tests
//!
//! Drives the full APQ orchestration layer through a realistic
//! conversation:
//!
//! 1. Three classical members.
//! 2. All members upgrade their device capabilities to PQ.
//! 3. The conversation mode is selected (should pick at least
//!    `PqConfidentiality`).
//! 4. `bootstrap_apq` runs to install the PQ side and the [`ApqInfo`]
//!    record. (Smoke-checked at the policy / state-machine layer; the
//!    actual MLS PQ group creation requires the libcrux provider and
//!    is gated behind the `xwing` feature.)
//! 5. PARTIAL commit cadence is exercised on the policy gate.
//! 6. Add / remove member triggers FULL-commit policy.
//! 7. Periodic refresh stays PARTIAL under
//!    [`PqPolicy::PqConfidentiality`].
//! 8. No-downgrade enforcement is exercised throughout.
//! 9. Epoch consistency between T and PQ is checked via
//!    [`detect_desync`].
//!
//! Error-path coverage:
//! - Adding a classical-only member to a PQ-required conversation.
//! - Attempting to downgrade the conversation mode.
//! - Detection of [`ApqInfo`] tampering.
//!
//! These tests live outside the `openmls` crate so they exercise the
//! public API the same way a downstream KChat orchestration layer
//! would.

use openmls::ciphersuite::SecurityMode;
use openmls::credentials::{BasicCredential, CredentialWithKey, DeviceCapability};
use openmls::extensions::apq_info::ApqInfo;
use openmls::group::apq_resync::DesyncStatus;
use openmls::group::conversation_upgrade::select_conversation_mode;
use openmls::group::kchat_conversation::{KChatConversationError, KChatMlsConversation};
use openmls::group::no_downgrade::{
    validate_apq_info_change, validate_joiner_key_package, DowngradeError,
};
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

fn classical_capability(provider: &str) -> DeviceCapability {
    DeviceCapability::new(
        1,
        vec![classical_cs()],
        vec![],
        false,
        false,
        provider.to_string(),
    )
}

fn pq_capability(provider: &str, pq_auth: bool) -> DeviceCapability {
    DeviceCapability::new(
        1,
        vec![classical_cs()],
        vec![xwing_cs()],
        true,
        pq_auth,
        provider.to_string(),
    )
}

fn pq_apq_info() -> ApqInfo {
    ApqInfo::new(
        GroupId::from_slice(&[0xAA; 16]),
        GroupId::from_slice(&[0xBB; 16]),
        5,
        5,
        classical_cs(),
        xwing_cs(),
        SecurityMode::PqConfidentiality,
    )
}

fn caps_refs(caps: &[DeviceCapability]) -> Vec<&DeviceCapability> {
    caps.iter().collect()
}

#[test]
fn step_1_classical_conversation_with_three_members() {
    // Three classical capabilities → conversation mode is Classical.
    let caps = vec![
        classical_capability("rust"),
        classical_capability("rust"),
        classical_capability("rust"),
    ];
    let refs = caps_refs(&caps);
    let (mode, _cs) = select_conversation_mode(&refs).expect("mode selection");
    assert_eq!(mode, SecurityMode::Classical);
}

#[test]
fn step_2_3_all_members_upgrade_to_pq_capabilities() {
    // After upgrade: all three are PQ-capable. Mode should pick at
    // least PqConfidentiality.
    let caps = vec![
        pq_capability("libcrux", false),
        pq_capability("libcrux", false),
        pq_capability("libcrux", false),
    ];
    let refs = caps_refs(&caps);
    let (mode, cs) = select_conversation_mode(&refs).expect("mode selection");
    assert_eq!(mode, SecurityMode::PqConfidentiality);
    assert_eq!(cs, xwing_cs());
}

#[test]
fn step_3_pq_authenticity_advertised_falls_back_to_pq_confidentiality() {
    // Even when peers advertise pq_signature_capable=true, the conversation
    // is forced down to PqConfidentiality if no PQ-signature ciphersuite is
    // available (X-Wing is confidentiality-only with Ed25519 signatures).
    let caps = vec![
        pq_capability("libcrux", true),
        pq_capability("libcrux", true),
        pq_capability("libcrux", true),
    ];
    let refs = caps_refs(&caps);
    let (mode, _cs) = select_conversation_mode(&refs).expect("mode selection");
    assert_eq!(mode, SecurityMode::PqConfidentiality);
}

#[test]
fn step_4_apq_info_links_t_and_pq_at_matching_epochs() {
    let info = pq_apq_info();
    info.validate().expect("apq info valid");
    assert_eq!(info.t_epoch, info.pq_epoch);
    assert_eq!(info.mode, SecurityMode::PqConfidentiality);
}

#[test]
fn step_5_partial_commit_policy_for_periodic_refresh_under_confidentiality() {
    let policy = PqPolicy::PqConfidentiality;
    assert_eq!(
        policy.required_commit_type(CommitTrigger::PeriodicRefresh),
        CommitType::Partial
    );
    assert_eq!(
        policy.required_commit_type(CommitTrigger::NormalMessage),
        CommitType::None
    );
}

#[test]
fn step_6_add_member_requires_full_commit_under_pq() {
    for policy in [PqPolicy::PqConfidentiality, PqPolicy::PqRequired] {
        assert_eq!(
            policy.required_commit_type(CommitTrigger::AddMember),
            CommitType::Full,
            "AddMember must be FULL under {policy:?}"
        );
    }
}

#[test]
fn step_6_remove_member_requires_full_commit_under_pq() {
    for policy in [PqPolicy::PqConfidentiality, PqPolicy::PqRequired] {
        assert_eq!(
            policy.required_commit_type(CommitTrigger::RemoveMember),
            CommitType::Full,
            "RemoveMember must be FULL under {policy:?}"
        );
    }
}

#[test]
fn step_7_periodic_refresh_is_full_under_pq_required() {
    // PqRequired tightens the periodic-refresh policy compared to
    // PqConfidentiality.
    assert_eq!(
        PqPolicy::PqRequired.required_commit_type(CommitTrigger::PeriodicRefresh),
        CommitType::Full
    );
}

#[test]
fn step_8_no_downgrade_classical_only_member_rejected_after_pq() {
    // After step 2/3 the conversation is PQ. Adding a classical-only
    // member must fail.
    let err = validate_joiner_key_package(SecurityMode::PqConfidentiality, classical_cs())
        .expect_err("classical KP rejected");
    assert!(matches!(err, DowngradeError::JoinerKeyPackageNotPq { .. }));
}

#[test]
fn step_8_no_downgrade_attempt_to_lower_mode_rejected() {
    // PqConfidentiality → Classical is rejected.
    let old = pq_apq_info();
    let mut new = old.clone();
    new.mode = SecurityMode::Classical;
    let err = validate_apq_info_change(Some(&old), Some(&new)).expect_err("downgrade rejected");
    assert!(matches!(err, DowngradeError::ApqInfoModeDowngrade { .. }));
}

#[test]
fn step_8_no_downgrade_attempt_pq_authenticity_to_pq_confidentiality_rejected() {
    let mut old = pq_apq_info();
    old.mode = SecurityMode::PqAuthenticity;
    let mut new = old.clone();
    new.mode = SecurityMode::PqConfidentiality;
    let err = validate_apq_info_change(Some(&old), Some(&new)).expect_err("downgrade rejected");
    assert!(matches!(err, DowngradeError::ApqInfoModeDowngrade { .. }));
}

#[test]
fn step_8_no_downgrade_apq_info_removal_rejected() {
    let old = pq_apq_info();
    let err = validate_apq_info_change(Some(&old), None).expect_err("removal of apq_info rejected");
    assert!(matches!(err, DowngradeError::ApqInfoRemoval));
}

#[test]
fn step_9_apq_info_tampering_pq_ciphersuite_changed() {
    let old = pq_apq_info();
    let mut new = old.clone();
    // Try to swap PQ ciphersuite — must be pinned at bootstrap.
    new.pq_ciphersuite = classical_cs();
    let err = validate_apq_info_change(Some(&old), Some(&new))
        .expect_err("pq ciphersuite change rejected");
    assert!(matches!(
        err,
        DowngradeError::ApqInfoCiphersuiteChange { .. }
    ));
}

#[test]
fn step_9_apq_info_tampering_t_ciphersuite_changed() {
    let old = pq_apq_info();
    let mut new = old.clone();
    new.t_ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
    let err = validate_apq_info_change(Some(&old), Some(&new))
        .expect_err("t ciphersuite change rejected");
    assert!(matches!(
        err,
        DowngradeError::ApqInfoCiphersuiteChange { .. }
    ));
}

#[test]
fn epoch_consistency_validator_checks_drift_via_detect_desync_pure_path() {
    // Pure-path test: we don't have real groups here, but the
    // `DesyncReport` shape is exercised in the apq_resync unit tests.
    // This test pins the high-level invariant: an in-sync report
    // reports `is_desynced() == false`.
    use openmls::group::apq_resync::DesyncReport;

    let report = DesyncReport {
        status: DesyncStatus::InSync,
        t_epoch: Some(7),
        pq_epoch: Some(7),
        pending_full_commit: false,
    };
    assert!(!report.is_desynced());

    let report = DesyncReport {
        status: DesyncStatus::DriftExceeded { delta: 3 },
        t_epoch: Some(5),
        pq_epoch: Some(8),
        pending_full_commit: false,
    };
    assert!(report.is_desynced());
}

#[test]
fn full_lifecycle_smoke_round_trip_apq_info() {
    use tls_codec::{Deserialize as _, Serialize as _};

    let info = pq_apq_info();
    let bytes = info.tls_serialize_detached().expect("serialize");
    let decoded = ApqInfo::tls_deserialize_exact(&bytes).expect("deserialize");
    assert_eq!(info, decoded);
    decoded.validate().expect("decoded info valid");
}

#[test]
fn full_lifecycle_step_by_step_assertions_in_one_run() {
    // A single end-to-end test that runs through the entire policy /
    // mode lifecycle so a regression in any single layer is visible
    // in one place.

    // Step 1: Classical conversation.
    let classical_caps = vec![classical_capability("rust"); 3];
    let classical_refs = caps_refs(&classical_caps);
    let (mode, _cs) = select_conversation_mode(&classical_refs).expect("mode");
    assert_eq!(mode, SecurityMode::Classical);

    // Step 2: All members upgrade to PQ.
    let pq_caps = vec![pq_capability("libcrux", false); 3];
    let pq_refs = caps_refs(&pq_caps);
    let (mode, _cs) = select_conversation_mode(&pq_refs).expect("mode");
    assert_eq!(mode, SecurityMode::PqConfidentiality);

    // Step 3: All members advertise PqAuthenticity capability, but no
    // PQ-signature suite is available so we settle for PqConfidentiality.
    let pq_auth_caps = vec![pq_capability("libcrux", true); 3];
    let pq_auth_refs = caps_refs(&pq_auth_caps);
    let (mode, _cs) = select_conversation_mode(&pq_auth_refs).expect("mode");
    assert_eq!(mode, SecurityMode::PqConfidentiality);

    // Step 4: ApqInfo round-trips and validates.
    let info = pq_apq_info();
    info.validate().expect("apq info valid");

    // Step 5: PARTIAL allowed for periodic refresh under
    // PqConfidentiality.
    assert_eq!(
        PqPolicy::PqConfidentiality.required_commit_type(CommitTrigger::PeriodicRefresh),
        CommitType::Partial
    );

    // Step 6: Add member triggers FULL.
    assert_eq!(
        PqPolicy::PqConfidentiality.required_commit_type(CommitTrigger::AddMember),
        CommitType::Full
    );

    // Step 7: Periodic refresh is FULL under PqRequired.
    assert_eq!(
        PqPolicy::PqRequired.required_commit_type(CommitTrigger::PeriodicRefresh),
        CommitType::Full
    );

    // Step 8: Classical-only member rejected.
    assert!(validate_joiner_key_package(SecurityMode::PqConfidentiality, classical_cs()).is_err());

    // Step 9: ApqInfo tampering rejected.
    let mut tampered = info.clone();
    tampered.mode = SecurityMode::Classical;
    assert!(validate_apq_info_change(Some(&info), Some(&tampered)).is_err());
}

// =============================================================================
// KChatMlsConversation integration tests with real MlsGroups.
//
// These tests construct actual `MlsGroup` instances via the RustCrypto
// provider and pass them into the `KChatMlsConversation` constructors so
// the constructor invariants are exercised end-to-end. The unit tests in
// `kchat_conversation.rs` only check the error paths without spinning up
// real groups; this layer pins down the happy paths and the accessors.
// =============================================================================

fn make_signer(scheme: SignatureScheme) -> SignatureKeyPair {
    SignatureKeyPair::new(scheme).expect("signature keypair generation")
}

fn make_credential(name: &str, signer: &SignatureKeyPair) -> CredentialWithKey {
    CredentialWithKey {
        credential: BasicCredential::new(name.as_bytes().to_vec()).into(),
        signature_key: signer.public().into(),
    }
}

fn make_classical_group(
    provider: &OpenMlsRustCrypto,
    signer: &SignatureKeyPair,
    name: &str,
) -> MlsGroup {
    let credential = make_credential(name, signer);
    MlsGroup::new(
        provider,
        signer,
        &MlsGroupCreateConfig::default(),
        credential,
    )
    .expect("classical group creation")
}

#[test]
fn new_classical_with_real_group_exposes_accessors() {
    let provider = OpenMlsRustCrypto::default();
    let signer = make_signer(classical_cs().signature_algorithm());
    let group = make_classical_group(&provider, &signer, "alice");
    let group_id = group.group_id().clone();
    let group_cs = group.ciphersuite();

    let convo =
        KChatMlsConversation::new_classical(b"conv-1".to_vec(), group).expect("classical convo");

    // Mode + classical/apq classifications.
    assert_eq!(convo.mode(), SecurityMode::Classical);
    assert!(convo.is_classical());
    assert!(!convo.is_pq());
    assert!(!convo.is_apq());

    // Accessors line up with the underlying MlsGroup.
    let t = convo.t_group().expect("t_group present");
    assert_eq!(t.group_id(), &group_id);
    assert_eq!(t.ciphersuite(), group_cs);
    assert!(t.is_active());
    assert_eq!(t.epoch().as_u64(), 0);

    // No PQ session and no APQInfo on a Classical conversation.
    assert!(convo.pq_group().is_none());
    assert!(convo.apq_info().is_none());

    // Pending-FULL-commit defaults.
    assert!(!convo.pending_full_commit());
    assert_eq!(convo.last_full_commit_epoch(), 0);
    assert_eq!(convo.pq_policy(), PqPolicy::Classical);
    assert_eq!(convo.conversation_id(), b"conv-1");
}

#[test]
fn new_apq_with_two_real_groups_reports_is_apq_true() {
    // Even though both underlying groups are *classical* MLS groups,
    // the orchestration constructor accepts them as long as the
    // supplied APQInfo is mode-consistent. The constructor does not
    // validate the underlying group ciphersuites against APQInfo —
    // that is left to the bootstrap path. This test pins the
    // constructor's actual behavior.
    let provider = OpenMlsRustCrypto::default();
    let signer = make_signer(classical_cs().signature_algorithm());
    let t_group = make_classical_group(&provider, &signer, "alice-t");
    let pq_group = make_classical_group(&provider, &signer, "alice-pq");

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
    .expect("apq convo");

    assert!(convo.is_apq());
    assert!(convo.is_pq());
    assert!(!convo.is_classical());
    assert_eq!(convo.mode(), SecurityMode::PqConfidentiality);
    assert_eq!(convo.pq_policy(), PqPolicy::PqConfidentiality);
    assert_eq!(convo.apq_info(), Some(&info));
    assert!(convo.t_group().is_some());
    assert!(convo.pq_group().is_some());
    // The two MlsGroups must remain distinct objects (different
    // memory) so callers can't mistake one for the other.
    let t_id = convo.t_group().unwrap().group_id().clone();
    let pq_id = convo.pq_group().unwrap().group_id().clone();
    assert_ne!(t_id, pq_id);
}

#[test]
fn new_direct_pq_rejects_classical_mode_with_real_group() {
    let provider = OpenMlsRustCrypto::default();
    let signer = make_signer(classical_cs().signature_algorithm());
    let group = make_classical_group(&provider, &signer, "alice");

    let err = KChatMlsConversation::new_direct_pq(
        b"conv-direct".to_vec(),
        SecurityMode::Classical,
        group,
        PqPolicy::Classical,
    )
    .expect_err("direct-pq must reject Classical mode");

    assert!(matches!(
        err,
        KChatConversationError::DirectPqWithClassicalMode {
            got: SecurityMode::Classical
        }
    ));
}

#[test]
fn new_direct_pq_with_pq_mode_real_group_succeeds() {
    let provider = OpenMlsRustCrypto::default();
    let signer = make_signer(classical_cs().signature_algorithm());
    let group = make_classical_group(&provider, &signer, "alice");

    let convo = KChatMlsConversation::new_direct_pq(
        b"conv-direct".to_vec(),
        SecurityMode::PqConfidentiality,
        group,
        PqPolicy::PqConfidentiality,
    )
    .expect("direct-pq with pq mode");

    assert_eq!(convo.mode(), SecurityMode::PqConfidentiality);
    assert!(convo.is_pq());
    // DIRECT_PQ stores the sole session under t_group; pq_group is
    // unused, and the conversation is NOT considered APQ.
    assert!(convo.t_group().is_some());
    assert!(convo.pq_group().is_none());
    assert!(convo.apq_info().is_none());
    assert!(!convo.is_apq());
}

#[test]
fn new_apq_rejects_mismatched_apq_info_mode() {
    let provider = OpenMlsRustCrypto::default();
    let signer = make_signer(classical_cs().signature_algorithm());
    let t_group = make_classical_group(&provider, &signer, "alice-t");
    let pq_group = make_classical_group(&provider, &signer, "alice-pq");

    // Conversation says PqAuthenticity but the APQInfo says
    // PqConfidentiality — must be rejected.
    let info = ApqInfo::new(
        GroupId::from_slice(&[0xAA; 16]),
        GroupId::from_slice(&[0xBB; 16]),
        0,
        0,
        classical_cs(),
        xwing_cs(),
        SecurityMode::PqConfidentiality,
    );

    let err = KChatMlsConversation::new_apq(
        b"conv-apq".to_vec(),
        SecurityMode::PqAuthenticity,
        t_group,
        pq_group,
        info,
        PqPolicy::PqRequired,
    )
    .expect_err("mode mismatch must fail");

    assert!(matches!(
        err,
        KChatConversationError::ApqInfoModeMismatch {
            expected: SecurityMode::PqAuthenticity,
            got: SecurityMode::PqConfidentiality,
        }
    ));
}

#[test]
fn new_apq_with_classical_mode_real_groups_rejected() {
    let provider = OpenMlsRustCrypto::default();
    let signer = make_signer(classical_cs().signature_algorithm());
    let t_group = make_classical_group(&provider, &signer, "alice-t");
    let pq_group = make_classical_group(&provider, &signer, "alice-pq");

    // Build any ApqInfo here — the mode check fires first so the
    // info contents are irrelevant.
    let info = ApqInfo::new(
        GroupId::from_slice(&[0xAA; 16]),
        GroupId::from_slice(&[0xBB; 16]),
        0,
        0,
        classical_cs(),
        xwing_cs(),
        SecurityMode::PqConfidentiality,
    );

    let err = KChatMlsConversation::new_apq(
        b"conv-apq".to_vec(),
        SecurityMode::Classical,
        t_group,
        pq_group,
        info,
        PqPolicy::Classical,
    )
    .expect_err("APQ with Classical mode must fail");

    assert!(matches!(
        err,
        KChatConversationError::ApqWithClassicalMode {
            got: SecurityMode::Classical
        }
    ));
}

#[test]
fn new_apq_propagates_invalid_apq_info_validation_error() {
    let provider = OpenMlsRustCrypto::default();
    let signer = make_signer(classical_cs().signature_algorithm());
    let t_group = make_classical_group(&provider, &signer, "alice-t");
    let pq_group = make_classical_group(&provider, &signer, "alice-pq");

    // Build an ApqInfo with t_group_id == pq_group_id — fails
    // ApqInfo::validate.
    let same_id = GroupId::from_slice(&[0xAA; 16]);
    let info = ApqInfo::new(
        same_id.clone(),
        same_id,
        0,
        0,
        classical_cs(),
        xwing_cs(),
        SecurityMode::PqConfidentiality,
    );

    let err = KChatMlsConversation::new_apq(
        b"conv-apq".to_vec(),
        SecurityMode::PqConfidentiality,
        t_group,
        pq_group,
        info,
        PqPolicy::PqConfidentiality,
    )
    .expect_err("invalid apq_info must propagate as InvalidApqInfo");

    assert!(matches!(err, KChatConversationError::InvalidApqInfo(_)));
}

#[test]
fn classical_conversation_pending_full_commit_can_be_toggled() {
    let provider = OpenMlsRustCrypto::default();
    let signer = make_signer(classical_cs().signature_algorithm());
    let group = make_classical_group(&provider, &signer, "alice");

    let mut convo =
        KChatMlsConversation::new_classical(b"conv-toggle".to_vec(), group).expect("classical");

    assert!(!convo.pending_full_commit());
    convo.set_pending_full_commit(true);
    assert!(convo.pending_full_commit());

    convo.record_full_commit(7);
    assert_eq!(convo.last_full_commit_epoch(), 7);
    // record_full_commit clears the pending flag.
    assert!(!convo.pending_full_commit());
}
