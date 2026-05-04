//! Integration tests for the PQ no-downgrade enforcement layer.
//!
//! These tests live outside the `openmls` crate so they exercise the public
//! API the same way a downstream KChat orchestration layer would: they
//! drive [`SecurityMode`], [`ApqInfo`], [`ConversationSecurityState`], and
//! the no-downgrade validators end-to-end.
//!
//! Coverage (PHASES.md Phase 6):
//!
//! - PQ_REQUIRED conversation rejects classical-only KeyPackage joiners.
//! - APQInfo removal is rejected.
//! - PqConfidentiality → Classical mode transitions are rejected.
//! - PqAuthenticity → PqConfidentiality transitions are rejected.
//! - Epoch mismatch between the T and PQ sessions is detected.
//! - Ciphersuite changes after APQ bootstrap are rejected.
//! - Full upgrade path Classical → PqConfidentiality → PqAuthenticity is
//!   accepted.
//! - APQInfo with the wrong recorded group IDs is rejected.

use openmls::ciphersuite::SecurityMode;
use openmls::extensions::apq_info::{ApqInfo, ApqInfoError};
use openmls::group::no_downgrade::{
    validate_apq_info_change, validate_ciphersuite_pin, validate_epoch_consistency,
    validate_joiner_key_package, validate_mode_change, ConversationSecurityState, DowngradeError,
};
use openmls::group::GroupId;
use openmls_traits::types::Ciphersuite;

fn classical_cs() -> Ciphersuite {
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
}

fn xwing_cs() -> Ciphersuite {
    Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519
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

#[test]
fn pq_required_rejects_classical_only_joiner_key_package() {
    // A PQ_REQUIRED conversation (any non-classical mode) must reject a
    // joiner whose KeyPackage is bound to a classical-only suite.
    let result = validate_joiner_key_package(SecurityMode::PqConfidentiality, classical_cs());
    match result {
        Err(DowngradeError::JoinerKeyPackageNotPq {
            kp_mode,
            required,
        }) => {
            assert_eq!(kp_mode, SecurityMode::Classical);
            assert_eq!(required, SecurityMode::PqConfidentiality);
        }
        other => panic!("expected JoinerKeyPackageNotPq, got {other:?}"),
    }

    // Same check at the strongest mode.
    let result = validate_joiner_key_package(SecurityMode::PqAuthenticity, classical_cs());
    assert!(matches!(
        result,
        Err(DowngradeError::JoinerKeyPackageNotPq { .. })
    ));

    // PQ KeyPackage is accepted by both PQ modes.
    validate_joiner_key_package(SecurityMode::PqConfidentiality, xwing_cs())
        .expect("PQ KP into PqConfidentiality ok");
}

#[test]
fn apq_info_removal_after_bootstrap_is_rejected() {
    let old = pq_apq_info();
    assert_eq!(
        validate_apq_info_change(Some(&old), None),
        Err(DowngradeError::ApqInfoRemoval)
    );
}

#[test]
fn mode_transition_pq_confidentiality_to_classical_rejected() {
    let state = ConversationSecurityState::new(SecurityMode::PqConfidentiality);
    let result = validate_mode_change(&state, SecurityMode::Classical);
    assert_eq!(
        result,
        Err(DowngradeError::ModeDowngrade {
            from: SecurityMode::PqConfidentiality,
            to: SecurityMode::Classical,
        })
    );
}

#[test]
fn mode_transition_pq_authenticity_to_pq_confidentiality_rejected() {
    let state = ConversationSecurityState::new(SecurityMode::PqAuthenticity);
    let result = validate_mode_change(&state, SecurityMode::PqConfidentiality);
    assert_eq!(
        result,
        Err(DowngradeError::ModeDowngrade {
            from: SecurityMode::PqAuthenticity,
            to: SecurityMode::PqConfidentiality,
        })
    );
}

#[test]
fn epoch_mismatch_between_t_and_pq_sessions_is_detected() {
    // Direct mismatch on the live values.
    let result = validate_epoch_consistency(5, 12, None);
    assert_eq!(
        result,
        Err(DowngradeError::EpochMismatch {
            t_epoch: 5,
            pq_epoch: 12,
            max: 1,
        })
    );

    // Mismatch recorded inside an ApqInfo is also detected.
    let mut info = pq_apq_info();
    info.t_epoch = 5;
    info.pq_epoch = 30;
    let result = validate_epoch_consistency(5, 5, Some(&info));
    assert_eq!(
        result,
        Err(DowngradeError::EpochMismatch {
            t_epoch: 5,
            pq_epoch: 30,
            max: 1,
        })
    );
}

#[test]
fn ciphersuite_change_after_apq_bootstrap_is_rejected_in_apq_info() {
    let old = pq_apq_info();
    let mut new = old.clone();
    new.t_ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
    let result = validate_apq_info_change(Some(&old), Some(&new));
    assert_eq!(
        result,
        Err(DowngradeError::ApqInfoCiphersuiteChange {
            old: classical_cs(),
            new: Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
        })
    );

    // PQ ciphersuite change is also rejected.
    let mut new2 = old.clone();
    new2.pq_ciphersuite = classical_cs();
    let result = validate_apq_info_change(Some(&old), Some(&new2));
    assert!(matches!(
        result,
        Err(DowngradeError::ApqInfoCiphersuiteChange { .. })
    ));
}

#[test]
fn ciphersuite_change_after_pin_is_rejected_in_state() {
    let mut state = ConversationSecurityState::new(SecurityMode::PqConfidentiality);
    state.pinned_ciphersuite = Some(xwing_cs());
    let result = validate_ciphersuite_pin(&state, classical_cs());
    assert_eq!(
        result,
        Err(DowngradeError::PinnedCiphersuiteChange {
            pinned: xwing_cs(),
            proposed: classical_cs(),
        })
    );
    // Same suite is accepted.
    validate_ciphersuite_pin(&state, xwing_cs()).expect("matching pin ok");
}

#[test]
fn full_upgrade_path_classical_to_pq_authenticity_succeeds() {
    let mut state = ConversationSecurityState::new(SecurityMode::Classical);

    // Step 1: Classical → PqConfidentiality.
    validate_mode_change(&state, SecurityMode::PqConfidentiality)
        .expect("classical → confidentiality is an upgrade");
    state
        .record_upgrade(SecurityMode::PqConfidentiality)
        .expect("classical → confidentiality recorded");
    assert_eq!(state.current_mode, SecurityMode::PqConfidentiality);
    assert_eq!(state.highest_mode_ever, SecurityMode::PqConfidentiality);

    // Step 2: PqConfidentiality → PqAuthenticity.
    validate_mode_change(&state, SecurityMode::PqAuthenticity)
        .expect("confidentiality → authenticity is an upgrade");
    state
        .record_upgrade(SecurityMode::PqAuthenticity)
        .expect("confidentiality → authenticity recorded");
    assert_eq!(state.current_mode, SecurityMode::PqAuthenticity);
    assert_eq!(state.highest_mode_ever, SecurityMode::PqAuthenticity);

    // Reflexivity: staying at the strongest mode is always accepted.
    validate_mode_change(&state, SecurityMode::PqAuthenticity)
        .expect("authenticity → authenticity is a no-op");

    // And once we've been at PqAuthenticity, dropping back is rejected even
    // through the AQ info change path.
    let old = ApqInfo::new(
        GroupId::from_slice(&[1; 16]),
        GroupId::from_slice(&[2; 16]),
        5,
        5,
        classical_cs(),
        xwing_cs(),
        SecurityMode::PqAuthenticity,
    );
    let mut new = old.clone();
    new.mode = SecurityMode::PqConfidentiality;
    assert!(matches!(
        validate_apq_info_change(Some(&old), Some(&new)),
        Err(DowngradeError::ApqInfoModeDowngrade { .. })
    ));
}

#[test]
fn apq_info_self_validation_rejects_classical_mode() {
    // APQInfo with mode=Classical is meaningless; the struct's own
    // validate() catches it before the no-downgrade layer ever sees it.
    let mut info = pq_apq_info();
    info.mode = SecurityMode::Classical;
    assert_eq!(info.validate(), Err(ApqInfoError::ClassicalMode));
}

#[test]
fn apq_info_with_wrong_recorded_group_ids_is_detected() {
    let info = pq_apq_info();
    let actual_t = GroupId::from_slice(&[0xCC; 16]);
    let actual_pq = GroupId::from_slice(&[0xBB; 16]);
    assert_eq!(
        info.matches_groups(&actual_t, &actual_pq),
        Err(ApqInfoError::GroupIdMismatch)
    );
}

#[test]
fn apq_info_unchanged_after_bootstrap_is_accepted() {
    // Re-applying the same APQInfo (e.g. on a session restore) is not a
    // downgrade and must succeed.
    let info = pq_apq_info();
    let copy = info.clone();
    validate_apq_info_change(Some(&info), Some(&copy)).expect("identity replacement ok");
}
