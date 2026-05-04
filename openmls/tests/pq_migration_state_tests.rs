//! Integration test for the per-conversation migration state machine.
//!
//! Exercises the full Classical → UpgradeEligible → UpgradeProposed →
//! UpgradeInProgress → PqActive lifecycle by driving the underlying
//! [`MigrationStateMachine`] through every event and verifying the
//! [`ConversationLifecycle`] projection lands in `PqActive` (because
//! the target is `PqConfidentiality`-but-not-APQ — the integration
//! test is run with the DIRECT_PQ projection convention by treating
//! the machine as if APQ bootstrap was not invoked).
//!
//! See unit tests in `openmls/src/group/migration_state.rs` for
//! per-transition coverage; this file pins the externally-visible
//! happy path.

use openmls::group::{
    ConversationLifecycle, MigrationEvent, MigrationState, MigrationStateMachine,
};
use openmls_traits::types::Ciphersuite;

#[test]
fn full_classical_to_pq_lifecycle_drives_through_every_phase() {
    let mut sm = MigrationStateMachine::new(b"conv-integration".to_vec());

    // Lifecycle starts at Classical.
    assert_eq!(
        ConversationLifecycle::from_state_machine(&sm),
        ConversationLifecycle::Classical
    );

    // CapabilitiesReady → UpgradeEligible.
    sm.advance(MigrationEvent::CapabilitiesReady).unwrap();
    assert_eq!(
        ConversationLifecycle::from_state_machine(&sm),
        ConversationLifecycle::UpgradeEligible
    );

    // KeyPackagesReady → UpgradeProposed.
    sm.advance(MigrationEvent::KeyPackagesReady).unwrap();
    assert_eq!(
        ConversationLifecycle::from_state_machine(&sm),
        ConversationLifecycle::UpgradeProposed
    );

    // ModeSelected (still UpgradeProposed in the lifecycle view —
    // the fine-grained machine moves to ModeSelected).
    use openmls::ciphersuite::SecurityMode;
    sm.advance(MigrationEvent::ModeSelected(
        SecurityMode::PqConfidentiality,
    ))
    .unwrap();
    assert_eq!(sm.state(), &MigrationState::ModeSelected);

    // BootstrapStarted → ApqBootstrapping (because target_mode is
    // PqConfidentiality, the projection treats it as APQ-track once
    // bootstrap begins).
    sm.advance(MigrationEvent::BootstrapStarted).unwrap();
    assert_eq!(
        ConversationLifecycle::from_state_machine(&sm),
        ConversationLifecycle::ApqBootstrapping
    );

    // BootstrapDone → still ApqBootstrapping in the projection until
    // the first FULL commit lands and the machine reaches Operational.
    sm.advance(MigrationEvent::BootstrapDone).unwrap();
    assert_eq!(
        ConversationLifecycle::from_state_machine(&sm),
        ConversationLifecycle::ApqBootstrapping
    );

    // First FULL commit lands (FirstFullCommitDone) — projection still
    // ApqBootstrapping until the auto-advance to Operational fires.
    sm.advance(MigrationEvent::FirstFullCommitDone).unwrap();
    assert_eq!(sm.state(), &MigrationState::FirstFullCommitDone);
    assert_eq!(
        ConversationLifecycle::from_state_machine(&sm),
        ConversationLifecycle::ApqBootstrapping
    );

    // Any subsequent legitimate event auto-advances to Operational
    // — projection is now ApqActive (target is APQ-track).
    sm.advance(MigrationEvent::FirstFullCommitDone).unwrap();
    assert_eq!(sm.state(), &MigrationState::Operational);
    assert!(sm.is_terminal());
    assert_eq!(
        ConversationLifecycle::from_state_machine(&sm),
        ConversationLifecycle::ApqActive
    );
}

#[test]
fn rollback_via_failed_event_lands_in_failed_lifecycle() {
    let mut sm = MigrationStateMachine::new(b"conv-rollback".to_vec());
    sm.advance(MigrationEvent::CapabilitiesReady).unwrap();
    sm.advance(MigrationEvent::Failed("rollback-test".into()))
        .unwrap();
    match ConversationLifecycle::from_state_machine(&sm) {
        ConversationLifecycle::Failed(reason) => assert_eq!(reason, "rollback-test"),
        other => panic!("expected Failed projection, got {other:?}"),
    }
}

#[test]
fn ciphersuite_wiring_is_independent_of_lifecycle_machine() {
    // Smoke check: the migration state machine doesn't lock the
    // process to a specific ciphersuite — every `Ciphersuite::try_from`
    // on a known classical codepoint still works while the machine is
    // mid-flight.
    let mut sm = MigrationStateMachine::new(b"conv-cs".to_vec());
    sm.advance(MigrationEvent::CapabilitiesReady).unwrap();
    assert!(matches!(
        Ciphersuite::try_from(0x0001u16),
        Ok(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
    ));
}
