//! # Per-conversation migration state machine
//!
//! Tracks the upgrade lifecycle of a KChat conversation as it migrates
//! from `Classical` to a PQ mode (DIRECT_PQ or APQ). The state machine
//! is **observational only** — it does not perform any cryptographic
//! work; it just enforces the *order* in which the orchestration layer
//! drives the migration so dashboards, recovery code, and tests can
//! reason about progress without pattern-matching on
//! [`KChatMlsConversation`] internals.
//!
//! State transitions:
//!
//! ```text
//! NotStarted
//!   └─[CapabilitiesReady]──→ CapabilitiesCollected
//!                              └─[KeyPackagesReady]──→ KeyPackagesPublished
//!                                                       └─[ModeSelected]──→ ModeSelected
//!                                                                            └─[BootstrapStarted]──→ BootstrapInitiated
//!                                                                                                     └─[BootstrapDone]──→ BootstrapComplete
//!                                                                                                                          └─[FirstFullCommitDone]──→ FirstFullCommitDone
//!                                                                                                                                                     └─→ Operational
//!                              (any non-terminal state) ──[Failed(_)]──→ Failed
//! ```
//!
//! `Failed` and `Operational` are terminal — once entered, no further
//! transitions are permitted.

use crate::ciphersuite::SecurityMode;

/// Lifecycle phase of a conversation migration. See module-level docs
/// for the legal transitions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MigrationState {
    /// No migration started yet. Initial state.
    NotStarted,
    /// `DeviceCapability` collection for every member is complete.
    CapabilitiesCollected,
    /// PQ KeyPackages have been published for every member.
    KeyPackagesPublished,
    /// `select_conversation_mode` has chosen the target mode.
    ModeSelected,
    /// `bootstrap_apq` (or the DIRECT_PQ equivalent) has been
    /// initiated but not yet completed.
    BootstrapInitiated,
    /// Bootstrap finished, but the first FULL commit has not yet
    /// landed.
    BootstrapComplete,
    /// The first FULL commit pair has been delivered and merged.
    FirstFullCommitDone,
    /// Migration is fully operational. Terminal success state.
    Operational,
    /// Migration failed; the carried `String` describes the failure
    /// reason (free-form, not a typed error). Terminal failure state.
    Failed(String),
}

/// Events that drive [`MigrationState`] transitions. See module-level
/// docs for the legal sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationEvent {
    /// Capabilities for every member have been collected.
    CapabilitiesReady,
    /// PQ KeyPackages for every member have been published.
    KeyPackagesReady,
    /// `select_conversation_mode` returned this mode.
    ModeSelected(SecurityMode),
    /// `bootstrap_apq` (or DIRECT_PQ equivalent) was initiated.
    BootstrapStarted,
    /// Bootstrap completed successfully.
    BootstrapDone,
    /// First FULL commit pair landed.
    FirstFullCommitDone,
    /// Migration failed with the given reason.
    Failed(String),
}

/// Errors returned by [`MigrationStateMachine::advance`] when the
/// caller attempts an illegal transition.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MigrationError {
    /// `event` is not a valid next step from `state`.
    #[error("invalid transition: cannot apply event {event:?} from state {state:?}")]
    InvalidTransition {
        /// Current state.
        state: MigrationState,
        /// Event the caller tried to apply.
        event: MigrationEvent,
    },
    /// Caller tried to advance a terminal state machine.
    #[error("cannot advance from terminal state {state:?}")]
    Terminal {
        /// The terminal state.
        state: MigrationState,
    },
}

/// Per-conversation migration state machine.
///
/// Construct with [`MigrationStateMachine::new`], drive forward with
/// [`Self::advance`], and inspect with [`Self::state`] / [`Self::is_terminal`].
///
/// Keeps timestamps for the initial transition out of `NotStarted`
/// (`started_at`) and the most-recent successful transition
/// (`last_transition_at`). Timestamps are nanoseconds since the
/// machine's monotonic clock origin (see [`Self::new`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationStateMachine {
    state: MigrationState,
    conversation_id: Vec<u8>,
    target_mode: Option<SecurityMode>,
    /// Wall-clock-style counter; the machine doesn't actually call
    /// `Instant::now()` — callers pass timestamps in via
    /// [`Self::advance_at`] for testability. [`Self::advance`] uses 0.
    started_at: Option<u64>,
    /// Timestamp of the most recent successful transition.
    last_transition_at: Option<u64>,
}

impl MigrationStateMachine {
    /// Construct a fresh state machine for `conversation_id`, starting
    /// in [`MigrationState::NotStarted`].
    pub fn new(conversation_id: Vec<u8>) -> Self {
        Self {
            state: MigrationState::NotStarted,
            conversation_id,
            target_mode: None,
            started_at: None,
            last_transition_at: None,
        }
    }

    /// Current state.
    pub fn state(&self) -> &MigrationState {
        &self.state
    }

    /// Conversation this machine is tracking.
    pub fn conversation_id(&self) -> &[u8] {
        &self.conversation_id
    }

    /// Target mode picked by `ModeSelected`, if any.
    pub fn target_mode(&self) -> Option<SecurityMode> {
        self.target_mode
    }

    /// Timestamp at which the machine first transitioned out of
    /// `NotStarted`.
    pub fn started_at(&self) -> Option<u64> {
        self.started_at
    }

    /// Timestamp of the most recent successful transition.
    pub fn last_transition_at(&self) -> Option<u64> {
        self.last_transition_at
    }

    /// Returns `true` if `state` is one of [`MigrationState::Operational`]
    /// or [`MigrationState::Failed`].
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            MigrationState::Operational | MigrationState::Failed(_)
        )
    }

    /// Pure check: would [`Self::advance`] succeed for `event` from the
    /// current state? Does not mutate the machine.
    pub fn can_advance(&self, event: &MigrationEvent) -> bool {
        Self::next_state(&self.state, event).is_ok()
    }

    /// Apply `event` and (on success) move to the new state. On
    /// success, returns the new state.
    ///
    /// `Failed(_)` is reachable from any non-terminal state.
    pub fn advance(&mut self, event: MigrationEvent) -> Result<MigrationState, MigrationError> {
        self.advance_at(event, 0)
    }

    /// Like [`Self::advance`] but records `at_ns` as the transition
    /// timestamp. Useful for tests that want deterministic ordering.
    pub fn advance_at(
        &mut self,
        event: MigrationEvent,
        at_ns: u64,
    ) -> Result<MigrationState, MigrationError> {
        let next = Self::next_state(&self.state, &event)?;
        // Record `target_mode` when ModeSelected fires.
        if let MigrationEvent::ModeSelected(m) = &event {
            self.target_mode = Some(*m);
        }
        if matches!(self.state, MigrationState::NotStarted) && self.started_at.is_none() {
            self.started_at = Some(at_ns);
        }
        self.last_transition_at = Some(at_ns);
        self.state = next.clone();
        Ok(next)
    }

    /// Pure transition function: returns the next state for `(state, event)`
    /// without mutating anything.
    fn next_state(
        state: &MigrationState,
        event: &MigrationEvent,
    ) -> Result<MigrationState, MigrationError> {
        // Failed(_) and Operational are terminal — reject every event.
        if matches!(
            state,
            MigrationState::Operational | MigrationState::Failed(_)
        ) {
            return Err(MigrationError::Terminal {
                state: state.clone(),
            });
        }

        // Failed(_) is reachable from any non-terminal state.
        if let MigrationEvent::Failed(reason) = event {
            return Ok(MigrationState::Failed(reason.clone()));
        }

        match (state, event) {
            (MigrationState::NotStarted, MigrationEvent::CapabilitiesReady) => {
                Ok(MigrationState::CapabilitiesCollected)
            }
            (MigrationState::CapabilitiesCollected, MigrationEvent::KeyPackagesReady) => {
                Ok(MigrationState::KeyPackagesPublished)
            }
            (MigrationState::KeyPackagesPublished, MigrationEvent::ModeSelected(_)) => {
                Ok(MigrationState::ModeSelected)
            }
            (MigrationState::ModeSelected, MigrationEvent::BootstrapStarted) => {
                Ok(MigrationState::BootstrapInitiated)
            }
            (MigrationState::BootstrapInitiated, MigrationEvent::BootstrapDone) => {
                Ok(MigrationState::BootstrapComplete)
            }
            (MigrationState::BootstrapComplete, MigrationEvent::FirstFullCommitDone) => {
                Ok(MigrationState::FirstFullCommitDone)
            }
            (MigrationState::FirstFullCommitDone, _) => {
                // FirstFullCommitDone auto-advances to Operational on
                // *any* further non-Failed event. We don't expose
                // an `Operational` event explicitly.
                Ok(MigrationState::Operational)
            }
            (s, e) => Err(MigrationError::InvalidTransition {
                state: s.clone(),
                event: e.clone(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conv_id() -> Vec<u8> {
        b"conv-1".to_vec()
    }

    #[test]
    fn happy_path_drives_through_every_state_to_operational() {
        let mut sm = MigrationStateMachine::new(conv_id());
        assert_eq!(sm.state(), &MigrationState::NotStarted);
        assert!(!sm.is_terminal());

        sm.advance(MigrationEvent::CapabilitiesReady).unwrap();
        assert_eq!(sm.state(), &MigrationState::CapabilitiesCollected);

        sm.advance(MigrationEvent::KeyPackagesReady).unwrap();
        assert_eq!(sm.state(), &MigrationState::KeyPackagesPublished);

        sm.advance(MigrationEvent::ModeSelected(
            SecurityMode::PqConfidentiality,
        ))
        .unwrap();
        assert_eq!(sm.state(), &MigrationState::ModeSelected);
        assert_eq!(sm.target_mode(), Some(SecurityMode::PqConfidentiality));

        sm.advance(MigrationEvent::BootstrapStarted).unwrap();
        assert_eq!(sm.state(), &MigrationState::BootstrapInitiated);

        sm.advance(MigrationEvent::BootstrapDone).unwrap();
        assert_eq!(sm.state(), &MigrationState::BootstrapComplete);

        sm.advance(MigrationEvent::FirstFullCommitDone).unwrap();
        assert_eq!(sm.state(), &MigrationState::FirstFullCommitDone);

        // Any further event auto-advances to Operational.
        sm.advance(MigrationEvent::FirstFullCommitDone).unwrap();
        assert_eq!(sm.state(), &MigrationState::Operational);
        assert!(sm.is_terminal());
    }

    #[test]
    fn invalid_transition_from_not_started_to_operational_is_rejected() {
        let mut sm = MigrationStateMachine::new(conv_id());
        let err = sm
            .advance(MigrationEvent::FirstFullCommitDone)
            .expect_err("must reject");
        assert!(matches!(err, MigrationError::InvalidTransition { .. }));
        // State must be unchanged.
        assert_eq!(sm.state(), &MigrationState::NotStarted);
    }

    #[test]
    fn skipping_capabilities_collection_is_rejected() {
        let mut sm = MigrationStateMachine::new(conv_id());
        let err = sm.advance(MigrationEvent::KeyPackagesReady).unwrap_err();
        assert!(matches!(err, MigrationError::InvalidTransition { .. }));
        assert_eq!(sm.state(), &MigrationState::NotStarted);
    }

    #[test]
    fn terminal_operational_rejects_all_events() {
        let mut sm = MigrationStateMachine::new(conv_id());
        // Drive to Operational.
        sm.advance(MigrationEvent::CapabilitiesReady).unwrap();
        sm.advance(MigrationEvent::KeyPackagesReady).unwrap();
        sm.advance(MigrationEvent::ModeSelected(
            SecurityMode::PqConfidentiality,
        ))
        .unwrap();
        sm.advance(MigrationEvent::BootstrapStarted).unwrap();
        sm.advance(MigrationEvent::BootstrapDone).unwrap();
        sm.advance(MigrationEvent::FirstFullCommitDone).unwrap();
        sm.advance(MigrationEvent::FirstFullCommitDone).unwrap();
        assert!(sm.is_terminal());

        // Every event must be rejected.
        for ev in [
            MigrationEvent::CapabilitiesReady,
            MigrationEvent::KeyPackagesReady,
            MigrationEvent::ModeSelected(SecurityMode::PqConfidentiality),
            MigrationEvent::BootstrapStarted,
            MigrationEvent::BootstrapDone,
            MigrationEvent::FirstFullCommitDone,
            MigrationEvent::Failed("nope".into()),
        ] {
            let err = sm.advance(ev).expect_err("operational rejects all");
            assert!(matches!(err, MigrationError::Terminal { .. }));
        }
    }

    #[test]
    fn terminal_failed_rejects_all_events() {
        let mut sm = MigrationStateMachine::new(conv_id());
        sm.advance(MigrationEvent::Failed("oops".into())).unwrap();
        assert!(sm.is_terminal());

        for ev in [
            MigrationEvent::CapabilitiesReady,
            MigrationEvent::KeyPackagesReady,
            MigrationEvent::Failed("again".into()),
        ] {
            let err = sm.advance(ev).expect_err("failed rejects all");
            assert!(matches!(err, MigrationError::Terminal { .. }));
        }
    }

    #[test]
    fn failed_is_reachable_from_every_non_terminal_state() {
        type Driver = Box<dyn Fn(&mut MigrationStateMachine)>;
        let drivers: Vec<Driver> = vec![
            Box::new(|_sm| { /* NotStarted */ }),
            Box::new(|sm| {
                sm.advance(MigrationEvent::CapabilitiesReady).unwrap();
            }),
            Box::new(|sm| {
                sm.advance(MigrationEvent::CapabilitiesReady).unwrap();
                sm.advance(MigrationEvent::KeyPackagesReady).unwrap();
            }),
            Box::new(|sm| {
                sm.advance(MigrationEvent::CapabilitiesReady).unwrap();
                sm.advance(MigrationEvent::KeyPackagesReady).unwrap();
                sm.advance(MigrationEvent::ModeSelected(
                    SecurityMode::PqConfidentiality,
                ))
                .unwrap();
            }),
            Box::new(|sm| {
                sm.advance(MigrationEvent::CapabilitiesReady).unwrap();
                sm.advance(MigrationEvent::KeyPackagesReady).unwrap();
                sm.advance(MigrationEvent::ModeSelected(
                    SecurityMode::PqConfidentiality,
                ))
                .unwrap();
                sm.advance(MigrationEvent::BootstrapStarted).unwrap();
            }),
            Box::new(|sm| {
                sm.advance(MigrationEvent::CapabilitiesReady).unwrap();
                sm.advance(MigrationEvent::KeyPackagesReady).unwrap();
                sm.advance(MigrationEvent::ModeSelected(
                    SecurityMode::PqConfidentiality,
                ))
                .unwrap();
                sm.advance(MigrationEvent::BootstrapStarted).unwrap();
                sm.advance(MigrationEvent::BootstrapDone).unwrap();
            }),
            Box::new(|sm| {
                sm.advance(MigrationEvent::CapabilitiesReady).unwrap();
                sm.advance(MigrationEvent::KeyPackagesReady).unwrap();
                sm.advance(MigrationEvent::ModeSelected(
                    SecurityMode::PqConfidentiality,
                ))
                .unwrap();
                sm.advance(MigrationEvent::BootstrapStarted).unwrap();
                sm.advance(MigrationEvent::BootstrapDone).unwrap();
                sm.advance(MigrationEvent::FirstFullCommitDone).unwrap();
            }),
        ];

        for (i, driver) in drivers.iter().enumerate() {
            let mut sm = MigrationStateMachine::new(conv_id());
            driver(&mut sm);
            assert!(!sm.is_terminal(), "driver {i} ended in terminal state");

            sm.advance(MigrationEvent::Failed(format!("driver-{i} failure")))
                .unwrap_or_else(|e| panic!("driver {i}: Failed must always succeed: {e:?}"));

            assert!(matches!(sm.state(), MigrationState::Failed(_)));
            assert!(sm.is_terminal());
        }
    }

    #[test]
    fn can_advance_does_not_mutate() {
        let mut sm = MigrationStateMachine::new(conv_id());
        assert!(sm.can_advance(&MigrationEvent::CapabilitiesReady));
        assert!(!sm.can_advance(&MigrationEvent::FirstFullCommitDone));
        // State unchanged after either query.
        assert_eq!(sm.state(), &MigrationState::NotStarted);

        sm.advance(MigrationEvent::CapabilitiesReady).unwrap();
        assert!(sm.can_advance(&MigrationEvent::KeyPackagesReady));
        assert!(!sm.can_advance(&MigrationEvent::CapabilitiesReady));
        // State unchanged.
        assert_eq!(sm.state(), &MigrationState::CapabilitiesCollected);
    }

    #[test]
    fn advance_at_records_started_and_last_transition_timestamps() {
        let mut sm = MigrationStateMachine::new(conv_id());
        assert_eq!(sm.started_at(), None);
        assert_eq!(sm.last_transition_at(), None);

        sm.advance_at(MigrationEvent::CapabilitiesReady, 100)
            .unwrap();
        assert_eq!(sm.started_at(), Some(100));
        assert_eq!(sm.last_transition_at(), Some(100));

        sm.advance_at(MigrationEvent::KeyPackagesReady, 200)
            .unwrap();
        // started_at must NOT update on subsequent transitions.
        assert_eq!(sm.started_at(), Some(100));
        assert_eq!(sm.last_transition_at(), Some(200));
    }

    #[test]
    fn target_mode_is_recorded_on_mode_selected() {
        let mut sm = MigrationStateMachine::new(conv_id());
        sm.advance(MigrationEvent::CapabilitiesReady).unwrap();
        sm.advance(MigrationEvent::KeyPackagesReady).unwrap();
        assert_eq!(sm.target_mode(), None);
        sm.advance(MigrationEvent::ModeSelected(SecurityMode::PqAuthenticity))
            .unwrap();
        assert_eq!(sm.target_mode(), Some(SecurityMode::PqAuthenticity));
    }

    #[test]
    fn state_machine_implements_clone_debug_and_partial_eq() {
        let sm1 = MigrationStateMachine::new(conv_id());
        let sm2 = sm1.clone();
        assert_eq!(sm1, sm2);
        // Debug must not panic.
        let _ = format!("{:?}", sm1);
    }

    #[test]
    fn invalid_transition_in_middle_state_does_not_corrupt_machine() {
        // From CapabilitiesCollected, a stray ModeSelected must be
        // rejected and the machine must remain in
        // CapabilitiesCollected.
        let mut sm = MigrationStateMachine::new(conv_id());
        sm.advance(MigrationEvent::CapabilitiesReady).unwrap();
        let err = sm
            .advance(MigrationEvent::ModeSelected(
                SecurityMode::PqConfidentiality,
            ))
            .unwrap_err();
        assert!(matches!(err, MigrationError::InvalidTransition { .. }));
        assert_eq!(sm.state(), &MigrationState::CapabilitiesCollected);
        // target_mode must NOT be set when the transition was rejected.
        assert_eq!(sm.target_mode(), None);
    }

    #[test]
    fn failed_carries_reason_string() {
        let mut sm = MigrationStateMachine::new(conv_id());
        sm.advance(MigrationEvent::CapabilitiesReady).unwrap();
        sm.advance(MigrationEvent::Failed("provider crashed".into()))
            .unwrap();
        match sm.state() {
            MigrationState::Failed(reason) => assert_eq!(reason, "provider crashed"),
            other => panic!("expected Failed, got {other:?}"),
        }
    }
}
