//! # PQ telemetry events and emitter trait
//!
//! KChat tracks several PQ-specific failure and lifecycle events that
//! must be observable without leaking plaintext or PSK material:
//!
//! - KeyPackage exhaustion at fetch time,
//! - selection of a ciphersuite the local provider does not support,
//! - missed FULL commit pairs (T or PQ side dropped),
//! - downgrade attempts,
//! - opaque PQ provider errors,
//! - APQ bootstrap completions,
//! - ReInit completions,
//! - resync events.
//!
//! These events are surfaced through the [`PqTelemetryEmitter`] trait so
//! the orchestration layer can plug in any backend (no-op, in-memory for
//! tests, an OTel exporter, etc.) without depending on a particular
//! observability stack.
//!
//! **No event variant carries plaintext or secret material.** All
//! identifiers are opaque byte strings or already-public types
//! (`Ciphersuite`, `SecurityMode`, epoch numbers).

use std::sync::Mutex;

use openmls_traits::types::Ciphersuite;

use crate::ciphersuite::SecurityMode;

/// Structured PQ-specific telemetry events.
///
/// Each variant corresponds to a single, well-defined operational moment
/// the orchestration layer wants to surface. Variants do **not** include
/// any plaintext or secret material; identifiers are opaque bytes or
/// already-public crypto types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PqTelemetryEvent {
    /// A KeyPackage fetch failed because the device has no available KP
    /// for the requested ciphersuite (and either no last-resort KP or
    /// last-resort exhaustion).
    KeyPackageExhaustion {
        /// User identifier as opaque bytes.
        user_id: Vec<u8>,
        /// Device identifier as opaque bytes.
        device_id: Vec<u8>,
        /// Ciphersuite the caller asked for.
        ciphersuite: Ciphersuite,
    },
    /// A ciphersuite was requested that the local provider does not
    /// support (e.g. X-Wing on the RustCrypto provider).
    UnsupportedCiphersuite {
        /// Ciphersuite that triggered the failure.
        ciphersuite: Ciphersuite,
        /// Free-form provider identifier (`"libcrux"`, `"rustcrypto"`,
        /// etc.).
        provider_id: String,
    },
    /// A FULL commit pair (T + PQ) is incomplete: one side committed and
    /// the other did not.
    MissedCommitPair {
        /// Application-level conversation ID.
        conversation_id: Vec<u8>,
        /// Which side missed: `"T"` or `"PQ"`.
        missed_side: String,
        /// T-session epoch at the time of detection.
        t_epoch: u64,
        /// PQ-session epoch at the time of detection.
        pq_epoch: u64,
    },
    /// A downgrade was attempted on a conversation. Surfaced even when
    /// the downgrade is *rejected* so dashboards can spot abuse spikes.
    DowngradeAttempt {
        /// Application-level conversation ID.
        conversation_id: Vec<u8>,
        /// Mode the conversation was at.
        from: SecurityMode,
        /// Mode that was requested (always `< from`).
        to: SecurityMode,
    },
    /// An opaque error from the PQ provider during a named operation.
    /// `error` is a free-form description and MUST NOT contain
    /// plaintext or secret material.
    PqProviderError {
        /// Operation name (e.g. `"hpke_seal"`, `"derive_keypair"`).
        operation: String,
        /// Free-form description of the failure.
        error: String,
    },
    /// An APQ bootstrap completed successfully.
    ApqBootstrapCompleted {
        /// Application-level conversation ID.
        conversation_id: Vec<u8>,
        /// Mode the conversation was bootstrapped into.
        mode: SecurityMode,
        /// Number of members in the conversation after bootstrap.
        member_count: usize,
    },
    /// A ReInit upgrade completed successfully.
    ReInitCompleted {
        /// Application-level conversation ID.
        conversation_id: Vec<u8>,
        /// Ciphersuite of the old (pre-ReInit) group.
        old_ciphersuite: Ciphersuite,
        /// Ciphersuite of the new group.
        new_ciphersuite: Ciphersuite,
    },
    /// A resync was triggered for an APQ conversation. `status` is a
    /// free-form description of the resync flavour
    /// (`"resync_from_pq"`, `"resync_from_t"`, `"force_resync"`).
    ResyncTriggered {
        /// Application-level conversation ID.
        conversation_id: Vec<u8>,
        /// Free-form description of the resync flavour.
        status: String,
    },
}

/// Sink for [`PqTelemetryEvent`]s.
///
/// Implementations are expected to be cheap on the hot path. The default
/// production implementation is [`NoOpTelemetryEmitter`] — the
/// orchestration layer plumbs through a no-op when no observability
/// backend is configured. The [`InMemoryTelemetryEmitter`] is intended
/// for tests.
pub trait PqTelemetryEmitter: Send + Sync {
    /// Emit a single event. Implementations MUST NOT panic on any input
    /// and SHOULD be lock-free or use short critical sections.
    fn emit(&self, event: PqTelemetryEvent);
}

/// Telemetry emitter that drops every event. Use as a default when no
/// observability backend is configured.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoOpTelemetryEmitter;

impl PqTelemetryEmitter for NoOpTelemetryEmitter {
    fn emit(&self, _event: PqTelemetryEvent) {
        // intentional no-op
    }
}

/// In-memory telemetry emitter for tests. Collects every emitted event
/// in insertion order.
#[derive(Debug, Default)]
pub struct InMemoryTelemetryEmitter {
    events: Mutex<Vec<PqTelemetryEvent>>,
}

impl InMemoryTelemetryEmitter {
    /// Construct an empty in-memory emitter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of every event collected so far.
    pub fn events(&self) -> Vec<PqTelemetryEvent> {
        self.events.lock().expect("telemetry mutex").clone()
    }

    /// Number of events collected so far.
    pub fn len(&self) -> usize {
        self.events.lock().expect("telemetry mutex").len()
    }

    /// `true` if no events have been collected yet.
    pub fn is_empty(&self) -> bool {
        self.events.lock().expect("telemetry mutex").is_empty()
    }

    /// Drain every event collected so far.
    pub fn drain(&self) -> Vec<PqTelemetryEvent> {
        std::mem::take(&mut self.events.lock().expect("telemetry mutex"))
    }
}

impl PqTelemetryEmitter for InMemoryTelemetryEmitter {
    fn emit(&self, event: PqTelemetryEvent) {
        self.events.lock().expect("telemetry mutex").push(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classical_cs() -> Ciphersuite {
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    }

    fn xwing_cs() -> Ciphersuite {
        Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519
    }

    #[test]
    fn noop_emitter_silently_accepts_every_event() {
        let emitter = NoOpTelemetryEmitter;
        emitter.emit(PqTelemetryEvent::KeyPackageExhaustion {
            user_id: b"alice".to_vec(),
            device_id: b"phone".to_vec(),
            ciphersuite: xwing_cs(),
        });
        emitter.emit(PqTelemetryEvent::PqProviderError {
            operation: "hpke_seal".into(),
            error: "unsupported".into(),
        });
        // No panic, no observable side-effect.
    }

    #[test]
    fn in_memory_emitter_collects_events_in_order() {
        let emitter = InMemoryTelemetryEmitter::new();
        assert!(emitter.is_empty());

        emitter.emit(PqTelemetryEvent::ApqBootstrapCompleted {
            conversation_id: b"conv-1".to_vec(),
            mode: SecurityMode::PqConfidentiality,
            member_count: 3,
        });
        emitter.emit(PqTelemetryEvent::ReInitCompleted {
            conversation_id: b"conv-2".to_vec(),
            old_ciphersuite: classical_cs(),
            new_ciphersuite: xwing_cs(),
        });
        emitter.emit(PqTelemetryEvent::ResyncTriggered {
            conversation_id: b"conv-3".to_vec(),
            status: "force_resync".into(),
        });

        assert_eq!(emitter.len(), 3);

        let events = emitter.events();
        assert!(matches!(
            events[0],
            PqTelemetryEvent::ApqBootstrapCompleted {
                mode: SecurityMode::PqConfidentiality,
                member_count: 3,
                ..
            }
        ));
        assert!(matches!(
            events[1],
            PqTelemetryEvent::ReInitCompleted { .. }
        ));
        assert!(matches!(
            events[2],
            PqTelemetryEvent::ResyncTriggered { .. }
        ));
    }

    #[test]
    fn drain_empties_the_emitter() {
        let emitter = InMemoryTelemetryEmitter::new();
        emitter.emit(PqTelemetryEvent::DowngradeAttempt {
            conversation_id: b"conv".to_vec(),
            from: SecurityMode::PqAuthenticity,
            to: SecurityMode::PqConfidentiality,
        });
        let drained = emitter.drain();
        assert_eq!(drained.len(), 1);
        assert!(emitter.is_empty());
    }

    #[test]
    fn emitter_trait_object_is_object_safe() {
        let emitter: Box<dyn PqTelemetryEmitter> = Box::new(InMemoryTelemetryEmitter::new());
        emitter.emit(PqTelemetryEvent::UnsupportedCiphersuite {
            ciphersuite: xwing_cs(),
            provider_id: "rustcrypto".into(),
        });
        // Emitting through the trait object compiles → trait is
        // object-safe.
    }

    #[test]
    fn missed_commit_pair_carries_both_epochs() {
        let emitter = InMemoryTelemetryEmitter::new();
        emitter.emit(PqTelemetryEvent::MissedCommitPair {
            conversation_id: b"conv".to_vec(),
            missed_side: "T".into(),
            t_epoch: 5,
            pq_epoch: 6,
        });
        let events = emitter.events();
        match &events[0] {
            PqTelemetryEvent::MissedCommitPair {
                missed_side,
                t_epoch,
                pq_epoch,
                ..
            } => {
                assert_eq!(missed_side, "T");
                assert_eq!(*t_epoch, 5);
                assert_eq!(*pq_epoch, 6);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }
}
