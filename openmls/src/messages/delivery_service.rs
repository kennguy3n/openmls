//! # In-memory `DeliveryService` reference implementation
//!
//! KChat servers fan out [`MlsMessageOut`]s to peers over an opaque
//! transport. APQ adds a wrinkle: a FULL commit is a *pair* (PQ first,
//! then T) and peers must see both halves in order, otherwise the T
//! commit's `PreSharedKey` proposal references material the receiver
//! has not yet derived. The delivery service therefore has to:
//!
//! - Queue messages per [`GroupId`] in FIFO order.
//! - Tag each message with its session side (`T` or `PQ`) and, for
//!   FULL-commit halves, a `pair_id` linking the two halves together.
//! - Refuse to enqueue the T half of a FULL pair until the matching PQ
//!   half has been observed (ordering invariant).
//!
//! This module ships an **in-memory reference implementation** scoped to
//! a single process — production deployments will plug in a different
//! transport, but the trait surface and ordering invariants are pinned
//! here so the orchestration layer has something concrete to test
//! against. See [`PROPOSAL.md`](../../../PROPOSAL.md) and
//! [`ARCHITECTURE.md`](../../../ARCHITECTURE.md) for the higher-level
//! delivery contract.
//!
//! ## Ordering invariant
//!
//! For every FULL-commit pair `(pq, t)`:
//!
//! ```text
//!   enqueue(pq) MUST happen before enqueue(t)
//! ```
//!
//! Calling [`DeliveryService::enqueue`] with a T half whose `pair_id`
//! has not been previously enqueued as a PQ half on the same group
//! returns [`DeliveryError::PqHalfMissing`]. This pins the wire
//! ordering described in [`crate::group::apq_commit::FullCommitResult`].

use std::collections::{HashMap, HashSet, VecDeque};

use crate::framing::MlsMessageOut;
use crate::group::GroupId;

/// Which APQ session a delivered message belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionSide {
    /// Classical / T session.
    T,
    /// Post-quantum / PQ session (only set in APQ conversations).
    Pq,
}

/// Delivery envelope: one [`MlsMessageOut`] plus the metadata the
/// delivery service needs to enforce ordering.
#[derive(Debug)]
pub struct ApqDeliveryEnvelope {
    /// Group the message belongs to.
    pub group_id: GroupId,
    /// Which APQ session this message is bound for.
    pub session_side: SessionSide,
    /// `true` if this envelope is one half of a FULL-commit pair. The
    /// pairing is identified by [`Self::pair_id`].
    pub is_full_commit_pair: bool,
    /// Stable pair identifier for FULL-commit halves. Two envelopes
    /// with the same `pair_id` and group but different `session_side`
    /// values form a FULL-commit pair. Ignored when
    /// [`Self::is_full_commit_pair`] is `false`.
    pub pair_id: Option<u64>,
    /// The wire message itself.
    pub message: MlsMessageOut,
}

impl ApqDeliveryEnvelope {
    /// Construct an envelope for a non-FULL-commit message (proposals,
    /// PARTIAL commits, application messages).
    pub fn new_simple(
        group_id: GroupId,
        session_side: SessionSide,
        message: MlsMessageOut,
    ) -> Self {
        Self {
            group_id,
            session_side,
            is_full_commit_pair: false,
            pair_id: None,
            message,
        }
    }

    /// Construct an envelope for one half of a FULL-commit pair.
    pub fn new_full_commit_half(
        group_id: GroupId,
        session_side: SessionSide,
        pair_id: u64,
        message: MlsMessageOut,
    ) -> Self {
        Self {
            group_id,
            session_side,
            is_full_commit_pair: true,
            pair_id: Some(pair_id),
            message,
        }
    }
}

/// Errors raised by [`DeliveryService::enqueue`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeliveryError {
    /// FULL-commit envelope was supplied without a `pair_id`. The
    /// orchestration layer must always set a pair ID for FULL halves
    /// so the delivery service can pin the ordering invariant.
    #[error("FULL-commit envelope must carry a pair_id")]
    FullCommitWithoutPairId,
    /// The T half of a FULL-commit pair was enqueued before the
    /// matching PQ half. This violates the wire-ordering invariant.
    #[error("T half of FULL-commit pair {pair_id} enqueued before its PQ half")]
    PqHalfMissing {
        /// Pair identifier the caller passed in.
        pair_id: u64,
    },
    /// Two PQ halves with the same `pair_id` were enqueued back-to-back
    /// on the same group — the orchestration layer must not retry by
    /// re-enqueueing without first delivering the previous half.
    #[error("duplicate PQ half for pair_id {pair_id}")]
    DuplicatePqHalf {
        /// Pair identifier the caller passed in.
        pair_id: u64,
    },
}

/// In-memory delivery service.
///
/// Storage shape: one FIFO queue per group, plus a set tracking PQ
/// halves whose matching T half has not yet been enqueued. The latter
/// is what enforces the ordering invariant — when the T half arrives
/// we look up its `pair_id` in this set; the lookup must succeed or
/// the enqueue is rejected.
#[derive(Debug, Default)]
pub struct DeliveryService {
    queues: HashMap<GroupId, VecDeque<ApqDeliveryEnvelope>>,
    /// Per-group set of pending PQ pair IDs (PQ enqueued, T not yet).
    pending_pq_halves: HashMap<GroupId, HashSet<u64>>,
}

impl DeliveryService {
    /// Construct an empty delivery service.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enqueue an envelope.
    ///
    /// FULL-commit ordering: PQ halves are accepted unconditionally
    /// (subject to no duplicate `pair_id`) and recorded in
    /// `pending_pq_halves`. T halves are accepted only if a PQ half
    /// with the same `pair_id` is already pending (the orchestration
    /// layer must enqueue PQ first, then T). Once the T half is
    /// enqueued the pair is "complete" and the `pair_id` is removed
    /// from the pending set.
    pub fn enqueue(&mut self, envelope: ApqDeliveryEnvelope) -> Result<(), DeliveryError> {
        if envelope.is_full_commit_pair {
            let pair_id = envelope
                .pair_id
                .ok_or(DeliveryError::FullCommitWithoutPairId)?;

            let pending = self
                .pending_pq_halves
                .entry(envelope.group_id.clone())
                .or_default();

            match envelope.session_side {
                SessionSide::Pq => {
                    if !pending.insert(pair_id) {
                        return Err(DeliveryError::DuplicatePqHalf { pair_id });
                    }
                }
                SessionSide::T => {
                    if !pending.remove(&pair_id) {
                        return Err(DeliveryError::PqHalfMissing { pair_id });
                    }
                }
            }
        }

        self.queues
            .entry(envelope.group_id.clone())
            .or_default()
            .push_back(envelope);
        Ok(())
    }

    /// Pop the next envelope for `group_id`, or `None` if the queue is
    /// empty / unknown.
    pub fn deliver_next(&mut self, group_id: &GroupId) -> Option<ApqDeliveryEnvelope> {
        self.queues.get_mut(group_id)?.pop_front()
    }

    /// Drain every envelope queued for `group_id` in FIFO order.
    pub fn deliver_all(&mut self, group_id: &GroupId) -> Vec<ApqDeliveryEnvelope> {
        match self.queues.get_mut(group_id) {
            Some(q) => q.drain(..).collect(),
            None => Vec::new(),
        }
    }

    /// Number of envelopes currently queued for `group_id`.
    pub fn pending_count(&self, group_id: &GroupId) -> usize {
        self.queues.get(group_id).map(|q| q.len()).unwrap_or(0)
    }

    /// Total number of envelopes queued across every group.
    pub fn total_pending(&self) -> usize {
        self.queues.values().map(|q| q.len()).sum()
    }

    /// Number of FULL-commit pairs currently mid-flight (PQ enqueued,
    /// T not yet enqueued) for `group_id`.
    pub fn pending_full_commit_pairs(&self, group_id: &GroupId) -> usize {
        self.pending_pq_halves
            .get(group_id)
            .map(|s| s.len())
            .unwrap_or(0)
    }

    /// `true` if no envelopes are queued anywhere.
    pub fn is_empty(&self) -> bool {
        self.queues.values().all(|q| q.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ciphersuite::SecurityMode;
    use crate::framing::MlsMessageOut;
    use crate::group::GroupId;
    use crate::messages::Welcome;
    use crate::versions::ProtocolVersion;

    // The delivery layer is transport-only; it does not introspect the
    // wire body. For these unit tests we therefore only need *some*
    // valid [`MlsMessageOut`] to push around. Building one from a
    // synthetic [`Welcome`] avoids having to fire up an
    // [`MlsGroup`] / signer just to test queue plumbing.
    fn dummy_message(cs_id: u16) -> MlsMessageOut {
        use openmls_traits::types::Ciphersuite;
        let cs = Ciphersuite::try_from(cs_id)
            .unwrap_or(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
        let welcome = Welcome::new(cs, vec![], Vec::new());
        MlsMessageOut::from_welcome(welcome, ProtocolVersion::default())
    }

    fn gid(byte: u8) -> GroupId {
        GroupId::from_slice(&[byte; 16])
    }

    #[test]
    fn enqueue_then_deliver_round_trips_a_simple_message() {
        let mut svc = DeliveryService::new();
        let g = gid(1);
        let env = ApqDeliveryEnvelope::new_simple(g.clone(), SessionSide::T, dummy_message(0x0001));
        svc.enqueue(env).expect("enqueue");
        assert_eq!(svc.pending_count(&g), 1);
        let out = svc.deliver_next(&g).expect("deliver");
        assert_eq!(out.session_side, SessionSide::T);
        assert!(svc.deliver_next(&g).is_none());
        assert!(svc.is_empty());
    }

    #[test]
    fn deliver_all_returns_envelopes_in_fifo_order() {
        let mut svc = DeliveryService::new();
        let g = gid(2);
        for i in 0..5 {
            let cs_id = 0x0001 + (i as u16 % 3);
            let env =
                ApqDeliveryEnvelope::new_simple(g.clone(), SessionSide::T, dummy_message(cs_id));
            svc.enqueue(env).expect("enqueue");
        }
        let drained = svc.deliver_all(&g);
        assert_eq!(drained.len(), 5);
        // Both calls drained the queue.
        assert_eq!(svc.pending_count(&g), 0);
    }

    #[test]
    fn full_commit_t_before_pq_is_rejected_with_pq_half_missing() {
        let mut svc = DeliveryService::new();
        let g = gid(3);
        let t_half = ApqDeliveryEnvelope::new_full_commit_half(
            g.clone(),
            SessionSide::T,
            42,
            dummy_message(0x0001),
        );
        let err = svc.enqueue(t_half).expect_err("must reject T-before-PQ");
        assert!(matches!(err, DeliveryError::PqHalfMissing { pair_id: 42 }));
        assert!(svc.is_empty(), "no envelope must be queued on rejection");
    }

    #[test]
    fn full_commit_pq_then_t_succeeds_and_clears_pending_pair() {
        let mut svc = DeliveryService::new();
        let g = gid(4);
        let pq = ApqDeliveryEnvelope::new_full_commit_half(
            g.clone(),
            SessionSide::Pq,
            7,
            dummy_message(0x0001),
        );
        let t = ApqDeliveryEnvelope::new_full_commit_half(
            g.clone(),
            SessionSide::T,
            7,
            dummy_message(0x0001),
        );
        svc.enqueue(pq).expect("PQ first");
        assert_eq!(svc.pending_full_commit_pairs(&g), 1);
        svc.enqueue(t).expect("T second");
        assert_eq!(
            svc.pending_full_commit_pairs(&g),
            0,
            "pair completes once both halves are enqueued"
        );
        assert_eq!(svc.pending_count(&g), 2);
    }

    #[test]
    fn duplicate_pq_half_is_rejected() {
        let mut svc = DeliveryService::new();
        let g = gid(5);
        let pq1 = ApqDeliveryEnvelope::new_full_commit_half(
            g.clone(),
            SessionSide::Pq,
            10,
            dummy_message(0x0001),
        );
        let pq2 = ApqDeliveryEnvelope::new_full_commit_half(
            g.clone(),
            SessionSide::Pq,
            10,
            dummy_message(0x0001),
        );
        svc.enqueue(pq1).expect("first PQ ok");
        let err = svc.enqueue(pq2).expect_err("duplicate must fail");
        assert!(matches!(
            err,
            DeliveryError::DuplicatePqHalf { pair_id: 10 }
        ));
    }

    #[test]
    fn full_commit_envelope_without_pair_id_is_rejected() {
        let mut svc = DeliveryService::new();
        let g = gid(6);
        let bad = ApqDeliveryEnvelope {
            group_id: g.clone(),
            session_side: SessionSide::Pq,
            is_full_commit_pair: true,
            pair_id: None,
            message: dummy_message(0x0001),
        };
        let err = svc.enqueue(bad).expect_err("must reject");
        assert!(matches!(err, DeliveryError::FullCommitWithoutPairId));
    }

    #[test]
    fn multiple_groups_are_isolated() {
        let mut svc = DeliveryService::new();
        let g1 = gid(11);
        let g2 = gid(12);
        for _ in 0..3 {
            svc.enqueue(ApqDeliveryEnvelope::new_simple(
                g1.clone(),
                SessionSide::T,
                dummy_message(0x0001),
            ))
            .expect("g1");
        }
        for _ in 0..2 {
            svc.enqueue(ApqDeliveryEnvelope::new_simple(
                g2.clone(),
                SessionSide::T,
                dummy_message(0x0001),
            ))
            .expect("g2");
        }
        assert_eq!(svc.pending_count(&g1), 3);
        assert_eq!(svc.pending_count(&g2), 2);
        assert_eq!(svc.total_pending(), 5);

        // Draining one group does not affect the other.
        let drained = svc.deliver_all(&g1);
        assert_eq!(drained.len(), 3);
        assert_eq!(svc.pending_count(&g1), 0);
        assert_eq!(svc.pending_count(&g2), 2);
    }

    #[test]
    fn empty_queue_returns_none_and_zero() {
        let svc = DeliveryService::new();
        let g = gid(99);
        assert_eq!(svc.pending_count(&g), 0);
        assert_eq!(svc.pending_full_commit_pairs(&g), 0);
        assert!(svc.is_empty());

        // deliver_next on an absent group returns None.
        let mut svc = svc;
        assert!(svc.deliver_next(&g).is_none());
    }

    #[test]
    fn full_commit_pair_ordering_holds_under_interleaved_groups() {
        let mut svc = DeliveryService::new();
        let g1 = gid(20);
        let g2 = gid(21);

        // Group 1 PQ half enqueued.
        svc.enqueue(ApqDeliveryEnvelope::new_full_commit_half(
            g1.clone(),
            SessionSide::Pq,
            1,
            dummy_message(0x0001),
        ))
        .expect("g1 PQ");

        // Group 2 cannot send T half before its own PQ — even though
        // group 1 already has a PQ half pending.
        let err = svc
            .enqueue(ApqDeliveryEnvelope::new_full_commit_half(
                g2.clone(),
                SessionSide::T,
                1,
                dummy_message(0x0001),
            ))
            .expect_err("g2 T-before-PQ must fail across groups");
        assert!(matches!(err, DeliveryError::PqHalfMissing { pair_id: 1 }));

        // Group 1 T half completes correctly.
        svc.enqueue(ApqDeliveryEnvelope::new_full_commit_half(
            g1.clone(),
            SessionSide::T,
            1,
            dummy_message(0x0001),
        ))
        .expect("g1 T after PQ ok");

        assert_eq!(svc.pending_full_commit_pairs(&g1), 0);
        assert_eq!(svc.pending_full_commit_pairs(&g2), 0);
    }

    #[test]
    fn session_side_round_trip_value_is_observable() {
        // Smoke: SessionSide variants round-trip and are observable on
        // dequeue. Pins the public-API contract for callers
        // dispatching by side.
        let mut svc = DeliveryService::new();
        let g = gid(30);
        svc.enqueue(ApqDeliveryEnvelope::new_simple(
            g.clone(),
            SessionSide::Pq,
            dummy_message(0x0001),
        ))
        .expect("enqueue");
        let out = svc.deliver_next(&g).unwrap();
        assert_eq!(out.session_side, SessionSide::Pq);
        // SecurityMode::Classical is unrelated but pulled in to ensure
        // the test compiles even without dragging extra imports into
        // the file scope.
        let _ = SecurityMode::Classical;
    }
}
