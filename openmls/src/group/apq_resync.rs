//! # APQ resync — recovering from missed half-commits
//!
//! In APQ a FULL commit is a **pair** of MLS commits (PQ first, then T).
//! If a client misses one half — for example, the PQ commit got lost in
//! transit while the T commit arrived — the conversation drifts: the
//! local T epoch and PQ epoch no longer match the orchestration's view
//! of the FULL-commit cadence.
//!
//! This module implements the recovery primitives:
//!
//! - [`detect_desync`] — compute a [`DesyncReport`] over the live
//!   epochs and the recorded [`ApqInfo`] / `last_full_commit_epoch`.
//! - [`resync_from_pq`] — apply a missed PQ commit and re-derive the
//!   matching `apq_psk` so the next T commit can verify it.
//! - [`resync_from_t`] — apply a missed T commit (the PSK is already in
//!   the store from a previous PQ resync).
//! - [`force_resync`] — last-resort: drive a fresh FULL commit to bring
//!   both sessions back into lockstep.
//!
//! See [`PHASES.md`](../../../PHASES.md) Phase 5 (Adoption / Recovery).

use openmls_traits::signatures::Signer;

use crate::framing::{MlsMessageIn, ProcessedMessageContent, ProtocolMessage};
use crate::group::apq_commit::{
    prepare_full_commit, ApqCommitError, FullCommitResult, APQ_PSK_LABEL, APQ_PSK_LENGTH,
};
use crate::group::kchat_conversation::KChatMlsConversation;
use crate::group::pq_policy::CommitTrigger;
use crate::schedule::psk::PreSharedKeyId;
use crate::storage::OpenMlsProvider;

/// Maximum number of epochs the T and PQ sessions are allowed to drift
/// apart before the orchestration layer should treat the conversation as
/// "desynced" and refuse routine commits.
///
/// Keeping this small (1) means a single missed FULL-commit half is the
/// upper bound — anything larger and we force a recovery. PHASES.md
/// Phase 5 leaves the value tunable; 1 is the strictest setting.
pub const MAX_EPOCH_DRIFT: u64 = 1;

/// High-level desync classification produced by [`detect_desync`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesyncStatus {
    /// Both sessions are in lockstep relative to the recorded
    /// [`ApqInfo`] and `last_full_commit_epoch`.
    InSync,
    /// PQ session is ahead by one epoch — typical sign that the PQ
    /// commit landed but the T commit is still in flight.
    PqAhead {
        /// How many epochs the PQ session is ahead of the T session
        /// (relative to the FULL-commit cadence).
        delta: u64,
    },
    /// T session is ahead by one epoch — typical sign that the T
    /// commit landed but the PQ commit is still in flight (rare:
    /// peers should send PQ first).
    TAhead {
        /// How many epochs the T session is ahead of the PQ session.
        delta: u64,
    },
    /// Drift exceeds [`MAX_EPOCH_DRIFT`] in either direction — recovery
    /// via incremental resync is no longer safe; callers should fall
    /// back to [`force_resync`].
    DriftExceeded {
        /// Absolute epoch delta between T and PQ.
        delta: u64,
    },
}

/// Detailed desync report.
#[derive(Debug, Clone)]
pub struct DesyncReport {
    /// Top-level classification.
    pub status: DesyncStatus,
    /// Live T-session epoch (`None` if the conversation has no T group).
    pub t_epoch: Option<u64>,
    /// Live PQ-session epoch (`None` if the conversation has no PQ
    /// group).
    pub pq_epoch: Option<u64>,
    /// `true` if the orchestration is currently in the middle of a FULL
    /// commit handshake (so a single-epoch drift is *expected*, not a
    /// bug).
    pub pending_full_commit: bool,
}

impl DesyncReport {
    /// `true` when [`Self::status`] indicates the sessions are out of
    /// sync (any non-[`DesyncStatus::InSync`] variant).
    pub fn is_desynced(&self) -> bool {
        !matches!(self.status, DesyncStatus::InSync)
    }
}

/// Result of a successful [`resync_from_pq`] / [`resync_from_t`] step.
#[derive(Debug)]
pub struct ResyncResult {
    /// `true` if the conversation is now back in lockstep (both
    /// sessions on the same FULL-commit epoch).
    pub recovered: bool,
    /// Live T-session epoch after the resync step.
    pub t_epoch: u64,
    /// Live PQ-session epoch after the resync step.
    pub pq_epoch: u64,
}

/// Errors raised by the resync helpers.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApqResyncError {
    /// Conversation is not APQ — there is nothing to resync.
    #[error("conversation is not APQ")]
    NotApqConversation,
    /// Conversation is missing the T session (cannot resync without
    /// it).
    #[error("conversation has no T session")]
    NoTSession,
    /// Conversation is missing the PQ session (cannot resync without
    /// it).
    #[error("conversation has no PQ session")]
    NoPqSession,
    /// Processing the missed PQ commit failed.
    #[error("PQ commit processing failed: {0}")]
    PqProcessingFailed(String),
    /// Processing the missed T commit failed.
    #[error("T commit processing failed: {0}")]
    TProcessingFailed(String),
    /// Merging a staged commit failed.
    #[error("staged commit merge failed: {0}")]
    MergeFailed(String),
    /// The supplied missed message is not a commit (e.g. it's a
    /// proposal-only message).
    #[error("missed message is not a commit")]
    NotACommit,
    /// Deriving the post-resync `apq_psk` failed.
    #[error("apq_psk derivation failed: {0}")]
    ExportSecretFailed(String),
    /// Random byte generation failed.
    #[error("random generation failed: {0}")]
    RandomGenerationFailed(String),
    /// Persisting the resynced `apq_psk` failed.
    #[error("apq_psk store failed: {0}")]
    PskStoreFailed(String),
    /// [`force_resync`] called [`prepare_full_commit`] which itself
    /// returned an error.
    #[error("forced FULL commit failed: {0}")]
    ForcedFullCommitFailed(ApqCommitError),
}

/// Compute a [`DesyncReport`] over `conversation`'s current state.
///
/// The check is a **pure function** of the live epochs and the recorded
/// `last_full_commit_epoch` — it never mutates state and never touches
/// the network.
pub fn detect_desync(conversation: &KChatMlsConversation) -> DesyncReport {
    let t_epoch = conversation.t_group().map(|g| g.epoch().as_u64());
    let pq_epoch = conversation.pq_group().map(|g| g.epoch().as_u64());
    let pending_full_commit = conversation.pending_full_commit();

    let status = match (t_epoch, pq_epoch) {
        (Some(t), Some(pq)) => {
            let delta = t.abs_diff(pq);
            if delta == 0 {
                DesyncStatus::InSync
            } else if delta > MAX_EPOCH_DRIFT {
                DesyncStatus::DriftExceeded { delta }
            } else if pq > t {
                DesyncStatus::PqAhead { delta }
            } else {
                DesyncStatus::TAhead { delta }
            }
        }
        // Single-session conversations (Classical / DIRECT_PQ) can't be
        // out of sync because there's nothing to be out of sync with.
        _ => DesyncStatus::InSync,
    };

    DesyncReport {
        status,
        t_epoch,
        pq_epoch,
        pending_full_commit,
    }
}

/// Apply a missed PQ commit and re-derive the matching `apq_psk`.
///
/// Steps:
///
/// 1. Process the supplied [`MlsMessageIn`] on the PQ session.
/// 2. Merge the staged commit so the new PQ epoch is live.
/// 3. Derive a fresh `apq_psk` via [`crate::group::mls_group::MlsGroup::export_secret`]
///    using [`APQ_PSK_LABEL`] and the conversation ID.
/// 4. Persist it under `expected_psk_id` so the matching T commit (whose
///    `PreSharedKey` proposal references the **same** ID — chosen by the
///    sender during [`prepare_full_commit`]) can be loaded by the
///    standard MLS PSK lookup when the caller follows up with
///    [`resync_from_t`].
///
/// `expected_psk_id` is supplied by the caller — typically extracted
/// from the missed T commit's `PreSharedKey` proposal before calling
/// this function. Generating a fresh random ID here would not match
/// what the wire commit references and would silently break the
/// recovery path.
pub fn resync_from_pq<P>(
    conversation: &mut KChatMlsConversation,
    missed_pq_commit: MlsMessageIn,
    expected_psk_id: PreSharedKeyId,
    provider: &P,
) -> Result<(ResyncResult, PreSharedKeyId), ApqResyncError>
where
    P: OpenMlsProvider,
{
    if !conversation.is_apq() {
        return Err(ApqResyncError::NotApqConversation);
    }
    if conversation.pq_group().is_none() {
        return Err(ApqResyncError::NoPqSession);
    }
    if conversation.t_group().is_none() {
        return Err(ApqResyncError::NoTSession);
    }

    conversation.emit_resync_triggered("resync_from_pq");

    let conversation_id = conversation.conversation_id().to_vec();

    // 1. Process the missed PQ commit ----------------------------------------
    let protocol_msg: ProtocolMessage = ProtocolMessage::try_from(missed_pq_commit)
        .map_err(|e| ApqResyncError::PqProcessingFailed(format!("{e:?}")))?;
    let processed = {
        let pq_group = conversation
            .pq_group_mut()
            .expect("pq_group present (precondition)");
        pq_group
            .process_message(provider, protocol_msg)
            .map_err(|e| ApqResyncError::PqProcessingFailed(format!("{e}")))?
    };

    let staged_commit = match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(boxed) => *boxed,
        _ => return Err(ApqResyncError::NotACommit),
    };

    // 2. Merge ---------------------------------------------------------------
    {
        let pq_group = conversation
            .pq_group_mut()
            .expect("pq_group present (precondition)");
        pq_group
            .merge_staged_commit(provider, staged_commit)
            .map_err(|e| ApqResyncError::MergeFailed(format!("{e}")))?;
    }

    // 3. Derive new apq_psk and persist under the wire-referenced ID --------
    let apq_psk = conversation
        .pq_group()
        .expect("pq_group present (precondition)")
        .export_secret(
            provider.crypto(),
            APQ_PSK_LABEL,
            &conversation_id,
            APQ_PSK_LENGTH,
        )
        .map_err(|e| ApqResyncError::ExportSecretFailed(format!("{e}")))?;

    expected_psk_id
        .store(provider, &apq_psk)
        .map_err(|e| ApqResyncError::PskStoreFailed(format!("{e}")))?;

    // The PQ side is now ahead — caller still owes us a T commit. Flip
    // the pending-FULL-commit flag so subsequent calls to
    // `prepare_partial_commit` short-circuit until the T commit lands.
    conversation.set_pending_full_commit(true);

    let report = detect_desync(conversation);
    Ok((
        ResyncResult {
            recovered: matches!(report.status, DesyncStatus::InSync),
            t_epoch: report.t_epoch.unwrap_or(0),
            pq_epoch: report.pq_epoch.unwrap_or(0),
        },
        expected_psk_id,
    ))
}

/// Apply a missed T commit on the T session.
///
/// Assumes the matching PSK is already in the provider's PSK store (e.g.
/// because [`resync_from_pq`] ran before this call, or because the
/// conversation never lost the PQ commit in the first place).
pub fn resync_from_t<P>(
    conversation: &mut KChatMlsConversation,
    missed_t_commit: MlsMessageIn,
    provider: &P,
) -> Result<ResyncResult, ApqResyncError>
where
    P: OpenMlsProvider,
{
    if !conversation.is_apq() {
        return Err(ApqResyncError::NotApqConversation);
    }
    if conversation.t_group().is_none() {
        return Err(ApqResyncError::NoTSession);
    }

    conversation.emit_resync_triggered("resync_from_t");

    let protocol_msg: ProtocolMessage = ProtocolMessage::try_from(missed_t_commit)
        .map_err(|e| ApqResyncError::TProcessingFailed(format!("{e:?}")))?;
    let processed = {
        let t_group = conversation
            .t_group_mut()
            .expect("t_group present (precondition)");
        t_group
            .process_message(provider, protocol_msg)
            .map_err(|e| ApqResyncError::TProcessingFailed(format!("{e}")))?
    };

    let staged_commit = match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(boxed) => *boxed,
        _ => return Err(ApqResyncError::NotACommit),
    };

    {
        let t_group = conversation
            .t_group_mut()
            .expect("t_group present (precondition)");
        t_group
            .merge_staged_commit(provider, staged_commit)
            .map_err(|e| ApqResyncError::MergeFailed(format!("{e}")))?;
    }

    let report = detect_desync(conversation);
    let recovered = matches!(report.status, DesyncStatus::InSync);
    if recovered {
        // Both sides are level again — clear the in-flight flag and
        // record this as the most recent FULL-commit epoch.
        let t_epoch = report.t_epoch.unwrap_or(0);
        conversation.record_full_commit(t_epoch);
    }

    Ok(ResyncResult {
        recovered,
        t_epoch: report.t_epoch.unwrap_or(0),
        pq_epoch: report.pq_epoch.unwrap_or(0),
    })
}

/// Last-resort recovery: drive a fresh FULL commit to bring both
/// sessions back into lockstep.
///
/// Used when [`detect_desync`] reports [`DesyncStatus::DriftExceeded`] or
/// when [`resync_from_pq`] / [`resync_from_t`] cannot apply the missed
/// commits (e.g. because they have already been pruned at the DS).
pub fn force_resync<P, S>(
    conversation: &mut KChatMlsConversation,
    provider: &P,
    signer: &S,
) -> Result<FullCommitResult, ApqResyncError>
where
    P: OpenMlsProvider,
    S: Signer,
{
    if !conversation.is_apq() {
        return Err(ApqResyncError::NotApqConversation);
    }

    conversation.emit_resync_triggered("force_resync");

    // Clear any stale in-flight flag — a force resync is the moral
    // equivalent of "I don't trust the previous handshake; start a new
    // one."
    conversation.set_pending_full_commit(false);

    prepare_full_commit(
        conversation,
        CommitTrigger::SecurityLevelIncrease,
        Vec::new(),
        provider,
        signer,
    )
    .map_err(ApqResyncError::ForcedFullCommitFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desync_status_in_sync_zero_delta() {
        // A pure-classification test using the public types.
        let report = DesyncReport {
            status: DesyncStatus::InSync,
            t_epoch: Some(7),
            pq_epoch: Some(7),
            pending_full_commit: false,
        };
        assert!(!report.is_desynced());
    }

    #[test]
    fn desync_status_pq_ahead_one_epoch() {
        let report = DesyncReport {
            status: DesyncStatus::PqAhead { delta: 1 },
            t_epoch: Some(7),
            pq_epoch: Some(8),
            pending_full_commit: true,
        };
        assert!(report.is_desynced());
    }

    #[test]
    fn desync_status_drift_exceeded_two_epochs() {
        let report = DesyncReport {
            status: DesyncStatus::DriftExceeded { delta: 2 },
            t_epoch: Some(5),
            pq_epoch: Some(7),
            pending_full_commit: false,
        };
        assert!(report.is_desynced());
    }

    #[test]
    fn max_epoch_drift_is_one() {
        // Pin the constant — a change here changes the resync semantics
        // for every consumer.
        assert_eq!(MAX_EPOCH_DRIFT, 1);
    }

    #[test]
    fn not_apq_conversation_error_renders_clearly() {
        let err = ApqResyncError::NotApqConversation;
        assert_eq!(format!("{err}"), "conversation is not APQ");
    }

    #[test]
    fn not_a_commit_error_renders_clearly() {
        let err = ApqResyncError::NotACommit;
        assert_eq!(format!("{err}"), "missed message is not a commit");
    }

    #[test]
    fn pq_processing_failed_error_propagates_underlying_string() {
        let err = ApqResyncError::PqProcessingFailed("invalid signature".into());
        let rendered = format!("{err}");
        assert!(rendered.contains("PQ commit processing failed"));
        assert!(rendered.contains("invalid signature"));
    }

    #[test]
    fn forced_full_commit_failed_wraps_apq_commit_error() {
        let err = ApqResyncError::ForcedFullCommitFailed(ApqCommitError::FullCommitInFlight);
        let rendered = format!("{err}");
        assert!(rendered.contains("forced FULL commit failed"));
        assert!(rendered.contains("already in flight"));
    }
}
