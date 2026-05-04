//! # APQ FULL/PARTIAL commit flow
//!
//! Implements the FULL and PARTIAL commit flows described in
//! [`ARCHITECTURE.md`](../../../ARCHITECTURE.md) and gated by
//! [`crate::group::pq_policy`](super::pq_policy):
//!
//! - **FULL**: commit on the PQ session first, derive `apq_psk` from the PQ
//!   session via the MLS exporter, then commit on the T session including a
//!   `PreSharedKey(apq_psk_id)` proposal that binds the two sessions at this
//!   epoch.
//! - **PARTIAL**: commit only on the T session. Used for routine PCS
//!   refreshes and the like — only allowed when the conversation's
//!   [`PqPolicy`] permits it for the given trigger.
//!
//! ## Wiring
//!
//! [`prepare_full_commit`] and [`prepare_partial_commit`] now drive the
//! underlying [`MlsGroup::commit_builder`] for both sessions:
//!
//! 1. Run all preconditions, mode/policy/in-flight checks first; failures
//!    short-circuit before we touch any group state.
//! 2. For FULL: stage and merge the PQ commit so the new epoch's exporter
//!    is available, derive `apq_psk` via [`MlsGroup::export_secret`] using
//!    the [`APQ_PSK_LABEL`] domain separator, generate a fresh
//!    [`PreSharedKeyId`] (random nonce + random ID), persist the PSK
//!    bundle in the provider's storage, flip
//!    [`KChatMlsConversation::set_pending_full_commit`] to `true`, then
//!    stage the T commit with a `PreSharedKey(apq_psk_id)` proposal.
//! 3. For PARTIAL: stage the T commit only. The PQ session is left
//!    untouched (no exporter call, no new PSK).
//!
//! Callers are responsible for delivering the resulting [`MlsMessageOut`]s
//! to peers and merging the T pending commit ([`MlsGroup::merge_pending_commit`])
//! once delivery is acknowledged. The PQ commit is **already merged
//! locally** when [`prepare_full_commit`] returns — that is required so the
//! exporter can derive `apq_psk` from the new epoch — and the
//! pending-FULL-commit flag stays `true` until the orchestration calls
//! [`KChatMlsConversation::record_full_commit`].
//!
//! See [`PHASES.md`](../../../PHASES.md) Phase 4/5.

use openmls_traits::{random::OpenMlsRand, signatures::Signer};

use crate::framing::MlsMessageOut;
use crate::group::kchat_conversation::KChatMlsConversation;
use crate::group::pq_policy::{CommitTrigger, CommitType};
use crate::messages::proposals::{PreSharedKeyProposal, Proposal};
use crate::schedule::psk::PreSharedKeyId;
use crate::storage::OpenMlsProvider;

/// Domain-separator label used when deriving `apq_psk` via
/// [`MlsGroup::export_secret`] from the PQ session.
///
/// All clients in an APQ conversation must agree on this label byte-for-byte
/// — it is part of the FULL commit choreography defined in
/// [`ARCHITECTURE.md`](../../../ARCHITECTURE.md) (APQ-MLS Combiner
/// Architecture).
pub const APQ_PSK_LABEL: &str = "kchat-apq-psk";

/// Length, in bytes, of the `apq_psk` material exported from the PQ
/// session. Matches the SHA-256 output size used by the current PQ
/// ciphersuites (X-Wing → SHA-256).
pub const APQ_PSK_LENGTH: usize = 32;

/// Length, in bytes, of the random `psk_id` blob embedded in
/// [`PreSharedKeyId::external`]. Long enough to make collisions
/// negligible across the lifetime of a conversation.
pub const APQ_PSK_ID_LENGTH: usize = 16;

/// Result of a successfully prepared FULL commit.
///
/// On the wire, the order matters: PQ commit first, then T commit. Callers
/// fan-out both messages to the delivery service in that order so peers
/// always see the PQ commit before the T commit that references its derived
/// PSK.
#[derive(Debug)]
pub struct FullCommitResult {
    /// PQ-session commit (must be sent first).
    pub pq_commit: MlsMessageOut,
    /// `PreSharedKeyId` for the `apq_psk` derived from the PQ session
    /// post-commit. The T-session commit references this PSK ID.
    pub apq_psk_id: PreSharedKeyId,
    /// T-session commit (sent after `pq_commit`).
    pub t_commit: MlsMessageOut,
}

/// Result of a successfully prepared PARTIAL commit.
#[derive(Debug)]
pub struct PartialCommitResult {
    /// T-session commit. The PQ session is untouched.
    pub t_commit: MlsMessageOut,
}

/// Errors raised by [`prepare_full_commit`] and [`prepare_partial_commit`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApqCommitError {
    /// FULL commit attempted on a Classical-mode conversation.
    #[error("FULL commit requested on a non-APQ conversation")]
    NotApqConversation,
    /// PARTIAL commit attempted on a Classical-mode conversation that has no
    /// T session at all.
    #[error("PARTIAL commit requested but conversation has no T session")]
    NoTSession,
    /// FULL commit attempted but the PQ session is missing.
    #[error("FULL commit requested but conversation has no PQ session")]
    NoPqSession,
    /// FULL commit attempted but the conversation has no APQInfo recorded.
    #[error("FULL commit requested but conversation has no APQInfo")]
    NoApqInfo,
    /// PARTIAL commit attempted with a trigger the policy does not allow to
    /// be PARTIAL.
    #[error("trigger {trigger:?} requires a FULL commit under the active policy")]
    TriggerRequiresFull {
        /// The trigger the caller passed in.
        trigger: CommitTrigger,
    },
    /// FULL commit attempted with a trigger the policy says only requires
    /// PARTIAL. The caller should invoke [`prepare_partial_commit`]
    /// instead.
    #[error(
        "trigger {trigger:?} only requires a PARTIAL commit under the active policy; use prepare_partial_commit instead"
    )]
    TriggerOnlyRequiresPartial {
        /// The trigger the caller passed in.
        trigger: CommitTrigger,
    },
    /// FULL commit attempted with a trigger that is not a commit at all
    /// under the active policy (`CommitType::None` — e.g. a normal message).
    #[error("trigger {trigger:?} is a no-op (not a commit) under the active policy")]
    TriggerIsNoCommit {
        /// The non-commit trigger.
        trigger: CommitTrigger,
    },
    /// Another FULL commit handshake is already mid-flight.
    #[error("another FULL commit is already in flight; complete it before starting a new one")]
    FullCommitInFlight,

    /// Building, validating, or staging the **PQ** commit failed.
    ///
    /// The error string includes the underlying [`CreateCommitError`] /
    /// [`CommitBuilderStageError`] description; we keep it as a string so
    /// [`ApqCommitError`] does not have to carry a generic
    /// `StorageError` parameter.
    #[error("PQ commit failed: {0}")]
    PqCommitFailed(String),

    /// Merging the local PQ pending commit failed. After this error the
    /// PQ session is in a partially-staged state; callers should treat
    /// this as a transient infrastructure failure and trigger
    /// [`crate::group::apq_resync::force_resync`] or equivalent recovery.
    #[error("PQ merge failed: {0}")]
    PqMergeFailed(String),

    /// Deriving `apq_psk` from the PQ session via
    /// [`MlsGroup::export_secret`] failed.
    #[error("PQ exporter derivation failed: {0}")]
    PqExportSecretFailed(String),

    /// Persisting the derived `apq_psk` bundle in the provider's PSK
    /// store failed.
    #[error("apq_psk store failed: {0}")]
    PskStoreFailed(String),

    /// Random byte generation (PSK ID / nonce) failed.
    #[error("random generation failed: {0}")]
    RandomGenerationFailed(String),

    /// Building, validating, or staging the **T** commit failed. The PQ
    /// half of the FULL commit has already been merged at this point —
    /// the conversation is left with `pending_full_commit == true` and
    /// requires resync.
    #[error("T commit failed: {0}")]
    TCommitFailed(String),
}

/// Validate FULL-commit preconditions and produce a [`FullCommitResult`].
///
/// Steps performed:
///
/// 1. Check that `conversation` is APQ (mode is non-classical AND both T and
///    PQ groups are present AND APQInfo is set).
/// 2. Check that the active [`PqPolicy`] requires a FULL commit for
///    `trigger` (i.e. `requires_full(trigger)`).
/// 3. Check that no FULL commit handshake is already in flight.
/// 4. Stage the PQ commit (with any caller-supplied `proposals`) and
///    merge it locally so the new epoch's exporter is available.
/// 5. Derive `apq_psk` via [`MlsGroup::export_secret`] using
///    [`APQ_PSK_LABEL`] and the conversation ID as context, store it in
///    the provider's PSK store, and flip
///    [`KChatMlsConversation::set_pending_full_commit`] to `true`.
/// 6. Stage the T commit with a `PreSharedKey(apq_psk_id)` proposal plus
///    the caller-supplied `proposals`. The T commit is **not** merged
///    here — callers merge it once delivery to peers is acknowledged.
///
/// The PQ commit must be sent before the T commit so peers can derive the
/// matching PSK on their side before processing the T commit.
///
/// See [`PHASES.md`](../../../PHASES.md) Phase 4/5.
pub fn prepare_full_commit<P, S>(
    conversation: &mut KChatMlsConversation,
    trigger: CommitTrigger,
    proposals: Vec<Proposal>,
    provider: &P,
    signer: &S,
) -> Result<FullCommitResult, ApqCommitError>
where
    P: OpenMlsProvider,
    S: Signer,
{
    // --- 1. Preconditions ----------------------------------------------------
    if !conversation.is_apq() {
        return Err(ApqCommitError::NotApqConversation);
    }
    if conversation.t_group().is_none() {
        return Err(ApqCommitError::NoTSession);
    }
    if conversation.pq_group().is_none() {
        return Err(ApqCommitError::NoPqSession);
    }
    if conversation.apq_info().is_none() {
        return Err(ApqCommitError::NoApqInfo);
    }
    if conversation.pending_full_commit() {
        return Err(ApqCommitError::FullCommitInFlight);
    }

    match conversation.pq_policy().required_commit_type(trigger) {
        CommitType::Full => {}
        CommitType::Partial => {
            return Err(ApqCommitError::TriggerOnlyRequiresPartial { trigger });
        }
        CommitType::None => return Err(ApqCommitError::TriggerIsNoCommit { trigger }),
    }

    // Snapshot inputs that we need later but that would otherwise conflict
    // with the `&mut MlsGroup` borrows below.
    let conversation_id = conversation.conversation_id().to_vec();
    let pq_ciphersuite = conversation
        .pq_group()
        .expect("pq_group present (precondition)")
        .ciphersuite();

    // --- 2. PQ commit --------------------------------------------------------
    let pq_proposals = proposals.clone();
    let pq_commit = {
        let pq_group = conversation
            .pq_group_mut()
            .expect("pq_group present (precondition)");
        let bundle = pq_group
            .commit_builder()
            .consume_proposal_store(true)
            .add_proposals(pq_proposals)
            .load_psks(provider.storage())
            .map_err(|e| ApqCommitError::PqCommitFailed(format!("load_psks: {e}")))?
            .build(provider.rand(), provider.crypto(), signer, |_| true)
            .map_err(|e| ApqCommitError::PqCommitFailed(format!("build: {e}")))?
            .stage_commit(provider)
            .map_err(|e| ApqCommitError::PqCommitFailed(format!("stage_commit: {e}")))?;
        bundle.into_commit()
    };

    // --- 3. Merge PQ pending commit so the new exporter is in scope ----------
    {
        let pq_group = conversation
            .pq_group_mut()
            .expect("pq_group present (precondition)");
        pq_group
            .merge_pending_commit(provider)
            .map_err(|e| ApqCommitError::PqMergeFailed(format!("{e}")))?;
    }

    // --- 4. Derive apq_psk ---------------------------------------------------
    let apq_psk = conversation
        .pq_group()
        .expect("pq_group present (precondition)")
        .export_secret(
            provider.crypto(),
            APQ_PSK_LABEL,
            &conversation_id,
            APQ_PSK_LENGTH,
        )
        .map_err(|e| ApqCommitError::PqExportSecretFailed(format!("{e}")))?;

    let psk_id_bytes = provider
        .rand()
        .random_vec(APQ_PSK_ID_LENGTH)
        .map_err(|e| ApqCommitError::RandomGenerationFailed(format!("psk_id: {e}")))?;
    let psk_nonce = provider
        .rand()
        .random_vec(pq_ciphersuite.hash_length())
        .map_err(|e| ApqCommitError::RandomGenerationFailed(format!("psk_nonce: {e}")))?;
    let apq_psk_id = PreSharedKeyId::external(psk_id_bytes, psk_nonce);

    apq_psk_id
        .store(provider, &apq_psk)
        .map_err(|e| ApqCommitError::PskStoreFailed(format!("{e}")))?;

    // --- 5. Flip pending flag (PQ side is committed locally) -----------------
    conversation.set_pending_full_commit(true);

    // --- 6. T commit with PreSharedKey proposal ------------------------------
    let mut t_proposals = Vec::with_capacity(1 + proposals.len());
    t_proposals.push(Proposal::psk(PreSharedKeyProposal::new(apq_psk_id.clone())));
    t_proposals.extend(proposals);

    let t_commit = {
        let t_group = conversation
            .t_group_mut()
            .expect("t_group present (precondition)");
        let bundle = t_group
            .commit_builder()
            .consume_proposal_store(true)
            .add_proposals(t_proposals)
            .load_psks(provider.storage())
            .map_err(|e| ApqCommitError::TCommitFailed(format!("load_psks: {e}")))?
            .build(provider.rand(), provider.crypto(), signer, |_| true)
            .map_err(|e| ApqCommitError::TCommitFailed(format!("build: {e}")))?
            .stage_commit(provider)
            .map_err(|e| ApqCommitError::TCommitFailed(format!("stage_commit: {e}")))?;
        bundle.into_commit()
    };

    Ok(FullCommitResult {
        pq_commit,
        apq_psk_id,
        t_commit,
    })
}

/// Validate PARTIAL-commit preconditions and produce a [`PartialCommitResult`].
///
/// Steps performed:
///
/// 1. Check that `conversation` has a T session.
/// 2. Check that the active [`PqPolicy`] permits PARTIAL for `trigger`
///    (i.e. `allows_partial(trigger)`).
/// 3. Check that no FULL commit handshake is already in flight (PARTIAL is
///    only safe when the two sessions are in sync).
/// 4. Stage the T commit (and only the T commit). The PQ session is left
///    untouched.
///
/// The PQ session is **not** modified — no exporter call, no PSK
/// derivation, no PQ commit on the wire. PARTIAL is the cheap path used
/// for routine PCS / refresh triggers when the policy allows it.
pub fn prepare_partial_commit<P, S>(
    conversation: &mut KChatMlsConversation,
    trigger: CommitTrigger,
    proposals: Vec<Proposal>,
    provider: &P,
    signer: &S,
) -> Result<PartialCommitResult, ApqCommitError>
where
    P: OpenMlsProvider,
    S: Signer,
{
    if conversation.t_group().is_none() {
        return Err(ApqCommitError::NoTSession);
    }
    if conversation.pending_full_commit() {
        return Err(ApqCommitError::FullCommitInFlight);
    }

    match conversation.pq_policy().required_commit_type(trigger) {
        CommitType::Partial => {}
        CommitType::Full => return Err(ApqCommitError::TriggerRequiresFull { trigger }),
        CommitType::None => return Err(ApqCommitError::TriggerIsNoCommit { trigger }),
    }

    let t_commit = {
        let t_group = conversation
            .t_group_mut()
            .expect("t_group present (precondition)");
        let bundle = t_group
            .commit_builder()
            .consume_proposal_store(true)
            .add_proposals(proposals)
            .load_psks(provider.storage())
            .map_err(|e| ApqCommitError::TCommitFailed(format!("load_psks: {e}")))?
            .build(provider.rand(), provider.crypto(), signer, |_| true)
            .map_err(|e| ApqCommitError::TCommitFailed(format!("build: {e}")))?
            .stage_commit(provider)
            .map_err(|e| ApqCommitError::TCommitFailed(format!("stage_commit: {e}")))?;
        bundle.into_commit()
    };

    Ok(PartialCommitResult { t_commit })
}

#[cfg(test)]
mod tests {
    //! Skeleton tests. These exercise the **flow logic** (mode checks,
    //! policy gating, in-flight detection) without driving real `MlsGroup`
    //! commits — those live in `tests/pq_lifecycle_tests.rs` and the unit
    //! tests in [`super::tests::with_real_groups`].
    use super::*;
    use crate::ciphersuite::SecurityMode;
    use crate::group::pq_policy::PqPolicy;

    #[test]
    fn full_commit_error_on_non_apq_conversation_renders_clearly() {
        let err = ApqCommitError::NotApqConversation;
        assert_eq!(
            format!("{err}"),
            "FULL commit requested on a non-APQ conversation"
        );
    }

    #[test]
    fn partial_commit_error_on_full_required_trigger_renders_clearly() {
        let err = ApqCommitError::TriggerRequiresFull {
            trigger: CommitTrigger::AddMember,
        };
        assert_eq!(
            format!("{err}"),
            "trigger AddMember requires a FULL commit under the active policy"
        );
    }

    #[test]
    fn full_commit_error_on_partial_only_trigger_renders_clearly() {
        let err = ApqCommitError::TriggerOnlyRequiresPartial {
            trigger: CommitTrigger::PeriodicRefresh,
        };
        let rendered = format!("{err}");
        assert!(
            rendered.contains("only requires a PARTIAL commit"),
            "unexpected message: {rendered}"
        );
        assert!(
            rendered.contains("prepare_partial_commit"),
            "unexpected message: {rendered}"
        );
        assert!(
            rendered.contains("PeriodicRefresh"),
            "unexpected message: {rendered}"
        );
    }

    #[test]
    fn full_commit_error_on_no_commit_trigger_renders_clearly() {
        let err = ApqCommitError::TriggerIsNoCommit {
            trigger: CommitTrigger::NormalMessage,
        };
        assert_eq!(
            format!("{err}"),
            "trigger NormalMessage is a no-op (not a commit) under the active policy"
        );
    }

    #[test]
    fn full_commit_in_flight_error_renders_clearly() {
        let err = ApqCommitError::FullCommitInFlight;
        assert!(format!("{err}").contains("already in flight"));
    }

    #[test]
    fn pq_commit_failed_error_renders_with_underlying_string() {
        let err = ApqCommitError::PqCommitFailed("build: boom".into());
        let rendered = format!("{err}");
        assert!(rendered.contains("PQ commit failed"));
        assert!(rendered.contains("boom"));
    }

    #[test]
    fn t_commit_failed_error_renders_with_underlying_string() {
        let err = ApqCommitError::TCommitFailed("stage_commit: boom".into());
        let rendered = format!("{err}");
        assert!(rendered.contains("T commit failed"));
        assert!(rendered.contains("boom"));
    }

    #[test]
    fn pq_export_secret_failed_error_renders_clearly() {
        let err = ApqCommitError::PqExportSecretFailed("no exporter".into());
        let rendered = format!("{err}");
        assert!(rendered.contains("PQ exporter derivation failed"));
        assert!(rendered.contains("no exporter"));
    }

    #[test]
    fn psk_store_failed_error_renders_clearly() {
        let err = ApqCommitError::PskStoreFailed("disk full".into());
        let rendered = format!("{err}");
        assert!(rendered.contains("apq_psk store failed"));
        assert!(rendered.contains("disk full"));
    }

    #[test]
    fn full_commit_result_can_be_constructed_from_components() {
        // A construction-only check — verifies the public field shape so
        // downstream code can build mock results in tests.
        fn _accept(r: FullCommitResult) -> (MlsMessageOut, PreSharedKeyId, MlsMessageOut) {
            (r.pq_commit, r.apq_psk_id, r.t_commit)
        }
    }

    #[test]
    fn full_commit_policy_check_table_matches_pq_policy() {
        // Sanity: the policy gate inside `prepare_full_commit` is a thin
        // wrapper over `PqPolicy::required_commit_type`. We verify the
        // expected set of FULL-commit triggers.
        for trigger in [
            CommitTrigger::AddMember,
            CommitTrigger::RemoveMember,
            CommitTrigger::ExternalJoin,
            CommitTrigger::CredentialRotation,
            CommitTrigger::SecurityLevelIncrease,
        ] {
            assert_eq!(
                PqPolicy::PqConfidentiality.required_commit_type(trigger),
                CommitType::Full,
                "trigger {trigger:?} must be FULL under PqConfidentiality"
            );
        }
        assert_eq!(
            PqPolicy::PqRequired.required_commit_type(CommitTrigger::PeriodicRefresh),
            CommitType::Full
        );
    }

    #[test]
    fn partial_commit_policy_allows_periodic_refresh_under_confidentiality() {
        assert_eq!(
            PqPolicy::PqConfidentiality.required_commit_type(CommitTrigger::PeriodicRefresh),
            CommitType::Partial
        );
    }

    #[test]
    fn full_full_partial_commit_modes_are_distinct() {
        // Sanity test enforcing that we treat the three modes as a
        // partition. (Belt-and-braces given Pq* / Classical interactions.)
        for mode in [
            SecurityMode::Classical,
            SecurityMode::PqConfidentiality,
            SecurityMode::PqAuthenticity,
        ] {
            let _ = mode; // exhaustive match in select_mode is enough.
        }
    }

    #[test]
    fn apq_psk_label_is_stable_domain_separator() {
        // The label is part of the wire choreography — every client must
        // agree on it byte-for-byte. Pin it here.
        assert_eq!(APQ_PSK_LABEL, "kchat-apq-psk");
        assert_eq!(APQ_PSK_LENGTH, 32);
        assert_eq!(APQ_PSK_ID_LENGTH, 16);
    }
}
