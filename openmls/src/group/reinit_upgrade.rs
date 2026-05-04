//! # MLS ReInit upgrade flow
//!
//! Implements the ReInit upgrade path described in
//! [`PHASES.md`](../../../PHASES.md) Phase 3. ReInit is the simplest path
//! for migrating a small group (1:1 or a handful of devices) from a
//! classical ciphersuite to a PQ ciphersuite without running APQ in
//! parallel: the old group is reinitialized as a new group with the
//! target ciphersuite, members are welcomed into the new group with a
//! `Resumption(ReInit)` PSK that ties the two epochs together, and the
//! old group is sealed read-only.
//!
//! ## Flow
//!
//! 1. [`propose_reinit`] builds a [`ReInitProposal`] for the new
//!    ciphersuite + new group ID. The caller still needs to drop this
//!    proposal into the group's commit builder; this helper just builds
//!    the proposal value.
//! 2. [`commit_reinit`] stages a commit on the old group containing only
//!    that ReInit proposal. After the commit is merged, the old group is
//!    in the [`MlsGroupState::Inactive`] state — it can no longer be used
//!    to send commits or messages.
//! 3. [`complete_reinit`] derives the `Resumption(ReInit)` PSK from the
//!    old group at its final epoch, persists it under a fresh
//!    [`PreSharedKeyId`], and returns that PSK ID so the orchestration
//!    layer can include it in the new group's Welcome and the new
//!    group's first commit.
//!
//! ## Caveats / scoping
//!
//! Current upstream OpenMLS lists ReInit as a partially-supported
//! proposal type — the proposal can be queued and committed, but the
//! state machine for "old group inactive → new group with resumption
//! PSK" is left to the orchestration layer. This module wires that
//! orchestration; the underlying MLS bits live in [`MlsGroup`].
//!
//! See [`PHASES.md`](../../../PHASES.md) Phase 3 for the upgrade
//! decision tree.

use openmls_traits::random::OpenMlsRand;
use openmls_traits::signatures::Signer;
use openmls_traits::types::Ciphersuite;

use crate::ciphersuite::SecurityMode;
use crate::extensions::Extensions;
use crate::framing::MlsMessageOut;
use crate::group::mls_group::MlsGroup;
use crate::group::{GroupEpoch, GroupId};
use crate::messages::proposals::{Proposal, ReInitProposal};
use crate::schedule::psk::{PreSharedKeyId, ResumptionPskUsage};
use crate::storage::OpenMlsProvider;
use crate::versions::ProtocolVersion;

/// Domain-separator label used when deriving the `Resumption(ReInit)` PSK
/// from the old group via [`MlsGroup::export_secret`].
///
/// Pinned here so all clients agree on the byte layout. Different from
/// [`crate::group::apq_commit::APQ_PSK_LABEL`] — these are independent PSKs
/// with independent purposes.
pub const REINIT_PSK_LABEL: &str = "kchat-reinit-psk";

/// Length, in bytes, of the resumption PSK material exported from the old
/// group at ReInit time.
pub const REINIT_PSK_LENGTH: usize = 32;

/// Length of the random `psk_nonce` blob attached to the resumption
/// [`PreSharedKeyId`].
pub const REINIT_PSK_NONCE_LENGTH: usize = 32;

/// Errors raised by the ReInit orchestration helpers.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReInitError {
    /// Caller supplied a target ciphersuite identical to the old group's.
    #[error("ReInit target ciphersuite {got:?} matches the old group's ciphersuite — nothing to upgrade")]
    TargetCiphersuiteSameAsOld {
        /// The redundant ciphersuite the caller passed in.
        got: Ciphersuite,
    },
    /// Caller asked for a downgrade (target mode is lower than old mode).
    #[error("ReInit would downgrade the conversation security mode from {old:?} to {target:?}")]
    DowngradeAttempt {
        /// Mode of the old group.
        old: SecurityMode,
        /// Mode the target ciphersuite would imply.
        target: SecurityMode,
    },
    /// Old group is not in the [`MlsGroupState::Operational`] state — it
    /// has either already been ReInit-ed or was previously evicted.
    #[error("old group is not active (already inactive / evicted)")]
    OldGroupInactive,
    /// Building / staging the ReInit commit on the old group failed.
    #[error("ReInit commit on old group failed: {0}")]
    CommitFailed(String),
    /// Merging the ReInit commit on the old group failed.
    #[error("ReInit merge on old group failed: {0}")]
    MergeFailed(String),
    /// [`MlsGroup::export_secret`] failed when deriving the resumption PSK.
    #[error("export of ReInit resumption PSK failed: {0}")]
    ExportSecretFailed(String),
    /// Random byte generation (PSK nonce) failed.
    #[error("random generation failed: {0}")]
    RandomGenerationFailed(String),
    /// Persisting the resumption PSK in the provider's PSK store failed.
    #[error("resumption PSK store failed: {0}")]
    PskStoreFailed(String),
    /// `commit_reinit` produced an [`MlsGroupState`] that the caller did
    /// not expect.
    #[error("ReInit commit did not transition old group to Inactive (state machine drift)")]
    OldGroupStillActive,
}

/// Parameters for a ReInit upgrade.
///
/// Construct via [`Self::new`] and pass to [`propose_reinit`] /
/// [`commit_reinit`] / [`complete_reinit`].
#[derive(Debug, Clone)]
pub struct ReInitPlan {
    /// Group ID for the **new** group. Must be different from the old
    /// group's ID.
    pub new_group_id: GroupId,
    /// Protocol version of the new group. Defaults to
    /// [`ProtocolVersion::default`] in [`Self::new`].
    pub new_version: ProtocolVersion,
    /// Ciphersuite of the new group. Must differ from the old group's
    /// ciphersuite (otherwise there is nothing to ReInit).
    pub new_ciphersuite: Ciphersuite,
    /// Group context extensions for the new group. Empty by default.
    pub new_extensions: Extensions<crate::group::GroupContext>,
}

impl ReInitPlan {
    /// Build a [`ReInitPlan`] with sensible defaults for `new_version`
    /// and empty `new_extensions`.
    pub fn new(new_group_id: GroupId, new_ciphersuite: Ciphersuite) -> Self {
        Self {
            new_group_id,
            new_version: ProtocolVersion::default(),
            new_ciphersuite,
            new_extensions: Extensions::default(),
        }
    }
}

/// Result of [`commit_reinit`].
#[derive(Debug)]
pub struct ReInitCommit {
    /// The ReInit commit message to deliver to peers.
    pub commit: MlsMessageOut,
    /// The optional Welcome / GroupInfo from staging — for ReInit there
    /// is no Welcome (no new joiners), but the field is reserved here for
    /// completeness.
    pub welcome: Option<MlsMessageOut>,
}

/// Result of [`complete_reinit`].
#[derive(Debug)]
pub struct ReInitResumption {
    /// The PSK ID to include as a `PreSharedKey` proposal in the **new**
    /// group's first commit (or in its Welcome, depending on the path).
    pub resumption_psk_id: PreSharedKeyId,
    /// Group ID of the old (now read-only) group.
    pub old_group_id: GroupId,
    /// Final epoch of the old group at ReInit time.
    pub old_group_epoch: GroupEpoch,
    /// Ciphersuite the old group ran under.
    pub old_ciphersuite: Ciphersuite,
}

/// Build a [`ReInitProposal`] for the upgrade.
///
/// Pure function — does not mutate the group. The caller is expected to
/// hand the returned [`Proposal`] to [`commit_reinit`].
pub fn propose_reinit(old_group: &MlsGroup, plan: &ReInitPlan) -> Result<Proposal, ReInitError> {
    if plan.new_ciphersuite == old_group.ciphersuite() {
        return Err(ReInitError::TargetCiphersuiteSameAsOld {
            got: plan.new_ciphersuite,
        });
    }

    let old_mode = SecurityMode::from_ciphersuite(old_group.ciphersuite());
    let new_mode = SecurityMode::from_ciphersuite(plan.new_ciphersuite);
    if (new_mode as u8) < (old_mode as u8) {
        return Err(ReInitError::DowngradeAttempt {
            old: old_mode,
            target: new_mode,
        });
    }

    let proposal = ReInitProposal {
        group_id: plan.new_group_id.clone(),
        version: plan.new_version,
        ciphersuite: plan.new_ciphersuite,
        extensions: plan.new_extensions.clone(),
    };

    Ok(Proposal::ReInit(Box::new(proposal)))
}

/// Stage and merge a ReInit commit on `old_group`.
///
/// After this returns successfully, `old_group.is_active()` is `false` —
/// the group can no longer be used for new commits or messages, and
/// callers should treat it as read-only.
pub fn commit_reinit<P, S>(
    old_group: &mut MlsGroup,
    plan: &ReInitPlan,
    provider: &P,
    signer: &S,
) -> Result<ReInitCommit, ReInitError>
where
    P: OpenMlsProvider,
    S: Signer,
{
    if !old_group.is_active() {
        return Err(ReInitError::OldGroupInactive);
    }

    let proposal = propose_reinit(old_group, plan)?;

    let bundle = old_group
        .commit_builder()
        .consume_proposal_store(true)
        .add_proposal(proposal)
        .load_psks(provider.storage())
        .map_err(|e| ReInitError::CommitFailed(format!("load_psks: {e}")))?
        .build(provider.rand(), provider.crypto(), signer, |_| true)
        .map_err(|e| ReInitError::CommitFailed(format!("build: {e}")))?
        .stage_commit(provider)
        .map_err(|e| ReInitError::CommitFailed(format!("stage_commit: {e}")))?;

    // We have to take ownership here so we can pull `commit` and
    // `welcome` out separately. The bundle's `into_commit()` consumes
    // the bundle and returns just the commit; we keep the welcome
    // (which will be `None` for a pure ReInit) in `welcome`.
    let commit_msg = bundle.into_commit();

    Ok(ReInitCommit {
        commit: commit_msg,
        welcome: None,
    })
}

/// Derive the `Resumption(ReInit)` PSK from `old_group` at its current
/// (post-ReInit-commit-merge) epoch and persist it in the provider.
///
/// The returned [`PreSharedKeyId`] should be included in the **new**
/// group's first commit (or Welcome) so all members tie the new group's
/// initial epoch to the old group's final epoch.
pub fn complete_reinit<P>(
    old_group: &MlsGroup,
    provider: &P,
) -> Result<ReInitResumption, ReInitError>
where
    P: OpenMlsProvider,
{
    let conversation_id_bytes = old_group.group_id().as_slice().to_vec();
    let psk_secret = old_group
        .export_secret(
            provider.crypto(),
            REINIT_PSK_LABEL,
            &conversation_id_bytes,
            REINIT_PSK_LENGTH,
        )
        .map_err(|e| ReInitError::ExportSecretFailed(format!("{e}")))?;

    let psk_nonce = provider
        .rand()
        .random_vec(REINIT_PSK_NONCE_LENGTH)
        .map_err(|e| ReInitError::RandomGenerationFailed(format!("psk_nonce: {e}")))?;

    let resumption_psk_id = PreSharedKeyId::resumption(
        ResumptionPskUsage::Reinit,
        old_group.group_id().clone(),
        old_group.epoch(),
        psk_nonce,
    );

    resumption_psk_id
        .store(provider, &psk_secret)
        .map_err(|e| ReInitError::PskStoreFailed(format!("{e}")))?;

    Ok(ReInitResumption {
        resumption_psk_id,
        old_group_id: old_group.group_id().clone(),
        old_group_epoch: old_group.epoch(),
        old_ciphersuite: old_group.ciphersuite(),
    })
}

#[cfg(test)]
mod tests {
    //! Unit tests covering the **pure** parts of the ReInit flow:
    //! parameter validation, proposal construction, error rendering. The
    //! group-state-machine pieces are exercised by the integration tests
    //! in `tests/pq_lifecycle_tests.rs`.
    use super::*;

    fn classical_cs() -> Ciphersuite {
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    }

    fn xwing_cs() -> Ciphersuite {
        Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519
    }

    #[test]
    fn reinit_plan_defaults_are_sensible() {
        let plan = ReInitPlan::new(GroupId::from_slice(&[7u8; 16]), xwing_cs());
        assert_eq!(plan.new_ciphersuite, xwing_cs());
        assert_eq!(plan.new_version, ProtocolVersion::default());
        assert!(plan.new_extensions.iter().next().is_none());
    }

    #[test]
    fn target_cs_same_as_old_error_renders_clearly() {
        let err = ReInitError::TargetCiphersuiteSameAsOld {
            got: classical_cs(),
        };
        let rendered = format!("{err}");
        assert!(
            rendered.contains("matches the old group"),
            "unexpected message: {rendered}"
        );
        assert!(
            rendered.contains("nothing to upgrade"),
            "unexpected message: {rendered}"
        );
    }

    #[test]
    fn downgrade_attempt_error_renders_clearly() {
        let err = ReInitError::DowngradeAttempt {
            old: SecurityMode::PqAuthenticity,
            target: SecurityMode::Classical,
        };
        let rendered = format!("{err}");
        assert!(rendered.contains("PqAuthenticity"));
        assert!(rendered.contains("Classical"));
        assert!(rendered.contains("downgrade"));
    }

    #[test]
    fn old_group_inactive_error_renders_clearly() {
        let err = ReInitError::OldGroupInactive;
        assert_eq!(
            format!("{err}"),
            "old group is not active (already inactive / evicted)"
        );
    }

    #[test]
    fn commit_failed_error_propagates_underlying_string() {
        let err = ReInitError::CommitFailed("stage_commit: boom".into());
        let rendered = format!("{err}");
        assert!(rendered.contains("ReInit commit on old group failed"));
        assert!(rendered.contains("boom"));
    }

    #[test]
    fn export_secret_failed_error_renders_clearly() {
        let err = ReInitError::ExportSecretFailed("no exporter".into());
        let rendered = format!("{err}");
        assert!(rendered.contains("export of ReInit resumption PSK failed"));
        assert!(rendered.contains("no exporter"));
    }

    #[test]
    fn psk_store_failed_error_renders_clearly() {
        let err = ReInitError::PskStoreFailed("disk full".into());
        let rendered = format!("{err}");
        assert!(rendered.contains("resumption PSK store failed"));
        assert!(rendered.contains("disk full"));
    }

    #[test]
    fn reinit_psk_label_is_stable_domain_separator() {
        assert_eq!(REINIT_PSK_LABEL, "kchat-reinit-psk");
        assert_eq!(REINIT_PSK_LENGTH, 32);
        assert_eq!(REINIT_PSK_NONCE_LENGTH, 32);
        assert_ne!(
            REINIT_PSK_LABEL,
            crate::group::apq_commit::APQ_PSK_LABEL,
            "ReInit PSK and APQ PSK must use different labels"
        );
    }
}
