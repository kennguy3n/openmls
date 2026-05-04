//! # FULL/PARTIAL commit policy engine
//!
//! After APQ is bootstrapped, day-to-day commits are governed by a policy
//! engine. The policy maps a [`CommitTrigger`] (why is a commit happening?)
//! and the conversation's [`PqPolicy`] (how strict is this conversation?) to
//! a [`CommitType`] — FULL re-keys both the T and PQ sessions; PARTIAL
//! re-keys only the T session.
//!
//! The trigger × policy table is defined in [`PHASES.md`](../../../PHASES.md)
//! Phase 5. This module implements that table directly, plus helpers for
//! "must this commit be FULL?" / "is this commit allowed to be PARTIAL?"
//! checks used by the orchestration layer.
//!
//! Add and remove are non-negotiable FULL operations: a removed device must
//! lose access to the next PQ-derived secret, otherwise PQ confidentiality
//! is broken.

use serde::{Deserialize, Serialize};

/// How strictly a conversation enforces PQ commit cadence.
///
/// Variants are ordered: `Classical < PqConfidentiality < PqRequired`. Higher
/// = more frequent FULL commits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum PqPolicy {
    /// Classical-only conversation. PQ commits never apply.
    Classical = 0,
    /// PQ confidentiality required. Membership changes (add/remove/external
    /// join), credential rotations, and security-level increases are FULL;
    /// routine refreshes may be PARTIAL.
    PqConfidentiality = 1,
    /// PQ required for every significant operation. Periodic refreshes are
    /// also FULL. Used by high-risk groups.
    PqRequired = 2,
}

/// Whether a commit re-keys both the T and PQ sessions (FULL) or only the T
/// session (PARTIAL).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CommitType {
    /// Update both T and PQ sessions. The orchestration layer commits on the
    /// PQ session first, derives `apq_psk`, then commits on the T session
    /// with a `PreSharedKey(apq_psk_id)` proposal.
    Full,
    /// Update T session only.
    Partial,
    /// No commit needed (e.g. an application message send).
    None,
}

/// What caused a commit to be considered.
///
/// The orchestration layer translates user-facing operations into a
/// [`CommitTrigger`] before consulting [`PqPolicy::required_commit_type`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CommitTrigger {
    /// A new member is being added to the conversation.
    AddMember,
    /// An existing member is being removed.
    RemoveMember,
    /// A new device is joining via an external commit.
    ExternalJoin,
    /// A member is rotating their credential / signature key.
    CredentialRotation,
    /// The conversation is moving to a stronger security level (e.g.
    /// `PqConfidentiality` → `PqAuthenticity`).
    SecurityLevelIncrease,
    /// A scheduled PCS refresh.
    PeriodicRefresh,
    /// A regular user-facing application message — no commit is needed.
    NormalMessage,
}

impl PqPolicy {
    /// What [`CommitType`] is required for a given [`CommitTrigger`] under
    /// this policy?
    ///
    /// Implements the table in [`PHASES.md`](../../../PHASES.md) Phase 5:
    ///
    /// - Add / Remove / External-join → always FULL (PQ confidentiality
    ///   requires re-keying both sessions).
    /// - Credential rotation → FULL.
    /// - Security level increase → FULL.
    /// - Periodic refresh → FULL on `PqRequired`, PARTIAL on
    ///   `PqConfidentiality`, no-op on `Classical`.
    /// - Normal message → never a commit.
    pub const fn required_commit_type(self, trigger: CommitTrigger) -> CommitType {
        match (self, trigger) {
            // Classical conversations don't run a PQ session at all.
            (PqPolicy::Classical, CommitTrigger::NormalMessage) => CommitType::None,
            (PqPolicy::Classical, _) => CommitType::Partial,

            // Adds / removes / external joins always re-key both sessions.
            (
                PqPolicy::PqConfidentiality | PqPolicy::PqRequired,
                CommitTrigger::AddMember
                | CommitTrigger::RemoveMember
                | CommitTrigger::ExternalJoin,
            ) => CommitType::Full,

            // Credential rotation and security-level increases re-key both.
            (
                PqPolicy::PqConfidentiality | PqPolicy::PqRequired,
                CommitTrigger::CredentialRotation | CommitTrigger::SecurityLevelIncrease,
            ) => CommitType::Full,

            // Periodic refresh: configurable. PARTIAL on confidentiality,
            // FULL on required.
            (PqPolicy::PqConfidentiality, CommitTrigger::PeriodicRefresh) => CommitType::Partial,
            (PqPolicy::PqRequired, CommitTrigger::PeriodicRefresh) => CommitType::Full,

            // Normal messages never commit.
            (
                PqPolicy::PqConfidentiality | PqPolicy::PqRequired,
                CommitTrigger::NormalMessage,
            ) => CommitType::None,
        }
    }

    /// Returns `true` if this policy ever requires a PQ session.
    pub const fn uses_pq_session(self) -> bool {
        !matches!(self, PqPolicy::Classical)
    }

    /// Returns `true` if `trigger` MUST be a FULL commit under this policy.
    pub const fn requires_full(self, trigger: CommitTrigger) -> bool {
        matches!(self.required_commit_type(trigger), CommitType::Full)
    }

    /// Returns `true` if `trigger` is allowed to be PARTIAL under this
    /// policy. Note: a `CommitType::None` trigger is NOT considered partial
    /// (it's no commit at all).
    pub const fn allows_partial(self, trigger: CommitTrigger) -> bool {
        matches!(self.required_commit_type(trigger), CommitType::Partial)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_POLICIES: &[PqPolicy] = &[
        PqPolicy::Classical,
        PqPolicy::PqConfidentiality,
        PqPolicy::PqRequired,
    ];

    const ALL_TRIGGERS: &[CommitTrigger] = &[
        CommitTrigger::AddMember,
        CommitTrigger::RemoveMember,
        CommitTrigger::ExternalJoin,
        CommitTrigger::CredentialRotation,
        CommitTrigger::SecurityLevelIncrease,
        CommitTrigger::PeriodicRefresh,
        CommitTrigger::NormalMessage,
    ];

    #[test]
    fn ordering_classical_lt_confidentiality_lt_required() {
        assert!(PqPolicy::Classical < PqPolicy::PqConfidentiality);
        assert!(PqPolicy::PqConfidentiality < PqPolicy::PqRequired);
    }

    #[test]
    fn classical_policy_never_uses_pq_session() {
        assert!(!PqPolicy::Classical.uses_pq_session());
        assert!(PqPolicy::PqConfidentiality.uses_pq_session());
        assert!(PqPolicy::PqRequired.uses_pq_session());
    }

    #[test]
    fn add_is_full_under_pq_policies() {
        assert_eq!(
            PqPolicy::PqConfidentiality.required_commit_type(CommitTrigger::AddMember),
            CommitType::Full
        );
        assert_eq!(
            PqPolicy::PqRequired.required_commit_type(CommitTrigger::AddMember),
            CommitType::Full
        );
    }

    #[test]
    fn remove_is_full_under_pq_policies() {
        assert_eq!(
            PqPolicy::PqConfidentiality.required_commit_type(CommitTrigger::RemoveMember),
            CommitType::Full
        );
        assert_eq!(
            PqPolicy::PqRequired.required_commit_type(CommitTrigger::RemoveMember),
            CommitType::Full
        );
    }

    #[test]
    fn external_join_is_full_under_pq_policies() {
        assert_eq!(
            PqPolicy::PqConfidentiality.required_commit_type(CommitTrigger::ExternalJoin),
            CommitType::Full
        );
        assert_eq!(
            PqPolicy::PqRequired.required_commit_type(CommitTrigger::ExternalJoin),
            CommitType::Full
        );
    }

    #[test]
    fn credential_rotation_is_full_under_pq_policies() {
        assert_eq!(
            PqPolicy::PqConfidentiality.required_commit_type(CommitTrigger::CredentialRotation),
            CommitType::Full
        );
        assert_eq!(
            PqPolicy::PqRequired.required_commit_type(CommitTrigger::CredentialRotation),
            CommitType::Full
        );
    }

    #[test]
    fn security_increase_is_full_under_pq_policies() {
        assert_eq!(
            PqPolicy::PqConfidentiality.required_commit_type(CommitTrigger::SecurityLevelIncrease),
            CommitType::Full
        );
        assert_eq!(
            PqPolicy::PqRequired.required_commit_type(CommitTrigger::SecurityLevelIncrease),
            CommitType::Full
        );
    }

    #[test]
    fn periodic_refresh_partial_on_conf_full_on_required() {
        assert_eq!(
            PqPolicy::PqConfidentiality.required_commit_type(CommitTrigger::PeriodicRefresh),
            CommitType::Partial
        );
        assert_eq!(
            PqPolicy::PqRequired.required_commit_type(CommitTrigger::PeriodicRefresh),
            CommitType::Full
        );
    }

    #[test]
    fn normal_message_never_commits_on_pq_policies() {
        assert_eq!(
            PqPolicy::PqConfidentiality.required_commit_type(CommitTrigger::NormalMessage),
            CommitType::None
        );
        assert_eq!(
            PqPolicy::PqRequired.required_commit_type(CommitTrigger::NormalMessage),
            CommitType::None
        );
        assert_eq!(
            PqPolicy::Classical.required_commit_type(CommitTrigger::NormalMessage),
            CommitType::None
        );
    }

    #[test]
    fn classical_policy_returns_partial_for_all_membership_triggers() {
        // Classical conversations only have a T session, but the policy
        // engine still returns PARTIAL (= "T-only commit") so the caller can
        // continue to gate on `requires_full` without a special case.
        for trigger in [
            CommitTrigger::AddMember,
            CommitTrigger::RemoveMember,
            CommitTrigger::ExternalJoin,
            CommitTrigger::CredentialRotation,
            CommitTrigger::PeriodicRefresh,
        ] {
            assert_eq!(
                PqPolicy::Classical.required_commit_type(trigger),
                CommitType::Partial,
                "trigger {trigger:?} should be Partial under Classical"
            );
        }
    }

    #[test]
    fn requires_full_matches_required_commit_type() {
        for &policy in ALL_POLICIES {
            for &trigger in ALL_TRIGGERS {
                let expect_full = matches!(
                    policy.required_commit_type(trigger),
                    CommitType::Full
                );
                assert_eq!(
                    policy.requires_full(trigger),
                    expect_full,
                    "requires_full disagrees for {policy:?} / {trigger:?}"
                );
            }
        }
    }

    #[test]
    fn allows_partial_matches_required_commit_type() {
        for &policy in ALL_POLICIES {
            for &trigger in ALL_TRIGGERS {
                let expect_partial = matches!(
                    policy.required_commit_type(trigger),
                    CommitType::Partial
                );
                assert_eq!(
                    policy.allows_partial(trigger),
                    expect_partial,
                    "allows_partial disagrees for {policy:?} / {trigger:?}"
                );
            }
        }
    }

    #[test]
    fn full_partial_none_are_disjoint_for_every_combo() {
        // Sanity: requires_full and allows_partial cannot both be true for
        // the same (policy, trigger) pair.
        for &policy in ALL_POLICIES {
            for &trigger in ALL_TRIGGERS {
                assert!(
                    !(policy.requires_full(trigger) && policy.allows_partial(trigger)),
                    "{policy:?} / {trigger:?} both full and partial?"
                );
            }
        }
    }
}
