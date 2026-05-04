//! # No-downgrade enforcement
//!
//! Once a conversation reaches a stronger [`SecurityMode`], the orchestration
//! layer must reject anything that tries to silently move it back to a weaker
//! mode. This module implements the rules from
//! [`PHASES.md`](../../../PHASES.md) Phase 6 as pure functions over a small
//! [`ConversationSecurityState`] snapshot.
//!
//! Validations live here (rather than in the call sites) so they can be:
//!
//! - unit-tested exhaustively without spinning up MLS groups, and
//! - called from both client orchestration code and the policy-aware server
//!   bridge with a single source of truth.

use openmls_traits::types::Ciphersuite;

use crate::ciphersuite::SecurityMode;
use crate::extensions::apq_info::ApqInfo;

/// Snapshot of a conversation's security state used for no-downgrade
/// validation.
///
/// `current_mode` is the mode the conversation is *currently* operating in;
/// `highest_mode_ever` is the strongest mode the conversation has ever
/// reached (so a `PqAuthenticity` conversation that briefly drops to
/// `PqConfidentiality` is still detected as a downgrade); `policy_floor` is
/// the lowest mode the conversation is *allowed* to be in (administrative
/// floor); and `pinned_ciphersuite` is the ciphersuite the conversation was
/// bootstrapped with — once APQ is bootstrapped, the suite is pinned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationSecurityState {
    /// Currently-operating mode.
    pub current_mode: SecurityMode,
    /// Highest mode this conversation has ever held.
    pub highest_mode_ever: SecurityMode,
    /// Lowest mode the conversation is administratively allowed to operate
    /// in.
    pub policy_floor: SecurityMode,
    /// Ciphersuite the conversation is pinned to, if any. `None` before
    /// APQ bootstrap.
    pub pinned_ciphersuite: Option<Ciphersuite>,
}

impl ConversationSecurityState {
    /// Construct a fresh state with `current_mode == highest_mode_ever ==
    /// policy_floor` and no pinned ciphersuite.
    pub fn new(mode: SecurityMode) -> Self {
        Self {
            current_mode: mode,
            highest_mode_ever: mode,
            policy_floor: mode,
            pinned_ciphersuite: None,
        }
    }

    /// Apply a successful upgrade to `to`. Bumps `current_mode` and (if
    /// applicable) `highest_mode_ever`.
    pub fn record_upgrade(&mut self, to: SecurityMode) {
        self.current_mode = to;
        if to > self.highest_mode_ever {
            self.highest_mode_ever = to;
        }
    }
}

/// Reasons a proposed change is rejected as a downgrade.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DowngradeError {
    /// `to < from`: the proposed mode is strictly weaker than the current
    /// mode.
    #[error("downgrade from {from:?} to {to:?} rejected: cannot move to a weaker security mode")]
    ModeDowngrade {
        /// Previous mode.
        from: SecurityMode,
        /// Proposed weaker mode.
        to: SecurityMode,
    },
    /// `to < highest_mode_ever`: the proposed mode is below the highest mode
    /// the conversation has ever reached.
    #[error(
        "mode change to {to:?} rejected: conversation has previously reached {highest:?}"
    )]
    BelowHighestEver {
        /// Highest mode this conversation has ever reached.
        highest: SecurityMode,
        /// Proposed weaker mode.
        to: SecurityMode,
    },
    /// `to < policy_floor`: the proposed mode is below the administrative
    /// policy floor.
    #[error("mode change to {to:?} rejected: below policy floor {floor:?}")]
    BelowPolicyFloor {
        /// Administrative floor the conversation must stay at or above.
        floor: SecurityMode,
        /// Proposed weaker mode.
        to: SecurityMode,
    },
    /// A `PqRequired` conversation received a classical-only KeyPackage.
    #[error(
        "joiner KeyPackage with mode {kp_mode:?} rejected: conversation requires {required:?}"
    )]
    JoinerKeyPackageNotPq {
        /// Mode of the joiner's KeyPackage.
        kp_mode: SecurityMode,
        /// Mode required by the conversation.
        required: SecurityMode,
    },
    /// APQInfo was removed from a conversation that previously had it.
    #[error("APQInfo removal rejected: conversation must keep APQInfo once bootstrapped")]
    ApqInfoRemoval,
    /// APQInfo's mode changed without authorization (i.e. it was rewritten
    /// to a weaker mode).
    #[error(
        "APQInfo mode change from {old:?} to {new:?} rejected: not authorized as upgrade"
    )]
    ApqInfoModeDowngrade {
        /// Previous APQInfo mode.
        old: SecurityMode,
        /// Proposed weaker APQInfo mode.
        new: SecurityMode,
    },
    /// APQInfo's pinned ciphersuite was changed after bootstrap.
    #[error(
        "APQInfo ciphersuite change from {old:?} to {new:?} rejected: pinned at bootstrap"
    )]
    ApqInfoCiphersuiteChange {
        /// Pinned ciphersuite.
        old: Ciphersuite,
        /// Proposed new ciphersuite.
        new: Ciphersuite,
    },
    /// `t_epoch` and `pq_epoch` drifted past the maximum allowed gap.
    #[error("APQInfo epoch mismatch: t_epoch {t_epoch} vs pq_epoch {pq_epoch} (max drift {max})")]
    EpochMismatch {
        /// T-session epoch.
        t_epoch: u64,
        /// PQ-session epoch.
        pq_epoch: u64,
        /// Maximum permitted drift.
        max: u64,
    },
    /// The conversation is pinned to a ciphersuite and the proposed change
    /// would violate the pin.
    #[error("ciphersuite change from pinned {pinned:?} to {proposed:?} rejected")]
    PinnedCiphersuiteChange {
        /// Currently-pinned suite.
        pinned: Ciphersuite,
        /// Proposed (different) suite.
        proposed: Ciphersuite,
    },
}

/// Maximum permitted drift between `t_epoch` and `pq_epoch`. Mirrors
/// [`crate::extensions::apq_info::MAX_EPOCH_DRIFT`].
pub const MAX_EPOCH_DRIFT: u64 = 1;

/// Validate a proposed mode transition for `state`.
///
/// Rejects:
///
/// - `to < from` (strict downgrade),
/// - `to < state.highest_mode_ever`,
/// - `to < state.policy_floor`.
pub fn validate_mode_change(
    state: &ConversationSecurityState,
    to: SecurityMode,
) -> Result<(), DowngradeError> {
    if !SecurityMode::allows_transition(state.current_mode, to) {
        return Err(DowngradeError::ModeDowngrade {
            from: state.current_mode,
            to,
        });
    }
    if to < state.highest_mode_ever {
        return Err(DowngradeError::BelowHighestEver {
            highest: state.highest_mode_ever,
            to,
        });
    }
    if to < state.policy_floor {
        return Err(DowngradeError::BelowPolicyFloor {
            floor: state.policy_floor,
            to,
        });
    }
    Ok(())
}

/// Validate that a joiner's KeyPackage is acceptable for `mode`.
///
/// Concretely: a `PqAuthenticity` or `PqConfidentiality` (i.e. PQ-required)
/// conversation cannot accept a classical-only KeyPackage. The KeyPackage's
/// mode is derived from its ciphersuite via [`SecurityMode::from_ciphersuite`].
pub fn validate_joiner_key_package(
    mode: SecurityMode,
    key_package_ciphersuite: Ciphersuite,
) -> Result<(), DowngradeError> {
    let kp_mode = SecurityMode::from_ciphersuite(key_package_ciphersuite);
    match mode {
        SecurityMode::Classical => Ok(()),
        SecurityMode::PqConfidentiality | SecurityMode::PqAuthenticity => {
            if kp_mode < mode {
                Err(DowngradeError::JoinerKeyPackageNotPq {
                    kp_mode,
                    required: mode,
                })
            } else {
                Ok(())
            }
        }
    }
}

/// Validate a proposed APQInfo replacement.
///
/// Rejects:
///
/// - removal (`old.is_some() && new.is_none()`),
/// - mode downgrade (`new.mode < old.mode`),
/// - ciphersuite change (`new.t_ciphersuite != old.t_ciphersuite ||
///   new.pq_ciphersuite != old.pq_ciphersuite`).
///
/// Setting APQInfo for the first time (`old.is_none()`) is always allowed —
/// that's the bootstrap path.
pub fn validate_apq_info_change(
    old: Option<&ApqInfo>,
    new: Option<&ApqInfo>,
) -> Result<(), DowngradeError> {
    match (old, new) {
        (None, _) => Ok(()),
        (Some(_), None) => Err(DowngradeError::ApqInfoRemoval),
        (Some(old), Some(new)) => {
            if !SecurityMode::allows_transition(old.mode, new.mode) {
                return Err(DowngradeError::ApqInfoModeDowngrade {
                    old: old.mode,
                    new: new.mode,
                });
            }
            if new.t_ciphersuite != old.t_ciphersuite {
                return Err(DowngradeError::ApqInfoCiphersuiteChange {
                    old: old.t_ciphersuite,
                    new: new.t_ciphersuite,
                });
            }
            if new.pq_ciphersuite != old.pq_ciphersuite {
                return Err(DowngradeError::ApqInfoCiphersuiteChange {
                    old: old.pq_ciphersuite,
                    new: new.pq_ciphersuite,
                });
            }
            Ok(())
        }
    }
}

/// Validate that the T and PQ session epochs in an APQInfo are within
/// [`MAX_EPOCH_DRIFT`] of each other and (if `apq_info` is set) consistent
/// with its recorded epochs.
pub fn validate_epoch_consistency(
    t_epoch: u64,
    pq_epoch: u64,
    apq_info: Option<&ApqInfo>,
) -> Result<(), DowngradeError> {
    let drift = t_epoch.abs_diff(pq_epoch);
    if drift > MAX_EPOCH_DRIFT {
        return Err(DowngradeError::EpochMismatch {
            t_epoch,
            pq_epoch,
            max: MAX_EPOCH_DRIFT,
        });
    }

    if let Some(info) = apq_info {
        let recorded_drift = info.t_epoch.abs_diff(info.pq_epoch);
        if recorded_drift > MAX_EPOCH_DRIFT {
            return Err(DowngradeError::EpochMismatch {
                t_epoch: info.t_epoch,
                pq_epoch: info.pq_epoch,
                max: MAX_EPOCH_DRIFT,
            });
        }
    }

    Ok(())
}

/// Reject a ciphersuite change once the conversation has been pinned.
///
/// Called whenever a commit appears that would change the ciphersuite of an
/// already-bootstrapped conversation. Returns `Ok(())` if `state` has no
/// pinned suite (pre-bootstrap), and otherwise rejects unless `proposed`
/// matches the pin exactly.
pub fn validate_ciphersuite_pin(
    state: &ConversationSecurityState,
    proposed: Ciphersuite,
) -> Result<(), DowngradeError> {
    match state.pinned_ciphersuite {
        None => Ok(()),
        Some(pinned) if pinned == proposed => Ok(()),
        Some(pinned) => Err(DowngradeError::PinnedCiphersuiteChange { pinned, proposed }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classical_state() -> ConversationSecurityState {
        ConversationSecurityState::new(SecurityMode::Classical)
    }

    fn confidentiality_state() -> ConversationSecurityState {
        ConversationSecurityState::new(SecurityMode::PqConfidentiality)
    }

    fn authenticity_state() -> ConversationSecurityState {
        ConversationSecurityState::new(SecurityMode::PqAuthenticity)
    }

    fn classical_cs() -> Ciphersuite {
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    }

    fn xwing_cs() -> Ciphersuite {
        Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519
    }

    fn pq_apq_info() -> ApqInfo {
        ApqInfo::new(
            crate::group::GroupId::from_slice(&[1; 16]),
            crate::group::GroupId::from_slice(&[2; 16]),
            5,
            5,
            classical_cs(),
            xwing_cs(),
            SecurityMode::PqConfidentiality,
        )
    }

    // ----- validate_mode_change -----

    #[test]
    fn mode_change_accepts_upgrade() {
        let state = confidentiality_state();
        validate_mode_change(&state, SecurityMode::PqAuthenticity).expect("upgrade ok");
    }

    #[test]
    fn mode_change_accepts_no_op() {
        let state = confidentiality_state();
        validate_mode_change(&state, SecurityMode::PqConfidentiality).expect("no-op ok");
    }

    #[test]
    fn mode_change_rejects_pq_to_classical() {
        let state = confidentiality_state();
        assert_eq!(
            validate_mode_change(&state, SecurityMode::Classical),
            Err(DowngradeError::ModeDowngrade {
                from: SecurityMode::PqConfidentiality,
                to: SecurityMode::Classical,
            })
        );
    }

    #[test]
    fn mode_change_rejects_authenticity_to_confidentiality() {
        let state = authenticity_state();
        assert_eq!(
            validate_mode_change(&state, SecurityMode::PqConfidentiality),
            Err(DowngradeError::ModeDowngrade {
                from: SecurityMode::PqAuthenticity,
                to: SecurityMode::PqConfidentiality,
            })
        );
    }

    #[test]
    fn mode_change_rejects_below_highest_ever() {
        // Conversation is currently at PqConfidentiality but historically
        // reached PqAuthenticity.
        let mut state = authenticity_state();
        state.current_mode = SecurityMode::PqConfidentiality;
        assert_eq!(
            validate_mode_change(&state, SecurityMode::PqConfidentiality),
            Err(DowngradeError::BelowHighestEver {
                highest: SecurityMode::PqAuthenticity,
                to: SecurityMode::PqConfidentiality,
            })
        );
    }

    #[test]
    fn mode_change_rejects_below_policy_floor() {
        // Floor is PqAuthenticity but somehow current_mode and highest are
        // PqAuthenticity too — proposed mode below the floor is rejected.
        let state = ConversationSecurityState {
            current_mode: SecurityMode::PqAuthenticity,
            highest_mode_ever: SecurityMode::PqAuthenticity,
            policy_floor: SecurityMode::PqAuthenticity,
            pinned_ciphersuite: None,
        };
        assert_eq!(
            validate_mode_change(&state, SecurityMode::PqConfidentiality),
            Err(DowngradeError::ModeDowngrade {
                from: SecurityMode::PqAuthenticity,
                to: SecurityMode::PqConfidentiality,
            })
        );
    }

    // ----- validate_joiner_key_package -----

    #[test]
    fn joiner_classical_key_package_into_classical_ok() {
        validate_joiner_key_package(SecurityMode::Classical, classical_cs()).expect("ok");
    }

    #[test]
    fn joiner_classical_key_package_into_confidentiality_rejected() {
        assert_eq!(
            validate_joiner_key_package(SecurityMode::PqConfidentiality, classical_cs()),
            Err(DowngradeError::JoinerKeyPackageNotPq {
                kp_mode: SecurityMode::Classical,
                required: SecurityMode::PqConfidentiality,
            })
        );
    }

    #[test]
    fn joiner_pq_key_package_into_confidentiality_ok() {
        validate_joiner_key_package(SecurityMode::PqConfidentiality, xwing_cs()).expect("ok");
    }

    // ----- validate_apq_info_change -----

    #[test]
    fn apq_info_first_setup_ok() {
        let new = pq_apq_info();
        validate_apq_info_change(None, Some(&new)).expect("first setup");
    }

    #[test]
    fn apq_info_unchanged_ok() {
        let old = pq_apq_info();
        let new = old.clone();
        validate_apq_info_change(Some(&old), Some(&new)).expect("unchanged");
    }

    #[test]
    fn apq_info_removal_rejected() {
        let old = pq_apq_info();
        assert_eq!(
            validate_apq_info_change(Some(&old), None),
            Err(DowngradeError::ApqInfoRemoval)
        );
    }

    #[test]
    fn apq_info_mode_downgrade_rejected() {
        let old = ApqInfo::new(
            crate::group::GroupId::from_slice(&[1; 16]),
            crate::group::GroupId::from_slice(&[2; 16]),
            5,
            5,
            classical_cs(),
            xwing_cs(),
            SecurityMode::PqAuthenticity,
        );
        let mut new = old.clone();
        new.mode = SecurityMode::PqConfidentiality;
        assert_eq!(
            validate_apq_info_change(Some(&old), Some(&new)),
            Err(DowngradeError::ApqInfoModeDowngrade {
                old: SecurityMode::PqAuthenticity,
                new: SecurityMode::PqConfidentiality,
            })
        );
    }

    #[test]
    fn apq_info_mode_upgrade_ok() {
        let old = pq_apq_info();
        let mut new = old.clone();
        new.mode = SecurityMode::PqAuthenticity;
        validate_apq_info_change(Some(&old), Some(&new)).expect("upgrade ok");
    }

    #[test]
    fn apq_info_t_ciphersuite_change_rejected() {
        let old = pq_apq_info();
        let mut new = old.clone();
        new.t_ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
        assert_eq!(
            validate_apq_info_change(Some(&old), Some(&new)),
            Err(DowngradeError::ApqInfoCiphersuiteChange {
                old: classical_cs(),
                new: Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            })
        );
    }

    // ----- validate_epoch_consistency -----

    #[test]
    fn epoch_consistency_ok_when_within_drift() {
        validate_epoch_consistency(5, 5, None).expect("equal ok");
        validate_epoch_consistency(5, 6, None).expect("drift 1 ok");
        validate_epoch_consistency(7, 6, None).expect("drift 1 ok");
    }

    #[test]
    fn epoch_consistency_rejects_drift_above_window() {
        assert_eq!(
            validate_epoch_consistency(5, 10, None),
            Err(DowngradeError::EpochMismatch {
                t_epoch: 5,
                pq_epoch: 10,
                max: MAX_EPOCH_DRIFT,
            })
        );
    }

    #[test]
    fn epoch_consistency_rejects_drift_in_apq_info() {
        let mut info = pq_apq_info();
        info.t_epoch = 5;
        info.pq_epoch = 20;
        assert_eq!(
            validate_epoch_consistency(5, 5, Some(&info)),
            Err(DowngradeError::EpochMismatch {
                t_epoch: 5,
                pq_epoch: 20,
                max: MAX_EPOCH_DRIFT,
            })
        );
    }

    // ----- validate_ciphersuite_pin -----

    #[test]
    fn ciphersuite_pin_unset_accepts_anything() {
        let state = classical_state();
        validate_ciphersuite_pin(&state, classical_cs()).expect("unset pin ok");
        validate_ciphersuite_pin(&state, xwing_cs()).expect("unset pin ok");
    }

    #[test]
    fn ciphersuite_pin_set_accepts_match() {
        let mut state = confidentiality_state();
        state.pinned_ciphersuite = Some(xwing_cs());
        validate_ciphersuite_pin(&state, xwing_cs()).expect("matching pin ok");
    }

    #[test]
    fn ciphersuite_pin_set_rejects_mismatch() {
        let mut state = confidentiality_state();
        state.pinned_ciphersuite = Some(xwing_cs());
        assert_eq!(
            validate_ciphersuite_pin(&state, classical_cs()),
            Err(DowngradeError::PinnedCiphersuiteChange {
                pinned: xwing_cs(),
                proposed: classical_cs(),
            })
        );
    }

    #[test]
    fn record_upgrade_advances_state() {
        let mut state = confidentiality_state();
        state.record_upgrade(SecurityMode::PqAuthenticity);
        assert_eq!(state.current_mode, SecurityMode::PqAuthenticity);
        assert_eq!(state.highest_mode_ever, SecurityMode::PqAuthenticity);
    }

    #[test]
    fn record_upgrade_does_not_lower_highest() {
        let mut state = authenticity_state();
        state.record_upgrade(SecurityMode::PqConfidentiality);
        // current_mode reflects what record_upgrade recorded, but
        // highest_mode_ever stays at the strongest seen.
        assert_eq!(state.current_mode, SecurityMode::PqConfidentiality);
        assert_eq!(state.highest_mode_ever, SecurityMode::PqAuthenticity);
    }
}
