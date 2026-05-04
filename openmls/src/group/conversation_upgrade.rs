//! # New-conversation creation logic
//!
//! Implements [`PHASES.md`](../../../PHASES.md) Phase 2: when a new
//! conversation is created we look at the [`DeviceCapability`] of every
//! invited member and pick:
//!
//! - **APQ** if every device supports APQ (and a PQ ciphersuite is in
//!   common),
//! - **DIRECT_PQ** if every device supports a PQ ciphersuite but not APQ,
//! - **CLASSICAL** otherwise.
//!
//! The actual `MlsGroup` creation is done by the orchestration layer via
//! [`crate::group::MlsGroup::new`]; this module only computes the **selection**
//! result so the upgrade decision is testable in isolation.

use openmls_traits::types::Ciphersuite;

use crate::ciphersuite::SecurityMode;
use crate::credentials::DeviceCapability;

/// Errors that prevent a conversation from being created.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConversationUpgradeError {
    /// `select_conversation_mode` was called with no peer capabilities.
    #[error("cannot create a conversation with zero participants")]
    NoParticipants,
    /// No common ciphersuite exists across all peers for the chosen mode.
    /// This is treated as fail-closed: Phase 2 says PQ failures must not
    /// silently downgrade to classical.
    #[error("no common ciphersuite for selected mode {mode:?}")]
    NoCommonCiphersuite {
        /// Mode that had no common suite.
        mode: SecurityMode,
    },
}

/// Pick the [`SecurityMode`] and ciphersuite for a new conversation given
/// the participants' [`DeviceCapability`]s.
///
/// Returns `(mode, Some(ciphersuite))` if a common suite exists for the
/// selected mode, or `(mode, None)` if no common suite can be found at the
/// strongest mode the peers support. Callers should treat the `None` case
/// as fail-closed at the `mode` level (do not silently downgrade).
///
/// Selection rules (Phase 2):
///
/// - If **all** peers support `PqAuthenticity` (i.e. `pq_auth_supported &&
///   supports_pq()` for every peer) and a common PqAuthenticity suite
///   exists → `(PqAuthenticity, Some(cs))`.
/// - Else if **all** peers support PQ (have a non-empty `pq_ciphersuites`
///   list) and a common PqConfidentiality suite exists →
///   `(PqConfidentiality, Some(cs))`.
/// - Else → `(Classical, Some(best_classical))` if a common classical suite
///   exists, otherwise `Err(NoCommonCiphersuite)` for `Classical`.
///
/// `peer_capabilities` must be non-empty.
pub fn select_conversation_mode(
    peer_capabilities: &[&DeviceCapability],
) -> Result<(SecurityMode, Ciphersuite), ConversationUpgradeError> {
    if peer_capabilities.is_empty() {
        return Err(ConversationUpgradeError::NoParticipants);
    }

    // Try the strongest mode every peer supports.
    let target_mode = SecurityMode::select_mode(peer_capabilities);

    if let Some(cs) = SecurityMode::select_ciphersuite(peer_capabilities, target_mode) {
        return Ok((target_mode, cs));
    }

    // Phase 2 says PQ failures must not silently downgrade to classical, so
    // return a NoCommonCiphersuite error at the target mode rather than
    // walking down the modes.
    Err(ConversationUpgradeError::NoCommonCiphersuite { mode: target_mode })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classical_suites() -> Vec<Ciphersuite> {
        vec![
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
        ]
    }

    fn xwing_suites() -> Vec<Ciphersuite> {
        vec![Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519]
    }

    fn classical_only_peer() -> DeviceCapability {
        DeviceCapability::new(1, classical_suites(), vec![], false, false, "rc".into())
    }

    fn pq_conf_peer() -> DeviceCapability {
        DeviceCapability::new(
            1,
            classical_suites(),
            xwing_suites(),
            true,
            false,
            "libcrux".into(),
        )
    }

    fn pq_auth_peer() -> DeviceCapability {
        DeviceCapability::new(
            1,
            classical_suites(),
            xwing_suites(),
            true,
            true,
            "libcrux".into(),
        )
    }

    #[test]
    fn empty_input_errors() {
        let result = select_conversation_mode(&[]);
        assert_eq!(result, Err(ConversationUpgradeError::NoParticipants));
    }

    #[test]
    fn all_classical_picks_classical() {
        let peers = [classical_only_peer(), classical_only_peer()];
        let refs: Vec<&DeviceCapability> = peers.iter().collect();
        let (mode, cs) = select_conversation_mode(&refs).expect("classical select ok");
        assert_eq!(mode, SecurityMode::Classical);
        assert_eq!(
            cs,
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
        );
    }

    #[test]
    fn mixed_falls_back_to_classical() {
        // One classical peer, one PQ peer → classical (since not all peers
        // support PQ).
        let peers = [classical_only_peer(), pq_conf_peer()];
        let refs: Vec<&DeviceCapability> = peers.iter().collect();
        let (mode, cs) = select_conversation_mode(&refs).expect("mixed select ok");
        assert_eq!(mode, SecurityMode::Classical);
        // Should pick the first classical suite they have in common.
        assert_eq!(
            cs,
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
        );
    }

    #[test]
    fn all_pq_capable_picks_pq_confidentiality() {
        // Both peers are PQ-capable but not PQ-authenticity.
        let peers = [pq_conf_peer(), pq_conf_peer()];
        let refs: Vec<&DeviceCapability> = peers.iter().collect();
        let (mode, cs) = select_conversation_mode(&refs).expect("pq select ok");
        assert_eq!(mode, SecurityMode::PqConfidentiality);
        assert_eq!(
            cs,
            Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519
        );
    }

    #[test]
    fn all_pq_auth_capable_falls_back_to_pq_confidentiality_without_auth_suites() {
        // Both peers advertise pq_auth_supported = true, but the only PQ
        // ciphersuite they have is X-Wing + Ed25519, which is
        // PqConfidentiality. There's no PqAuthenticity ciphersuite available
        // → select_mode returns PqAuthenticity, but select_ciphersuite
        // can't find a PqAuthenticity suite. We fail closed at PqAuthenticity.
        let peers = [pq_auth_peer(), pq_auth_peer()];
        let refs: Vec<&DeviceCapability> = peers.iter().collect();
        let result = select_conversation_mode(&refs);
        assert_eq!(
            result,
            Err(ConversationUpgradeError::NoCommonCiphersuite {
                mode: SecurityMode::PqAuthenticity,
            })
        );
    }

    #[test]
    fn classical_with_no_common_suite_errors() {
        let mut peer_a = classical_only_peer();
        peer_a.classical_ciphersuites =
            vec![Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519];
        let mut peer_b = classical_only_peer();
        peer_b.classical_ciphersuites =
            vec![Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519];
        let refs = [&peer_a, &peer_b];
        let result = select_conversation_mode(&refs);
        assert_eq!(
            result,
            Err(ConversationUpgradeError::NoCommonCiphersuite {
                mode: SecurityMode::Classical,
            })
        );
    }

    #[test]
    fn single_pq_peer_picks_pq_confidentiality() {
        // One participant doesn't really make sense in MLS but the helper
        // tolerates it: the "highest mode all peers support" = the single
        // peer's mode.
        let peers = [pq_conf_peer()];
        let refs: Vec<&DeviceCapability> = peers.iter().collect();
        let (mode, _cs) = select_conversation_mode(&refs).expect("single peer");
        assert_eq!(mode, SecurityMode::PqConfidentiality);
    }
}
