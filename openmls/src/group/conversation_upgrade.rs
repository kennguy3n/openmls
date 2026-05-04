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
use crate::group::pq_telemetry::{PqTelemetryEmitter, PqTelemetryEvent};

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
/// Returns `(mode, ciphersuite)` for the strongest mode the peers can
/// agree on, or [`ConversationUpgradeError::NoCommonCiphersuite`] if no
/// shared suite exists at any acceptable tier.
///
/// Selection rules (Phase 2):
///
/// - If **all** peers support `PqAuthenticity` (`pq_auth_supported`) and a
///   common PqAuthenticity suite exists → `(PqAuthenticity, cs)`.
/// - Else if **all** peers support PQ (non-empty `pq_ciphersuites`) and a
///   common PqConfidentiality suite exists → `(PqConfidentiality, cs)`.
/// - Else → `(Classical, best_classical)` if a common classical suite
///   exists.
///
/// Cascade scope: when the target mode is PQ but no suite is available
/// for that exact tier, we walk **within PQ** (PqAuthenticity →
/// PqConfidentiality) so peers who advertise readiness for the higher
/// tier are not punished for missing a PqAuthenticity-grade suite. We
/// never silently fall back from PQ to Classical — that is the
/// PHASES.md Phase 2 fail-closed rule.
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

    // Within-PQ fallback: if the peer set is universally PQ-capable but
    // they don't share a PqAuthenticity suite, drop to PqConfidentiality
    // rather than failing the whole conversation. Crossing into Classical
    // is still forbidden (Phase 2 fail-closed rule).
    if target_mode == SecurityMode::PqAuthenticity {
        if let Some(cs) =
            SecurityMode::select_ciphersuite(peer_capabilities, SecurityMode::PqConfidentiality)
        {
            return Ok((SecurityMode::PqConfidentiality, cs));
        }
        // No PqConfidentiality suite either, but every peer is PQ-capable
        // — never silently downgrade to Classical.
        return Err(ConversationUpgradeError::NoCommonCiphersuite {
            mode: SecurityMode::PqAuthenticity,
        });
    }

    Err(ConversationUpgradeError::NoCommonCiphersuite { mode: target_mode })
}

/// Telemetry-aware variant of [`select_conversation_mode`].
///
/// Behaves identically to [`select_conversation_mode`] but emits a
/// [`PqTelemetryEvent::UnsupportedCiphersuite`] event for every peer
/// whose advertised PQ ciphersuite list could not be honoured at the
/// returned mode. This makes Phase 2 fail-closed selection observable
/// without changing the success path.
///
/// `provider_id` identifies the local crypto provider in the emitted
/// event (typically `"rustcrypto"` or `"libcrux"`).
pub fn select_conversation_mode_with_emitter(
    peer_capabilities: &[&DeviceCapability],
    emitter: &dyn PqTelemetryEmitter,
    provider_id: &str,
) -> Result<(SecurityMode, Ciphersuite), ConversationUpgradeError> {
    let result = select_conversation_mode(peer_capabilities);
    if let Err(ConversationUpgradeError::NoCommonCiphersuite { mode }) = &result {
        // Emit one UnsupportedCiphersuite event per *advertised* PQ
        // ciphersuite that the chosen mode could not honour. We emit
        // for every PQ suite at or below the target mode, since any
        // such suite was advertised but not honoured by the final
        // selection. Suites *above* the target mode are not flagged —
        // those are correctly excluded by `select_mode`'s "highest
        // mode all peers support" rule, not by the per-suite filter.
        let mut emitted = 0_usize;
        for cap in peer_capabilities {
            for cs in &cap.pq_ciphersuites {
                if SecurityMode::from_ciphersuite(*cs) <= *mode {
                    emitter.emit(PqTelemetryEvent::UnsupportedCiphersuite {
                        ciphersuite: *cs,
                        provider_id: provider_id.to_string(),
                    });
                    emitted += 1;
                }
            }
        }
        // Always emit at least one event so callers can pin the
        // "selection failed" signal even when no per-suite event was
        // produced above (e.g. peers advertised no PQ suites at all,
        // or every advertised suite is *above* the target mode).
        if emitted == 0 {
            emitter.emit(PqTelemetryEvent::UnsupportedCiphersuite {
                ciphersuite: Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                provider_id: provider_id.to_string(),
            });
        }
    }
    result
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
        // PqConfidentiality. There's no PqAuthenticity ciphersuite
        // available → select_mode returns PqAuthenticity, but
        // select_ciphersuite can't find a PqAuthenticity suite. The
        // within-PQ fallback then drops to PqConfidentiality (X-Wing) —
        // crossing into Classical would be a silent downgrade and is
        // still forbidden.
        let peers = [pq_auth_peer(), pq_auth_peer()];
        let refs: Vec<&DeviceCapability> = peers.iter().collect();
        let (mode, cs) = select_conversation_mode(&refs).expect("within-PQ fallback ok");
        assert_eq!(mode, SecurityMode::PqConfidentiality);
        assert_eq!(
            cs,
            Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519
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

    /// Regression test for the bug where
    /// `select_conversation_mode_with_emitter` emitted zero events when
    /// peers advertised disjoint PQ ciphersuites that all mapped to the
    /// *same* target mode. The original implementation used a strict
    /// `<` filter, missing same-mode suites entirely, and the fallback
    /// only fired when every peer's PQ list was empty.
    #[test]
    fn with_emitter_emits_events_for_disjoint_same_mode_suites() {
        use crate::group::pq_telemetry::InMemoryTelemetryEmitter;

        // Peer A advertises X-Wing only; peer B advertises a hypothetical
        // ML-KEM hybrid. Both map to PqConfidentiality. The intersection
        // of PQ suites is empty, so `select_conversation_mode` returns
        // `NoCommonCiphersuite { mode: PqConfidentiality }`. The bug
        // would have produced zero telemetry events.
        let peer_a = DeviceCapability::new(
            1,
            classical_suites(),
            vec![Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519],
            true,
            false,
            "libcrux".into(),
        );
        let peer_b = DeviceCapability::new(
            1,
            classical_suites(),
            vec![Ciphersuite::MLS_256_MLKEM768_X25519_AES256GCM_SHA384_Ed25519],
            true,
            false,
            "libcrux".into(),
        );
        let refs: Vec<&DeviceCapability> = vec![&peer_a, &peer_b];

        let emitter = InMemoryTelemetryEmitter::new();
        let result = select_conversation_mode_with_emitter(&refs, &emitter, "libcrux");
        assert_eq!(
            result,
            Err(ConversationUpgradeError::NoCommonCiphersuite {
                mode: SecurityMode::PqConfidentiality,
            })
        );
        let events = emitter.events();
        assert!(
            !events.is_empty(),
            "must emit at least one telemetry event for selection failure"
        );
        // Both per-suite events must be present (one per advertised PQ
        // suite at-or-below the target mode).
        let suites: Vec<Ciphersuite> = events
            .iter()
            .filter_map(|e| match e {
                PqTelemetryEvent::UnsupportedCiphersuite { ciphersuite, .. } => Some(*ciphersuite),
                _ => None,
            })
            .collect();
        assert!(
            suites.contains(&Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519),
            "X-Wing must be flagged: {suites:?}"
        );
        assert!(
            suites.contains(&Ciphersuite::MLS_256_MLKEM768_X25519_AES256GCM_SHA384_Ed25519),
            "ML-KEM-768 must be flagged: {suites:?}"
        );
    }

    /// Companion to the disjoint-same-mode regression: when peers
    /// genuinely advertise no PQ suites, the function must still emit
    /// at least one fallback event so dashboards can pin the failure.
    #[test]
    fn with_emitter_emits_fallback_when_no_pq_suites_advertised() {
        use crate::group::pq_telemetry::InMemoryTelemetryEmitter;

        // Two peers with only classical suites, but disjoint classical
        // suites → `NoCommonCiphersuite { mode: Classical }`.
        let mut peer_a = classical_only_peer();
        peer_a.classical_ciphersuites =
            vec![Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519];
        let mut peer_b = classical_only_peer();
        peer_b.classical_ciphersuites =
            vec![Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519];
        let refs = vec![&peer_a, &peer_b];

        let emitter = InMemoryTelemetryEmitter::new();
        let result = select_conversation_mode_with_emitter(&refs, &emitter, "rustcrypto");
        assert!(matches!(
            result,
            Err(ConversationUpgradeError::NoCommonCiphersuite { .. })
        ));
        assert_eq!(
            emitter.events().len(),
            1,
            "exactly one fallback event when no PQ suites are advertised"
        );
    }
}
