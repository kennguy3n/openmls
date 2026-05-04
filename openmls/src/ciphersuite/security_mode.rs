//! # Security mode selection for KChat conversations
//!
//! KChat conversations advertise — and enforce — one of three security
//! modes:
//!
//! - [`SecurityMode::Classical`]: pre-PQ MLS. Classical KEM, classical
//!   signature.
//! - [`SecurityMode::PqConfidentiality`]: hybrid / PQ KEM, classical
//!   signature. Defends against "harvest now, decrypt later" attacks.
//! - [`SecurityMode::PqAuthenticity`]: hybrid / PQ KEM **and** ML-DSA
//!   signatures. Full PQ for high-risk groups.
//!
//! `SecurityMode` is `Ord`-comparable so we can express "the highest mode all
//! peers support" and "no downgrade allowed" as plain comparisons. The
//! numeric `repr(u8)` is also wire-stable.
//!
//! See [`ARCHITECTURE.md`](../../../ARCHITECTURE.md) (Security Modes section)
//! and [`PHASES.md`](../../../PHASES.md) for how these modes drive the
//! migration plan.

use openmls_traits::types::{Ciphersuite, SignatureScheme};
use serde::{Deserialize, Serialize};

use crate::credentials::DeviceCapability;

/// One of three KChat conversation security modes.
///
/// Variants are ordered: `Classical < PqConfidentiality < PqAuthenticity`.
/// "Higher" means stronger PQ guarantees.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum SecurityMode {
    /// Classical MLS — current ciphersuites and Ed25519/P-256 signatures.
    Classical = 0,
    /// Hybrid / PQ KEM with classical signatures. Near-term default for
    /// PQ-capable peers.
    PqConfidentiality = 1,
    /// Hybrid / PQ KEM **and** ML-DSA signatures. Long-term default for
    /// high-risk groups.
    PqAuthenticity = 2,
}

impl SecurityMode {
    /// Map a concrete ciphersuite to the security mode it provides.
    ///
    /// The mapping is driven by the underlying signature scheme and the
    /// ciphersuite identity:
    ///
    /// - PQ KEM + ML-DSA signature → [`SecurityMode::PqAuthenticity`].
    /// - PQ KEM + classical signature → [`SecurityMode::PqConfidentiality`].
    /// - Otherwise → [`SecurityMode::Classical`].
    pub fn from_ciphersuite(cs: Ciphersuite) -> SecurityMode {
        let signature: SignatureScheme = cs.signature_algorithm();
        let pq_kem = ciphersuite_uses_pq_kem(cs);
        let pq_sig = signature.is_post_quantum();
        match (pq_kem, pq_sig) {
            (true, true) => SecurityMode::PqAuthenticity,
            (true, false) => SecurityMode::PqConfidentiality,
            // PQ signatures with a classical KEM is not a mode KChat exposes
            // today; treat it as classical for selection purposes (the
            // "authenticity" mode is gated on a hybrid/PQ KEM as well).
            (false, _) => SecurityMode::Classical,
        }
    }

    /// Pick the highest [`SecurityMode`] all peers in `capabilities` support.
    ///
    /// "Supports" semantics:
    ///
    /// - [`SecurityMode::PqAuthenticity`]: every peer has both `pq_auth_supported`
    ///   AND at least one PQ ciphersuite.
    /// - [`SecurityMode::PqConfidentiality`]: every peer has at least one PQ
    ///   ciphersuite.
    /// - [`SecurityMode::Classical`]: always supported (assumed for every
    ///   device that speaks MLS at all).
    ///
    /// An empty capability slice returns [`SecurityMode::Classical`] — there
    /// is no PQ peer to upgrade with.
    pub fn select_mode(capabilities: &[&DeviceCapability]) -> SecurityMode {
        if capabilities.is_empty() {
            return SecurityMode::Classical;
        }

        let all_pq_auth = capabilities
            .iter()
            .all(|c| c.pq_auth_supported && c.supports_pq());
        if all_pq_auth {
            return SecurityMode::PqAuthenticity;
        }

        let all_pq_conf = capabilities.iter().all(|c| c.supports_pq());
        if all_pq_conf {
            return SecurityMode::PqConfidentiality;
        }

        SecurityMode::Classical
    }

    /// Pick the best ciphersuite for `mode` from the intersection of every
    /// peer's capability lists.
    ///
    /// Mode → list mapping:
    ///
    /// - [`SecurityMode::Classical`]: peers' `classical_ciphersuites`.
    /// - [`SecurityMode::PqConfidentiality`]: peers' `pq_ciphersuites`,
    ///   filtered to suites whose [`SecurityMode::from_ciphersuite`] is
    ///   exactly `PqConfidentiality`.
    /// - [`SecurityMode::PqAuthenticity`]: peers' `pq_ciphersuites`, filtered
    ///   to suites whose [`SecurityMode::from_ciphersuite`] is
    ///   `PqAuthenticity` (i.e. PQ KEM + ML-DSA).
    ///
    /// Within the candidate list the choice follows the **first** peer's
    /// ordering — peers can therefore express their preference by ordering
    /// their own capability lists, which is the same convention used by
    /// [`DeviceCapability::best_common_ciphersuite`].
    pub fn select_ciphersuite(
        capabilities: &[&DeviceCapability],
        mode: SecurityMode,
    ) -> Option<Ciphersuite> {
        let (anchor, rest) = capabilities.split_first()?;

        let candidates: &[Ciphersuite] = match mode {
            SecurityMode::Classical => &anchor.classical_ciphersuites,
            SecurityMode::PqConfidentiality | SecurityMode::PqAuthenticity => {
                &anchor.pq_ciphersuites
            }
        };

        for suite in candidates {
            if SecurityMode::from_ciphersuite(*suite) != mode {
                continue;
            }
            let supported_by_all_peers = rest.iter().all(|peer| match mode {
                SecurityMode::Classical => peer.classical_ciphersuites.contains(suite),
                SecurityMode::PqConfidentiality | SecurityMode::PqAuthenticity => {
                    peer.pq_ciphersuites.contains(suite)
                }
            });
            if supported_by_all_peers {
                return Some(*suite);
            }
        }

        None
    }

    /// No-downgrade helper.
    ///
    /// Returns `true` if `to >= from` — i.e. the conversation is staying at
    /// the same mode or *upgrading* to a stronger one. Returns `false` for
    /// any downgrade. This is the primitive callers should use to gate
    /// `set_mode` / `apply_apq_info` operations against silent downgrade.
    pub const fn allows_transition(from: SecurityMode, to: SecurityMode) -> bool {
        (to as u8) >= (from as u8)
    }
}

/// Returns `true` if `cs`'s KEM is post-quantum / hybrid.
///
/// Covers both the X-Wing draft suite and the IETF MLS PQ draft
/// ML-KEM hybrid / pure ML-KEM suites. Mirrors the
/// [`HpkeKemType::is_draft_codepoint`] check at the KEM level — any
/// suite whose KEM is currently a draft / private-use codepoint is by
/// definition post-quantum or hybrid in this codebase.
fn ciphersuite_uses_pq_kem(cs: Ciphersuite) -> bool {
    matches!(
        cs,
        Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_256_MLKEM768_X25519_AES256GCM_SHA384_Ed25519
            | Ciphersuite::MLS_256_MLKEM768_X25519_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_Ed448
            | Ciphersuite::MLS_256_MLKEM768_AES256GCM_SHA384_Ed25519
            | Ciphersuite::MLS_256_MLKEM768_X25519_AES256GCM_SHA384_MLDSA65
            | Ciphersuite::MLS_256_MLKEM768_AES256GCM_SHA384_MLDSA65
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classical_only_peer() -> DeviceCapability {
        DeviceCapability::new(
            1,
            vec![
                Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            ],
            vec![],
            false,
            false,
            "rustcrypto".to_string(),
        )
    }

    fn pq_confidentiality_peer() -> DeviceCapability {
        DeviceCapability::new(
            1,
            vec![Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519],
            vec![Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519],
            true,
            false,
            "libcrux".to_string(),
        )
    }

    fn pq_auth_peer() -> DeviceCapability {
        DeviceCapability::new(
            1,
            vec![Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519],
            vec![Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519],
            true,
            true,
            "libcrux".to_string(),
        )
    }

    #[test]
    fn from_ciphersuite_classical() {
        assert_eq!(
            SecurityMode::from_ciphersuite(
                Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            ),
            SecurityMode::Classical
        );
    }

    #[test]
    fn from_ciphersuite_pq_confidentiality() {
        assert_eq!(
            SecurityMode::from_ciphersuite(
                Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519
            ),
            SecurityMode::PqConfidentiality
        );
    }

    #[test]
    fn from_ciphersuite_ml_kem_drafts_are_pq_confidentiality() {
        for cs in [
            Ciphersuite::MLS_256_MLKEM768_X25519_AES256GCM_SHA384_Ed25519,
            Ciphersuite::MLS_256_MLKEM768_X25519_CHACHA20POLY1305_SHA256_Ed25519,
            Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_Ed448,
            // Pure ML-KEM-768 + Ed25519 (PQ batch 4) is also
            // confidentiality-only because the signature stays classical.
            Ciphersuite::MLS_256_MLKEM768_AES256GCM_SHA384_Ed25519,
        ] {
            // PQ / hybrid KEM + classical signature → PqConfidentiality.
            assert_eq!(
                SecurityMode::from_ciphersuite(cs),
                SecurityMode::PqConfidentiality,
                "expected PqConfidentiality for {cs:?}"
            );
        }
    }

    #[test]
    fn from_ciphersuite_ml_kem_with_mldsa_is_pq_authenticity() {
        for cs in [
            Ciphersuite::MLS_256_MLKEM768_X25519_AES256GCM_SHA384_MLDSA65,
            Ciphersuite::MLS_256_MLKEM768_AES256GCM_SHA384_MLDSA65,
        ] {
            // PQ KEM + ML-DSA signature → PqAuthenticity.
            assert_eq!(
                SecurityMode::from_ciphersuite(cs),
                SecurityMode::PqAuthenticity,
                "expected PqAuthenticity for {cs:?}"
            );
        }
    }

    #[test]
    fn select_mode_all_classical() {
        let a = classical_only_peer();
        let b = classical_only_peer();
        assert_eq!(
            SecurityMode::select_mode(&[&a, &b]),
            SecurityMode::Classical
        );
    }

    #[test]
    fn select_mode_one_classical_only_drops_to_classical() {
        let pq = pq_confidentiality_peer();
        let classical = classical_only_peer();
        assert_eq!(
            SecurityMode::select_mode(&[&pq, &classical]),
            SecurityMode::Classical
        );
    }

    #[test]
    fn select_mode_all_pq_confidentiality() {
        let a = pq_confidentiality_peer();
        let b = pq_confidentiality_peer();
        assert_eq!(
            SecurityMode::select_mode(&[&a, &b]),
            SecurityMode::PqConfidentiality
        );
    }

    #[test]
    fn select_mode_all_pq_auth() {
        let a = pq_auth_peer();
        let b = pq_auth_peer();
        assert_eq!(
            SecurityMode::select_mode(&[&a, &b]),
            SecurityMode::PqAuthenticity
        );
    }

    #[test]
    fn select_mode_mixed_auth_falls_back_to_confidentiality() {
        let auth = pq_auth_peer();
        let conf = pq_confidentiality_peer();
        assert_eq!(
            SecurityMode::select_mode(&[&auth, &conf]),
            SecurityMode::PqConfidentiality
        );
    }

    #[test]
    fn select_ciphersuite_classical_intersection() {
        let a = classical_only_peer();
        let b = classical_only_peer();
        let chosen = SecurityMode::select_ciphersuite(&[&a, &b], SecurityMode::Classical);
        assert_eq!(
            chosen,
            Some(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
        );
    }

    #[test]
    fn select_ciphersuite_pq_confidentiality_picks_xwing() {
        let a = pq_confidentiality_peer();
        let b = pq_confidentiality_peer();
        let chosen = SecurityMode::select_ciphersuite(&[&a, &b], SecurityMode::PqConfidentiality);
        assert_eq!(
            chosen,
            Some(Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519)
        );
    }

    #[test]
    fn select_ciphersuite_pq_auth_returns_none_with_only_xwing() {
        // X-Wing maps to PqConfidentiality (Ed25519 sig), not PqAuthenticity.
        // Until ML-DSA-bearing ciphersuites are added, PqAuthenticity has no
        // candidate.
        let a = pq_auth_peer();
        let b = pq_auth_peer();
        let chosen = SecurityMode::select_ciphersuite(&[&a, &b], SecurityMode::PqAuthenticity);
        assert!(chosen.is_none());
    }

    #[test]
    fn allows_transition_no_downgrade() {
        // Equal — allowed.
        assert!(SecurityMode::allows_transition(
            SecurityMode::Classical,
            SecurityMode::Classical
        ));
        assert!(SecurityMode::allows_transition(
            SecurityMode::PqConfidentiality,
            SecurityMode::PqConfidentiality
        ));
        // Upgrade — allowed.
        assert!(SecurityMode::allows_transition(
            SecurityMode::Classical,
            SecurityMode::PqConfidentiality
        ));
        assert!(SecurityMode::allows_transition(
            SecurityMode::PqConfidentiality,
            SecurityMode::PqAuthenticity
        ));
        assert!(SecurityMode::allows_transition(
            SecurityMode::Classical,
            SecurityMode::PqAuthenticity
        ));
        // Downgrade — rejected.
        assert!(!SecurityMode::allows_transition(
            SecurityMode::PqConfidentiality,
            SecurityMode::Classical
        ));
        assert!(!SecurityMode::allows_transition(
            SecurityMode::PqAuthenticity,
            SecurityMode::Classical
        ));
        assert!(!SecurityMode::allows_transition(
            SecurityMode::PqAuthenticity,
            SecurityMode::PqConfidentiality
        ));
    }

    #[test]
    fn ordering_is_classical_lt_conf_lt_auth() {
        assert!(SecurityMode::Classical < SecurityMode::PqConfidentiality);
        assert!(SecurityMode::PqConfidentiality < SecurityMode::PqAuthenticity);
    }
}
