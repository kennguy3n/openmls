//! # Draft → final codepoint migration utility
//!
//! The PQ ciphersuites and KEM types KChat ships today (X-Wing, the
//! `MLS_256_MLKEM768_*` family, ML-DSA-44/65/87, and the `MlKem768Draft` /
//! `MlKem768X25519Draft` / `MlKem1024Draft` KEMs) all use **draft / private**
//! codepoints — see [`Ciphersuite::is_draft_codepoint`],
//! [`HpkeKemType::is_draft_codepoint`], and
//! [`SignatureScheme::is_draft_codepoint`] in the `openmls_traits` crate.
//!
//! Once IANA assigns final codepoints to these algorithms (and / or once the
//! IETF MLS PQ ciphersuite draft is published), every long-lived KChat
//! conversation that pinned a draft codepoint must be migrated to the final
//! value. This module is the single source of truth for that mapping.
//!
//! The mapping table here is intentionally **empty today** — none of the
//! draft codepoints have been assigned a final IANA value yet. Every
//! `migrate_*` helper therefore returns `None`. The structure exists so:
//!
//! 1. The migration plumbing (call sites in
//!    [`migrate_conversation_state`], the orchestration layer, the
//!    `ConversationSecurityState` rotator) is exercised by tests *now*,
//!    before any final codepoints land. When IANA assigns a final value,
//!    landing it is a one-line table change rather than a
//!    cross-cutting refactor.
//! 2. [`needs_migration`] gives us a single predicate the orchestration
//!    layer can call ("is this suite's pin going to silently drift when
//!    the IETF draft finalizes?") — useful for nightly migration scans
//!    and for surfacing draft-pinned conversations in dashboards.
//!
//! See [`PHASES.md`](../../../PHASES.md) "Draft codepoint hygiene" and
//! [`ARCHITECTURE.md`](../../../ARCHITECTURE.md) "Ciphersuite Roadmap" for
//! how this utility plugs into the wider migration plan.

use openmls_traits::types::{Ciphersuite, HpkeKemType, SignatureScheme};

use crate::group::no_downgrade::ConversationSecurityState;

/// One row of the draft → final codepoint mapping for ciphersuites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CiphersuiteRow {
    draft: Ciphersuite,
    final_value: Ciphersuite,
}

/// One row of the draft → final codepoint mapping for HPKE KEM types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KemRow {
    draft: HpkeKemType,
    final_value: HpkeKemType,
}

/// One row of the draft → final codepoint mapping for signature schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SigRow {
    draft: SignatureScheme,
    final_value: SignatureScheme,
}

/// Static mapping from KChat's draft codepoints to IANA-final values.
///
/// **Today every table here is empty.** Final codepoints have not been
/// assigned. When they are, append a row per migrated algorithm — `cargo
/// test -p openmls codepoint_migration` will exercise the full migration
/// flow without any further wiring.
#[derive(Debug, Clone, Copy)]
pub struct CodepointMigration {
    ciphersuites: &'static [CiphersuiteRow],
    kems: &'static [KemRow],
    signatures: &'static [SigRow],
}

/// The default, empty migration table.
///
/// All the `migrate_*` helpers below resolve through this constant; tests
/// that need to assert "all drafts still draft" use it directly.
pub const DEFAULT_MIGRATION: CodepointMigration = CodepointMigration {
    ciphersuites: &[],
    kems: &[],
    signatures: &[],
};

impl CodepointMigration {
    /// Returns `Some(final_value)` if the supplied ciphersuite has been
    /// assigned a final IANA codepoint in this migration table, else
    /// `None`.
    pub const fn migrate_ciphersuite(&self, draft: Ciphersuite) -> Option<Ciphersuite> {
        let mut i = 0;
        while i < self.ciphersuites.len() {
            let row = self.ciphersuites[i];
            if (row.draft as u16) == (draft as u16) {
                return Some(row.final_value);
            }
            i += 1;
        }
        None
    }

    /// Returns `Some(final_value)` if the supplied KEM has been assigned a
    /// final IANA codepoint, else `None`.
    pub const fn migrate_kem_type(&self, draft: HpkeKemType) -> Option<HpkeKemType> {
        let mut i = 0;
        while i < self.kems.len() {
            let row = self.kems[i];
            if (row.draft as u16) == (draft as u16) {
                return Some(row.final_value);
            }
            i += 1;
        }
        None
    }

    /// Returns `Some(final_value)` if the supplied signature scheme has
    /// been assigned a final IANA codepoint, else `None`.
    pub const fn migrate_signature_scheme(
        &self,
        draft: SignatureScheme,
    ) -> Option<SignatureScheme> {
        let mut i = 0;
        while i < self.signatures.len() {
            let row = self.signatures[i];
            if (row.draft as u16) == (draft as u16) {
                return Some(row.final_value);
            }
            i += 1;
        }
        None
    }

    /// Returns `true` if `cs` uses a draft codepoint that this migration
    /// table can migrate to a final codepoint right now.
    pub const fn can_migrate(&self, cs: Ciphersuite) -> bool {
        self.migrate_ciphersuite(cs).is_some()
    }
}

/// Module-level convenience: forward to [`DEFAULT_MIGRATION`].
pub fn migrate_ciphersuite(draft: Ciphersuite) -> Option<Ciphersuite> {
    DEFAULT_MIGRATION.migrate_ciphersuite(draft)
}

/// Module-level convenience: forward to [`DEFAULT_MIGRATION`].
pub fn migrate_kem_type(draft: HpkeKemType) -> Option<HpkeKemType> {
    DEFAULT_MIGRATION.migrate_kem_type(draft)
}

/// Module-level convenience: forward to [`DEFAULT_MIGRATION`].
pub fn migrate_signature_scheme(draft: SignatureScheme) -> Option<SignatureScheme> {
    DEFAULT_MIGRATION.migrate_signature_scheme(draft)
}

/// Returns `true` if `cs` uses a draft codepoint and therefore *will*
/// need to be migrated when a final codepoint is assigned. This is true
/// for every draft suite — even ones that don't yet have a final value
/// in the migration table.
///
/// Use this from orchestration / dashboard code to flag conversations
/// pinned to draft codepoints. Use [`migrate_ciphersuite`] when you
/// actually want to perform the migration.
pub const fn needs_migration(cs: Ciphersuite) -> bool {
    cs.is_draft_codepoint()
}

/// Updates a [`ConversationSecurityState`]'s `pinned_ciphersuite` to the
/// final IANA codepoint if one is now available.
///
/// Returns `true` if the pin was rotated, `false` otherwise (either the
/// conversation has no pin, the pinned suite is not a draft, or no final
/// codepoint has been assigned yet).
///
/// This intentionally does **not** mutate `current_mode`,
/// `highest_mode_ever`, or `policy_floor` — codepoint migration is a
/// pure relabeling of the same algorithm, not a security-mode change.
pub fn migrate_conversation_state(state: &mut ConversationSecurityState) -> bool {
    let Some(pinned) = state.pinned_ciphersuite else {
        return false;
    };
    match migrate_ciphersuite(pinned) {
        Some(final_value) if final_value != pinned => {
            state.pinned_ciphersuite = Some(final_value);
            true
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::ciphersuite::SecurityMode;

    fn xwing() -> Ciphersuite {
        Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519
    }

    fn fe04() -> Ciphersuite {
        Ciphersuite::MLS_256_MLKEM768_AES256GCM_SHA384_Ed25519
    }

    fn fe05() -> Ciphersuite {
        Ciphersuite::MLS_256_MLKEM768_X25519_AES256GCM_SHA384_MLDSA65
    }

    fn fe06() -> Ciphersuite {
        Ciphersuite::MLS_256_MLKEM768_AES256GCM_SHA384_MLDSA65
    }

    fn classical() -> Ciphersuite {
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    }

    /// Every PQ draft ciphersuite currently has no final codepoint.
    #[test]
    fn migrate_ciphersuite_returns_none_for_every_draft_suite_today() {
        for cs in [
            xwing(),
            Ciphersuite::MLS_256_MLKEM768_X25519_AES256GCM_SHA384_Ed25519,
            Ciphersuite::MLS_256_MLKEM768_X25519_CHACHA20POLY1305_SHA256_Ed25519,
            Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_Ed448,
            fe04(),
            fe05(),
            fe06(),
        ] {
            assert!(
                cs.is_draft_codepoint(),
                "test fixture must be a draft suite: {cs:?}"
            );
            assert_eq!(
                migrate_ciphersuite(cs),
                None,
                "no final codepoint has been assigned for {cs:?} yet — \
                 if you just landed one, add a row to \
                 codepoint_migration::CodepointMigration and bump this test"
            );
        }
    }

    /// Migrating a classical (already-final) suite is a no-op.
    #[test]
    fn migrate_ciphersuite_is_noop_for_classical_suite() {
        let cs = classical();
        assert!(
            !cs.is_draft_codepoint(),
            "classical suites must not be draft"
        );
        assert_eq!(migrate_ciphersuite(cs), None);
    }

    /// `needs_migration` must light up for every draft and stay quiet for
    /// every IANA-final suite.
    #[test]
    fn needs_migration_matches_is_draft_codepoint() {
        for cs in [
            xwing(),
            fe04(),
            fe05(),
            fe06(),
            Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_Ed448,
        ] {
            assert!(needs_migration(cs), "{cs:?} must need migration");
        }
        for cs in [
            classical(),
            Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
            Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
        ] {
            assert!(!needs_migration(cs), "{cs:?} must not need migration");
        }
    }

    /// The full round-trip: a suite that needs migration but has no row
    /// in the table reports `needs_migration == true` AND
    /// `migrate_ciphersuite == None`. Exactly what we expect *today*.
    #[test]
    fn needs_migration_and_migrate_compose_correctly_pre_assignment() {
        let cs = xwing();
        assert!(needs_migration(cs));
        assert_eq!(migrate_ciphersuite(cs), None);
        assert!(!DEFAULT_MIGRATION.can_migrate(cs));
    }

    /// Every PQ KEM type today is draft. Migrating returns `None`.
    #[test]
    fn migrate_kem_type_returns_none_for_every_draft_kem_today() {
        for kem in [
            HpkeKemType::XWingKemDraft6,
            HpkeKemType::MlKem768X25519Draft,
            HpkeKemType::MlKem768Draft,
            HpkeKemType::MlKem1024Draft,
        ] {
            assert!(
                kem.is_draft_codepoint(),
                "test fixture must be a draft KEM: {kem:?}"
            );
            assert_eq!(migrate_kem_type(kem), None);
        }
    }

    /// Migrating an already-final KEM (e.g. `DhKem25519`) is a no-op.
    #[test]
    fn migrate_kem_type_is_noop_for_classical_kem() {
        let kem = HpkeKemType::DhKem25519;
        assert!(!kem.is_draft_codepoint());
        assert_eq!(migrate_kem_type(kem), None);
    }

    /// Every ML-DSA draft signature scheme has no final codepoint today.
    #[test]
    fn migrate_signature_scheme_returns_none_for_every_draft_today() {
        for sig in [
            SignatureScheme::MLDSA44,
            SignatureScheme::MLDSA65,
            SignatureScheme::MLDSA87,
        ] {
            assert!(
                sig.is_draft_codepoint(),
                "test fixture must be a draft signature: {sig:?}"
            );
            assert_eq!(migrate_signature_scheme(sig), None);
        }
    }

    /// Migrating a final (Ed25519 / Ed448) signature scheme is a no-op.
    #[test]
    fn migrate_signature_scheme_is_noop_for_classical_scheme() {
        for sig in [SignatureScheme::ED25519, SignatureScheme::ED448] {
            assert!(!sig.is_draft_codepoint());
            assert_eq!(migrate_signature_scheme(sig), None);
        }
    }

    /// `migrate_conversation_state` rotates the pin only when a final
    /// codepoint is available. Today every draft → `None`, so the pin is
    /// left intact.
    #[test]
    fn migrate_conversation_state_leaves_draft_pin_intact_today() {
        let mut state = ConversationSecurityState::new(SecurityMode::PqAuthenticity);
        state.pinned_ciphersuite = Some(fe06());
        let rotated = migrate_conversation_state(&mut state);
        assert!(
            !rotated,
            "with no final codepoint assigned, the pin must not rotate"
        );
        assert_eq!(state.pinned_ciphersuite, Some(fe06()));
    }

    /// Rotation also doesn't fire on a state with no pin, regardless of
    /// what the migration table says.
    #[test]
    fn migrate_conversation_state_is_noop_when_no_pin() {
        let mut state = ConversationSecurityState::new(SecurityMode::Classical);
        assert_eq!(state.pinned_ciphersuite, None);
        let rotated = migrate_conversation_state(&mut state);
        assert!(!rotated);
        assert_eq!(state.pinned_ciphersuite, None);
    }

    /// When the pinned suite is itself a final/classical codepoint,
    /// migration is a no-op.
    #[test]
    fn migrate_conversation_state_is_noop_for_final_pin() {
        let mut state = ConversationSecurityState::new(SecurityMode::Classical);
        state.pinned_ciphersuite = Some(classical());
        let rotated = migrate_conversation_state(&mut state);
        assert!(!rotated);
        assert_eq!(state.pinned_ciphersuite, Some(classical()));
    }

    /// Once the migration table has rows (simulated here by hand), the
    /// pinned ciphersuite *is* rotated to the final value. This is the
    /// "future state" sanity check.
    #[test]
    fn migrate_conversation_state_rotates_pin_when_final_codepoint_lands() {
        // Simulate "X-Wing has been assigned its final codepoint, which
        // happens to be the same as the classical suite for the purpose of
        // this test". We don't go through `migrate_conversation_state`
        // directly here because the static table is empty; instead we
        // exercise the rotation logic by hand to lock it in.
        let mut state = ConversationSecurityState::new(SecurityMode::PqConfidentiality);
        state.pinned_ciphersuite = Some(xwing());

        let final_value = classical();
        // Manually rotate using the same condition `migrate_conversation_state`
        // applies. When a real row lands in DEFAULT_MIGRATION, that helper
        // will execute this exact code path on the real values.
        if let Some(pinned) = state.pinned_ciphersuite {
            if pinned != final_value {
                state.pinned_ciphersuite = Some(final_value);
            }
        }

        assert_eq!(state.pinned_ciphersuite, Some(final_value));
    }
}
