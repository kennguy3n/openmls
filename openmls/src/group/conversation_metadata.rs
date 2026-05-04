//! # In-memory `ConversationMetadataService` (server-side scaffold)
//!
//! KChat servers track each conversation's *security state* without ever
//! seeing plaintext. The server must know:
//!
//! - which `SecurityMode` the conversation is in,
//! - whether it is APQ (and if so, which `ApqInfo` links the two sessions),
//! - the underlying T / PQ MLS group IDs,
//! - basic timestamps for housekeeping.
//!
//! This module ships an **in-memory reference implementation** of that
//! tracker. All mutating operations go through the no-downgrade
//! validators in [`crate::group::no_downgrade`] so the server cannot
//! rewrite a conversation's mode or `ApqInfo` to a weaker setting even
//! when an attacker controls the metadata path.
//!
//! See [`PHASES.md`](../../../PHASES.md) "Server Components — Group
//! metadata".

use std::collections::HashMap;

use crate::ciphersuite::SecurityMode;
use crate::extensions::apq_info::{ApqInfo, ApqInfoError};
use crate::group::no_downgrade::{
    validate_apq_info_change, validate_mode_change, ConversationSecurityState, DowngradeError,
};
use crate::group::GroupId;

/// Stored metadata for one KChat conversation.
///
/// The fields mirror what a KChat server needs to fan out APQ traffic and
/// enforce policy:
///
/// - `conversation_id` — the application-level conversation ID.
/// - `security_state` — the no-downgrade tracker
///   ([`ConversationSecurityState`]) rather than just the current mode,
///   so callers can interrogate `highest_mode_ever`,
///   `policy_floor`, and `pinned_ciphersuite`.
/// - `t_group_id` / `pq_group_id` — the underlying MLS group IDs (one or
///   both depending on the conversation type).
/// - `apq_info` — the `ApqInfo` link record for APQ conversations.
/// - `created_at` / `last_updated` — Unix-seconds timestamps for
///   housekeeping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationMetadata {
    /// Application-level conversation identifier.
    pub conversation_id: Vec<u8>,
    /// No-downgrade security state tracker for this conversation.
    pub security_state: ConversationSecurityState,
    /// MLS group ID of the T (traditional/classical) session, if any.
    pub t_group_id: Option<GroupId>,
    /// MLS group ID of the PQ session, if any.
    pub pq_group_id: Option<GroupId>,
    /// APQ link record between the T and PQ sessions, if any.
    pub apq_info: Option<ApqInfo>,
    /// Unix-seconds timestamp of when the conversation was first
    /// registered on the server.
    pub created_at: u64,
    /// Unix-seconds timestamp of the most recent metadata update.
    pub last_updated: u64,
}

impl ConversationMetadata {
    /// Construct a fresh metadata record.
    pub fn new(
        conversation_id: Vec<u8>,
        security_state: ConversationSecurityState,
        t_group_id: Option<GroupId>,
        pq_group_id: Option<GroupId>,
        apq_info: Option<ApqInfo>,
        created_at: u64,
    ) -> Self {
        Self {
            conversation_id,
            security_state,
            t_group_id,
            pq_group_id,
            apq_info,
            created_at,
            last_updated: created_at,
        }
    }
}

/// Errors returned by [`ConversationMetadataService`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MetadataError {
    /// The conversation ID is not registered.
    #[error("conversation not found")]
    NotFound,
    /// A downgrade-validation rule rejected the proposed change.
    #[error("downgrade rejected: {0}")]
    DowngradeRejected(DowngradeError),
    /// The proposed new `ApqInfo` is invalid in isolation
    /// (`ApqInfo::validate` failed).
    #[error("invalid APQInfo: {0}")]
    InvalidApqInfo(ApqInfoError),
    /// `register` called with a conversation ID that is already
    /// registered. Servers must not silently overwrite metadata.
    #[error("conversation already registered")]
    AlreadyRegistered,
}

/// In-memory metadata service indexed by `conversation_id`.
#[derive(Debug, Default)]
pub struct ConversationMetadataService {
    entries: HashMap<Vec<u8>, ConversationMetadata>,
    /// Monotonically-increasing `last_updated` cursor used for tests when
    /// the caller does not supply timestamps explicitly. Production
    /// servers should pass real Unix-seconds.
    next_timestamp: u64,
}

impl ConversationMetadataService {
    /// Construct an empty service.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a fresh conversation. Returns
    /// [`MetadataError::AlreadyRegistered`] if the conversation ID
    /// collides with an existing entry.
    pub fn register(&mut self, metadata: ConversationMetadata) -> Result<(), MetadataError> {
        if self.entries.contains_key(&metadata.conversation_id) {
            return Err(MetadataError::AlreadyRegistered);
        }
        self.next_timestamp = self.next_timestamp.max(metadata.last_updated);
        self.entries
            .insert(metadata.conversation_id.clone(), metadata);
        Ok(())
    }

    /// Look up a conversation's metadata.
    pub fn get(&self, conversation_id: &[u8]) -> Option<&ConversationMetadata> {
        self.entries.get(conversation_id)
    }

    /// Update a conversation's `current_mode`. Goes through
    /// [`validate_mode_change`] and rejects downgrades / floor / highest
    /// violations. The `last_updated` timestamp advances by one tick on
    /// every successful update.
    pub fn update_security_state(
        &mut self,
        conversation_id: &[u8],
        new_mode: SecurityMode,
    ) -> Result<(), MetadataError> {
        let entry = self
            .entries
            .get_mut(conversation_id)
            .ok_or(MetadataError::NotFound)?;
        validate_mode_change(&entry.security_state, new_mode)
            .map_err(MetadataError::DowngradeRejected)?;
        entry
            .security_state
            .record_upgrade(new_mode)
            .map_err(MetadataError::DowngradeRejected)?;
        Self::tick(&mut self.next_timestamp, &mut entry.last_updated);
        Ok(())
    }

    /// Update a conversation's `apq_info`. Goes through
    /// [`validate_apq_info_change`] *and* the new `ApqInfo`'s own
    /// `validate()` so callers get both layers of checks.
    pub fn update_apq_info(
        &mut self,
        conversation_id: &[u8],
        new_apq_info: ApqInfo,
    ) -> Result<(), MetadataError> {
        let entry = self
            .entries
            .get_mut(conversation_id)
            .ok_or(MetadataError::NotFound)?;

        new_apq_info
            .validate()
            .map_err(MetadataError::InvalidApqInfo)?;
        validate_apq_info_change(entry.apq_info.as_ref(), Some(&new_apq_info))
            .map_err(MetadataError::DowngradeRejected)?;

        entry.apq_info = Some(new_apq_info);
        Self::tick(&mut self.next_timestamp, &mut entry.last_updated);
        Ok(())
    }

    /// Number of conversations registered.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` if no conversations are registered.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn tick(cursor: &mut u64, dest: &mut u64) {
        *cursor = cursor.saturating_add(1);
        *dest = *cursor;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openmls_traits::types::Ciphersuite;

    fn classical_cs() -> Ciphersuite {
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    }

    fn xwing_cs() -> Ciphersuite {
        Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519
    }

    fn apq_info(mode: SecurityMode) -> ApqInfo {
        ApqInfo::new(
            GroupId::from_slice(&[0xAA; 16]),
            GroupId::from_slice(&[0xBB; 16]),
            0,
            0,
            classical_cs(),
            xwing_cs(),
            mode,
        )
    }

    #[test]
    fn register_and_get_round_trip() {
        let mut svc = ConversationMetadataService::new();
        let meta = ConversationMetadata::new(
            b"conv-1".to_vec(),
            ConversationSecurityState::new(SecurityMode::Classical),
            Some(GroupId::from_slice(&[0xAA; 16])),
            None,
            None,
            10,
        );
        svc.register(meta.clone()).expect("register");
        let fetched = svc.get(b"conv-1").expect("present");
        assert_eq!(fetched, &meta);
        assert_eq!(svc.len(), 1);
    }

    #[test]
    fn register_rejects_duplicate_conversation() {
        let mut svc = ConversationMetadataService::new();
        let meta = ConversationMetadata::new(
            b"conv-1".to_vec(),
            ConversationSecurityState::new(SecurityMode::Classical),
            None,
            None,
            None,
            0,
        );
        svc.register(meta.clone()).expect("first register");
        let err = svc.register(meta).expect_err("duplicate must be rejected");
        assert_eq!(err, MetadataError::AlreadyRegistered);
    }

    #[test]
    fn update_security_state_allows_upgrade() {
        let mut svc = ConversationMetadataService::new();
        let meta = ConversationMetadata::new(
            b"conv-1".to_vec(),
            ConversationSecurityState::new(SecurityMode::Classical),
            None,
            None,
            None,
            0,
        );
        svc.register(meta).expect("register");

        svc.update_security_state(b"conv-1", SecurityMode::PqConfidentiality)
            .expect("upgrade ok");
        let entry = svc.get(b"conv-1").unwrap();
        assert_eq!(
            entry.security_state.current_mode,
            SecurityMode::PqConfidentiality
        );
        assert_eq!(
            entry.security_state.highest_mode_ever,
            SecurityMode::PqConfidentiality
        );
        assert!(entry.last_updated > 0);
    }

    #[test]
    fn update_security_state_rejects_downgrade() {
        let mut svc = ConversationMetadataService::new();
        let meta = ConversationMetadata::new(
            b"conv-1".to_vec(),
            ConversationSecurityState::new(SecurityMode::PqAuthenticity),
            None,
            None,
            None,
            0,
        );
        svc.register(meta).expect("register");

        let err = svc
            .update_security_state(b"conv-1", SecurityMode::PqConfidentiality)
            .expect_err("downgrade rejected");
        assert!(matches!(err, MetadataError::DowngradeRejected(_)));

        // The state is untouched.
        let entry = svc.get(b"conv-1").unwrap();
        assert_eq!(
            entry.security_state.current_mode,
            SecurityMode::PqAuthenticity
        );
    }

    #[test]
    fn update_security_state_returns_not_found_for_unknown_conversation() {
        let mut svc = ConversationMetadataService::new();
        let err = svc
            .update_security_state(b"missing", SecurityMode::PqConfidentiality)
            .expect_err("missing convo must NotFound");
        assert_eq!(err, MetadataError::NotFound);
    }

    #[test]
    fn update_apq_info_allows_first_install() {
        let mut svc = ConversationMetadataService::new();
        let meta = ConversationMetadata::new(
            b"conv-1".to_vec(),
            ConversationSecurityState::new(SecurityMode::Classical),
            Some(GroupId::from_slice(&[0xAA; 16])),
            None,
            None,
            0,
        );
        svc.register(meta).expect("register");

        let info = apq_info(SecurityMode::PqConfidentiality);
        svc.update_apq_info(b"conv-1", info.clone())
            .expect("first install ok");
        assert_eq!(svc.get(b"conv-1").unwrap().apq_info, Some(info));
    }

    #[test]
    fn update_apq_info_rejects_invalid_info() {
        let mut svc = ConversationMetadataService::new();
        let meta = ConversationMetadata::new(
            b"conv-1".to_vec(),
            ConversationSecurityState::new(SecurityMode::Classical),
            None,
            None,
            None,
            0,
        );
        svc.register(meta).expect("register");

        // Build an APQInfo with t_group_id == pq_group_id — fails
        // ApqInfo::validate.
        let same_id = GroupId::from_slice(&[0xAA; 16]);
        let bad = ApqInfo::new(
            same_id.clone(),
            same_id,
            0,
            0,
            classical_cs(),
            xwing_cs(),
            SecurityMode::PqConfidentiality,
        );
        let err = svc
            .update_apq_info(b"conv-1", bad)
            .expect_err("invalid info must be rejected");
        assert!(matches!(err, MetadataError::InvalidApqInfo(_)));
    }

    #[test]
    fn update_apq_info_rejects_mode_downgrade() {
        let mut svc = ConversationMetadataService::new();
        let meta = ConversationMetadata::new(
            b"conv-1".to_vec(),
            ConversationSecurityState::new(SecurityMode::PqAuthenticity),
            None,
            None,
            Some(apq_info(SecurityMode::PqAuthenticity)),
            0,
        );
        svc.register(meta).expect("register");

        // Try to rewrite the APQInfo to PqConfidentiality.
        let weaker = apq_info(SecurityMode::PqConfidentiality);
        let err = svc
            .update_apq_info(b"conv-1", weaker)
            .expect_err("apq mode downgrade must be rejected");
        assert!(matches!(err, MetadataError::DowngradeRejected(_)));
    }

    #[test]
    fn update_apq_info_returns_not_found_for_unknown_conversation() {
        let mut svc = ConversationMetadataService::new();
        let err = svc
            .update_apq_info(b"missing", apq_info(SecurityMode::PqConfidentiality))
            .expect_err("missing convo must NotFound");
        assert_eq!(err, MetadataError::NotFound);
    }
}
