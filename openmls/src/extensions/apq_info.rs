//! # APQInfo extension
//!
//! `ApqInfo` is the small TLS-encoded blob that links the two MLS sessions
//! (T and PQ) backing a single KChat APQ conversation. It is carried in the
//! GroupInfo of both groups and persisted client-side; it is consulted by the
//! orchestration layer to:
//!
//! - detect epoch drift between the two sessions,
//! - reject downgrades that try to remove or rewrite it,
//! - reject ciphersuite/mode changes after APQ bootstrap (the conversation is
//!   pinned to its bootstrap suite).
//!
//! See [`ARCHITECTURE.md`](../../../ARCHITECTURE.md) (APQ-MLS Combiner) and
//! [`PHASES.md`](../../../PHASES.md) (Phases 4 and 6) for the role this struct
//! plays in the larger PQ migration plan.

use std::io::{Read, Write};

use openmls_traits::types::Ciphersuite;
use serde::{Deserialize, Serialize};
use tls_codec::{
    Deserialize as TlsDeserializeTrait, DeserializeBytes as TlsDeserializeBytesTrait,
    Error as TlsError, Serialize as TlsSerializeTrait, Size as TlsSizeTrait,
};

use crate::ciphersuite::SecurityMode;
use crate::group::GroupId;

/// Link record between the T and PQ MLS sessions in an APQ conversation.
///
/// All fields are wire-stable: this struct is TLS-serialized into the
/// GroupInfo of both groups and persisted alongside the conversation state.
/// The `mode` is encoded as a single byte (`SecurityMode as u8`) so the
/// wire format does not depend on serde.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ApqInfo {
    /// Group ID of the T (classical / traditional) session.
    pub t_group_id: GroupId,
    /// Group ID of the PQ session.
    pub pq_group_id: GroupId,
    /// FULL-commit synchronization counter as observed on the T side.
    ///
    /// **Not** the live MLS epoch of the T group. This is a counter that
    /// advances by 1 on every FULL commit; both `t_epoch` and `pq_epoch`
    /// are seeded at bootstrap from the PQ group's initial epoch and move
    /// together thereafter. Decoupling this from the absolute T-group
    /// epoch lets long-running classical groups bootstrap into APQ
    /// without the recorded drift check failing.
    pub t_epoch: u64,
    /// FULL-commit synchronization counter as observed on the PQ side.
    ///
    /// See [`Self::t_epoch`] for the full semantics. The two counters
    /// stay equal between FULL commits and may differ by at most
    /// [`MAX_EPOCH_DRIFT`] while a FULL commit is in flight.
    pub pq_epoch: u64,
    /// Ciphersuite of the T session.
    pub t_ciphersuite: Ciphersuite,
    /// Ciphersuite of the PQ session.
    pub pq_ciphersuite: Ciphersuite,
    /// Active security mode of the conversation. Pinned at bootstrap; any
    /// downgrade is rejected by the orchestration layer.
    pub mode: SecurityMode,
}

/// Reasons an [`ApqInfo`] can fail validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApqInfoError {
    /// `mode` claims an APQ mode but the ciphersuite combination does not
    /// match (e.g. PQ session uses a classical-only suite).
    #[error("APQ mode {mode:?} is inconsistent with ciphersuite combination")]
    ModeMismatch {
        /// The advertised mode.
        mode: SecurityMode,
    },
    /// `t_group_id == pq_group_id`. The two sessions must have distinct IDs.
    #[error("APQInfo t_group_id and pq_group_id must differ")]
    DuplicateGroupIds,
    /// One of the supplied actual group IDs does not match the recorded ID.
    #[error("APQInfo group ID does not match actual session group ID")]
    GroupIdMismatch,
    /// Epoch counters drifted past the maximum allowed gap.
    #[error("APQInfo T/PQ epoch drift {drift} exceeds maximum {max}")]
    EpochDrift {
        /// Observed drift between `t_epoch` and `pq_epoch`.
        drift: u64,
        /// Maximum drift permitted by the orchestration layer.
        max: u64,
    },
    /// `mode` is `Classical` but the struct exists at all. APQInfo only ever
    /// applies to APQ-mode conversations.
    #[error("APQInfo carries Classical mode; APQInfo is only valid for APQ-mode conversations")]
    ClassicalMode,
}

/// Maximum permitted drift between `t_epoch` and `pq_epoch`. The two sessions
/// run in lockstep on FULL commits but may drift by one epoch while a FULL
/// commit is in flight. Anything beyond that is treated as a programming
/// error or an attempted desync attack.
pub const MAX_EPOCH_DRIFT: u64 = 1;

impl ApqInfo {
    /// Construct a new `ApqInfo`. Does not validate; call [`Self::validate`]
    /// before persisting or shipping over the wire.
    pub fn new(
        t_group_id: GroupId,
        pq_group_id: GroupId,
        t_epoch: u64,
        pq_epoch: u64,
        t_ciphersuite: Ciphersuite,
        pq_ciphersuite: Ciphersuite,
        mode: SecurityMode,
    ) -> Self {
        Self {
            t_group_id,
            pq_group_id,
            t_epoch,
            pq_epoch,
            t_ciphersuite,
            pq_ciphersuite,
            mode,
        }
    }

    /// Validate internal consistency of the APQInfo:
    ///
    /// - the two group IDs must differ,
    /// - epoch drift must not exceed [`MAX_EPOCH_DRIFT`],
    /// - the mode must be one of the APQ modes (not `Classical`),
    /// - the ciphersuite combination must match the advertised mode.
    pub fn validate(&self) -> Result<(), ApqInfoError> {
        if self.t_group_id == self.pq_group_id {
            return Err(ApqInfoError::DuplicateGroupIds);
        }

        let drift = self.t_epoch.abs_diff(self.pq_epoch);
        if drift > MAX_EPOCH_DRIFT {
            return Err(ApqInfoError::EpochDrift {
                drift,
                max: MAX_EPOCH_DRIFT,
            });
        }

        match self.mode {
            SecurityMode::Classical => Err(ApqInfoError::ClassicalMode),
            SecurityMode::PqConfidentiality | SecurityMode::PqAuthenticity => {
                let pq_session_mode = SecurityMode::from_ciphersuite(self.pq_ciphersuite);
                if pq_session_mode < self.mode {
                    return Err(ApqInfoError::ModeMismatch { mode: self.mode });
                }
                Ok(())
            }
        }
    }

    /// Verify that the recorded group IDs match the actual session IDs.
    pub fn matches_groups(
        &self,
        actual_t_group_id: &GroupId,
        actual_pq_group_id: &GroupId,
    ) -> Result<(), ApqInfoError> {
        if &self.t_group_id != actual_t_group_id {
            return Err(ApqInfoError::GroupIdMismatch);
        }
        if &self.pq_group_id != actual_pq_group_id {
            return Err(ApqInfoError::GroupIdMismatch);
        }
        Ok(())
    }

    fn payload_tls_serialized_len(&self) -> usize {
        self.t_group_id.tls_serialized_len()
            + self.pq_group_id.tls_serialized_len()
            + self.t_epoch.tls_serialized_len()
            + self.pq_epoch.tls_serialized_len()
            + self.t_ciphersuite.tls_serialized_len()
            + self.pq_ciphersuite.tls_serialized_len()
            + 1 // mode as u8
    }
}

// ===== TLS codec =====
//
// Hand-rolled because `SecurityMode` is not `tls_codec`-derived. We encode
// `mode` as a single `u8` matching its `repr(u8)` discriminant.

impl TlsSizeTrait for ApqInfo {
    fn tls_serialized_len(&self) -> usize {
        self.payload_tls_serialized_len()
    }
}

impl TlsSerializeTrait for ApqInfo {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, TlsError> {
        let mut written = 0;
        written += self.t_group_id.tls_serialize(writer)?;
        written += self.pq_group_id.tls_serialize(writer)?;
        written += self.t_epoch.tls_serialize(writer)?;
        written += self.pq_epoch.tls_serialize(writer)?;
        written += self.t_ciphersuite.tls_serialize(writer)?;
        written += self.pq_ciphersuite.tls_serialize(writer)?;
        let mode_byte: u8 = self.mode as u8;
        written += mode_byte.tls_serialize(writer)?;
        Ok(written)
    }
}

impl TlsDeserializeTrait for ApqInfo {
    fn tls_deserialize<R: Read>(reader: &mut R) -> Result<Self, TlsError> {
        let t_group_id = GroupId::tls_deserialize(reader)?;
        let pq_group_id = GroupId::tls_deserialize(reader)?;
        let t_epoch = u64::tls_deserialize(reader)?;
        let pq_epoch = u64::tls_deserialize(reader)?;
        let t_ciphersuite = Ciphersuite::tls_deserialize(reader)?;
        let pq_ciphersuite = Ciphersuite::tls_deserialize(reader)?;
        let mode_byte = u8::tls_deserialize(reader)?;
        let mode = security_mode_from_u8(mode_byte)?;
        Ok(Self {
            t_group_id,
            pq_group_id,
            t_epoch,
            pq_epoch,
            t_ciphersuite,
            pq_ciphersuite,
            mode,
        })
    }
}

impl TlsDeserializeBytesTrait for ApqInfo {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), TlsError> {
        let mut reader = bytes;
        let value = Self::tls_deserialize(&mut reader)?;
        Ok((value, reader))
    }
}

fn security_mode_from_u8(byte: u8) -> Result<SecurityMode, TlsError> {
    match byte {
        0 => Ok(SecurityMode::Classical),
        1 => Ok(SecurityMode::PqConfidentiality),
        2 => Ok(SecurityMode::PqAuthenticity),
        other => Err(TlsError::DecodingError(format!(
            "invalid SecurityMode discriminant {other}",
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group_id(tag: u8) -> GroupId {
        GroupId::from_slice(&[tag; 16])
    }

    fn pq_apq_info() -> ApqInfo {
        ApqInfo::new(
            group_id(0xAA),
            group_id(0xBB),
            5,
            5,
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
            SecurityMode::PqConfidentiality,
        )
    }

    #[test]
    fn roundtrip_pq_confidentiality() {
        let info = pq_apq_info();
        let bytes = info.tls_serialize_detached().expect("serialize");
        let decoded = ApqInfo::tls_deserialize_exact(&bytes).expect("deserialize");
        assert_eq!(info, decoded);
    }

    #[test]
    fn validate_accepts_pq_confidentiality() {
        let info = pq_apq_info();
        info.validate().expect("valid PQ_CONFIDENTIALITY APQInfo");
    }

    #[test]
    fn validate_rejects_classical_mode() {
        let mut info = pq_apq_info();
        info.mode = SecurityMode::Classical;
        assert_eq!(info.validate(), Err(ApqInfoError::ClassicalMode));
    }

    #[test]
    fn validate_rejects_duplicate_group_ids() {
        let mut info = pq_apq_info();
        info.pq_group_id = info.t_group_id.clone();
        assert_eq!(info.validate(), Err(ApqInfoError::DuplicateGroupIds));
    }

    #[test]
    fn validate_rejects_epoch_drift() {
        let mut info = pq_apq_info();
        info.t_epoch = 10;
        info.pq_epoch = 5;
        assert_eq!(
            info.validate(),
            Err(ApqInfoError::EpochDrift { drift: 5, max: 1 })
        );
    }

    #[test]
    fn validate_accepts_drift_within_window() {
        let mut info = pq_apq_info();
        info.t_epoch = 5;
        info.pq_epoch = 6;
        info.validate().expect("drift of 1 is permitted");
    }

    #[test]
    fn validate_rejects_classical_pq_ciphersuite() {
        // Mode says PqConfidentiality but the pq_ciphersuite is a classical
        // suite — that means the "PQ session" wouldn't actually be PQ.
        let mut info = pq_apq_info();
        info.pq_ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        assert_eq!(
            info.validate(),
            Err(ApqInfoError::ModeMismatch {
                mode: SecurityMode::PqConfidentiality,
            })
        );
    }

    #[test]
    fn matches_groups_accepts_correct_ids() {
        let info = pq_apq_info();
        info.matches_groups(&group_id(0xAA), &group_id(0xBB))
            .expect("matching ids accepted");
    }

    #[test]
    fn matches_groups_rejects_wrong_t_id() {
        let info = pq_apq_info();
        assert_eq!(
            info.matches_groups(&group_id(0xCC), &group_id(0xBB)),
            Err(ApqInfoError::GroupIdMismatch)
        );
    }

    #[test]
    fn matches_groups_rejects_wrong_pq_id() {
        let info = pq_apq_info();
        assert_eq!(
            info.matches_groups(&group_id(0xAA), &group_id(0xCC)),
            Err(ApqInfoError::GroupIdMismatch)
        );
    }

    #[test]
    fn sync_counter_seeded_from_pq_epoch_is_valid() {
        // `bootstrap_apq` seeds both `t_epoch` and `pq_epoch` from the
        // PQ group's epoch (the synchronization anchor), regardless of
        // how far the live T group has advanced. Validate that any such
        // seed value passes — there is no implicit "absolute MLS epoch"
        // assumption hiding in the validator.
        for seed in [0u64, 1, 5, 1_000, u64::MAX / 2] {
            let mut info = pq_apq_info();
            info.t_epoch = seed;
            info.pq_epoch = seed;
            info.validate()
                .unwrap_or_else(|e| panic!("seed {seed} should be a valid APQ sync counter: {e}"));
        }
    }

    #[test]
    fn deserialize_rejects_invalid_mode_byte() {
        let info = pq_apq_info();
        let mut bytes = info.tls_serialize_detached().expect("serialize");
        // The last byte is the mode; corrupt it.
        *bytes.last_mut().unwrap() = 0xEE;
        let err = ApqInfo::tls_deserialize_exact(&bytes).unwrap_err();
        match err {
            tls_codec::Error::DecodingError(msg) => assert!(msg.contains("SecurityMode")),
            other => panic!("expected DecodingError, got {other:?}"),
        }
    }
}
