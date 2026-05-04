//! # APQWelcome — bootstrap message for APQ conversations
//!
//! When a new device joins an APQ conversation it must be welcomed into
//! **both** sessions in lockstep: the T (classical) session and the PQ
//! session. [`ApqWelcome`] bundles the two MLS [`Welcome`]s together with
//! the [`ApqInfo`] linking the two groups and the initial PSK ID for the
//! PQ-derived `apq_psk` so the joiner can ratchet straight into the FULL
//! commit cadence.
//!
//! See [`PHASES.md`](../../../PHASES.md) Phase 4 for the bootstrap flow.
//!
//! `t_welcome` is `Option<Welcome>` because direct-PQ bootstraps (when the
//! conversation has no T session) are still encoded with this struct so
//! Phase 4 has a single bootstrap message type. `initial_apq_psk_id` is
//! `Option<PreSharedKeyId>` for the same reason.

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use tls_codec::{
    Deserialize as TlsDeserializeTrait, DeserializeBytes as TlsDeserializeBytesTrait,
    Error as TlsError, Serialize as TlsSerializeTrait, Size as TlsSizeTrait,
};

use crate::extensions::apq_info::{ApqInfo, ApqInfoError};
use crate::group::GroupId;
use crate::messages::Welcome;
use crate::schedule::psk::PreSharedKeyId;

/// APQ bootstrap envelope: paired Welcomes plus the link record.
///
/// On the wire this is a single TLS-serialized blob; the orchestration layer
/// is responsible for delivering it to the joiner intact (the delivery
/// service should not split it across messages — partial delivery would
/// cause the joiner to reach an inconsistent state).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApqWelcome {
    /// Welcome for the T session. `None` for direct-PQ bootstraps.
    pub t_welcome: Option<Welcome>,
    /// Welcome for the PQ session. Always present in APQ — without a PQ
    /// session there is no APQ.
    pub pq_welcome: Welcome,
    /// Link record between the two sessions.
    pub apq_info: ApqInfo,
    /// `PreSharedKeyId` for the initial `apq_psk` derived from the PQ
    /// session post-bootstrap. The orchestration layer uses this to ratchet
    /// the T session at the first FULL commit. `None` for direct-PQ
    /// bootstraps (no T session to PSK-bind).
    pub initial_apq_psk_id: Option<PreSharedKeyId>,
}

/// Reasons an [`ApqWelcome`] fails validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApqWelcomeError {
    /// Underlying [`ApqInfo`] failed validation.
    #[error("APQInfo invalid: {0}")]
    InvalidApqInfo(ApqInfoError),
    /// `apq_info` says this is APQ (mode is non-classical, t_group_id is
    /// recorded) but no `t_welcome` is supplied.
    #[error("APQ-mode bootstrap missing t_welcome")]
    MissingTWelcome,
    /// `apq_info` says this is direct-PQ (no T session) but a `t_welcome`
    /// was supplied.
    #[error("direct-PQ bootstrap unexpectedly carries a t_welcome")]
    UnexpectedTWelcome,
    /// `t_welcome` is present but its ciphersuite does not match
    /// `apq_info.t_ciphersuite`.
    #[error("t_welcome ciphersuite does not match APQInfo t_ciphersuite")]
    TCiphersuiteMismatch,
    /// `pq_welcome` ciphersuite does not match `apq_info.pq_ciphersuite`.
    #[error("pq_welcome ciphersuite does not match APQInfo pq_ciphersuite")]
    PqCiphersuiteMismatch,
    /// APQ bootstrap is missing the initial PSK ID (required for the joiner
    /// to ratchet its T session at the first FULL commit).
    #[error("APQ bootstrap missing initial_apq_psk_id")]
    MissingPskId,
}

impl ApqWelcome {
    /// Construct an `ApqWelcome` for a full APQ bootstrap (both T and PQ
    /// welcomes present).
    pub fn new_apq(
        t_welcome: Welcome,
        pq_welcome: Welcome,
        apq_info: ApqInfo,
        initial_apq_psk_id: PreSharedKeyId,
    ) -> Self {
        Self {
            t_welcome: Some(t_welcome),
            pq_welcome,
            apq_info,
            initial_apq_psk_id: Some(initial_apq_psk_id),
        }
    }

    /// Construct an `ApqWelcome` for a direct-PQ bootstrap (PQ session only,
    /// no T session). `apq_info` must still be supplied for the `mode` and
    /// `pq_ciphersuite` it records; `t_*` fields in the `apq_info` are
    /// ignored at validate time when `t_welcome` is `None`.
    pub fn new_direct_pq(pq_welcome: Welcome, apq_info: ApqInfo) -> Self {
        Self {
            t_welcome: None,
            pq_welcome,
            apq_info,
            initial_apq_psk_id: None,
        }
    }

    /// Validate internal consistency of the bootstrap envelope.
    ///
    /// - `apq_info.validate()` must succeed.
    /// - If `t_welcome.is_some()` then it must match `apq_info.t_ciphersuite`.
    /// - `pq_welcome.ciphersuite()` must match `apq_info.pq_ciphersuite`.
    /// - APQ-mode bootstraps (`t_welcome.is_some()`) must carry an
    ///   `initial_apq_psk_id`.
    pub fn validate(&self) -> Result<(), ApqWelcomeError> {
        self.apq_info
            .validate()
            .map_err(ApqWelcomeError::InvalidApqInfo)?;

        if self.pq_welcome.ciphersuite() != self.apq_info.pq_ciphersuite {
            return Err(ApqWelcomeError::PqCiphersuiteMismatch);
        }

        match self.t_welcome.as_ref() {
            Some(t_welcome) => {
                if t_welcome.ciphersuite() != self.apq_info.t_ciphersuite {
                    return Err(ApqWelcomeError::TCiphersuiteMismatch);
                }
                if self.initial_apq_psk_id.is_none() {
                    return Err(ApqWelcomeError::MissingPskId);
                }
            }
            None => {
                // direct-PQ bootstrap. Nothing more to check; the absence of
                // a T-side PSK ID is expected and `apq_info.t_*` fields are
                // intentionally ignored.
            }
        }

        Ok(())
    }

    /// Pull out both group IDs (`(t_group_id, pq_group_id)`) so callers
    /// don't have to dig into `apq_info` directly.
    pub fn extract_group_ids(&self) -> (&GroupId, &GroupId) {
        (&self.apq_info.t_group_id, &self.apq_info.pq_group_id)
    }
}

// ===== TLS codec =====
//
// We hand-roll the TLS encoding because `Option<T>` is not derivable. We
// encode `Option<T>` as `u8 presence flag + T body when present`.

impl TlsSizeTrait for ApqWelcome {
    fn tls_serialized_len(&self) -> usize {
        let t_welcome_len = match &self.t_welcome {
            Some(w) => 1 + w.tls_serialized_len(),
            None => 1,
        };
        let psk_len = match &self.initial_apq_psk_id {
            Some(p) => 1 + p.tls_serialized_len(),
            None => 1,
        };
        t_welcome_len
            + self.pq_welcome.tls_serialized_len()
            + self.apq_info.tls_serialized_len()
            + psk_len
    }
}

impl TlsSerializeTrait for ApqWelcome {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, TlsError> {
        let mut written = 0;
        match &self.t_welcome {
            Some(w) => {
                written += 1u8.tls_serialize(writer)?;
                written += w.tls_serialize(writer)?;
            }
            None => {
                written += 0u8.tls_serialize(writer)?;
            }
        }
        written += self.pq_welcome.tls_serialize(writer)?;
        written += self.apq_info.tls_serialize(writer)?;
        match &self.initial_apq_psk_id {
            Some(p) => {
                written += 1u8.tls_serialize(writer)?;
                written += p.tls_serialize(writer)?;
            }
            None => {
                written += 0u8.tls_serialize(writer)?;
            }
        }
        Ok(written)
    }
}

impl TlsDeserializeTrait for ApqWelcome {
    fn tls_deserialize<R: Read>(reader: &mut R) -> Result<Self, TlsError> {
        let t_welcome = match u8::tls_deserialize(reader)? {
            0 => None,
            1 => Some(Welcome::tls_deserialize(reader)?),
            other => {
                return Err(TlsError::DecodingError(format!(
                    "invalid t_welcome presence flag {other}",
                )))
            }
        };
        let pq_welcome = Welcome::tls_deserialize(reader)?;
        let apq_info = ApqInfo::tls_deserialize(reader)?;
        let initial_apq_psk_id = match u8::tls_deserialize(reader)? {
            0 => None,
            1 => Some(PreSharedKeyId::tls_deserialize(reader)?),
            other => {
                return Err(TlsError::DecodingError(format!(
                    "invalid initial_apq_psk_id presence flag {other}",
                )))
            }
        };
        Ok(Self {
            t_welcome,
            pq_welcome,
            apq_info,
            initial_apq_psk_id,
        })
    }
}

impl TlsDeserializeBytesTrait for ApqWelcome {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), TlsError> {
        let mut reader = bytes;
        let value = Self::tls_deserialize(&mut reader)?;
        Ok((value, reader))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ciphersuite::SecurityMode;
    use crate::messages::EncryptedGroupSecrets;
    use openmls_traits::types::Ciphersuite;

    fn classical_cs() -> Ciphersuite {
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    }

    fn xwing_cs() -> Ciphersuite {
        Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519
    }

    fn dummy_welcome(cs: Ciphersuite) -> Welcome {
        // Welcome::new is `pub(crate)`, so this stub is only buildable from
        // inside the openmls crate. Encrypted secrets and group info are
        // empty — these tests do not exercise welcome decryption, only the
        // ApqWelcome wrapper.
        let secrets: Vec<EncryptedGroupSecrets> = vec![];
        Welcome::new(cs, secrets, b"encrypted_group_info".to_vec())
    }

    fn pq_apq_info() -> ApqInfo {
        ApqInfo::new(
            GroupId::from_slice(&[1; 16]),
            GroupId::from_slice(&[2; 16]),
            5,
            5,
            classical_cs(),
            xwing_cs(),
            SecurityMode::PqConfidentiality,
        )
    }

    fn dummy_psk_id() -> PreSharedKeyId {
        PreSharedKeyId::external(b"apq_psk_id".to_vec(), vec![0u8; 32])
    }

    #[test]
    fn apq_bootstrap_validate_ok() {
        let aw = ApqWelcome::new_apq(
            dummy_welcome(classical_cs()),
            dummy_welcome(xwing_cs()),
            pq_apq_info(),
            dummy_psk_id(),
        );
        aw.validate().expect("apq bootstrap valid");
    }

    #[test]
    fn direct_pq_bootstrap_validate_ok() {
        let aw = ApqWelcome::new_direct_pq(dummy_welcome(xwing_cs()), pq_apq_info());
        aw.validate().expect("direct pq bootstrap valid");
    }

    #[test]
    fn pq_ciphersuite_mismatch_rejected() {
        let mut aw = ApqWelcome::new_apq(
            dummy_welcome(classical_cs()),
            dummy_welcome(classical_cs()), // wrong cs for pq side
            pq_apq_info(),
            dummy_psk_id(),
        );
        // Re-pin the apq_info so the validate() inner check fires (otherwise
        // ApqInfo::validate flags the mode/cs mismatch first).
        aw.apq_info.pq_ciphersuite = xwing_cs();
        assert_eq!(aw.validate(), Err(ApqWelcomeError::PqCiphersuiteMismatch));
    }

    #[test]
    fn t_ciphersuite_mismatch_rejected() {
        let aw = ApqWelcome::new_apq(
            dummy_welcome(Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519),
            dummy_welcome(xwing_cs()),
            pq_apq_info(),
            dummy_psk_id(),
        );
        assert_eq!(aw.validate(), Err(ApqWelcomeError::TCiphersuiteMismatch));
    }

    #[test]
    fn apq_bootstrap_without_psk_id_rejected() {
        let aw = ApqWelcome {
            t_welcome: Some(dummy_welcome(classical_cs())),
            pq_welcome: dummy_welcome(xwing_cs()),
            apq_info: pq_apq_info(),
            initial_apq_psk_id: None,
        };
        assert_eq!(aw.validate(), Err(ApqWelcomeError::MissingPskId));
    }

    #[test]
    fn invalid_apq_info_propagates_through_validate() {
        let mut info = pq_apq_info();
        info.t_group_id = info.pq_group_id.clone();
        let aw = ApqWelcome::new_apq(
            dummy_welcome(classical_cs()),
            dummy_welcome(xwing_cs()),
            info,
            dummy_psk_id(),
        );
        match aw.validate() {
            Err(ApqWelcomeError::InvalidApqInfo(_)) => {}
            other => panic!("expected InvalidApqInfo, got {other:?}"),
        }
    }

    #[test]
    fn extract_group_ids_returns_both() {
        let aw = ApqWelcome::new_apq(
            dummy_welcome(classical_cs()),
            dummy_welcome(xwing_cs()),
            pq_apq_info(),
            dummy_psk_id(),
        );
        let (t_id, pq_id) = aw.extract_group_ids();
        assert_eq!(t_id, &GroupId::from_slice(&[1; 16]));
        assert_eq!(pq_id, &GroupId::from_slice(&[2; 16]));
    }

    #[test]
    fn roundtrip_apq_bootstrap() {
        let aw = ApqWelcome::new_apq(
            dummy_welcome(classical_cs()),
            dummy_welcome(xwing_cs()),
            pq_apq_info(),
            dummy_psk_id(),
        );
        let bytes = aw.tls_serialize_detached().expect("serialize");
        let decoded = ApqWelcome::tls_deserialize_exact(&bytes).expect("deserialize");
        assert_eq!(aw, decoded);
    }

    #[test]
    fn roundtrip_direct_pq_bootstrap() {
        let aw = ApqWelcome::new_direct_pq(dummy_welcome(xwing_cs()), pq_apq_info());
        let bytes = aw.tls_serialize_detached().expect("serialize");
        let decoded = ApqWelcome::tls_deserialize_exact(&bytes).expect("deserialize");
        assert_eq!(aw, decoded);
    }

    #[test]
    fn invalid_t_welcome_presence_byte_rejected() {
        let aw = ApqWelcome::new_direct_pq(dummy_welcome(xwing_cs()), pq_apq_info());
        let mut bytes = aw.tls_serialize_detached().expect("serialize");
        bytes[0] = 0x07;
        match ApqWelcome::tls_deserialize_exact(&bytes) {
            Err(tls_codec::Error::DecodingError(msg)) => {
                assert!(msg.contains("t_welcome presence"));
            }
            other => panic!("expected DecodingError, got {other:?}"),
        }
    }
}
