//! # APQ delivery wire wrappers
//!
//! [`crate::messages::delivery_service`] handles the **runtime queue**
//! used by an in-process delivery service: it pins per-group FIFO and
//! enforces "PQ half before T half" on FULL-commit pairs. This module
//! covers the **wire format** that sits in front of that queue.
//!
//! Two wrapper types and one ordering enum are exposed:
//!
//! - [`ApqMessage`] — a single MLS message tagged with which APQ
//!   session ([`crate::messages::delivery_service::SessionSide`]) it
//!   belongs to. Used for proposals, PARTIAL commits, and application
//!   messages.
//! - [`ApqCommitPair`] — a FULL commit's PQ half **and** T half
//!   bundled together with an opaque pair identifier so the receiver
//!   can correlate the two halves even if they ride different
//!   sub-streams of the same transport.
//! - [`ApqDeliveryOrder`] — declared transport ordering: `PqFirst`,
//!   `TFirst`, or `Independent`. The orchestration layer reads this
//!   off an [`ApqCommitPair`] (or the application protocol) and
//!   refuses to ship a pair with `TFirst` ordering — see
//!   [`ApqCommitPair::declared_order`] and
//!   [`ApqCommitPair::validate_order`].
//!
//! Validation rules:
//!
//! - A FULL commit MUST be shipped PQ-first
//!   ([`ApqDeliveryOrder::PqFirst`]). Any other declared order is
//!   rejected at validate time.
//! - PARTIAL commits and application messages are T-only by
//!   construction (no PQ half), so they always travel as a single
//!   [`ApqMessage`] with `session_side ==
//!   SessionSide::T` and ordering [`ApqDeliveryOrder::Independent`].
//!
//! All three types implement [`tls_codec::Serialize`] /
//! [`tls_codec::Deserialize`]. The inner MLS message is encoded as
//! length-prefixed `VLBytes` so this wire format does **not** depend
//! on `MlsMessageOut`'s deserialize impl (which OpenMLS does not
//! expose) — callers attach already-serialized MLS bytes here.

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use tls_codec::{
    Deserialize as TlsDeserializeTrait, Error as TlsError, Serialize as TlsSerializeTrait,
    Size as TlsSizeTrait, VLBytes,
};

use crate::messages::delivery_service::SessionSide;

/// Declared transport ordering for an APQ delivery unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ApqDeliveryOrder {
    /// PQ half MUST arrive before the T half. Required for FULL
    /// commits — the T half's `PreSharedKey` proposal references PSK
    /// material derived from the PQ half, so the receiver cannot
    /// process the T half until the PQ half is on-disk.
    PqFirst = 0,
    /// T half MUST arrive before the PQ half. **Forbidden** in KChat:
    /// the FULL-commit protocol pins PQ-first ordering, and there is
    /// no construction in MLS today that would require T-first.
    /// Surfaced as an enum variant only so misordered pairs from
    /// untrusted transports can be **named and rejected** rather than
    /// silently mis-decoded.
    TFirst = 1,
    /// The two halves are independent and can be delivered in any
    /// order. Used for non-FULL APQ messages (proposals, PARTIAL
    /// commits, application messages) — there is no half-to-half
    /// dependency to pin.
    Independent = 2,
}

impl ApqDeliveryOrder {
    /// Returns the wire byte for this ordering. See [`Self::from_byte`].
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    /// Decode the wire byte into an [`ApqDeliveryOrder`]. Returns
    /// [`ApqOrderingError::InvalidOrder`] on an unknown discriminant.
    pub const fn from_byte(b: u8) -> Result<Self, ApqOrderingError> {
        match b {
            0 => Ok(Self::PqFirst),
            1 => Ok(Self::TFirst),
            2 => Ok(Self::Independent),
            _ => Err(ApqOrderingError::InvalidOrder { value: b }),
        }
    }
}

/// Reasons an [`ApqCommitPair`] or [`ApqMessage`] fails validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApqOrderingError {
    /// Wire byte for [`ApqDeliveryOrder`] was outside the known range.
    #[error("invalid APQ delivery order discriminant {value}")]
    InvalidOrder {
        /// The byte the encoder produced.
        value: u8,
    },
    /// FULL commit declared a non-`PqFirst` ordering. The KChat
    /// protocol pins PQ-first for FULL commits — anything else means
    /// either the transport is buggy or someone is trying to feed the
    /// receiver a misordered pair.
    #[error(
        "FULL-commit pair must be ordered PqFirst, but ordering was declared as {declared:?}"
    )]
    FullCommitNotPqFirst {
        /// What the wire actually said.
        declared: ApqDeliveryOrder,
    },
}

/// Single APQ-tagged MLS message.
///
/// Wraps an opaque MLS payload (the byte string produced by
/// [`crate::framing::MlsMessageOut::tls_serialize_detached`]) plus
/// metadata identifying which APQ session it belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApqMessage {
    /// Which APQ session this payload is bound for.
    pub session_side: SessionSide,
    /// TLS-encoded `MlsMessageOut` bytes. Encoded as length-prefixed
    /// `VLBytes` on the wire.
    pub payload: VLBytes,
}

impl ApqMessage {
    /// Construct a new [`ApqMessage`] from raw MLS bytes and a session
    /// side.
    pub fn new(session_side: SessionSide, payload: impl Into<VLBytes>) -> Self {
        Self {
            session_side,
            payload: payload.into(),
        }
    }

    /// Construct an [`ApqMessage`] for a T-session payload (PARTIAL
    /// commits, application messages).
    pub fn new_t(payload: impl Into<VLBytes>) -> Self {
        Self::new(SessionSide::T, payload)
    }

    /// Construct an [`ApqMessage`] for a PQ-session payload.
    pub fn new_pq(payload: impl Into<VLBytes>) -> Self {
        Self::new(SessionSide::Pq, payload)
    }
}

/// Bundle of a FULL commit's PQ and T halves.
///
/// `pair_id` is opaque to the wire; the orchestration layer assigns
/// it. Receivers use it to correlate the PQ and T halves if the
/// transport delivers them out of order across separate streams (the
/// invariant is that the **PQ half MUST become observable first**, see
/// [`ApqDeliveryOrder::PqFirst`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApqCommitPair {
    /// Stable pair identifier; mirrors the `pair_id` carried by
    /// [`crate::messages::delivery_service::ApqDeliveryEnvelope`].
    pub pair_id: u64,
    /// Declared ordering. MUST be [`ApqDeliveryOrder::PqFirst`] for a
    /// well-formed FULL-commit pair; anything else fails
    /// [`Self::validate_order`].
    pub declared_order: ApqDeliveryOrder,
    /// PQ half of the FULL commit (the FIRST one to be ratcheted on
    /// the receiver).
    pub pq_half: ApqMessage,
    /// T half of the FULL commit (the SECOND one to be ratcheted on
    /// the receiver).
    pub t_half: ApqMessage,
}

impl ApqCommitPair {
    /// Construct a FULL-commit pair with the canonical PQ-first
    /// ordering. The PQ half is forced to `SessionSide::Pq` and the T
    /// half to `SessionSide::T`.
    pub fn new(
        pair_id: u64,
        pq_payload: impl Into<VLBytes>,
        t_payload: impl Into<VLBytes>,
    ) -> Self {
        Self {
            pair_id,
            declared_order: ApqDeliveryOrder::PqFirst,
            pq_half: ApqMessage::new_pq(pq_payload),
            t_half: ApqMessage::new_t(t_payload),
        }
    }

    /// Validate the structural invariants of a FULL-commit pair:
    ///
    /// - `declared_order` MUST be [`ApqDeliveryOrder::PqFirst`].
    /// - `pq_half.session_side` MUST be [`SessionSide::Pq`].
    /// - `t_half.session_side` MUST be [`SessionSide::T`].
    pub fn validate_order(&self) -> Result<(), ApqOrderingError> {
        if self.declared_order != ApqDeliveryOrder::PqFirst {
            return Err(ApqOrderingError::FullCommitNotPqFirst {
                declared: self.declared_order,
            });
        }
        if self.pq_half.session_side != SessionSide::Pq {
            return Err(ApqOrderingError::FullCommitNotPqFirst {
                declared: ApqDeliveryOrder::TFirst,
            });
        }
        if self.t_half.session_side != SessionSide::T {
            return Err(ApqOrderingError::FullCommitNotPqFirst {
                declared: ApqDeliveryOrder::TFirst,
            });
        }
        Ok(())
    }
}

// ----- TLS codec wiring -----
//
// `SessionSide` and `ApqDeliveryOrder` are both single-byte enums;
// `tls_codec` doesn't ship derive support for foreign types, so the
// codec is hand-written and matches the existing apq_welcome.rs
// convention (single-byte discriminants with explicit accept lists).

const SESSION_SIDE_T_BYTE: u8 = 0;
const SESSION_SIDE_PQ_BYTE: u8 = 1;

#[inline]
fn session_side_byte(side: SessionSide) -> u8 {
    match side {
        SessionSide::T => SESSION_SIDE_T_BYTE,
        SessionSide::Pq => SESSION_SIDE_PQ_BYTE,
    }
}

#[inline]
fn session_side_from_byte(b: u8) -> Result<SessionSide, TlsError> {
    match b {
        SESSION_SIDE_T_BYTE => Ok(SessionSide::T),
        SESSION_SIDE_PQ_BYTE => Ok(SessionSide::Pq),
        _ => Err(TlsError::DecodingError(
            "invalid SessionSide discriminant".to_string(),
        )),
    }
}

impl TlsSizeTrait for ApqDeliveryOrder {
    fn tls_serialized_len(&self) -> usize {
        1
    }
}

impl TlsSerializeTrait for ApqDeliveryOrder {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, TlsError> {
        self.as_byte().tls_serialize(writer)
    }
}

impl TlsDeserializeTrait for ApqDeliveryOrder {
    fn tls_deserialize<R: Read>(reader: &mut R) -> Result<Self, TlsError>
    where
        Self: Sized,
    {
        let byte = u8::tls_deserialize(reader)?;
        ApqDeliveryOrder::from_byte(byte).map_err(|e| TlsError::DecodingError(e.to_string()))
    }
}

impl TlsSizeTrait for ApqMessage {
    fn tls_serialized_len(&self) -> usize {
        // 1 byte for SessionSide + length-prefixed payload.
        1 + self.payload.tls_serialized_len()
    }
}

impl TlsSerializeTrait for ApqMessage {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, TlsError> {
        let mut written = session_side_byte(self.session_side).tls_serialize(writer)?;
        written += self.payload.tls_serialize(writer)?;
        Ok(written)
    }
}

impl TlsDeserializeTrait for ApqMessage {
    fn tls_deserialize<R: Read>(reader: &mut R) -> Result<Self, TlsError>
    where
        Self: Sized,
    {
        let side_byte = u8::tls_deserialize(reader)?;
        let session_side = session_side_from_byte(side_byte)?;
        let payload = VLBytes::tls_deserialize(reader)?;
        Ok(Self {
            session_side,
            payload,
        })
    }
}

impl TlsSizeTrait for ApqCommitPair {
    fn tls_serialized_len(&self) -> usize {
        self.pair_id.tls_serialized_len()
            + self.declared_order.tls_serialized_len()
            + self.pq_half.tls_serialized_len()
            + self.t_half.tls_serialized_len()
    }
}

impl TlsSerializeTrait for ApqCommitPair {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, TlsError> {
        let mut written = self.pair_id.tls_serialize(writer)?;
        written += self.declared_order.tls_serialize(writer)?;
        written += self.pq_half.tls_serialize(writer)?;
        written += self.t_half.tls_serialize(writer)?;
        Ok(written)
    }
}

impl TlsDeserializeTrait for ApqCommitPair {
    fn tls_deserialize<R: Read>(reader: &mut R) -> Result<Self, TlsError>
    where
        Self: Sized,
    {
        let pair_id = u64::tls_deserialize(reader)?;
        let declared_order = ApqDeliveryOrder::tls_deserialize(reader)?;
        let pq_half = ApqMessage::tls_deserialize(reader)?;
        let t_half = ApqMessage::tls_deserialize(reader)?;
        Ok(Self {
            pair_id,
            declared_order,
            pq_half,
            t_half,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tls_codec::{Deserialize as _, Serialize as _};

    #[test]
    fn apq_message_round_trips_t_payload() {
        let msg = ApqMessage::new_t(b"t-payload".to_vec());
        let bytes = msg.tls_serialize_detached().expect("serialize");
        let decoded = ApqMessage::tls_deserialize_exact(&bytes).expect("deserialize");
        assert_eq!(decoded, msg);
        assert_eq!(decoded.session_side, SessionSide::T);
    }

    #[test]
    fn apq_message_round_trips_pq_payload() {
        let msg = ApqMessage::new_pq(b"pq-payload".to_vec());
        let bytes = msg.tls_serialize_detached().expect("serialize");
        let decoded = ApqMessage::tls_deserialize_exact(&bytes).expect("deserialize");
        assert_eq!(decoded, msg);
        assert_eq!(decoded.session_side, SessionSide::Pq);
    }

    #[test]
    fn apq_message_rejects_invalid_session_side_byte() {
        // Build a two-byte payload: bogus side byte (0xFF) + empty
        // length-prefixed VLBytes (0x00).
        let bogus = [0xFFu8, 0x00];
        let err = ApqMessage::tls_deserialize_exact(&bogus).expect_err("must reject");
        assert!(matches!(err, TlsError::DecodingError(_)));
    }

    #[test]
    fn apq_commit_pair_round_trips() {
        let pair = ApqCommitPair::new(42, b"pq-bytes".to_vec(), b"t-bytes".to_vec());
        let bytes = pair.tls_serialize_detached().expect("serialize");
        let decoded = ApqCommitPair::tls_deserialize_exact(&bytes).expect("deserialize");
        assert_eq!(decoded, pair);
        assert_eq!(decoded.pair_id, 42);
        assert_eq!(decoded.declared_order, ApqDeliveryOrder::PqFirst);
        decoded
            .validate_order()
            .expect("freshly-constructed pair must validate");
    }

    #[test]
    fn apq_commit_pair_validate_rejects_t_first_ordering() {
        let mut pair = ApqCommitPair::new(7, b"pq".to_vec(), b"t".to_vec());
        pair.declared_order = ApqDeliveryOrder::TFirst;
        let err = pair.validate_order().expect_err("must reject");
        assert_eq!(
            err,
            ApqOrderingError::FullCommitNotPqFirst {
                declared: ApqDeliveryOrder::TFirst
            }
        );
    }

    #[test]
    fn apq_commit_pair_validate_rejects_independent_ordering() {
        let mut pair = ApqCommitPair::new(8, b"pq".to_vec(), b"t".to_vec());
        pair.declared_order = ApqDeliveryOrder::Independent;
        let err = pair.validate_order().expect_err("must reject");
        assert_eq!(
            err,
            ApqOrderingError::FullCommitNotPqFirst {
                declared: ApqDeliveryOrder::Independent
            }
        );
    }

    #[test]
    fn apq_commit_pair_validate_rejects_swapped_session_sides() {
        // Caller manually swaps the session side metadata on the
        // halves. validate_order should catch this even though
        // declared_order is still PqFirst.
        let mut pair = ApqCommitPair::new(9, b"pq".to_vec(), b"t".to_vec());
        pair.pq_half.session_side = SessionSide::T;
        pair.t_half.session_side = SessionSide::Pq;
        let err = pair.validate_order().expect_err("must reject");
        // We don't pin exactly which sub-check fires; just that one
        // does and it surfaces as the canonical FullCommitNotPqFirst
        // error so callers have a single error path to handle.
        assert!(matches!(err, ApqOrderingError::FullCommitNotPqFirst { .. }));
    }

    #[test]
    fn apq_delivery_order_byte_round_trip() {
        for order in [
            ApqDeliveryOrder::PqFirst,
            ApqDeliveryOrder::TFirst,
            ApqDeliveryOrder::Independent,
        ] {
            let byte = order.as_byte();
            let back = ApqDeliveryOrder::from_byte(byte).expect("decode");
            assert_eq!(back, order);
        }
    }

    #[test]
    fn apq_delivery_order_rejects_unknown_byte() {
        let err = ApqDeliveryOrder::from_byte(99).expect_err("must reject");
        assert_eq!(err, ApqOrderingError::InvalidOrder { value: 99 });
    }

    #[test]
    fn apq_delivery_order_tls_round_trip() {
        for order in [
            ApqDeliveryOrder::PqFirst,
            ApqDeliveryOrder::TFirst,
            ApqDeliveryOrder::Independent,
        ] {
            let bytes = order.tls_serialize_detached().expect("serialize");
            let back = ApqDeliveryOrder::tls_deserialize_exact(&bytes).expect("deserialize");
            assert_eq!(back, order);
        }
    }
}
