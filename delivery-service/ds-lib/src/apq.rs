//! # APQ delivery wire types for the reference DS
//!
//! Re-exports the [`ApqMessage`] / [`ApqCommitPair`] /
//! [`ApqDeliveryOrder`] / [`ApqOrderingError`] wrapper types from
//! [`openmls::messages::apq_delivery`] under the `ds-lib`
//! namespace, plus a request/response pair the reference delivery
//! service can speak so test harnesses don't need to reach into the
//! `openmls` crate directly.
//!
//! The reference DS is intentionally minimal — it does not enforce the
//! "PQ half before T half" invariant itself (that lives in
//! [`openmls::messages::delivery_service::DeliveryService::enqueue`]
//! and is exercised in the openmls test suite). It just carries the
//! wire envelope across the test transport.

use openmls::prelude::tls_codec::{
    self, Deserialize, Error, Serialize, Size, TlsDeserialize, TlsSerialize, TlsSize,
};
pub use openmls::prelude::{
    ApqCommitPair, ApqDeliveryOrder, ApqMessage, ApqOrderingError, SessionSide,
};

use crate::messages::AuthToken;

/// Client → DS: enqueue a single [`ApqMessage`] for fan-out.
#[derive(Debug, Clone, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct PublishApqMessageRequest {
    /// Wire envelope.
    pub message: ApqMessage,
    /// Caller's auth token (mirrors every other ds-lib request).
    pub auth_token: AuthToken,
}

/// Client → DS: enqueue a FULL-commit pair (PQ half + T half) in a
/// single round trip. The DS will deliver them PQ-first to every peer.
#[derive(Debug, Clone, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct PublishApqCommitPairRequest {
    /// Wire envelope.
    pub pair: ApqCommitPair,
    /// Caller's auth token.
    pub auth_token: AuthToken,
}

/// DS → client: list of envelopes pending for this client.
///
/// Both single messages and FULL-commit pairs ride the same response
/// envelope; clients dispatch on the `ApqEnvelope` discriminant.
#[derive(Debug, Clone, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct RecvApqMessagesResponse {
    /// Pending envelopes in delivery order (PQ-first for FULL-commit
    /// pairs).
    pub envelopes: Vec<ApqEnvelope>,
}

/// One delivered envelope: either a stand-alone [`ApqMessage`] or a
/// FULL-commit [`ApqCommitPair`].
///
/// Encoded with a single-byte discriminant on the wire (`0` = message,
/// `1` = pair). The discriminant is *not* derived via the `TlsSize` /
/// `TlsSerialize` proc macros — those don't ship a tagged-union mode
/// in the version of `tls_codec` we use — so the codec is hand-written
/// below.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApqEnvelope {
    /// A single APQ-tagged MLS message.
    Message(ApqMessage),
    /// A FULL-commit PQ + T pair.
    CommitPair(ApqCommitPair),
}

const ENVELOPE_TAG_MESSAGE: u8 = 0;
const ENVELOPE_TAG_COMMIT_PAIR: u8 = 1;

impl Size for ApqEnvelope {
    fn tls_serialized_len(&self) -> usize {
        1 + match self {
            ApqEnvelope::Message(m) => m.tls_serialized_len(),
            ApqEnvelope::CommitPair(p) => p.tls_serialized_len(),
        }
    }
}

impl Serialize for ApqEnvelope {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        match self {
            ApqEnvelope::Message(m) => {
                let mut written = ENVELOPE_TAG_MESSAGE.tls_serialize(writer)?;
                written += m.tls_serialize(writer)?;
                Ok(written)
            }
            ApqEnvelope::CommitPair(p) => {
                let mut written = ENVELOPE_TAG_COMMIT_PAIR.tls_serialize(writer)?;
                written += p.tls_serialize(writer)?;
                Ok(written)
            }
        }
    }
}

impl Deserialize for ApqEnvelope {
    fn tls_deserialize<R: std::io::Read>(reader: &mut R) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let tag = u8::tls_deserialize(reader)?;
        match tag {
            ENVELOPE_TAG_MESSAGE => Ok(ApqEnvelope::Message(ApqMessage::tls_deserialize(reader)?)),
            ENVELOPE_TAG_COMMIT_PAIR => Ok(ApqEnvelope::CommitPair(
                ApqCommitPair::tls_deserialize(reader)?,
            )),
            other => Err(Error::DecodingError(format!(
                "unknown ApqEnvelope tag {other}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apq_envelope_round_trips_single_message() {
        let env = ApqEnvelope::Message(ApqMessage::new_t(b"hello".to_vec()));
        let bytes = env.tls_serialize_detached().expect("serialize");
        let back = ApqEnvelope::tls_deserialize_exact(&bytes).expect("deserialize");
        assert_eq!(back, env);
    }

    #[test]
    fn apq_envelope_round_trips_commit_pair() {
        let env = ApqEnvelope::CommitPair(ApqCommitPair::new(
            123,
            b"pq-half".to_vec(),
            b"t-half".to_vec(),
        ));
        let bytes = env.tls_serialize_detached().expect("serialize");
        let back = ApqEnvelope::tls_deserialize_exact(&bytes).expect("deserialize");
        assert_eq!(back, env);
        if let ApqEnvelope::CommitPair(pair) = back {
            pair.validate_order().expect("validate");
        } else {
            panic!("expected CommitPair");
        }
    }

    #[test]
    fn apq_envelope_rejects_unknown_tag() {
        // Smallest possible bogus tag: 0xFF + nothing else.
        let bogus = [0xFFu8];
        let err = ApqEnvelope::tls_deserialize_exact(bogus.as_slice()).expect_err("must reject");
        assert!(matches!(err, Error::DecodingError(_)));
    }
}
