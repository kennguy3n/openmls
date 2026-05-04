//! Integration tests for the APQ delivery wire wrappers.
//!
//! Covers the round-trip of [`ApqCommitPair`] / [`ApqMessage`] through
//! TLS encoding and the canonical PQ-first ordering invariant. The
//! queue-level "PQ half before T half" enforcement is exercised by
//! the `DeliveryService`'s own unit tests inside
//! [`openmls::messages::delivery_service`]; this suite is the public
//! wire-format companion to those tests.

use openmls::messages::apq_delivery::{
    ApqCommitPair, ApqDeliveryOrder, ApqMessage, ApqOrderingError,
};
use openmls::messages::delivery_service::SessionSide;
use tls_codec::{Deserialize, Serialize};

#[test]
fn full_commit_pair_round_trips_and_validates() {
    let pair = ApqCommitPair::new(0xCAFE, b"pq-half-bytes".to_vec(), b"t-half-bytes".to_vec());
    let bytes = pair.tls_serialize_detached().expect("serialize");
    let recovered = ApqCommitPair::tls_deserialize_exact(&bytes).expect("deserialize");
    assert_eq!(recovered, pair);
    assert_eq!(recovered.declared_order, ApqDeliveryOrder::PqFirst);
    recovered
        .validate_order()
        .expect("freshly constructed PQ-first pair must validate");
}

#[test]
fn misordered_full_commit_pair_is_rejected_by_validate() {
    let mut pair = ApqCommitPair::new(1, b"pq".to_vec(), b"t".to_vec());
    pair.declared_order = ApqDeliveryOrder::TFirst;
    let err = pair.validate_order().expect_err("must reject TFirst");
    assert_eq!(
        err,
        ApqOrderingError::FullCommitNotPqFirst {
            declared: ApqDeliveryOrder::TFirst
        }
    );
}

#[test]
fn full_commit_pair_session_sides_are_canonical() {
    let pair = ApqCommitPair::new(7, b"pq".to_vec(), b"t".to_vec());
    assert_eq!(pair.pq_half.session_side, SessionSide::Pq);
    assert_eq!(pair.t_half.session_side, SessionSide::T);
    pair.validate_order().expect("PQ-first pair must validate");
}

#[test]
fn apq_message_round_trips_for_t_session() {
    let msg = ApqMessage::new_t(b"application-message".to_vec());
    let bytes = msg.tls_serialize_detached().expect("serialize");
    let recovered = ApqMessage::tls_deserialize_exact(&bytes).expect("deserialize");
    assert_eq!(recovered, msg);
    assert_eq!(recovered.session_side, SessionSide::T);
}

#[test]
fn apq_message_round_trips_for_pq_session() {
    let msg = ApqMessage::new_pq(b"pq-application-message".to_vec());
    let bytes = msg.tls_serialize_detached().expect("serialize");
    let recovered = ApqMessage::tls_deserialize_exact(&bytes).expect("deserialize");
    assert_eq!(recovered, msg);
    assert_eq!(recovered.session_side, SessionSide::Pq);
}

#[test]
fn partial_commit_uses_independent_ordering() {
    // PARTIAL commits are T-only; they ride a single ApqMessage with
    // Independent ordering. Verify the wire round-trips.
    let order = ApqDeliveryOrder::Independent;
    let bytes = order.tls_serialize_detached().expect("serialize");
    let back = ApqDeliveryOrder::tls_deserialize_exact(&bytes).expect("deserialize");
    assert_eq!(back, order);
}

#[test]
fn delivery_order_rejects_unknown_byte() {
    // Hand-crafted invalid discriminant must round-trip to a
    // DecodingError on tls_deserialize.
    let bogus = [0xAAu8];
    let err = ApqDeliveryOrder::tls_deserialize_exact(&bogus).expect_err("must reject");
    assert!(matches!(err, tls_codec::Error::DecodingError(_)));
}
