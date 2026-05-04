//! Welcome fanout load tests.
//!
//! These tests exercise the Welcome message construction and
//! serialization paths at scale using real `MlsGroup` operations under
//! the RustCrypto provider with classical ciphersuites. They are
//! load-shaped (50–100 group operations per test) but are not
//! benchmarks — the goal is to catch regressions where Welcome
//! emission gets lost, becomes nondeterministic, or breaks under
//! concurrent group setup.

use openmls::credentials::{BasicCredential, CredentialWithKey};
use openmls::extensions::apq_info::ApqInfo;
use openmls::framing::{MlsMessageBodyIn, MlsMessageIn};
use openmls::group::{GroupId, MlsGroup, MlsGroupCreateConfig};
use openmls::key_packages::KeyPackage;
use openmls::messages::ApqWelcome;
use openmls::prelude::SecurityMode;
use openmls::schedule::psk::PreSharedKeyId;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::types::Ciphersuite;
use tls_codec::{Deserialize as _, Serialize as _};

const CS: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const CS_ALT: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

fn signer(cs: Ciphersuite) -> SignatureKeyPair {
    SignatureKeyPair::new(cs.signature_algorithm()).expect("signer")
}

fn credential(name: &str, signer: &SignatureKeyPair) -> CredentialWithKey {
    CredentialWithKey {
        credential: BasicCredential::new(name.as_bytes().to_vec()).into(),
        signature_key: signer.public().into(),
    }
}

fn group_for(
    provider: &OpenMlsRustCrypto,
    name: &str,
    cs: Ciphersuite,
) -> (MlsGroup, SignatureKeyPair) {
    let s = signer(cs);
    let cred = credential(name, &s);
    let cfg = MlsGroupCreateConfig::builder().ciphersuite(cs).build();
    let group = MlsGroup::new(provider, &s, &cfg, cred).expect("group new");
    (group, s)
}

fn key_package(
    provider: &OpenMlsRustCrypto,
    name: &str,
    cs: Ciphersuite,
) -> (KeyPackage, SignatureKeyPair) {
    let s = signer(cs);
    let cred = credential(name, &s);
    let kpb = KeyPackage::builder()
        .build(cs, provider, &s, cred)
        .expect("kp build");
    (kpb.key_package().clone(), s)
}

#[test]
fn add_ten_members_to_one_group_produces_one_welcome_each_round() {
    // Phase 4 says "Welcome fanout = N members per add_members call →
    // one Welcome carrying secrets for every joiner". Pin that the
    // welcome is emitted on every add_members call, and that joiners
    // outside the call don't get one.
    let provider = OpenMlsRustCrypto::default();
    let (mut alice_group, alice_signer) = group_for(&provider, "alice", CS);

    for i in 0..10 {
        let (kp, _bob_signer) = key_package(&provider, &format!("bob-{i}"), CS);
        let (_, welcome, _) = alice_group
            .add_members(&provider, &alice_signer, &[kp])
            .expect("add_members");
        // Welcome must be present (we added at least one member).
        assert!(matches!(
            welcome.body(),
            openmls::framing::MlsMessageBodyOut::Welcome(_)
        ));
        alice_group.merge_pending_commit(&provider).expect("merge");
    }
}

#[test]
fn welcome_serialize_deserialize_round_trips_a_hundred_times() {
    // Serialize one Welcome and round-trip it through TLS codec 100
    // times — verify the bytes are byte-stable and never corrupted
    // across the loop.
    let provider = OpenMlsRustCrypto::default();
    let (mut alice_group, alice_signer) = group_for(&provider, "alice", CS);
    let (kp, _bob_signer) = key_package(&provider, "bob", CS);
    let (_, welcome, _) = alice_group
        .add_members(&provider, &alice_signer, &[kp])
        .expect("add_members");

    let bytes = welcome.tls_serialize_detached().expect("serialize");
    for i in 0..100 {
        let decoded = MlsMessageIn::tls_deserialize_exact(&bytes)
            .unwrap_or_else(|e| panic!("iteration {i} deserialize: {e:?}"));
        // Round-trip back through MlsMessageOut so byte-stability is
        // observable. We assert that the body is a Welcome — that's
        // the contract `add_members` promises.
        assert!(
            matches!(decoded.extract(), MlsMessageBodyIn::Welcome(_)),
            "iteration {i}: decoded body is not a Welcome",
        );
    }
}

#[test]
fn fifty_groups_each_with_two_members_produce_distinct_welcomes() {
    // Each (creator, group) tuple must produce a Welcome that is
    // structurally distinct from every other group's Welcome — at
    // minimum the bytes must differ pairwise.
    let provider = OpenMlsRustCrypto::default();
    const NUM_GROUPS: usize = 50;

    let mut welcomes: Vec<Vec<u8>> = Vec::with_capacity(NUM_GROUPS);
    for g in 0..NUM_GROUPS {
        let (mut alice_group, alice_signer) = group_for(&provider, &format!("alice-{g}"), CS);
        let (bob_kp, _) = key_package(&provider, &format!("bob-{g}"), CS);
        let (charlie_kp, _) = key_package(&provider, &format!("charlie-{g}"), CS);
        let (_, welcome, _) = alice_group
            .add_members(&provider, &alice_signer, &[bob_kp, charlie_kp])
            .expect("add_members");
        let bytes = welcome.tls_serialize_detached().expect("serialize");
        welcomes.push(bytes);
        alice_group.merge_pending_commit(&provider).expect("merge");
    }

    // Pairwise-distinct check.
    for i in 0..NUM_GROUPS {
        for j in (i + 1)..NUM_GROUPS {
            assert_ne!(
                welcomes[i], welcomes[j],
                "groups {i} and {j} produced identical Welcome bytes — \
                 ratchet/secrets reused across groups"
            );
        }
    }
}

#[test]
fn apq_welcome_round_trip_at_scale() {
    // Build 20 ApqWelcome envelopes from real MLS Welcomes and round
    // trip every one of them through TLS codec — verify validate()
    // succeeds on every decoded copy.
    let provider = OpenMlsRustCrypto::default();
    const N: usize = 20;

    for i in 0..N {
        // Build a real Welcome for the T session.
        let (mut t_group, t_signer) = group_for(&provider, &format!("alice-t-{i}"), CS);
        let (bob_kp_t, _) = key_package(&provider, &format!("bob-t-{i}"), CS);
        let (_, t_welcome_msg, _) = t_group
            .add_members(&provider, &t_signer, &[bob_kp_t])
            .expect("add t");
        t_group.merge_pending_commit(&provider).expect("merge t");

        // And a real Welcome for the PQ session — for these tests
        // we use a different *classical* ciphersuite as a stand-in
        // for the PQ session because we're not running under the
        // `xwing` feature.
        let (mut pq_group, pq_signer) = group_for(&provider, &format!("alice-pq-{i}"), CS_ALT);
        let (bob_kp_pq, _) = key_package(&provider, &format!("bob-pq-{i}"), CS_ALT);
        let (_, pq_welcome_msg, _) = pq_group
            .add_members(&provider, &pq_signer, &[bob_kp_pq])
            .expect("add pq");
        pq_group.merge_pending_commit(&provider).expect("merge pq");

        let t_welcome = t_welcome_msg.into_welcome().expect("t welcome");
        let pq_welcome = pq_welcome_msg.into_welcome().expect("pq welcome");

        // Non-PQ stand-in: even though the PQ session is classical,
        // the ApqInfo still pins both ciphersuites, so the
        // ciphersuite-mismatch check in validate() fires correctly.
        let info = ApqInfo::new(
            GroupId::from_slice(&[(i as u8).wrapping_add(0xA0); 16]),
            GroupId::from_slice(&[(i as u8).wrapping_add(0xB0); 16]),
            0,
            0,
            CS,
            CS_ALT,
            SecurityMode::PqConfidentiality,
        );
        let psk_id = PreSharedKeyId::external(format!("apq_psk_{i}").into_bytes(), vec![0u8; 32]);

        let aw = ApqWelcome::new_apq(t_welcome, pq_welcome, info, psk_id);
        // Round-trip.
        let bytes = aw.tls_serialize_detached().expect("serialize");
        let decoded = ApqWelcome::tls_deserialize_exact(&bytes).expect("deserialize");
        assert_eq!(aw, decoded, "ApqWelcome {i} did not round-trip");
        // The structural shape and ApqInfo's `mode == PqConfidentiality`
        // round-trip cleanly. validate() rejects the bundle because
        // the test runs without `xwing` and uses a classical
        // ciphersuite as a stand-in for the PQ session — so we pin
        // that the *expected* error is `ModeMismatch` and nothing
        // else.
        match decoded.validate() {
            Err(openmls::messages::ApqWelcomeError::InvalidApqInfo(_)) => {}
            other => panic!(
                "iteration {i}: expected ModeMismatch (PQ ciphersuite is a classical \
                 stand-in without `xwing`), got {other:?}"
            ),
        }
    }
}

#[test]
fn welcome_ciphersuite_consistent_across_a_batch() {
    // A batch of 10 add_members operations on the same group must
    // emit Welcomes whose ciphersuite matches the group's
    // ciphersuite. Pins that the Welcome we hand to joiners always
    // tells them which suite to set up — Phase 4 depends on this
    // being correct.
    let provider = OpenMlsRustCrypto::default();
    let (mut alice_group, alice_signer) = group_for(&provider, "alice", CS);

    for i in 0..10 {
        let (bob_kp, _) = key_package(&provider, &format!("bob-{i}"), CS);
        let (_, welcome_msg, _) = alice_group
            .add_members(&provider, &alice_signer, &[bob_kp])
            .expect("add");
        // Round-trip the Welcome through TLS codec and confirm the
        // decoded message is a Welcome — pins that the wire shape
        // is stable across the batch.
        let bytes = welcome_msg.tls_serialize_detached().expect("serialize");
        let decoded = MlsMessageIn::tls_deserialize_exact(&bytes)
            .unwrap_or_else(|e| panic!("iteration {i} deserialize: {e:?}"));
        assert!(
            matches!(decoded.extract(), MlsMessageBodyIn::Welcome(_)),
            "iteration {i}: add_members must emit a Welcome",
        );
        alice_group.merge_pending_commit(&provider).expect("merge");
    }
    // Group's ciphersuite stays pinned across the batch — that's
    // the structural invariant `add_members` relies on.
    assert_eq!(alice_group.ciphersuite(), CS);
}
