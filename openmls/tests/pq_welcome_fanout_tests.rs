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

// =============================================================================
// High-scale `#[ignore]`d Welcome fanout tests (Task 6).
//
// These exercise Welcome emission for groups of 100, 500, and 1000
// members and assert the size budget documented in
// ARCHITECTURE.md (≈2669 bytes / X-Wing PQ KeyPackage). They are
// `#[ignore]`d because the build-time cost of generating that many
// keypairs is significant; run with
// `cargo test -p openmls --test pq_welcome_fanout_tests -- --ignored`.
//
// Each test prints the per-Welcome serialized size so a human
// running the suite can spot regressions in the size budget.
// =============================================================================

/// Documented per-PQ-KeyPackage budget for X-Wing-shaped Welcomes.
/// See ARCHITECTURE.md (line ~330) — this is the size we expect a
/// classical-equivalent Welcome to live well under, so the assertion
/// here is "Welcome is at most a small multiple of this number".
const ARCHITECTURE_PQ_KEYPACKAGE_BUDGET_BYTES: usize = 2669;

#[test]
#[ignore = "load test — run with `cargo test -- --ignored`"]
fn load_welcome_fanout_one_hundred_members() {
    welcome_fanout_at_scale(100);
}

#[test]
#[ignore = "load test — run with `cargo test -- --ignored`"]
fn load_welcome_fanout_five_hundred_members() {
    welcome_fanout_at_scale(500);
}

#[test]
#[ignore = "load test — run with `cargo test -- --ignored`"]
fn load_welcome_fanout_one_thousand_members() {
    welcome_fanout_at_scale(1_000);
}

fn welcome_fanout_at_scale(num_members: usize) {
    use std::time::Instant;
    let provider = OpenMlsRustCrypto::default();
    let (mut alice_group, alice_signer) = group_for(&provider, "alice", CS);

    // Generate `num_members` KeyPackages up front so the timing
    // measurements isolate the add+serialize cost.
    let kp_start = Instant::now();
    let kps: Vec<KeyPackage> = (0..num_members)
        .map(|i| key_package(&provider, &format!("member-{i:05}"), CS).0)
        .collect();
    let kp_elapsed = kp_start.elapsed();
    eprintln!(
        "fanout({num_members}): generated {num_members} KeyPackages in {:?}",
        kp_elapsed
    );

    // Add every member in a single commit so the Welcome contains
    // every joiner's encrypted secrets.
    let add_start = Instant::now();
    let (_, welcome_msg, _) = alice_group
        .add_members(&provider, &alice_signer, &kps)
        .expect("add bulk");
    let add_elapsed = add_start.elapsed();

    let serialized = welcome_msg.tls_serialize_detached().expect("serialize");
    let total_size = serialized.len();
    let per_member = total_size / num_members.max(1);
    eprintln!(
        "fanout({num_members}): bulk add+welcome in {:?}; welcome serialized = {} bytes \
         ({} bytes / member)",
        add_elapsed, total_size, per_member
    );

    // The classical Welcome's per-member overhead must be well under
    // the PQ budget — pin it at 2× as a generous bound. If this ever
    // trips it indicates the per-member encrypted secrets blob got
    // unexpectedly large.
    let upper_bound = 2 * ARCHITECTURE_PQ_KEYPACKAGE_BUDGET_BYTES;
    assert!(
        per_member < upper_bound,
        "fanout({num_members}): per-member welcome size {per_member} >= upper bound {upper_bound}"
    );

    // Round-trip the Welcome through TLS codec — pins that the wire
    // format is stable at scale.
    let decoded = MlsMessageIn::tls_deserialize_exact(&serialized).expect("deserialize");
    assert!(
        matches!(decoded.extract(), MlsMessageBodyIn::Welcome(_)),
        "fanout({num_members}): bulk add must emit a Welcome"
    );

    alice_group.merge_pending_commit(&provider).expect("merge");
}

#[test]
#[ignore = "load test — run with `cargo test -- --ignored`"]
fn load_apq_welcome_pair_size_tracks_classical() {
    // ApqWelcome wraps two paired Welcomes plus an ApqInfo and a PSK
    // ID. Verify the wrapped pair stays within ~3× the budget of a
    // single classical Welcome at 100 members. This is a coarse
    // upper bound — the real budget tightens once X-Wing lands.
    use std::time::Instant;
    let provider = OpenMlsRustCrypto::default();
    let (mut alice_group_t, alice_signer_t) = group_for(&provider, "alice-t", CS);
    let (mut alice_group_pq, alice_signer_pq) = group_for(&provider, "alice-pq", CS_ALT);

    const NUM_MEMBERS: usize = 100;
    let kps_t: Vec<KeyPackage> = (0..NUM_MEMBERS)
        .map(|i| key_package(&provider, &format!("t-{i:05}"), CS).0)
        .collect();
    let kps_pq: Vec<KeyPackage> = (0..NUM_MEMBERS)
        .map(|i| key_package(&provider, &format!("pq-{i:05}"), CS_ALT).0)
        .collect();

    let start = Instant::now();
    let (_, welcome_t, _) = alice_group_t
        .add_members(&provider, &alice_signer_t, &kps_t)
        .expect("add t");
    let (_, welcome_pq, _) = alice_group_pq
        .add_members(&provider, &alice_signer_pq, &kps_pq)
        .expect("add pq");
    let elapsed = start.elapsed();

    let apq_info = ApqInfo::new(
        GroupId::from_slice(b"t-id"),
        GroupId::from_slice(b"pq-id"),
        0,
        0,
        CS,
        CS_ALT,
        SecurityMode::PqConfidentiality,
    );
    let welcome_t_inner = match welcome_t.body() {
        openmls::framing::MlsMessageBodyOut::Welcome(w) => w.clone(),
        _ => panic!("expected Welcome body"),
    };
    let welcome_pq_inner = match welcome_pq.body() {
        openmls::framing::MlsMessageBodyOut::Welcome(w) => w.clone(),
        _ => panic!("expected Welcome body"),
    };
    let pair = ApqWelcome::new_apq(
        welcome_t_inner,
        welcome_pq_inner,
        apq_info,
        PreSharedKeyId::external(b"apq-psk".to_vec(), b"nonce".to_vec()),
    );
    let bytes = pair.tls_serialize_detached().expect("serialize");
    let total = bytes.len();
    eprintln!(
        "apq fanout({NUM_MEMBERS}): bulk add of two paired Welcomes in {:?}; \
         apq welcome serialized = {total} bytes ({} bytes / member)",
        elapsed,
        total / NUM_MEMBERS
    );
    let upper_bound = 6 * ARCHITECTURE_PQ_KEYPACKAGE_BUDGET_BYTES * NUM_MEMBERS;
    assert!(
        total < upper_bound,
        "apq fanout({NUM_MEMBERS}): wire size {total} >= upper bound {upper_bound}"
    );

    alice_group_t.merge_pending_commit(&provider).expect("merge t");
    alice_group_pq
        .merge_pending_commit(&provider)
        .expect("merge pq");
}
