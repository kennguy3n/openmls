//! Criterion benchmarks for PQ-critical operations.
//!
//! The benchmark suite focuses on operations that are *only* relevant
//! to KChat's PQ orchestration layer: capability signing/verification,
//! mode selection across many peers, ApqInfo TLS round-trips, no-
//! downgrade validators, and the storage migrator. Anything that
//! would require a real PQ KEM (X-Wing) or PQ signature scheme
//! (ML-DSA) is gated behind the corresponding `xwing` / `mldsa`
//! feature on the `openmls` crate so the default `cargo bench` still
//! runs in environments without libcrux.

#[macro_use]
extern crate criterion;
extern crate openmls;

use criterion::{BenchmarkId, Criterion};
use openmls::{
    ciphersuite::security_mode::SecurityMode,
    credentials::DeviceCapability,
    extensions::ApqInfo,
    group::{
        select_conversation_mode, validate_apq_info_change, validate_ciphersuite_pin,
        validate_epoch_consistency, validate_joiner_key_package, validate_mode_change,
        ConversationSecurityState, GroupId,
    },
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{Ciphersuite, SignatureScheme},
    OpenMlsProvider,
};
use tls_codec::{Deserialize as _, Serialize as _};

/// Default classical ciphersuite used across benchmarks.
const CLASSICAL_CS: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

fn signed_capability(
    crypto: &impl OpenMlsCrypto,
    classical: Vec<Ciphersuite>,
    pq: Vec<Ciphersuite>,
    pq_auth_supported: bool,
    provider_id: &str,
) -> (DeviceCapability, Vec<u8>) {
    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let mut cap = DeviceCapability::new(
        1,
        classical,
        pq,
        true,
        pq_auth_supported,
        provider_id.to_string(),
    );
    cap.sign(SignatureScheme::ED25519, signer.private(), crypto)
        .unwrap();
    (cap, signer.to_public_vec())
}

/// `DeviceCapability::sign` and `verify`. Ed25519 baseline only by
/// default — extending to ML-DSA-65 would require gating behind
/// `cfg(feature = "mldsa")` on this crate, which the suite doesn't
/// currently expose.
fn bench_capability_sign_verify(c: &mut Criterion) {
    let provider = OpenMlsRustCrypto::default();
    let (cap, public_key) = signed_capability(
        provider.crypto(),
        vec![CLASSICAL_CS],
        vec![],
        false,
        "rustcrypto",
    );

    c.bench_function("DeviceCapability::sign (Ed25519)", |b| {
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        b.iter_with_setup(
            || {
                DeviceCapability::new(
                    1,
                    vec![CLASSICAL_CS],
                    vec![],
                    true,
                    false,
                    "rustcrypto".to_string(),
                )
            },
            |mut cap| {
                cap.sign(
                    SignatureScheme::ED25519,
                    signer.private(),
                    provider.crypto(),
                )
                .unwrap();
            },
        )
    });

    c.bench_function("DeviceCapability::verify (Ed25519)", |b| {
        b.iter(|| {
            cap.verify(SignatureScheme::ED25519, &public_key, provider.crypto())
                .unwrap();
        })
    });
}

/// `select_conversation_mode` with peer set sizes 10, 100, and 1000.
/// Exercises the PQ-aware selection logic — every peer here is
/// classical-only so the result is deterministic.
fn bench_select_conversation_mode(c: &mut Criterion) {
    let provider = OpenMlsRustCrypto::default();
    let mut group = c.benchmark_group("select_conversation_mode");
    for &n in &[10usize, 100, 1000] {
        let caps: Vec<DeviceCapability> = (0..n)
            .map(|_| {
                signed_capability(
                    provider.crypto(),
                    vec![CLASSICAL_CS],
                    vec![],
                    false,
                    "rustcrypto",
                )
                .0
            })
            .collect();
        let refs: Vec<&DeviceCapability> = caps.iter().collect();
        group.bench_with_input(BenchmarkId::from_parameter(n), &refs, |b, refs| {
            b.iter(|| {
                let _ = select_conversation_mode(refs).unwrap();
            });
        });
    }
    group.finish();
}

/// `ApqInfo` TLS encode/decode round-trip.
fn bench_apq_info_tls_roundtrip(c: &mut Criterion) {
    let info = ApqInfo::new(
        GroupId::from_slice(b"t-group-id-bench"),
        GroupId::from_slice(b"pq-group-id-bench"),
        7,
        7,
        CLASSICAL_CS,
        CLASSICAL_CS,
        SecurityMode::PqConfidentiality,
    );

    c.bench_function("ApqInfo::tls_serialize", |b| {
        b.iter(|| {
            let mut buf = Vec::new();
            info.tls_serialize(&mut buf).unwrap();
        })
    });

    let mut buf = Vec::new();
    info.tls_serialize(&mut buf).unwrap();
    c.bench_function("ApqInfo::tls_deserialize", |b| {
        b.iter(|| {
            let mut slice = buf.as_slice();
            let _ = ApqInfo::tls_deserialize(&mut slice).unwrap();
        })
    });
}

/// `ConversationSecurityState` no-downgrade validators.
///
/// The five validators all run in O(1) per call, so the bench just
/// verifies the steady-state cost. We call them in a fan-out pattern
/// so the iteration time amortises across all five.
fn bench_no_downgrade_validators(c: &mut Criterion) {
    let state = ConversationSecurityState::new(SecurityMode::Classical);

    let info = ApqInfo::new(
        GroupId::from_slice(b"t-group-id"),
        GroupId::from_slice(b"pq-group-id"),
        1,
        1,
        CLASSICAL_CS,
        CLASSICAL_CS,
        SecurityMode::PqConfidentiality,
    );

    c.bench_function("ConversationSecurityState validators (5x)", |b| {
        b.iter(|| {
            let _ = validate_mode_change(&state, SecurityMode::Classical);
            let _ = validate_joiner_key_package(SecurityMode::Classical, CLASSICAL_CS);
            let _ = validate_apq_info_change(Some(&info), Some(&info));
            let _ = validate_epoch_consistency(1, 1, Some(&info));
            let _ = validate_ciphersuite_pin(&state, CLASSICAL_CS);
        })
    });
}

criterion_group!(
    pq_benches,
    bench_capability_sign_verify,
    bench_select_conversation_mode,
    bench_apq_info_tls_roundtrip,
    bench_no_downgrade_validators,
);
criterion_main!(pq_benches);
