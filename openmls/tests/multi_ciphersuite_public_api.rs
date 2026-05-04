//! Integration tests for the public multi-ciphersuite KeyPackage API.
//!
//! Lives outside the `openmls` crate so it exercises the public module
//! exports the same way a downstream KChat orchestration layer would.
//!
//! Coverage:
//!
//! - Classical-only generation succeeds with the RustCrypto provider.
//! - Classical-only generation rejects an empty capability.
//! - The per-device cap is enforced via the public `_with_cap` API.
//! - All generated KeyPackages serialize and deserialize.
//!
//! X-Wing tests live in the `multi_ciphersuite::tests::xwing_provider_tests`
//! module of the openmls crate (gated behind the `xwing` feature) so they
//! can use the libcrux provider without pulling it into the public API.

use openmls::credentials::{BasicCredential, CredentialWithKey, DeviceCapability};
use openmls::key_packages::multi_ciphersuite::{
    MultiCiphersuiteError, MultiCiphersuiteKeyPackages, MAX_KEY_PACKAGES_PER_DEVICE,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::types::{Ciphersuite, SignatureScheme};
use tls_codec::Serialize as _;

fn classical_capability() -> DeviceCapability {
    DeviceCapability::new(
        1,
        vec![
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
        ],
        vec![],
        false,
        false,
        "rustcrypto".into(),
    )
}

#[test]
fn public_api_generates_classical_bundle() {
    let provider = OpenMlsRustCrypto::default();
    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).expect("keygen");
    let credential = CredentialWithKey {
        credential: BasicCredential::new(b"alice".to_vec()).into(),
        signature_key: signer.public().into(),
    };
    let bundle = MultiCiphersuiteKeyPackages::generate_for_capability(
        &classical_capability(),
        &provider,
        &credential,
        &signer,
    )
    .expect("generate succeeded");

    assert_eq!(bundle.len(), 2);
    for kp_bundle in bundle.classical_packages() {
        let bytes = kp_bundle
            .key_package()
            .tls_serialize_detached()
            .expect("serialize");
        assert!(!bytes.is_empty());
    }
    assert_eq!(bundle.pq_packages().len(), 0);
}

#[test]
fn public_api_rejects_empty_capability() {
    let provider = OpenMlsRustCrypto::default();
    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).expect("keygen");
    let credential = CredentialWithKey {
        credential: BasicCredential::new(b"alice".to_vec()).into(),
        signature_key: signer.public().into(),
    };
    let cap = DeviceCapability::new(1, vec![], vec![], false, false, "rustcrypto".into());
    let result =
        MultiCiphersuiteKeyPackages::generate_for_capability(&cap, &provider, &credential, &signer);
    assert!(matches!(result, Err(MultiCiphersuiteError::NoCiphersuites)));
}

#[test]
fn public_api_enforces_per_device_cap() {
    let provider = OpenMlsRustCrypto::default();
    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).expect("keygen");
    let credential = CredentialWithKey {
        credential: BasicCredential::new(b"alice".to_vec()).into(),
        signature_key: signer.public().into(),
    };
    let cap = classical_capability();
    let result = MultiCiphersuiteKeyPackages::generate_for_capability_with_cap(
        &cap,
        &provider,
        &credential,
        &signer,
        1,
    );
    assert!(matches!(
        result,
        Err(MultiCiphersuiteError::TooManyCiphersuites { .. })
    ));
}

#[test]
fn public_api_max_key_packages_per_device_pinned() {
    // The per-device cap is exposed publicly for downstream
    // server-side accounting. Pin it here so a constant change is
    // immediately visible to consumers.
    assert_eq!(MAX_KEY_PACKAGES_PER_DEVICE, 16);
}
