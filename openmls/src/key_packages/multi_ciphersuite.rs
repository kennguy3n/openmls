//! # Multi-ciphersuite KeyPackage publication
//!
//! Phase 1 of the PQ migration plan asks every PQ-capable device to publish
//! KeyPackages for **every** ciphersuite it speaks — classical and PQ — so
//! that conversations created later can pick the best suite all participants
//! have a fresh KeyPackage for.
//!
//! [`MultiCiphersuiteKeyPackages`] is the per-device bundle: it holds the
//! generated [`KeyPackageBundle`]s indexed by [`Ciphersuite`] and exposes
//! filtered views for classical / PQ ciphersuites.
//!
//! See [`PHASES.md`](../../../PHASES.md) Phase 1 for the storage budget
//! discussion and per-device caps.
//!
//! ## Bounded publication
//!
//! KeyPackage publication is **bounded**: a device may publish at most
//! [`MAX_KEY_PACKAGES_PER_DEVICE`] KeyPackages per
//! [`generate_for_capability`] call. This is a hard floor; the server-side
//! capability registry enforces an additional cap per device per epoch.

use std::collections::HashMap;

use openmls_traits::{signatures::Signer, types::Ciphersuite};

use crate::ciphersuite::SecurityMode;
use crate::credentials::{CredentialWithKey, DeviceCapability};
use crate::key_packages::{
    errors::KeyPackageNewError, KeyPackage, KeyPackageBuilder, KeyPackageBundle,
};
use crate::storage::OpenMlsProvider;

/// Hard upper bound on the number of KeyPackages a single device may
/// generate in one [`generate_for_capability`] call.
///
/// Phase 1 budgets ~2669 bytes per PQ KeyPackage (X-Wing). 16 packages × ~3
/// kB ≈ 48 kB per device per publication, which is the per-device budget the
/// server registry is sized for.
pub const MAX_KEY_PACKAGES_PER_DEVICE: usize = 16;

/// A device's bundle of KeyPackages — one per ciphersuite the device
/// supports — as produced by [`Self::generate_for_capability`].
#[derive(Debug)]
pub struct MultiCiphersuiteKeyPackages {
    packages: HashMap<Ciphersuite, KeyPackageBundle>,
}

/// Errors raised by [`MultiCiphersuiteKeyPackages::generate_for_capability`].
#[derive(Debug, thiserror::Error)]
pub enum MultiCiphersuiteError {
    /// The device's capability advertised more than
    /// [`MAX_KEY_PACKAGES_PER_DEVICE`] ciphersuites.
    #[error(
        "device capability advertises {requested} ciphersuites, exceeding the per-device cap of {cap}"
    )]
    TooManyCiphersuites {
        /// Total advertised ciphersuites (classical + PQ).
        requested: usize,
        /// Hard cap.
        cap: usize,
    },
    /// The device's capability advertised zero ciphersuites.
    #[error("device capability advertises no ciphersuites at all")]
    NoCiphersuites,
    /// Underlying [`KeyPackageBuilder::build`] failed for a particular
    /// ciphersuite.
    #[error("KeyPackage generation failed for ciphersuite {cs:?}: {source}")]
    KeyPackageError {
        /// Ciphersuite whose KeyPackage build failed.
        cs: Ciphersuite,
        /// Underlying error from `KeyPackage::builder().build(...)`.
        #[source]
        source: KeyPackageNewError,
    },
}

impl MultiCiphersuiteKeyPackages {
    /// Generate KeyPackages for every ciphersuite advertised in
    /// `capability`.
    ///
    /// The classical and PQ ciphersuite lists are concatenated and
    /// deduplicated (a suite that appears in both lists is generated once);
    /// the total count must not exceed [`MAX_KEY_PACKAGES_PER_DEVICE`]. If
    /// generation fails for any single ciphersuite the call short-circuits
    /// — partial publication is not exposed (the caller can retry with a
    /// reduced capability list).
    pub fn generate_for_capability(
        capability: &DeviceCapability,
        provider: &impl OpenMlsProvider,
        credential_with_key: &CredentialWithKey,
        signer: &impl Signer,
    ) -> Result<Self, MultiCiphersuiteError> {
        Self::generate_for_capability_with_cap(
            capability,
            provider,
            credential_with_key,
            signer,
            MAX_KEY_PACKAGES_PER_DEVICE,
        )
    }

    /// Same as [`Self::generate_for_capability`] but with a caller-supplied
    /// cap. Internal helper exposed so tests can drive the
    /// [`MultiCiphersuiteError::TooManyCiphersuites`] path with a small cap
    /// (the IANA ciphersuite registry currently has fewer than the
    /// production cap, so we can't synthesize a 17-suite capability).
    pub fn generate_for_capability_with_cap(
        capability: &DeviceCapability,
        provider: &impl OpenMlsProvider,
        credential_with_key: &CredentialWithKey,
        signer: &impl Signer,
        cap: usize,
    ) -> Result<Self, MultiCiphersuiteError> {
        let suites = unique_ciphersuites(capability);

        if suites.is_empty() {
            return Err(MultiCiphersuiteError::NoCiphersuites);
        }
        if suites.len() > cap {
            return Err(MultiCiphersuiteError::TooManyCiphersuites {
                requested: suites.len(),
                cap,
            });
        }

        let mut packages = HashMap::with_capacity(suites.len());
        for cs in suites {
            let bundle = KeyPackageBuilder::new()
                .build(cs, provider, signer, credential_with_key.clone())
                .map_err(|source| MultiCiphersuiteError::KeyPackageError { cs, source })?;
            packages.insert(cs, bundle);
        }

        Ok(Self { packages })
    }

    /// Look up the [`KeyPackageBundle`] for `cs`, if one was generated.
    pub fn get_for_ciphersuite(&self, cs: Ciphersuite) -> Option<&KeyPackageBundle> {
        self.packages.get(&cs)
    }

    /// All ciphersuites in this bundle.
    pub fn all_ciphersuites(&self) -> Vec<Ciphersuite> {
        self.packages.keys().copied().collect()
    }

    /// Borrow the underlying [`KeyPackage`] for `cs`.
    pub fn key_package(&self, cs: Ciphersuite) -> Option<&KeyPackage> {
        self.packages.get(&cs).map(|bundle| bundle.key_package())
    }

    /// Bundles whose ciphersuite is `Classical` per
    /// [`SecurityMode::from_ciphersuite`].
    pub fn classical_packages(&self) -> Vec<&KeyPackageBundle> {
        self.packages
            .iter()
            .filter(|(cs, _)| SecurityMode::from_ciphersuite(**cs) == SecurityMode::Classical)
            .map(|(_, bundle)| bundle)
            .collect()
    }

    /// Bundles whose ciphersuite is non-`Classical` per
    /// [`SecurityMode::from_ciphersuite`].
    pub fn pq_packages(&self) -> Vec<&KeyPackageBundle> {
        self.packages
            .iter()
            .filter(|(cs, _)| SecurityMode::from_ciphersuite(**cs) != SecurityMode::Classical)
            .map(|(_, bundle)| bundle)
            .collect()
    }

    /// Returns the number of stored KeyPackages.
    pub fn len(&self) -> usize {
        self.packages.len()
    }

    /// Returns `true` if no KeyPackages are stored.
    pub fn is_empty(&self) -> bool {
        self.packages.is_empty()
    }
}

fn unique_ciphersuites(capability: &DeviceCapability) -> Vec<Ciphersuite> {
    let mut seen = Vec::new();
    for cs in capability
        .classical_ciphersuites
        .iter()
        .chain(capability.pq_ciphersuites.iter())
    {
        if !seen.contains(cs) {
            seen.push(*cs);
        }
    }
    seen
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::BasicCredential;
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_rust_crypto::OpenMlsRustCrypto;
    use openmls_traits::types::SignatureScheme;

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

    fn empty_capability() -> DeviceCapability {
        DeviceCapability::new(1, vec![], vec![], false, false, "rustcrypto".into())
    }

    /// Build a capability with `n` distinct ciphersuites, drawn from the
    /// IANA registry (and X-Wing). Saturates at the registry size.
    fn capability_with_n_ciphersuites(n: usize) -> DeviceCapability {
        let all = [
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,
            Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
            Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448,
            Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
            Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
        ];
        let take = n.min(all.len());
        let classical = all[..take.saturating_sub(1)].to_vec();
        let pq = if take > 0 {
            vec![all[take - 1]]
        } else {
            vec![]
        };
        DeviceCapability::new(1, classical, pq, true, false, "libcrux".into())
    }

    #[test]
    fn unique_ciphersuites_dedupes_classical_and_pq() {
        let mut cap = classical_capability();
        // Add a duplicate via pq list.
        cap.pq_ciphersuites = vec![Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519];
        let suites = unique_ciphersuites(&cap);
        assert_eq!(suites.len(), 2);
    }

    #[test]
    fn empty_capability_returns_no_ciphersuites_error() {
        let cap = empty_capability();
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519).expect("keygen");
        let credential = CredentialWithKey {
            credential: BasicCredential::new("alice".into()).into(),
            signature_key: signer.public().into(),
        };
        let result = MultiCiphersuiteKeyPackages::generate_for_capability(
            &cap,
            &provider,
            &credential,
            &signer,
        );
        match result {
            Err(MultiCiphersuiteError::NoCiphersuites) => {}
            other => panic!("expected NoCiphersuites, got {other:?}"),
        }
    }

    #[test]
    fn generates_classical_key_packages_with_rust_crypto() {
        let cap = classical_capability();
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519).expect("keygen");
        let credential = CredentialWithKey {
            credential: BasicCredential::new("alice".into()).into(),
            signature_key: signer.public().into(),
        };
        let bundle = MultiCiphersuiteKeyPackages::generate_for_capability(
            &cap,
            &provider,
            &credential,
            &signer,
        )
        .expect("generate succeeded");

        assert_eq!(bundle.len(), 2);
        for cs in &cap.classical_ciphersuites {
            assert!(
                bundle.get_for_ciphersuite(*cs).is_some(),
                "missing key package for {cs:?}"
            );
        }
    }

    #[test]
    fn classical_and_pq_filtered_views() {
        let cap = classical_capability();
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519).expect("keygen");
        let credential = CredentialWithKey {
            credential: BasicCredential::new("alice".into()).into(),
            signature_key: signer.public().into(),
        };
        let bundle = MultiCiphersuiteKeyPackages::generate_for_capability(
            &cap,
            &provider,
            &credential,
            &signer,
        )
        .expect("generate succeeded");

        assert_eq!(bundle.classical_packages().len(), 2);
        assert_eq!(bundle.pq_packages().len(), 0);
    }

    #[test]
    fn rejects_capability_above_per_device_cap() {
        // Drive the bound check via the test-only `_with_cap` variant since
        // the IANA ciphersuite registry doesn't yet hold enough entries to
        // hit the production cap.
        let cap = capability_with_n_ciphersuites(3);
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519).expect("keygen");
        let credential = CredentialWithKey {
            credential: BasicCredential::new("alice".into()).into(),
            signature_key: signer.public().into(),
        };
        let result = MultiCiphersuiteKeyPackages::generate_for_capability_with_cap(
            &cap,
            &provider,
            &credential,
            &signer,
            2, // hard cap below the 3 advertised
        );
        match result {
            Err(MultiCiphersuiteError::TooManyCiphersuites {
                requested,
                cap: cap_value,
            }) => {
                assert_eq!(cap_value, 2);
                assert_eq!(requested, 3);
            }
            other => panic!("expected TooManyCiphersuites, got {other:?}"),
        }
    }

    #[test]
    fn all_ciphersuites_matches_packages_keys() {
        let cap = classical_capability();
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519).expect("keygen");
        let credential = CredentialWithKey {
            credential: BasicCredential::new("alice".into()).into(),
            signature_key: signer.public().into(),
        };
        let bundle = MultiCiphersuiteKeyPackages::generate_for_capability(
            &cap,
            &provider,
            &credential,
            &signer,
        )
        .expect("generate succeeded");

        let mut suites = bundle.all_ciphersuites();
        suites.sort_by_key(|cs| *cs as u16);
        let mut expected = cap.classical_ciphersuites.clone();
        expected.sort_by_key(|cs| *cs as u16);
        assert_eq!(suites, expected);
    }

    #[test]
    fn key_package_accessor_returns_underlying_package() {
        let cap = classical_capability();
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519).expect("keygen");
        let credential = CredentialWithKey {
            credential: BasicCredential::new("alice".into()).into(),
            signature_key: signer.public().into(),
        };
        let bundle = MultiCiphersuiteKeyPackages::generate_for_capability(
            &cap,
            &provider,
            &credential,
            &signer,
        )
        .expect("generate succeeded");
        let cs = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let kp = bundle.key_package(cs).expect("kp present");
        assert_eq!(kp.ciphersuite(), cs);
    }

    /// X-Wing-gated coverage of multi-ciphersuite KeyPackage generation
    /// using the libcrux PQ provider. PHASES.md Phase 1.
    #[cfg(feature = "xwing")]
    mod xwing_provider_tests {
        use super::*;
        use openmls_libcrux_crypto::Provider as LibcruxProvider;

        fn pq_capability() -> DeviceCapability {
            DeviceCapability::new(
                1,
                vec![Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519],
                vec![Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519],
                true,
                false,
                "libcrux".into(),
            )
        }

        #[test]
        fn libcrux_generates_pq_key_packages_for_xwing() {
            let cap = pq_capability();
            let provider = LibcruxProvider::default();
            let signer = SignatureKeyPair::new(SignatureScheme::ED25519).expect("keygen");
            let credential = CredentialWithKey {
                credential: BasicCredential::new("alice".into()).into(),
                signature_key: signer.public().into(),
            };
            let bundle = MultiCiphersuiteKeyPackages::generate_for_capability(
                &cap,
                &provider,
                &credential,
                &signer,
            )
            .expect("generate succeeded");

            // Both classical + PQ KP must be present.
            assert_eq!(bundle.len(), 2);
            assert_eq!(bundle.pq_packages().len(), 1);
            assert_eq!(bundle.classical_packages().len(), 1);
            assert!(bundle
                .key_package(Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519)
                .is_some());
        }

        #[test]
        fn xwing_key_package_is_significantly_larger_than_classical() {
            // ARCHITECTURE.md docs ~2669 bytes for X-Wing KPs vs ~299
            // for classical. We assert the size *ratio* rather than
            // absolute bytes so this stays robust to encoding tweaks.
            let cap = pq_capability();
            let provider = LibcruxProvider::default();
            let signer = SignatureKeyPair::new(SignatureScheme::ED25519).expect("keygen");
            let credential = CredentialWithKey {
                credential: BasicCredential::new("alice".into()).into(),
                signature_key: signer.public().into(),
            };
            let bundle = MultiCiphersuiteKeyPackages::generate_for_capability(
                &cap,
                &provider,
                &credential,
                &signer,
            )
            .expect("generate succeeded");

            use tls_codec::Serialize as _;
            let classical_cs = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
            let xwing_cs = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
            let classical_kp = bundle.key_package(classical_cs).expect("classical KP");
            let xwing_kp = bundle.key_package(xwing_cs).expect("xwing KP");
            let classical_bytes = classical_kp
                .tls_serialize_detached()
                .expect("ser classical");
            let xwing_bytes = xwing_kp.tls_serialize_detached().expect("ser xwing");
            assert!(
                xwing_bytes.len() > classical_bytes.len() * 4,
                "X-Wing KP ({}) is not >>4x classical KP ({})",
                xwing_bytes.len(),
                classical_bytes.len()
            );
        }

        #[test]
        fn libcrux_per_device_cap_enforced_for_mixed_classical_pq() {
            let cap = pq_capability();
            let provider = LibcruxProvider::default();
            let signer = SignatureKeyPair::new(SignatureScheme::ED25519).expect("keygen");
            let credential = CredentialWithKey {
                credential: BasicCredential::new("alice".into()).into(),
                signature_key: signer.public().into(),
            };
            let result = MultiCiphersuiteKeyPackages::generate_for_capability_with_cap(
                &cap,
                &provider,
                &credential,
                &signer,
                1, // below the 2 ciphersuites advertised
            );
            assert!(matches!(
                result,
                Err(MultiCiphersuiteError::TooManyCiphersuites { .. })
            ));
        }

        #[test]
        fn libcrux_pq_key_package_can_be_used_for_group_creation() {
            use crate::group::{MlsGroup, MlsGroupCreateConfig};

            let cap = pq_capability();
            let provider = LibcruxProvider::default();
            let signer = SignatureKeyPair::new(SignatureScheme::ED25519).expect("keygen");
            let credential = CredentialWithKey {
                credential: BasicCredential::new("alice".into()).into(),
                signature_key: signer.public().into(),
            };
            let bundle = MultiCiphersuiteKeyPackages::generate_for_capability(
                &cap,
                &provider,
                &credential,
                &signer,
            )
            .expect("generate succeeded");
            let xwing_cs = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
            let xwing_kp = bundle.key_package(xwing_cs).expect("xwing KP");

            // Verify the KP is internally consistent and usable as a
            // group founder. (We use the credential the KP was built
            // with rather than a fresh one so the signature checks
            // align.)
            let group = MlsGroup::new(
                &provider,
                &signer,
                &MlsGroupCreateConfig::builder()
                    .ciphersuite(xwing_cs)
                    .build(),
                CredentialWithKey {
                    credential: xwing_kp.leaf_node().credential().clone(),
                    signature_key: xwing_kp.leaf_node().signature_key().clone(),
                },
            )
            .expect("PQ group creation");
            assert_eq!(group.ciphersuite(), xwing_cs);
        }
    }
}
