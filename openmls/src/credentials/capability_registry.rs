//! # In-memory `CapabilityRegistry` (server-side scaffold)
//!
//! KChat servers keep a copy of every device's signed
//! [`DeviceCapability`] so peers (and the policy layer) can decide which
//! ciphersuite a conversation should use without trusting the server's
//! word for what each device speaks.
//!
//! This module provides an **in-memory reference implementation** of that
//! registry. It is intentionally minimal: a single `HashMap` keyed by
//! `(user_id, device_id)`. It is meant for tests and as a contract that
//! production server implementations (in the KChat backend) can mirror.
//!
//! Invariants enforced on insertion:
//!
//! - The capability blob must carry a non-empty signature
//!   ([`DeviceCapability::is_signed`]).
//! - The signature must verify against the supplied public key under the
//!   supplied [`SignatureScheme`]. The server cannot *upgrade* a device's
//!   capabilities — only the device, with its identity key, can sign that
//!   it is PQ-capable.
//!
//! See [`PHASES.md`](../../../PHASES.md) Phase 0 (capability advertisement)
//! and the "Server Components" section for the role this registry plays.

use std::collections::HashMap;

use openmls_traits::{crypto::OpenMlsCrypto, types::SignatureScheme};

use super::DeviceCapability;

/// Reasons a [`CapabilityRegistry::store`] call can fail.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    /// The capability had no signature attached
    /// ([`DeviceCapability::is_signed`] returned `false`). The server
    /// must reject unsigned capabilities — accepting one would let a
    /// malicious server forge PQ capability for a non-PQ device.
    #[error("capability blob is unsigned")]
    UnsignedCapability,
    /// The capability's signature failed verification against the
    /// supplied public key under the supplied scheme.
    #[error("capability signature failed verification")]
    InvalidSignature,
}

/// Composite key identifying a device.
type DeviceKey = (Vec<u8>, Vec<u8>);

/// In-memory store of signed [`DeviceCapability`] blobs keyed by
/// `(user_id, device_id)`.
///
/// Only one capability is held per device at any given time — the most
/// recently stored one wins. Callers that need history should layer
/// versioning on top of this struct.
#[derive(Debug, Default)]
pub struct CapabilityRegistry {
    entries: HashMap<DeviceKey, DeviceCapability>,
}

impl CapabilityRegistry {
    /// Construct an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of `(user_id, device_id)` entries currently held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` if the registry holds no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Verify the capability's signature and store it under
    /// `(user_id, device_id)`.
    ///
    /// Replaces any existing entry for the same key.
    pub fn store(
        &mut self,
        user_id: Vec<u8>,
        device_id: Vec<u8>,
        capability: DeviceCapability,
        signature_scheme: SignatureScheme,
        public_key: &[u8],
        crypto: &impl OpenMlsCrypto,
    ) -> Result<(), RegistryError> {
        if !capability.is_signed() {
            return Err(RegistryError::UnsignedCapability);
        }
        capability
            .verify(signature_scheme, public_key, crypto)
            .map_err(|_| RegistryError::InvalidSignature)?;
        self.entries.insert((user_id, device_id), capability);
        Ok(())
    }

    /// Look up the capability for a single `(user_id, device_id)` pair.
    pub fn fetch(&self, user_id: &[u8], device_id: &[u8]) -> Option<&DeviceCapability> {
        self.entries.get(&(user_id.to_vec(), device_id.to_vec()))
    }

    /// Return every capability the registry holds for a given user, in
    /// arbitrary order. Useful for "fan out a Welcome to all of Alice's
    /// devices" call sites.
    pub fn fetch_all_for_user(&self, user_id: &[u8]) -> Vec<&DeviceCapability> {
        self.entries
            .iter()
            .filter_map(|((u, _d), cap)| {
                if u.as_slice() == user_id {
                    Some(cap)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Remove the capability for a single device. Returns `true` if an
    /// entry was removed.
    pub fn remove(&mut self, user_id: &[u8], device_id: &[u8]) -> bool {
        self.entries
            .remove(&(user_id.to_vec(), device_id.to_vec()))
            .is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_rust_crypto::OpenMlsRustCrypto;
    use openmls_traits::types::Ciphersuite;
    use openmls_traits::OpenMlsProvider;

    fn classical_cs() -> Ciphersuite {
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    }

    fn signed_capability(
        crypto: &impl OpenMlsCrypto,
    ) -> (DeviceCapability, SignatureKeyPair, SignatureScheme) {
        let scheme = classical_cs().signature_algorithm();
        let signer = SignatureKeyPair::new(scheme).expect("signer");
        let mut cap = DeviceCapability::new(
            1,
            vec![classical_cs()],
            vec![],
            false,
            false,
            "rustcrypto".into(),
        );
        cap.sign(scheme, signer.private(), crypto).expect("sign");
        (cap, signer, scheme)
    }

    #[test]
    fn store_and_fetch_round_trip() {
        let provider = OpenMlsRustCrypto::default();
        let crypto = provider.crypto();
        let (cap, signer, scheme) = signed_capability(crypto);

        let mut registry = CapabilityRegistry::new();
        registry
            .store(
                b"alice".to_vec(),
                b"phone".to_vec(),
                cap.clone(),
                scheme,
                signer.public(),
                crypto,
            )
            .expect("store");

        assert_eq!(registry.len(), 1);
        let fetched = registry.fetch(b"alice", b"phone").expect("fetched");
        assert_eq!(fetched, &cap);
    }

    #[test]
    fn store_rejects_unsigned_capability() {
        let provider = OpenMlsRustCrypto::default();
        let crypto = provider.crypto();
        let scheme = classical_cs().signature_algorithm();
        let signer = SignatureKeyPair::new(scheme).expect("signer");
        let cap = DeviceCapability::new(
            1,
            vec![classical_cs()],
            vec![],
            false,
            false,
            "rustcrypto".into(),
        );
        assert!(!cap.is_signed());

        let mut registry = CapabilityRegistry::new();
        let err = registry
            .store(
                b"alice".to_vec(),
                b"phone".to_vec(),
                cap,
                scheme,
                signer.public(),
                crypto,
            )
            .expect_err("unsigned must be rejected");
        assert_eq!(err, RegistryError::UnsignedCapability);
        assert!(registry.is_empty());
    }

    #[test]
    fn store_rejects_tampered_signature() {
        let provider = OpenMlsRustCrypto::default();
        let crypto = provider.crypto();
        let (mut cap, signer, scheme) = signed_capability(crypto);

        // Mutate the payload after signing — verification must fail.
        cap.provider_id = "evil-provider".into();

        let mut registry = CapabilityRegistry::new();
        let err = registry
            .store(
                b"alice".to_vec(),
                b"phone".to_vec(),
                cap,
                scheme,
                signer.public(),
                crypto,
            )
            .expect_err("tampered must be rejected");
        assert_eq!(err, RegistryError::InvalidSignature);
        assert!(registry.is_empty());
    }

    #[test]
    fn store_rejects_signature_for_other_key() {
        let provider = OpenMlsRustCrypto::default();
        let crypto = provider.crypto();
        let (cap, _alice_signer, scheme) = signed_capability(crypto);

        // Verify against a *different* signer's public key.
        let bad_signer = SignatureKeyPair::new(scheme).expect("bad signer");

        let mut registry = CapabilityRegistry::new();
        let err = registry
            .store(
                b"alice".to_vec(),
                b"phone".to_vec(),
                cap,
                scheme,
                bad_signer.public(),
                crypto,
            )
            .expect_err("wrong key must be rejected");
        assert_eq!(err, RegistryError::InvalidSignature);
    }

    #[test]
    fn fetch_returns_none_for_missing_device() {
        let registry = CapabilityRegistry::new();
        assert!(registry.fetch(b"alice", b"phone").is_none());
    }

    #[test]
    fn fetch_all_for_user_returns_every_device() {
        let provider = OpenMlsRustCrypto::default();
        let crypto = provider.crypto();
        let (phone_cap, phone_signer, scheme) = signed_capability(crypto);
        let (laptop_cap, laptop_signer, _) = signed_capability(crypto);

        let mut registry = CapabilityRegistry::new();
        registry
            .store(
                b"alice".to_vec(),
                b"phone".to_vec(),
                phone_cap.clone(),
                scheme,
                phone_signer.public(),
                crypto,
            )
            .expect("store phone");
        registry
            .store(
                b"alice".to_vec(),
                b"laptop".to_vec(),
                laptop_cap.clone(),
                scheme,
                laptop_signer.public(),
                crypto,
            )
            .expect("store laptop");

        // Alice has two devices.
        let mut alice_caps = registry.fetch_all_for_user(b"alice");
        alice_caps.sort_by(|a, b| a.provider_id.cmp(&b.provider_id));
        assert_eq!(alice_caps.len(), 2);

        // Bob has none.
        assert!(registry.fetch_all_for_user(b"bob").is_empty());
    }

    #[test]
    fn remove_returns_true_when_entry_existed_and_false_otherwise() {
        let provider = OpenMlsRustCrypto::default();
        let crypto = provider.crypto();
        let (cap, signer, scheme) = signed_capability(crypto);

        let mut registry = CapabilityRegistry::new();
        registry
            .store(
                b"alice".to_vec(),
                b"phone".to_vec(),
                cap,
                scheme,
                signer.public(),
                crypto,
            )
            .expect("store");

        assert!(registry.remove(b"alice", b"phone"));
        assert!(registry.fetch(b"alice", b"phone").is_none());
        // Removing a missing device is a clean no-op.
        assert!(!registry.remove(b"alice", b"phone"));
        assert!(!registry.remove(b"bob", b"unknown"));
    }

    #[test]
    fn store_overwrites_existing_entry_for_same_device() {
        let provider = OpenMlsRustCrypto::default();
        let crypto = provider.crypto();
        let (cap_v1, signer, scheme) = signed_capability(crypto);

        // Build a second, semantically-different capability for the
        // same device — bumped mls_version.
        let mut cap_v2 = DeviceCapability::new(
            2,
            vec![classical_cs()],
            vec![],
            true,
            false,
            "rustcrypto".into(),
        );
        cap_v2
            .sign(scheme, signer.private(), crypto)
            .expect("sign v2");

        let mut registry = CapabilityRegistry::new();
        registry
            .store(
                b"alice".to_vec(),
                b"phone".to_vec(),
                cap_v1,
                scheme,
                signer.public(),
                crypto,
            )
            .expect("store v1");
        registry
            .store(
                b"alice".to_vec(),
                b"phone".to_vec(),
                cap_v2.clone(),
                scheme,
                signer.public(),
                crypto,
            )
            .expect("store v2");

        let fetched = registry.fetch(b"alice", b"phone").expect("present");
        assert_eq!(fetched, &cap_v2);
        assert_eq!(registry.len(), 1);
    }
}
