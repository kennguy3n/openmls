//! # Server-side capability exchange wire protocol
//!
//! KChat clients publish their signed [`DeviceCapability`] blobs to the
//! server, fetch other devices' capabilities, and subscribe to capability
//! changes for groups they care about. The
//! [`CapabilityRegistry`] provides the
//! in-memory storage for the **server side** of that exchange; this
//! module defines the **wire format** that sits in front of it.
//!
//! Five message types are defined here:
//!
//! - [`CapabilityPublishRequest`] — client → server. Carries one signed
//!   `DeviceCapability` plus enough metadata for the server to verify
//!   the signature (`signature_scheme`, `public_key`).
//! - [`CapabilityPublishResponse`] — server → client. Acknowledges a
//!   publish and returns the registry's monotonically-increasing
//!   version number for that `(user_id, device_id)` tuple.
//! - [`CapabilityFetchRequest`] — client → server. A list of
//!   `(user_id, device_id)` tuples to look up.
//! - [`CapabilityFetchResponse`] — server → client. Returns a
//!   [`FetchedCapability`] entry per requested tuple (with
//!   `capability == None` when the device is unknown).
//! - [`CapabilityUpdateNotification`] — server → client (push). The
//!   server signals that a particular `(user_id, device_id)` tuple's
//!   capability has changed; clients holding cached copies can re-fetch
//!   and re-validate.
//!
//! All five types implement
//! [`tls_codec::Serialize`] / [`tls_codec::Deserialize`] so they can be
//! shipped over an existing KChat WebSocket / RPC channel without
//! introducing a new on-the-wire framing format.
//!
//! ## Validation rules
//!
//! - The server **MUST** verify the signature on a publish before
//!   accepting it (see [`process_publish`]). It cannot upgrade or
//!   downgrade a device's capabilities — only the device, with its
//!   identity key, can. This mirrors the contract the in-memory
//!   [`CapabilityRegistry`] enforces.
//! - The server **MUST NOT** forge `CapabilityFetchResponse` entries —
//!   it returns the signed blob the device originally published, so
//!   the client can re-verify the signature itself.
//! - The notification payload is **not signed**. It is purely a hint
//!   to clients that they should re-fetch; the authoritative
//!   capability blob still comes from the next
//!   `CapabilityFetchResponse` and must be signature-verified there.
//!
//! See [`PHASES.md`](../../../PHASES.md) Phase 0 (capability
//! advertisement) and [`ARCHITECTURE.md`](../../../ARCHITECTURE.md)
//! "Server Components" for how this protocol layer fits into the
//! larger KChat orchestration plan.

use openmls_traits::{crypto::OpenMlsCrypto, types::SignatureScheme};
use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize, VLBytes};

use super::{CapabilityRegistry, DeviceCapability, RegistryError};

/// Monotonically-increasing version stamp returned by the server on
/// every accepted publish.
///
/// Servers MUST increment this for every accepted publish for a given
/// `(user_id, device_id)` tuple, even if the capability blob itself is
/// byte-for-byte identical. Clients can use it to detect "did the
/// server actually accept my publish?" without round-tripping the
/// whole blob.
pub type CapabilityVersion = u64;

/// Client → server: publish a signed [`DeviceCapability`].
///
/// `user_id` and `device_id` are opaque byte strings agreed on out of
/// band (typically the KChat user UUID + device ID). `public_key` is
/// the device's identity key, encoded in whatever format
/// [`OpenMlsCrypto::verify_signature`] expects for the supplied
/// `signature_scheme`.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct CapabilityPublishRequest {
    /// Opaque user identifier; mirrors the `user_id` key in
    /// [`CapabilityRegistry`].
    pub user_id: VLBytes,
    /// Opaque device identifier; mirrors the `device_id` key in
    /// [`CapabilityRegistry`].
    pub device_id: VLBytes,
    /// The signature scheme the device's identity key uses; needed by
    /// the server to dispatch [`OpenMlsCrypto::verify_signature`].
    pub signature_scheme: SignatureScheme,
    /// The device's identity public key, in the wire format expected
    /// by [`OpenMlsCrypto::verify_signature`] for `signature_scheme`.
    pub public_key: VLBytes,
    /// The signed [`DeviceCapability`] blob the device wants to publish.
    pub capability: DeviceCapability,
}

/// Server → client: acknowledgement for an accepted
/// [`CapabilityPublishRequest`].
///
/// The server returns the new version stamp; clients that publish
/// optimistically can match this against their pending state. The
/// server SHOULD reject an out-of-date publish (lower version stamp)
/// rather than silently accept it.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct CapabilityPublishResponse {
    /// Echo of the published `(user_id, device_id)` tuple so a single
    /// pipelined RPC channel doesn't have to track outstanding
    /// requests by-correlation-id.
    pub user_id: VLBytes,
    /// See [`CapabilityPublishRequest::device_id`].
    pub device_id: VLBytes,
    /// Monotonically-increasing version stamp; see [`CapabilityVersion`].
    pub version: CapabilityVersion,
}

/// One `(user_id, device_id)` tuple requested in a
/// [`CapabilityFetchRequest`].
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct CapabilityFetchKey {
    /// See [`CapabilityPublishRequest::user_id`].
    pub user_id: VLBytes,
    /// See [`CapabilityPublishRequest::device_id`].
    pub device_id: VLBytes,
}

/// Client → server: fetch capabilities for a batch of devices.
///
/// Batching is encouraged (one request per group, not one per peer) so
/// the server can dedupe lookups and the client doesn't pay
/// `O(num_peers)` round-trip latency.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct CapabilityFetchRequest {
    /// One entry per `(user_id, device_id)` tuple the client wants to
    /// learn about.
    pub keys: Vec<CapabilityFetchKey>,
}

/// One result entry in a [`CapabilityFetchResponse`].
///
/// `capability` is `None` when the server has no record of the
/// requested device. `Some(_)` carries the device's most recent signed
/// capability blob, which the client MUST re-verify on receipt — the
/// server is not trusted to forge or mutate signatures.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct FetchedCapability {
    /// See [`CapabilityFetchKey::user_id`].
    pub user_id: VLBytes,
    /// See [`CapabilityFetchKey::device_id`].
    pub device_id: VLBytes,
    /// The latest signed capability blob, or `None` if the server has
    /// no record. Encoded as a TLS optional (`u8` discriminant).
    pub capability: Option<DeviceCapability>,
    /// The version stamp matching `capability`, or `0` when
    /// `capability == None`. Allows clients to dedupe push
    /// notifications against pull responses.
    pub version: CapabilityVersion,
}

/// Server → client: results of a [`CapabilityFetchRequest`].
///
/// Order is **not** guaranteed to match the request — callers should
/// match by `(user_id, device_id)` rather than positional index.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct CapabilityFetchResponse {
    /// One entry per device the server has a result for; missing
    /// devices appear with `capability == None`.
    pub entries: Vec<FetchedCapability>,
}

/// Server → client (push): a single device's capability has changed.
///
/// This message is **not authenticated**; it is purely a hint to
/// clients that they should re-fetch the affected `(user_id,
/// device_id)` tuple. Clients MUST NOT trust the new `version` until
/// they fetch the actual signed capability blob and verify the
/// signature themselves.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct CapabilityUpdateNotification {
    /// See [`CapabilityFetchKey::user_id`].
    pub user_id: VLBytes,
    /// See [`CapabilityFetchKey::device_id`].
    pub device_id: VLBytes,
    /// The new version stamp, matching the next
    /// [`CapabilityFetchResponse`] for this tuple.
    pub version: CapabilityVersion,
}

/// Reasons a [`process_publish`] call can fail.
///
/// Wraps the registry's [`RegistryError`] with the protocol-layer
/// errors that can only happen at the wire boundary.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProtocolError {
    /// The publish failed registry-side validation (unsigned blob,
    /// signature mismatch, etc.). See [`RegistryError`].
    #[error(transparent)]
    Registry(#[from] RegistryError),
}

/// Apply a [`CapabilityPublishRequest`] to a [`CapabilityRegistry`].
///
/// Returns the [`CapabilityPublishResponse`] the server should send
/// back. `next_version` is supplied by the caller (typically a counter
/// in the server's persistent state) so the registry doesn't have to
/// own version assignment.
///
/// Validation:
///
/// - Verifies the capability's signature via the registry's `store`
///   call ([`CapabilityRegistry::store`]).
/// - On signature failure, returns [`ProtocolError::Registry`] with
///   [`RegistryError::InvalidSignature`].
/// - On unsigned blob, returns [`RegistryError::UnsignedCapability`].
pub fn process_publish(
    registry: &mut CapabilityRegistry,
    request: CapabilityPublishRequest,
    next_version: CapabilityVersion,
    crypto: &impl OpenMlsCrypto,
) -> Result<CapabilityPublishResponse, ProtocolError> {
    let CapabilityPublishRequest {
        user_id,
        device_id,
        signature_scheme,
        public_key,
        capability,
    } = request;

    let user_id_bytes: Vec<u8> = user_id.as_slice().to_vec();
    let device_id_bytes: Vec<u8> = device_id.as_slice().to_vec();

    registry.store(
        user_id_bytes.clone(),
        device_id_bytes.clone(),
        capability,
        signature_scheme,
        public_key.as_slice(),
        crypto,
    )?;

    Ok(CapabilityPublishResponse {
        user_id: VLBytes::from(user_id_bytes),
        device_id: VLBytes::from(device_id_bytes),
        version: next_version,
    })
}

/// Build a [`CapabilityFetchResponse`] for a [`CapabilityFetchRequest`].
///
/// The server walks every requested `(user_id, device_id)` tuple,
/// looks it up in the registry, and bundles the result. Missing
/// devices come back with `capability == None` and `version == 0`.
///
/// `version_for` is a closure (or function pointer) the server passes
/// in to look up the current version stamp for a given tuple. It is
/// kept as a callback so the registry doesn't have to grow versioning
/// state.
pub fn process_fetch(
    registry: &CapabilityRegistry,
    request: &CapabilityFetchRequest,
    mut version_for: impl FnMut(&[u8], &[u8]) -> CapabilityVersion,
) -> CapabilityFetchResponse {
    let entries = request
        .keys
        .iter()
        .map(|key| {
            let user_id = key.user_id.as_slice();
            let device_id = key.device_id.as_slice();
            match registry.fetch(user_id, device_id) {
                Some(cap) => FetchedCapability {
                    user_id: key.user_id.clone(),
                    device_id: key.device_id.clone(),
                    capability: Some(cap.clone()),
                    version: version_for(user_id, device_id),
                },
                None => FetchedCapability {
                    user_id: key.user_id.clone(),
                    device_id: key.device_id.clone(),
                    capability: None,
                    version: 0,
                },
            }
        })
        .collect();

    CapabilityFetchResponse { entries }
}

/// Construct a [`CapabilityUpdateNotification`] the server can fan out
/// after an accepted publish.
///
/// Provided as a helper rather than wired into [`process_publish`] so
/// the server is in full control of which clients to notify (e.g.
/// only fan out to clients in groups that contain `device_id`).
pub fn build_update_notification(
    user_id: impl Into<VLBytes>,
    device_id: impl Into<VLBytes>,
    version: CapabilityVersion,
) -> CapabilityUpdateNotification {
    CapabilityUpdateNotification {
        user_id: user_id.into(),
        device_id: device_id.into(),
        version,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_rust_crypto::OpenMlsRustCrypto;
    use openmls_traits::types::Ciphersuite;
    use openmls_traits::OpenMlsProvider;
    use tls_codec::{Deserialize as _, Serialize as _};

    fn classical_cs() -> Ciphersuite {
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    }

    fn signed_capability(provider: &OpenMlsRustCrypto) -> (DeviceCapability, SignatureKeyPair) {
        let cs = classical_cs();
        let scheme = cs.signature_algorithm();
        let keypair = SignatureKeyPair::new(scheme).expect("keypair generation");
        let mut cap =
            DeviceCapability::new(1, vec![cs], vec![], false, false, "rustcrypto".to_string());
        cap.sign(scheme, keypair.private(), provider.crypto())
            .expect("sign capability");
        (cap, keypair)
    }

    fn publish_request(
        user_id: &[u8],
        device_id: &[u8],
        cap: DeviceCapability,
        keypair: &SignatureKeyPair,
    ) -> CapabilityPublishRequest {
        CapabilityPublishRequest {
            user_id: user_id.to_vec().into(),
            device_id: device_id.to_vec().into(),
            signature_scheme: classical_cs().signature_algorithm(),
            public_key: keypair.public().to_vec().into(),
            capability: cap,
        }
    }

    #[test]
    fn publish_request_round_trips_through_tls_codec() {
        let provider = OpenMlsRustCrypto::default();
        let (cap, keypair) = signed_capability(&provider);
        let req = publish_request(b"alice", b"phone", cap, &keypair);

        let encoded = req.tls_serialize_detached().expect("serialize");
        let decoded =
            CapabilityPublishRequest::tls_deserialize_exact(&encoded).expect("deserialize");
        assert_eq!(req, decoded);
    }

    #[test]
    fn fetch_response_round_trips_through_tls_codec() {
        let provider = OpenMlsRustCrypto::default();
        let (cap, _) = signed_capability(&provider);
        let response = CapabilityFetchResponse {
            entries: vec![
                FetchedCapability {
                    user_id: b"alice".to_vec().into(),
                    device_id: b"phone".to_vec().into(),
                    capability: Some(cap),
                    version: 7,
                },
                FetchedCapability {
                    user_id: b"bob".to_vec().into(),
                    device_id: b"phone".to_vec().into(),
                    capability: None,
                    version: 0,
                },
            ],
        };

        let encoded = response.tls_serialize_detached().expect("serialize");
        let decoded =
            CapabilityFetchResponse::tls_deserialize_exact(&encoded).expect("deserialize");
        assert_eq!(response, decoded);
    }

    #[test]
    fn process_publish_accepts_signed_capability() {
        let provider = OpenMlsRustCrypto::default();
        let (cap, keypair) = signed_capability(&provider);
        let req = publish_request(b"alice", b"phone", cap, &keypair);

        let mut registry = CapabilityRegistry::new();
        let response = process_publish(&mut registry, req, 1, provider.crypto())
            .expect("publish must succeed for a valid signed capability");

        assert_eq!(response.user_id.as_slice(), b"alice");
        assert_eq!(response.device_id.as_slice(), b"phone");
        assert_eq!(response.version, 1);
        assert_eq!(registry.len(), 1);
        assert!(registry.fetch(b"alice", b"phone").is_some());
    }

    #[test]
    fn process_publish_rejects_unsigned_capability() {
        let provider = OpenMlsRustCrypto::default();
        let cs = classical_cs();
        let keypair = SignatureKeyPair::new(cs.signature_algorithm()).expect("keypair generation");
        // Build the capability but skip `.sign(...)`.
        let cap =
            DeviceCapability::new(1, vec![cs], vec![], false, false, "rustcrypto".to_string());
        let req = publish_request(b"alice", b"phone", cap, &keypair);

        let mut registry = CapabilityRegistry::new();
        let err = process_publish(&mut registry, req, 1, provider.crypto())
            .expect_err("unsigned blob must be rejected");
        assert_eq!(
            err,
            ProtocolError::Registry(RegistryError::UnsignedCapability)
        );
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn process_publish_rejects_signature_mismatch() {
        let provider = OpenMlsRustCrypto::default();
        let (cap, _real_keypair) = signed_capability(&provider);

        // Use a *different* keypair's public key in the publish request,
        // so verify will fail.
        let cs = classical_cs();
        let other = SignatureKeyPair::new(cs.signature_algorithm()).expect("keypair");
        let req = CapabilityPublishRequest {
            user_id: b"alice".to_vec().into(),
            device_id: b"phone".to_vec().into(),
            signature_scheme: cs.signature_algorithm(),
            public_key: other.public().to_vec().into(),
            capability: cap,
        };

        let mut registry = CapabilityRegistry::new();
        let err = process_publish(&mut registry, req, 1, provider.crypto())
            .expect_err("signature mismatch must be rejected");
        assert_eq!(
            err,
            ProtocolError::Registry(RegistryError::InvalidSignature)
        );
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn process_fetch_returns_none_for_unknown_devices() {
        let provider = OpenMlsRustCrypto::default();
        let (cap, keypair) = signed_capability(&provider);
        let mut registry = CapabilityRegistry::new();
        process_publish(
            &mut registry,
            publish_request(b"alice", b"phone", cap, &keypair),
            1,
            provider.crypto(),
        )
        .expect("publish");

        let request = CapabilityFetchRequest {
            keys: vec![
                CapabilityFetchKey {
                    user_id: b"alice".to_vec().into(),
                    device_id: b"phone".to_vec().into(),
                },
                CapabilityFetchKey {
                    user_id: b"bob".to_vec().into(),
                    device_id: b"phone".to_vec().into(),
                },
            ],
        };

        let response = process_fetch(&registry, &request, |_user, _device| 1);
        assert_eq!(response.entries.len(), 2);

        let alice = response
            .entries
            .iter()
            .find(|e| e.user_id.as_slice() == b"alice")
            .expect("alice should be present");
        assert!(alice.capability.is_some());
        assert_eq!(alice.version, 1);

        let bob = response
            .entries
            .iter()
            .find(|e| e.user_id.as_slice() == b"bob")
            .expect("bob should be present");
        assert!(bob.capability.is_none());
        assert_eq!(bob.version, 0);
    }

    #[test]
    fn fetched_capability_signature_re_verifies_after_round_trip() {
        // Models the client side: server forwards a previously-stored
        // capability blob, client re-verifies the signature itself rather
        // than trusting the server.
        let provider = OpenMlsRustCrypto::default();
        let (cap, keypair) = signed_capability(&provider);
        let mut registry = CapabilityRegistry::new();
        process_publish(
            &mut registry,
            publish_request(b"alice", b"phone", cap.clone(), &keypair),
            1,
            provider.crypto(),
        )
        .expect("publish");

        let request = CapabilityFetchRequest {
            keys: vec![CapabilityFetchKey {
                user_id: b"alice".to_vec().into(),
                device_id: b"phone".to_vec().into(),
            }],
        };
        let response = process_fetch(&registry, &request, |_, _| 1);

        let alice = response
            .entries
            .iter()
            .find(|e| e.user_id.as_slice() == b"alice")
            .expect("alice should be present");
        let returned = alice
            .capability
            .as_ref()
            .expect("alice capability should be present");

        // Round-trip through the wire format and re-verify on the
        // far side.
        let bytes = returned.tls_serialize_detached().expect("serialize");
        let recovered = DeviceCapability::tls_deserialize_exact(&bytes).expect("deserialize");
        recovered
            .verify(
                classical_cs().signature_algorithm(),
                keypair.public(),
                provider.crypto(),
            )
            .expect("server-forwarded capability must still verify on the client");
    }

    #[test]
    fn build_update_notification_round_trips() {
        let n = build_update_notification(b"alice".to_vec(), b"phone".to_vec(), 42);
        assert_eq!(n.user_id.as_slice(), b"alice");
        assert_eq!(n.device_id.as_slice(), b"phone");
        assert_eq!(n.version, 42);

        let bytes = n.tls_serialize_detached().expect("serialize");
        let decoded =
            CapabilityUpdateNotification::tls_deserialize_exact(&bytes).expect("deserialize");
        assert_eq!(n, decoded);
    }

    #[test]
    fn end_to_end_publish_then_fetch_then_notify() {
        let provider = OpenMlsRustCrypto::default();
        let (cap, keypair) = signed_capability(&provider);
        let mut registry = CapabilityRegistry::new();

        // Publish.
        let publish = publish_request(b"alice", b"phone", cap, &keypair);
        let publish_response =
            process_publish(&mut registry, publish, 7, provider.crypto()).expect("publish");
        assert_eq!(publish_response.version, 7);

        // Fetch.
        let request = CapabilityFetchRequest {
            keys: vec![CapabilityFetchKey {
                user_id: b"alice".to_vec().into(),
                device_id: b"phone".to_vec().into(),
            }],
        };
        let fetch_response = process_fetch(&registry, &request, |_, _| 7);
        assert_eq!(fetch_response.entries.len(), 1);
        let fetched = fetch_response.entries[0]
            .capability
            .as_ref()
            .expect("must be present after publish");
        // Client-side verify mirrors what every real client does on
        // receipt.
        fetched
            .verify(
                classical_cs().signature_algorithm(),
                keypair.public(),
                provider.crypto(),
            )
            .expect("verify");

        // Build push notification.
        let notification = build_update_notification(
            publish_response.user_id.as_slice().to_vec(),
            publish_response.device_id.as_slice().to_vec(),
            publish_response.version,
        );
        assert_eq!(notification.version, 7);
    }
}
