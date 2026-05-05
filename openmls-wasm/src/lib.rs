mod utils;

use js_sys::Uint8Array;
use openmls::{
    ciphersuite::security_mode::SecurityMode as InnerSecurityMode,
    credentials::{BasicCredential, CredentialWithKey, DeviceCapability as InnerDeviceCapability},
    framing::{MlsMessageBodyIn, MlsMessageIn, MlsMessageOut},
    group::{
        select_conversation_mode as inner_select_conversation_mode, ConversationLifecycle, GroupId,
        MlsGroup, MlsGroupJoinConfig, StagedWelcome,
    },
    key_packages::KeyPackage as OpenMlsKeyPackage,
    prelude::SignatureScheme,
    treesync::RatchetTreeIn,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{types::Ciphersuite, OpenMlsProvider};
use tls_codec::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);

    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

/// The ciphersuite used here. Fixed in order to reduce the binary size.
static CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

#[wasm_bindgen]
#[derive(Default)]
pub struct Provider(OpenMlsRustCrypto);

impl AsRef<OpenMlsRustCrypto> for Provider {
    fn as_ref(&self) -> &OpenMlsRustCrypto {
        &self.0
    }
}

impl AsMut<OpenMlsRustCrypto> for Provider {
    fn as_mut(&mut self) -> &mut OpenMlsRustCrypto {
        &mut self.0
    }
}

#[wasm_bindgen]
impl Provider {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }
}

#[wasm_bindgen]
pub fn greet() {
    alert("Hello, openmls!");
}

#[wasm_bindgen]
pub struct Identity {
    credential_with_key: CredentialWithKey,
    keypair: openmls_basic_credential::SignatureKeyPair,
}

#[wasm_bindgen]
impl Identity {
    #[wasm_bindgen(constructor)]
    pub fn new(provider: &Provider, name: &str) -> Result<Identity, JsError> {
        let signature_scheme = SignatureScheme::ED25519;
        let identity = name.bytes().collect();
        let credential = BasicCredential::new(identity);
        let keypair = SignatureKeyPair::new(signature_scheme)?;

        keypair.store(provider.0.storage())?;

        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: keypair.public().into(),
        };

        Ok(Identity {
            credential_with_key,
            keypair,
        })
    }

    pub fn key_package(&self, provider: &Provider) -> KeyPackage {
        KeyPackage(
            OpenMlsKeyPackage::builder()
                .build(
                    CIPHERSUITE,
                    &provider.0,
                    &self.keypair,
                    self.credential_with_key.clone(),
                )
                .unwrap()
                .key_package()
                .clone(),
        )
    }
}

#[wasm_bindgen]
pub struct Group {
    mls_group: MlsGroup,
}

#[wasm_bindgen]
pub struct AddMessages {
    proposal: Uint8Array,
    commit: Uint8Array,
    welcome: Uint8Array,
}

#[cfg(test)]
#[allow(dead_code)]
struct NativeAddMessages {
    proposal: Vec<u8>,
    commit: Vec<u8>,
    welcome: Vec<u8>,
}

#[wasm_bindgen]
impl AddMessages {
    #[wasm_bindgen(getter)]
    pub fn proposal(&self) -> Uint8Array {
        self.proposal.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn commit(&self) -> Uint8Array {
        self.commit.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn welcome(&self) -> Uint8Array {
        self.welcome.clone()
    }
}

#[wasm_bindgen]
impl Group {
    pub fn create_new(provider: &Provider, founder: &Identity, group_id: &str) -> Group {
        let group_id_bytes = group_id.bytes().collect::<Vec<_>>();

        let mls_group = MlsGroup::builder()
            .ciphersuite(CIPHERSUITE)
            .with_group_id(GroupId::from_slice(&group_id_bytes))
            .build(
                &provider.0,
                &founder.keypair,
                founder.credential_with_key.clone(),
            )
            .unwrap();

        Group { mls_group }
    }
    pub fn join(
        provider: &Provider,
        mut welcome: &[u8],
        ratchet_tree: RatchetTree,
    ) -> Result<Group, JsError> {
        let welcome = match MlsMessageIn::tls_deserialize(&mut welcome)?.extract() {
            MlsMessageBodyIn::Welcome(welcome) => Ok(welcome),
            other => Err(openmls::error::ErrorString::from(format!(
                "expected a message of type welcome, got {other:?}",
            ))),
        }?;
        let config = MlsGroupJoinConfig::builder().build();
        let mls_group =
            StagedWelcome::new_from_welcome(&provider.0, &config, welcome, Some(ratchet_tree.0))?
                .into_group(&provider.0)?;

        Ok(Group { mls_group })
    }

    pub fn export_ratchet_tree(&self) -> RatchetTree {
        RatchetTree(self.mls_group.export_ratchet_tree().into())
    }

    pub fn propose_and_commit_add(
        &mut self,
        provider: &Provider,
        sender: &Identity,
        new_member: &KeyPackage,
    ) -> Result<AddMessages, JsError> {
        let (proposal_msg, _proposal_ref) =
            self.mls_group
                .propose_add_member(provider.as_ref(), &sender.keypair, &new_member.0)?;

        let (commit_msg, welcome_msg, _group_info) = self
            .mls_group
            .commit_to_pending_proposals(&provider.0, &sender.keypair)?;

        let welcome_msg = welcome_msg.ok_or(NoWelcomeError)?;

        let proposal = mls_message_to_uint8array(&proposal_msg);
        let commit = mls_message_to_uint8array(&commit_msg);
        let welcome = mls_message_to_uint8array(&welcome_msg);

        Ok(AddMessages {
            proposal,
            commit,
            welcome,
        })
    }

    pub fn merge_pending_commit(&mut self, provider: &mut Provider) -> Result<(), JsError> {
        self.mls_group
            .merge_pending_commit(provider.as_mut())
            .map_err(|e| e.into())
    }

    pub fn create_message(
        &mut self,
        provider: &Provider,
        sender: &Identity,
        msg: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        let msg_out = &self
            .mls_group
            .create_message(provider.as_ref(), &sender.keypair, msg)?;
        let mut serialized = vec![];
        msg_out.tls_serialize(&mut serialized)?;
        Ok(serialized)
    }

    pub fn process_message(
        &mut self,
        provider: &mut Provider,
        mut msg: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        let msg = MlsMessageIn::tls_deserialize(&mut msg).unwrap();

        let msg = match msg.extract() {
            openmls::framing::MlsMessageBodyIn::PublicMessage(msg) => {
                self.mls_group.process_message(provider.as_ref(), msg)?
            }

            openmls::framing::MlsMessageBodyIn::PrivateMessage(msg) => {
                self.mls_group.process_message(provider.as_ref(), msg)?
            }
            openmls::framing::MlsMessageBodyIn::Welcome(_) => todo!(),
            openmls::framing::MlsMessageBodyIn::GroupInfo(_) => todo!(),
            openmls::framing::MlsMessageBodyIn::KeyPackage(_) => todo!(),
        };

        match msg.into_content() {
            openmls::framing::ProcessedMessageContent::ApplicationMessage(app_msg) => {
                Ok(app_msg.into_bytes())
            }
            openmls::framing::ProcessedMessageContent::ProposalMessage(proposal)
            | openmls::framing::ProcessedMessageContent::ExternalJoinProposalMessage(proposal) => {
                self.mls_group
                    .store_pending_proposal(provider.0.storage(), *proposal)?;
                Ok(vec![])
            }
            openmls::framing::ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                self.mls_group
                    .merge_staged_commit(provider.as_mut(), *staged_commit)?;
                Ok(vec![])
            }
        }
    }

    pub fn export_key(
        &self,
        provider: &Provider,
        label: &str,
        context: &[u8],
        key_length: usize,
    ) -> Result<Vec<u8>, JsError> {
        self.mls_group
            .export_secret(provider.as_ref().crypto(), label, context, key_length)
            .map_err(|e| {
                println!("export key error: {e}");
                e.into()
            })
    }
}

#[cfg(test)]
impl Group {
    fn native_propose_and_commit_add(
        &mut self,
        provider: &Provider,
        sender: &Identity,
        new_member: &KeyPackage,
    ) -> Result<NativeAddMessages, JsError> {
        let (proposal_msg, _proposal_ref) =
            self.mls_group
                .propose_add_member(provider.as_ref(), &sender.keypair, &new_member.0)?;

        let (commit_msg, welcome_msg, _group_info) = self
            .mls_group
            .commit_to_pending_proposals(provider.as_ref(), &sender.keypair)?;

        let welcome_msg = welcome_msg.ok_or(NoWelcomeError)?;

        let proposal = mls_message_to_u8vec(&proposal_msg);
        let commit = mls_message_to_u8vec(&commit_msg);
        let welcome = mls_message_to_u8vec(&welcome_msg);

        Ok(NativeAddMessages {
            proposal,
            commit,
            welcome,
        })
    }

    fn native_join(provider: &Provider, mut welcome: &[u8], ratchet_tree: RatchetTree) -> Group {
        let welcome = match MlsMessageIn::tls_deserialize(&mut welcome)
            .unwrap()
            .extract()
        {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            other => panic!("expected a message of type welcome, got {other:?}"),
        };
        let config = MlsGroupJoinConfig::builder().build();
        let mls_group = StagedWelcome::new_from_welcome(
            provider.as_ref(),
            &config,
            welcome,
            Some(ratchet_tree.0),
        )
        .unwrap()
        .into_group(provider.as_ref())
        .unwrap();

        Group { mls_group }
    }
}

#[wasm_bindgen]
#[derive(Debug)]
pub struct NoWelcomeError;

impl std::fmt::Display for NoWelcomeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "no welcome")
    }
}

impl std::error::Error for NoWelcomeError {}

#[wasm_bindgen]
pub struct KeyPackage(OpenMlsKeyPackage);

#[wasm_bindgen]
impl KeyPackage {
    /// Serialize this KeyPackage to bytes
    #[wasm_bindgen]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.tls_serialize_detached().unwrap()
    }

    /// Deserialize a KeyPackage from bytes
    #[wasm_bindgen]
    pub fn from_bytes(bytes: &[u8]) -> Result<KeyPackage, JsError> {
        let mut s = bytes;
        let kp_in = openmls::key_packages::KeyPackageIn::tls_deserialize(&mut s)
            .map_err(|e| JsError::new(&format!("KeyPackage deserialization error: {e}")))?;
        let kp = kp_in
            .validate(
                &openmls_rust_crypto::RustCrypto::default(),
                openmls::prelude::ProtocolVersion::Mls10,
            )
            .map_err(|e| JsError::new(&format!("KeyPackage validation error: {e}")))?;
        Ok(KeyPackage(kp))
    }
}

#[wasm_bindgen]
pub struct RatchetTree(RatchetTreeIn);

#[wasm_bindgen]
impl RatchetTree {
    /// Serialize this RatchetTree to bytes
    #[wasm_bindgen]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.tls_serialize_detached().unwrap()
    }

    /// Deserialize a RatchetTree from bytes
    #[wasm_bindgen]
    pub fn from_bytes(bytes: &[u8]) -> Result<RatchetTree, JsError> {
        let mut s = bytes;
        let tree = RatchetTreeIn::tls_deserialize(&mut s)
            .map_err(|e| JsError::new(&format!("RatchetTree deserialization error: {e}")))?;
        Ok(RatchetTree(tree))
    }
}

fn mls_message_to_uint8array(msg: &MlsMessageOut) -> Uint8Array {
    // see https://github.com/rustwasm/wasm-bindgen/issues/1619#issuecomment-505065294

    let mut serialized = vec![];
    msg.tls_serialize(&mut serialized).unwrap();

    unsafe { Uint8Array::new(&Uint8Array::view(&serialized)) }
}

// =============================================================================
// PQ orchestration bindings (KChat layer)
// =============================================================================
//
// These types mirror the Rust-side `SecurityMode`, `ConversationLifecycle`,
// and `DeviceCapability` so a JS/wasm caller can drive the PQ orchestration
// from the browser. The mapping is intentionally one-way (Rust enums →
// `#[wasm_bindgen]` enums) so we don't have to keep the discriminants in
// sync by hand.

/// Mirror of [`openmls::ciphersuite::security_mode::SecurityMode`].
///
/// Variants are ordered so JS code can compare numerically:
/// `Classical < PqConfidentiality < PqAuthenticity`.
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityMode {
    Classical = 0,
    PqConfidentiality = 1,
    PqAuthenticity = 2,
}

impl From<InnerSecurityMode> for SecurityMode {
    fn from(m: InnerSecurityMode) -> Self {
        match m {
            InnerSecurityMode::Classical => SecurityMode::Classical,
            InnerSecurityMode::PqConfidentiality => SecurityMode::PqConfidentiality,
            InnerSecurityMode::PqAuthenticity => SecurityMode::PqAuthenticity,
        }
    }
}

/// Mirror of [`openmls::group::ConversationLifecycle`], flattened so it can
/// cross the wasm-bindgen boundary as a C-style enum. `Failed` discards
/// the carried reason because `wasm_bindgen` does not support enum
/// variants with payloads — JS callers interested in the reason should
/// fall back to the underlying state machine through a future binding.
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecyclePhase {
    Classical = 0,
    UpgradeEligible = 1,
    UpgradeProposed = 2,
    UpgradeInProgress = 3,
    PqActive = 4,
    ApqBootstrapping = 5,
    ApqActive = 6,
    Failed = 7,
}

impl From<&ConversationLifecycle> for LifecyclePhase {
    fn from(l: &ConversationLifecycle) -> Self {
        match l {
            ConversationLifecycle::Classical => LifecyclePhase::Classical,
            ConversationLifecycle::UpgradeEligible => LifecyclePhase::UpgradeEligible,
            ConversationLifecycle::UpgradeProposed => LifecyclePhase::UpgradeProposed,
            ConversationLifecycle::UpgradeInProgress => LifecyclePhase::UpgradeInProgress,
            ConversationLifecycle::PqActive => LifecyclePhase::PqActive,
            ConversationLifecycle::ApqBootstrapping => LifecyclePhase::ApqBootstrapping,
            ConversationLifecycle::ApqActive => LifecyclePhase::ApqActive,
            ConversationLifecycle::Failed(_) => LifecyclePhase::Failed,
        }
    }
}

/// JS-facing wrapper around [`openmls::credentials::DeviceCapability`].
///
/// Constructors and accessors mirror the Rust struct one-for-one. The
/// inner blob is owned and only handed back to JS as a serialized
/// payload (`tls_encode`) — JS is not expected to manipulate the
/// fields directly.
#[wasm_bindgen]
#[derive(Clone)]
pub struct DeviceCapability {
    inner: InnerDeviceCapability,
}

#[wasm_bindgen]
impl DeviceCapability {
    /// Construct a new, **unsigned** capability. `classical_ciphersuites`
    /// and `pq_ciphersuites` are passed as JS arrays of `u16` codepoints.
    #[wasm_bindgen(constructor)]
    pub fn new(
        mls_version: u16,
        classical_ciphersuites: Vec<u16>,
        pq_ciphersuites: Vec<u16>,
        apq_supported: bool,
        pq_auth_supported: bool,
        provider_id: String,
    ) -> Result<DeviceCapability, JsError> {
        let classical = classical_ciphersuites
            .into_iter()
            .map(|cs| {
                Ciphersuite::try_from(cs).map_err(|e| {
                    JsError::new(&format!("invalid classical ciphersuite codepoint: {e:?}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let pq = pq_ciphersuites
            .into_iter()
            .map(|cs| {
                Ciphersuite::try_from(cs)
                    .map_err(|e| JsError::new(&format!("invalid pq ciphersuite codepoint: {e:?}")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(DeviceCapability {
            inner: InnerDeviceCapability::new(
                mls_version,
                classical,
                pq,
                apq_supported,
                pq_auth_supported,
                provider_id,
            ),
        })
    }

    /// `true` iff the capability has been signed.
    #[wasm_bindgen(js_name = isSigned)]
    pub fn is_signed(&self) -> bool {
        self.inner.is_signed()
    }

    #[wasm_bindgen(getter, js_name = mlsVersion)]
    pub fn mls_version(&self) -> u16 {
        self.inner.mls_version
    }

    #[wasm_bindgen(getter, js_name = providerId)]
    pub fn provider_id(&self) -> String {
        self.inner.provider_id.clone()
    }

    #[wasm_bindgen(getter, js_name = apqSupported)]
    pub fn apq_supported(&self) -> bool {
        self.inner.apq_supported
    }

    #[wasm_bindgen(getter, js_name = pqAuthSupported)]
    pub fn pq_auth_supported(&self) -> bool {
        self.inner.pq_auth_supported
    }

    /// Returns the classical ciphersuite codepoints as a `Vec<u16>`.
    #[wasm_bindgen(getter, js_name = classicalCiphersuites)]
    pub fn classical_ciphersuites(&self) -> Vec<u16> {
        self.inner
            .classical_ciphersuites
            .iter()
            .map(|cs| u16::from(*cs))
            .collect()
    }

    /// Returns the PQ ciphersuite codepoints as a `Vec<u16>`.
    #[wasm_bindgen(getter, js_name = pqCiphersuites)]
    pub fn pq_ciphersuites(&self) -> Vec<u16> {
        self.inner
            .pq_ciphersuites
            .iter()
            .map(|cs| u16::from(*cs))
            .collect()
    }

    /// Sign the capability with `signing_key` under `signature_scheme`
    /// (the `u16` codepoint, e.g. `0x0807` for Ed25519). Updates the
    /// capability in place. The signing key is the raw private key
    /// bytes the device's identity keypair produced.
    pub fn sign(
        &mut self,
        signature_scheme: u16,
        signing_key: &[u8],
        provider: &Provider,
    ) -> Result<(), JsError> {
        let scheme = SignatureScheme::try_from(signature_scheme)
            .map_err(|e| JsError::new(&format!("invalid signature scheme codepoint: {e:?}")))?;
        self.inner
            .sign(scheme, signing_key, provider.0.crypto())
            .map_err(|e| JsError::new(&format!("DeviceCapability::sign failed: {e:?}")))
    }

    /// Verify the capability's signature against `public_key` under
    /// `signature_scheme`. Returns an error if the signature is
    /// missing, malformed, or does not match the recomputed payload.
    pub fn verify(
        &self,
        signature_scheme: u16,
        public_key: &[u8],
        provider: &Provider,
    ) -> Result<(), JsError> {
        let scheme = SignatureScheme::try_from(signature_scheme)
            .map_err(|e| JsError::new(&format!("invalid signature scheme codepoint: {e:?}")))?;
        self.inner
            .verify(scheme, public_key, provider.0.crypto())
            .map_err(|e| JsError::new(&format!("DeviceCapability::verify failed: {e:?}")))
    }

    /// TLS-encode the full capability (including signature) for
    /// transport over the wire. Mirrors the Rust-side `tls_serialize`.
    #[wasm_bindgen(js_name = tlsEncode)]
    pub fn tls_encode(&self) -> Result<Vec<u8>, JsError> {
        let mut buf = Vec::new();
        self.inner
            .tls_serialize(&mut buf)
            .map_err(|e| JsError::new(&format!("tls_serialize: {e:?}")))?;
        Ok(buf)
    }

    /// TLS-decode a capability blob back into a JS-facing
    /// [`DeviceCapability`]. Inverse of [`Self::tls_encode`].
    #[wasm_bindgen(js_name = tlsDecode)]
    pub fn tls_decode(mut bytes: &[u8]) -> Result<DeviceCapability, JsError> {
        let inner = InnerDeviceCapability::tls_deserialize(&mut bytes)
            .map_err(|e| JsError::new(&format!("tls_deserialize: {e:?}")))?;
        Ok(DeviceCapability { inner })
    }
}

/// Result of [`select_conversation_mode`] suitable for crossing the
/// wasm-bindgen boundary. `ciphersuite` is the chosen MLS codepoint.
#[wasm_bindgen]
#[derive(Debug, Clone, Copy)]
pub struct SelectModeResult {
    mode: SecurityMode,
    ciphersuite: u16,
}

#[wasm_bindgen]
impl SelectModeResult {
    #[wasm_bindgen(getter)]
    pub fn mode(&self) -> SecurityMode {
        self.mode
    }
    #[wasm_bindgen(getter)]
    pub fn ciphersuite(&self) -> u16 {
        self.ciphersuite
    }
}

/// Inner non-wasm helper: lifts the empty-list / openmls error cases
/// to a String so the wasm-bindgen wrapper can box them as `JsError`
/// while host-side tests can compare them as plain strings without
/// pulling in JS bindings.
fn select_conversation_mode_inner(
    peer_capabilities: &[DeviceCapability],
) -> Result<SelectModeResult, String> {
    if peer_capabilities.is_empty() {
        return Err("selectConversationMode requires at least one peer capability".to_string());
    }
    let inner_caps: Vec<&InnerDeviceCapability> =
        peer_capabilities.iter().map(|c| &c.inner).collect();
    let (mode, cs) = inner_select_conversation_mode(&inner_caps)
        .map_err(|e| format!("select_conversation_mode: {e:?}"))?;
    Ok(SelectModeResult {
        mode: mode.into(),
        ciphersuite: u16::from(cs),
    })
}

/// Pick the highest [`SecurityMode`] all peers support and the best
/// shared ciphersuite for that mode. Wraps
/// [`openmls::group::select_conversation_mode`].
///
/// `peer_capabilities` is a JS array of `DeviceCapability` clones.
#[wasm_bindgen(js_name = selectConversationMode)]
pub fn select_conversation_mode(
    peer_capabilities: Vec<DeviceCapability>,
) -> Result<SelectModeResult, JsError> {
    select_conversation_mode_inner(&peer_capabilities).map_err(|e| JsError::new(&e))
}

#[cfg(test)]
fn mls_message_to_u8vec(msg: &MlsMessageOut) -> Vec<u8> {
    // see https://github.com/rustwasm/wasm-bindgen/issues/1619#issuecomment-505065294

    let mut serialized = vec![];
    msg.tls_serialize(&mut serialized).unwrap();
    serialized
}

#[cfg(test)]
mod tests {
    use super::*;

    fn js_error_to_string(e: JsError) -> String {
        let v: JsValue = e.into();
        v.as_string().unwrap()
    }

    fn create_group_alice_and_bob() -> (Provider, Identity, Group, Provider, Identity, Group) {
        let mut alice_provider = Provider::new();
        let bob_provider = Provider::new();

        let alice = Identity::new(&alice_provider, "alice")
            .map_err(js_error_to_string)
            .unwrap();
        let bob = Identity::new(&bob_provider, "bob")
            .map_err(js_error_to_string)
            .unwrap();

        let mut chess_club_alice = Group::create_new(&alice_provider, &alice, "chess club");

        let bob_key_pkg = bob.key_package(&bob_provider);

        let add_msgs = chess_club_alice
            .native_propose_and_commit_add(&alice_provider, &alice, &bob_key_pkg)
            .map_err(js_error_to_string)
            .unwrap();

        chess_club_alice
            .merge_pending_commit(&mut alice_provider)
            .map_err(js_error_to_string)
            .unwrap();

        let ratchet_tree = chess_club_alice.export_ratchet_tree();

        let chess_club_bob = Group::native_join(&bob_provider, &add_msgs.welcome, ratchet_tree);

        (
            alice_provider,
            alice,
            chess_club_alice,
            bob_provider,
            bob,
            chess_club_bob,
        )
    }

    #[test]
    fn basic() {
        let (alice_provider, _, chess_club_alice, bob_provider, _, chess_club_bob) =
            create_group_alice_and_bob();

        let bob_exported_key = chess_club_bob
            .export_key(&bob_provider, "chess_key", &[0x30], 32)
            .map_err(js_error_to_string)
            .unwrap();
        let alice_exported_key = chess_club_alice
            .export_key(&alice_provider, "chess_key", &[0x30], 32)
            .map_err(js_error_to_string)
            .unwrap();

        assert_eq!(bob_exported_key, alice_exported_key);
    }

    #[test]
    fn create_message() {
        let (alice_provider, alice, mut chess_club_alice, mut bob_provider, _, mut chess_club_bob) =
            create_group_alice_and_bob();

        let alice_msg = "hello, bob!".as_bytes();
        let msg_out = chess_club_alice
            .create_message(&alice_provider, &alice, alice_msg)
            .map_err(js_error_to_string)
            .unwrap();

        let bob_msg = chess_club_bob
            .process_message(&mut bob_provider, &msg_out)
            .map_err(js_error_to_string)
            .unwrap();

        assert_eq!(alice_msg, bob_msg);
    }

    // -----------------------------------------------------------------
    // PQ orchestration binding tests. These run on the host as
    // ordinary `cargo test` cases so we don't need a wasm-bindgen
    // browser harness in CI; the JS-facing surface is exercised by
    // calling the same methods JS would.
    // -----------------------------------------------------------------

    fn classical_codepoint() -> u16 {
        u16::from(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
    }

    #[test]
    fn pq_security_mode_ordering_matches_inner() {
        // wasm_bindgen-friendly C-enums don't get `PartialOrd` for free,
        // so compare via the `u8` discriminants. JS callers do the same
        // — they get plain numeric values back from the wasm module.
        assert!((SecurityMode::Classical as u8) < (SecurityMode::PqConfidentiality as u8));
        assert!((SecurityMode::PqConfidentiality as u8) < (SecurityMode::PqAuthenticity as u8));
    }

    #[test]
    fn pq_device_capability_round_trips_through_tls() {
        let cap = DeviceCapability::new(
            1,
            vec![classical_codepoint()],
            vec![],
            false,
            false,
            "rustcrypto-wasm".to_string(),
        )
        .expect("DeviceCapability::new must succeed");
        let bytes = cap.tls_encode().expect("tls_encode");
        let round = DeviceCapability::tls_decode(&bytes).expect("tls_decode");
        assert_eq!(round.mls_version(), cap.mls_version());
        assert_eq!(round.classical_ciphersuites(), cap.classical_ciphersuites());
        assert_eq!(round.provider_id(), cap.provider_id());
    }

    #[test]
    fn pq_select_conversation_mode_with_only_classical_peers_returns_classical() {
        let cap = DeviceCapability::new(
            1,
            vec![classical_codepoint()],
            vec![],
            false,
            false,
            "rustcrypto-wasm".to_string(),
        )
        .unwrap();
        let result = select_conversation_mode_inner(&[cap.clone(), cap])
            .expect("select_conversation_mode must succeed for classical-only peers");
        assert_eq!(result.mode(), SecurityMode::Classical);
        assert_eq!(result.ciphersuite(), classical_codepoint());
    }

    #[test]
    fn pq_select_conversation_mode_rejects_empty_peer_list() {
        let result = select_conversation_mode_inner(&[]);
        assert!(result.is_err(), "empty peer list must error out");
    }

    #[test]
    fn pq_lifecycle_phase_classical_for_default_state() {
        // Use the public ConversationLifecycle::Classical projection
        // directly — the from-state-machine projection is exercised in
        // the openmls crate's own tests.
        let phase: LifecyclePhase = (&ConversationLifecycle::Classical).into();
        assert_eq!(phase, LifecyclePhase::Classical);
    }

    #[test]
    fn pq_lifecycle_phase_failed_drops_reason() {
        let phase: LifecyclePhase = (&ConversationLifecycle::Failed("anything".to_string())).into();
        assert_eq!(phase, LifecyclePhase::Failed);
    }
}
