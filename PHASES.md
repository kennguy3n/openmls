# KChat Quantum Resistance Migration Phases

**Current status: Phase 0 — Complete | Phase 1–2 / 3–6 — In progress (~95%)**

This document defines the staged migration plan for taking KChat from
classical MLS to a mixed CLASSICAL / `PQ_CONFIDENTIALITY` / `PQ_AUTHENTICITY`
deployment. Each phase has a clear precondition and a clear definition of
done; later phases assume earlier phases are deployed.

See [`PROPOSAL.md`](./PROPOSAL.md) for the high-level product proposal,
[`ARCHITECTURE.md`](./ARCHITECTURE.md) for the underlying model, and
[`PROGRESS.md`](./PROGRESS.md) for current status.

## Phase 0 — Make Clients Crypto-Agile

Before any PQ traffic can flow, every client must be able to advertise — and
every server component must be able to consume — a structured description of
what each device supports.

- Each upgraded client advertises a `DeviceCapability` containing:
  - `mls_version`
  - `classical_ciphersuites`
  - `pq_ciphersuites`
  - `apq_supported`
  - `pq_auth_supported`
  - `provider_id` (e.g. `libcrux`, `rustcrypto`)
  - `capability_signature` — Ed25519/ML-DSA signature over the rest of the
    capability blob, bound to the device identity key.
- The server stores capabilities verbatim (signed). It MUST NOT be able to
  forge or upgrade a device's PQ capability — only the device, with its
  identity key, can sign that it is PQ-capable.

Definition of done: clients on all platforms publish a signed
`DeviceCapability`, the server validates the signature on ingest, and other
clients can fetch peer capabilities to drive ciphersuite selection.

## Phase 1 — Publish Multiple KeyPackages Per Device

Every PQ-capable device publishes KeyPackages for **all** the ciphersuites it
can speak, classical and PQ:

- Classical KeyPackages for the existing suites.
- PQ KeyPackages for the active draft / final ML-KEM or hybrid ciphersuite,
  optionally with ML-DSA credentials.
- The KeyPackage service indexes by:
  `(user_id, device_id, credential_id, ciphersuite, capability_version, expiry, last_resort)`.
- Storage budget: roughly **~2669 bytes per PQ KeyPackage** (X-Wing
  benchmark). One PQ KeyPackage per device across 100M devices ≈ **267 GB**.
  Publication must therefore be **bounded** (per-device caps, last-resort
  semantics, expiry) and rate-limited at fetch time.

Definition of done: PQ-capable devices can publish and rotate PQ KeyPackages,
and other clients can fetch the right KeyPackage for a target ciphersuite.

**Implementation note (2026-05-04):** the multi-ciphersuite KeyPackage
publication helper has landed at
[`openmls/src/key_packages/multi_ciphersuite.rs`](./openmls/src/key_packages/multi_ciphersuite.rs).
`MultiCiphersuiteKeyPackages::generate_for_capability` walks a
`DeviceCapability`, deduplicates between the classical and PQ lists, and
generates one `KeyPackageBundle` per advertised ciphersuite. Per-device
cap is enforced (`MAX_KEY_PACKAGES_PER_DEVICE = 16`) so a misbehaving
capability cannot blow up storage. Server-side per-suite indexing /
last-resort semantics still belong to the KeyPackage service.

## Phase 2 — Upgrade New Conversations First

The simplest, lowest-risk traffic to upgrade is **new** conversations:

- Conversation creation logic:
  - if **all** invited devices support APQ → create APQ;
  - else if **all** support direct PQ → create direct PQ;
  - else → fall back to classical.
- Telemetry on PQ failures (missing KeyPackage, unsupported suite, provider
  error) must be clean and content-free, and PQ failures must not disrupt
  classical traffic on the same client.

Definition of done: every new conversation among PQ-capable devices is created
in PQ mode by default, and classical traffic is unaffected.

**Implementation note (2026-05-04):** the conversation-creation selector
has landed at
[`openmls/src/group/conversation_upgrade.rs`](./openmls/src/group/conversation_upgrade.rs).
`select_conversation_mode` consumes a slice of `DeviceCapability`
references, picks the highest mode every peer supports via
`SecurityMode::select_mode`, and then picks the best ciphersuite for
that mode via `SecurityMode::select_ciphersuite`. It fails closed when
no common ciphersuite exists rather than silently downgrading. The
actual `KChatMlsConversation` constructor that consumes this output is
follow-up wiring.

## Phase 3 — Upgrade Existing 1:1 and Small Groups

For existing small conversations, MLS `ReInit` (RFC 9420 §11.2) is the
standards-track upgrade path:

1. Propose a `ReInit` with the new (PQ) ciphersuite.
2. Commit the `ReInit`.
3. Create a new group with the same membership using the new ciphersuite.
4. Distribute a `Welcome` carrying a **resumption PSK** with `usage = reinit`
   so the new group is cryptographically bound to the prior group.
5. Mark the old group **read-only** for history; new traffic flows on the new
   group.

Definition of done: existing 1:1 and small groups whose members are all
PQ-capable can be upgraded to PQ via `ReInit` without losing message history.

**Implementation note (2026-05-04):** the ReInit upgrade flow has landed
at
[`openmls/src/group/reinit_upgrade.rs`](./openmls/src/group/reinit_upgrade.rs).
`propose_reinit` builds the proposal and rejects same-suite transitions
and mode downgrades, `commit_reinit` derives the Resumption(ReInit)
PSK via the MLS exporter (`REINIT_PSK_LABEL = "kchat-reinit-psk"`,
32 bytes) **before** sealing the old group via `set_inactive`, and
stores the secret on `ReInitCommit`. `complete_reinit_from_commit`
then consumes the pre-derived secret and registers the
`PreSharedKeyId` for the new group's Welcome. This avoids the prior
`UseAfterEviction` failure where `complete_reinit` tried to call
`export_secret` on an inactive group; see
[`openmls/tests/pq_reinit_e2e_tests.rs`](./openmls/tests/pq_reinit_e2e_tests.rs)
(`commit_reinit_then_complete_reinit_from_commit_succeeds_after_seal`)
for the regression test.

## Phase 4 — Upgrade Larger Groups Using APQ Bootstrap

For groups too large for a clean `ReInit` (or where APQ's per-message cost
profile is preferred), the migration uses an **APQ bootstrap**:

For groups where all active devices are PQ-capable:

1. Fetch a PQ KeyPackage for each member (Phase 1).
2. Create a `PQ_group` with the same membership and the chosen PQ ciphersuite.
3. Add an `APQInfo` extension linking `t_group_id`, `pq_group_id`, the
   synchronized epochs, the chosen ciphersuites, and the mode.
4. Send an `APQWelcome` to each member that lets them join the PQ session.
5. Run the **first FULL commit**: PQ commit first, derive `apq_psk` from the
   PQ session, then commit on the T session including a
   `PreSharedKey(apq_psk_id)` proposal.
6. Mark the conversation security state to the new mode (`APQ_CONF` or
   `APQ_AUTH`) and persist the new state.

Definition of done: larger groups can be upgraded in place without rebuilding
membership, and after the first FULL commit both sessions are in lockstep.

**Implementation note (2026-05-04):** the APQ bootstrap entrypoint
`KChatMlsConversation::bootstrap_apq` has landed in
[`openmls/src/group/kchat_conversation.rs`](./openmls/src/group/kchat_conversation.rs).
It validates preconditions (conversation is not already APQ, has a T
session, advertised PQ ciphersuite is non-classical, membership lists
match), adds the T-group members to the supplied PQ group, derives the
`apq_psk` from the PQ session via the MLS exporter
(`APQ_PSK_LABEL = "kchat-apq-psk"`, 32 bytes), creates the linking
`ApqInfo`, emits an `ApqWelcome` envelope, and updates the conversation
state with the new PQ session and APQ mode/policy. Recovery from a
missed half of a FULL commit pair is handled in
[`openmls/src/group/apq_resync.rs`](./openmls/src/group/apq_resync.rs)
(`detect_desync`, `resync_from_pq`, `resync_from_t`, `force_resync`).

## Phase 5 — Operate with FULL/PARTIAL Policy

Once APQ is running, day-to-day operation is governed by a FULL/PARTIAL commit
policy. FULL commits update both T and PQ sessions; PARTIAL commits update
only the T session.

| Trigger                      | Commit Type                          |
|------------------------------|--------------------------------------|
| Add user/device              | FULL                                 |
| Remove user/device           | FULL                                 |
| External join                | FULL immediately after               |
| Credential rotation          | FULL                                 |
| Security level increase      | FULL                                 |
| Normal message send          | No commit                            |
| Periodic PCS refresh         | PARTIAL or FULL based on risk        |
| High-risk conversation       | More frequent FULL                   |
| Large public group           | Less frequent FULL, but FULL on membership changes |

Add and remove are non-negotiable FULL operations: a removed device must lose
access to the **next** PQ-derived secret, otherwise PQ confidentiality is
broken.

**Implementation note (2026-05-04):** the FULL/PARTIAL policy engine has
landed at
[`openmls/src/group/pq_policy.rs`](./openmls/src/group/pq_policy.rs).
`PqPolicy::required_commit_type(trigger)` is a `const fn` implementing
the table above for every `CommitTrigger`. The `prepare_full_commit` /
`prepare_partial_commit` skeletons in
[`openmls/src/group/apq_commit.rs`](./openmls/src/group/apq_commit.rs)
are wired against `MlsGroup::commit_builder`. `prepare_full_commit`
drives the PQ commit first, derives `apq_psk` via the MLS exporter,
stores the resulting `PreSharedKeyId`, and then drives the T commit
with a PSK proposal. `prepare_partial_commit` drives a T-session-only
commit when policy permits.

**Implementation note (2026-05-04, auto-classification):** the
"external join → FULL" and "credential rotation → FULL" rows in the
table above are now wired end-to-end inside
[`openmls/src/group/apq_commit.rs`](./openmls/src/group/apq_commit.rs).
`detect_external_join` / `detect_credential_rotation` walk a
`StagedCommit`'s proposals; `classify_proposal_types` projects a list
of `ProposalType`s onto the highest-priority `CommitTrigger` using a
strict priority ladder (ExternalInit > Add > Remove > Update >
everything-else), and `auto_classify_commit_type` routes the chosen
trigger through `PqPolicy::required_commit_type`. The conversation
surface picks the new logic up via
`KChatMlsConversation::classify_incoming_commit`, which the
orchestration layer can call when processing an incoming commit to
decide whether the next outgoing commit needs to be FULL or PARTIAL.
The conservative bias of the priority ladder means that any commit
carrying an ExternalInit or membership change collapses to FULL even
when bundled with an Update.

## Phase 6 — Enforce No-Downgrade Rules

Once a conversation has reached `PQ_REQUIRED`, the orchestration layer (and
the server, where it is policy-aware) MUST reject:

- Classical-only KeyPackages for new joiners.
- Commits that remove or replace `APQInfo` without explicit policy
  authorization (e.g. an admin-driven mode change).
- `APQInfo` epoch mismatch between T and PQ sessions.
- Ciphersuite or mode changes after APQ bootstrap (the conversation is pinned
  to its bootstrap suite).
- Fallback to classical due to "missing PQ packages" — the conversation must
  fail closed and surface the error rather than silently downgrade.

Definition of done: a misbehaving server, a downgraded peer, or a malicious
member cannot silently move a `PQ_REQUIRED` conversation back to classical
without the orchestration layer detecting and rejecting the change.

**Implementation note (2026-05-04):** the no-downgrade enforcement layer
has landed at
[`openmls/src/group/no_downgrade.rs`](./openmls/src/group/no_downgrade.rs).
`ConversationSecurityState` plus five validators
(`validate_mode_change`, `validate_joiner_key_package`,
`validate_apq_info_change`, `validate_epoch_consistency`,
`validate_ciphersuite_pin`) cover every rejection rule above.
[`openmls/src/extensions/apq_info.rs`](./openmls/src/extensions/apq_info.rs)
adds the `ApqInfo` link record with its own self-validation, and
[`openmls/tests/pq_downgrade_tests.rs`](./openmls/tests/pq_downgrade_tests.rs)
exercises the rules end-to-end through the public API.

## Server Components

The server side is **policy-aware but cipher-agnostic**: it never sees plaintext
and never sees secret PQ material, but it does need to understand which
ciphersuite/capability each device speaks and how to fan out APQ traffic.

| Component              | Change                                                                                  | Reference impl                                                                |
|------------------------|-----------------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| KeyPackage service     | Store/fetch per ciphersuite and capability version, last-resort fallback                | `openmls/src/key_packages/key_package_service.rs` (`KeyPackageService`)        |
| Capability registry    | Signed per-device PQ capability                                                         | `openmls/src/credentials/capability_registry.rs` (`CapabilityRegistry`)        |
| Delivery service       | APQ wrapper messages, preserve commit ordering                                          | `openmls/src/messages/delivery_service.rs` (`DeliveryService`, `ApqDeliveryEnvelope`) — in-memory reference impl, PQ‑before‑T FULL‑pair ordering enforced |
| Group metadata         | Track conversation security state (not secrets), enforce no-downgrade                   | `openmls/src/group/conversation_metadata.rs` (`ConversationMetadataService`)   |
| Abuse/rate limit       | Rate-limit PQ KeyPackage fetches and Welcome fanout                                     | `openmls/src/key_packages/rate_limiter.rs` (`KeyPackageFetchRateLimiter`)      |
| Telemetry              | Track failures, unsupported suites, rejections, exhaustion (no plaintext)               | `openmls/src/group/pq_telemetry.rs` (`PqTelemetryEvent`, `PqTelemetryEmitter`) |

All six reference implementations are **in-memory**. They define the
API contract a production server is expected to honour and let tests
drive end-to-end flows without standing up a real backend; production
servers must back them with persistent storage and the appropriate
authentication / authorization shim.

**Migration state machine.** Independent of the per-component
reference impls above, every conversation upgrade is tracked by
[`openmls/src/group/migration_state.rs`](./openmls/src/group/migration_state.rs)
(`MigrationStateMachine`). The state machine has eight fine-grained
states (`NotStarted` → `CapabilitiesCollected` → `KeyPackagesPublished` →
`ModeSelected` → `BootstrapInitiated` → `BootstrapComplete` →
`FirstFullCommitDone` → `Operational` | `Failed`); `Failed` is
reachable from any non-terminal state. The accompanying
`ConversationLifecycle` projection collapses these onto eight named
phases (Classical, UpgradeEligible, UpgradeProposed,
UpgradeInProgress, PqActive, ApqBootstrapping, ApqActive, Failed) for
UI / metrics / on-disk persistence. `KChatMlsConversation` exposes an
optional `migration_state: Option<MigrationStateMachine>` field plus a
`lifecycle()` accessor returning the projection.

**Capability protocol.** The wire protocol for client/server
capability exchange lives in
[`openmls/src/credentials/capability_protocol.rs`](./openmls/src/credentials/capability_protocol.rs).
`CapabilityPublishRequest` / `CapabilityPublishResponse`,
`CapabilityFetchRequest` / `CapabilityFetchResponse`, and
`CapabilityUpdateNotification` carry TLS codecs, signature
verification on every accepted capability, and a registry-backed
publish/fetch/notification flow on top of the existing in-memory
`CapabilityRegistry`.

**Delivery service APQ wrapper.** The wire wrapper for paired APQ
messages lives in
[`openmls/src/messages/apq_delivery.rs`](./openmls/src/messages/apq_delivery.rs)
and is mirrored as `delivery-service/ds-lib/src/apq.rs`. `ApqMessage`
pairs a payload with a `SessionSide` marker, `ApqCommitPair` bundles
a PQ commit + T commit + a declared `ApqDeliveryOrder`, and
`validate_order` rejects misordered FULL commit pairs.

**Load testing.** Phase 1 (KeyPackage storage) and Phase 4 (Welcome
fanout) ship `#[ignore]`d high-scale tests in
[`openmls/tests/pq_load_tests.rs`](./openmls/tests/pq_load_tests.rs)
(10K KPs across 1000 devices, rate-limiter burst, last-resort
fallback) and
[`openmls/tests/pq_welcome_fanout_tests.rs`](./openmls/tests/pq_welcome_fanout_tests.rs)
(100 / 500 / 1000-member fanout pinning the ~2669-byte / PQ
KeyPackage budget). Run them with `cargo test -- --ignored`.

**Draft codepoint migration.** Until IANA assigns final codepoints
the migration plumbing in
[`openmls/src/ciphersuite/codepoint_migration.rs`](./openmls/src/ciphersuite/codepoint_migration.rs)
holds three empty static `&[Row]` tables (ciphersuite / KEM /
signature scheme). `migrate_ciphersuite` / `migrate_kem_type` /
`migrate_signature_scheme` return `None` while a draft codepoint is
still draft, `needs_migration` lights up for every draft suite, and
`migrate_conversation_state` rotates
`ConversationSecurityState::pinned_ciphersuite` once a final value is
on file. Adding a real assignment is therefore a one-row table change
and immediately fires across every persisted conversation on the next
boot.

**Idempotent client storage migration.** The Phase 0–6 storage
contract enumerated under "Storage Requirements" in
[`ARCHITECTURE.md`](./ARCHITECTURE.md) is driven by
[`openmls/src/group/storage_migration.rs`](./openmls/src/group/storage_migration.rs).
`MigrationStep` is the ordered list (group state → APQ info →
conversation mapping → PSK material → commit counters →
anti-downgrade state); `StorageMigrationState` is the persisted
progress marker; `StorageMigrator::run_migration` runs each step
check-before-write, persists progress between steps, and resumes
cleanly from the marker on the next start. Concrete backends
(SQLite, Sled, etc.) plug in via the `MigrationStorage` trait. The
canonical SQLite implementation lives in
[`sqlite_storage/src/migration.rs`](./sqlite_storage/src/migration.rs);
each step idempotently creates the underlying table (`apq_info`,
`conversation_mapping`, `psk_material`, `commit_counters`,
`anti_downgrade_state`), `read_state` / `persist_state` round-trip
through a `migration_state` row, and the `*_present` validators back
`validate_post_migration`. This is the canonical implementation of
the "storage migration must be idempotent so that a client can be
upgraded, crash mid-migration, and re-run the migration safely on
next start" requirement and is a prerequisite for the PQ-version
storage gate below.

**Reference DS APQ message routing.** The reference Delivery Service
in [`delivery-service/ds/src/main.rs`](./delivery-service/ds/src/main.rs)
exposes three actix-web endpoints: `POST /apq/publish` (single
`ApqMessage`), `POST /apq/publish-pair` (FULL-commit pair), and
`GET /apq/recv/{id}` (drains the per-client queue). Wire types are
re-exported from
[`delivery-service/ds-lib/src/apq.rs`](./delivery-service/ds-lib/src/apq.rs).
The endpoints validate that each recipient is a registered client
before enqueueing and the `/reset` admin endpoint clears the APQ
queue alongside the client and group maps.

**MLDSA44 / MLDSA65 / MLDSA87.** The libcrux provider implements all
three FIPS 204 parameter sets on top of `libcrux-ml-dsa`, gated
behind the independent `mldsa44` / `mldsa` (ML-DSA-65) / `mldsa87`
feature flags (passthrough from the `openmls` crate). When a feature
is disabled, the provider returns `UnsupportedSignatureScheme` for
the corresponding scheme. Provider behaviour is locked in by
feature-gated tests in `libcrux_crypto/src/crypto.rs` (signing key
/ verification key / signature byte-length pinning + tampered
message rejection), and KAT vectors in
`openmls/tests/pq_kat_vectors/` cover all three parameter sets.

## Rollout Gates

Each gate must be cleared before the next phase rolls to general availability.
These are deployment gates, not engineering gates — code may exist behind a
feature flag earlier.

| Gate                | Required Before Advancing                                                            |
|---------------------|--------------------------------------------------------------------------------------|
| Client support      | PQ-capable clients on all major platforms                                            |
| Provider support    | libcrux/final PQ provider on mobile, desktop, WASM                                   |
| Interop             | Classical/PQ/APQ test vectors pass                                                   |
| Downgrade safety    | Clients reject unauthorized fallback                                                 |
| Load                | KeyPackage storage and Welcome fanout tested at scale                                |
| Recovery            | Clients can resync after missed PQ/T commit pair                                     |
| Security review     | External review of APQ orchestration and provider integration                        |
