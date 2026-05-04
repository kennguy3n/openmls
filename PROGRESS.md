# KChat Quantum Resistance — Progress Tracker

This document tracks the concrete state of this repository against the
[`PROPOSAL.md`](./PROPOSAL.md) goals, the [`ARCHITECTURE.md`](./ARCHITECTURE.md)
target, and the [`PHASES.md`](./PHASES.md) migration plan.

**Status: Phase 0 — Complete | Phase 1–2 / 3–6 — In progress | ~80%**

## Version Targets

### KChat PQ v1 (current target)

- OpenMLS base.
- libcrux-backed PQ provider.
- Classical groups remain supported.
- New clients publish classical + PQ KeyPackages.
- Direct hybrid/PQ MLS for new 1:1 and small groups.
- APQ orchestration for larger groups.
- `PQ_CONFIDENTIALITY` default for new conversations among PQ-capable
  devices.
- No silent downgrade.

### KChat PQ v2

- Final IETF MLS PQ ciphersuite codepoints.
- APQ aligned with the final RFC.
- ML-DSA mode for high-assurance groups.
- Forced retirement policy for legacy-only devices.

### KChat PQ v3

- `PQ_REQUIRED` by default for all eligible conversations.
- Legacy classical groups read-only or sunset.
- Final codepoint migration complete.

## Current Repository State

### Completed

- [x] OpenMLS RFC 9420 base implementation (fork of upstream).
- [x] Pluggable crypto provider architecture (`traits/src/types.rs`).
- [x] X-Wing KEM type defined: `XWingKemDraft6 = 0x004D`
      (`traits/src/types.rs` line 186).
- [x] X-Wing ciphersuite defined:
      `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 = 0x004D`
      (`traits/src/types.rs` line 401).
- [x] libcrux provider maps X-Wing to `XWingDraft06`
      (`libcrux_crypto/src/crypto.rs`, gated behind the `xwing` feature).
- [x] libcrux provider lists X-Wing in `supported_ciphersuites()`
      when the `xwing` feature is enabled
      (`libcrux_crypto/src/crypto.rs`).

### In Progress / Not Started

#### Immediate fixes (OpenMLS repo)

- [x] Replace `unimplemented!` panic in RustCrypto provider
      (`openmls_rust_crypto/src/provider.rs`) with an
      `Err(CryptoError::UnsupportedCiphersuite)` return.
- [x] Add tests proving an unsupported PQ ciphersuite does not panic in the
      RustCrypto provider.
- [x] Gate X-Wing in the libcrux provider behind an explicit feature flag
      (`openmls_libcrux_crypto/xwing`, surfaced as `openmls/xwing`).
- [x] Add FIPS 203 / IETF HPKE-PQ Known Answer Tests (KATs) — placeholder
      vectors for ML-KEM and ML-DSA in
      `openmls/tests/pq_kat_vectors/{ml_kem,ml_dsa}.json`, with schema
      and classical-rejection tests in `openmls/tests/pq_kat_tests.rs`.
      Real FIPS 203 vectors will replace the placeholders once the
      libcrux provider lands ML-KEM bindings.
- [x] Separate draft / private codepoints from final IANA codepoints in
      `traits/src/types.rs` via `is_draft_codepoint()` helpers and module
      docs.

#### MLS PQ ciphersuite layer

- [x] Add IETF MLS PQ draft ciphersuites (ML-KEM hybrid, pure ML-KEM)
      with versioned draft codepoints. Six variants in
      `traits/src/types.rs`:
      `MLS_256_MLKEM768_X25519_AES256GCM_SHA384_Ed25519` (`0xFE01`),
      `MLS_256_MLKEM768_X25519_CHACHA20POLY1305_SHA256_Ed25519`
      (`0xFE02`), `MLS_256_MLKEM1024_AES256GCM_SHA512_Ed448`
      (`0xFE03`), `MLS_256_MLKEM768_AES256GCM_SHA384_Ed25519`
      (`0xFE04`), `MLS_256_MLKEM768_X25519_AES256GCM_SHA384_MLDSA65`
      (`0xFE05`), and `MLS_256_MLKEM768_AES256GCM_SHA384_MLDSA65`
      (`0xFE06`). All flagged via `is_draft_codepoint()`. Both providers
      reject them with `UnsupportedCiphersuite` until libcrux ML-KEM
      and ML-DSA bindings land.
- [x] Add ML-DSA signature scheme support to the `SignatureScheme` enum
      (`traits/src/types.rs`). Variants `MLDSA44 = 0x0904`,
      `MLDSA65 = 0x0905`, `MLDSA87 = 0x0906` are wired through with
      `is_draft_codepoint()` and `is_post_quantum()` helpers; both providers
      explicitly reject them.
- [x] Implement ML-DSA in at least one crypto provider — libcrux
      provider gates ML-DSA-65 keygen / sign / verify behind a new
      `mldsa` feature flag (surfaced as `openmls/mldsa`). RustCrypto
      still rejects all three ML-DSA variants with
      `UnsupportedSignatureScheme`.

#### APQ-MLS combiner

- [x] Design the `KChatMlsConversation` orchestration struct
      (`openmls/src/group/kchat_conversation.rs`). Constructors for
      classical, direct-PQ, and APQ modes; mode helpers; pending-commit
      tracking; `apq_info` linkage; and a live `bootstrap_apq` method
      (Phase 4) that links a freshly-built PQ group to an existing T
      group, generates the `apq_psk`, and emits an `ApqWelcome`.
- [x] Implement dual-session (T + PQ) group management. The FULL/PARTIAL
      commit flows now drive real `MlsGroup::commit_builder` calls and
      wire the apq_psk via the MLS exporter.
- [x] Implement the FULL commit flow
      (`openmls/src/group/apq_commit.rs`): PQ-side commit, exporter-based
      apq_psk derivation, `PreSharedKeyId` storage, and T-side commit with
      a PSK proposal.
- [x] Implement the PARTIAL commit flow
      (`openmls/src/group/apq_commit.rs`): T-session-only commit when
      policy permits.
- [x] Implement the `APQInfo` extension and downgrade prevention
      (`openmls/src/extensions/apq_info.rs`,
      `openmls/src/group/no_downgrade.rs`).
- [x] Implement `APQWelcome` for bootstrap
      (`openmls/src/messages/apq_welcome.rs`).

#### Migration protocol

- [x] Implement `DeviceCapability` advertisement (struct, signing,
      verification, common-ciphersuite selection — see
      `openmls/src/credentials/device_capability.rs`). Server-side
      registry/storage is still pending.
- [x] Implement `SecurityMode` enum and selection logic (Classical /
      PqConfidentiality / PqAuthenticity, mode + ciphersuite selection from
      a peer set, no-downgrade transition helper — see
      `openmls/src/ciphersuite/security_mode.rs`).
- [x] Implement multi-ciphersuite KeyPackage publication
      (`openmls/src/key_packages/multi_ciphersuite.rs`).
- [x] Implement conversation upgrade logic for new conversations
      (`openmls/src/group/conversation_upgrade.rs`).
- [x] Implement the MLS `ReInit` flow for 1:1 and small group upgrades
      (`openmls/src/group/reinit_upgrade.rs`): `propose_reinit`,
      `commit_reinit`, `complete_reinit` and the resumption-PSK helpers.
- [x] Implement APQ bootstrap for larger group upgrades
      (`KChatMlsConversation::bootstrap_apq`).
- [x] Implement the FULL/PARTIAL commit policy engine
      (`openmls/src/group/pq_policy.rs`).
- [x] Implement no-downgrade enforcement rules
      (`openmls/src/group/no_downgrade.rs`).

#### Server components

- [x] KeyPackage service: per-ciphersuite and per-capability-version
      storage/fetch — in-memory reference impl in
      `openmls/src/key_packages/key_package_service.rs`.
- [x] Capability registry: signed per-device PQ capability — in-memory
      reference impl in
      `openmls/src/credentials/capability_registry.rs`.
- [x] Delivery service: APQ wrapper message support and commit
      ordering — in-memory reference impl in
      `openmls/src/messages/delivery_service.rs`. Per-group FIFO
      queue, FULL-pair ordering enforcement (PQ before T), and
      `pending_count` tracking. 8 unit tests.
- [x] Group metadata service: conversation security state tracking —
      in-memory reference impl in
      `openmls/src/group/conversation_metadata.rs`.
- [x] Rate limiting for PQ KeyPackage fetches and Welcome fanout —
      sliding-window limiter in
      `openmls/src/key_packages/rate_limiter.rs`.
- [x] Telemetry for PQ-specific failure modes — event enum, emitter
      trait, and in-memory test emitter in
      `openmls/src/group/pq_telemetry.rs`.

#### Testing and validation

- [x] Classical / PQ / APQ interop test scaffolding
      (`openmls/tests/pq_interop_tests.rs`).
- [x] PQ KAT framework with placeholder X-Wing/ML-KEM/ML-DSA vectors
      (`openmls/tests/pq_kat_tests.rs`,
      `openmls/tests/pq_kat_vectors/`).
- [x] End-to-end APQ lifecycle test coverage
      (`openmls/tests/pq_lifecycle_tests.rs`).
- [x] Downgrade rejection tests
      (`openmls/tests/pq_downgrade_tests.rs` — 11 integration tests).
- [x] PQ KeyPackage storage load testing
      (`openmls/tests/pq_load_tests.rs` — 6 integration tests at
      100-device / 1000-KP scale).
- [x] Welcome fanout load testing at target scale
      (`openmls/tests/pq_welcome_fanout_tests.rs` — 5 integration
      tests at 50-group / 100-Welcome scale).
- [x] Client resync after a missed PQ/T commit pair
      (`openmls/src/group/apq_resync.rs`).
- [ ] External security review of APQ orchestration.

## Known Gaps

| Gap                                              | Impact                                                                |
|--------------------------------------------------|-----------------------------------------------------------------------|
| X-Wing only, draft codepoint `0x004D`            | Not sufficient for final standards-based deployment                   |
| ~~RustCrypto provider panics on X-Wing~~         | Fixed: RustCrypto returns `UnsupportedCiphersuite` instead of panicking |
| No ML-DSA signature support in any provider      | PQ confidentiality ≠ PQ authenticity (enum + helpers landed; no provider impl) |
| ~~No APQ-MLS combiner~~                          | Combiner scaffolding (FULL/PARTIAL commits, ApqInfo, bootstrap, ReInit, resync) is wired against `MlsGroup`; live multi-client soak tests still pending |
| Server stubs are in-memory only                  | `CapabilityRegistry`, `KeyPackageService`, `ConversationMetadataService`, `KeyPackageFetchRateLimiter`, `DeliveryService`, `PqTelemetryEmitter` are reference implementations meant for tests and as API contracts — production servers must back them with persistent storage |
| ~~`commit_reinit` seals the old group before `complete_reinit` can run~~ | Fixed: `commit_reinit` now derives the Resumption(ReInit) PSK before sealing the old group and stores it on `ReInitCommit`. `complete_reinit` consumes the pre-derived secret instead of calling `export_secret` on an inactive group |
| ~~No migration state machine~~                   | Fixed: per-conversation `MigrationStateMachine` in `openmls/src/group/migration_state.rs` with the 8-state fine-grained lifecycle and the higher-level `ConversationLifecycle` projection wired into `KChatMlsConversation::migration_state` |
| ~~No server-side capability protocol~~            | Fixed: wire types in `openmls/src/credentials/capability_protocol.rs` (publish / fetch / notification request-response messages with TLS codecs and signature verification, layered on top of the existing in-memory `CapabilityRegistry`) |
| No final IETF PQ ciphersuite codepoints          | Need versioning and migration from draft IDs (six ML-KEM hybrid + pure ML-KEM 768/1024 + ML-DSA-signed draft codepoints currently shipped) |

## Changelog

### 2026-05-04 (PQ batch 4 — provider impls + wire protocols)

- Added three more IETF MLS PQ draft ciphersuites to
  `traits/src/types.rs`:
  `MLS_256_MLKEM768_AES256GCM_SHA384_Ed25519` (`0xFE04`),
  `MLS_256_MLKEM768_X25519_AES256GCM_SHA384_MLDSA65` (`0xFE05`), and
  `MLS_256_MLKEM768_AES256GCM_SHA384_MLDSA65` (`0xFE06`). Added the
  `MlKem768Draft` (`0xFE04`) `HpkeKemType` for pure ML-KEM-768.
  Updated `SecurityMode::from_ciphersuite` so MLDSA65-signed suites
  classify as `PqAuthenticity` and the ML-DSA-free hybrid /
  pure-MLKEM suites classify as `PqConfidentiality`.
- Implemented ML-DSA-65 in the libcrux provider behind a new `mldsa`
  feature flag (`libcrux_crypto/Cargo.toml`,
  `libcrux_crypto/src/crypto.rs`), surfaced as `openmls/mldsa`.
  Provider implements `signature_key_gen`, `sign`, and
  `verify_signature` for `SignatureScheme::MLDSA65`; `MLDSA44` and
  `MLDSA87` still return `UnsupportedSignatureScheme`. RustCrypto
  rejects all three.
- Added `openmls/src/messages/apq_delivery.rs` — Delivery Service
  APQ wrapper. `ApqMessage` pairs a payload with a `SessionSide`
  marker; `ApqCommitPair` bundles a PQ commit with its T commit and
  a declared `ApqDeliveryOrder` (PqFirst, TFirst, Independent);
  `validate_order` rejects misordered FULL commit pairs. Hand-written
  TLS codec + 7 integration tests in
  `openmls/tests/pq_apq_delivery_wire_tests.rs`. Mirrored as
  `delivery-service/ds-lib/src/apq.rs` exposing the wrapper to the
  delivery service crate via an `ApqEnvelope` tagged-union.
- Added `openmls/src/credentials/capability_protocol.rs` — wire
  protocol for client/server capability exchange.
  `CapabilityPublishRequest` / `CapabilityPublishResponse`,
  `CapabilityFetchRequest` / `CapabilityFetchResponse`, and
  `CapabilityUpdateNotification` with TLS codecs, signature
  verification on every accepted capability, and a registry-backed
  publish/fetch/notification flow built on top of the existing
  in-memory `CapabilityRegistry`.
- Added the `ConversationLifecycle` projection in
  `openmls/src/group/migration_state.rs`: the eight named lifecycle
  phases (Classical, UpgradeEligible, UpgradeProposed,
  UpgradeInProgress, PqActive, ApqBootstrapping, ApqActive, Failed)
  derived from the fine-grained `MigrationStateMachine`. Wired the
  optional `migration_state: Option<MigrationStateMachine>` field
  onto `KChatMlsConversation` plus accessor / mutator / `lifecycle`
  helpers, and shipped `openmls/tests/pq_migration_state_tests.rs`
  pinning the full Classical → ApqActive happy path through the
  external API.
- Extended the KAT framework in `openmls/tests/pq_kat_tests.rs`.
  X-Wing now runs a functional HPKE roundtrip against the libcrux
  provider; ML-DSA gains a sign/verify roundtrip runner gated behind
  the `mldsa` feature; ML-KEM gains a schema-validation runner that
  asserts draft codepoints and hex-decodes every field.
- Added high-scale `#[ignore]`d load tests:
  `pq_load_tests.rs` adds a 10K-KP / 1000-device publish-and-fetch
  stress test, a 4K-KP `expire_before` bulk purge, a rate-limiter
  burst test, and a 200-device last-resort fallback test;
  `pq_welcome_fanout_tests.rs` adds 100/500/1000-member fanout
  tests pinning the `~2669-byte` per-PQ-KeyPackage budget plus a
  paired-`ApqWelcome` size test. Run with `cargo test -- --ignored`.

### 2026-05-04 (PQ batch 3 — orchestration completion)

- Fixed the `commit_reinit` seal-order bug. `commit_reinit` now
  derives the Resumption(ReInit) PSK via `export_secret` *before*
  calling `set_inactive`, stores the secret on `ReInitCommit`, and
  `complete_reinit` / `complete_reinit_from_commit` consume the
  pre-derived secret instead of attempting to call `export_secret` on
  an inactive group. The regression test in
  `openmls/tests/pq_reinit_e2e_tests.rs` that previously pinned the
  `UseAfterEviction` failure now drives the full propose → commit →
  complete flow end-to-end.
- Added `openmls/src/messages/delivery_service.rs` — in-memory
  reference Delivery Service. Wraps outbound MLS messages in
  `ApqDeliveryEnvelope` (group_id, T or PQ session side, FULL-pair
  metadata), enqueues per-group, enforces PQ-before-T ordering on
  FULL commit pairs, and exposes `enqueue` / `deliver_next` /
  `deliver_all` / `pending_count` / `pending_full_pairs`. 8 unit
  tests.
- Added IETF MLS PQ draft ciphersuites to `traits/src/types.rs`:
  `MLS_256_MLKEM768_X25519_AES256GCM_SHA384_Ed25519` (`0xFE01`),
  `MLS_256_MLKEM768_X25519_CHACHA20POLY1305_SHA256_Ed25519`
  (`0xFE02`), and `MLS_256_MLKEM1024_AES256GCM_SHA512_Ed448`
  (`0xFE03`). Both providers reject them with
  `UnsupportedCiphersuite`. New `HpkeKemType` variants
  `MlKem768X25519Draft` (`0xFE01`) and `MlKem1024Draft` (`0xFE03`).
- Expanded the FIPS 203 KAT scaffolding. Added
  `openmls/tests/pq_kat_vectors/ml_kem.json` and
  `openmls/tests/pq_kat_vectors/ml_dsa.json` with three placeholder
  vectors each, plus `mod ml_kem` and `mod ml_dsa` runner modules in
  `openmls/tests/pq_kat_tests.rs` covering schema parsing,
  hex-decode round-trip, ciphersuite codepoint pinning, and classical-
  provider rejection (5 new tests).
- Added `openmls/tests/pq_load_tests.rs` (6 integration tests):
  1000-KeyPackage / 100-device publish stress, per-device cap
  enforcement, multi-ciphersuite fetch, `expire_before` at scale,
  last-resort fallback under load, and rate-limiter sliding-window
  enforcement. All complete in well under a second on dev hardware.
- Added `openmls/tests/pq_welcome_fanout_tests.rs` (5 integration
  tests): single-Welcome-per-`add_members` invariant under repeated
  adds, 100x Welcome serialize/deserialize round-trip, 50 simultaneous
  group setups, 20-envelope `ApqWelcome` round-trip, and Welcome
  ciphersuite consistency across a 10-add batch.
- Wired `PqTelemetryEmitter` into the orchestration layer. Added an
  `Arc<dyn PqTelemetryEmitter>` field (defaulting to
  `NoOpTelemetryEmitter`) and a `set_telemetry_emitter` method on
  `KChatMlsConversation`. `bootstrap_apq` emits
  `ApqBootstrapCompleted` on success and `PqProviderError` on every
  crypto failure path. `apq_resync` functions emit `ResyncTriggered`.
  Three new telemetry-aware wrappers preserve backward compatibility:
  `select_conversation_mode_with_emitter` (emits
  `UnsupportedCiphersuite`), `validate_mode_change_with_emitter`
  (emits `DowngradeAttempt`), and
  `complete_reinit_from_commit_with_emitter` (emits `ReInitCompleted`
  / `PqProviderError`). `ReInitCommit` gained a `new_ciphersuite`
  field for telemetry payloads.
- Added `openmls/tests/pq_telemetry_integration_tests.rs` (8
  integration tests) demonstrating event emission through the
  orchestration layer, NoOp safety, FIFO event ordering, and
  emitter swap-after-construction.
- Added `openmls/src/group/migration_state.rs` — per-conversation
  upgrade lifecycle state machine with eight states
  (`NotStarted` → `CapabilitiesCollected` → `KeyPackagesPublished` →
  `ModeSelected` → `BootstrapInitiated` → `BootstrapComplete` →
  `FirstFullCommitDone` → `Operational` | `Failed`),
  `MigrationEvent` enum, `advance` / `can_advance` / `is_terminal`
  methods, and `Failed` reachability from every non-terminal state.
  12 unit tests.
- Added `openmls/tests/pq_full_e2e_tests.rs` (15 integration tests)
  driving the complete orchestration lifecycle against real
  `MlsGroup` instances: classical group creation, `add_members` +
  Welcome fanout, capability-driven mode selection,
  no-downgrade validators (mode, joiner KP, APQ info),
  `ConversationMetadataService` round-trip, `CapabilityRegistry`
  store/fetch, `KeyPackageService` publish/fetch/expire,
  `KeyPackageFetchRateLimiter` per-device enforcement, ReInit
  proposal construction, `PqPolicy::required_commit_type`, and a
  full `MigrationStateMachine` lifecycle traversal.

### 2026-05-04 (server stubs and end-to-end tests)

- Added `openmls/src/credentials/capability_registry.rs` — in-memory
  signed capability store keyed by `(user_id, device_id)`. Verifies
  signatures on `store`, supports `fetch`, `fetch_all_for_user`, and
  `remove`. 8 unit tests.
- Added `openmls/src/key_packages/key_package_service.rs` — in-memory
  KeyPackage server scaffold with one-time consumption and last-resort
  fallback. Enforces `MAX_KEY_PACKAGES_PER_DEVICE`. 8 unit tests.
- Added `openmls/src/group/conversation_metadata.rs` — metadata service
  keyed by conversation ID. `update_security_state` and
  `update_apq_info` go through `validate_mode_change` /
  `validate_apq_info_change`. 9 unit tests.
- Added `openmls/src/key_packages/rate_limiter.rs` — sliding-window
  per-device rate limiter for PQ KeyPackage fetches. 7 unit tests.
- Added `openmls/src/group/pq_telemetry.rs` — `PqTelemetryEvent` enum
  (8 variants), `PqTelemetryEmitter` trait, `NoOpTelemetryEmitter`
  (default) and `InMemoryTelemetryEmitter` (testing). 5 unit tests.
- Populated `openmls/tests/pq_kat_vectors/xwing.json` with three
  synthetic vectors and extended `openmls/tests/pq_kat_tests.rs` with
  schema-parse, hex-decode, and classical-rejection tests (5 new
  tests).
- Added `openmls/tests/pq_apq_e2e_tests.rs` (11 tests) exercising
  `bootstrap_apq` error paths, `PqPolicy::required_commit_type`
  table, `detect_desync` on fresh conversations, and
  `prepare_full_commit` rejection on non-APQ conversations.
- Added `openmls/tests/pq_reinit_e2e_tests.rs` (8 tests) exercising
  the ReInit flow: `propose_reinit` happy path / same-cs error,
  `commit_reinit` transition-to-inactive, idempotent
  `complete_reinit`, and a regression test pinning the current
  commit-reinit-before-complete-reinit seal-order limitation.
- Extended `openmls/tests/pq_lifecycle_tests.rs` with 8 real-MlsGroup
  integration tests for `KChatMlsConversation` constructors and
  accessors (using the RustCrypto provider with classical
  ciphersuites).

### 2026-05-04 (orchestration wiring)

- Wired the FULL commit flow in `openmls/src/group/apq_commit.rs` to
  real `MlsGroup` operations: PQ-side commit via `commit_builder`,
  apq_psk derivation via the MLS exporter (`APQ_PSK_LABEL =
  "kchat-apq-psk"`, 32-byte output), `PreSharedKeyId` storage on the
  provider, and a T-side commit that consumes the PSK as a proposal.
  Pending-FULL-commit tracking is set only after the PQ commit
  succeeds.
- Wired the PARTIAL commit flow in `openmls/src/group/apq_commit.rs`
  to drive a T-session-only commit through `commit_builder` while
  leaving the PQ session untouched.
- Added `KChatMlsConversation::bootstrap_apq` in
  `openmls/src/group/kchat_conversation.rs` (Phase 4): adds T-group
  membership to a freshly-created PQ group, derives `apq_psk`,
  produces an `ApqInfo` and `ApqWelcome`, and installs the PQ session
  on the conversation. `ApqBootstrapError` enumerates 14 distinct
  precondition / crypto / membership failure modes.
- Added `openmls/src/group/reinit_upgrade.rs` (Phase 3) for the MLS
  ReInit upgrade path: `propose_reinit`, `commit_reinit`,
  `complete_reinit`. Derives the Resumption(ReInit) PSK via the MLS
  exporter (`REINIT_PSK_LABEL = "kchat-reinit-psk"`) and transitions
  the old group to read-only.
- Added `openmls/src/group/apq_resync.rs` for client recovery after a
  missed half of a FULL commit pair: `detect_desync`,
  `resync_from_pq`, `resync_from_t`, and `force_resync`. Exposes
  `MAX_EPOCH_DRIFT = 1` and emits a fresh `apq_psk` after a successful
  PQ-side resync.
- Added `openmls/tests/pq_kat_tests.rs` (7 tests) and a
  `openmls/tests/pq_kat_vectors/` directory with placeholder JSON
  vector files for X-Wing, ML-KEM, and ML-DSA. Includes JSON schema,
  hex decoding utilities, and an X-Wing runner gated behind the
  `xwing` feature.
- Added `openmls/tests/pq_interop_tests.rs` (8 tests) covering
  classical group creation, mixed-provider rejection (PQ group
  creation fails on RustCrypto), classical-only joiner rejection in
  PqConfidentiality conversations, and Welcome roundtrip across
  provider boundaries.
- Added `openmls/tests/pq_lifecycle_tests.rs` (17 tests) covering the
  end-to-end APQ lifecycle: classical → PQ capability upgrade → mode
  selection → bootstrap → PARTIAL/FULL policy → no-downgrade
  enforcement → epoch consistency.
- Added `openmls/tests/multi_ciphersuite_public_api.rs` (4 tests)
  exercising the public `MultiCiphersuiteKeyPackages` API the way a
  downstream KChat orchestration layer would, plus four
  X-Wing-feature-gated tests inside
  `openmls/src/key_packages/multi_ciphersuite.rs` that drive PQ
  KeyPackage generation through the libcrux provider, assert size
  ratios against classical KPs, exercise the per-device cap, and round
  the resulting KP through `MlsGroup::new`.

### 2026-05-04 (orchestration layer)

- Added `KChatMlsConversation` orchestration struct
  (`openmls/src/group/kchat_conversation.rs`) with constructors for
  classical, direct-PQ, and APQ modes, accessors for the underlying T /
  PQ groups, mode-classification helpers (`is_classical`, `is_pq`,
  `is_apq`), pending-FULL-commit tracking, and APQInfo linkage. Each
  constructor validates its preconditions before returning
  (`KChatConversationError`). 4 unit tests cover error shapes and
  precondition checks.
- Added `ApqInfo` extension struct
  (`openmls/src/extensions/apq_info.rs`): T/PQ group IDs, T/PQ epochs,
  T/PQ ciphersuites, and `SecurityMode`. Hand-rolled TLS codec
  (`SecurityMode` encoded as `u8`), `validate()` (rejects classical
  mode, ciphersuite/mode mismatch, duplicate group IDs, epoch drift
  beyond `MAX_EPOCH_DRIFT = 1`), and `matches_groups()`. 11 unit tests.
- Added `PqPolicy` and the FULL/PARTIAL commit policy engine
  (`openmls/src/group/pq_policy.rs`). `PqPolicy` is
  `Classical < PqConfidentiality < PqRequired` with `Ord`. Const
  `required_commit_type(trigger)` implements the PHASES.md Phase 5
  table for all 7 `CommitTrigger` values. 12 unit tests cover every
  policy × trigger combination.
- Added the no-downgrade enforcement layer
  (`openmls/src/group/no_downgrade.rs`). `ConversationSecurityState`
  tracks `current_mode`, `highest_mode_ever`, `policy_floor`, and
  `pinned_ciphersuite`. Five validators (`validate_mode_change`,
  `validate_joiner_key_package`, `validate_apq_info_change`,
  `validate_epoch_consistency`, `validate_ciphersuite_pin`) cover
  Phase 6's rejection rules. `DowngradeError` enumerates 8 distinct
  rejection reasons. 19 unit tests.
- Added the multi-ciphersuite KeyPackage helper
  (`openmls/src/key_packages/multi_ciphersuite.rs`). Generates a
  `KeyPackageBundle` for every ciphersuite advertised in a
  `DeviceCapability`, deduplicates between classical and PQ lists,
  enforces a per-device cap (`MAX_KEY_PACKAGES_PER_DEVICE = 16`), and
  exposes per-suite / classical / PQ accessors. 6 unit tests, including
  one that drives an actual classical KeyPackage build through the
  RustCrypto provider.
- Added the conversation-upgrade selector
  (`openmls/src/group/conversation_upgrade.rs`). `select_conversation_mode`
  uses `SecurityMode::select_mode` + `select_ciphersuite` to pick the
  highest mode every peer supports plus the best ciphersuite for that
  mode, and falls closed (no silent downgrade) when no common
  ciphersuite exists. 7 unit tests cover all-classical, mixed,
  all-PQ-confidentiality, all-PQ-authenticity (with and without ML-DSA
  suites available), single-peer, and error paths.
- Added the FULL/PARTIAL commit flow skeletons
  (`openmls/src/group/apq_commit.rs`). `prepare_full_commit` and
  `prepare_partial_commit` validate preconditions (mode, policy,
  in-flight FULL commit, conversation shape) and currently return
  `ApqCommitError::NotImplemented` until the live MLS wiring lands.
  `FullCommitResult` and `PartialCommitResult` capture the eventual
  output shape. 10 unit tests cover error surfaces, policy gating,
  in-flight detection, and result shape.
- Added `ApqWelcome` (`openmls/src/messages/apq_welcome.rs`) bundling
  the T-side and PQ-side `Welcome`s, the `ApqInfo` link record, and the
  initial `apq_psk` `PreSharedKeyId`. Hand-rolled TLS codec encoding
  `Option<T>` as a u8 presence flag, `validate()` cross-checks
  ciphersuites against `apq_info`, and `extract_group_ids()` exposes
  both group IDs in one call. 10 unit tests cover roundtrip, validation
  (APQ and direct-PQ paths), ciphersuite mismatches, missing PSK ID,
  and invalid presence bytes.
- Added `openmls/tests/pq_downgrade_tests.rs` (11 integration tests)
  covering: PQ-required conversations rejecting classical KeyPackages,
  APQInfo removal rejection, mode downgrades from PqAuthenticity →
  PqConfidentiality and PqConfidentiality → Classical, epoch
  mismatches, ciphersuite changes after bootstrap, the full upgrade
  path Classical → PqConfidentiality → PqAuthenticity, group-ID
  mismatches, and unchanged-APQInfo replay.

### 2026-05-04 (later session)

- Added `DeviceCapability` struct (
  `openmls/src/credentials/device_capability.rs`) for signed per-device
  capability advertisement: classical and PQ ciphersuite lists, APQ
  support flag, PQ-authenticity support flag, free-form provider id, and
  a signature over the rest. `serializable_payload()` produces the
  canonical signing input; `sign()` / `verify()` / `is_signed()` use any
  `OpenMlsCrypto` provider; `best_common_ciphersuite()` picks the best
  shared suite across a peer set (PQ preferred over classical).
  Hand-rolled TLS codec impl encodes `bool` as `u8` and `String` as
  `VLBytes`. 9 unit tests cover roundtrip, sign/verify, tamper rejection,
  and selection edge cases.
- Added `SecurityMode` enum (
  `openmls/src/ciphersuite/security_mode.rs`) with
  `Classical < PqConfidentiality < PqAuthenticity` ordering and
  `repr(u8)` wire stability. Helpers: `from_ciphersuite()`,
  `select_mode()` (highest mode all peers support),
  `select_ciphersuite()` (best suite for a target mode), and
  `allows_transition()` (no-downgrade primitive). 12 unit tests cover
  mode selection, ciphersuite selection, downgrade rejection, and
  ordering invariants.
- Added `openmls/tests/pq_capability_tests.rs` integration tests (7
  tests): TLS roundtrip, sign+verify with Ed25519 plus tamper rejection,
  best-common-ciphersuite for all-PQ and mixed peer sets, security-mode
  selection across peer combinations, no-downgrade enforcement, and
  `Classical < PqConfidentiality < PqAuthenticity` ordering invariant.

### 2026-05-04

- Replaced the `unimplemented!` panic in the RustCrypto provider with
  `Err(CryptoError::UnsupportedCiphersuite)`. `kem_mode()` and
  `hpke_from_config()` now return `Result`s, and every HPKE call site
  propagates the error with `?` instead of crashing the process.
- Added comprehensive tests in `openmls_rust_crypto/src/provider.rs`
  covering `supports()`, `supported_ciphersuites()`, `hpke_seal`,
  `hpke_open`, and `derive_hpke_keypair` for the X-Wing ciphersuite, plus
  classical-suite happy-path tests.
- Gated the X-Wing ciphersuite behind a new `xwing` feature in
  `openmls_libcrux_crypto`. Without the feature, `supports()` and
  `supported_ciphersuites()` no longer expose X-Wing, and `hpke_kem`
  returns `UnsupportedCiphersuite` instead of silently routing to a draft
  KEM. Surfaced as a passthrough `xwing` feature on the `openmls` crate.
- Added `is_draft_codepoint()` methods to `Ciphersuite`, `HpkeKemType`, and
  `SignatureScheme` so callers can distinguish draft / private codepoints
  from final IANA values, plus a module-level doc section in
  `traits/src/types.rs` describing the migration requirement.
- Added ML-DSA (FIPS 204) signature scheme variants `MLDSA44`, `MLDSA65`,
  and `MLDSA87` to `SignatureScheme` with draft codepoints, including a
  `TryFrom<u16>` mapping and `is_post_quantum()` helper. Both providers'
  catch-all arms reject these variants, with explicit tests verifying
  rejection.
- Created `PROPOSAL.md` summarising goals, problem statement, solution
  overview, and success criteria, and linked it from `README.md`.

## Last Updated

2026-05-04 (PQ batch 3)
