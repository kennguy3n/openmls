# OpenMLS

[![OpenMLS Chat][chat-image]][chat-link]
[![OpenMLS List][list-image]][list-link]

[![Tests & Checks][gh-tests-image]](https://github.com/openmls/openmls/actions/workflows/tests.yml?branch=main)
[![codecov][codecov-image]](https://codecov.io/gh/openmls/openmls)

[![Docs][docs-release-badge]][docs-release-link]
[![Book][book-release-badge]][book-release-link]
![Rust Version][rustc-image]

_OpenMLS_ is a Rust implementation of the Messaging Layer Security (MLS) protocol, as specified in [RFC 9420](https://datatracker.ietf.org/doc/html/rfc9420).

<!-- The introduction of the book imports the lines up until here (line 13), excluding the headline and separately the lines below (starting from line 19, "Supported ciphersuite"). If the line numbers change here, please modify the imported lines in the book.-->

It is a software library that can serve as a building block in applications that require end-to-end encryption of messages.
It has a safe and easy-to-use interface that hides the complexity of the underlying cryptographic operations.

## About this fork

This is the **KChat PQ-resistant fork** of OpenMLS. We track upstream OpenMLS
as a foundation and layer in post-quantum and PQ/classical hybrid ciphersuites
plus orchestration scaffolding (APQ-MLS combiner, draft-codepoint helpers,
ML-DSA enum support) needed to ship quantum-resistant E2E encryption to KChat
at production scale. See [`PROPOSAL.md`](./PROPOSAL.md) for the high-level
product proposal, [`ARCHITECTURE.md`](./ARCHITECTURE.md) for the technical
design, [`PHASES.md`](./PHASES.md) for the staged migration plan, and
[`PROGRESS.md`](./PROGRESS.md) for the current implementation status.

## Quick start

```bash
git clone https://github.com/kennguy3n/openmls.git
cd openmls

# Default workspace build (classical only, no PQ).
cargo build --workspace

# Build the openmls crate with the libcrux PQ provider.
cargo build -p openmls --features libcrux-provider

# Opt in to the X-Wing draft-06 hybrid PQ ciphersuite.
# `xwing` implies `libcrux-provider`. The codepoint 0x004D is a draft and
# will change once IANA assigns the final value.
cargo build -p openmls --features xwing
```

## Project structure

- [`openmls/`](./openmls) — main `openmls` crate; MLS protocol logic, group
  management, and the public API.
- [`traits/`](./traits) — `openmls_traits`: provider trait, ciphersuite,
  KEM, signature, and HPKE type definitions consumed by the rest of the
  workspace.
- [`openmls_rust_crypto/`](./openmls_rust_crypto) — RustCrypto-backed
  classical provider. PQ ciphersuites return
  `CryptoError::UnsupportedCiphersuite`.
- [`libcrux_crypto/`](./libcrux_crypto) — libcrux-backed provider. Adds
  X-Wing under the `xwing` feature flag; ML-KEM/ML-DSA tracked as upstream
  libcrux gains support.
- [`memory_storage/`](./memory_storage), [`sqlite_storage/`](./sqlite_storage)
  — storage providers.
- [`basic_credential/`](./basic_credential) — a minimal credential
  implementation used in tests and examples.
- [`cli/`](./cli) — command-line client / demo.
- [`delivery-service/`](./delivery-service) — a reference delivery-service
  implementation (`ds`, `ds-lib`).
- [`interop_client/`](./interop_client) — interop test client used against
  the IETF MLS interop matrix.
- [`openmls_test/`](./openmls_test), [`fuzz/`](./fuzz),
  [`openmls-wasm/`](./openmls-wasm) — test harnesses, fuzz targets, and
  the wasm bindings crate.

## Running tests

```bash
# Whole workspace (classical only).
cargo test --workspace

# Individual provider crates.
cargo test -p openmls_rust_crypto
cargo test -p openmls_libcrux_crypto                       # without xwing
cargo test -p openmls_libcrux_crypto --features xwing      # with xwing

# Trait-level tests (draft-codepoint helpers, ML-DSA enum, ...).
cargo test -p openmls_traits

# PQ-specific integration test files.
cargo test -p openmls --test pq_capability_tests
cargo test -p openmls --test pq_downgrade_tests
cargo test -p openmls --test pq_interop_tests
cargo test -p openmls --test pq_kat_tests
cargo test -p openmls --test pq_lifecycle_tests
cargo test -p openmls --test pq_apq_e2e_tests
cargo test -p openmls --test pq_reinit_e2e_tests
cargo test -p openmls --test pq_load_tests
cargo test -p openmls --test pq_welcome_fanout_tests
cargo test -p openmls --test pq_telemetry_integration_tests
cargo test -p openmls --test pq_full_e2e_tests
cargo test -p openmls --test multi_ciphersuite_public_api
cargo test -p openmls --test pq_apq_delivery_wire_tests
cargo test -p openmls --test pq_migration_state_tests

# Real-crypto APQ end-to-end (libcrux + xwing).
cargo test -p openmls --features xwing,libcrux-provider \
    --test pq_real_crypto_e2e_tests

# Reference DS APQ message routing.
cargo test -p mls-ds

# SQLite `MigrationStorage` integration tests.
cargo test -p openmls_sqlite_storage

# PQ orchestration benchmarks.
cargo bench -p openmls --bench pq_benchmark

# High-scale load tests are gated behind `#[ignore]`; opt in with --ignored.
cargo test -p openmls --test pq_load_tests          -- --ignored
cargo test -p openmls --test pq_welcome_fanout_tests -- --ignored

# Lint + format (matches CI).
cargo fmt --all -- --check
cargo clippy --workspace --tests -- -D warnings
```

CI runs every command above on push to `main` and on pull requests via
[`.github/workflows/pq-tests.yml`](./.github/workflows/pq-tests.yml).

## Documentation index

- [`PROPOSAL.md`](./PROPOSAL.md) — product proposal: goal, problem,
  solution overview, success criteria.
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — standards basis, security modes,
  APQ-MLS combiner, decision matrix, ciphersuite roadmap.
- [`PHASES.md`](./PHASES.md) — phased migration plan and rollout gates.
- [`PROGRESS.md`](./PROGRESS.md) — implementation status, version targets,
  changelog, known gaps.

## PQ orchestration layer

The fork ships an in-tree orchestration layer that downstream KChat clients
use to drive the dual-session APQ design without reimplementing the
no-downgrade and policy logic. All modules below live in the `openmls`
crate and are exported under the `group`, `extensions`, `key_packages`,
and `messages` modules respectively.

- [`group::kchat_conversation::KChatMlsConversation`](./openmls/src/group/kchat_conversation.rs)
  — orchestration container holding the optional T (classical) and PQ
  groups, the `ApqInfo` link record, the `PqPolicy`, and the
  pending-FULL-commit flag.
- [`extensions::apq_info::ApqInfo`](./openmls/src/extensions/apq_info.rs)
  — link record between the T and PQ sessions: T/PQ group IDs, T/PQ
  epochs, T/PQ ciphersuites, and the `SecurityMode`.
- [`group::pq_policy`](./openmls/src/group/pq_policy.rs)
  — `PqPolicy` × `CommitTrigger` → `CommitType` table implementing
  PHASES.md Phase 5 (FULL on membership/credential changes,
  PARTIAL on T-only updates).
- [`group::no_downgrade`](./openmls/src/group/no_downgrade.rs)
  — `ConversationSecurityState` plus five validators enforcing the
  Phase 6 no-downgrade rules (mode change, joiner KP, APQInfo change,
  epoch consistency, ciphersuite pin).
- [`key_packages::multi_ciphersuite::MultiCiphersuiteKeyPackages`](./openmls/src/key_packages/multi_ciphersuite.rs)
  — Phase 1 helper that generates a `KeyPackageBundle` for every
  ciphersuite in a `DeviceCapability`, deduplicates between classical
  and PQ lists, and enforces a per-device cap.
- [`group::conversation_upgrade::select_conversation_mode`](./openmls/src/group/conversation_upgrade.rs)
  — Phase 2 selector that picks the highest mode every peer supports
  plus the best ciphersuite for that mode.
- [`group::apq_commit`](./openmls/src/group/apq_commit.rs)
  — `prepare_full_commit` and `prepare_partial_commit` wired to
  `MlsGroup::commit_builder` and the MLS exporter (`APQ_PSK_LABEL =
  "kchat-apq-psk"`).
- [`messages::apq_welcome::ApqWelcome`](./openmls/src/messages/apq_welcome.rs)
  — Phase 4 bootstrap envelope bundling the T and PQ `Welcome`s, the
  `ApqInfo`, and the initial `apq_psk` `PreSharedKeyId`.
- [`group::reinit_upgrade`](./openmls/src/group/reinit_upgrade.rs)
  — Phase 3 ReInit upgrade path (`propose_reinit`, `commit_reinit`,
  `complete_reinit`) for upgrading 1:1 and small classical groups to
  PQ via a Resumption(ReInit) PSK.
- [`group::apq_resync`](./openmls/src/group/apq_resync.rs)
  — Recovery (`detect_desync`, `resync_from_pq`, `resync_from_t`,
  `force_resync`) for clients that miss one half of a FULL commit
  pair (`MAX_EPOCH_DRIFT = 1`).
- [`credentials::capability_registry::CapabilityRegistry`](./openmls/src/credentials/capability_registry.rs)
  — in-memory Phase 0 server-side capability registry. Verifies the
  signature on each `DeviceCapability` before storing.
- [`key_packages::key_package_service::KeyPackageService`](./openmls/src/key_packages/key_package_service.rs)
  — in-memory Phase 1 KeyPackage server scaffold with one-time
  consumption, last-resort fallback, and `expire_before` bulk purge.
- [`group::conversation_metadata::ConversationMetadataService`](./openmls/src/group/conversation_metadata.rs)
  — in-memory conversation security-state tracker; mode and
  `ApqInfo` updates run through the no-downgrade validators.
- [`key_packages::rate_limiter::KeyPackageFetchRateLimiter`](./openmls/src/key_packages/rate_limiter.rs)
  — sliding-window per-device rate limiter for PQ KeyPackage
  fetches.
- [`group::pq_telemetry`](./openmls/src/group/pq_telemetry.rs)
  — 8-variant `PqTelemetryEvent` enum, `PqTelemetryEmitter` trait,
  and `NoOp` / `InMemory` reference emitters.
  `KChatMlsConversation` accepts an `Arc<dyn PqTelemetryEmitter>` via
  `set_telemetry_emitter`; orchestration entry points emit
  `ApqBootstrapCompleted`, `PqProviderError`, `ResyncTriggered`,
  `DowngradeAttempt`, `UnsupportedCiphersuite`, and `ReInitCompleted`
  through the telemetry-aware wrappers
  (`select_conversation_mode_with_emitter`,
  `validate_mode_change_with_emitter`,
  `complete_reinit_from_commit_with_emitter`).
- [`messages::delivery_service::DeliveryService`](./openmls/src/messages/delivery_service.rs)
  — in-memory reference Delivery Service. Wraps outbound messages
  in `ApqDeliveryEnvelope`, enforces PQ-before-T ordering on FULL
  commit pairs, and exposes per-group `enqueue` / `deliver_next` /
  `deliver_all` / `pending_count` / `pending_full_pairs`.
- [`group::migration_state::MigrationStateMachine`](./openmls/src/group/migration_state.rs)
  — per-conversation upgrade lifecycle state machine:
  `NotStarted` → `CapabilitiesCollected` → `KeyPackagesPublished` →
  `ModeSelected` → `BootstrapInitiated` → `BootstrapComplete` →
  `FirstFullCommitDone` → `Operational` | `Failed`. `advance` /
  `can_advance` / `is_terminal` make the state machine cheap to
  observe from dashboards and recovery code. The accompanying
  `ConversationLifecycle` projection collapses the fine-grained
  states onto eight named phases (Classical, UpgradeEligible,
  UpgradeProposed, UpgradeInProgress, PqActive, ApqBootstrapping,
  ApqActive, Failed); `KChatMlsConversation` now exposes an
  optional `migration_state` field plus a `lifecycle()` accessor.
- [`messages::apq_delivery`](./openmls/src/messages/apq_delivery.rs)
  — Delivery Service APQ wrapper. `ApqMessage` pairs a payload with
  a `SessionSide` marker; `ApqCommitPair` bundles a PQ commit + T
  commit + an `ApqDeliveryOrder` (PqFirst, TFirst, Independent) and
  rejects misordered FULL pairs via `validate_order`. Mirrored in
  `delivery-service/ds-lib/src/apq.rs` as an `ApqEnvelope` tagged
  union for the delivery service crate.
- [`credentials::capability_protocol`](./openmls/src/credentials/capability_protocol.rs)
  — wire protocol for client/server capability exchange.
  `CapabilityPublishRequest` / `CapabilityPublishResponse`,
  `CapabilityFetchRequest` / `CapabilityFetchResponse`, and
  `CapabilityUpdateNotification` with TLS codecs, signature
  verification on every accepted capability, and a registry-backed
  publish/fetch/notification flow on top of `CapabilityRegistry`.
- [`ciphersuite::codepoint_migration`](./openmls/src/ciphersuite/codepoint_migration.rs)
  — single source of truth for draft → final IANA codepoint
  migration. The static `CodepointMigration` table is currently empty
  (no IANA assignments yet), so every `migrate_ciphersuite` /
  `migrate_kem_type` / `migrate_signature_scheme` lookup returns
  `None`, but `needs_migration` lights up for every draft suite and
  `migrate_conversation_state` rotates a
  `ConversationSecurityState::pinned_ciphersuite` in place once a row
  is added to the table.
- [`group::storage_migration`](./openmls/src/group/storage_migration.rs)
  — idempotent client-side storage migration driver. `MigrationStep`
  is the ordered list (`MigrateGroupState` → `MigrateApqInfo` →
  `MigrateConversationMapping` → `MigratePskMaterial` →
  `MigrateCommitCounters` → `MigrateAntiDowngradeState`),
  `StorageMigrationState` is the persisted progress marker
  (`NotStarted` / `InProgress(step)` / `Complete` / `Failed(reason)`),
  and `StorageMigrator` is the driver that runs each step
  check-before-write, persists progress between steps, and resumes
  cleanly from the marker on the next start. Concrete backends plug
  in via the `MigrationStorage` trait. The canonical SQLite
  implementation lives in
  [`sqlite_storage::migration`](./sqlite_storage/src/migration.rs).
- Reference Delivery Service APQ endpoints
  ([`delivery-service/ds/src/main.rs`](./delivery-service/ds/src/main.rs))
  — `POST /apq/publish`, `POST /apq/publish-pair`, and
  `GET /apq/recv/{id}` route `ApqEnvelope` payloads to a per-client
  in-memory queue for the actix-web reference DS binary.
- CLI / WASM PQ surface — the `cli/` and `openmls-wasm/` crates now
  expose `SecurityMode`, `DeviceCapability`, `select_conversation_mode`,
  and the `LifecyclePhase` projection so end-to-end PQ flows can be
  driven from the CLI and from the browser without going through
  unstable internal types.
- PQ benchmarks — [`openmls/benches/pq_benchmark.rs`](./openmls/benches/pq_benchmark.rs)
  ships criterion benches for `DeviceCapability::sign` / `verify`,
  `select_conversation_mode` at 10 / 100 / 1000 peers, `ApqInfo` TLS
  round-trip, and the `ConversationSecurityState` validators.
- [`group::apq_commit::auto_classify_commit_type`](./openmls/src/group/apq_commit.rs)
  — Phase 5 trigger auto-classification.
  `detect_external_join` / `detect_credential_rotation` walk a
  `StagedCommit`'s proposals; `classify_proposal_types` maps a list
  of `ProposalType`s onto the highest-priority `CommitTrigger`
  (ExternalInit > Add > Remove > Update > everything-else);
  `auto_classify_commit_type` routes the trigger through
  `PqPolicy::required_commit_type`. The conversation surface
  `KChatMlsConversation::classify_incoming_commit` exposes the whole
  pipeline as a single method.

## Supported ciphersuites

### Classical (production)

- MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (MTI)
- MLS_128_DHKEMP256_AES128GCM_SHA256_P256
- MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519

### Post-Quantum (in progress)

This fork adds post-quantum (PQ) and PQ/classical hybrid ciphersuites. They are
still tracking IETF/NIST drafts and are gated behind the libcrux provider; the
RustCrypto provider does **not** implement any PQ primitives.

- **MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519** — X-Wing hybrid KEM
  (ML-KEM-768 + X25519), **draft** codepoint `0x004D`, libcrux provider
  only. Gated behind the `xwing` feature flag (which implies
  `libcrux-provider`); the suite is hidden from
  `supported_ciphersuites()` and rejected by `supports()` when the feature
  is off. Selecting this suite on the RustCrypto provider returns
  `CryptoError::UnsupportedCiphersuite` rather than panicking. Provides
  HNDL-bridge confidentiality with classical Ed25519 authenticity. The
  `0x004D` codepoint is a draft and will change once IANA assigns a final
  value — see
  [`Ciphersuite::is_draft_codepoint()`](./traits/src/types.rs).

Tracking the
[IETF MLS PQ ciphersuite draft](https://datatracker.ietf.org/doc/draft-ietf-mls-mls-pq-cs/)
(codepoints are draft / private-use until IANA assignment, currently in
the `0xFE00`–`0xFEFF` range):

- **MLS_256_MLKEM768_X25519_AES256GCM_SHA384_Ed25519** — ML-KEM-768 +
  X25519 hybrid KEM with classical Ed25519 signatures, AES-256-GCM
  AEAD. Draft codepoint `0xFE01`. Both providers currently reject the
  suite with `CryptoError::UnsupportedCiphersuite`.
- **MLS_256_MLKEM768_X25519_CHACHA20POLY1305_SHA256_Ed25519** — same KEM
  with ChaCha20-Poly1305 AEAD. Draft codepoint `0xFE02`.
- **MLS_256_MLKEM1024_AES256GCM_SHA512_Ed448** — pure ML-KEM-1024
  (FIPS 203) with Ed448 signatures. Draft codepoint `0xFE03`.
- **MLS_256_MLKEM768_AES256GCM_SHA384_Ed25519** — pure ML-KEM-768
  with classical Ed25519 signatures, AES-256-GCM AEAD. Draft
  codepoint `0xFE04`.
- **MLS_256_MLKEM768_X25519_AES256GCM_SHA384_MLDSA65** — ML-KEM-768
  + X25519 hybrid KEM with ML-DSA-65 signatures (FIPS 204). Draft
  codepoint `0xFE05`. Targets `PQ_AUTHENTICITY` deployments.
- **MLS_256_MLKEM768_AES256GCM_SHA384_MLDSA65** — pure ML-KEM-768
  with ML-DSA-65 signatures. Draft codepoint `0xFE06`.

ML-DSA signature suites (FIPS 204) for `PQ_AUTHENTICITY` deployments.
The `SignatureScheme` enum exposes `MLDSA44`, `MLDSA65`, and
`MLDSA87` variants with draft codepoints (`0x0904`–`0x0906`).
**`MLDSA65` is implemented in the libcrux provider behind the
`mldsa` feature flag** (key generation, sign, verify); `MLDSA44` and
`MLDSA87` still return `UnsupportedSignatureScheme`. RustCrypto
rejects all three.

See [`ARCHITECTURE.md`](./ARCHITECTURE.md), [`PHASES.md`](./PHASES.md), and
[`PROGRESS.md`](./PROGRESS.md) for the full roadmap.

## Quantum Resistance Roadmap

This fork is being upgraded to provide quantum-resistant end-to-end encryption
for [KChat](https://github.com/kennguy3n) at production scale, on top of the
upstream OpenMLS RFC 9420 base.

The roadmap is structured around three security modes:

- **CLASSICAL** — current MLS ciphersuites; legacy devices and groups.
- **PQ_CONFIDENTIALITY** — hybrid/PQ KEM with classical signatures; defends
  against "harvest now, decrypt later" (HNDL) attacks. Near-term default.
- **PQ_AUTHENTICITY** — hybrid/PQ KEM **plus** ML-DSA signatures; full PQ
  protection for high-risk groups, longer-term default.

Migration is two-track:

1. **Direct hybrid/PQ MLS** for new 1:1 chats and small groups, using a single
   PQ ciphersuite end-to-end (and `ReInit` for upgrading existing small
   groups).
2. **APQ-MLS combiner** for medium and large groups, where each conversation
   runs a classical (`T`) MLS session in parallel with a PQ MLS session and
   periodically injects PQ-derived secrets into the `T` session as a PSK. This
   keeps per-message overhead classical while still providing PQ
   confidentiality.

Details:

- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — standards basis, security modes,
  APQ-MLS combiner, decision matrix, ciphersuite roadmap, KChat orchestration
  layer, storage requirements, and risks.
- [`PHASES.md`](./PHASES.md) — phased migration plan (capabilities,
  KeyPackages, new conversations, ReInit, APQ bootstrap, FULL/PARTIAL policy,
  no-downgrade, server components, rollout gates).
- [`PROGRESS.md`](./PROGRESS.md) — current implementation status, version
  targets, and known gaps.

## Supported platforms

OpenMLS is built and tested on the Github CI for the following rust targets.

- x86_64-unknown-linux-gnu
- i686-unknown-linux-gnu
- x86_64-pc-windows-msvc
- i686-pc-windows-msvc
- x86_64-apple-darwin

### Unsupported, but built on CI

The Github CI also builds (but doesn't test) the following rust targets.

- aarch64-apple-darwin
- aarch64-unknown-linux-gnu
- aarch64-linux-android
- aarch64-apple-ios
- aarch64-apple-ios-sim
- wasm32-unknown-unknown
- armv7-linux-androideabi
- x86_64-linux-android
- i686-linux-android

OpenMLS supports 32 bit platforms and above.

## Cryptography Dependencies

OpenMLS does not implement its own cryptographic primitives. Instead, it relies
on existing implementations of the cryptographic primitives used by MLS. There
are two different cryptography providers implemented right now. But consumers
can bring their own implementation. See [traits](https://github.com/openmls/openmls/tree/main/traits) for more
details.

- **libcrux** ([`libcrux_crypto`](./libcrux_crypto)) — formally verified PQ-capable
  provider. This is the provider used for any of the post-quantum or hybrid
  ciphersuites listed above (currently X-Wing draft-06 behind the `xwing`
  feature; ML-KEM and ML-DSA as the IETF MLS PQ draft and libcrux gain
  support).
- **RustCrypto** ([`openmls_rust_crypto`](./openmls_rust_crypto)) — pure-Rust
  classical provider. **Does not support any PQ ciphersuite.** Selecting a PQ
  ciphersuite (e.g. `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519`) with
  this provider returns `CryptoError::UnsupportedCiphersuite` instead of
  panicking, and `signature_key_gen` rejects the ML-DSA `SignatureScheme`
  variants with `CryptoError::UnsupportedSignatureScheme`.

## Features
OpenMLS provides the following features

- **extensions-draft-08**: enable features defined in [MLS extensions draft-08](https://messaginglayersecurity.rocks/mls-extensions/draft-ietf-mls-extensions.html)
- **fork-resolution**: helper functionality for [resolving forks](https://book.openmls.tech/user_manual/fork-resolution.html).
- **js**: enable compilation to wasm
- **mldsa**: enable the ML-DSA-65 signature scheme in the libcrux
  provider (FIPS 204). Surfaces `openmls_libcrux_crypto/mldsa`.
- **xwing**: enable the X-Wing draft-06 hybrid KEM ciphersuite
  (`MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519`). Implies
  `libcrux-provider` and is opt-in because the `0x004D` codepoint is a
  draft.

<details>
<summary>Developer features</summary>

- **libcrux-provider**: enable the libcrux crypto provider dependency
- **openmls_rust_crypto**: enable the rust crypto provider
- **sqlite-provider**: enable the sqlite provider
- **backtrace**: enable backtraces
- **content-debug**: allow printing sensitive content of messages for debugging
- **crypto-debug**: allow printing cryptographic key material for debugging
- **test-util**: test utilities

</details>

## Working on OpenMLS

For more details when working on OpenMLS itself please see the [Developer.md].

## Maintenance & Support

OpenMLS is maintained and developed by [Phoenix R&D] and [Cryspen].

## Acknowledgements

[Zulip] graciously provides the OpenMLS community with a "Zulip Cloud Standard" tier [Zulip instance][chat-link].

[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg?style=for-the-badge&logo=zulip
[chat-link]: https://openmls.zulipchat.com
[list-image]: https://img.shields.io/badge/mailing-list-blue.svg?style=for-the-badge
[list-link]: https://groups.google.com/u/0/g/openmls-dev
[rustc-image]: https://img.shields.io/badge/rustc-1.56+-blue.svg?style=for-the-badge&logo=rust
[docs-release-badge]: https://img.shields.io/badge/docs-release-blue.svg?style=for-the-badge
[docs-release-link]: https://docs.rs/crate/openmls/latest
[book-release-badge]: https://img.shields.io/badge/book-release-blue.svg?style=for-the-badge
[book-release-link]: https://book.openmls.tech
[drone-image]: https://img.shields.io/drone/build/openmls/openmls/main?label=ARM64%20Build%20Status&logo=drone&style=for-the-badge
[codecov-image]: https://img.shields.io/codecov/c/github/openmls/openmls/main?logo=codecov&style=for-the-badge
[gh-tests-image]: https://img.shields.io/github/actions/workflow/status/openmls/openmls/tests.yml?branch=main&style=for-the-badge&logo=github
[gh-deploy-docs-image]: https://img.shields.io/github/workflow/status/openmls/openmls/Deploy%20Docs/main?label=Deploy%20Docs&logo=github&style=for-the-badge
[Developer.md]: https://github.com/openmls/openmls/blob/main/Developer.md
[Phoenix R&D]: https://phnx.im
[Cryspen]: https://cryspen.com
[Zulip]: https://zulip.com/
