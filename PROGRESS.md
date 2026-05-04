# KChat Quantum Resistance — Progress Tracker

This document tracks the concrete state of this repository against the
[`PROPOSAL.md`](./PROPOSAL.md) goals, the [`ARCHITECTURE.md`](./ARCHITECTURE.md)
target, and the [`PHASES.md`](./PHASES.md) migration plan.

**Status: Phase 0 — Complete | Phase 1–2 / 5–6 — In progress | ~25%**

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
- [ ] Add FIPS 203 / IETF HPKE-PQ Known Answer Tests (KATs) when available.
- [x] Separate draft / private codepoints from final IANA codepoints in
      `traits/src/types.rs` via `is_draft_codepoint()` helpers and module
      docs.

#### MLS PQ ciphersuite layer

- [ ] Add IETF MLS PQ draft ciphersuites (ML-KEM hybrid, pure ML-KEM, ML-DSA
      variants) with versioned draft codepoints.
- [x] Add ML-DSA signature scheme support to the `SignatureScheme` enum
      (`traits/src/types.rs`). Variants `MLDSA44 = 0x0904`,
      `MLDSA65 = 0x0905`, `MLDSA87 = 0x0906` are wired through with
      `is_draft_codepoint()` and `is_post_quantum()` helpers; both providers
      explicitly reject them.
- [ ] Implement ML-DSA in at least one crypto provider.

#### APQ-MLS combiner

- [x] Design the `KChatMlsConversation` orchestration struct
      (`openmls/src/group/kchat_conversation.rs`). Skeleton with classical /
      direct-PQ / APQ constructors, mode helpers, pending-commit tracking,
      and `apq_info` linkage.
- [ ] Implement dual-session (T + PQ) group management — orchestration
      skeleton landed; live wiring against `MlsGroup` is still pending.
- [x] Implement the FULL commit flow skeleton
      (`openmls/src/group/apq_commit.rs`):
      preconditions, in-flight tracking, error surface. PQ commit → PSK
      derivation → T commit with PSK still returns `NotImplemented` until
      the live MLS wiring lands.
- [x] Implement the PARTIAL commit flow skeleton
      (`openmls/src/group/apq_commit.rs`): policy gate, in-flight
      tracking, error surface. Live MLS wiring still pending.
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
- [ ] Implement the MLS `ReInit` flow for 1:1 and small group upgrades.
- [ ] Implement APQ bootstrap for larger group upgrades.
- [x] Implement the FULL/PARTIAL commit policy engine
      (`openmls/src/group/pq_policy.rs`).
- [x] Implement no-downgrade enforcement rules
      (`openmls/src/group/no_downgrade.rs`).

#### Server components

- [ ] KeyPackage service: per-ciphersuite and per-capability-version
      storage/fetch.
- [ ] Capability registry: signed per-device PQ capability.
- [ ] Delivery service: APQ wrapper message support and commit ordering.
- [ ] Group metadata service: conversation security state tracking.
- [ ] Rate limiting for PQ KeyPackage fetches and Welcome fanout.
- [ ] Telemetry for PQ-specific failure modes.

#### Testing and validation

- [ ] Classical / PQ / APQ interop test vectors.
- [x] Downgrade rejection tests
      (`openmls/tests/pq_downgrade_tests.rs` — 11 integration tests).
- [ ] PQ KeyPackage storage load testing.
- [ ] Welcome fanout load testing at target scale.
- [ ] Client resync after a missed PQ/T commit pair.
- [ ] External security review of APQ orchestration.

## Known Gaps

| Gap                                              | Impact                                                                |
|--------------------------------------------------|-----------------------------------------------------------------------|
| X-Wing only, draft codepoint `0x004D`            | Not sufficient for final standards-based deployment                   |
| ~~RustCrypto provider panics on X-Wing~~         | Fixed: RustCrypto returns `UnsupportedCiphersuite` instead of panicking |
| No ML-DSA signature support in any provider      | PQ confidentiality ≠ PQ authenticity (enum + helpers landed; no provider impl) |
| No APQ-MLS combiner                              | Needed for bandwidth-efficient PQ at scale                            |
| No migration state machine                       | Millions of users need per-device, per-conversation upgrade logic     |
| No server-side capability protocol               | Required for staged rollout                                           |
| No final IETF PQ ciphersuite codepoints          | Need versioning and migration from draft IDs                          |

## Changelog

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

2026-05-04
