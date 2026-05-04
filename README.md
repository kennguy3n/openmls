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
cargo test -p openmls --test multi_ciphersuite_public_api

# Lint + format (matches CI).
cargo fmt --all -- --check
cargo clippy --workspace --tests -- -D warnings
```

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

Planned, tracking the
[IETF MLS PQ ciphersuite draft](https://datatracker.ietf.org/doc/draft-ietf-mls-mls-pq-cs/)
(codepoints TBD until IANA assignment):

- ML-KEM hybrid suites (ML-KEM + X25519/P-256, classical signatures) for
  `PQ_CONFIDENTIALITY` deployments.
- Pure ML-KEM suites (FIPS 203) once the IETF draft stabilizes.
- ML-DSA signature suites (FIPS 204) for `PQ_AUTHENTICITY` deployments.
  The `SignatureScheme` enum already exposes `MLDSA44`, `MLDSA65`, and
  `MLDSA87` variants with draft codepoints (`0x0904`–`0x0906`); both
  providers reject them today, and provider implementations land once
  upstream libcrux gains ML-DSA support.

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
