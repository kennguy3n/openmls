# Proposal: Quantum-Resistant E2E Encryption for KChat (OpenMLS Fork)

Status: Active — Phase 0 complete; Phases 1–6 in progress (~95%)
Last updated: 2026-05-05 (PQ batch 6 — doc reconciliation)

## 1. Project Goal

Add quantum-resistant end-to-end encryption to KChat by extending this fork of
[OpenMLS](https://github.com/openmls/openmls) (Messaging Layer Security,
[RFC 9420](https://datatracker.ietf.org/doc/html/rfc9420)) with PQ and
hybrid-PQ ciphersuites and a dual-session (APQ-MLS) orchestration layer. The
goal is to deliver a production-grade PQ deployment for KChat at scale while
remaining standards-aligned with the IETF MLS PQ ciphersuite draft and the
APQ-MLS combiner draft.

## 2. Problem Statement

The current MLS deployment uses classical ciphersuites (X25519/P-256 KEM,
Ed25519/P-256 signatures). Two threats motivate this work:

- **Harvest-now, decrypt-later (HNDL).** A capable adversary can record
  classical MLS handshakes today and decrypt the application traffic later,
  once a cryptographically-relevant quantum computer (CRQC) is available. MLS
  group secrets — and therefore message confidentiality — are exposed.
- **Future quantum signature breaks.** Once a CRQC exists, classical signatures
  (Ed25519, ECDSA) can be forged. Without PQ signatures the authenticity of
  MLS handshake messages — adds, removes, commits, KeyPackages — is no longer
  protected.

These threats are independent: a hybrid/PQ KEM neutralizes HNDL but does
nothing for handshake authenticity. Closing both gaps requires upgrading
**both** the KEM and the signature scheme along separate axes.

## 3. Solution Overview

KChat exposes three security modes per conversation, evolved independently:

| Mode                | Cryptographic behavior                              | Use case                          |
|---------------------|------------------------------------------------------|-----------------------------------|
| `CLASSICAL`         | Existing classical MLS ciphersuites                  | Legacy devices/groups             |
| `PQ_CONFIDENTIALITY`| Hybrid/PQ KEM, classical signatures                  | Default near-term target          |
| `PQ_AUTHENTICITY`   | Hybrid/PQ KEM **plus** ML-DSA signatures             | High-risk groups, longer-term     |

The migration uses two complementary patterns:

1. **Direct hybrid/PQ MLS** for new 1:1 chats and small groups. A single PQ
   ciphersuite (e.g. X-Wing `0x004D` today, ML-KEM hybrid suites once the IETF
   MLS PQ draft assigns codepoints) is used end-to-end. Existing small groups
   are upgraded via MLS `ReInit` (RFC 9420 §11.2) with a resumption PSK.
2. **APQ-MLS combiner** for medium and large groups. Each KChat conversation
   is backed by **two** parallel MLS sessions — a classical `T` session and a
   PQ session. Application messages flow only on the `T` session; on FULL
   commits the PQ session derives a fresh `apq_psk` that is injected into the
   `T` session as a `PreSharedKey` proposal, binding the two sessions at that
   epoch. This pays PQ overhead only on membership changes and scheduled
   refreshes rather than on every message.

Cryptography lives behind the existing `OpenMlsCrypto` provider trait. The
libcrux provider (this fork's primary PQ provider) implements X-Wing today and
will implement ML-KEM/ML-DSA as libcrux upstream lands them. The RustCrypto
provider remains classical-only and explicitly rejects PQ ciphersuites with an
`UnsupportedCiphersuite` error rather than panicking.

The orchestration layer (FULL/PARTIAL commit policy, `APQInfo`, no-downgrade
rules, capability-driven ciphersuite selection) lives **outside core OpenMLS**
in the KChat client and uses the existing `MlsGroup` API as a primitive.

## 4. Success Criteria

The success criteria are tracked as the six phases defined in
[PHASES.md](./PHASES.md):

- **Phase 0 — Crypto-agile clients.** Every upgraded client publishes a
  signed `DeviceCapability` advertising MLS version, classical and PQ
  ciphersuites, APQ support, PQ-auth support, and provider id. The server
  validates the signature and other clients drive ciphersuite selection from
  these capabilities.
- **Phase 1 — Multiple KeyPackages per device.** PQ-capable devices publish
  KeyPackages for **every** ciphersuite they speak (classical and PQ), with
  bounded publication and rate-limited fetch.
- **Phase 2 — New conversations first.** New conversations among PQ-capable
  devices are created in PQ mode by default; classical traffic is unaffected.
- **Phase 3 — `ReInit` for existing 1:1 and small groups.** Existing small
  groups whose members are all PQ-capable can be upgraded to PQ via `ReInit`
  without losing message history.
- **Phase 4 — APQ bootstrap for larger groups.** Larger groups can be upgraded
  in place via the APQ bootstrap (PQ group + `APQInfo` + `APQWelcome` + first
  FULL commit) without rebuilding membership.
- **Phase 5 — FULL/PARTIAL commit policy.** Add/remove/credential-rotation
  trigger FULL commits; routine PCS updates may be PARTIAL.
- **Phase 6 — No-downgrade enforcement.** `PQ_REQUIRED` conversations cannot
  silently fall back to classical; downgrade attempts fail closed.

Definitions of done for each phase, plus rollout gates (provider support,
interop, downgrade safety, load, recovery, security review), are detailed in
[PHASES.md](./PHASES.md).

## 5. Companion Documents

- [ARCHITECTURE.md](./ARCHITECTURE.md) — standards basis, security modes,
  APQ-MLS combiner, decision matrix, ciphersuite roadmap, KChat orchestration
  layer, storage requirements, and risks.
- [PHASES.md](./PHASES.md) — staged migration plan, definitions of done, and
  rollout gates.
- [PROGRESS.md](./PROGRESS.md) — concrete state of this repository: completed
  items, in-progress fixes, known gaps, and changelog.
