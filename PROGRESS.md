# KChat Quantum Resistance — Progress Tracker

This document tracks the concrete state of this repository against the
[`ARCHITECTURE.md`](./ARCHITECTURE.md) target and the
[`PHASES.md`](./PHASES.md) migration plan.

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
      (`libcrux_crypto/src/crypto.rs` line 402).
- [x] libcrux provider lists X-Wing in `supported_ciphersuites()`
      (`libcrux_crypto/src/crypto.rs` line 60).

### In Progress / Not Started

#### Immediate fixes (OpenMLS repo)

- [ ] Replace `unimplemented!` panic in RustCrypto provider
      (`openmls_rust_crypto/src/provider.rs` line 62) with an
      `Err(CryptoError::UnsupportedCiphersuite)` return.
- [ ] Add tests proving an unsupported PQ ciphersuite does not panic in the
      RustCrypto provider.
- [ ] Gate X-Wing in the libcrux provider behind an explicit feature flag.
- [ ] Add FIPS 203 / IETF HPKE-PQ Known Answer Tests (KATs) when available.
- [ ] Separate draft / private codepoints from final IANA codepoints in
      `traits/src/types.rs`.

#### MLS PQ ciphersuite layer

- [ ] Add IETF MLS PQ draft ciphersuites (ML-KEM hybrid, pure ML-KEM, ML-DSA
      variants) with versioned draft codepoints.
- [ ] Add ML-DSA signature scheme support to the `SignatureScheme` enum
      (`traits/src/types.rs`).
- [ ] Implement ML-DSA in at least one crypto provider.

#### APQ-MLS combiner

- [ ] Design the `KChatMlsConversation` orchestration struct.
- [ ] Implement dual-session (T + PQ) group management.
- [ ] Implement the FULL commit flow:
      PQ commit → PSK derivation → T commit with PSK.
- [ ] Implement the PARTIAL commit flow for T-session-only updates.
- [ ] Implement the `APQInfo` extension and downgrade prevention.
- [ ] Implement `APQWelcome` for bootstrap.

#### Migration protocol

- [ ] Implement `DeviceCapability` advertisement and server-side registry.
- [ ] Implement multi-ciphersuite KeyPackage publication.
- [ ] Implement conversation upgrade logic (new conversations first).
- [ ] Implement the MLS `ReInit` flow for 1:1 and small group upgrades.
- [ ] Implement APQ bootstrap for larger group upgrades.
- [ ] Implement the FULL/PARTIAL commit policy engine.
- [ ] Implement no-downgrade enforcement rules.

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
- [ ] Downgrade rejection tests.
- [ ] PQ KeyPackage storage load testing.
- [ ] Welcome fanout load testing at target scale.
- [ ] Client resync after a missed PQ/T commit pair.
- [ ] External security review of APQ orchestration.

## Known Gaps

| Gap                                              | Impact                                                                |
|--------------------------------------------------|-----------------------------------------------------------------------|
| X-Wing only, draft codepoint `0x004D`            | Not sufficient for final standards-based deployment                   |
| RustCrypto provider panics on X-Wing             | Misconfiguration could be operationally unsafe                        |
| No ML-DSA signature support                      | PQ confidentiality ≠ PQ authenticity                                  |
| No APQ-MLS combiner                              | Needed for bandwidth-efficient PQ at scale                            |
| No migration state machine                       | Millions of users need per-device, per-conversation upgrade logic     |
| No server-side capability protocol               | Required for staged rollout                                           |
| No final IETF PQ ciphersuite codepoints          | Need versioning and migration from draft IDs                          |

## Last Updated

2026-05-04
