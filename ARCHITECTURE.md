# Quantum-Resistant MLS Architecture for KChat

This document describes the target architecture for adding quantum-resistant
end-to-end encryption to KChat on top of OpenMLS. It covers the standards we
track, the security modes we expose, the APQ-MLS combiner used for large
groups, backward-compatibility expectations, the direct-PQ vs. APQ decision
matrix, the planned ciphersuite roadmap, the client-side orchestration layer,
storage requirements, and the main risks.

The companion documents are:

- [`PROPOSAL.md`](./PROPOSAL.md) — high-level product proposal.
- [`PHASES.md`](./PHASES.md) — staged migration plan and rollout gates.
- [`PROGRESS.md`](./PROGRESS.md) — concrete state of this repository.

## Standards Basis

| Area                    | Status                       | Implication                                                    |
|-------------------------|------------------------------|----------------------------------------------------------------|
| Base MLS                | RFC 9420                     | Safe base protocol                                             |
| ML-KEM                  | NIST FIPS 203 (Aug 2024)     | PQ key establishment                                           |
| ML-DSA                  | NIST FIPS 204 (Aug 2024)     | PQ handshake authenticity                                      |
| X-Wing                  | IETF/CFRG draft              | HNDL bridge, not final                                         |
| MLS PQ ciphersuites     | IETF draft (March 2026)      | Track closely, avoid permanent private codepoints              |
| APQ-MLS combiner        | Draft (April 2026)           | Best fit for large-scale, must be feature-flagged              |

The base protocol — group state, framing, key schedule, ratchet tree — comes
from RFC 9420 and is provided unchanged by upstream OpenMLS. PQ work happens
at two layers above that: the ciphersuite/provider layer (ML-KEM, ML-DSA,
X-Wing) and the orchestration layer (APQ-MLS combiner, migration policy).

### Crypto provider layout

The ciphersuite/provider layer in this repo is split between two providers:

- **libcrux** (`libcrux_crypto`) is the PQ-capable provider. The X-Wing
  draft-06 hybrid KEM (`MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519`,
  draft codepoint `0x004D`) is gated behind a dedicated **`xwing` Cargo
  feature** so the draft suite cannot be selected without an explicit
  build-time opt-in. With `xwing` disabled, `supports()` rejects the suite,
  `supported_ciphersuites()` omits it, and `hpke_kem` returns
  `CryptoError::UnsupportedCiphersuite` instead of routing to the draft KEM.
  The `openmls` crate exposes a passthrough `xwing` feature that pulls in
  `libcrux-provider` and turns on `openmls_libcrux_crypto/xwing`.
- **RustCrypto** (`openmls_rust_crypto`) is the classical-only provider. It
  intentionally does not implement any post-quantum primitives; selecting
  X-Wing returns `CryptoError::UnsupportedCiphersuite` (rather than
  panicking), and `signature_key_gen` rejects ML-DSA with
  `CryptoError::UnsupportedSignatureScheme`.

## Security Modes

KChat exposes three security modes per conversation:

| Mode                | Name           | Cryptographic Behavior                                | Use Case                          |
|---------------------|----------------|-------------------------------------------------------|-----------------------------------|
| `CLASSICAL`         | Existing MLS   | Current classical ciphersuites                        | Legacy devices/groups             |
| `PQ_CONFIDENTIALITY`| HNDL protection| PQ/hybrid KEM, classical signatures                   | Default near-term target          |
| `PQ_AUTHENTICITY`   | Full PQ        | PQ KEM + ML-DSA signatures                            | High-risk groups, later default   |

`PQ_CONFIDENTIALITY` is the near-term default: it neutralizes harvest-now,
decrypt-later (HNDL) attacks against MLS group secrets while keeping the
existing Ed25519/P-256 identity infrastructure. `PQ_AUTHENTICITY` adds ML-DSA
to also protect handshake authenticity against future quantum signature
attacks; it requires both client and server identity infrastructure to be
upgraded and is the long-term default.

## APQ-MLS Combiner Architecture

For groups that are too large for direct PQ MLS to be bandwidth-friendly, KChat
uses the APQ-MLS combiner: each KChat conversation is backed by **two** MLS
sessions running in parallel.

```
KChat conversation
 ├─ T session  = traditional/classical MLS
 └─ PQ session = PQ MLS session
```

Key properties:

- The PQ session **exports secret material** (e.g. via the MLS exporter
  interface) that is injected into the T session as a `PreSharedKey` proposal
  during **FULL** commits.
- **Application messages are sent only in the T session.** This avoids paying
  per-message PQ overhead at scale; the PQ session is used only for the
  group-state ratchet.
- **FULL commits update the PQ session first**, derive a fresh `apq_psk`, then
  commit on the T session with a `PreSharedKey(apq_psk_id)` proposal, binding
  the two sessions at that epoch.
- **Add and remove are mandatory FULL operations** — both T and PQ sessions
  must be re-keyed together so a removed device is removed from both. Other
  updates (routine PCS refresh, leaf updates) MAY be **PARTIAL** (T-only).

### Operation table

| Operation                  | Handling                                                 |
|----------------------------|----------------------------------------------------------|
| New group creation         | APQ if all devices PQ-capable; otherwise classical       |
| Add/remove member          | FULL commit: update both T and PQ sessions               |
| Join by external commit    | Join both sessions, first commit must be FULL            |
| Routine key update         | PARTIAL commit unless policy requires FULL               |
| Application message        | Send in T session only                                   |
| PQ refresh                 | Scheduled FULL commit based on risk policy               |

The two sessions are linked by an `APQInfo` extension carried in the GroupInfo
of both groups (and persisted client-side). It records `t_group_id`,
`pq_group_id`, the latest synchronized epochs, the chosen ciphersuites, and
the active mode. APQInfo is part of the no-downgrade enforcement surface
described in [`PHASES.md`](./PHASES.md).

## Backward Compatibility

"Backward-compatible" here means **the rollout is non-disruptive**, not that
old conversations get retroactive PQ security.

| Layer                          | Behavior                                                                     |
|--------------------------------|------------------------------------------------------------------------------|
| Existing classical groups      | Continue working unchanged                                                   |
| Existing users/devices         | Upgrade client-by-client; no global hard cutover                             |
| Existing conversation IDs      | Preserve app-level identity; crypto group IDs may change                     |
| Existing messages              | Remain decryptable but not retroactively PQ-secure                           |
| New PQ policy                  | Reject silent fallback to classical-only                                     |
| Legacy devices                 | Stay classical, become read-only, or removed after threshold                 |

The application-level conversation identity (KChat conversation ID, room
metadata, history) is preserved across upgrades, but the **MLS group ID** for a
PQ-upgraded conversation may differ — for example, after a `ReInit` the new
group has a fresh group ID. The mapping is owned by the KChat orchestration
layer, not by OpenMLS.

## Direct PQ vs APQ Decision Matrix

| Scenario                                  | Recommended Path                              |
|-------------------------------------------|-----------------------------------------------|
| New 1:1, both upgraded                    | Direct PQ/hybrid or APQ                       |
| Existing 1:1                              | ReInit to PQ when both support                |
| Small group, all upgraded                 | Direct PQ or APQ                              |
| Medium/large group                        | APQ                                           |
| Group with non-upgraded device            | Stay classical or remove legacy               |
| High-risk needing PQ auth                 | APQ with ML-DSA or direct PQ with ML-DSA      |
| Public/channel-scale                      | APQ with conservative FULL schedule           |

Direct PQ is simpler — there is one MLS session per conversation, and PQ
overhead is paid at every commit and Welcome — so it suits 1:1 and small
groups where bandwidth is not the bottleneck. APQ pays PQ overhead only on
membership changes and scheduled refreshes, which is the right shape for
medium and large groups, channels, and public rooms.

## Ciphersuite Roadmap

PQ confidentiality (KEM) and PQ authenticity (signatures) are tracked as
separate axes:

**Confidentiality (KEM):**
- **Current draft (HNDL bridge):** `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519`
  at draft codepoint `0x004D` (X-Wing hybrid: ML-KEM-768 + X25519).
- **Planned, tracking the IETF MLS PQ ciphersuite draft (codepoints TBD until
  IANA assignment):**
  - ML-KEM hybrid suites (ML-KEM + X25519 or P-256) — primary
    `PQ_CONFIDENTIALITY` target.
  - Pure ML-KEM suites — once IETF/NIST guidance settles on standalone PQ.

**Authenticity (signatures):**
- ML-DSA suites (FIPS 204) — required for `PQ_AUTHENTICITY`. Distinct from KEM
  selection: a conversation can run a hybrid KEM with classical Ed25519
  signatures (`PQ_CONFIDENTIALITY`) or with ML-DSA (`PQ_AUTHENTICITY`).
  The `SignatureScheme` enum in `traits/src/types.rs` already exposes
  `MLDSA44 = 0x0904`, `MLDSA65 = 0x0905`, and `MLDSA87 = 0x0906` (all
  draft codepoints) so the rest of the stack can compile against them.
  **Provider implementations are not yet wired up:** both the RustCrypto
  and libcrux providers reject these schemes with
  `CryptoError::UnsupportedSignatureScheme`. Implementing ML-DSA in at
  least one provider is tracked in [`PROGRESS.md`](./PROGRESS.md).

### Draft codepoint hygiene

Until the IETF MLS PQ ciphersuite draft assigns final codepoints, all PQ
suites are stored under draft / private codepoints and must be migrated to
their final IANA-assigned values during rollout (see [`PROGRESS.md`](./PROGRESS.md)).
To make the draft / final distinction visible at the type level,
[`Ciphersuite`](./traits/src/types.rs), [`HpkeKemType`](./traits/src/types.rs),
and [`SignatureScheme`](./traits/src/types.rs) each expose an
`is_draft_codepoint()` helper. Production code paths that depend on a final
IANA codepoint (e.g. no-downgrade enforcement, telemetry, capability
advertisement) should consult these helpers rather than hard-coding the set
of draft suites.

## KChat Orchestration Layer

The orchestration layer lives **outside core OpenMLS** and uses the existing
`MlsGroup` API as a primitive. The conceptual shape:

```rust
KChatMlsConversation {
    conversation_id,
    mode: CLASSICAL | DIRECT_PQ | APQ_CONF | APQ_AUTH,
    t_group: Option<MlsGroup>,
    pq_group: Option<MlsGroup>,
    apq_info,
    pending_full_commit,
    last_full_commit_epoch,
    pq_policy,
}
```

Responsibilities of this layer:

- Keep the T and PQ groups in sync (membership, FULL/PARTIAL discipline,
  commit ordering).
- Drive the FULL commit handshake (PQ commit → derive `apq_psk` → T commit
  with `PreSharedKey(apq_psk_id)`).
- Enforce the no-downgrade rules (mode never decreases, `APQInfo` stays
  consistent, ciphersuite mode does not change post-bootstrap).
- Emit telemetry for PQ-specific failure modes (KeyPackage exhaustion,
  unsupported suites, missed commit pairs, etc.).

This keeps OpenMLS itself focused on RFC 9420 group operations while letting
KChat compose them into the APQ pattern.

## Storage Requirements

Clients must persist enough state to recover both sessions deterministically:

- Classical group state (`MlsGroup` for the T session).
- PQ group state (`MlsGroup` for the PQ session).
- `APQInfo` (group IDs, last synchronized epochs, ciphersuites, mode).
- Conversation-to-group mapping (KChat conversation ID ↔ T group ID,
  PQ group ID).
- Pending commits on either session (FULL handshake in progress, half-applied
  state).
- PSK IDs and the latest `apq_psk` material needed to reconstruct the link.
- Commit counters per session for ordering and replay protection.
- Anti-downgrade state (highest mode the conversation has ever held, current
  policy floor).

Storage migration must be **idempotent** so that a client can be upgraded,
crash mid-migration, and re-run the migration safely on next start.

## Main Risks

1. **Draft churn.** X-Wing, MLS PQ ciphersuites, HPKE-PQ, and APQ-MLS are all
   still in draft. Final codepoints, wire formats, and combiner details may
   change. We must version draft codepoints separately from final IANA
   codepoints and avoid burning permanent private codepoints.
2. **Downgrade attacks.** The largest security risk during a phased rollout is
   silent fallback to classical or to a weaker mode. No-downgrade enforcement
   (server policy, client checks, signed capabilities, `APQInfo` validation)
   is mandatory before turning on `PQ_REQUIRED`.
3. **PQ authenticity gap.** Hybrid/PQ KEM alone protects only confidentiality.
   An attacker with a future quantum signature break could still forge MLS
   handshake messages and impersonate members. Closing this gap requires
   `PQ_AUTHENTICITY` (ML-DSA) and is tracked as a separate phase.
4. **Large message overhead.** PQ KeyPackages are roughly an order of
   magnitude larger than classical ones (~2669 bytes for X-Wing vs. ~299
   bytes classical). Multiplied across users and devices, this dominates
   KeyPackage storage and Welcome fanout cost; rate-limiting and bounded
   publication are mandatory.
5. **Operational fork handling.** APQ runs two MLS sessions per conversation.
   Commit ordering between T and PQ sessions, recovery from missed commit
   pairs, and clean handling of partial FULL commits are all new failure
   modes that the orchestration layer must handle deterministically.
