# KChat Quantum Resistance Migration Phases

**Current status: Phase 0 — In Progress (~55%)**

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

## Server Components

The server side is **policy-aware but cipher-agnostic**: it never sees plaintext
and never sees secret PQ material, but it does need to understand which
ciphersuite/capability each device speaks and how to fan out APQ traffic.

| Component              | Change                                                                                  |
|------------------------|-----------------------------------------------------------------------------------------|
| KeyPackage service     | Store/fetch per ciphersuite and capability version                                      |
| Capability registry    | Signed per-device PQ capability                                                         |
| Delivery service       | APQ wrapper messages, preserve commit ordering                                          |
| Group metadata         | Track conversation security state (not secrets)                                         |
| Abuse/rate limit       | Rate-limit PQ KeyPackage fetches and Welcome fanout                                     |
| Telemetry              | Track failures, unsupported suites, rejections, exhaustion (no plaintext)               |

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
