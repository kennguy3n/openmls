# PQ KAT vectors

Known-Answer-Test vectors for post-quantum ciphersuites. Loaded by the
runners in `openmls/tests/pq_kat_tests.rs`.

## Schema

Each file is a JSON array of `PqKatVector`:

```json
[
  {
    "name": "string",
    "ciphersuite": 77,
    "input_keying_material_hex": "deadbeef",
    "expected_ciphertext_hex": "cafebabe",
    "expected_shared_secret_hex": "f00d"
  }
]
```

`ciphersuite` is the RFC 9420 `u16` ciphersuite identifier (e.g.
`0x004D` / `77` for X-Wing).

## Files

- `xwing.json` — X-Wing draft KEM vectors. Run with the `xwing` feature.
- `ml_kem.json` — placeholder for ML-KEM vectors (Phase 6).
- `ml_dsa.json` — placeholder for ML-DSA vectors (Phase 6).

Empty arrays are valid — the runner treats "no vectors" as "nothing to
verify, but the framework is wired up." Drop real KAT vectors in as
they land in the IETF / NIST drafts.
