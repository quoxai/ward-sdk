# STATUS_AND_LIMITS — WARD SDK

> Treat the README and CHANGELOG as marketing-adjacent. Treat this file as the source of truth for what works and what doesn't in this package.

**Repo:** `ward-sdk` (`@quox/ward` TypeScript). MIT licensed, unpublished.
**Created:** 2026-07-25. **Last verified:** 2026-08-31 (tests run live against this checkout, WARD v0.2 pass).
**Authoritative paths:** `src/chain.ts`, `src/verify.ts`, `src/sign.ts`, `src/crypto.ts`, `src/store/` (`InMemoryStore`, `FileStore`), `bin/ward-verify.mjs`, `SPEC-POINTERS.md` (documents where the SDK diverges from or extends the spec), `conformance/`.

## How to read the tags

| Tag | Meaning |
|---|---|
| **Stable-candidate** | Fully implemented, spec-conformant, backed by an automated test suite with a live green run. Not "Stable" in the strict production-use sense yet (pre-launch, zero deployed consumers), but no known gap between spec and implementation. |
| **Not included** | Deliberately out of core scope; lives (or will live) in a different package. |
| **Not built** | Does not exist. |

## Maturity table

| Capability | Status | Notes |
|---|---|---|
| Chain math (genesis hash, `chain_hash`, tip computation) | Stable-candidate | Implements SPEC §4. New entries default to `ward_version: "0.2"` (canonical-JSON hash body, SPEC §4.4) and `buildEntry` refuses to create a new v0.1 entry or a `chain_id` containing `"::"` (SPEC §5.2, §16.1). `test/chain.test.ts` (10 tests). |
| Verification (INTACT / BROKEN / PARTIAL, reason codes) | Stable-candidate | 6-step algorithm (VERIFICATION.md §3): Step 0 validates entry well-formedness before any hash is recomputed (11 required fields, 64-hex hashes, `seq` in `[1, 2^53-1]`, no null hash-body members, well-formed-NFC strings, no `::` in `chain_id`) → `BROKEN`/`SCHEMA_INVALID` on failure. Step 2 selects the hash scheme per entry from its own `ward_version` (SPEC §16.1): `"0.2"` canonical-JSON, `"0.1"` legacy pipe-concatenation (Appendix A, verify-only), any other value is `BROKEN`/`CHAIN_HASH_MISMATCH` with a detail naming the unrecognized version, and a `"0.1"` entry following a `"0.2"` entry is `BROKEN`/`VERSION_DOWNGRADE` (version monotonicity). A v0.1 entry whose `ward_entry_id`/`source_id` contains `"|"` adds a delimiter-injection warning. 13 total reason codes: 9 spec-defined (`SCHEMA_INVALID`, `GENESIS_MISMATCH`, `CHAIN_HASH_MISMATCH`, `VERSION_DOWNGRADE`, `CHAIN_LINK_BROKEN`, `SEQ_INVALID`, `DUPLICATE_SOURCE`, `TIP_MISMATCH`, `TIP_SIGNATURE_INVALID`) plus 3 SDK verifier extensions from the security-hardening pass (`KEY_ID_MISMATCH`, `TRUNCATED_BEHIND_ANCHOR`, `SIGNATURE_REQUIRED`) and one PARTIAL code (`INCOMPLETE_CHAIN`). `test/verify.test.ts` (39 tests). |
| Canonicalization profile WARD-CANON-1 (SPEC §3.2) | Stable-candidate | `canonicalize` sorts object keys by **UTF-8 byte order** (not JS's default UTF-16 code-unit order — differs for supplementary-plane characters), rejects (never silently repairs) a string that is not well-formed Unicode already in NFC, bounds integers to `+/-(2^53-1)`, and rejects non-finite numbers. `parseStrictJson` (dependency-free hand-written parser) rejects duplicate JSON member names at the two untrusted-byte boundaries (`FileStore` NDJSON reads, `ward-verify` CLI file reads); `verifyChain` itself takes already-parsed objects, which cannot represent a duplicate key, so that rule cannot be re-checked there. `test/crypto.test.ts` (6), `conformance/spec-v0.2-vectors.test.ts` (21), `test/strict-json.test.ts` (7). |
| Ed25519 tip signing / verification | Stable-candidate | `node:crypto` only, no external crypto dependency. `test/sign.test.ts` (7 tests), `test/crypto.test.ts` (6 tests). |
| `key_id` binding to key fingerprint | Stable-candidate, documented spec gap | `deriveKeyId(publicKey)` binds a tip's declared `key_id` to the verifying key's fingerprint; `verifyChain(..., { expectedKeyId })` supports opaque/DID-style `key_id`s. Per `SPEC-POINTERS.md`, SPEC §8.2 requires `key_id` to be a "stable identifier" but does not define a concrete fingerprint derivation, so `key_id` is opaque at the protocol level. This SDK's fingerprint scheme is the SDK's own choice, not the spec's. |
| External anchor (defeats tail-rewrite) | Stable-candidate | `verifyChain(..., { anchor: { expectedTip, expectedHeadSeq } })`, CLI `--anchor`. Distinguishes a truncated tail (`TRUNCATED_BEHIND_ANCHOR`) from a rewrite (`TIP_MISMATCH` with `details.anchor: true`). |
| Require-signatures mode | Stable-candidate | `verifyChain(..., { requireSignatures: true })`, CLI `--require-signed`. No silent downgrade to unsigned-but-passing. |
| Storage: in-memory + file NDJSON | Stable-candidate | `InMemoryStore` (non-durable, tests/ephemeral) and `FileStore` (durable, gap-free `seq` + `(chain_id, source_kind, source_id)` uniqueness enforced). `FileStore` recovers from a torn final line on both the entries file and the tips file via `getWarnings()` rather than making the whole chain unreadable; a parse failure on any non-final line still throws as real corruption. `test/store.test.ts` (13 tests). |
| `ward-verify` CLI | Stable-candidate | Exit codes mirror `ward-service` (0 INTACT, 1 BROKEN, 2 ERROR, 3 PARTIAL). `test/cli.test.ts` (10 tests). |
| External conformance vectors | Stable-candidate | `conformance/external-vectors.test.ts` (v0.1 legacy scheme) and `conformance/spec-v0.2-vectors.test.ts` (v0.2, vendors the WARD spec repo's own `examples/single-chain` and `examples/meta-chain` fixtures verbatim — every hash and signature is real, from `ward/tools/gen-examples.mjs`, not fabricated) recompute chain math with independent code, so conformance is not self-verifying against the SDK's own fixture generator. |
| Whole suite | Stable-candidate | 142 tests across 12 files, all green as of this verification pass (`npx vitest run`). |

## Not included in core (by design)

- **CMS / X.509 tip anchoring.** Requires `pkijs`/`asn1js`. Lives in `ward-service`, not this package, so core stays dependency-free. See `SPEC-POINTERS.md`.
- **SQLite-backed store.** Documented as a future optional peer. Core ships only `InMemoryStore` and `FileStore`. Bring your own by implementing the `WardStore` interface if you need SQLite today.

## Not built

- **Python port.** This package is JavaScript/TypeScript only. There is no `quox-ward` Python package, and no partial work toward one in this repo.

## Known gaps

- `key_id` derivation is an SDK-invented fingerprint scheme, not a spec-mandated one (see table above). If a caller's `key_id`s are DIDs or another external opaque scheme, `expectedKeyId` must be supplied explicitly; the SDK cannot derive it from the key alone in that case.
- Verification proves chain integrity (recomputed hashes, unbroken links, gap-free `seq`, no duplicate sources, matching signed tips). It does **not** prove the underlying source events were truthful or that the issuer was uncompromised. This is documented in the README as a deliberate scope boundary, not a gap to be closed.

## What this SDK is NOT

- Not an oracle for the truthfulness of witnessed events, only for the integrity of the chain that records them.
- Not a CMS/X.509 anchoring solution; that's `ward-service`.
- Not multi-language yet; TypeScript/Node only.

## Cross-cutting (applies to all four SDK repos: aee-sdk, ward-sdk, volt-sdk, aocl-sdk)

- None of the four packages are published to npm or PyPI yet. Publishing is owner-gated, planned for launch.
- None of the four repos have a public GitHub remote configured yet (`git remote -v` returns empty in all four checkouts as of this verification). Publishing the remote is owner-gated.
- Install-from-source only today (`npm install && npm run build`, then reference the built package by path). Any `npm install @quox/ward` instruction elsewhere is aspirational until launch.
- Zero runtime dependencies in core (only `node:crypto` and `node:fs`; `ajv` is dev/test only).
