# @quox/ward

**WARD** (Write-once Append-only Receipt Digests). A small, zero-dependency
library for **tamper-evident hash-chain witnessing**: build a content-free
receipt chain over events, verify its integrity, and sign checkpoints with
Ed25519.

This SDK packages the WARD v0.2 protocol (chain math + verification) as a
clean standalone library. New entries are written under the v0.2
canonical-JSON chain hash (SPEC §4.4, canonicalization profile WARD-CANON-1,
§3.2); existing v0.1 chains remain verifiable under the legacy scheme
(Appendix A) but the writer will not create new v0.1 entries. It implements
[SPEC.md](https://github.com/quoxai/ward) §3.2 (canonicalization), §4
(crypto), §6-§8 (schemas), §11 (lifecycle), §16 (versioning), and the
[VERIFICATION.md](https://github.com/quoxai/ward) 6-step algorithm.

## Scope (be honest about what this is)

| Area | Status |
|------|--------|
| Chain math (genesis, chain_hash, tip computation) | **Core.** Fully implemented, spec-conformant. |
| Verification (INTACT / BROKEN / PARTIAL + reason codes) | **Core.** Fully implemented, conformance-tested against every tamper type. |
| Ed25519 tip signing / verification | **Core.** `node:crypto` only. |
| Storage | **Minimal.** In-memory + file NDJSON in core. SQLite is a future optional peer (not in this package). |
| CMS / X.509 tip anchoring | **Not included.** Requires `pkijs`/`asn1js`; lives in `ward-service`. See [SPEC-POINTERS.md](./SPEC-POINTERS.md). |

**Zero runtime dependencies in core.** Only Node's built-in `node:crypto` and
`node:fs`. `ajv` is a dev/test dependency only.

## Install (from source)

**Publishing to npm at launch.** `@quox/ward` is not on the registry yet, so
there is no working `npm install @quox/ward` today. The repo
(github.com/quoxai/ward-sdk) opens at launch as well; until then you are
working from a private checkout. From the repo root:

```bash
cd ward-sdk
npm install
npm run build
```

Then reference the built package by path (`npm install /path/to/ward-sdk`),
via `npm link`, or import from source in a monorepo.

## Quick start

```ts
import {
  appendEntry,
  verifyChain,
  computeTip,
  generateKeypair,
  signTipHash,
  InMemoryStore,
} from '@quox/ward';

const chainId = 'ward:org/quox/env/production';
const store = new InMemoryStore();

// Witness a source event (content-free: you pass the payload HASH, never the payload).
const e1 = appendEntry(store.getEntries(chainId), {
  chainId,
  issuerId: 'ward-issuer-prod-01',
  sourceKind: 'AEE',
  sourceId: 'aee-env-550e8400',
  payloadHash: 'a1b2c3...'.padEnd(64, '0'), // SHA-256 hex of the source event
});
store.appendEntry(e1);

// Verify the whole chain.
const result = verifyChain(chainId, store.getEntries(chainId));
console.log(result.status); // "INTACT"

// Checkpoint + sign the head.
const kp = generateKeypair();
const head = store.getHead(chainId)!;
const tip = computeTip(chainId, store.getEntries(chainId), head.seq, {
  sig: signTipHash(head.chain_hash, kp.privateKey),
  keyId: kp.keyId,
});
store.putTip(tip);
```

### Compute a payload hash

WARD never stores content. Hash the canonical source event yourself:

```ts
import { payloadHash } from '@quox/ward';
const h = payloadHash(sourceEvent); // SHA-256 over canonical JSON (SPEC §3.2)
```

## CLI: `ward-verify`

Verify a portable chain export file. Exit codes mirror `ward-service`:
`0` INTACT · `1` BROKEN · `2` ERROR · `3` PARTIAL.

```bash
ward-verify chain.json
ward-verify --chain chain.json --pubkey ed25519.pem --pretty
```

Input file shape:

```json
{ "chain_id": "ward:org/quox/env/production", "entries": [ /* ward entries */ ], "tips": [ /* optional */ ] }
```

## Storage

`@quox/ward/store` exports:

- `InMemoryStore`: non-durable, for tests and ephemeral pipelines.
- `FileStore`: durable append-only NDJSON files (one dir, one file per chain).

Both implement the `WardStore` interface and enforce gap-free `seq` and the
`(chain_id, source_kind, source_id)` uniqueness constraint (SPEC §6.3). A
**SQLite-backed store is a documented future optional peer**, kept out
of core so core stays dependency-free. Bring your own by implementing
`WardStore`.

## Verification guarantees

A passing verification proves the chain has integrity: genesis is correct,
every `chain_hash` recomputes, links are unbroken, `seq` is gap-free, no
duplicate sources, and any tips (and their signatures) match. It does **not**
prove the source events were truthful or that the issuer was uncompromised
(VERIFICATION.md §2). WARD is tamper-evidence, not an oracle.

## Pinning tips out of band (defeating tail-rewrite)

A hash chain alone cannot detect a **wholesale rewrite**: an attacker who
controls the store can rebuild every entry with consistent hashes, producing a
different chain that still verifies INTACT. The mitigation is an **external
anchor**: periodically compute a tip, sign it, and publish it to an
append-only sink you do not control (Gitea signed tags, S3 Object Lock, a
notary). The anchor is your out-of-band memory of where the chain was.

At verification time, pass that saved tip back in:

```ts
const result = verifyChain(chainId, entries, {
  anchor: { expectedTip: savedTip, expectedHeadSeq: savedTip.tip_seq },
});
```

- If the chain no longer reaches the anchored seq (a truncated tail), you get
  `BROKEN` / `TRUNCATED_BEHIND_ANCHOR`.
- If the chain reaches that seq but the hash diverges (a rewrite), you get
  `BROKEN` / `TIP_MISMATCH` with `details.anchor: true`.

`expectedTip` accepts a full tip object or a bare `tip_chain_hash` string. From
the CLI, save the tip JSON and pass `--anchor <tip.json>`. To additionally
require that a tip signature verifies (no silent downgrade to unsigned), pass
`requireSignatures: true` (CLI: `--require-signed`).

## WARD v0.2: canonical-JSON chain hash

Chain hashing moved from v0.1's pipe-delimited concatenation to SHA-256 over
the canonical JSON of the entry's hash body (SPEC §4.4), closing a
delimiter-injection gap: a crafted `ward_entry_id`/`source_id` containing `|`
could make two distinct field tuples hash identically under the old scheme.

- `buildEntry`/`appendEntry` always stamp `ward_version: "0.2"` on new
  entries and refuse to create a new `"0.1"` entry, or a `chain_id`
  containing `"::"` (reserved for meta-chain `source_id`s, SPEC §5.2).
- `verifyChain` selects the hash scheme **per entry** from its own
  `ward_version`: `"0.2"` uses the canonical-JSON scheme, `"0.1"` uses the
  legacy formula (Appendix A, verify-only), and any other value is `BROKEN`
  / `CHAIN_HASH_MISMATCH` with a detail naming the unrecognized version. A
  chain MAY contain v0.1 entries followed by v0.2 entries (a mid-chain
  upgrade), but never the reverse (`VERSION_DOWNGRADE`).
- A v0.1 entry whose `ward_entry_id`/`source_id` contains `|` (the exposure
  the v0.2 scheme fixes) adds a warning rather than failing outright, so
  existing v0.1 chains keep verifying while flagging the risk.
- Before any hash is recomputed, every entry is checked for well-formedness
  (Step 0: all 11 required fields, 64-hex hash fields, `seq` in
  `[1, 2^53 - 1]`, no null hash-body members, well-formed-NFC strings, no
  `::` in `chain_id`): failure is `BROKEN` / `SCHEMA_INVALID`.
- `canonicalize` implements canonicalization profile **WARD-CANON-1** (SPEC
  §3.2): object keys sorted by UTF-8 byte order (not JS's default UTF-16
  code-unit order), strings must already be well-formed NFC (rejected, never
  silently repaired), integers bounded to `+/-(2^53 - 1)`. `parseStrictJson`
  (used by `FileStore` and the CLI) rejects duplicate JSON member names,
  since an already-parsed JS object cannot represent one for `canonicalize`
  to catch.

## Reason codes

`BROKEN` / `PARTIAL` results carry a `reason`. Nine are spec-defined
(VERIFICATION.md §5, including the v0.2 additions `SCHEMA_INVALID` and
`VERSION_DOWNGRADE`); the last three are SDK verifier extensions from the
security-hardening pass.

| Reason code | Status | Meaning |
|-------------|--------|---------|
| `SCHEMA_INVALID` | BROKEN | An entry failed Step 0 well-formedness validation (missing/null/malformed field, bad `seq`, `::` in `chain_id`, non-NFC string) |
| `GENESIS_MISMATCH` | BROKEN | Entry seq 1 does not link to the derived genesis hash |
| `CHAIN_HASH_MISMATCH` | BROKEN | An entry's `chain_hash` does not recompute (or `ward_version` is unrecognized) |
| `VERSION_DOWNGRADE` | BROKEN | A `"0.1"` entry follows a `"0.2"` entry in the chain (SPEC §16.1 monotonicity) |
| `CHAIN_LINK_BROKEN` | BROKEN | An entry's `prev_chain_hash` breaks the link |
| `SEQ_INVALID` | BROKEN | `seq` is not contiguous from 1 |
| `DUPLICATE_SOURCE` | BROKEN | A `(chain_id, source_kind, source_id)` tuple repeats |
| `TIP_MISMATCH` | BROKEN | A tip (or anchor) hash does not match the chain |
| `TIP_SIGNATURE_INVALID` | BROKEN | A tip Ed25519 signature fails to verify |
| `KEY_ID_MISMATCH` | BROKEN | A tip's `key_id` is not the identity of the verifying key |
| `TRUNCATED_BEHIND_ANCHOR` | BROKEN | The chain head falls short of an external anchor seq |
| `SIGNATURE_REQUIRED` | BROKEN | `requireSignatures` is set but no tip signature verified |
| `INCOMPLETE_CHAIN` | PARTIAL | A tip references a seq beyond the available entries |

## Status and maturity

**[STATUS_AND_LIMITS.md](./STATUS_AND_LIMITS.md) is the honest source of truth
for what works and what doesn't.** Where this README and that file disagree,
that file wins. Snapshot as of the last verification pass (WARD v0.2): 142
tests across 12 files, all green, run live against this checkout. Not built: a
Python port (this package is TypeScript/Node only) and a SQLite store (future
optional peer; implement `WardStore` yourself if you need one today).

The protocol itself lives in the [WARD spec repo](https://github.com/quoxai/ward)
(SPEC.md, VERIFICATION.md, THREAT_MODEL.md, WORKED_EXAMPLES.md). Where this SDK
extends or interprets the spec, [SPEC-POINTERS.md](./SPEC-POINTERS.md) documents
the divergence explicitly (notably the `key_id` fingerprint derivation, which is
an SDK choice, not a spec mandate).

## Conformance

`conformance/fixtures/` holds a valid v0.1 chain (reproducing
WORKED_EXAMPLES.md Example 2), a signed-tip chain (Example 5), and one tamper
fixture per reason code (modified entry, broken link, forged genesis, deleted
entry, duplicate source, forged tip, bad signature). These are legacy-scheme
fixtures now, exercising the Appendix A verify-only path. The fixtures are
produced by the SDK's own writer math, and the test suite asserts the
verifier **rejects every tamper with the correct reason code**. Fixtures also
validate against the four spec JSON schemas in `schemas/`.

`conformance/fixtures/spec-v0.2/` vendors the WARD spec repo's own
`examples/single-chain` and `examples/meta-chain` fixtures verbatim (every
hash and signature is real, generated by `ward/tools/gen-examples.mjs`, not
fabricated). `conformance/spec-v0.2-vectors.test.ts` recomputes every
`chain_hash` and `payload_hash` and verifies the published tip signature
against the documented Ed25519 public key, anchoring the v0.2 canonical-JSON
scheme against a source outside this repo, the same role
`external-vectors.test.ts` plays for v0.1.

## License

Apache-2.0. See [LICENSE](./LICENSE).
