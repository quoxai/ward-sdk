# Spec pointers & out-of-core features

`@quox/ward` implements the **core** of WARD v0.2: chain math, verification,
and Ed25519 tip signing, with zero runtime dependencies. New entries use the
v0.2 canonical-JSON chain hash (SPEC §4.4); the verifier still accepts
existing v0.1 chains under the legacy scheme (SPEC Appendix A), selected
per-entry by `ward_version` (SPEC §16.1). Some spec-adjacent capabilities are
intentionally out of core to preserve the zero-dependency property.

## Non-integer numbers in `payloadHash` inputs: resolved upstream, not a gap

`canonicalize`/`payloadHash` accept non-integer finite numbers (rejecting only
exponent notation), while WARD-CANON-1's integer rule (SPEC §3.2 rule 4) is
silent on floats. This is intentional, not an open ambiguity: SPEC §3.2's
scope note states WARD's own hash bodies contain no non-integer numbers, and
WARD-CANON-1 deliberately defines no serialization for them; a caller hashing
a source event with non-integer numbers via `payloadHash` must define and
document its own canonical number form, and WARD treats the resulting
`payload_hash` as an opaque commitment either way. No SDK change follows from
this; `chainHashV2`'s own hash-body fields never include a non-integer number.

## key_id format is spec-doc opaque, not just SDK-opaque

The WARD spec repo's own documentation examples (`ward/tools/gen-examples.mjs`,
`examples/single-chain/`) use a `key_id` of the form
`"ed25519:sha256:<16-hex-chars>"` (SHA-256 of the raw public key, truncated).
This SDK's own `deriveKeyId` uses a different derivation (see below): the last
32 bytes of the SPKI DER, hex-encoded, first 16 chars, with no hashing step.
Both are valid under the spec (SPEC §8.2 only requires a "stable identifier"),
but they are **not the same string** for the same key, so verifying a
doc-style `key_id` against this SDK's own fingerprint fails `KEY_ID_MISMATCH`
unless the caller passes `expectedKeyId` explicitly (see
`conformance/spec-v0.2-vectors.test.ts`). This is the opaque-`key_id` gap
below, made concrete by a second real-world scheme diverging from the SDK's.

## key_id derivation is a spec gap (SDK fingerprint scheme)

SPEC §8.2 says a tip's `key_id` is a "stable identifier for signing key (DID or
fingerprint)" and VERIFICATION.md §5 step 3 says the signature is verified
"using `key_id`", but the spec does **not** define a concrete fingerprint
derivation. `key_id` is therefore opaque at the protocol level.

To make the key identity actually participate in verification (rather than
trusting whatever public key the caller supplies), this SDK fills the gap with
a concrete scheme: `deriveKeyId(publicKey)` = the last 32 bytes of the SPKI DER
(the raw Ed25519 public key), hex-encoded, first 16 chars. It is exactly what
`generateKeypair` mints. The verifier binds a tip's declared `key_id` to the
verifying key with this derivation and fails `KEY_ID_MISMATCH` on divergence.

If your `key_id`s are DIDs or another opaque scheme not derivable from the key,
pass `verifyChain(..., { expectedKeyId })` to assert the identity out of band
instead of relying on the fingerprint derivation.

## CMS / X.509 tip anchoring, deliberately NOT in core

The spec allows tips to be published to external sinks and, in enterprise
deployments, wrapped in CMS/PKCS#7 detached signatures backed by an X.509
certificate chain. That needs `pkijs` + `asn1js` (ASN.1/DER), which are heavy
third-party dependencies.

Core WARD signing here uses **raw Ed25519 over the `tip_chain_hash` hex bytes**
(SPEC §12.2), the spec baseline, `node:crypto` only. That is sufficient for
tamper-evidence and tip non-repudiation.

If you need CMS envelopes, X.509 anchoring, or a SQLite-backed store, use the
richer, dependency-heavy implementation:

- **`ward-service`** (`quox-dashboard/services/ward`, v0.2.0): the full
  witness/verify/tip/sink stack on `better-sqlite3` + `pkijs` + `asn1js`.

## Storage

- **In-memory** and **file NDJSON** stores ship in core (`@quox/ward/store`).
- **SQLite** is a future optional peer dependency, not implemented here. It
  belongs outside core; implement the `WardStore` interface to add it.

## Upstream spec

The authoritative protocol documents (SPEC.md, CHAIN_STRUCTURE.md,
VERIFICATION.md, WORKED_EXAMPLES.md, THREAT_MODEL, JSON schemas) live in the
`ward` protocol repository. The four JSON schemas are vendored under
`schemas/` for offline schema-conformance testing.
