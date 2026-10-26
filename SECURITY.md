# Security policy

## What WARD protects

WARD provides **tamper-evidence** over an append-only sequence of content-free
receipts. A passing `verifyChain` result proves the chain has not been
modified, reordered, truncated in the middle, or had entries inserted,
provided the verifier recomputes hashes from first principles (which this SDK
does).

## What WARD does NOT protect against (by design)

Per [VERIFICATION.md §2], verification does **not** prove:

- that the witnessed source events were truthful;
- that the issuer was uncompromised when it wrote the entries;
- that a **wholesale rewrite** of an *unsigned* chain occurred. An attacker who
  controls the store and rewrites every entry with consistent hashes produces a
  chain that verifies INTACT. This is the fundamental limitation of any
  hash chain without an external anchor.

**Mitigation:** sign tips (Ed25519) and publish them to an external
append-only sink (e.g. Gitea signed tags, S3 Object Lock). Pass the saved tip
back at verify time via `opts.anchor`: a rewrite then fails `TIP_MISMATCH`
(anchor context) and a truncated tail fails `TRUNCATED_BEHIND_ANCHOR`. Use
`opts.requireSignatures` (CLI `--require-signed`) to reject a silent downgrade
to unsigned tips. Sinks are out of core; see
[SPEC-POINTERS.md](./SPEC-POINTERS.md) and the README anchor workflow.

## Cryptography

- Hashing: SHA-256 (`node:crypto`), lowercase hex.
- Signatures: Ed25519 (`node:crypto`), over the raw UTF-8 bytes of the
  `tip_chain_hash` hex string (SPEC §12.2).
- No custom crypto is implemented; all primitives are Node built-ins.
- `verifyTipSignature` is written to never throw on malformed input (returns
  `false`), so untrusted input cannot crash a verifier.

## Content-free guarantee

WARD entries store **only** a `payload_hash`, never source content (SPEC §2.1).
Callers compute the hash; this SDK's `payloadHash()` canonicalizes and hashes
but never persists the input. Do not place secrets, PII, or payloads in
`source_id`, `tags`, or `notes`.

## Key handling

- `exportKeypair` writes private keys with mode `0600` and re-`chmod`s them.
- Keep signing private keys out of the store and out of version control.

## Reporting a vulnerability

Report suspected vulnerabilities privately to security@quox.ai rather than
opening a public issue. Please include a reproduction and the affected
version. Triage is best-effort and carries no service-level agreement.
