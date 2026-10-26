# Experimental / out-of-core

This directory is intentionally empty of runtime code.

## CMS / X.509 tip anchoring, NOT in core

The WARD spec allows tips to be published to external sinks (Gitea signed
tags, S3 Object Lock) and, in richer deployments, wrapped in CMS/PKCS#7
detached signatures backed by an X.509 chain. That machinery requires
`pkijs` + `asn1js` (ASN.1/DER encoding), which are heavy third-party
dependencies.

To keep `@quox/ward` core **zero-dependency**, CMS/ASN.1 support is **left
out of this SDK**. The proven, dependency-heavy implementation lives in:

- `quox-dashboard/services/ward` (`ward-service` v0.2.0): `lib/signing.js`
  and its CMS/sink helpers, built on `pkijs` + `asn1js` + `better-sqlite3`.

Core WARD signing here uses **raw Ed25519 over the `tip_chain_hash` hex
bytes** (SPEC §12.2), which is the spec's baseline and needs only
`node:crypto`. That is sufficient for tamper-evidence and non-repudiation of
tips. Reach for `ward-service` only if you need CMS envelopes or a
SQLite-backed store.
