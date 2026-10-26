import { describe, it, expect } from 'vitest';
import { appendEntry, computeTip } from '../src/chain.js';
import { verifyChain } from '../src/verify.js';
import { generateKeypair, signTipHash, deriveKeyId } from '../src/sign.js';
import { chainHash as legacyChainHash, genesisHash } from '../src/crypto.js';
import type { WardEntry } from '../src/types.js';

const CHAIN = 'ward:org/quox/env/staging';
const ISSUER = 'ward-issuer-stg-01';

function build3(): WardEntry[] {
  const entries: WardEntry[] = [];
  entries.push(appendEntry(entries, { chainId: CHAIN, issuerId: ISSUER, sourceKind: 'AEE', sourceId: 's1', payloadHash: 'a'.repeat(64) }));
  entries.push(appendEntry(entries, { chainId: CHAIN, issuerId: ISSUER, sourceKind: 'AOCL', sourceId: 's2', payloadHash: 'b'.repeat(64) }));
  entries.push(appendEntry(entries, { chainId: CHAIN, issuerId: ISSUER, sourceKind: 'VOLT', sourceId: 's3', payloadHash: 'c'.repeat(64) }));
  return entries;
}

const clone = (e: WardEntry[]): WardEntry[] => JSON.parse(JSON.stringify(e));

describe('verifyChain — VERIFICATION.md §3-§5', () => {
  it('a writer-built chain verifies INTACT', () => {
    const r = verifyChain(CHAIN, build3());
    expect(r.status).toBe('INTACT');
    if (r.status === 'INTACT') {
      expect(r.entry_count).toBe(3);
      expect(r.head_seq).toBe(3);
      expect(r.genesis_verified).toBe(true);
    }
  });

  it('an empty chain is INTACT', () => {
    const r = verifyChain(CHAIN, []);
    expect(r.status).toBe('INTACT');
  });

  it('GENESIS_MISMATCH when seq=1 prev is wrong', () => {
    const e = clone(build3());
    e[0]!.prev_chain_hash = 'a'.repeat(64);
    const r = verifyChain(CHAIN, e);
    expect(r).toMatchObject({ status: 'BROKEN', reason: 'GENESIS_MISMATCH' });
  });

  it('CHAIN_HASH_MISMATCH when an entry field is modified', () => {
    const e = clone(build3());
    e[1]!.payload_hash = '0'.repeat(64);
    const r = verifyChain(CHAIN, e);
    expect(r).toMatchObject({ status: 'BROKEN', reason: 'CHAIN_HASH_MISMATCH' });
  });

  it('CHAIN_LINK_BROKEN when a link is severed', () => {
    const e = clone(build3());
    e[2]!.prev_chain_hash = 'f'.repeat(64);
    const r = verifyChain(CHAIN, e);
    expect(r).toMatchObject({ status: 'BROKEN', reason: 'CHAIN_LINK_BROKEN' });
  });

  it('SEQ_INVALID when a middle entry is deleted', () => {
    const e = clone(build3());
    e.splice(1, 1);
    const r = verifyChain(CHAIN, e);
    expect(r).toMatchObject({ status: 'BROKEN', reason: 'SEQ_INVALID' });
  });

  it('DUPLICATE_SOURCE when the same source repeats', () => {
    const e: WardEntry[] = [];
    e.push(appendEntry(e, { chainId: CHAIN, issuerId: ISSUER, sourceKind: 'AEE', sourceId: 'dup', payloadHash: 'a'.repeat(64) }));
    e.push(appendEntry(e, { chainId: CHAIN, issuerId: ISSUER, sourceKind: 'AEE', sourceId: 'dup', payloadHash: 'b'.repeat(64) }));
    const r = verifyChain(CHAIN, e);
    expect(r).toMatchObject({ status: 'BROKEN', reason: 'DUPLICATE_SOURCE' });
  });

  it('TIP_MISMATCH when a tip hash does not match the chain', () => {
    const entries = build3();
    const tip = computeTip(CHAIN, entries, 3);
    tip.tip_chain_hash = '0'.repeat(64);
    const r = verifyChain(CHAIN, entries, { tips: [tip] });
    expect(r).toMatchObject({ status: 'BROKEN', reason: 'TIP_MISMATCH' });
  });

  it('signed tip verifies and counts a signature', () => {
    const entries = build3();
    const kp = generateKeypair();
    const sig = signTipHash(entries[2]!.chain_hash, kp.privateKey);
    const tip = computeTip(CHAIN, entries, 3, { sig, keyId: kp.keyId });
    const r = verifyChain(CHAIN, entries, { tips: [tip], publicKey: kp.publicKey });
    expect(r.status).toBe('INTACT');
    if (r.status === 'INTACT') {
      expect(r.tips_verified).toBe(1);
      expect(r.signatures_verified).toBe(1);
    }
  });

  it('TIP_SIGNATURE_INVALID when the signature is forged', () => {
    const entries = build3();
    const kp = generateKeypair();
    const other = generateKeypair();
    const sig = signTipHash(entries[2]!.chain_hash, other.privateKey);
    const tip = computeTip(CHAIN, entries, 3, { sig, keyId: kp.keyId });
    const r = verifyChain(CHAIN, entries, { tips: [tip], publicKey: kp.publicKey });
    expect(r).toMatchObject({ status: 'BROKEN', reason: 'TIP_SIGNATURE_INVALID' });
  });

  it('PARTIAL when a tip references a seq beyond the chain', () => {
    const entries = build3();
    const tip = computeTip(CHAIN, entries, 3);
    tip.tip_seq = 99;
    const r = verifyChain(CHAIN, entries, { tips: [tip] });
    expect(r).toMatchObject({ status: 'PARTIAL', reason: 'INCOMPLETE_CHAIN' });
  });

  it('warns when a signed tip has no public key', () => {
    const entries = build3();
    const kp = generateKeypair();
    const sig = signTipHash(entries[2]!.chain_hash, kp.privateKey);
    const tip = computeTip(CHAIN, entries, 3, { sig, keyId: kp.keyId });
    const r = verifyChain(CHAIN, entries, { tips: [tip] });
    expect(r.status).toBe('INTACT');
    if (r.status === 'INTACT') {
      expect(r.warnings.length).toBe(1);
      expect(r.signatures_verified).toBe(0);
    }
  });
});

describe('key_id binding (audit finding 1)', () => {
  it('deriveKeyId reproduces the keyId minted by generateKeypair', () => {
    const kp = generateKeypair();
    expect(deriveKeyId(kp.publicKey)).toBe(kp.keyId);
  });

  it('KEY_ID_MISMATCH when tip.key_id differs from the verifying key fingerprint', () => {
    const entries = build3();
    const kp = generateKeypair();
    // Valid signature by kp, but the tip claims some other key_id.
    const sig = signTipHash(entries[2]!.chain_hash, kp.privateKey);
    const tip = computeTip(CHAIN, entries, 3, { sig, keyId: 'DEADBEEFDEADBEEF' });
    const r = verifyChain(CHAIN, entries, { tips: [tip], publicKey: kp.publicKey });
    expect(r).toMatchObject({ status: 'BROKEN', reason: 'KEY_ID_MISMATCH' });
  });

  it('KEY_ID_MISMATCH when opts.expectedKeyId does not match tip.key_id', () => {
    const entries = build3();
    const kp = generateKeypair();
    const sig = signTipHash(entries[2]!.chain_hash, kp.privateKey);
    const tip = computeTip(CHAIN, entries, 3, { sig, keyId: kp.keyId });
    const r = verifyChain(CHAIN, entries, {
      tips: [tip],
      publicKey: kp.publicKey,
      expectedKeyId: 'did:example:someone-else',
    });
    expect(r).toMatchObject({ status: 'BROKEN', reason: 'KEY_ID_MISMATCH' });
  });

  it('INTACT when tip.key_id matches the verifying key fingerprint', () => {
    const entries = build3();
    const kp = generateKeypair();
    const sig = signTipHash(entries[2]!.chain_hash, kp.privateKey);
    const tip = computeTip(CHAIN, entries, 3, { sig, keyId: kp.keyId });
    const r = verifyChain(CHAIN, entries, { tips: [tip], publicKey: kp.publicKey });
    expect(r.status).toBe('INTACT');
    if (r.status === 'INTACT') expect(r.signatures_verified).toBe(1);
  });

  it('opts.expectedKeyId asserts identity even without a public key', () => {
    const entries = build3();
    const kp = generateKeypair();
    const sig = signTipHash(entries[2]!.chain_hash, kp.privateKey);
    const tip = computeTip(CHAIN, entries, 3, { sig, keyId: kp.keyId });
    const r = verifyChain(CHAIN, entries, { tips: [tip], expectedKeyId: 'other' });
    expect(r).toMatchObject({ status: 'BROKEN', reason: 'KEY_ID_MISMATCH' });
  });
});

describe('external anchor (audit finding 2)', () => {
  it('INTACT when the anchored tip matches the computed head', () => {
    const entries = build3();
    const tip = computeTip(CHAIN, entries, 3);
    const r = verifyChain(CHAIN, entries, {
      anchor: { expectedTip: tip, expectedHeadSeq: 3 },
    });
    expect(r.status).toBe('INTACT');
  });

  it('accepts a bare tip_chain_hash string as the anchor', () => {
    const entries = build3();
    const r = verifyChain(CHAIN, entries, {
      anchor: { expectedTip: entries[2]!.chain_hash },
    });
    expect(r.status).toBe('INTACT');
  });

  it('TRUNCATED_BEHIND_ANCHOR when the tail was dropped below the anchor seq', () => {
    const entries = build3();
    const anchorTip = computeTip(CHAIN, entries, 3);
    const truncated = entries.slice(0, 2); // drop seq=3
    const r = verifyChain(CHAIN, truncated, {
      anchor: { expectedTip: anchorTip, expectedHeadSeq: 3 },
    });
    expect(r).toMatchObject({ status: 'BROKEN', reason: 'TRUNCATED_BEHIND_ANCHOR' });
  });

  it('TIP_MISMATCH (anchor context) when a rewritten chain diverges from the pinned tip', () => {
    const original = build3();
    const anchorTip = computeTip(CHAIN, original, 3);
    // Attacker rewrites the chain into a different-but-internally-valid chain.
    const rewritten: WardEntry[] = [];
    rewritten.push(appendEntry(rewritten, { chainId: CHAIN, issuerId: ISSUER, sourceKind: 'AEE', sourceId: 'x1', payloadHash: 'd'.repeat(64) }));
    rewritten.push(appendEntry(rewritten, { chainId: CHAIN, issuerId: ISSUER, sourceKind: 'AOCL', sourceId: 'x2', payloadHash: 'e'.repeat(64) }));
    rewritten.push(appendEntry(rewritten, { chainId: CHAIN, issuerId: ISSUER, sourceKind: 'VOLT', sourceId: 'x3', payloadHash: 'f'.repeat(64) }));
    const r = verifyChain(CHAIN, rewritten, { anchor: { expectedTip: anchorTip, expectedHeadSeq: 3 } });
    expect(r).toMatchObject({ status: 'BROKEN', reason: 'TIP_MISMATCH' });
    expect((r as { details?: { anchor?: boolean } }).details?.anchor).toBe(true);
  });
});

describe('requireSignatures (audit finding 3)', () => {
  it('SIGNATURE_REQUIRED when a tip has no signature', () => {
    const entries = build3();
    const tip = computeTip(CHAIN, entries, 3); // unsigned
    const r = verifyChain(CHAIN, entries, { tips: [tip], requireSignatures: true });
    expect(r).toMatchObject({ status: 'BROKEN', reason: 'SIGNATURE_REQUIRED' });
  });

  it('SIGNATURE_REQUIRED when a signed tip cannot be verified (no public key)', () => {
    const entries = build3();
    const kp = generateKeypair();
    const sig = signTipHash(entries[2]!.chain_hash, kp.privateKey);
    const tip = computeTip(CHAIN, entries, 3, { sig, keyId: kp.keyId });
    const r = verifyChain(CHAIN, entries, { tips: [tip], requireSignatures: true });
    expect(r).toMatchObject({ status: 'BROKEN', reason: 'SIGNATURE_REQUIRED' });
  });

  it('INTACT when requireSignatures is met by a verified tip', () => {
    const entries = build3();
    const kp = generateKeypair();
    const sig = signTipHash(entries[2]!.chain_hash, kp.privateKey);
    const tip = computeTip(CHAIN, entries, 3, { sig, keyId: kp.keyId });
    const r = verifyChain(CHAIN, entries, { tips: [tip], publicKey: kp.publicKey, requireSignatures: true });
    expect(r.status).toBe('INTACT');
  });

  it('warns (not fails) on a signature downgrade when requireSignatures is false', () => {
    const entries = build3();
    const kp = generateKeypair();
    // A tip that declares a key_id (signed-capable) but arrives without a sig.
    const tip = computeTip(CHAIN, entries, 3, { keyId: kp.keyId });
    const r = verifyChain(CHAIN, entries, { tips: [tip] });
    expect(r.status).toBe('INTACT');
    if (r.status === 'INTACT') {
      expect(r.warnings.length).toBe(1);
      expect(r.warnings[0]).toMatch(/downgrade/);
    }
  });
});

describe('per-entry hash-scheme selection (SPEC §16.1, VERIFICATION.md §3 Step 2)', () => {
  const clone2 = (e: WardEntry[]): WardEntry[] => JSON.parse(JSON.stringify(e));

  it('a v0.2 writer-built chain verifies INTACT under the canonical scheme', () => {
    const r = verifyChain(CHAIN, build3());
    expect(r.status).toBe('INTACT');
    if (r.status === 'INTACT') expect(r.ward_version).toBe('0.2');
  });

  it('a legacy v0.1 entry still verifies INTACT under Appendix A (verify-only)', () => {
    // Build a v0.1 entry directly with the legacy pipe-concatenation preimage,
    // since the writer refuses to create new v0.1 entries.
    const genesis = genesisHash(CHAIN);
    const legacyEntry: WardEntry = {
      ward_version: '0.1',
      ward_entry_id: 'legacy-e1',
      chain_id: CHAIN,
      seq: 1,
      witnessed_at: '2026-01-01T00:00:00.000Z',
      source_kind: 'AEE',
      source_id: 'legacy-s1',
      payload_hash: 'a'.repeat(64),
      prev_chain_hash: genesis,
      chain_hash: '',
      issuer_id: ISSUER,
    };
    legacyEntry.chain_hash = legacyChainHash({
      prevChainHash: genesis,
      chainId: CHAIN,
      seq: 1,
      wardEntryId: legacyEntry.ward_entry_id,
      timestamp: legacyEntry.witnessed_at,
      sourceKind: legacyEntry.source_kind,
      sourceId: legacyEntry.source_id,
      payloadHash: legacyEntry.payload_hash,
    });
    const r = verifyChain(CHAIN, [legacyEntry]);
    expect(r.status).toBe('INTACT');
  });

  it('CHAIN_HASH_MISMATCH with a detail naming the version for an unrecognized ward_version', () => {
    const e = clone2(build3());
    (e[0]! as WardEntry & { ward_version: string }).ward_version = '9.9';
    const r = verifyChain(CHAIN, e);
    expect(r).toMatchObject({ status: 'BROKEN', reason: 'CHAIN_HASH_MISMATCH' });
    if (r.status === 'BROKEN') {
      expect(JSON.stringify(r.details)).toMatch(/9\.9/);
    }
  });

  it('warns when a v0.1 entry ward_entry_id contains the delimiter "|" (Appendix A)', () => {
    const genesis = genesisHash(CHAIN);
    const wardEntryId = 'legacy|injected';
    const chainHashValue = legacyChainHash({
      prevChainHash: genesis,
      chainId: CHAIN,
      seq: 1,
      wardEntryId,
      timestamp: '2026-01-01T00:00:00.000Z',
      sourceKind: 'AEE',
      sourceId: 'legacy-s1',
      payloadHash: 'a'.repeat(64),
    });
    const legacyEntry: WardEntry = {
      ward_version: '0.1',
      ward_entry_id: wardEntryId,
      chain_id: CHAIN,
      seq: 1,
      witnessed_at: '2026-01-01T00:00:00.000Z',
      source_kind: 'AEE',
      source_id: 'legacy-s1',
      payload_hash: 'a'.repeat(64),
      prev_chain_hash: genesis,
      chain_hash: chainHashValue,
      issuer_id: ISSUER,
    };
    const r = verifyChain(CHAIN, [legacyEntry]);
    expect(r.status).toBe('INTACT');
    if (r.status === 'INTACT') {
      expect(r.warnings.some((w) => /\|/.test(w))).toBe(true);
    }
  });
});

describe('Step 0 — entry well-formedness (VERIFICATION.md §3 Step 0)', () => {
  const clone3 = (e: WardEntry[]): WardEntry[] => JSON.parse(JSON.stringify(e));

  it('SCHEMA_INVALID when a required field is missing', () => {
    const e = clone3(build3()) as Array<Partial<WardEntry>>;
    delete e[0]!.issuer_id;
    const r = verifyChain(CHAIN, e as WardEntry[]);
    expect(r).toMatchObject({ status: 'BROKEN', reason: 'SCHEMA_INVALID' });
  });

  it('SCHEMA_INVALID when a hash field is not 64-char lowercase hex', () => {
    const e = clone3(build3());
    e[0]!.payload_hash = 'not-a-hash';
    const r = verifyChain(CHAIN, e);
    expect(r).toMatchObject({ status: 'BROKEN', reason: 'SCHEMA_INVALID' });
  });

  it('SCHEMA_INVALID when seq is not an integer >= 1', () => {
    const e = clone3(build3()) as Array<WardEntry & { seq: unknown }>;
    e[0]!.seq = 0;
    const r = verifyChain(CHAIN, e as WardEntry[]);
    expect(r).toMatchObject({ status: 'BROKEN', reason: 'SCHEMA_INVALID' });
  });

  it('SCHEMA_INVALID when seq exceeds 2^53 - 1', () => {
    const e = clone3(build3());
    e[0]!.seq = Number.MAX_SAFE_INTEGER + 2;
    const r = verifyChain(CHAIN, e);
    expect(r).toMatchObject({ status: 'BROKEN', reason: 'SCHEMA_INVALID' });
  });

  it('SCHEMA_INVALID when a hash-body member is null', () => {
    const e = clone3(build3());
    (e[0] as unknown as { issuer_id: unknown }).issuer_id = null;
    const r = verifyChain(CHAIN, e);
    expect(r).toMatchObject({ status: 'BROKEN', reason: 'SCHEMA_INVALID' });
  });

  it('SCHEMA_INVALID when chain_id contains the reserved "::" sequence', () => {
    const e = clone3(build3());
    e[0]!.chain_id = 'ward:org/quox::env/staging';
    const r = verifyChain('ward:org/quox::env/staging', e);
    expect(r).toMatchObject({ status: 'BROKEN', reason: 'SCHEMA_INVALID' });
  });

  it('SCHEMA_INVALID when a hash-body string is not well-formed NFC', () => {
    const e = clone3(build3());
    e[0]!.ward_entry_id = 'é'; // "e" + combining acute (NFD, not NFC)
    const r = verifyChain(CHAIN, e);
    expect(r).toMatchObject({ status: 'BROKEN', reason: 'SCHEMA_INVALID' });
  });

  it('SCHEMA_INVALID when source_kind is not a recognized enum value', () => {
    const e = clone3(build3());
    (e[0] as unknown as { source_kind: string }).source_kind = 'BOGUS';
    const r = verifyChain(CHAIN, e);
    expect(r).toMatchObject({ status: 'BROKEN', reason: 'SCHEMA_INVALID' });
  });

  it('a well-formed chain still verifies INTACT (Step 0 does not false-positive)', () => {
    expect(verifyChain(CHAIN, build3()).status).toBe('INTACT');
  });
});

describe('version monotonicity (SPEC §16.1, VERIFICATION.md §3 Step 2.4)', () => {
  it('VERSION_DOWNGRADE when a v0.1 entry follows a v0.2 entry', () => {
    const v02 = appendEntry([], { chainId: CHAIN, issuerId: ISSUER, sourceKind: 'AEE', sourceId: 's1', payloadHash: 'a'.repeat(64) });
    const v01: WardEntry = {
      ward_version: '0.1',
      ward_entry_id: 'legacy-e2',
      chain_id: CHAIN,
      seq: 2,
      witnessed_at: '2026-01-01T00:00:01.000Z',
      source_kind: 'AEE',
      source_id: 'legacy-s2',
      payload_hash: 'b'.repeat(64),
      prev_chain_hash: v02.chain_hash,
      chain_hash: '',
      issuer_id: ISSUER,
    };
    v01.chain_hash = legacyChainHash({
      prevChainHash: v01.prev_chain_hash,
      chainId: CHAIN,
      seq: v01.seq,
      wardEntryId: v01.ward_entry_id,
      timestamp: v01.witnessed_at,
      sourceKind: v01.source_kind,
      sourceId: v01.source_id,
      payloadHash: v01.payload_hash,
    });
    const r = verifyChain(CHAIN, [v02, v01]);
    expect(r).toMatchObject({ status: 'BROKEN', reason: 'VERSION_DOWNGRADE' });
  });
});
