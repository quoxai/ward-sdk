import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { sha256, genesisHash, chainHash, canonicalize, payloadHash } from '../src/crypto.js';

describe('crypto — SPEC §3.2, §4', () => {
  it('sha256 returns 64-char lowercase hex', () => {
    const h = sha256('hello');
    expect(h).toMatch(/^[0-9a-f]{64}$/);
    expect(h).toBe(createHash('sha256').update('hello', 'utf8').digest('hex'));
  });

  it('genesisHash = SHA-256("WARD-GENESIS|" + chain_id) — SPEC §4.3', () => {
    const chainId = 'ward:org/quox/env/staging';
    const expected = createHash('sha256')
      .update(`WARD-GENESIS|${chainId}`, 'utf8')
      .digest('hex');
    expect(genesisHash(chainId)).toBe(expected);
  });

  it('chainHash uses the exact pipe-separated preimage — SPEC §4.4', () => {
    const input = {
      prevChainHash: 'p'.repeat(64),
      chainId: 'ward:org/quox/env/staging',
      seq: 1,
      wardEntryId: '01WARD-STG-E001',
      timestamp: '2026-03-05T15:00:00.000Z',
      sourceKind: 'AEE',
      sourceId: 'aee-env-001',
      payloadHash: 'a'.repeat(64),
    };
    const preimage = [
      input.prevChainHash,
      input.chainId,
      '1',
      input.wardEntryId,
      input.timestamp,
      input.sourceKind,
      input.sourceId,
      input.payloadHash,
    ].join('|');
    expect(chainHash(input)).toBe(sha256(preimage));
  });

  it('chainHash is deterministic and seq-sensitive', () => {
    const base = {
      prevChainHash: 'p'.repeat(64),
      chainId: 'c',
      seq: 1,
      wardEntryId: 'e',
      timestamp: 't',
      sourceKind: 'AEE',
      sourceId: 's',
      payloadHash: 'a'.repeat(64),
    };
    expect(chainHash(base)).toBe(chainHash(base));
    expect(chainHash(base)).not.toBe(chainHash({ ...base, seq: 2 }));
  });

  it('canonicalize sorts keys at every nesting level, no whitespace', () => {
    const c = canonicalize({ b: 1, a: { d: 2, c: 3 } });
    expect(c).toBe('{"a":{"c":3,"d":2},"b":1}');
  });

  it('canonicalize is order-independent (payloadHash stable)', () => {
    expect(payloadHash({ x: 1, y: 2 })).toBe(payloadHash({ y: 2, x: 1 }));
  });
});
