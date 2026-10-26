import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { appendEntry } from '../src/chain.js';
import { verifyChain } from '../src/verify.js';
import { genesisHash, chainHash as legacyChainHash } from '../src/crypto.js';
import type { WardEntry } from '../src/types.js';

/**
 * Cross-check: the SDK writer (src/chain.ts) MUST produce chain hashes
 * identical to an independent reference implementation of the current
 * WARD v0.2 canonical-JSON scheme (SPEC §4.4), reproduced here verbatim
 * (mirrors ward/tools/gen-examples.mjs, the spec repo's own reference). If
 * they match and the SDK verifier accepts the result, the writer/verifier
 * split is proven drift-free. A second block below cross-checks the legacy
 * v0.1 pipe-concatenation scheme (Appendix A), which the writer no longer
 * produces but the verifier must still accept.
 */

const CHAIN = 'ward:qluster/controller';
const ISSUER = 'qluster:controller';

// Verbatim port of wardVerify.js genesisHash() — unchanged by v0.2 (SPEC §4.3).
function qlogsGenesis(chainId: string): string {
  return createHash('sha256').update(`WARD-GENESIS|${chainId}`, 'utf8').digest('hex');
}

// Independent reference of the v0.2 canonical-JSON hash body (SPEC §4.4),
// written from scratch against the spec text rather than importing src/.
function refCanonicalize(value: unknown): string {
  if (value === undefined) throw new Error('undefined is not serializable');
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') return String(value);
  if (typeof value === 'string') return JSON.stringify(value.normalize('NFC'));
  if (Array.isArray(value)) return '[' + value.map(refCanonicalize).join(',') + ']';
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).filter((k) => record[k] !== undefined).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + refCanonicalize(record[k])).join(',') + '}';
}

function refChainHashV2(e: {
  ward_version: string;
  ward_entry_id: string;
  chain_id: string;
  seq: number;
  witnessed_at: string;
  source_kind: string;
  source_id: string;
  payload_hash: string;
  prev_chain_hash: string;
  issuer_id: string;
}): string {
  const body = {
    chain_id: e.chain_id,
    issuer_id: e.issuer_id,
    payload_hash: e.payload_hash,
    prev_chain_hash: e.prev_chain_hash,
    seq: e.seq,
    source_id: e.source_id,
    source_kind: e.source_kind,
    ward_entry_id: e.ward_entry_id,
    ward_version: e.ward_version,
    witnessed_at: e.witnessed_at,
  };
  return createHash('sha256').update(refCanonicalize(body), 'utf8').digest('hex');
}

describe('writer/verifier split — no drift with an independent v0.2 reference', () => {
  it('SDK genesis matches the independent genesis preimage (SPEC §4.3, unchanged by v0.2)', () => {
    expect(genesisHash(CHAIN)).toBe(qlogsGenesis(CHAIN));
  });

  it('SDK chain_hash matches the independent v0.2 canonical-JSON preimage at every seq', () => {
    const entries: WardEntry[] = [];
    const seeds = [
      { sourceKind: 'AEE' as const, sourceId: 'aee-1', payloadHash: 'a'.repeat(64) },
      { sourceKind: 'AOCL' as const, sourceId: 'aocl-2', payloadHash: 'b'.repeat(64) },
      { sourceKind: 'VOLT' as const, sourceId: 'volt-3', payloadHash: 'c'.repeat(64) },
    ];
    for (const s of seeds) {
      entries.push(appendEntry(entries, { chainId: CHAIN, issuerId: ISSUER, ...s }));
    }

    let prev = qlogsGenesis(CHAIN);
    for (const e of entries) {
      expect(e.ward_version).toBe('0.2');
      const expected = refChainHashV2({
        ward_version: e.ward_version,
        ward_entry_id: e.ward_entry_id,
        chain_id: e.chain_id,
        seq: e.seq,
        witnessed_at: e.witnessed_at,
        source_kind: e.source_kind,
        source_id: e.source_id,
        payload_hash: e.payload_hash,
        prev_chain_hash: e.prev_chain_hash,
        issuer_id: e.issuer_id,
      });
      expect(e.prev_chain_hash).toBe(prev);
      expect(e.chain_hash).toBe(expected);
      prev = e.chain_hash;
    }

    // And the SDK verifier accepts the writer's output.
    expect(verifyChain(CHAIN, entries).status).toBe('INTACT');
  });

  it('any tamper on a writer-produced chain verifies FAIL', () => {
    const entries: WardEntry[] = [];
    entries.push(appendEntry(entries, { chainId: CHAIN, issuerId: ISSUER, sourceKind: 'AEE', sourceId: 'x1', payloadHash: 'a'.repeat(64) }));
    entries.push(appendEntry(entries, { chainId: CHAIN, issuerId: ISSUER, sourceKind: 'AEE', sourceId: 'x2', payloadHash: 'b'.repeat(64) }));
    const tampered = JSON.parse(JSON.stringify(entries)) as WardEntry[];
    tampered[1]!.payload_hash = '0'.repeat(64);
    expect(verifyChain(CHAIN, tampered).status).toBe('BROKEN');
  });
});

describe('legacy v0.1 scheme — verify-only cross-check (SPEC Appendix A)', () => {
  // Verbatim port of the pre-v0.2 QLOGS writer's computeEntryHash(): the
  // writer no longer produces this scheme (buildEntry refuses new v0.1
  // entries), but the verifier must still accept chains written under it.
  function qlogsEntryHashV1(chainId: string, e: {
    prev_hash: string;
    seq: number;
    ward_entry_id: string;
    ts: string;
    source_kind: string;
    source_id: string;
    payload_hash: string;
  }): string {
    const input = [
      e.prev_hash,
      chainId,
      String(e.seq),
      e.ward_entry_id,
      e.ts,
      e.source_kind,
      e.source_id,
      e.payload_hash,
    ].join('|');
    return createHash('sha256').update(input, 'utf8').digest('hex');
  }

  it('SDK legacy chainHash matches the pre-v0.2 QLOGS preimage, and the verifier accepts it', () => {
    const genesis = qlogsGenesis(CHAIN);
    const entry: WardEntry = {
      ward_version: '0.1',
      ward_entry_id: 'legacy-e1',
      chain_id: CHAIN,
      seq: 1,
      witnessed_at: '2026-01-01T00:00:00.000Z',
      source_kind: 'AEE',
      source_id: 'legacy-1',
      payload_hash: 'a'.repeat(64),
      prev_chain_hash: genesis,
      chain_hash: '',
      issuer_id: ISSUER,
    };
    const expected = qlogsEntryHashV1(CHAIN, {
      prev_hash: entry.prev_chain_hash,
      seq: entry.seq,
      ward_entry_id: entry.ward_entry_id,
      ts: entry.witnessed_at,
      source_kind: entry.source_kind,
      source_id: entry.source_id,
      payload_hash: entry.payload_hash,
    });
    entry.chain_hash = legacyChainHash({
      prevChainHash: entry.prev_chain_hash,
      chainId: CHAIN,
      seq: entry.seq,
      wardEntryId: entry.ward_entry_id,
      timestamp: entry.witnessed_at,
      sourceKind: entry.source_kind,
      sourceId: entry.source_id,
      payloadHash: entry.payload_hash,
    });
    expect(entry.chain_hash).toBe(expected);
    expect(verifyChain(CHAIN, [entry]).status).toBe('INTACT');
  });
});
