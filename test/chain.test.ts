import { describe, it, expect } from 'vitest';
import {
  buildEntry,
  appendEntry,
  headOf,
  chainDescriptor,
  computeTip,
} from '../src/chain.js';
import { genesisHash } from '../src/crypto.js';
import type { WardEntry } from '../src/types.js';

const CHAIN = 'ward:org/quox/env/staging';
const ISSUER = 'ward-issuer-stg-01';

function build3(): WardEntry[] {
  const entries: WardEntry[] = [];
  entries.push(
    appendEntry(entries, { chainId: CHAIN, issuerId: ISSUER, sourceKind: 'AEE', sourceId: 's1', payloadHash: 'a'.repeat(64) }),
  );
  entries.push(
    appendEntry(entries, { chainId: CHAIN, issuerId: ISSUER, sourceKind: 'AOCL', sourceId: 's2', payloadHash: 'b'.repeat(64) }),
  );
  entries.push(
    appendEntry(entries, { chainId: CHAIN, issuerId: ISSUER, sourceKind: 'VOLT', sourceId: 's3', payloadHash: 'c'.repeat(64) }),
  );
  return entries;
}

describe('chain math — writer side (SPEC §4, §11)', () => {
  it('headOf empty chain is genesis at seq 0', () => {
    const head = headOf(CHAIN, []);
    expect(head).toEqual({ seq: 0, chainHash: genesisHash(CHAIN) });
  });

  it('first entry links to genesis with seq 1', () => {
    const e = appendEntry([], { chainId: CHAIN, issuerId: ISSUER, sourceKind: 'AEE', sourceId: 's1', payloadHash: 'a'.repeat(64) });
    expect(e.seq).toBe(1);
    expect(e.prev_chain_hash).toBe(genesisHash(CHAIN));
    expect(e.chain_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(e.ward_version).toBe('0.2');
  });

  it('appendEntry links each entry to its predecessor', () => {
    const entries = build3();
    expect(entries.map((e) => e.seq)).toEqual([1, 2, 3]);
    expect(entries[1]!.prev_chain_hash).toBe(entries[0]!.chain_hash);
    expect(entries[2]!.prev_chain_hash).toBe(entries[1]!.chain_hash);
  });

  it('buildEntry rejects an unrecognized source_kind (SPEC §9)', () => {
    expect(() =>
      buildEntry({
        chainId: CHAIN,
        issuerId: ISSUER,
        // @ts-expect-error deliberately invalid
        sourceKind: 'BOGUS',
        sourceId: 's',
        payloadHash: 'a'.repeat(64),
        prevChainHash: genesisHash(CHAIN),
        seq: 1,
      }),
    ).toThrow(/source_kind/);
  });

  it('chainDescriptor summarizes head + genesis', () => {
    const entries = build3();
    const d = chainDescriptor(CHAIN, 'staging', entries);
    expect(d.genesis_hash).toBe(genesisHash(CHAIN));
    expect(d.entry_count).toBe(3);
    expect(d.head_seq).toBe(3);
    expect(d.head_chain_hash).toBe(entries[2]!.chain_hash);
  });

  it('computeTip checkpoints the entry at tip_seq', () => {
    const entries = build3();
    const tip = computeTip(CHAIN, entries, 2);
    expect(tip.tip_seq).toBe(2);
    expect(tip.tip_chain_hash).toBe(entries[1]!.chain_hash);
    expect(tip.entry_count).toBe(2);
  });

  it('computeTip throws when no entry has tip_seq', () => {
    expect(() => computeTip(CHAIN, build3(), 99)).toThrow(/tip_seq/);
  });
});

describe('chain math — v0.2 writer defaults (SPEC §16.1)', () => {
  it('buildEntry defaults ward_version to 0.2', () => {
    const e = appendEntry([], { chainId: CHAIN, issuerId: ISSUER, sourceKind: 'AEE', sourceId: 's1', payloadHash: 'a'.repeat(64) });
    expect(e.ward_version).toBe('0.2');
  });

  it('buildEntry refuses to create a new v0.1 entry', () => {
    expect(() =>
      buildEntry({
        chainId: CHAIN,
        issuerId: ISSUER,
        sourceKind: 'AEE',
        sourceId: 's1',
        payloadHash: 'a'.repeat(64),
        prevChainHash: genesisHash(CHAIN),
        seq: 1,
        wardVersion: '0.1',
      }),
    ).toThrow(/0\.1|ward_version/);
  });

  it('buildEntry rejects a chain_id containing "::" (SPEC §5.2)', () => {
    expect(() =>
      buildEntry({
        chainId: 'ward:org/quox::env/staging',
        issuerId: ISSUER,
        sourceKind: 'AEE',
        sourceId: 's1',
        payloadHash: 'a'.repeat(64),
        prevChainHash: genesisHash(CHAIN),
        seq: 1,
      }),
    ).toThrow(/::/);
  });
});

describe('chain_id "::" rejection mirrored across writer-side paths', () => {
  it('chainDescriptor rejects a chain_id containing "::"', () => {
    expect(() => chainDescriptor('ward:org/quox::env/staging', 'staging', [])).toThrow(/::/);
  });

  it('computeTip rejects a chain_id containing "::"', () => {
    const entries = build3();
    expect(() => computeTip('ward:org/quox::env/staging', entries, 1)).toThrow(/::/);
  });
});
