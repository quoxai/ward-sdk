import { describe, it, expect } from 'vitest';
import { mkdtempSync, readdirSync, appendFileSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { InMemoryStore, FileStore } from '../src/store/index.js';
import type { WardStore } from '../src/store/index.js';
import { appendEntry } from '../src/chain.js';
import { verifyChain } from '../src/verify.js';
import type { WardEntry } from '../src/types.js';

const CHAIN = 'ward:org/quox/env/staging';
const ISSUER = 'ward-issuer-stg-01';

function next(store: WardStore, sourceId: string, kind: 'AEE' | 'AOCL' | 'VOLT' = 'AEE'): WardEntry {
  const e = appendEntry(store.getEntries(CHAIN), {
    chainId: CHAIN,
    issuerId: ISSUER,
    sourceKind: kind,
    sourceId,
    payloadHash: 'a'.repeat(64),
  });
  store.appendEntry(e);
  return e;
}

function runContract(make: () => WardStore, label: string) {
  describe(`WardStore contract — ${label}`, () => {
    it('appends and reads back entries in seq order, chain verifies INTACT', () => {
      const store = make();
      next(store, 's1', 'AEE');
      next(store, 's2', 'AOCL');
      next(store, 's3', 'VOLT');
      const entries = store.getEntries(CHAIN);
      expect(entries.map((e) => e.seq)).toEqual([1, 2, 3]);
      expect(verifyChain(CHAIN, entries).status).toBe('INTACT');
      expect(store.getHead(CHAIN)!.seq).toBe(3);
      expect(store.listChains()).toContain(CHAIN);
    });

    it('rejects a seq gap (append-only discipline)', () => {
      const store = make();
      next(store, 's1');
      const bad: WardEntry = { ...store.getHead(CHAIN)!, seq: 5, ward_entry_id: 'x', source_id: 'sX' };
      expect(() => store.appendEntry(bad)).toThrow(/seq/);
    });

    it('rejects a duplicate (source_kind, source_id) — SPEC §6.3', () => {
      const store = make();
      next(store, 'dup', 'AEE');
      const dupe = appendEntry(store.getEntries(CHAIN), {
        chainId: CHAIN,
        issuerId: ISSUER,
        sourceKind: 'AEE',
        sourceId: 'dup',
        payloadHash: 'b'.repeat(64),
      });
      expect(() => store.appendEntry(dupe)).toThrow(/duplicate/);
    });

    it('stores and reads tips', () => {
      const store = make();
      next(store, 's1');
      store.putTip({ tip_id: 't1', chain_id: CHAIN, tip_seq: 1, tip_chain_hash: store.getHead(CHAIN)!.chain_hash, entry_count: 1, created_at: '2026-03-05T15:01:00.000Z' });
      expect(store.getTips(CHAIN)).toHaveLength(1);
    });
  });
}

runContract(() => new InMemoryStore(), 'InMemoryStore');
runContract(() => new FileStore(mkdtempSync(join(tmpdir(), 'ward-fs-'))), 'FileStore');

describe('FileStore durability', () => {
  it('reloads entries and tips from disk in a fresh instance', () => {
    const dir = mkdtempSync(join(tmpdir(), 'ward-fs-durable-'));
    const a = new FileStore(dir);
    a.appendEntry(appendEntry([], { chainId: CHAIN, issuerId: ISSUER, sourceKind: 'AEE', sourceId: 's1', payloadHash: 'a'.repeat(64) }));
    a.appendEntry(appendEntry(a.getEntries(CHAIN), { chainId: CHAIN, issuerId: ISSUER, sourceKind: 'AOCL', sourceId: 's2', payloadHash: 'b'.repeat(64) }));
    a.putTip({ tip_id: 't1', chain_id: CHAIN, tip_seq: 2, tip_chain_hash: a.getHead(CHAIN)!.chain_hash, entry_count: 2, created_at: '2026-03-05T15:01:00.000Z' });

    const b = new FileStore(dir);
    expect(b.getEntries(CHAIN).map((e) => e.seq)).toEqual([1, 2]);
    expect(b.getTips(CHAIN)).toHaveLength(1);
    expect(b.listChains()).toEqual([CHAIN]);
    expect(verifyChain(CHAIN, b.getEntries(CHAIN)).status).toBe('INTACT');
  });
});

describe('FileStore torn-write recovery (audit finding 4)', () => {
  function entriesFile(dir: string): string {
    const f = readdirSync(dir).find((n) => n.endsWith('.entries.ndjson'))!;
    return join(dir, f);
  }

  it('recovers a truncated final line, surfacing a warning', () => {
    const dir = mkdtempSync(join(tmpdir(), 'ward-torn-'));
    const a = new FileStore(dir);
    a.appendEntry(appendEntry([], { chainId: CHAIN, issuerId: ISSUER, sourceKind: 'AEE', sourceId: 's1', payloadHash: 'a'.repeat(64) }));
    a.appendEntry(appendEntry(a.getEntries(CHAIN), { chainId: CHAIN, issuerId: ISSUER, sourceKind: 'AOCL', sourceId: 's2', payloadHash: 'b'.repeat(64) }));
    // Simulate a crash mid-append: a truncated (unterminated) JSON line at EOF.
    appendFileSync(entriesFile(dir), '{"ward_version":"0.1","seq":3,"chain_id":"' + CHAIN, 'utf8');

    const b = new FileStore(dir);
    expect(b.getEntries(CHAIN).map((e) => e.seq)).toEqual([1, 2]);
    const warns = b.getWarnings(CHAIN);
    expect(warns.length).toBe(1);
    expect(warns[0]).toMatch(/truncated/i);
    expect(verifyChain(CHAIN, b.getEntries(CHAIN)).status).toBe('INTACT');
  });

  it('throws on a corrupt NON-final line (real corruption)', () => {
    const dir = mkdtempSync(join(tmpdir(), 'ward-corrupt-'));
    const a = new FileStore(dir);
    a.appendEntry(appendEntry([], { chainId: CHAIN, issuerId: ISSUER, sourceKind: 'AEE', sourceId: 's1', payloadHash: 'a'.repeat(64) }));
    a.appendEntry(appendEntry(a.getEntries(CHAIN), { chainId: CHAIN, issuerId: ISSUER, sourceKind: 'AOCL', sourceId: 's2', payloadHash: 'b'.repeat(64) }));
    const path = entriesFile(dir);
    const lines = readFileSync(path, 'utf8').split('\n').filter((l) => l.trim());
    // Corrupt the FIRST line, keep the last line intact.
    lines[0] = '{ this is not json';
    writeFileSync(path, lines.join('\n') + '\n', 'utf8');

    const b = new FileStore(dir);
    expect(() => b.getEntries(CHAIN)).toThrow();
  });
});

describe('FileStore torn-write recovery — tips (parity with entries)', () => {
  function tipsFile(dir: string): string {
    const f = readdirSync(dir).find((n) => n.endsWith('.tips.ndjson'))!;
    return join(dir, f);
  }

  it('recovers a truncated final tip line, surfacing a warning', () => {
    const dir = mkdtempSync(join(tmpdir(), 'ward-tips-torn-'));
    const a = new FileStore(dir);
    a.appendEntry(appendEntry([], { chainId: CHAIN, issuerId: ISSUER, sourceKind: 'AEE', sourceId: 's1', payloadHash: 'a'.repeat(64) }));
    a.putTip({ tip_id: 't1', chain_id: CHAIN, tip_seq: 1, tip_chain_hash: a.getHead(CHAIN)!.chain_hash, entry_count: 1, created_at: '2026-03-05T15:01:00.000Z' });
    // Simulate a crash mid-append: a truncated (unterminated) JSON line at EOF.
    appendFileSync(tipsFile(dir), '{"tip_id":"t2","chain_id":"' + CHAIN, 'utf8');

    const b = new FileStore(dir);
    expect(b.getTips(CHAIN).map((t) => t.tip_id)).toEqual(['t1']);
    const warns = b.getWarnings(CHAIN);
    expect(warns.length).toBe(1);
    expect(warns[0]).toMatch(/truncated/i);
  });

  it('throws on a corrupt NON-final tip line (real corruption)', () => {
    const dir = mkdtempSync(join(tmpdir(), 'ward-tips-corrupt-'));
    const a = new FileStore(dir);
    a.appendEntry(appendEntry([], { chainId: CHAIN, issuerId: ISSUER, sourceKind: 'AEE', sourceId: 's1', payloadHash: 'a'.repeat(64) }));
    a.putTip({ tip_id: 't1', chain_id: CHAIN, tip_seq: 1, tip_chain_hash: a.getHead(CHAIN)!.chain_hash, entry_count: 1, created_at: '2026-03-05T15:01:00.000Z' });
    a.putTip({ tip_id: 't2', chain_id: CHAIN, tip_seq: 2, tip_chain_hash: a.getHead(CHAIN)!.chain_hash, entry_count: 1, created_at: '2026-03-05T15:02:00.000Z' });
    const path = tipsFile(dir);
    const lines = readFileSync(path, 'utf8').split('\n').filter((l) => l.trim());
    // Corrupt the FIRST line, keep the last line intact.
    lines[0] = '{ this is not json';
    writeFileSync(path, lines.join('\n') + '\n', 'utf8');

    const b = new FileStore(dir);
    expect(() => b.getTips(CHAIN)).toThrow();
  });
});

describe('FileStore rejects duplicate JSON member names (SPEC §3.2 rule 5)', () => {
  function entriesFile(dir: string): string {
    const f = readdirSync(dir).find((n) => n.endsWith('.entries.ndjson'))!;
    return join(dir, f);
  }

  it('throws when an entry line has a duplicate top-level member name', () => {
    const dir = mkdtempSync(join(tmpdir(), 'ward-dup-'));
    const a = new FileStore(dir);
    a.appendEntry(appendEntry([], { chainId: CHAIN, issuerId: ISSUER, sourceKind: 'AEE', sourceId: 's1', payloadHash: 'a'.repeat(64) }));
    a.appendEntry(appendEntry(a.getEntries(CHAIN), { chainId: CHAIN, issuerId: ISSUER, sourceKind: 'AOCL', sourceId: 's2', payloadHash: 'b'.repeat(64) }));
    const path = entriesFile(dir);
    const lines = readFileSync(path, 'utf8').split('\n').filter((l) => l.trim());
    // Corrupt the FIRST (non-final) line with a duplicate member name so the
    // torn-write recovery path (which only tolerates a bad LAST line) can't
    // mask it — this must be real corruption, not a recoverable torn write.
    lines[0] = '{"seq":1,"seq":2,"chain_id":"' + CHAIN + '"}';
    writeFileSync(path, lines.join('\n') + '\n', 'utf8');

    const b = new FileStore(dir);
    expect(() => b.getEntries(CHAIN)).toThrow(/duplicate/i);
  });
});
