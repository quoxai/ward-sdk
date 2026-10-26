import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Ajv2020, type ValidateFunction } from 'ajv/dist/2020.js';
import { appendEntry, computeTip, chainDescriptor } from '../src/chain.js';
import { verifyChain } from '../src/verify.js';
import { generateKeypair, signTipHash } from '../src/sign.js';
import type { WardEntry, ChainExport } from '../src/types.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SCHEMAS = join(ROOT, 'schemas');
const FIX = join(ROOT, 'conformance', 'fixtures');

function loadSchema(name: string): object {
  return JSON.parse(readFileSync(join(SCHEMAS, name), 'utf8'));
}

const CHAIN = 'ward:org/quox/env/staging';
const ISSUER = 'ward-issuer-stg-01';

let vEntry: ValidateFunction;
let vChain: ValidateFunction;
let vTip: ValidateFunction;
let vResult: ValidateFunction;

beforeAll(() => {
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  vEntry = ajv.compile(loadSchema('ward-entry.schema.json'));
  vChain = ajv.compile(loadSchema('ward-chain.schema.json'));
  vTip = ajv.compile(loadSchema('ward-tip.schema.json'));
  vResult = ajv.compile(loadSchema('ward-verification-result.schema.json'));
});

function build3(): WardEntry[] {
  const e: WardEntry[] = [];
  e.push(appendEntry(e, { chainId: CHAIN, issuerId: ISSUER, sourceKind: 'AEE', sourceId: 's1', payloadHash: 'a'.repeat(64) }));
  e.push(appendEntry(e, { chainId: CHAIN, issuerId: ISSUER, sourceKind: 'AOCL', sourceId: 's2', payloadHash: 'b'.repeat(64) }));
  e.push(appendEntry(e, { chainId: CHAIN, issuerId: ISSUER, sourceKind: 'VOLT', sourceId: 's3', payloadHash: 'c'.repeat(64) }));
  return e;
}

describe('spec schema conformance', () => {
  it('generated entries validate against ward-entry.schema.json', () => {
    for (const entry of build3()) {
      expect(vEntry(entry), JSON.stringify(vEntry.errors)).toBe(true);
    }
  });

  it('chain descriptor validates against ward-chain.schema.json', () => {
    const d = chainDescriptor(CHAIN, 'staging', build3());
    expect(vChain(d), JSON.stringify(vChain.errors)).toBe(true);
  });

  it('signed tip validates against ward-tip.schema.json', () => {
    const entries = build3();
    const kp = generateKeypair();
    const sig = signTipHash(entries[2]!.chain_hash, kp.privateKey);
    const tip = computeTip(CHAIN, entries, 3, { sig, keyId: kp.keyId, sinkRef: 'https://gitea.example/tags/x', notes: 'batch' });
    expect(vTip(tip), JSON.stringify(vTip.errors)).toBe(true);
  });

  it('every fixture entry validates against ward-entry.schema.json', () => {
    for (const file of ['valid-chain.json', 'valid-chain-with-tip.json', 'tampered-modified-entry.json']) {
      const data = JSON.parse(readFileSync(join(FIX, file), 'utf8')) as ChainExport;
      for (const entry of data.entries) {
        expect(vEntry(entry), `${file}: ${JSON.stringify(vEntry.errors)}`).toBe(true);
      }
    }
  });

  it('INTACT result validates against ward-verification-result.schema.json', () => {
    const r = verifyChain(CHAIN, build3());
    expect(vResult(r), JSON.stringify(vResult.errors)).toBe(true);
  });

  it('every BROKEN reason code produces a schema-valid result', () => {
    const reasons: Array<() => unknown> = [
      () => { const e = build3(); e[0]!.prev_chain_hash = 'a'.repeat(64); return verifyChain(CHAIN, e); },
      () => { const e = build3(); e[1]!.payload_hash = '0'.repeat(64); return verifyChain(CHAIN, e); },
      () => { const e = build3(); e[2]!.prev_chain_hash = 'f'.repeat(64); return verifyChain(CHAIN, e); },
      () => { const e = build3(); e.splice(1, 1); return verifyChain(CHAIN, e); },
    ];
    for (const make of reasons) {
      const r = make();
      expect(vResult(r), JSON.stringify(vResult.errors)).toBe(true);
      expect((r as { status: string }).status).toBe('BROKEN');
    }
  });

  it('PARTIAL result validates against ward-verification-result.schema.json', () => {
    const entries = build3();
    const tip = computeTip(CHAIN, entries, 3);
    tip.tip_seq = 99;
    const r = verifyChain(CHAIN, entries, { tips: [tip] });
    expect(r.status).toBe('PARTIAL');
    expect(vResult(r), JSON.stringify(vResult.errors)).toBe(true);
  });
});

describe('spec schema conformance — v0.2 schema deltas', () => {
  it('ward-entry schema rejects a chain_id containing "::" (SPEC §5.2)', () => {
    const entry = build3()[0]!;
    const bad = { ...entry, chain_id: 'ward:org/quox::env/staging' };
    expect(vEntry(bad)).toBe(false);
  });

  it('ward-entry schema rejects seq above 2^53 - 1', () => {
    const entry = build3()[0]!;
    const bad = { ...entry, seq: Number.MAX_SAFE_INTEGER + 2 };
    expect(vEntry(bad)).toBe(false);
  });

  it('ward-verification-result schema accepts the new SCHEMA_INVALID and VERSION_DOWNGRADE reason codes', () => {
    const schemaInvalid = { status: 'BROKEN', chain_id: CHAIN, reason: 'SCHEMA_INVALID', details: { field: 'issuer_id' } };
    const versionDowngrade = { status: 'BROKEN', chain_id: CHAIN, reason: 'VERSION_DOWNGRADE', details: { seq: 2 } };
    expect(vResult(schemaInvalid), JSON.stringify(vResult.errors)).toBe(true);
    expect(vResult(versionDowngrade), JSON.stringify(vResult.errors)).toBe(true);
  });
});
