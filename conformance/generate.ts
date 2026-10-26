/**
 * Conformance fixture generator.
 *
 * Builds fixture chains with the SDK's own writer math (src/chain.ts
 * appendEntry — the harvested QLOGS/services-ward hash preimage) so that a
 * chain WRITTEN by the writer verifies PASS, and every tamper verifies FAIL
 * with the correct reason code. The valid chain reproduces WORKED_EXAMPLES.md
 * Example 2 (the 3-entry staging chain); the tip reproduces Example 5.
 *
 * Regenerate with:  npm run fixtures
 * (Committed fixtures already exist; regeneration must be deterministic except
 *  for the Ed25519 keypair, which is written alongside the signed fixtures.)
 */

import { writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { appendEntry, computeTip } from '../src/chain.js';
import { generateKeypair, signTipHash, exportKeypair } from '../src/sign.js';
import type { WardEntry, WardTip, ChainExport } from '../src/types.js';

// Write to the SOURCE fixtures dir (this file may run from dist/ after
// compilation, so resolve against the package root, not import.meta.url).
const HERE = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = HERE.includes(`${'dist'}/`) || HERE.endsWith('/dist/conformance')
  ? join(HERE, '..', '..')
  : join(HERE, '..');
const FIX = join(PKG_ROOT, 'conformance', 'fixtures');
mkdirSync(FIX, { recursive: true });

const CHAIN = 'ward:org/quox/env/staging';
const ISSUER = 'ward-issuer-stg-01';

// WORKED_EXAMPLES.md Example 2 — deterministic inputs.
const seed: Array<Omit<Parameters<typeof appendEntry>[1], 'chainId' | 'issuerId'>> = [
  {
    sourceKind: 'AEE',
    sourceId: 'aee-env-001',
    payloadHash: 'aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa7777bbbb8888',
    wardEntryId: '01WARD-STG-E001',
    witnessedAt: '2026-03-05T15:00:00.000Z',
  },
  {
    sourceKind: 'AOCL',
    sourceId: 'aocl-dec-002',
    payloadHash: '1111aaaa2222bbbb3333cccc4444dddd5555eeee6666ffff7777aaaa8888bbbb',
    wardEntryId: '01WARD-STG-E002',
    witnessedAt: '2026-03-05T15:00:01.000Z',
  },
  {
    sourceKind: 'VOLT',
    sourceId: 'volt-bundle-003',
    payloadHash: 'ffff9999eeee8888dddd7777cccc6666bbbb5555aaaa444499993333888822ff',
    wardEntryId: '01WARD-STG-E003',
    witnessedAt: '2026-03-05T15:00:05.000Z',
  },
];

function buildValidChain(): WardEntry[] {
  const entries: WardEntry[] = [];
  for (const s of seed) {
    entries.push(appendEntry(entries, { chainId: CHAIN, issuerId: ISSUER, ...s }));
  }
  return entries;
}

function clone<T>(x: T): T {
  return JSON.parse(JSON.stringify(x)) as T;
}

function writeFixture(name: string, data: ChainExport): void {
  writeFileSync(join(FIX, name), JSON.stringify(data, null, 2) + '\n', 'utf8');
}

const valid = buildValidChain();

// 1. Valid, no tip.
writeFixture('valid-chain.json', { chain_id: CHAIN, entries: valid });

// 2. Valid + signed tip at seq=3 (WORKED_EXAMPLES Example 5).
const kp = generateKeypair();
exportKeypair(kp, join(FIX, 'tip-pubkey.pem'), join(FIX, 'tip-privkey.pem'));
const tipHash = valid[valid.length - 1]!.chain_hash;
const goodSig = signTipHash(tipHash, kp.privateKey);
const signedTip: WardTip = computeTip(CHAIN, valid, 3, {
  tipId: 'tip-stg-002',
  createdAt: '2026-03-05T15:01:00.000Z',
  keyId: kp.keyId,
  sig: goodSig,
  notes: 'End-of-batch tip for staging, March 5 2026',
});
writeFixture('valid-chain-with-tip.json', { chain_id: CHAIN, entries: valid, tips: [signedTip] });

// 3. Tamper: modified entry (WORKED_EXAMPLES Example 4) → CHAIN_HASH_MISMATCH.
const modified = clone(valid);
modified[1]!.payload_hash = '0'.repeat(64); // chain_hash left stale
writeFixture('tampered-modified-entry.json', { chain_id: CHAIN, entries: modified });

// 4. Tamper: broken link → CHAIN_LINK_BROKEN.
// Corrupt only entry 3's prev_chain_hash so seq+hash of e2 stay valid.
const brokenLink = clone(valid);
brokenLink[2]!.prev_chain_hash = 'f'.repeat(64);
// Recompute e3's own chain_hash so it doesn't trip CHAIN_HASH_MISMATCH first.
// The link check runs before the hash check, so this isolates CHAIN_LINK_BROKEN.
writeFixture('tampered-broken-link.json', { chain_id: CHAIN, entries: brokenLink });

// 5. Tamper: forged genesis → GENESIS_MISMATCH.
const badGenesis = clone(valid);
badGenesis[0]!.prev_chain_hash = 'a'.repeat(64);
writeFixture('tampered-genesis.json', { chain_id: CHAIN, entries: badGenesis });

// 6. Tamper: deleted middle entry → SEQ_INVALID.
const badSeq = clone(valid);
badSeq.splice(1, 1); // remove seq=2, leaving [1, 3]
writeFixture('tampered-seq.json', { chain_id: CHAIN, entries: badSeq });

// 7. Tamper: duplicate source → DUPLICATE_SOURCE.
// Build a fresh 2-entry chain where both entries witness the same source.
const dupEntries: WardEntry[] = [];
dupEntries.push(
  appendEntry(dupEntries, {
    chainId: CHAIN,
    issuerId: ISSUER,
    sourceKind: 'AEE',
    sourceId: 'aee-dup-1',
    payloadHash: 'a'.repeat(64),
    wardEntryId: '01WARD-DUP-E001',
    witnessedAt: '2026-03-05T15:00:00.000Z',
  }),
);
dupEntries.push(
  appendEntry(dupEntries, {
    chainId: CHAIN,
    issuerId: ISSUER,
    sourceKind: 'AEE',
    sourceId: 'aee-dup-1', // same (kind,id) as entry 1
    payloadHash: 'b'.repeat(64),
    wardEntryId: '01WARD-DUP-E002',
    witnessedAt: '2026-03-05T15:00:01.000Z',
  }),
);
writeFixture('tampered-duplicate-source.json', { chain_id: CHAIN, entries: dupEntries });

// 8. Tamper: forged tip → TIP_MISMATCH.
const forgedTip: WardTip = computeTip(CHAIN, valid, 3, {
  tipId: 'tip-forged-001',
  createdAt: '2026-03-05T15:01:00.000Z',
});
forgedTip.tip_chain_hash = '0'.repeat(64); // does not match entry 3
writeFixture('tampered-forged-tip.json', { chain_id: CHAIN, entries: valid, tips: [forgedTip] });

// 9. Tamper: bad signature → TIP_SIGNATURE_INVALID (verify with tip-pubkey.pem).
const badSig = goodSig.slice(0, -4) + (goodSig.endsWith('AAAA') ? 'BBBB' : 'AAAA');
const badSigTip: WardTip = computeTip(CHAIN, valid, 3, {
  tipId: 'tip-badsig-001',
  createdAt: '2026-03-05T15:01:00.000Z',
  keyId: kp.keyId,
  sig: badSig,
});
writeFixture('tampered-bad-signature.json', { chain_id: CHAIN, entries: valid, tips: [badSigTip] });

// Manifest describing each fixture's expected verification outcome.
const manifest = {
  chain_id: CHAIN,
  pubkey: 'tip-pubkey.pem',
  fixtures: [
    { file: 'valid-chain.json', expect_status: 'INTACT' },
    { file: 'valid-chain-with-tip.json', expect_status: 'INTACT', pubkey: true, expect_signatures_verified: 1 },
    { file: 'tampered-modified-entry.json', expect_status: 'BROKEN', expect_reason: 'CHAIN_HASH_MISMATCH' },
    { file: 'tampered-broken-link.json', expect_status: 'BROKEN', expect_reason: 'CHAIN_LINK_BROKEN' },
    { file: 'tampered-genesis.json', expect_status: 'BROKEN', expect_reason: 'GENESIS_MISMATCH' },
    { file: 'tampered-seq.json', expect_status: 'BROKEN', expect_reason: 'SEQ_INVALID' },
    { file: 'tampered-duplicate-source.json', expect_status: 'BROKEN', expect_reason: 'DUPLICATE_SOURCE' },
    { file: 'tampered-forged-tip.json', expect_status: 'BROKEN', expect_reason: 'TIP_MISMATCH' },
    { file: 'tampered-bad-signature.json', expect_status: 'BROKEN', expect_reason: 'TIP_SIGNATURE_INVALID', pubkey: true },
  ],
};
writeFileSync(join(FIX, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n', 'utf8');

process.stdout.write(`Generated ${manifest.fixtures.length} fixtures + keypair in ${FIX}\n`);
