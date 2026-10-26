import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyChain } from '../src/verify.js';
import { publicKeyFromPem } from '../src/sign.js';
import type { ChainExport } from '../src/types.js';

const FIX = join(dirname(fileURLToPath(import.meta.url)), '..', 'conformance', 'fixtures');

interface ManifestEntry {
  file: string;
  expect_status: 'INTACT' | 'BROKEN' | 'PARTIAL';
  expect_reason?: string;
  expect_signatures_verified?: number;
  pubkey?: boolean;
}
interface Manifest {
  chain_id: string;
  pubkey: string;
  fixtures: ManifestEntry[];
}

const manifest = JSON.parse(readFileSync(join(FIX, 'manifest.json'), 'utf8')) as Manifest;
const pubKey = publicKeyFromPem(readFileSync(join(FIX, manifest.pubkey), 'utf8'));

describe('conformance — fixture corpus (built by the harvested writer math)', () => {
  it('manifest covers all 7 tamper reason codes plus valid + signed', () => {
    const reasons = new Set(manifest.fixtures.map((f) => f.expect_reason).filter(Boolean));
    expect(reasons).toEqual(
      new Set([
        'CHAIN_HASH_MISMATCH',
        'CHAIN_LINK_BROKEN',
        'GENESIS_MISMATCH',
        'SEQ_INVALID',
        'DUPLICATE_SOURCE',
        'TIP_MISMATCH',
        'TIP_SIGNATURE_INVALID',
      ]),
    );
    expect(manifest.fixtures.filter((f) => f.expect_status === 'INTACT')).toHaveLength(2);
  });

  for (const fx of manifest.fixtures) {
    it(`${fx.file} → ${fx.expect_status}${fx.expect_reason ? ` (${fx.expect_reason})` : ''}`, () => {
      const data = JSON.parse(readFileSync(join(FIX, fx.file), 'utf8')) as ChainExport;
      const result = verifyChain(data.chain_id, data.entries, {
        tips: data.tips,
        publicKey: fx.pubkey ? pubKey : undefined,
      });
      expect(result.status).toBe(fx.expect_status);
      if (fx.expect_reason) {
        expect((result as { reason?: string }).reason).toBe(fx.expect_reason);
      }
      if (fx.expect_signatures_verified !== undefined && result.status === 'INTACT') {
        expect(result.signatures_verified).toBe(fx.expect_signatures_verified);
      }
    });
  }
});
