import { describe, it, expect } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  generateKeypair,
  signTipHash,
  verifyTipSignature,
  exportKeypair,
  loadKeypair,
  ensureKeypair,
} from '../src/sign.js';

describe('sign — Ed25519 via node:crypto (SPEC §4.5, §12.2)', () => {
  it('generates a keypair with a stable 16-hex keyId', () => {
    const kp = generateKeypair();
    expect(kp.keyId).toMatch(/^[0-9a-f]{16}$/);
  });

  it('sign/verify round-trips over the tip_chain_hash hex bytes', () => {
    const kp = generateKeypair();
    const hash = 'a'.repeat(64);
    const sig = signTipHash(hash, kp.privateKey);
    expect(verifyTipSignature(hash, sig, kp.publicKey)).toBe(true);
  });

  it('rejects a signature from a different key', () => {
    const kp = generateKeypair();
    const other = generateKeypair();
    const hash = 'a'.repeat(64);
    const sig = signTipHash(hash, other.privateKey);
    expect(verifyTipSignature(hash, sig, kp.publicKey)).toBe(false);
  });

  it('rejects a signature over a different hash', () => {
    const kp = generateKeypair();
    const sig = signTipHash('a'.repeat(64), kp.privateKey);
    expect(verifyTipSignature('b'.repeat(64), sig, kp.publicKey)).toBe(false);
  });

  it('verifyTipSignature never throws on garbage input', () => {
    const kp = generateKeypair();
    expect(verifyTipSignature('a'.repeat(64), 'not-base64!!', kp.publicKey)).toBe(false);
  });

  it('export/load PEM round-trips and preserves keyId', () => {
    const dir = mkdtempSync(join(tmpdir(), 'ward-sign-'));
    const kp = generateKeypair();
    const pub = join(dir, 'pub.pem');
    const priv = join(dir, 'priv.pem');
    exportKeypair(kp, pub, priv);
    const loaded = loadKeypair(pub, priv);
    expect(loaded.keyId).toBe(kp.keyId);
    const sig = signTipHash('c'.repeat(64), loaded.privateKey);
    expect(verifyTipSignature('c'.repeat(64), sig, kp.publicKey)).toBe(true);
  });

  it('ensureKeypair creates then reuses the same key', () => {
    const dir = mkdtempSync(join(tmpdir(), 'ward-ensure-'));
    const pub = join(dir, 'pub.pem');
    const priv = join(dir, 'priv.pem');
    const first = ensureKeypair(pub, priv);
    const second = ensureKeypair(pub, priv);
    expect(second.keyId).toBe(first.keyId);
  });
});
