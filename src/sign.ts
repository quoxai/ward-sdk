/**
 * WARD tip signing — Ed25519 via node:crypto only (SPEC §4.5, §8.2, §12.2).
 *
 * Harvested from quox-dashboard/services/ward/lib/signing.js. Tips SHOULD be
 * signed; the signature is over the raw UTF-8 bytes of the tip_chain_hash hex
 * string. Zero third-party dependencies.
 */

import {
  generateKeyPairSync,
  sign as edSign,
  verify as edVerify,
  createPublicKey,
  createPrivateKey,
  type KeyObject,
} from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, chmodSync } from 'node:fs';

export interface Keypair {
  publicKey: KeyObject;
  privateKey: KeyObject;
  /** Stable 16-hex-char fingerprint derived from the SPKI public key. */
  keyId: string;
}

/**
 * Derive a stable key_id fingerprint from an Ed25519 public key: the last 32
 * bytes of the SPKI DER (the raw public key), hex-encoded, first 16 chars.
 *
 * The WARD spec (SPEC §8.2) leaves key_id opaque ("DID or fingerprint") and
 * does NOT mandate a concrete derivation. This is the SDK's concrete
 * fingerprint scheme: it is what generateKeypair mints, so a verifier can bind
 * a tip's declared key_id to the key it is checking against. Callers whose
 * key_ids are DIDs (not derivable from the key) should use the verifier's
 * `expectedKeyId` option instead. See SPEC-POINTERS.md.
 */
export function deriveKeyId(publicKey: KeyObject): string {
  const der = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  return der.subarray(-32).toString('hex').slice(0, 16);
}

/** Generate a new Ed25519 keypair with a stable keyId. */
export function generateKeypair(): Keypair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return { publicKey, privateKey, keyId: deriveKeyId(publicKey) };
}

/**
 * Sign a tip_chain_hash (hex string) with an Ed25519 private key.
 * Returns a base64 signature. SPEC §12.2.
 */
export function signTipHash(
  tipChainHash: string,
  privateKey: KeyObject,
): string {
  const sig = edSign(null, Buffer.from(tipChainHash, 'utf8'), privateKey);
  return sig.toString('base64');
}

/** Verify an Ed25519 signature over a tip_chain_hash. Never throws. */
export function verifyTipSignature(
  tipChainHash: string,
  signature: string,
  publicKey: KeyObject,
): boolean {
  try {
    return edVerify(
      null,
      Buffer.from(tipChainHash, 'utf8'),
      publicKey,
      Buffer.from(signature, 'base64'),
    );
  } catch {
    return false;
  }
}

/** Load a PEM-encoded Ed25519 public key from a string. */
export function publicKeyFromPem(pem: string): KeyObject {
  return createPublicKey(pem);
}

/** Load a PEM-encoded Ed25519 private key from a string. */
export function privateKeyFromPem(pem: string): KeyObject {
  return createPrivateKey(pem);
}

/** Export a keypair to PEM files (private key mode 0600). */
export function exportKeypair(
  keypair: Keypair,
  pubPath: string,
  privPath: string,
): void {
  const pubPem = keypair.publicKey.export({ type: 'spki', format: 'pem' });
  const privPem = keypair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  writeFileSync(pubPath, pubPem as string, { encoding: 'utf8', mode: 0o644 });
  writeFileSync(privPath, privPem as string, { encoding: 'utf8', mode: 0o600 });
  chmodSync(privPath, 0o600);
}

/** Load a keypair from PEM files. */
export function loadKeypair(pubPath: string, privPath: string): Keypair {
  const publicKey = createPublicKey(readFileSync(pubPath, 'utf8'));
  const privateKey = createPrivateKey(readFileSync(privPath, 'utf8'));
  return { publicKey, privateKey, keyId: deriveKeyId(publicKey) };
}

/** Load a keypair if the PEM files exist, else generate and persist one. */
export function ensureKeypair(pubPath: string, privPath: string): Keypair {
  if (existsSync(pubPath) && existsSync(privPath)) {
    return loadKeypair(pubPath, privPath);
  }
  const kp = generateKeypair();
  exportKeypair(kp, pubPath, privPath);
  return kp;
}
