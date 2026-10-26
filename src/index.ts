/**
 * @quox/ward — WARD (Write-once Append-only Receipt Digests) v0.1.
 *
 * Tamper-evident hash-chain witnessing: chain math + verification, with
 * Ed25519 tip signing. Zero runtime dependencies (node:crypto only).
 *
 * Scope: chain math and verification are the core. Storage is minimal
 * (in-memory + file NDJSON, importable from "@quox/ward/store"). CMS/X.509
 * tip anchoring is intentionally NOT in core — see SPEC-POINTERS.md.
 */

// Protocol constants + types
export {
  WARD_VERSION,
  LEGACY_WARD_VERSION,
  SOURCE_KINDS,
  type SourceKind,
  type WardEntry,
  type WardChain,
  type WardTip,
  type ReasonCode,
  type IntactResult,
  type BrokenResult,
  type PartialResult,
  type VerificationResult,
  type ChainExport,
} from './types.js';

// Crypto primitives (SPEC §3.2, §4)
export {
  sha256,
  genesisHash,
  chainHash,
  chainHashV2,
  canonicalize,
  isWellFormedNfc,
  payloadHash,
  type ChainHashInput,
  type ChainHashV2Input,
} from './crypto.js';

// Strict JSON parsing at untrusted-byte boundaries (SPEC §3.2 rule 5)
export { parseStrictJson } from './strict-json.js';

// Chain math — the writer side (SPEC §4, §11)
export {
  headOf,
  buildEntry,
  appendEntry,
  chainDescriptor,
  computeTip,
  type ChainHead,
  type WitnessInput,
  type AppendInput,
  type TipOptions,
} from './chain.js';

// Verification (VERIFICATION.md §3-§5)
export {
  verifyChain,
  type VerifyOptions,
  type AnchorOptions,
} from './verify.js';

// Ed25519 tip signing (SPEC §4.5, §8.2, §12.2)
export {
  generateKeypair,
  deriveKeyId,
  signTipHash,
  verifyTipSignature,
  publicKeyFromPem,
  privateKeyFromPem,
  exportKeypair,
  loadKeypair,
  ensureKeypair,
  type Keypair,
} from './sign.js';

// Storage (also available via "@quox/ward/store")
export {
  InMemoryStore,
  FileStore,
  type WardStore,
} from './store/index.js';
