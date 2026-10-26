/**
 * WARD cryptographic primitives (SPEC §3.2, §4).
 *
 * Harvested from quox-dashboard/services/ward/lib/crypto.js (decoupled,
 * retyped). Zero runtime dependencies — node:crypto only.
 */

import { createHash } from 'node:crypto';

/** SHA-256 of a UTF-8 string, lowercase hex (64 chars). SPEC §4.1, §4.2. */
export function sha256(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

/**
 * Genesis hash anchoring a chain's origin (SPEC §4.3):
 *   genesis_hash = SHA-256("WARD-GENESIS|" + chain_id)
 */
export function genesisHash(chainId: string): string {
  return sha256(`WARD-GENESIS|${chainId}`);
}

/** Inputs to the chain-hash preimage (SPEC §4.4). */
export interface ChainHashInput {
  prevChainHash: string;
  chainId: string;
  seq: number;
  wardEntryId: string;
  /** ISO 8601 UTC from the entry's witnessed_at field. */
  timestamp: string;
  sourceKind: string;
  sourceId: string;
  payloadHash: string;
}

/**
 * Legacy v0.1 chain hash (SPEC Appendix A), verify-only as of v0.2:
 *   chain_hash = SHA-256(prev_chain_hash | chain_id | seq | ward_entry_id
 *     | timestamp | source_kind | source_id | payload_hash)
 * All values UTF-8, pipe-separated. `seq` is the decimal string (no leading
 * zeros). This is the exact preimage the QLOGS writer and services/ward used
 * pre-v0.2. Deprecated: a crafted `ward_entry_id`/`source_id` containing `|`
 * can make two distinct field tuples collide (delimiter injection,
 * THREAT_MODEL.md §6 T9). New entries MUST use `chainHashV2` instead (SPEC
 * §4.4); this function remains so verifiers can check existing v0.1 chains.
 */
export function chainHash(input: ChainHashInput): string {
  const preimage = [
    input.prevChainHash,
    input.chainId,
    String(input.seq),
    input.wardEntryId,
    input.timestamp,
    input.sourceKind,
    input.sourceId,
    input.payloadHash,
  ].join('|');
  return sha256(preimage);
}

const MAX_SAFE_MAGNITUDE = Number.MAX_SAFE_INTEGER; // 2^53 - 1 (SPEC §3.2 rule 4)

/**
 * True if `s` is well-formed Unicode (no unpaired surrogates) and already in
 * NFC (SPEC §3.2 rule 3). Does not throw; `canonicalize` uses this to decide
 * whether to reject.
 */
export function isWellFormedNfc(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      // High surrogate: must be immediately followed by a low surrogate.
      const next = s.charCodeAt(i + 1);
      if (Number.isNaN(next) || next < 0xdc00 || next > 0xdfff) return false;
      i++; // consume the paired low surrogate
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      // Unpaired low surrogate (a high surrogate would have consumed it above).
      return false;
    }
  }
  return s.normalize('NFC') === s;
}

/**
 * Compare two strings by UTF-8 byte order (unsigned byte-by-byte), per SPEC
 * §3.2 rule 2. This differs from JS's default string comparison (UTF-16 code
 * units) for supplementary-plane characters: e.g. U+E000 sorts before
 * U+10000 in UTF-8 byte order, but after it under naive UTF-16 comparison
 * (0xD800 < 0xE000 as the leading surrogate).
 */
function compareUtf8Bytes(a: string, b: string): number {
  return Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}

/**
 * Canonical JSON for hashing — profile **WARD-CANON-1** (SPEC §3.2):
 *   1. UTF-8, no insignificant whitespace.
 *   2. Object keys sorted by UTF-8 byte order (not JS default string sort)
 *      at every nesting level.
 *   3. Strings MUST be well-formed Unicode and already in NFC; a string that
 *      is not is REJECTED (thrown), never silently repaired.
 *   4. Integers are bounded to +/-(2^53 - 1) and serialized in exact decimal
 *      form (no leading zeros, no plus sign). Non-finite numbers throw.
 *      Non-integer finite numbers are rendered without exponent notation
 *      where the specific field does not require an integer.
 *   5. Duplicate JSON member names must be rejected by the parser feeding
 *      this function; canonicalize itself operates on already-parsed JS
 *      objects, which cannot represent a duplicate key, so that rule is
 *      enforced at the parse boundary (see `parseStrictJson`), not here.
 *   `undefined` object values are omitted (the field is absent), matching
 *   how the writer treats OPTIONAL fields it did not set.
 */
export function canonicalize(value: unknown): string {
  if (value === undefined) {
    throw new Error('canonicalize: undefined is not serializable; omit the field instead');
  }
  if (value === null || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error(`canonicalize: non-finite number is not serializable: ${value}`);
    }
    if (Number.isInteger(value)) {
      if (value > MAX_SAFE_MAGNITUDE || value < -MAX_SAFE_MAGNITUDE) {
        throw new Error(
          `canonicalize: integer ${value} is outside the WARD-CANON-1 range +/-(2^53 - 1)`,
        );
      }
      return String(value);
    }
    const s = String(value);
    if (/[eE]/.test(s)) {
      throw new Error(`canonicalize: number ${s} requires exponent notation, not canonical-safe`);
    }
    return s;
  }
  if (typeof value === 'string') {
    if (!isWellFormedNfc(value)) {
      throw new Error(
        `canonicalize: string is not well-formed Unicode in NFC (WARD-CANON-1 rule 3 rejects, never repairs): ${JSON.stringify(value)}`,
      );
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map((v) => canonicalize(v)).join(',') + ']';
  }

  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).filter((k) => record[k] !== undefined);
  for (const k of keys) {
    if (!isWellFormedNfc(k)) {
      throw new Error(
        `canonicalize: object key is not well-formed Unicode in NFC (WARD-CANON-1 rule 3): ${JSON.stringify(k)}`,
      );
    }
  }
  keys.sort(compareUtf8Bytes);
  const pairs = keys.map((k) => JSON.stringify(k) + ':' + canonicalize(record[k]));
  return '{' + pairs.join(',') + '}';
}

/** SHA-256 payload hash of an object via its canonical JSON (SPEC §10.1). */
export function payloadHash(obj: unknown): string {
  return sha256(canonicalize(obj));
}

/**
 * Inputs to the v0.2 chain-hash body (SPEC §4.4): the 10 REQUIRED fields of
 * §6.1 excluding chain_hash itself.
 */
export interface ChainHashV2Input {
  wardVersion: string;
  wardEntryId: string;
  chainId: string;
  seq: number;
  witnessedAt: string;
  sourceKind: string;
  sourceId: string;
  payloadHash: string;
  prevChainHash: string;
  issuerId: string;
}

/**
 * WARD v0.2 chain hash (SPEC §4.4):
 *   chain_hash = SHA-256(canonical_json(hash_body))
 * where hash_body is the entry's 10 required fields excluding chain_hash,
 * canonicalized per §3.2 (sorted keys, `seq` hashed as a JSON integer).
 * Replaces the v0.1 pipe-concatenation scheme (see `chainHash` and Appendix
 * A) to close the delimiter-injection gap: caller-supplied strings
 * (`ward_entry_id`, `source_id`) can no longer produce colliding preimages,
 * because JSON string escaping makes field boundaries unambiguous.
 */
export function chainHashV2(input: ChainHashV2Input): string {
  const body = {
    chain_id: input.chainId,
    issuer_id: input.issuerId,
    payload_hash: input.payloadHash,
    prev_chain_hash: input.prevChainHash,
    seq: input.seq,
    source_id: input.sourceId,
    source_kind: input.sourceKind,
    ward_entry_id: input.wardEntryId,
    ward_version: input.wardVersion,
    witnessed_at: input.witnessedAt,
  };
  // The hash body MUST contain exactly these 10 members: none absent, none
  // null (SPEC §4.4). Fail loudly rather than letting `canonicalize` silently
  // drop an absent (undefined) field from the hash input.
  for (const [field, value] of Object.entries(body)) {
    if (value === undefined || value === null) {
      throw new Error(`chainHashV2: hash body field "${field}" is ${String(value)}, required (SPEC §4.4)`);
    }
  }
  return sha256(canonicalize(body));
}
