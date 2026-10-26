/**
 * WARD protocol types (v0.2).
 *
 * Field names follow the WARD SPEC schemas verbatim (SPEC.md §6-§8,
 * ward-entry/ward-chain/ward-tip.schema.json). This is the wire shape:
 * a chain exported to JSON uses exactly these keys.
 */

/**
 * WARD protocol version new entries are written with (SPEC §16.1). The
 * writer always stamps this on new entries; the verifier selects the
 * chain-hash scheme per entry from its own `ward_version` field instead of
 * this constant, so v0.1 entries in an existing chain still verify (Appendix
 * A, verify-only).
 */
export const WARD_VERSION = '0.2' as const;

/** The retired hash scheme (Appendix A). Verify-only: writers MUST NOT create new v0.1 entries (SPEC §16.1). */
export const LEGACY_WARD_VERSION = '0.1' as const;

/** Source-event kinds a WARD entry may witness (SPEC §9). */
export type SourceKind = 'AEE' | 'AOCL' | 'VOLT' | 'WARD' | 'EXTERNAL';

export const SOURCE_KINDS: readonly SourceKind[] = [
  'AEE',
  'AOCL',
  'VOLT',
  'WARD',
  'EXTERNAL',
];

/** A single ward entry — a content-free hash-chain receipt (SPEC §6). */
export interface WardEntry {
  ward_version: string;
  ward_entry_id: string;
  chain_id: string;
  seq: number;
  witnessed_at: string;
  source_kind: SourceKind;
  source_id: string;
  payload_hash: string;
  prev_chain_hash: string;
  chain_hash: string;
  issuer_id: string;
  /** Optional (SPEC §6.2). */
  source_ts?: string;
  tags?: string[];
  sig?: string;
}

/** A ward chain descriptor — convenience metadata, not part of the chain (SPEC §7). */
export interface WardChain {
  chain_id: string;
  genesis_hash: string;
  scope: string;
  created_at: string;
  entry_count: number;
  head_seq: number;
  head_chain_hash: string;
}

/** A tip — a signed checkpoint over chain state (SPEC §8). */
export interface WardTip {
  tip_id: string;
  chain_id: string;
  tip_seq: number;
  tip_chain_hash: string;
  entry_count: number;
  created_at: string;
  /** Optional (SPEC §8.2). */
  sig?: string;
  key_id?: string;
  sink_ref?: string;
  notes?: string;
}

/**
 * Standard failure reason codes.
 *
 * `SCHEMA_INVALID` and `VERSION_DOWNGRADE` are v0.2 additions
 * (VERIFICATION.md §3 Step 0, Step 2.4). Of the rest, seven are the original
 * spec-defined codes (VERIFICATION.md §5). The final three are SDK verifier
 * extensions added in the security-hardening pass: KEY_ID_MISMATCH (tip
 * key_id not bound to the verifying key), TRUNCATED_BEHIND_ANCHOR (chain head
 * falls short of an external anchor), and SIGNATURE_REQUIRED
 * (opts.requireSignatures with an unsigned/unverified tip).
 */
export type ReasonCode =
  | 'SCHEMA_INVALID'
  | 'GENESIS_MISMATCH'
  | 'CHAIN_HASH_MISMATCH'
  | 'VERSION_DOWNGRADE'
  | 'CHAIN_LINK_BROKEN'
  | 'SEQ_INVALID'
  | 'DUPLICATE_SOURCE'
  | 'TIP_MISMATCH'
  | 'TIP_SIGNATURE_INVALID'
  | 'KEY_ID_MISMATCH'
  | 'TRUNCATED_BEHIND_ANCHOR'
  | 'SIGNATURE_REQUIRED';

/** INTACT verification result (VERIFICATION.md §4.2). */
export interface IntactResult {
  status: 'INTACT';
  chain_id: string;
  ward_version: string;
  entry_count: number;
  head_seq: number;
  head_chain_hash: string;
  genesis_verified: boolean;
  tips_verified: number;
  signatures_verified: number;
  warnings: string[];
}

/** BROKEN verification result (VERIFICATION.md §4.3). */
export interface BrokenResult {
  status: 'BROKEN';
  chain_id: string;
  reason: ReasonCode | string;
  details?: Record<string, unknown>;
}

/** PARTIAL verification result (VERIFICATION.md §4.4). */
export interface PartialResult {
  status: 'PARTIAL';
  chain_id: string;
  reason: string;
  details?: Record<string, unknown>;
}

/** A spec-conformant ward_verification_result (VERIFICATION.md §4). */
export type VerificationResult = IntactResult | BrokenResult | PartialResult;

/** A portable chain export the CLI and stores read/write. */
export interface ChainExport {
  chain_id: string;
  entries: WardEntry[];
  tips?: WardTip[];
  chain?: WardChain;
}
