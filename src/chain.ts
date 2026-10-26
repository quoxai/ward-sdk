/**
 * WARD chain math — the writer side (SPEC §4, §11).
 *
 * Harvested from quox-qluster/server/lib/ward.js (the QLOGS writer: head
 * derivation + computeEntryHash append loop) and services/ward, decoupled
 * from any storage backend. A chain written with these helpers verifies PASS
 * against verify.ts — same hash preimage for both directions, no drift.
 */

import { randomUUID } from 'node:crypto';
import { chainHashV2, genesisHash } from './crypto.js';
import {
  WARD_VERSION,
  SOURCE_KINDS,
  type SourceKind,
  type WardEntry,
  type WardChain,
  type WardTip,
} from './types.js';

/**
 * Reject a chain_id containing the reserved "::" meta-chain source_id
 * separator (SPEC §5.2). Writer-side validation: applied wherever a chain_id
 * is used to construct new chain state.
 */
function assertValidChainId(chainId: string): void {
  if (chainId.includes('::')) {
    throw new Error(`chain_id MUST NOT contain "::" (reserved as the meta-chain source_id separator): ${chainId}`);
  }
}

/** Head of a chain: the last entry's seq + chain_hash, or genesis for empty. */
export interface ChainHead {
  seq: number;
  chainHash: string;
}

/** Compute the current head of an ordered entry list. Empty → genesis. */
export function headOf(chainId: string, entries: readonly WardEntry[]): ChainHead {
  if (entries.length === 0) {
    return { seq: 0, chainHash: genesisHash(chainId) };
  }
  const last = entries[entries.length - 1]!;
  return { seq: last.seq, chainHash: last.chain_hash };
}

/** Fields the caller supplies to witness a source event. */
export interface WitnessInput {
  chainId: string;
  sourceKind: SourceKind;
  sourceId: string;
  /** SHA-256 hex of the source event's canonical content. */
  payloadHash: string;
  issuerId: string;
  /** Defaults to a random UUID. */
  wardEntryId?: string;
  /** Defaults to now (ISO 8601 UTC). */
  witnessedAt?: string;
  prevChainHash: string;
  seq: number;
  sourceTs?: string;
  tags?: string[];
  /**
   * Protocol version to stamp on the entry. Defaults to the current version
   * (SPEC §16.1). The writer MUST NOT create new v0.1 entries: passing any
   * value other than the current `WARD_VERSION` throws. This field exists
   * only so the type signals versioning is deliberate, not to permit
   * downgrading writes.
   */
  wardVersion?: string;
}

/**
 * Build a single, fully-linked ward entry with a computed chain_hash.
 * Throws on an unrecognized source_kind (SPEC §9), a chain_id containing
 * "::" (SPEC §5.2), or a requested ward_version other than the current one
 * (SPEC §16.1 — new entries MUST use 0.2; the legacy v0.1 scheme is
 * verify-only, see Appendix A).
 */
export function buildEntry(input: WitnessInput): WardEntry {
  if (!SOURCE_KINDS.includes(input.sourceKind)) {
    throw new Error(`unrecognized source_kind: ${input.sourceKind}`);
  }
  assertValidChainId(input.chainId);
  const wardVersion = input.wardVersion ?? WARD_VERSION;
  if (wardVersion !== WARD_VERSION) {
    throw new Error(
      `refusing to create a new entry with ward_version "${wardVersion}": new entries MUST use the current version "${WARD_VERSION}" (SPEC §16.1). The legacy scheme is verify-only.`,
    );
  }
  const wardEntryId = input.wardEntryId ?? randomUUID();
  const witnessedAt = input.witnessedAt ?? new Date().toISOString();

  const computedChainHash = chainHashV2({
    wardVersion,
    wardEntryId,
    chainId: input.chainId,
    seq: input.seq,
    witnessedAt,
    sourceKind: input.sourceKind,
    sourceId: input.sourceId,
    payloadHash: input.payloadHash,
    prevChainHash: input.prevChainHash,
    issuerId: input.issuerId,
  });

  const entry: WardEntry = {
    ward_version: wardVersion,
    ward_entry_id: wardEntryId,
    chain_id: input.chainId,
    seq: input.seq,
    witnessed_at: witnessedAt,
    source_kind: input.sourceKind,
    source_id: input.sourceId,
    payload_hash: input.payloadHash,
    prev_chain_hash: input.prevChainHash,
    chain_hash: computedChainHash,
    issuer_id: input.issuerId,
  };
  if (input.sourceTs !== undefined) entry.source_ts = input.sourceTs;
  if (input.tags !== undefined) entry.tags = input.tags;
  return entry;
}

/** What appendEntry needs beyond the head it derives itself. */
export interface AppendInput {
  chainId: string;
  sourceKind: SourceKind;
  sourceId: string;
  payloadHash: string;
  issuerId: string;
  wardEntryId?: string;
  witnessedAt?: string;
  sourceTs?: string;
  tags?: string[];
}

/**
 * Append a new entry to an ordered entry list, deriving seq and
 * prev_chain_hash from the current head. Returns the new entry (does not
 * mutate the input array).
 */
export function appendEntry(
  entries: readonly WardEntry[],
  input: AppendInput,
): WardEntry {
  const head = headOf(input.chainId, entries);
  return buildEntry({
    ...input,
    prevChainHash: head.chainHash,
    seq: head.seq + 1,
  });
}

/** Build a convenience chain descriptor from an ordered entry list (SPEC §7). */
export function chainDescriptor(
  chainId: string,
  scope: string,
  entries: readonly WardEntry[],
  createdAt: string = new Date().toISOString(),
): WardChain {
  assertValidChainId(chainId);
  const head = headOf(chainId, entries);
  return {
    chain_id: chainId,
    genesis_hash: genesisHash(chainId),
    scope,
    created_at: createdAt,
    entry_count: entries.length,
    head_seq: head.seq,
    head_chain_hash: head.chainHash,
  };
}

/** Options for computeTip. */
export interface TipOptions {
  tipId?: string;
  createdAt?: string;
  keyId?: string;
  sinkRef?: string;
  notes?: string;
  /** Base64 Ed25519 signature over tip_chain_hash (see sign.ts). */
  sig?: string;
}

/**
 * Build a tip checkpointing the chain at `tipSeq` (SPEC §8, §12). Throws if
 * no entry has that seq.
 */
export function computeTip(
  chainId: string,
  entries: readonly WardEntry[],
  tipSeq: number,
  opts: TipOptions = {},
): WardTip {
  assertValidChainId(chainId);
  const target = entries.find((e) => e.seq === tipSeq);
  if (!target) {
    throw new Error(`no entry at tip_seq ${tipSeq}`);
  }
  const tip: WardTip = {
    tip_id: opts.tipId ?? randomUUID(),
    chain_id: chainId,
    tip_seq: tipSeq,
    tip_chain_hash: target.chain_hash,
    entry_count: tipSeq,
    created_at: opts.createdAt ?? new Date().toISOString(),
  };
  if (opts.sig !== undefined) tip.sig = opts.sig;
  if (opts.keyId !== undefined) tip.key_id = opts.keyId;
  if (opts.sinkRef !== undefined) tip.sink_ref = opts.sinkRef;
  if (opts.notes !== undefined) tip.notes = opts.notes;
  return tip;
}
