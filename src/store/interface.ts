/**
 * WardStore — the minimal append-only storage contract WARD needs.
 *
 * A store persists entries and tips for one or more chains and enforces the
 * append-only, gap-free seq discipline the spec requires (CHAIN_STRUCTURE.md
 * §4). It does NOT compute hashes — that is chain.ts's job. Implementations
 * append pre-built entries and read them back in seq order for verification.
 */

import type { WardEntry, WardTip } from '../types.js';

export interface WardStore {
  /**
   * Append a fully-built entry to its chain. MUST reject an entry whose seq
   * is not exactly currentHead.seq + 1, and reject a duplicate
   * (chain_id, source_kind, source_id) tuple (SPEC §6.3).
   */
  appendEntry(entry: WardEntry): void;

  /** All entries for a chain, seq ascending. */
  getEntries(chainId: string): WardEntry[];

  /** The last entry of a chain, or undefined for an empty chain. */
  getHead(chainId: string): WardEntry | undefined;

  /** Persist a tip. */
  putTip(tip: WardTip): void;

  /** All tips for a chain, tip_seq ascending. */
  getTips(chainId: string): WardTip[];

  /** All known chain IDs. */
  listChains(): string[];
}
