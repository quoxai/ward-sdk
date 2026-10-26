/**
 * In-memory WARD store. Non-durable — for tests, ephemeral pipelines, and as
 * the reference implementation of the WardStore append-only discipline.
 */

import type { WardEntry, WardTip } from '../types.js';
import type { WardStore } from './interface.js';

export class InMemoryStore implements WardStore {
  private entries = new Map<string, WardEntry[]>();
  private tips = new Map<string, WardTip[]>();
  private sourceKeys = new Map<string, Set<string>>();

  appendEntry(entry: WardEntry): void {
    const list = this.entries.get(entry.chain_id) ?? [];
    const expectedSeq = list.length + 1;
    if (entry.seq !== expectedSeq) {
      throw new Error(
        `seq gap in ${entry.chain_id}: expected ${expectedSeq}, got ${entry.seq}`,
      );
    }
    const keys = this.sourceKeys.get(entry.chain_id) ?? new Set<string>();
    const sourceKey = `${entry.source_kind}:${entry.source_id}`;
    if (keys.has(sourceKey)) {
      throw new Error(
        `duplicate source in ${entry.chain_id}: ${sourceKey}`,
      );
    }
    keys.add(sourceKey);
    list.push(entry);
    this.entries.set(entry.chain_id, list);
    this.sourceKeys.set(entry.chain_id, keys);
  }

  getEntries(chainId: string): WardEntry[] {
    return [...(this.entries.get(chainId) ?? [])];
  }

  getHead(chainId: string): WardEntry | undefined {
    const list = this.entries.get(chainId);
    return list && list.length > 0 ? list[list.length - 1] : undefined;
  }

  putTip(tip: WardTip): void {
    const list = this.tips.get(tip.chain_id) ?? [];
    list.push(tip);
    list.sort((a, b) => a.tip_seq - b.tip_seq);
    this.tips.set(tip.chain_id, list);
  }

  getTips(chainId: string): WardTip[] {
    return [...(this.tips.get(chainId) ?? [])];
  }

  listChains(): string[] {
    return [...this.entries.keys()];
  }
}
