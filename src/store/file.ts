/**
 * File-backed NDJSON WARD store. Durable, append-only, dependency-free.
 *
 * Layout: one directory holding, per chain, `<slug>.entries.ndjson` and
 * `<slug>.tips.ndjson`, where <slug> derives deterministically from the
 * chain_id. Entries are appended one JSON object per line (SPEC §3.1 permits
 * NDJSON storage). A small in-memory mirror is loaded lazily per chain and
 * enforces the append-only seq + uniqueness discipline before each write.
 */

import {
  mkdirSync,
  readdirSync,
  readFileSync,
  appendFileSync,
  existsSync,
} from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { parseStrictJson } from '../strict-json.js';
import type { WardEntry, WardTip } from '../types.js';
import type { WardStore } from './interface.js';

function slug(chainId: string): string {
  const safe = chainId.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 80);
  const digest = createHash('sha256').update(chainId, 'utf8').digest('hex').slice(0, 8);
  return `${safe}.${digest}`;
}

export class FileStore implements WardStore {
  private readonly dir: string;
  private entriesCache = new Map<string, WardEntry[]>();
  private tipsCache = new Map<string, WardTip[]>();
  private sourceKeys = new Map<string, Set<string>>();
  private slugToChain = new Map<string, string>();
  private warnings = new Map<string, string[]>();
  private tipWarnings = new Map<string, string[]>();

  constructor(dir: string) {
    this.dir = dir;
    mkdirSync(dir, { recursive: true });
  }

  private entriesPath(chainId: string): string {
    return join(this.dir, `${slug(chainId)}.entries.ndjson`);
  }

  private tipsPath(chainId: string): string {
    return join(this.dir, `${slug(chainId)}.tips.ndjson`);
  }

  private loadEntries(chainId: string): WardEntry[] {
    if (this.entriesCache.has(chainId)) return this.entriesCache.get(chainId)!;
    const path = this.entriesPath(chainId);
    const list: WardEntry[] = [];
    const keys = new Set<string>();
    const warns: string[] = [];
    if (existsSync(path)) {
      const raw = readFileSync(path, 'utf8');
      // Index of the last non-empty line: a torn write (crash mid-append)
      // leaves an unterminated JSON object as the final line. Recover from
      // that (skip + warn); a parse failure on any EARLIER line is real
      // corruption and must throw.
      const rawLines = raw.split('\n');
      let lastIdx = -1;
      for (let i = rawLines.length - 1; i >= 0; i--) {
        if (rawLines[i]!.trim()) {
          lastIdx = i;
          break;
        }
      }
      for (let i = 0; i < rawLines.length; i++) {
        const line = rawLines[i]!;
        if (!line.trim()) continue;
        let entry: WardEntry;
        try {
          entry = parseStrictJson(line) as WardEntry;
        } catch (err) {
          if (i === lastIdx) {
            warns.push(
              `recovered from a truncated final line in ${path} (torn write skipped): ${(err as Error).message}`,
            );
            continue;
          }
          throw new Error(
            `corrupt WARD entry at ${path} line ${i + 1}: ${(err as Error).message}`,
          );
        }
        list.push(entry);
        keys.add(`${entry.source_kind}:${entry.source_id}`);
      }
    }
    this.entriesCache.set(chainId, list);
    this.sourceKeys.set(chainId, keys);
    this.warnings.set(chainId, warns);
    this.slugToChain.set(slug(chainId), chainId);
    return list;
  }

  /** Warnings surfaced while loading a chain (e.g. recovered torn writes). */
  getWarnings(chainId: string): string[] {
    this.loadEntries(chainId);
    this.loadTips(chainId);
    return [...(this.warnings.get(chainId) ?? []), ...(this.tipWarnings.get(chainId) ?? [])];
  }

  appendEntry(entry: WardEntry): void {
    const list = this.loadEntries(entry.chain_id);
    const expectedSeq = list.length + 1;
    if (entry.seq !== expectedSeq) {
      throw new Error(
        `seq gap in ${entry.chain_id}: expected ${expectedSeq}, got ${entry.seq}`,
      );
    }
    const keys = this.sourceKeys.get(entry.chain_id)!;
    const sourceKey = `${entry.source_kind}:${entry.source_id}`;
    if (keys.has(sourceKey)) {
      throw new Error(`duplicate source in ${entry.chain_id}: ${sourceKey}`);
    }
    appendFileSync(this.entriesPath(entry.chain_id), JSON.stringify(entry) + '\n', 'utf8');
    keys.add(sourceKey);
    list.push(entry);
  }

  getEntries(chainId: string): WardEntry[] {
    return [...this.loadEntries(chainId)];
  }

  getHead(chainId: string): WardEntry | undefined {
    const list = this.loadEntries(chainId);
    return list.length > 0 ? list[list.length - 1] : undefined;
  }

  private loadTips(chainId: string): WardTip[] {
    if (this.tipsCache.has(chainId)) return this.tipsCache.get(chainId)!;
    const path = this.tipsPath(chainId);
    const list: WardTip[] = [];
    const warns: string[] = [];
    if (existsSync(path)) {
      const raw = readFileSync(path, 'utf8');
      // Same torn-write recovery semantics as loadEntries: a truncated
      // (unterminated) final line is a crash mid-append — recover from it
      // (skip + warn). A parse failure on any EARLIER line is real
      // corruption and must throw.
      const rawLines = raw.split('\n');
      let lastIdx = -1;
      for (let i = rawLines.length - 1; i >= 0; i--) {
        if (rawLines[i]!.trim()) {
          lastIdx = i;
          break;
        }
      }
      for (let i = 0; i < rawLines.length; i++) {
        const line = rawLines[i]!;
        if (!line.trim()) continue;
        let tip: WardTip;
        try {
          tip = parseStrictJson(line) as WardTip;
        } catch (err) {
          if (i === lastIdx) {
            warns.push(
              `recovered from a truncated final line in ${path} (torn write skipped): ${(err as Error).message}`,
            );
            continue;
          }
          throw new Error(
            `corrupt WARD tip at ${path} line ${i + 1}: ${(err as Error).message}`,
          );
        }
        list.push(tip);
      }
    }
    list.sort((a, b) => a.tip_seq - b.tip_seq);
    this.tipsCache.set(chainId, list);
    this.tipWarnings.set(chainId, warns);
    return list;
  }

  putTip(tip: WardTip): void {
    const list = this.loadTips(tip.chain_id);
    appendFileSync(this.tipsPath(tip.chain_id), JSON.stringify(tip) + '\n', 'utf8');
    list.push(tip);
    list.sort((a, b) => a.tip_seq - b.tip_seq);
  }

  getTips(chainId: string): WardTip[] {
    return [...this.loadTips(chainId)];
  }

  listChains(): string[] {
    if (!existsSync(this.dir)) return [];
    const chains = new Set<string>();
    for (const file of readdirSync(this.dir)) {
      if (!file.endsWith('.entries.ndjson')) continue;
      const fileSlug = file.replace(/\.entries\.ndjson$/, '');
      const known = this.slugToChain.get(fileSlug);
      if (known) {
        chains.add(known);
      } else {
        // Recover chain_id from the first entry line.
        const raw = readFileSync(join(this.dir, file), 'utf8');
        const firstLine = raw.split('\n').find((l) => l.trim());
        if (firstLine) {
          const entry = parseStrictJson(firstLine) as WardEntry;
          this.slugToChain.set(fileSlug, entry.chain_id);
          chains.add(entry.chain_id);
        }
      }
    }
    return [...chains];
  }
}
