/**
 * Pluggable WARD storage (SPEC §15, CHAIN_STRUCTURE.md §2).
 *
 * Core ships an in-memory store and a file NDJSON store. A SQLite-backed
 * store is a documented future optional peer (see README) — it belongs
 * outside core so the core stays zero-dependency.
 */

export type { WardStore } from './interface.js';
export { InMemoryStore } from './memory.js';
export { FileStore } from './file.js';
