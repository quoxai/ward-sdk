/**
 * WARD verifier — 6-step chain integrity check (VERIFICATION.md §3-§5).
 *
 * Harvested from quox-dashboard/services/ward/lib/verify.js (the fullest walk:
 * genesis + seq + linkage + hash recomputation + uniqueness + tips + signatures)
 * and the QLOGS verifier math in quox-qluster/server/lib/wardVerify.js.
 * Decoupled from any storage backend: it takes an ordered entry list and
 * optional tips directly, and returns a spec-conformant ward_verification_result.
 */

import type { KeyObject } from 'node:crypto';
import { chainHash as legacyChainHash, chainHashV2, genesisHash, isWellFormedNfc } from './crypto.js';
import { verifyTipSignature, deriveKeyId } from './sign.js';
import {
  WARD_VERSION,
  LEGACY_WARD_VERSION,
  SOURCE_KINDS,
  type WardEntry,
  type WardTip,
  type VerificationResult,
} from './types.js';

const MAX_SAFE_SEQ = Number.MAX_SAFE_INTEGER; // 2^53 - 1 (SPEC §3.2 rule 4, §6.1)
const HEX64 = /^[0-9a-f]{64}$/;

/** The 10 hash-body string fields whose values must be non-null strings. */
const HASH_BODY_STRING_FIELDS = [
  'ward_version',
  'ward_entry_id',
  'chain_id',
  'witnessed_at',
  'source_kind',
  'source_id',
  'payload_hash',
  'prev_chain_hash',
  'issuer_id',
] as const;

const HASH_FIELDS = ['payload_hash', 'prev_chain_hash', 'chain_hash'] as const;

/**
 * Step 0 (VERIFICATION.md §3): validate an entry's well-formedness before any
 * hash is recomputed. Checks presence/type of all 11 required fields, 64-hex
 * hash fields, `seq` bounds, no null hash-body members, well-formed-NFC
 * hash-body strings (WARD-CANON-1 rule 3), and that `chain_id` does not
 * contain the reserved "::" sequence (SPEC §5.2). Returns a detail object
 * naming the failing rule, or `null` if the entry is well-formed.
 *
 * Duplicate JSON member names (WARD-CANON-1 rule 5) are NOT re-checked here:
 * `entries` are already-parsed JS objects, which cannot represent a
 * duplicate key by construction. That rule is enforced at the byte-parsing
 * boundary instead (`parseStrictJson`, used by FileStore and the CLI).
 */
function validateEntryWellFormedness(entry: WardEntry): Record<string, unknown> | null {
  for (const field of HASH_BODY_STRING_FIELDS) {
    const value = (entry as unknown as Record<string, unknown>)[field];
    if (value === null) {
      return { field, rule: 'no-null-hash-body-member', message: `${field} is null` };
    }
    if (typeof value !== 'string' || value.length === 0) {
      return { field, rule: 'required-field', message: `${field} is missing or not a non-empty string` };
    }
  }
  const seq = (entry as unknown as Record<string, unknown>).seq;
  if (typeof seq !== 'number' || !Number.isInteger(seq) || seq < 1 || seq > MAX_SAFE_SEQ) {
    return { field: 'seq', rule: 'seq-range', message: `seq must be an integer in [1, 2^53 - 1], got ${String(seq)}` };
  }

  for (const field of HASH_FIELDS) {
    const value = (entry as unknown as Record<string, unknown>)[field];
    if (typeof value !== 'string' || !HEX64.test(value)) {
      return { field, rule: 'hex64', message: `${field} must be 64-char lowercase hex` };
    }
  }

  if (!SOURCE_KINDS.includes(entry.source_kind)) {
    return { field: 'source_kind', rule: 'enum', message: `unrecognized source_kind: ${String(entry.source_kind)}` };
  }

  if (entry.chain_id.includes('::')) {
    return { field: 'chain_id', rule: 'reserved-delimiter', message: 'chain_id MUST NOT contain "::" (SPEC §5.2)' };
  }

  for (const field of HASH_BODY_STRING_FIELDS) {
    const value = (entry as unknown as Record<string, string>)[field];
    if (!isWellFormedNfc(value)) {
      return { field, rule: 'nfc-well-formed', message: `${field} is not well-formed Unicode in NFC (WARD-CANON-1 rule 3)` };
    }
  }

  return null;
}

/** An external anchor pins chain state out of band (mitigates tail-rewrite). */
export interface AnchorOptions {
  /**
   * The externally-pinned tip: either a full tip object or a bare
   * tip_chain_hash hex string. The computed chain state at the anchor point
   * MUST match, else BROKEN (TIP_MISMATCH, anchor context).
   */
  expectedTip?: WardTip | string;
  /**
   * The chain head MUST reach at least this seq, else BROKEN
   * (TRUNCATED_BEHIND_ANCHOR). Catches tail truncation.
   */
  expectedHeadSeq?: number;
}

export interface VerifyOptions {
  tips?: WardTip[];
  /** Public key for tip signature verification (Ed25519). */
  publicKey?: KeyObject;
  /**
   * Assert the signing key identity out of band. When set, every tip's key_id
   * MUST equal this value, else BROKEN (KEY_ID_MISMATCH). Use this for opaque
   * or DID-based key_ids. When unset but publicKey is given, the verifier
   * binds key_id to deriveKeyId(publicKey) instead.
   */
  expectedKeyId?: string;
  /**
   * Fail on unsigned or unverified tips. Default false (back-compat). When
   * true, a tip without a sig, or a run that verifies zero signatures, is
   * BROKEN (SIGNATURE_REQUIRED).
   */
  requireSignatures?: boolean;
  /** External anchor to defeat tail-rewrite (see AnchorOptions). */
  anchor?: AnchorOptions;
}

/**
 * Verify a WARD chain's integrity. `entries` MUST be ordered by seq ascending.
 * An empty chain is INTACT (mirrors services/ward and the QLOGS verifier).
 */
export function verifyChain(
  chainId: string,
  entries: readonly WardEntry[],
  opts: VerifyOptions = {},
): VerificationResult {
  const expectedGenesis = genesisHash(chainId);

  if (entries.length === 0) {
    return {
      status: 'INTACT',
      chain_id: chainId,
      ward_version: WARD_VERSION,
      entry_count: 0,
      head_seq: 0,
      head_chain_hash: expectedGenesis,
      genesis_verified: true,
      tips_verified: 0,
      signatures_verified: 0,
      warnings: [],
    };
  }

  // Step 0 — validate every entry's well-formedness before any hash is
  // recomputed (VERIFICATION.md §3 Step 0). Runs as a full pre-pass so a
  // malformed entry can't be reached (and its garbage fields hashed or
  // linked against) by any later step, including genesis.
  for (const entry of entries) {
    const failure = validateEntryWellFormedness(entry);
    if (failure) {
      return {
        status: 'BROKEN',
        chain_id: chainId,
        reason: 'SCHEMA_INVALID',
        details: { seq: entry.seq, ward_entry_id: entry.ward_entry_id, ...failure },
      };
    }
  }

  // Step 1 — genesis: entry seq=1 links to the computed genesis hash.
  const first = entries[0]!;
  if (first.seq !== 1) {
    return {
      status: 'BROKEN',
      chain_id: chainId,
      reason: 'SEQ_INVALID',
      details: { message: 'first entry seq is not 1', found_seq: first.seq },
    };
  }
  if (first.prev_chain_hash !== expectedGenesis) {
    return {
      status: 'BROKEN',
      chain_id: chainId,
      reason: 'GENESIS_MISMATCH',
      details: { expected: expectedGenesis, found: first.prev_chain_hash },
    };
  }

  // Steps 2-4 — walk the chain.
  const seenSources = new Set<string>();
  let prevHash = expectedGenesis;
  const warnings: string[] = [];

  // Version monotonicity (SPEC §16.1, VERIFICATION.md §3 Step 2.4): once any
  // entry declares 0.2, a later entry MUST NOT declare 0.1.
  let sawCurrentVersion = false;

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i]!;
    const expectedSeq = i + 1;

    // Step 4a — contiguous seq starting at 1, no gaps/duplicates.
    if (entry.seq !== expectedSeq) {
      return {
        status: 'BROKEN',
        chain_id: chainId,
        reason: 'SEQ_INVALID',
        details: {
          expected_seq: expectedSeq,
          found_seq: entry.seq,
          ward_entry_id: entry.ward_entry_id,
        },
      };
    }

    // Step 3 — linkage: prev_chain_hash matches the running previous hash.
    if (entry.prev_chain_hash !== prevHash) {
      return {
        status: 'BROKEN',
        chain_id: chainId,
        reason: 'CHAIN_LINK_BROKEN',
        details: {
          seq: entry.seq,
          ward_entry_id: entry.ward_entry_id,
          expected_prev: prevHash,
          found_prev: entry.prev_chain_hash,
        },
      };
    }

    // Step 2 — select the hash scheme from ward_version (SPEC §16.1,
    // VERIFICATION.md §3 Step 2), recompute chain_hash under that scheme, and
    // confirm it matches the stored value.
    let computed: string;
    if (entry.ward_version === WARD_VERSION) {
      sawCurrentVersion = true;
      // "0.2" -> canonical-JSON hash body (SPEC §4.4).
      computed = chainHashV2({
        wardVersion: entry.ward_version,
        wardEntryId: entry.ward_entry_id,
        chainId: entry.chain_id,
        seq: entry.seq,
        witnessedAt: entry.witnessed_at,
        sourceKind: entry.source_kind,
        sourceId: entry.source_id,
        payloadHash: entry.payload_hash,
        prevChainHash: entry.prev_chain_hash,
        issuerId: entry.issuer_id,
      });
    } else if (entry.ward_version === LEGACY_WARD_VERSION) {
      // Version monotonicity (SPEC §16.1, VERIFICATION.md §3 Step 2.4): a
      // v0.1 entry MUST NOT follow a v0.2 entry — the writer only downgrades
      // by mistake or tamper, never legitimately.
      if (sawCurrentVersion) {
        return {
          status: 'BROKEN',
          chain_id: chainId,
          reason: 'VERSION_DOWNGRADE',
          details: {
            seq: entry.seq,
            ward_entry_id: entry.ward_entry_id,
            message: `entry declares ward_version "${LEGACY_WARD_VERSION}" after a "${WARD_VERSION}" entry earlier in the chain`,
          },
        };
      }
      // "0.1" -> legacy delimiter concatenation, verify-only (SPEC Appendix A).
      computed = legacyChainHash({
        prevChainHash: entry.prev_chain_hash,
        chainId,
        seq: entry.seq,
        wardEntryId: entry.ward_entry_id,
        timestamp: entry.witnessed_at,
        sourceKind: entry.source_kind,
        sourceId: entry.source_id,
        payloadHash: entry.payload_hash,
      });
      // Delimiter-injection exposure warning (SPEC Appendix A, VERIFICATION.md
      // §3 Step 2.4): a v0.1 entry whose ward_entry_id/source_id carries the
      // "|" separator could collide with a different field tuple.
      if (entry.ward_entry_id.includes('|') || entry.source_id.includes('|')) {
        warnings.push(
          `entry seq ${entry.seq} (${entry.ward_entry_id}) is ward_version 0.1 and its ward_entry_id or source_id contains "|", exposing it to delimiter-injection collision under the legacy hash scheme (SPEC Appendix A)`,
        );
      }
    } else {
      // Any other value -> BROKEN, with a detail naming the unrecognized
      // version (VERIFICATION.md §3 Step 2).
      return {
        status: 'BROKEN',
        chain_id: chainId,
        reason: 'CHAIN_HASH_MISMATCH',
        details: {
          seq: entry.seq,
          ward_entry_id: entry.ward_entry_id,
          message: `unrecognized ward_version: ${String(entry.ward_version)}`,
          ward_version: entry.ward_version,
        },
      };
    }
    if (computed !== entry.chain_hash) {
      return {
        status: 'BROKEN',
        chain_id: chainId,
        reason: 'CHAIN_HASH_MISMATCH',
        details: {
          seq: entry.seq,
          ward_entry_id: entry.ward_entry_id,
          expected_chain_hash: computed,
          found_chain_hash: entry.chain_hash,
        },
      };
    }

    // Step 4b — uniqueness of (chain_id, source_kind, source_id).
    const sourceKey = `${entry.source_kind}:${entry.source_id}`;
    if (seenSources.has(sourceKey)) {
      return {
        status: 'BROKEN',
        chain_id: chainId,
        reason: 'DUPLICATE_SOURCE',
        details: {
          seq: entry.seq,
          source_kind: entry.source_kind,
          source_id: entry.source_id,
        },
      };
    }
    seenSources.add(sourceKey);

    prevHash = entry.chain_hash;
  }

  const last = entries[entries.length - 1]!;

  // External anchor (mitigates tail-rewrite). Evaluated before tips so an
  // anchor breach is reported regardless of whether tips are supplied.
  if (opts.anchor) {
    const { expectedTip, expectedHeadSeq } = opts.anchor;
    if (expectedHeadSeq !== undefined && last.seq < expectedHeadSeq) {
      return {
        status: 'BROKEN',
        chain_id: chainId,
        reason: 'TRUNCATED_BEHIND_ANCHOR',
        details: { expected_head_seq: expectedHeadSeq, found_head_seq: last.seq },
      };
    }
    if (expectedTip !== undefined) {
      const anchorHash = typeof expectedTip === 'string' ? expectedTip : expectedTip.tip_chain_hash;
      const anchorSeq = typeof expectedTip === 'string' ? undefined : expectedTip.tip_seq;
      let computedHash: string;
      if (anchorSeq !== undefined) {
        const anchorEntry = entries.find((e) => e.seq === anchorSeq);
        if (!anchorEntry) {
          return {
            status: 'BROKEN',
            chain_id: chainId,
            reason: 'TRUNCATED_BEHIND_ANCHOR',
            details: { expected_head_seq: anchorSeq, found_head_seq: last.seq },
          };
        }
        computedHash = anchorEntry.chain_hash;
      } else {
        computedHash = last.chain_hash;
      }
      if (computedHash !== anchorHash) {
        return {
          status: 'BROKEN',
          chain_id: chainId,
          reason: 'TIP_MISMATCH',
          details: {
            anchor: true,
            tip_seq: anchorSeq,
            expected: anchorHash,
            found: computedHash,
          },
        };
      }
    }
  }

  // Step 5 — tips (if present).
  const tips = opts.tips ?? [];
  let tipsVerified = 0;
  let signaturesVerified = 0;
  // `warnings` accumulates from Step 2 (v0.1 delimiter-injection exposure)
  // through to tip signature downgrades below.

  // The key identity the tips are expected to carry (VERIFICATION.md §5 step 3
  // — the key must participate). Explicit expectedKeyId wins; otherwise the
  // supplied public key's fingerprint binds the declared key_id.
  const expectedKeyId =
    opts.expectedKeyId ?? (opts.publicKey ? deriveKeyId(opts.publicKey) : undefined);

  for (const tip of tips) {
    const tipEntry = entries.find((e) => e.seq === tip.tip_seq);
    if (!tipEntry) {
      return {
        status: 'PARTIAL',
        chain_id: chainId,
        reason: 'INCOMPLETE_CHAIN',
        details: {
          verified_through_seq: entries.length,
          tip_references_seq: tip.tip_seq,
        },
      };
    }
    if (tip.tip_chain_hash !== tipEntry.chain_hash) {
      return {
        status: 'BROKEN',
        chain_id: chainId,
        reason: 'TIP_MISMATCH',
        details: {
          tip_id: tip.tip_id,
          tip_seq: tip.tip_seq,
          expected: tipEntry.chain_hash,
          found: tip.tip_chain_hash,
        },
      };
    }
    tipsVerified++;

    // Bind the key identity (VERIFICATION.md §5 step 3) before trusting the sig.
    if (tip.key_id !== undefined && expectedKeyId !== undefined && tip.key_id !== expectedKeyId) {
      return {
        status: 'BROKEN',
        chain_id: chainId,
        reason: 'KEY_ID_MISMATCH',
        details: {
          tip_id: tip.tip_id,
          tip_seq: tip.tip_seq,
          expected_key_id: expectedKeyId,
          found_key_id: tip.key_id,
        },
      };
    }

    if (opts.requireSignatures && !tip.sig) {
      return {
        status: 'BROKEN',
        chain_id: chainId,
        reason: 'SIGNATURE_REQUIRED',
        details: { tip_id: tip.tip_id, tip_seq: tip.tip_seq },
      };
    }

    if (tip.sig && opts.publicKey) {
      const ok = verifyTipSignature(tip.tip_chain_hash, tip.sig, opts.publicKey);
      if (!ok) {
        return {
          status: 'BROKEN',
          chain_id: chainId,
          reason: 'TIP_SIGNATURE_INVALID',
          details: { tip_id: tip.tip_id, tip_seq: tip.tip_seq, key_id: tip.key_id },
        };
      }
      signaturesVerified++;
    } else if (tip.sig && !opts.publicKey) {
      warnings.push(
        `tip ${tip.tip_id} has a signature but no public key was provided for verification`,
      );
    } else if (!tip.sig && tip.key_id !== undefined) {
      // Signed-capable tip (declares a key_id) that arrived without a sig: a
      // silent signature downgrade. Surface it (finding 3).
      warnings.push(
        `tip ${tip.tip_id} declares key_id ${tip.key_id} but carries no signature (possible downgrade)`,
      );
    }
  }

  if (opts.requireSignatures && signaturesVerified === 0) {
    return {
      status: 'BROKEN',
      chain_id: chainId,
      reason: 'SIGNATURE_REQUIRED',
      details: { message: 'requireSignatures is set but no signature was verified' },
    };
  }

  return {
    status: 'INTACT',
    chain_id: chainId,
    // The head entry's own declared version, not a hardcoded constant: a
    // chain MAY contain v0.1 entries followed by v0.2 entries if the writer
    // upgraded mid-chain (SPEC §16.1), so this reflects the scheme the chain
    // is currently being written under.
    ward_version: last.ward_version,
    entry_count: entries.length,
    head_seq: last.seq,
    head_chain_hash: last.chain_hash,
    genesis_verified: true,
    tips_verified: tipsVerified,
    signatures_verified: signaturesVerified,
    warnings,
  };
}
