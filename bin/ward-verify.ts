#!/usr/bin/env node
/**
 * ward-verify — verify a WARD chain export file (VERIFICATION.md §6).
 *
 * Mirrors the exit-code and result semantics of
 * quox-dashboard/services/ward/bin/ward-verify.js, but reads a portable JSON
 * chain export instead of a SQLite store, so it has zero runtime dependencies.
 *
 * Usage:
 *   ward-verify <chain.json>
 *   ward-verify --chain <chain.json> [--pubkey <ed25519.pem>] [--pretty]
 *
 * Input file shape:
 *   { "chain_id": "...", "entries": [ ...ward entries... ], "tips": [ ... ] }
 * (chain_id may be omitted if entries[0].chain_id is present.)
 *
 * Exit codes: 0 INTACT · 1 BROKEN · 2 ERROR · 3 PARTIAL
 */

import { parseArgs } from 'node:util';
import { readFileSync, existsSync } from 'node:fs';
import { verifyChain, type AnchorOptions } from '../src/verify.js';
import { publicKeyFromPem } from '../src/sign.js';
import { parseStrictJson } from '../src/strict-json.js';
import type { ChainExport, VerificationResult, WardTip } from '../src/types.js';

const EXIT_INTACT = 0;
const EXIT_BROKEN = 1;
const EXIT_ERROR = 2;
const EXIT_PARTIAL = 3;

function usage(): void {
  process.stdout.write(
    `ward-verify — WARD chain integrity verification (v0.2, legacy v0.1 verify-only)

Usage:
  ward-verify <chain.json>
  ward-verify --chain <chain.json> [--pubkey <pem>] [--anchor <tip.json>] [--require-signed] [--pretty]

Options:
  --chain          <path>   Path to a WARD chain export JSON file (or pass positionally)
  --pubkey         <path>   Path to an Ed25519 public-key PEM (for tip signatures)
  --anchor         <path>   Path to a saved tip JSON to pin chain state out of band
  --require-signed          Fail unless a tip signature is verified
  --pretty                  Pretty-print the JSON result
  --help                    Show this help

Exit codes:
  0  INTACT · 1  BROKEN · 2  ERROR · 3  PARTIAL
`,
  );
}

function exitCodeFor(status: VerificationResult['status']): number {
  if (status === 'INTACT') return EXIT_INTACT;
  if (status === 'BROKEN') return EXIT_BROKEN;
  if (status === 'PARTIAL') return EXIT_PARTIAL;
  return EXIT_ERROR;
}

export function main(argv: string[] = process.argv.slice(2)): number {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        chain: { type: 'string' },
        pubkey: { type: 'string' },
        anchor: { type: 'string' },
        'require-signed': { type: 'boolean', default: false },
        pretty: { type: 'boolean', default: false },
        help: { type: 'boolean', default: false },
      },
      strict: true,
    });
  } catch (err) {
    process.stderr.write(`Error: ${(err as Error).message}\n`);
    usage();
    return EXIT_ERROR;
  }

  const { chain, pubkey, anchor, pretty, help } = parsed.values;
  const requireSigned = parsed.values['require-signed'] as boolean;
  if (help) {
    usage();
    return EXIT_INTACT;
  }

  const chainPath = (chain as string | undefined) ?? parsed.positionals[0];
  if (!chainPath) {
    process.stderr.write('Error: a chain export file is required\n');
    usage();
    return EXIT_ERROR;
  }
  if (!existsSync(chainPath)) {
    process.stderr.write(`Error: file not found: ${chainPath}\n`);
    return EXIT_ERROR;
  }

  let data: ChainExport;
  try {
    data = parseStrictJson(readFileSync(chainPath, 'utf8')) as ChainExport;
  } catch (err) {
    process.stderr.write(`Error: failed to parse ${chainPath}: ${(err as Error).message}\n`);
    return EXIT_ERROR;
  }

  const entries = Array.isArray(data.entries) ? data.entries : [];
  const chainId = data.chain_id ?? entries[0]?.chain_id;
  if (!chainId) {
    process.stderr.write('Error: chain_id missing (not in file and no entries)\n');
    return EXIT_ERROR;
  }

  let publicKey;
  if (pubkey) {
    if (!existsSync(pubkey as string)) {
      process.stderr.write(`Error: public key not found: ${pubkey}\n`);
      return EXIT_ERROR;
    }
    try {
      publicKey = publicKeyFromPem(readFileSync(pubkey as string, 'utf8'));
    } catch (err) {
      process.stderr.write(`Error: failed to load public key: ${(err as Error).message}\n`);
      return EXIT_ERROR;
    }
  }

  let anchorOpt: AnchorOptions | undefined;
  if (anchor) {
    if (!existsSync(anchor as string)) {
      process.stderr.write(`Error: anchor file not found: ${anchor}\n`);
      return EXIT_ERROR;
    }
    try {
      const anchorTip = parseStrictJson(readFileSync(anchor as string, 'utf8')) as WardTip;
      anchorOpt = { expectedTip: anchorTip, expectedHeadSeq: anchorTip.tip_seq };
    } catch (err) {
      process.stderr.write(`Error: failed to parse anchor ${anchor}: ${(err as Error).message}\n`);
      return EXIT_ERROR;
    }
  }

  const result = verifyChain(chainId, entries, {
    tips: data.tips,
    publicKey,
    anchor: anchorOpt,
    requireSignatures: requireSigned,
  });
  process.stdout.write(JSON.stringify(result, null, pretty ? 2 : 0) + '\n');
  return exitCodeFor(result.status);
}

// Run when invoked directly (not when imported by tests).
import { fileURLToPath } from 'node:url';
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  process.exit(main());
}
