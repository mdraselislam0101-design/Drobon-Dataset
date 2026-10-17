#!/usr/bin/env node
/**
 * Import GitHub-reviewed advisories (GHSA) into vuln-intel/ as v1 records.
 *
 * Source: the GitHub Advisory API (api.github.com/advisories) —
 * reviewed advisories only, withdrawn excluded. Every record carries
 * full provenance (source GHSA + advisory URL + retrieval time) and
 * must pass scripts/validate.mjs before it is written; anything that
 * fails is skipped with a logged reason, never force-fitted.
 *
 * Usage:
 *   GITHUB_TOKEN=... node scripts/import-ghsa.mjs [--ecosystem npm|pip|both]
 *     [--limit N] [--out vuln-intel] [--force] [--max-pages N] [--dry-run]
 *
 * The token is optional but recommended (higher API rate limit).
 * Existing files are skipped; --force re-checks content (identical files
 * skip as duplicates, differing files quarantine as conflicts - never
 * overwritten). Retrieval follows API Link pagination (default 10 pages,
 * cap 50) with bounded retries (scripts/retry.mjs) and tmp checkpoints
 * (scripts/checkpoint.mjs).
 *
 * Safety contract (this pump):
 *  - Fail-closed batching: all pages of all ecosystems are fetched and
 *    validated BEFORE any file is written. A failed run writes nothing.
 *  - Repeated-cursor guard: a next-URL already visited stops traversal
 *    (no infinite loops, no double-counted pages).
 *  - Safe traversal: next-URLs must stay on https://api.github.com/ - a
 *    crafted Link header can never redirect the fetch.
 *  - --dry-run: discover + validate + report, writes NOTHING (not even
 *    quarantine); the only mode that may run without the ingestion gates.
 *  - Structured summary separates discovered (validated candidates) from
 *    production-approved (always 0 here: promotion needs owner gates).
 *  - Production runs call requireGates() first: any BLOCKED gate aborts
 *    before args, network, or writes (fail-closed).
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { SCHEMA_VERSION, validateRecord } from './validate.mjs';
import { requireGates } from './ingestion-gates.mjs';
import { HttpError, withRetries } from './retry.mjs';
import { appendCursor, lastCursorFor, loadCheckpoint } from './checkpoint.mjs';
import { quarantineRecord } from './quarantine.mjs';

// REST advisory API uses low/medium/high/critical ("moderate" kept defensively).
const SEVERITY_MAP = {
  low: 'LOW',
  medium: 'MEDIUM',
  moderate: 'MEDIUM',
  high: 'HIGH',
  critical: 'CRITICAL',
};
const ECOSYSTEM_MAP = { npm: 'npm', pip: 'pypi' };
export const SAFE_NEXT_PREFIX = 'https://api.github.com/';

export function parseArgs(argv) {
  const args = { ecosystem: 'both', limit: 15, out: 'vuln-intel', force: false, maxPages: 10, dryRun: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--ecosystem') {
      args.ecosystem = argv[i + 1] ?? '';
      i += 1;
    } else if (arg === '--limit') {
      args.limit = Number.parseInt(argv[i + 1] ?? '', 10);
      i += 1;
    } else if (arg === '--out') {
      args.out = argv[i + 1] ?? '';
      i += 1;
    } else if (arg === '--force') {
      args.force = true;
    } else if (arg === '--max-pages') {
      args.maxPages = Number.parseInt(argv[i + 1] ?? '', 10);
      i += 1;
    } else if (arg === '--dry-run') {
      args.dryRun = true;
    } else {
      throw new Error(`unknown argument "${arg}"`);
    }
  }
  if (!['npm', 'pip', 'both'].includes(args.ecosystem)) {
    throw new Error('--ecosystem must be npm, pip, or both');
  }
  if (!Number.isInteger(args.limit) || args.limit < 1 || args.limit > 100) {
    throw new Error('--limit must be an integer 1..100');
  }
  if (!Number.isInteger(args.maxPages) || args.maxPages < 1 || args.maxPages > 50) {
    throw new Error('--max-pages must be an integer 1..50');
  }
  if (args.out === '') {
    throw new Error('--out must not be empty');
  }
  return args;
}

export function parseLinkNext(linkHeader) {
  if (typeof linkHeader !== 'string' || linkHeader === '') {
    return null;
  }
  for (const part of linkHeader.split(',')) {
    const match = /<([^>]+)>\s*;\s*rel="next"/.exec(part.trim());
    if (match !== null) {
      return match[1];
    }
  }
  return null;
}

/** Next-URLs must stay on the advisory API host (crafted Link headers cannot redirect us). */
export function isSafeNextUrl(url) {
  return typeof url === 'string' && url.startsWith(SAFE_NEXT_PREFIX);
}

export async function fetchAdvisoriesPage(fetchImpl, url, headers, retryOptions = {}) {
  return withRetries(async () => {
    const response = await fetchImpl(url, { headers });
    if (!response.ok) {
      throw new HttpError(response.status, response.statusText, url);
    }
    const items = await response.json();
    const link = typeof response.headers?.get === 'function' ? response.headers.get('link') : null;
    return { items: Array.isArray(items) ? items : [], nextUrl: parseLinkNext(link) };
  }, retryOptions);
}

export async function fetchAdvisories(ecosystem, token, options = {}) {
  const fetchImpl = options.fetchImpl ?? fetch;
  const maxPages = options.maxPages ?? 10;
  const checkpointFile = options.checkpointFile ?? null;
  const retryOptions = options.retry ?? {};
  const onNote = options.onNote ?? null;
  const note = (text) => {
    if (onNote !== null) onNote(text);
  };
  if (!Number.isInteger(maxPages) || maxPages < 1 || maxPages > 50) {
    throw new Error('fetchAdvisories: maxPages must be an integer 1..50');
  }
  const headers = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'drobon-dataset-importer',
  };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  const startUrl =
    `https://api.github.com/advisories?ecosystem=${ecosystem}` +
    '&type=reviewed&sort=updated&direction=desc&per_page=100';
  let skipPages = 0;
  if (checkpointFile !== null) {
    const cursor = lastCursorFor(loadCheckpoint(checkpointFile), 'ghsa', `advisories:${ecosystem}`);
    skipPages = cursor === null ? 0 : Number.parseInt(cursor.value, 10) || 0;
  }
  const collected = [];
  const seenUrls = new Set();
  let url = startUrl;
  let pageIndex = 0;
  while (url !== null && pageIndex < maxPages) {
    if (seenUrls.has(url)) {
      note(`repeated cursor guard: next-URL already visited, stopping (${url.slice(0, 80)})`);
      break;
    }
    seenUrls.add(url);
    pageIndex += 1;
    const page = await fetchAdvisoriesPage(fetchImpl, url, headers, retryOptions);
    if (pageIndex > skipPages) {
      collected.push(...page.items);
    }
    if (checkpointFile !== null) {
      appendCursor(checkpointFile, {
        source: 'ghsa',
        kind: `advisories:${ecosystem}`,
        value: String(pageIndex),
        at: new Date().toISOString(),
      });
    }
    if (page.nextUrl !== null && !isSafeNextUrl(page.nextUrl)) {
      note(`unsafe next-URL rejected (must start with ${SAFE_NEXT_PREFIX}): ${page.nextUrl.slice(0, 80)}`);
      break;
    }
    url = page.nextUrl;
  }
  return collected;
}

function toRecords(advisory, retrievedAt, skips) {
  const ghsaId = advisory.ghsa_id;
  if (typeof ghsaId !== 'string' || ghsaId === '') {
    skips.push('missing ghsa_id');
    return [];
  }
  if (advisory.withdrawn_at !== null && advisory.withdrawn_at !== undefined) {
    skips.push(`${ghsaId}: withdrawn`);
    return [];
  }
  const severity = SEVERITY_MAP[advisory.severity] ?? null;
  if (severity === null) {
    skips.push(`${ghsaId}: unknown severity "${String(advisory.severity)}"`);
    return [];
  }
  const summary = typeof advisory.summary === 'string' ? advisory.summary.trim() : '';
  if (summary === '') {
    skips.push(`${ghsaId}: empty summary`);
    return [];
  }
  const url = advisory.html_url;
  const vulnerabilities = Array.isArray(advisory.vulnerabilities) ? advisory.vulnerabilities : [];
  const records = [];
  for (const vuln of vulnerabilities) {
    const eco = ECOSYSTEM_MAP[vuln?.package?.ecosystem] ?? null;
    const name = vuln?.package?.name;
    const range = vuln?.vulnerable_version_range;
    if (eco === null || typeof name !== 'string' || name === '') {
      continue;
    }
    if (typeof range !== 'string' || range.trim() === '') {
      skips.push(`${ghsaId} (${name}): no vulnerable version range`);
      continue;
    }
    const affected = { range: range.trim() };
    if (typeof vuln.first_patched_version === 'string' && vuln.first_patched_version.trim() !== '') {
      affected.fixed = vuln.first_patched_version.trim();
    }
    const record = {
      schemaVersion: SCHEMA_VERSION,
      fixture: false,
      id: ghsaId,
      ecosystem: eco,
      package: name,
      summary,
      severity,
      url,
      affected: [affected],
      provenance: {
        source: 'GHSA',
        sourceUrl: url,
        retrievedAt,
        license: 'Verify terms: github.com/github/advisory-database',
      },
    };
    const errors = validateRecord(record);
    if (errors.length > 0) {
      skips.push(`${ghsaId} (${name}): rejected: validation failed (${errors[0]})`);
      continue;
    }
    records.push(record);
  }
  if (records.length === 0 && vulnerabilities.length > 0) {
    skips.push(`${ghsaId}: no usable npm/pip entries`);
  }
  return records;
}

/**
 * Run one import batch. Writes nothing on fetch failure (fail-closed
 * staging). Returns a structured summary; productionApproved is always 0
 * here because promotion needs the owner gates plus a license grant.
 */
export async function runImport(options = {}) {
  const fetchImpl = options.fetchImpl ?? fetch;
  const token = options.token ?? '';
  const ecosystems = options.ecosystems ?? ['npm', 'pip'];
  const outRoot = options.outRoot ?? resolve(process.cwd(), 'vuln-intel');
  const quarantineRoot = options.quarantineRoot ?? process.cwd();
  const force = options.force ?? false;
  const limit = options.limit ?? 15;
  const maxPages = options.maxPages ?? 10;
  const dryRun = options.dryRun ?? false;
  const checkpointFileFor = options.checkpointFileFor ?? (() => null);
  const retryOptions = options.retry ?? {};
  const retrievedAt = options.retrievedAt ?? new Date().toISOString();
  const batchId = options.batchId ?? `ghsa-${retrievedAt.slice(0, 10)}`;

  const summary = {
    mode: dryRun ? 'dry-run' : 'import',
    fetched: 0,
    discovered: 0,
    accepted: 0,
    rejected: 0,
    duplicate: 0,
    skipped: 0,
    failed: 0,
    productionApproved: 0,
    notes: [],
    skips: [],
    error: null,
  };
  const skips = summary.skips;

  // ---- STAGE 1: fetch everything (any failure aborts with zero writes) ----
  let advisoriesByEcosystem;
  try {
    advisoriesByEcosystem = [];
    for (const ecosystem of ecosystems) {
      const advisories = await fetchAdvisories(ecosystem, token, {
        fetchImpl,
        maxPages,
        retry: retryOptions,
        checkpointFile: checkpointFileFor(ecosystem),
        onNote: (text) => summary.notes.push(text),
      });
      summary.fetched += advisories.length;
      advisoriesByEcosystem.push({ ecosystem, advisories });
    }
  } catch (err) {
    summary.failed += 1;
    summary.error = String(err?.message ?? err);
    summary.skips = skips;
    return summary;
  }

  // ---- STAGE 2: transform + validate (still no writes) ----
  const staged = [];
  const stagedFingerprints = new Set();
  for (const { advisories } of advisoriesByEcosystem) {
    for (const advisory of advisories) {
      const before = skips.length;
      const records = toRecords(advisory, retrievedAt, skips);
      const newSkips = skips.slice(before);
      summary.skipped += newSkips.filter((s) => !s.includes('rejected:')).length;
      summary.rejected += newSkips.filter((s) => s.includes('rejected:')).length;
      for (const record of records) {
        // Duplicate-page / repeated-item protection: identical staged records
        // (same identity + same affected range) are storage dupes, never new shards.
        const fingerprint = JSON.stringify([record.id, record.ecosystem, record.package, record.affected]);
        if (stagedFingerprints.has(fingerprint)) {
          summary.duplicate += 1;
          skips.push(`${record.id} (${record.package}): duplicate: identical record already staged`);
          continue;
        }
        stagedFingerprints.add(fingerprint);
        summary.discovered += 1;
        staged.push(record);
      }
    }
  }

  // ---- STAGE 3: commit (skipped entirely in dry-run) ----
  if (dryRun) {
    summary.skipped += staged.length; // would-write, not written
    summary.notes.push(`dry-run: ${staged.length} validated record(s) NOT written`);
    return summary;
  }
  const perAdvisoryCount = new Map();
  let kept = 0;
  for (const record of staged) {
    if (kept >= limit) {
      summary.skipped += 1;
      skips.push(`${record.id} (${record.package}): skipped: limit ${limit} reached`);
      continue;
    }
    const seen = (perAdvisoryCount.get(record.id) ?? 0) + 1;
    perAdvisoryCount.set(record.id, seen);
    const fileName = seen === 1 ? `${record.id}.json` : `${record.id}--${seen}.json`;
    const dir = join(outRoot, record.ecosystem);
    const file = join(dir, fileName);
    const newBytes = `${JSON.stringify(record, null, 2)}\n`;
    if (existsSync(file)) {
      if (!force) {
        summary.duplicate += 1;
        skips.push(`${record.id} (${record.package}): duplicate: file exists`);
        continue;
      }
      if (readFileSync(file, 'utf8') === newBytes) {
        summary.duplicate += 1;
        skips.push(`${record.id} (${record.package}): duplicate, unchanged`);
        continue;
      }
      quarantineRecord(quarantineRoot, batchId, 'GHSA', record.id, record, `file conflict: ${file} differs; --force refuses to overwrite`);
      summary.skipped += 1;
      skips.push(`${record.id} (${record.package}): conflict quarantined`);
      continue;
    }
    mkdirSync(dir, { recursive: true });
    writeFileSync(file, newBytes);
    kept += 1;
    summary.accepted += 1;
  }
  return summary;
}

async function main() {
  const rawArgs = process.argv.slice(2);
  // Fail-closed first: production runs need every ingestion gate before any
  // arg parsing, network call, or write. --dry-run is the only exception
  // (writes nothing at all).
  const dryRun = rawArgs.includes('--dry-run');
  if (!dryRun) {
    requireGates();
  } else {
    process.stdout.write('import-ghsa: dry-run (no gates required; writes nothing)\n');
  }
  const args = parseArgs(rawArgs);
  const token = process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN ?? '';
  const runDay = new Date().toISOString().slice(0, 10);
  const summary = await runImport({
    fetchImpl: fetch,
    token,
    ecosystems: args.ecosystem === 'both' ? ['npm', 'pip'] : [args.ecosystem],
    outRoot: resolve(process.cwd(), args.out),
    quarantineRoot: process.cwd(),
    force: args.force,
    limit: args.limit,
    maxPages: args.maxPages,
    dryRun: args.dryRun,
    batchId: `ghsa-${runDay}`,
    checkpointFileFor: (ecosystem) => join(tmpdir(), `drobon-import-ghsa-${ecosystem}-${runDay}.json`),
  });
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
  for (const skip of summary.skips.slice(0, 30)) {
    process.stdout.write(`  skip: ${skip}\n`);
  }
  if (summary.skips.length > 30) {
    process.stdout.write(`  ... and ${summary.skips.length - 30} more skips\n`);
  }
  if (summary.failed > 0) {
    process.stderr.write(`import-ghsa: FAIL (${summary.error}) — nothing written\n`);
    process.exitCode = 1;
    return;
  }
  process.stdout.write(
    `import-ghsa: accepted ${summary.accepted}, discovered ${summary.discovered}, `
    + `rejected ${summary.rejected}, duplicate ${summary.duplicate}, skipped ${summary.skipped}; `
    + `production-approved 0 (owner gates required)\n`,
  );
}

const invokedAsScript =
  process.argv[1] !== undefined &&
  pathToFileURL(resolve(process.argv[1])).href === import.meta.url;

if (invokedAsScript) {
  main().catch((err) => {
    process.stderr.write(`import-ghsa: FAIL (${err.message})\n`);
    process.exitCode = 1;
  });
}
