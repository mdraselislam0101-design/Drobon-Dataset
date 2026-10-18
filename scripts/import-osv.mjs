#!/usr/bin/env node
/**
 * Import OSV records (https://osv.dev — open, aggregated vulnerabilities)
 * into vuln-intel/ as v1 records.
 *
 * OSV is queried per package (POST /v1/query), so imports走 over a
 * curated package list (data/osv-seed-packages.json by default).
 * Every record carries full provenance (source OSV + reference or
 * osv.dev URL + retrieval time) and must pass scripts/validate.mjs
 * before it is written; anything that fails is skipped with a logged
 * reason, never force-fitted.
 *
 * Severity comes from the record's CVSS score via the STANDARD CVSS
 * qualitative mapping (>=9 Critical, >=7 High, >=4 Medium, >0 Low,
 * 0 Info). Records without a parseable CVSS score are skipped —
 * severity is never guessed.
 *
 * Mapping notes:
 * - ecosystems: npm → npm, PyPI → pypi (case-insensitive); others skipped.
 * - ranges: ECOSYSTEM type (npm also accepts SEMVER); each
 *   introduced → fixed/last_affected segment becomes one affected
 *   entry; introduced "0" means "from the start" (no lower bound).
 * - withdrawn records are skipped.
 *
 * Usage:
 *   node scripts/import-osv.mjs [--packages-file data/osv-seed-packages.json]
 *     [--limit N] [--out vuln-intel] [--force] [--max-pages N]
 *
 * Needs network access to api.osv.dev. The mapping itself
 * (mapOsvVulnToRecords) is pure and covered by fixture tests in
 * scripts/test-packs.mjs, so it stays correct where the network is not.
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

export function parseArgs(argv) {
  const args = { packagesFile: 'data/osv-seed-packages.json', limit: 20, out: 'vuln-intel', force: false, maxPages: 5 };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--packages-file') {
      args.packagesFile = argv[i + 1] ?? '';
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
    } else {
      throw new Error(`unknown argument "${arg}"`);
    }
  }
  if (args.packagesFile === '') {
    throw new Error('--packages-file must not be empty');
  }
  if (!Number.isInteger(args.limit) || args.limit < 1 || args.limit > 100) {
    throw new Error('--limit must be an integer 1..100');
  }
  if (!Number.isInteger(args.maxPages) || args.maxPages < 1 || args.maxPages > 20) {
    throw new Error('--max-pages must be an integer 1..20');
  }
  if (args.out === '') {
    throw new Error('--out must not be empty');
  }
  return args;
}

function mapEcosystem(ecosystem) {
  const lowered = typeof ecosystem === 'string' ? ecosystem.toLowerCase() : '';
  if (lowered === 'npm') {
    return 'npm';
  }
  if (lowered === 'pypi') {
    return 'pypi';
  }
  return null;
}

function cvssScoreToSeverity(score) {
  const numeric = typeof score === 'number' ? score : Number.parseFloat(score);
  if (!Number.isFinite(numeric) || numeric < 0 || numeric > 10) {
    return null;
  }
  if (numeric >= 9) {
    return 'CRITICAL';
  }
  if (numeric >= 7) {
    return 'HIGH';
  }
  if (numeric >= 4) {
    return 'MEDIUM';
  }
  if (numeric > 0) {
    return 'LOW';
  }
  return 'INFO';
}

function severityOf(vuln) {
  const entries = Array.isArray(vuln.severity) ? vuln.severity : [];
  const pick =
    entries.find((entry) => entry?.type === 'CVSS_V3') ??
    entries.find((entry) => entry?.type === 'CVSS_V2') ??
    null;
  return pick === null ? null : cvssScoreToSeverity(pick.score);
}

function firstHttpsReference(vuln) {
  const references = Array.isArray(vuln.references) ? vuln.references : [];
  for (const reference of references) {
    const url = reference?.url;
    if (typeof url === 'string' && url.startsWith('https://') && url.length <= 400) {
      return url;
    }
  }
  return null;
}

function segmentsOf(events) {
  // Walk introduced → fixed/last_affected pairs; each pair is one segment.
  const segments = [];
  let introduced = null;
  for (const event of events) {
    if (typeof event !== 'object' || event === null) {
      continue;
    }
    if (typeof event.introduced === 'string') {
      if (introduced !== null) {
        segments.push({ introduced, fixed: null, lastAffected: null });
      }
      introduced = event.introduced;
    }
    if (typeof event.fixed === 'string' || typeof event.last_affected === 'string') {
      segments.push({
        introduced,
        fixed: typeof event.fixed === 'string' ? event.fixed : null,
        lastAffected: typeof event.last_affected === 'string' ? event.last_affected : null,
      });
      introduced = null;
    }
  }
  if (introduced !== null) {
    segments.push({ introduced, fixed: null, lastAffected: null });
  }
  return segments;
}

function segmentToEntry(segment) {
  const lower =
    segment.introduced !== null && segment.introduced !== '0' ? `>=${segment.introduced}` : null;
  let upper = null;
  let fixed = null;
  if (segment.fixed !== null) {
    upper = `<${segment.fixed}`;
    fixed = segment.fixed;
  } else if (segment.lastAffected !== null) {
    upper = `<=${segment.lastAffected}`;
  }
  if (lower === null && upper === null) {
    return null;
  }
  const entry = { range: lower !== null && upper !== null ? `${lower}, ${upper}` : (lower ?? upper) };
  if (fixed !== null) {
    entry.fixed = fixed;
  }
  return entry;
}

/**
 * Map one OSV vuln object to v1 records (one per affected npm/pypi
 * package). Pure function of (vuln, retrievedAt); skips are appended
 * to `skips`. Exported for fixture tests.
 */
export function mapOsvVulnToRecords(vuln, retrievedAt, skips) {
  const id = vuln?.id;
  if (typeof id !== 'string' || id === '') {
    skips.push('missing OSV id');
    return [];
  }
  if (vuln?.withdrawn !== null && vuln?.withdrawn !== undefined) {
    skips.push(`${id}: withdrawn`);
    return [];
  }
  const summary = typeof vuln?.summary === 'string' ? vuln.summary.trim() : '';
  if (summary === '') {
    skips.push(`${id}: empty summary`);
    return [];
  }
  const severity = severityOf(vuln);
  if (severity === null) {
    skips.push(`${id}: no parseable CVSS score`);
    return [];
  }
  const reference = firstHttpsReference(vuln);
  const sourceUrl = reference ?? `https://osv.dev/vulnerability/${id}`;
  const affected = Array.isArray(vuln?.affected) ? vuln.affected : [];
  const records = [];
  for (const entry of affected) {
    const ecosystem = mapEcosystem(entry?.package?.ecosystem);
    const name = entry?.package?.name;
    if (ecosystem === null || typeof name !== 'string' || name === '') {
      continue;
    }
    const ranges = Array.isArray(entry?.ranges) ? entry.ranges : [];
    const collected = [];
    for (const range of ranges) {
      const type = range?.type;
      const typeOk =
        type === 'ECOSYSTEM' || (ecosystem === 'npm' && type === 'SEMVER');
      if (!typeOk || !Array.isArray(range?.events)) {
        continue;
      }
      for (const segment of segmentsOf(range.events)) {
        const affectedEntry = segmentToEntry(segment);
        if (affectedEntry !== null) {
          collected.push(affectedEntry);
        }
      }
    }
    if (collected.length === 0) {
      skips.push(`${id} (${name}): no usable version segments`);
      continue;
    }
    const record = {
      schemaVersion: SCHEMA_VERSION,
      fixture: false,
      id,
      ecosystem,
      package: name,
      summary,
      severity,
      affected: collected.slice(0, 50),
      provenance: {
        source: 'OSV',
        sourceUrl,
        retrievedAt,
        license: 'Verify terms: osv.dev (open data, check per-record sources)',
      },
    };
    if (reference !== null) {
      record.url = reference;
    }
    const errors = validateRecord(record);
    if (errors.length > 0) {
      skips.push(`${id} (${name}): validation failed (${errors[0]})`);
      continue;
    }
    records.push(record);
  }
  if (records.length === 0) {
    skips.push(`${id}: no usable npm/pypi entries`);
  }
  return records;
}

export async function fetchOsvForPackage(name, ecosystem, options = {}) {
  const fetchImpl = options.fetchImpl ?? fetch;
  const maxPages = options.maxPages ?? 5;
  const checkpointFile = options.checkpointFile ?? null;
  const retryOptions = options.retry ?? {};
  if (!Number.isInteger(maxPages) || maxPages < 1 || maxPages > 20) {
    throw new Error('fetchOsvForPackage: maxPages must be an integer 1..20');
  }
  const kind = `osv:${ecosystem}:${name}`;
  let skipPages = 0;
  if (checkpointFile !== null) {
    const cursor = lastCursorFor(loadCheckpoint(checkpointFile), 'osv', kind);
    skipPages = cursor === null ? 0 : Number.parseInt(cursor.value, 10) || 0;
  }
  const vulns = [];
  let pageToken = null;
  const seenTokens = new Set();
  for (let page = 0; page < maxPages; page += 1) {
    const body = { package: { name, ecosystem }, page_size: 100 };
    if (pageToken !== null) {
      if (seenTokens.has(pageToken)) {
        // Repeated-cursor guard: a looping page_token would re-fetch the same
        // page and shard-duplicate its records. Stop fail-closed.
        if (typeof options.onNote === 'function') {
          options.onNote(`repeated page_token guard: stopping after token repeat for ${name}`);
        }
        break;
      }
      seenTokens.add(pageToken);
      body.page_token = pageToken;
    }
    const parsed = await withRetries(async () => {
      const response = await fetchImpl('https://api.osv.dev/v1/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!response.ok) {
        throw new HttpError(response.status, response.statusText, 'api.osv.dev/v1/query');
      }
      return response.json();
    }, retryOptions);
    if (page + 1 > skipPages && Array.isArray(parsed.vulns)) {
      vulns.push(...parsed.vulns);
    }
    if (checkpointFile !== null) {
      appendCursor(checkpointFile, { source: 'osv', kind, value: String(page + 1), at: new Date().toISOString() });
    }
    pageToken = parsed.next_page_token ?? null;
    if (pageToken === null) {
      break;
    }
    // No-progress guard: a next_token equal to the one we just spent means the
    // cursor is looping; stop instead of re-fetching the same page.
    const spentToken = body.page_token ?? null;
    if (spentToken !== null && pageToken === spentToken) {
      if (typeof options.onNote === 'function') {
        options.onNote(`repeated page_token guard: next_page_token equals sent token, stopping for ${name}`);
      }
      break;
    }
  }
  return vulns;
}

function loadPackageList(file) {
  const parsed = JSON.parse(readFileSync(file, 'utf8'));
  if (typeof parsed !== 'object' || parsed === null || !Array.isArray(parsed.packages)) {
    throw new Error(`${file}: expected { "packages": [{ "ecosystem", "name" }] }`);
  }
  return parsed.packages;
}

async function main() {
  requireGates();
  const args = parseArgs(process.argv.slice(2));
  const packages = loadPackageList(resolve(process.cwd(), args.packagesFile));
  const outRoot = resolve(process.cwd(), args.out);
  const retrievedAt = new Date().toISOString();
  const runDay = retrievedAt.slice(0, 10);
  const batchId = `osv-${runDay}`;
  const perIdCount = new Map();
  const skips = [];
  let written = 0;
  for (const pkg of packages) {
    if (written >= args.limit) {
      break;
    }
    if (typeof pkg?.name !== 'string' || typeof pkg?.ecosystem !== 'string') {
      skips.push('packages file: skipping malformed entry');
      continue;
    }
    let vulns;
    try {
      vulns = await fetchOsvForPackage(pkg.name, pkg.ecosystem, {
        maxPages: args.maxPages,
        checkpointFile: join(tmpdir(), `drobon-import-osv-${runDay}.json`),
      });
    } catch (err) {
      skips.push(`${pkg.ecosystem}:${pkg.name}: fetch failed (${err.message})`);
      continue;
    }
    for (const vuln of vulns) {
      if (written >= args.limit) {
        break;
      }
      const records = mapOsvVulnToRecords(vuln, retrievedAt, skips);
      for (const record of records) {
        if (written >= args.limit) {
          break;
        }
        const seen = (perIdCount.get(record.id) ?? 0) + 1;
        perIdCount.set(record.id, seen);
        const fileName = seen === 1 ? `${record.id}.json` : `${record.id}--${seen}.json`;
        const dir = join(outRoot, record.ecosystem);
        const file = join(dir, fileName);
        const newBytes = `${JSON.stringify(record, null, 2)}\n`;
        if (existsSync(file)) {
          if (!args.force) {
            skips.push(`${record.id} (${record.package}): file exists`);
            continue;
          }
          if (readFileSync(file, 'utf8') === newBytes) {
            skips.push(`${record.id} (${record.package}): duplicate, unchanged`);
            continue;
          }
          quarantineRecord(process.cwd(), batchId, 'OSV', record.id, record, `file conflict: ${file} differs; --force refuses to overwrite`);
          skips.push(`${record.id} (${record.package}): conflict quarantined`);
          continue;
        }
        mkdirSync(dir, { recursive: true });
        writeFileSync(file, newBytes);
        process.stdout.write(`wrote ${file}\n`);
        written += 1;
      }
    }
  }
  process.stdout.write(`import-osv: wrote ${written} records, ${skips.length} skips\n`);
  for (const skip of skips.slice(0, 30)) {
    process.stdout.write(`  skip: ${skip}\n`);
  }
  if (skips.length > 30) {
    process.stdout.write(`  ... and ${skips.length - 30} more skips\n`);
  }
}

const invokedAsScript =
  process.argv[1] !== undefined &&
  pathToFileURL(resolve(process.argv[1])).href === import.meta.url;

if (invokedAsScript) {
  main().catch((err) => {
    process.stderr.write(`import-osv: FAIL (${err.message})\n`);
    process.exitCode = 1;
  });
}
