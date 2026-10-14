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
 *     [--limit N] [--out vuln-intel] [--force]
 *
 * The token is optional but recommended (higher API rate limit).
 * Existing files are skipped unless --force is given.
 */
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { SCHEMA_VERSION, validateRecord } from './validate.mjs';

// REST advisory API uses low/medium/high/critical ("moderate" kept defensively).
const SEVERITY_MAP = {
  low: 'LOW',
  medium: 'MEDIUM',
  moderate: 'MEDIUM',
  high: 'HIGH',
  critical: 'CRITICAL',
};
const ECOSYSTEM_MAP = { npm: 'npm', pip: 'pypi' };

function parseArgs(argv) {
  const args = { ecosystem: 'both', limit: 15, out: 'vuln-intel', force: false };
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
  if (args.out === '') {
    throw new Error('--out must not be empty');
  }
  return args;
}

async function fetchAdvisories(ecosystem, token) {
  const url =
    `https://api.github.com/advisories?ecosystem=${ecosystem}` +
    '&type=reviewed&sort=updated&direction=desc&per_page=100';
  const headers = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'drobon-dataset-importer',
  };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  const response = await fetch(url, { headers });
  if (!response.ok) {
    throw new Error(`advisory API failed for ${ecosystem}: ${response.status} ${response.statusText}`);
  }
  return response.json();
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
      skips.push(`${ghsaId} (${name}): validation failed (${errors[0]})`);
      continue;
    }
    records.push(record);
  }
  if (records.length === 0 && vulnerabilities.length > 0) {
    skips.push(`${ghsaId}: no usable npm/pip entries`);
  }
  return records;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const token = process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN ?? '';
  const ecosystems = args.ecosystem === 'both' ? ['npm', 'pip'] : [args.ecosystem];
  const outRoot = resolve(process.cwd(), args.out);
  const retrievedAt = new Date().toISOString();
  let written = 0;
  const skips = [];
  for (const ecosystem of ecosystems) {
    const advisories = await fetchAdvisories(ecosystem, token);
    const perAdvisoryCount = new Map();
    let kept = 0;
    for (const advisory of advisories) {
      if (kept >= args.limit) {
        break;
      }
      const records = toRecords(advisory, retrievedAt, skips);
      for (const record of records) {
        if (kept >= args.limit) {
          break;
        }
        const seen = (perAdvisoryCount.get(record.id) ?? 0) + 1;
        perAdvisoryCount.set(record.id, seen);
        const fileName = seen === 1 ? `${record.id}.json` : `${record.id}--${seen}.json`;
        const dir = join(outRoot, record.ecosystem);
        const file = join(dir, fileName);
        if (!args.force && existsSync(file)) {
          skips.push(`${record.id} (${record.package}): file exists`);
          continue;
        }
        mkdirSync(dir, { recursive: true });
        writeFileSync(file, `${JSON.stringify(record, null, 2)}\n`);
        process.stdout.write(`wrote ${file}\n`);
        kept += 1;
        written += 1;
      }
    }
  }
  process.stdout.write(`import-ghsa: wrote ${written} records, ${skips.length} skips\n`);
  for (const skip of skips.slice(0, 30)) {
    process.stdout.write(`  skip: ${skip}\n`);
  }
  if (skips.length > 30) {
    process.stdout.write(`  ... and ${skips.length - 30} more skips\n`);
  }
}

main().catch((err) => {
  process.stderr.write(`import-ghsa: FAIL (${err.message})\n`);
  process.exitCode = 1;
});
