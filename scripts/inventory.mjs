/**
 * inventory.mjs — deterministic current-state inventory generator.
 *
 * Why this exists: counts used to be copied into prose by hand, and several
 * current-state documents drifted after the Phase 9 rule additions
 * (954 rules / 97 secrets / 954 remediation). This script derives every
 * count from files, then either writes the canonical machine-readable
 * snapshot (docs/CURRENT_INVENTORY.json) or verifies it byte-for-byte.
 *
 * Determinism contract: the output contains no timestamps, no absolute
 * paths, no git metadata and no environment data. Two runs over the same
 * tree must produce identical bytes.
 *
 * Read-only by default with --check. `--write` regenerates the snapshot.
 *
 * Usage:
 *   node scripts/inventory.mjs --check   # exit 1 when the snapshot is stale
 *   node scripts/inventory.mjs --write   # regenerate docs/CURRENT_INVENTORY.json
 *   node scripts/inventory.mjs --stdout  # print the computed snapshot
 */
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const ROOT = resolve(new URL('.', import.meta.url).pathname, '..');
export const SNAPSHOT_PATH = 'docs/CURRENT_INVENTORY.json';

export const CLASSIFICATIONS = Object.freeze([
  'DATASET_ENGINEERING',
  'OWNER_DECISION_REQUIRED',
  'LEGAL_SOURCE_RIGHTS_REVIEW',
  'APP_PROVIDER_ACCEPTANCE_REQUIRED',
  'DEFERRED_OUT_OF_SCOPE',
  'DOCUMENTED_LIMITATION',
  'RESOLVED',
]);

export const FINAL_STATUSES = Object.freeze([
  'CLOSED_VERIFIED',
  'NOT_APPLICABLE_WITH_REASON',
  'BLOCKED_APP_IMPLEMENTATION',
  'BLOCKED_OWNER_AUTHORIZATION',
  'BLOCKED_MISSING_REQUIREMENT',
  'BLOCKED_SOURCE_LICENSE',
  'IMPLEMENTED_NOT_VERIFIED',
]);

export const SCOPE_CLASSES = Object.freeze(['REQUIRED', 'SUPPLEMENTAL', 'NONE']);
export const PRIORITIES = Object.freeze(['P0', 'P1', 'P2', 'P3']);
export const WORK_CLASSES = Object.freeze(['A', 'B', 'C', 'D', 'E', 'F', 'G']);

/** Count `*.json` files directly inside a repository directory. */
export function countFiles(rel) {
  const dir = join(ROOT, rel);
  if (!existsSync(dir)) return 0;
  return readdirSync(dir).filter((name) => name.endsWith('.json')).length;
}

/** Minimal RFC-4180 CSV reader (quoted fields, embedded commas, CRLF). */
export function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"') {
        if (text[i + 1] === '"') { field += '"'; i += 1; } else { quoted = false; }
      } else {
        field += ch;
      }
    } else if (ch === '"') {
      quoted = true;
    } else if (ch === ',') {
      row.push(field); field = '';
    } else if (ch === '\n') {
      row.push(field.replace(/\r$/, '')); field = '';
      if (row.length > 1 || row[0] !== '') rows.push(row);
      row = [];
    } else if (ch !== '\r') {
      field += ch;
    }
  }
  if (field !== '' || row.length > 0) { row.push(field); rows.push(row); }
  const header = rows.shift() ?? [];
  return rows.filter((r) => r.some((v) => v !== ''))
    .map((r) => Object.fromEntries(header.map((h, idx) => [h, r[idx] ?? ''])));
}

function readCsv(rel) {
  return parseCsv(readFileSync(join(ROOT, rel), 'utf8'));
}

function readJson(rel) {
  return JSON.parse(readFileSync(join(ROOT, rel), 'utf8'));
}

function tally(values) {
  const out = {};
  for (const value of [...values].sort()) out[value] = (out[value] ?? 0) + 1;
  return out;
}

function advisoryIdentity() {
  const ids = new Set();
  const items = new Set();
  const byId = new Map();
  for (const eco of ['npm', 'pypi']) {
    const dir = join(ROOT, 'vuln-intel', eco);
    if (!existsSync(dir)) continue;
    for (const name of readdirSync(dir).filter((n) => n.endsWith('.json'))) {
      const rec = readJson(`vuln-intel/${eco}/${name}`);
      ids.add(rec.id);
      items.add(`${rec.source}\u0000${rec.id}\u0000${rec.ecosystem}\u0000${rec.package}`);
      const key = `${rec.id}|${rec.ecosystem}|${rec.package}`;
      byId.set(key, (byId.get(key) ?? 0) + 1);
    }
  }
  const multiFileTuples = [...byId.values()].filter((n) => n > 1).length;
  return { ids: ids.size, items: items.size, multiFileTuples };
}

function evalCaseCounts() {
  const dir = join(ROOT, 'data', 'eval-cases');
  if (!existsSync(dir)) return { total: 0, assessed: 0, unassessed: 0, byCohort: {} };
  const cases = readdirSync(dir).filter((n) => n.endsWith('.json'))
    .map((n) => readJson(`data/eval-cases/${n}`));
  const assessed = cases.filter((c) => c.groundTruth?.state === 'ASSESSED').length;
  const cohort = (c) => c.cohort ?? 'core';
  return {
    total: cases.length,
    assessed,
    unassessed: cases.length - assessed,
    byCohort: tally(cases.map(cohort)),
  };
}

/** Compute the full inventory. Pure function of the working tree. */
export function computeInventory() {
  const sast = countFiles('packs/sast/v1/rules');
  const secrets = countFiles('packs/secrets/v1/rules');
  const dast = countFiles('packs/dast/v1/rules');
  const advisory = advisoryIdentity();
  const evalCounts = evalCaseCounts();
  const requirements = readJson('docs/REQUIREMENTS_MATRIX.json').requirements ?? [];
  const traceability = readCsv('DROBON_REQUIREMENT_TRACEABILITY.csv');
  const remaining = readCsv('DROBON_REMAINING_WORK.csv');
  const decisions = readJson('docs/OWNER_DECISIONS.json').decisions ?? [];
  const blockers = readJson('docs/BLOCKER_REGISTER.json');
  const gates = (readJson('docs/RELEASE_READINESS_MATRIX.json').gates ?? []);
  const completion = (readJson('docs/COMPLETION_MATRIX.json').items ?? []);

  return {
    schemaVersion: 'drobon.current-inventory/v1',
    note: 'Deterministic snapshot recomputed from tracked files by scripts/inventory.mjs. '
      + 'Contains no timestamps or environment data. Regenerate with `node scripts/inventory.mjs --write`; '
      + 'staleness fails `npm run test:current-state`.',
    counts: {
      advisoryFixtures: countFiles('vuln-intel/npm/samples') + countFiles('vuln-intel/pypi/samples'),
      advisoryIds: advisory.ids,
      advisoryItems: advisory.items,
      advisoryRealFiles: countFiles('vuln-intel/npm') + countFiles('vuln-intel/pypi'),
      assessmentTemplates: countFiles('assessments/templates'),
      cweEntries: countFiles('knowledge/cwe'),
      dastRules: dast,
      engagements: countFiles('engagements'),
      evalCasesAssessed: evalCounts.assessed,
      evalCasesTotal: evalCounts.total,
      evalCasesUnassessed: evalCounts.unassessed,
      lessons: countFiles('learning/lessons'),
      packRules: sast + secrets + dast,
      patterns: countFiles('knowledge/patterns'),
      providerVectors: (readJson('interop/provider-vectors.json').vectors ?? []).length,
      records: countFiles('knowledge/records'),
      remediation: countFiles('knowledge/remediation'),
      sastRules: sast,
      secretsRules: secrets,
    },
    registers: {
      blockers: {
        open: blockers.counts?.open ?? (blockers.blockers ?? []).length,
        byStatus: tally((blockers.blockers ?? []).map((b) => b.status)),
        resolvedForRecord: (blockers.resolvedForRecord ?? []).length,
      },
      completionMatrix: {
        items: completion.length,
        byStatus: tally(completion.map((i) => i.status)),
      },
      evalCasesByCohort: evalCounts.byCohort,
      ownerDecisions: {
        approvedSubjects: decisions.filter((d) => d.status === 'APPROVED').map((d) => d.subject).sort(),
        pending: decisions.filter((d) => d.status !== 'APPROVED').length,
        total: decisions.length,
      },
      releaseGates: {
        byStatus: tally(gates.map((g) => g.status)),
        total: gates.length,
      },
      remainingWork: {
        byClassification: tally(remaining.map((g) => g.classification)),
        rows: remaining.length,
      },
      requirements: {
        byCoverageStatus: tally(requirements.map((r) => r.coverageStatus)),
        total: requirements.length,
      },
      traceability: {
        byFinalStatus: tally(traceability.map((r) => r.finalStatus)),
        byScopeClass: tally(traceability.map((r) => r.scopeClass)),
        rows: traceability.length,
      },
    },
  };
}

export function serialize(inventory) {
  return `${JSON.stringify(inventory, null, 2)}\n`;
}

export function currentSnapshot() {
  return readFileSync(join(ROOT, SNAPSHOT_PATH), 'utf8');
}

function main(argv) {
  const mode = argv.includes('--write') ? 'write' : argv.includes('--stdout') ? 'stdout' : 'check';
  const payload = serialize(computeInventory());
  if (mode === 'stdout') { process.stdout.write(payload); return; }
  if (mode === 'write') {
    writeFileSync(join(ROOT, SNAPSHOT_PATH), payload);
    process.stdout.write(`inventory: wrote ${SNAPSHOT_PATH}\n`);
    return;
  }
  if (!existsSync(join(ROOT, SNAPSHOT_PATH))) {
    process.stderr.write(`inventory: ${SNAPSHOT_PATH} is missing — run: node scripts/inventory.mjs --write\n`);
    process.exitCode = 1;
    return;
  }
  const current = currentSnapshot();
  if (current !== payload) {
    process.stderr.write('inventory: STALE — docs/CURRENT_INVENTORY.json does not match the tree.\n');
    process.stderr.write('           run: node scripts/inventory.mjs --write\n');
    process.exitCode = 1;
    return;
  }
  process.stdout.write(`inventory: ${SNAPSHOT_PATH} matches the tree\n`);
}

const invokedAsScript = process.argv[1] !== undefined
  && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (invokedAsScript) main(process.argv.slice(2));
