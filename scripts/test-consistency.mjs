#!/usr/bin/env node
/**
 * Cross-dataset consistency runner (zero dependencies), executed last
 * via `npm test`. This is the datacenter integrity bar — references
 * between datasets must resolve, or the suite fails:
 *  1. every CWE entry validates + filename matches id;
 *  2. REMEDIATION COVERAGE: every DPK-* pack rule has a
 *     knowledge/remediation/<id>.json entry (no finding without guidance);
 *  3. CWE RESOLUTION: every pack rule `cwe` and every remediation
 *     `standardId` exists in knowledge/cwe/ (no dangling standards);
 *  4. prints a coverage report (counts per dataset);
 *  5. SPLIT INTEGRITY: same-advisory `<ID>--N.json` splits agree on
 *     severity/summary/url, differ in `affected` (exact duplicates
 *     rejected), and every real record carries provenance.license;
 *  6. STALE-METADATA TRIPWIRES: count-bearing README lines match
 *     recomputed counts (the count-line format is load-bearing);
 *  7. every fixture under test/invalid-cwe/ MUST be rejected;
 *  8. the requirements matrix validates + every fixture under
 *     test/invalid-matrix/ MUST be rejected.
 *
 * Usage: node scripts/test-consistency.mjs
 */
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateCwePath } from './validate-cwe.mjs';
import { validateMatrixPath } from './validate-matrix.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
let passed = 0;
let failed = 0;

function assert(condition, label, detail = '') {
  if (condition) {
    passed += 1;
    process.stdout.write(`ok - ${label}\n`);
  } else {
    failed += 1;
    process.stdout.write(`FAIL - ${label}\n`);
    if (detail) {
      process.stdout.write(`    ${detail}\n`);
    }
  }
}

function collectJsonFiles(root) {
  const found = [];
  const walk = (dir) => {
    const entries = readdirSync(dir, { withFileTypes: true }).sort((a, b) =>
      a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
    );
    for (const entry of entries) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.isFile() && entry.name.endsWith('.json')) {
        found.push(full);
      }
    }
  };
  walk(root);
  return found;
}

const readJson = (file) => JSON.parse(readFileSync(file, 'utf8'));

// --- 1. CWE entries -----------------------------------------------------------
const cweFiles = collectJsonFiles(join(ROOT, 'knowledge', 'cwe'));
assert(cweFiles.length >= 10, `consistency: CWE knowledge present (found ${cweFiles.length})`);
const cweIds = new Set();
for (const file of cweFiles) {
  const errors = validateCwePath(file);
  const record = errors.length === 0 ? readJson(file) : null;
  assert(errors.length === 0, `positive: ${file.split('/').slice(-3).join('/')} validates`, errors.join('; '));
  if (record !== null) {
    cweIds.add(record.id);
    const fileName = file.split('/').pop().replace(/\.json$/, '');
    assert(record.id === fileName, `layout: knowledge/cwe/${fileName}.json matches id`);
  }
}

// --- 2. remediation coverage ---------------------------------------------------
const packRuleFiles = ['sast', 'secrets', 'dast'].flatMap((kind) =>
  collectJsonFiles(join(ROOT, 'packs', kind, 'v1', 'rules')),
);
assert(packRuleFiles.length >= 18, `consistency: pack rules present (found ${packRuleFiles.length})`);
const missingRemediation = [];
for (const file of packRuleFiles) {
  const rule = readJson(file);
  if (!existsSync(join(ROOT, 'knowledge', 'remediation', `${rule.id}.json`))) {
    missingRemediation.push(rule.id);
  }
}
assert(
  missingRemediation.length === 0,
  `consistency: every pack rule has remediation (${packRuleFiles.length - missingRemediation.length}/${packRuleFiles.length})`,
  `missing: ${missingRemediation.join(', ')}`,
);

// --- 3. CWE resolution ----------------------------------------------------------
const dangling = [];
for (const file of packRuleFiles) {
  const rule = readJson(file);
  if (rule.cwe !== undefined && !cweIds.has(rule.cwe)) {
    dangling.push(`${rule.id} → ${rule.cwe}`);
  }
}
const remediationFiles = collectJsonFiles(join(ROOT, 'knowledge', 'remediation'));
for (const file of remediationFiles) {
  const entry = readJson(file);
  if (entry.standardId !== undefined && !cweIds.has(entry.standardId)) {
    dangling.push(`${entry.ruleId} → ${entry.standardId}`);
  }
}
assert(dangling.length === 0, 'consistency: every CWE reference resolves', `dangling: ${dangling.join(', ')}`);

// --- 4. coverage report ----------------------------------------------------------
const count = (dir) => {
  try {
    return collectJsonFiles(join(ROOT, dir)).length;
  } catch {
    return 0;
  }
};
process.stdout.write('--- datacenter coverage ---\n');
const realAdvisories =
  count('vuln-intel/npm') -
  count('vuln-intel/npm/samples') +
  (count('vuln-intel/pypi') - count('vuln-intel/pypi/samples'));
const fixtures = count('vuln-intel/npm/samples') + count('vuln-intel/pypi/samples');
process.stdout.write(`vuln-intel advisories (npm+pypi): ${realAdvisories} (+${fixtures} fixtures)\n`);
process.stdout.write(`pack rules (sast/secrets/dast): ${packRuleFiles.length}\n`);
process.stdout.write(`remediation entries           : ${remediationFiles.length}\n`);
process.stdout.write(`CWE knowledge entries         : ${cweFiles.length}\n`);
process.stdout.write(`lessons / templates / engagements: ${count('learning/lessons')} / ${count('assessments/templates')} / ${count('engagements')}\n`);
const vectors = readJson(join(ROOT, 'interop', 'provider-vectors.json'));
process.stdout.write(`provider vectors              : ${vectors.vectors.length}\n`);

// --- 5. advisory split integrity --------------------------------------------------
// Same-advisory splits (multi-package / multi-range-branch `<ID>--N.json`
// files) must agree on advisory-level fields, differ in `affected`
// (exact duplicates are rejected), and every real record must carry a
// provenance.license pointer (HONESTY checklist, machine-enforced).
function normalizedAffected(record) {
  return (record.affected ?? [])
    .map((entry) => `${entry.range}||${entry.fixed ?? ''}`)
    .sort()
    .join('&&');
}
const advisoryRecords = [];
for (const file of collectJsonFiles(join(ROOT, 'vuln-intel'))) {
  const record = readJson(file);
  if (record.fixture === true) {
    continue;
  }
  advisoryRecords.push({
    file: file.split('/').slice(-3).join('/'),
    ecosystem: record.ecosystem,
    id: record.id,
    package: record.package,
    severity: record.severity,
    summary: record.summary,
    url: record.url,
    affected: normalizedAffected(record),
    license:
      typeof record.provenance?.license === 'string' && record.provenance.license.length > 0,
  });
}
function checkExactDupes(records) {
  const seen = new Map();
  const dupes = [];
  for (const record of records) {
    const key = `${record.ecosystem}|${record.id}|${record.package}|${record.affected}`;
    if (seen.has(key)) {
      dupes.push(`${record.file} duplicates ${seen.get(key)}`);
    } else {
      seen.set(key, record.file);
    }
  }
  return dupes;
}
function checkSplitConflicts(records) {
  const groups = new Map();
  for (const record of records) {
    if (!groups.has(record.id)) {
      groups.set(record.id, []);
    }
    groups.get(record.id).push(record);
  }
  const conflicts = [];
  for (const [id, group] of groups) {
    const signatures = new Set(group.map((r) => `${r.severity}\n${r.summary}\n${r.url}`));
    if (signatures.size > 1) {
      conflicts.push(`${id} (${group.length} splits disagree on severity/summary/url)`);
    }
  }
  return conflicts;
}
function checkMissingLicense(records) {
  return records.filter((record) => !record.license).map((record) => record.file);
}
const realDupes = checkExactDupes(advisoryRecords);
assert(realDupes.length === 0, 'consistency: no exact-duplicate advisory splits', realDupes.join('; '));
const realConflicts = checkSplitConflicts(advisoryRecords);
assert(
  realConflicts.length === 0,
  'consistency: advisory splits agree on severity/summary/url',
  realConflicts.join('; '),
);
const realMissingLicense = checkMissingLicense(advisoryRecords);
assert(
  realMissingLicense.length === 0,
  'consistency: every real record carries provenance.license',
  realMissingLicense.join('; '),
);
// Synthetic negatives: the checks above must fire on crafted bad input.
const syntheticSplits = [
  { file: 'a.json', ecosystem: 'npm', id: 'GHSA-dup', package: 'p', severity: 'HIGH', summary: 's', url: 'u', affected: 'r||f', license: true },
  { file: 'b.json', ecosystem: 'npm', id: 'GHSA-dup', package: 'p', severity: 'HIGH', summary: 's', url: 'u', affected: 'r||f', license: true },
  { file: 'c.json', ecosystem: 'npm', id: 'GHSA-cf', package: 'p', severity: 'HIGH', summary: 's', url: 'u', affected: 'r1||', license: true },
  { file: 'd.json', ecosystem: 'npm', id: 'GHSA-cf', package: 'p', severity: 'LOW', summary: 's', url: 'u', affected: 'r2||', license: false },
];
assert(
  checkExactDupes(syntheticSplits).length === 1,
  'negative: exact-duplicate split detected',
  checkExactDupes(syntheticSplits).join('; '),
);
const syntheticConflicts = checkSplitConflicts(syntheticSplits);
assert(
  syntheticConflicts.length === 1 && syntheticConflicts[0].includes('GHSA-cf'),
  'negative: split severity disagreement detected',
  syntheticConflicts.join('; '),
);
assert(
  checkMissingLicense(syntheticSplits).join(',') === 'd.json',
  'negative: missing license pointer detected',
);

// --- 6. stale-metadata tripwires ----------------------------------------------------
// Count-bearing README lines must match recomputed counts; the count-line
// format below is load-bearing — keep one `N ... records (A npm + B pypi)`
// line and one `N ... fixtures` line per doc, or this section fails with
// instructions instead of silently accepting drift.
function parseSeedCounts(text) {
  const records = /(\d+)[^\n]*?records\*{0,2}\s*\((\d+) npm \+ (\d+) pypi\)/.exec(text);
  const fixtures = /(\d+)[^\n]*?fixtures/.exec(text);
  if (records === null || fixtures === null) {
    return null;
  }
  return {
    real: Number(records[1]),
    npmReal: Number(records[2]),
    pypiReal: Number(records[3]),
    fixtures: Number(fixtures[1]),
  };
}
const actualSeed = {
  real: advisoryRecords.length,
  npmReal: advisoryRecords.filter((record) => record.ecosystem === 'npm').length,
  pypiReal: advisoryRecords.filter((record) => record.ecosystem === 'pypi').length,
  fixtures,
};
for (const doc of ['vuln-intel/README.md', 'README.md']) {
  const parsed = parseSeedCounts(readFileSync(join(ROOT, doc), 'utf8'));
  assert(parsed !== null, `stale-check: ${doc} keeps the load-bearing count lines`);
  if (parsed !== null) {
    const drifted = ['real', 'npmReal', 'pypiReal', 'fixtures'].filter(
      (key) => parsed[key] !== actualSeed[key],
    );
    assert(
      drifted.length === 0,
      `stale-check: ${doc} counts match the tree`,
      `drifted: ${drifted.join(', ')}`,
    );
  }
}
assert(
  parseSeedCounts('no counts here') === null,
  'negative: count parser rejects text without count lines',
);
const staleParsed = parseSeedCounts('**5 real records** (2 npm + 3 pypi)\n**1 fixtures**');
assert(
  staleParsed !== null && staleParsed.real !== actualSeed.real,
  'negative: count parser surfaces stale numbers for comparison',
);

// --- 7. negative: invalid CWE fixtures rejected --------------------------------------
const NEGATIVE_CWE = {
  'cwe-leading-zero.json': 'id: must match',
};
for (const [name, needle] of Object.entries(NEGATIVE_CWE)) {
  const file = join(ROOT, 'test', 'invalid-cwe', name);
  const errors = existsSync(file) ? validateCwePath(file) : [];
  const rejected = errors.length > 0 && errors.some((error) => error.includes(needle));
  assert(rejected, `negative: test/invalid-cwe/${name} rejected (${needle})`, errors.join('; '));
}

// --- 8. requirements matrix ------------------------------------------------------------
const matrixErrors = validateMatrixPath(join(ROOT, 'docs', 'REQUIREMENTS_MATRIX.json'), ROOT);
assert(
  matrixErrors.length === 0,
  'positive: docs/REQUIREMENTS_MATRIX.json validates',
  matrixErrors.join('; '),
);
const NEGATIVE_MATRIX = {
  'bad-status.json': 'coverageStatus',
  'missing-evidence.json': 'evidence',
  'count-mismatch.json': 'recompute',
  'dangling-script.json': 'not found',
  'bare-none-asset.json': 'repo path',
};
for (const [name, needle] of Object.entries(NEGATIVE_MATRIX)) {
  const file = join(ROOT, 'test', 'invalid-matrix', name);
  const errors = existsSync(file) ? validateMatrixPath(file, ROOT) : [];
  const rejected = errors.length > 0 && errors.some((error) => error.includes(needle));
  assert(rejected, `negative: test/invalid-matrix/${name} rejected (${needle})`, errors.join('; '));
}

// --- summary --------------------------------------------------------------------
const total = passed + failed;
process.stdout.write(`consistency-tests: ${failed === 0 ? 'PASS' : 'FAIL'} (${passed}/${total} passed)\n`);
process.exitCode = failed === 0 ? 0 : 1;
