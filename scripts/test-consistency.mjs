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
 *  4. prints a coverage report (counts per dataset).
 *
 * Usage: node scripts/test-consistency.mjs
 */
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateCwePath } from './validate-cwe.mjs';

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

// --- summary --------------------------------------------------------------------
const total = passed + failed;
process.stdout.write(`consistency-tests: ${failed === 0 ? 'PASS' : 'FAIL'} (${passed}/${total} passed)\n`);
process.exitCode = failed === 0 ? 0 : 1;
