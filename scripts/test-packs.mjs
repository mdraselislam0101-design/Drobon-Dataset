#!/usr/bin/env node
/**
 * Phase-2 test runner (zero dependencies), executed after test.mjs via
 * `npm test`:
 *  1. every pack manifest + rule under packs/ MUST validate (positive);
 *  2. pack layout policy (kind dirs, filename == rule id);
 *  3. every fixture under test/invalid-packs/ MUST be rejected (negative);
 *  4. ReDoS lint unit checks;
 *  5. OSV mapping fixture tests (pure mapping, no network).
 *
 * Usage: node scripts/test-packs.mjs
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mapOsvVulnToRecords } from './import-osv.mjs';
import { lintRedos, validatePackManifest, validatePackPath } from './validate-packs.mjs';
import { validateRecord } from './validate.mjs';

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

const SCHEMA_BY_KIND = {
  sast: 'drobon.pack.sast/v1',
  secrets: 'drobon.pack.secrets/v1',
  dast: 'drobon.pack.dast/v1',
};

// --- 1. positive: manifests + rules validate -------------------------------
for (const kind of Object.keys(SCHEMA_BY_KIND)) {
  const manifestFile = join(ROOT, 'packs', kind, 'v1', 'pack.json');
  let manifestErrors = ['missing pack.json'];
  try {
    statSync(manifestFile);
    manifestErrors = validatePackManifest(JSON.parse(readFileSync(manifestFile, 'utf8')));
  } catch {
    manifestErrors = ['missing pack.json'];
  }
  assert(manifestErrors.length === 0, `packs: ${kind} manifest validates`, manifestErrors.join('; '));
  const rules = collectJsonFiles(join(ROOT, 'packs', kind, 'v1', 'rules'));
  assert(rules.length >= 4, `packs: ${kind} ships starter rules (found ${rules.length})`);
}

const packFiles = collectJsonFiles(join(ROOT, 'packs'));
for (const file of packFiles) {
  const errors = validatePackPath(file);
  assert(errors.length === 0, `positive: ${relative(ROOT, file)} validates`, errors.join('; '));
}

// --- 2. layout policy -------------------------------------------------------
for (const file of packFiles) {
  const rel = relative(ROOT, file);
  const parts = rel.split('/');
  // packs/<kind>/v1/(rules/)<file>.json
  const kind = parts[1];
  const record = JSON.parse(readFileSync(file, 'utf8'));
  if (parts[parts.length - 1] === 'pack.json') {
    assert(
      parts.length === 4 && SCHEMA_BY_KIND[kind] !== undefined,
      `layout: ${rel} is a pack manifest in a kind dir`,
    );
    assert(
      record.schemaVersion === SCHEMA_BY_KIND[kind],
      `layout: ${rel} schemaVersion matches its kind dir`,
      String(record.schemaVersion),
    );
    continue;
  }
  assert(
    parts.length === 5 && parts[3] === 'rules' && SCHEMA_BY_KIND[kind] !== undefined,
    `layout: ${rel} sits in packs/<kind>/v1/rules/`,
  );
  assert(
    record.schemaVersion === SCHEMA_BY_KIND[kind],
    `layout: ${rel} schemaVersion matches its kind dir`,
    String(record.schemaVersion),
  );
  const fileName = parts[parts.length - 1].replace(/\.json$/, '');
  assert(
    typeof record.id === 'string' && record.id === fileName,
    `layout: ${rel} filename matches rule id`,
    `file ${fileName} vs id ${String(record.id)}`,
  );
}

// --- 3. negative: invalid pack fixtures rejected ----------------------------
const NEGATIVE = {
  'sast-bad-regex.json': 'invalid regex',
  'sast-failing-test.json': 'tests[#0]',
  'sast-nested-quantifier.json': 'nested quantifier',
  'sast-bad-id.json': 'must match',
  'secrets-bad-confidence.json': 'confidence',
  'dast-unknown-check.json': 'must be one of',
};
for (const [name, needle] of Object.entries(NEGATIVE)) {
  const file = join(ROOT, 'test', 'invalid-packs', name);
  let errors = [];
  try {
    statSync(file);
    errors = validatePackPath(file);
  } catch {
    errors = [];
  }
  const rejected = errors.length > 0 && errors.some((error) => error.includes(needle));
  assert(rejected, `negative: test/invalid-packs/${name} rejected (${needle})`, errors.join('; '));
}

// --- 4. ReDoS lint units -----------------------------------------------------
assert(lintRedos('(a*)*') !== null, 'redos: nested quantifier (a*)* rejected');
assert(lintRedos('.*.*x') !== null, 'redos: repeated wildcard .*.* rejected');
assert(lintRedos('\\beval\\s*\\(') === null, 'redos: plain sink pattern accepted');
assert(lintRedos('[.*]+') === null, 'redos: class literal [.*] accepted');
assert(
  lintRedos('-----BEGIN (?:RSA |EC )?PRIVATE KEY-----') === null,
  'redos: optional non-capturing group accepted',
);

// --- 5. OSV mapping fixtures (no network) ------------------------------------
const osvFixture = JSON.parse(
  readFileSync(join(ROOT, 'test', 'fixtures', 'osv-query-response.fixture.json'), 'utf8'),
);
const retrievedAt = '2026-10-14T00:00:00.000Z';
const mapped = new Map();
for (const vuln of osvFixture.vulns) {
  const skips = [];
  mapped.set(vuln.id, mapOsvVulnToRecords(vuln, retrievedAt, skips));
}
const npmRecords = mapped.get('FIXTURE-OSV-0001') ?? [];
assert(npmRecords.length === 1, 'osv: npm fixture maps to one record', JSON.stringify(npmRecords.length));
if (npmRecords.length === 1) {
  const record = npmRecords[0];
  assert(
    record.severity === 'HIGH' &&
      record.ecosystem === 'npm' &&
      record.affected[0].range === '<1.2.3' &&
      record.affected[0].fixed === '1.2.3' &&
      record.provenance.source === 'OSV' &&
      record.url === 'https://example.invalid/fixture-osv-0001',
    'osv: npm record fields mapped (CVSS 7.5 → HIGH, introduced 0 → <fixed)',
    JSON.stringify(record),
  );
  const recordErrors = validateRecord(record);
  assert(recordErrors.length === 0, 'osv: npm record passes the advisories validator', recordErrors.join('; '));
}
assert((mapped.get('FIXTURE-OSV-0002') ?? [1]).length === 0, 'osv: withdrawn record skipped');
assert((mapped.get('FIXTURE-OSV-0003') ?? [1]).length === 0, 'osv: unscored record skipped');
const pypiRecords = mapped.get('FIXTURE-OSV-0004') ?? [];
assert(pypiRecords.length === 1, 'osv: pypi fixture maps to one record');
if (pypiRecords.length === 1) {
  const record = pypiRecords[0];
  assert(
    record.severity === 'MEDIUM' &&
      record.ecosystem === 'pypi' &&
      record.affected[0].range === '>=1.0, <2.0' &&
      record.url === undefined &&
      record.provenance.sourceUrl === 'https://osv.dev/vulnerability/FIXTURE-OSV-0004',
    'osv: pypi record mapped (PyPI→pypi, insecure ref → osv.dev fallback)',
    JSON.stringify(record),
  );
  const recordErrors = validateRecord(record);
  assert(recordErrors.length === 0, 'osv: pypi record passes the advisories validator', recordErrors.join('; '));
}

// --- summary -----------------------------------------------------------------
const total = passed + failed;
process.stdout.write(`pack-tests: ${failed === 0 ? 'PASS' : 'FAIL'} (${passed}/${total} passed)\n`);
process.exitCode = failed === 0 ? 0 : 1;
