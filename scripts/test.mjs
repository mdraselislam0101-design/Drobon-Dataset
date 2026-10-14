#!/usr/bin/env node
/**
 * Test runner (zero dependencies):
 *  1. every record under vuln-intel/ MUST validate (positive);
 *  2. every fixture under test/invalid/ MUST be rejected (negative);
 *  3. programmatic edge cases (bounds, control chars, url scheme,
 *     schemaVersion, and a real-record happy path).
 *
 * Usage: node scripts/test.mjs   (or: npm test)
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkVectors } from './check-vectors.mjs';
import { satisfiesRange, validateRange } from './range.mjs';
import { SCHEMA_VERSION, validateFile, validateRecord } from './validate.mjs';

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
      } else if (entry.isFile() && entry.name.endsWith('.json') && entry.name !== 'sources.json') {
        // sources.json is registry metadata, not a record (validated by validate-sources.mjs).
        found.push(full);
      }
    }
  };
  walk(root);
  return found;
}

// --- 1. positive: shipped records validate -------------------------------
const records = collectJsonFiles(join(ROOT, 'vuln-intel'));
assert(records.length >= 3, `positive: sample records present (found ${records.length})`);
for (const file of records) {
  const errors = validateFile(file);
  assert(errors.length === 0, `positive: ${relative(ROOT, file)} validates`, errors.join('; '));
}

// --- 2. negative: invalid fixtures are rejected ---------------------------
const NEGATIVE = {
  'extra-field.json': 'unknown property',
  'bad-severity.json': 'severity',
  'fixture-real-id.json': 'DROBON-SAMPLE-###',
  'missing-provenance.json': 'sourceUrl',
  'empty-affected.json': 'affected',
  'not-an-object.json': 'must be an object',
  'invalid-range.json': 'affected[0].range',
};
for (const [name, needle] of Object.entries(NEGATIVE)) {
  const file = join(ROOT, 'test', 'invalid', name);
  let errors;
  try {
    statSync(file);
    errors = validateFile(file);
  } catch {
    errors = [];
  }
  const rejected = errors.length > 0 && errors.some((error) => error.includes(needle));
  assert(rejected, `negative: test/invalid/${name} rejected (${needle})`, errors.join('; '));
}

// --- 3. programmatic edge cases -------------------------------------------
const sample = JSON.parse(
  readFileSync(join(ROOT, 'vuln-intel', 'npm', 'samples', 'DROBON-SAMPLE-001.json'), 'utf8'),
);
const clone = () => JSON.parse(JSON.stringify(sample));

const oversize = clone();
oversize.summary = `x: ${'x'.repeat(400)}`; // 403 chars > 400 bound
assert(
  validateRecord(oversize).some((error) => error.includes('summary')),
  'edge: 403-char summary rejected',
  validateRecord(oversize).join('; '),
);

const controlChar = clone();
controlChar.package = 'sample-wid\u0001get';
assert(
  validateRecord(controlChar).some((error) => error.includes('control characters')),
  'edge: control character in package rejected',
  validateRecord(controlChar).join('; '),
);

const plainHttp = clone();
plainHttp.url = 'http://example.invalid/nope';
assert(
  validateRecord(plainHttp).some((error) => error.includes('https://')),
  'edge: non-https url rejected',
  validateRecord(plainHttp).join('; '),
);

const badVersion = clone();
badVersion.schemaVersion = 'drobon.vuln-intel/v2';
assert(
  validateRecord(badVersion).some((error) => error.includes('schemaVersion')),
  'edge: wrong schemaVersion rejected',
  validateRecord(badVersion).join('; '),
);

const realRecord = {
  schemaVersion: SCHEMA_VERSION,
  fixture: false,
  id: 'GHSA-test-1234-xxxx',
  ecosystem: 'npm',
  package: 'sample-widget',
  summary: 'Programmatic real-record shape (never shipped as data).',
  severity: 'LOW',
  affected: [{ range: '<1.0.0', fixed: '1.0.0' }],
  provenance: {
    source: 'GHSA',
    sourceUrl: 'https://github.com/advisories/test-record',
    retrievedAt: '2026-10-14T00:00:00.000Z',
  },
};
const realErrors = validateRecord(realRecord);
assert(realErrors.length === 0, 'positive: real-record shape validates', realErrors.join('; '));

// --- 4. range syntax + evaluation -----------------------------------------
const VALID_RANGES = {
  npm: [
    '<2.0.0',
    '>=1.0.0 <1.4.2',
    '>= 4.0.0, < 4.17.21',
    '1.2.3 - 2.0.0',
    '=1.0.0',
    'v1.2.3',
    '<= 2.7.0',
    '>=1.0.0 <2.0.0 || >=3.0.0 <3.1.0',
    '1.x',
  ],
  pypi: ['<1.2.0', '>=1.0.0,<1.4.2', '==1.2.*', '~=1.4.2', '!=1.5.0', '>2.0,<=3.0'],
};
for (const [ecosystem, ranges] of Object.entries(VALID_RANGES)) {
  for (const range of ranges) {
    assert(
      validateRange(ecosystem, range) === null,
      `range: valid ${ecosystem} "${range}" accepted`,
      validateRange(ecosystem, range) ?? '',
    );
  }
}
const INVALID_RANGES = {
  npm: ['*', 'foo', '>>1.0.0', '1.0.0 -', '>=1.0.0 ||', '1.0.0.0', '=>1.0.0', '>=', ''],
  pypi: ['1.0.0', '=>1.0', '==', '~=1', '>=1.0,,<2.0', '>=1.0; python_version > "3"'],
};
for (const [ecosystem, ranges] of Object.entries(INVALID_RANGES)) {
  for (const range of ranges) {
    assert(
      validateRange(ecosystem, range) !== null,
      `range: invalid ${ecosystem} "${range}" rejected`,
    );
  }
}
const SATISFIES = [
  // [ecosystem, version, range, expected]
  ['npm', '1.5.0', '>=1.0.0 <2.0.0', true],
  ['npm', '2.0.0', '>=1.0.0 <2.0.0', false],
  ['npm', '1.4.2', '>=1.0.0 <1.4.2', false],
  ['npm', '2.7.0', '<= 2.7.0', true],
  ['npm', '3.0.0', '<= 2.7.0', false],
  ['npm', '1.5.0', '1.2.3 - 2.0.0', true],
  ['npm', '1.0.0', '1.x', true],
  ['npm', '2.0.0', '1.x', false],
  ['npm', '3.0.5', '>=1.0.0 <2.0.0 || >=3.0.0 <3.1.0', true],
  ['pypi', '1.2.5', '==1.2.*', true],
  ['pypi', '1.3.0', '==1.2.*', false],
  ['pypi', '1.4.5', '~=1.4.2', true],
  ['pypi', '1.5.0', '~=1.4.2', false],
  ['pypi', '0.8.9', '<0.9.0', true],
  ['pypi', '1.0a1', '>=1.0', false],
  ['pypi', '1.0', '>=1.0a1', true],
];
for (const [ecosystem, version, range, expected] of SATISFIES) {
  let actual;
  let thrown = null;
  try {
    actual = satisfiesRange(ecosystem, version, range);
  } catch (err) {
    thrown = err.message;
  }
  assert(
    thrown === null && actual === expected,
    `range: ${ecosystem} ${version} vs "${range}" → ${String(expected)}`,
    thrown ?? `got ${String(actual)}`,
  );
}
const badRangeRecord = clone();
badRangeRecord.affected[0].range = '>>nope';
assert(
  validateRecord(badRangeRecord).some((error) => error.includes('affected[0].range')),
  'edge: record with unparseable range rejected',
  validateRecord(badRangeRecord).join('; '),
);

function escapeRegExp(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// A record id plus any number of `--N` range/package splits (no hardcoded depth).
function isSplitFilename(id, fileName) {
  if (typeof id !== 'string' || typeof fileName !== 'string') {
    return false;
  }
  if (fileName === id) {
    return true;
  }
  return new RegExp(`^${escapeRegExp(id)}--[0-9]+$`).test(fileName);
}

// --- 5. layout policy ------------------------------------------------------
const layoutFiles = collectJsonFiles(join(ROOT, 'vuln-intel'));
for (const file of layoutFiles) {
  const rel = relative(ROOT, file);
  const parts = rel.split('/');
  // vuln-intel/<ecosystem>/(samples/)<file>.json
  const inSamples = parts.includes('samples');
  const record = JSON.parse(readFileSync(file, 'utf8'));
  const fileName = parts[parts.length - 1].replace(/\.json$/, '');
  if (inSamples) {
    assert(
      record.fixture === true,
      `layout: ${rel} under samples/ is a labeled fixture`,
      `fixture flag is ${String(record.fixture)}`,
    );
  } else {
    assert(
      record.fixture === false,
      `layout: ${rel} outside samples/ is a real record`,
      `fixture flag is ${String(record.fixture)}`,
    );
    assert(
      isSplitFilename(record.id, fileName),
      `layout: ${rel} filename matches record id (optionally with --N split suffix)`,
      `expected ${String(record.id)} or ${String(record.id)}--N`,
    );
  }
  assert(
    parts.length >= 3 && (parts[1] === 'npm' || parts[1] === 'pypi'),
    `layout: ${rel} sits under a supported ecosystem dir`,
  );
}
assert(isSplitFilename('GHSA-xxxx-yyyy-zzzz', 'GHSA-xxxx-yyyy-zzzz'), 'positive: split matcher accepts the bare id');
assert(isSplitFilename('GHSA-xxxx-yyyy-zzzz', 'GHSA-xxxx-yyyy-zzzz--99'), 'positive: split matcher accepts --N suffixes');
assert(!isSplitFilename('GHSA-xxxx-yyyy-zzzz', 'GHSA-xxxx-yyyy-zzzz--x'), 'negative: split matcher rejects non-numeric suffixes');
assert(!isSplitFilename('GHSA-xxxx-yyyy-zzzz', 'GHSA-other'), 'negative: split matcher rejects other ids');

// --- 6. provider interop vectors -------------------------------------------
const vectorResult = checkVectors(ROOT);
assert(
  vectorResult.failed === 0,
  `vectors: all provider vectors match (${vectorResult.passed} vectors)`,
  vectorResult.failures.join('; '),
);

// --- summary ---------------------------------------------------------------
const total = passed + failed;
process.stdout.write(`tests: ${failed === 0 ? 'PASS' : 'FAIL'} (${passed}/${total} passed)\n`);
process.exitCode = failed === 0 ? 0 : 1;
