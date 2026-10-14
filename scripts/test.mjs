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
      } else if (entry.isFile() && entry.name.endsWith('.json')) {
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

// --- summary ---------------------------------------------------------------
const total = passed + failed;
process.stdout.write(`tests: ${failed === 0 ? 'PASS' : 'FAIL'} (${passed}/${total} passed)\n`);
process.exitCode = failed === 0 ? 0 : 1;
