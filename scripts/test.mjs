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
  'invalid-ghsa-id.json': 'GHSA-xxxx-yyyy-zzzz',
  'duplicate-affected.json': 'exact-duplicate affected entry',
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
  pypi: ['<1.2.0', '>=1.0.0,<1.4.2', '==1.2.*', '~=1.4.2', '!=1.5.0', '>2.0,<=3.0',
    // Pump 6: local labels are allowed in == / != / === (PEP 440 exception); prefix matches on pre-releases are valid.
    '==1.0+abc', '!=1.0+abc', '===1.0+abc', '==1.1a1.*', '~=2.2.post3'],
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
  npm: ['*', 'foo', '>>1.0.0', '1.0.0 -', '>=1.0.0 ||', '1.0.0.0', '=>1.0.0', '>=', '', '1.2.3 - 2.0.0 - 3.0.0', '>=1.0.0 <2.0.0 || '],
  pypi: ['1.0.0', '=>1.0', '==', '~=1', '>=1.0,,<2.0', '>=1.0; python_version > "3"',
    // Pump 6 (D3): local identifiers are not permitted in ordered comparisons or ~= (PEP 440 Version scheme + ordered comparison).
    '<1.7+local', '<=1.7+local', '>1.7+local', '>=1.7+local', '~=1.7+local',
    // Pump 6 (D4): a prefix match containing a developmental or local release is invalid (PEP 440 Version matching).
    '==1.0.dev1.*', '!=1.0.dev1.*', '==1.0+foo1.*',
    // Pump 7 (D5): an empty local label is malformed; rejected by the validator (validity layer).
    '==1.0+', '!=1.0+'],
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
  // Pump 3 synthetic boundary rows (npm semver + PEP 440 specifier semantics).
  ['npm', '1.0.0', '>=1.0.0 <2.0.0', true], // lower bound inclusive
  ['npm', '1.0.0', '>1.0.0', false], // strict lower bound exclusive
  ['npm', '2.0.0', '1.2.3 - 2.0.0', true], // hyphen upper bound inclusive
  ['npm', '2.0.1', '1.2.3 - 2.0.0', false], // above hyphen upper bound
  ['npm', '1.2.2', '1.2.3 - 2.0.0', false], // below hyphen lower bound
  ['npm', '1.9.9', '1.x', true], // x-range covers minor
  ['npm', '0.9.9', '1.x', false], // x-range excludes lower major
  ['npm', '1.2.3', 'v1.2.3', true], // v-prefixed exact
  ['npm', '1.0.1', '=1.0.0', false], // explicit equality
  ['npm', '4.17.21', '>= 4.0.0, < 4.17.21', false], // comma AND upper exclusive
  ['npm', '2.5.0', '>=1.0.0 <2.0.0 || >=3.0.0 <3.1.0', false], // gap between OR branches
  ['npm', '3.1.0', '>=1.0.0 <2.0.0 || >=3.0.0 <3.1.0', false], // OR branch upper exclusive
  ['npm', '3.0.0', '>=1.0.0 <2.0.0 || >=3.0.0 <3.1.0', true], // OR second branch lower inclusive
  ['pypi', '1.0', '>=1.0,<2.0', true], // lower inclusive
  ['pypi', '2.0', '>=1.0,<2.0', false], // upper exclusive
  ['pypi', '1.5.0', '!=1.5.0', false], // exclusion exact
  ['pypi', '1.5.1', '!=1.5.0', true], // exclusion neighbour
  ['pypi', '1.2', '==1.2.*', true], // PEP 440 prefix match: 1.2 matches 1.2.*
  ['pypi', '1.2.0.5', '==1.2.*', true], // prefix match on deeper segments
  ['pypi', '1.4.2', '~=1.4.2', true], // compatible lower inclusive
  ['pypi', '1.4.9', '~=1.4.2', true], // compatible within minor
  ['pypi', '1.5', '~=1.4.2', false], // compatible excludes next minor
  ['pypi', '1.9', '~=1.4', true], // ~=1.4 means >=1.4,==1.*
  ['pypi', '2.0', '~=1.4', false], // ~=1.4 excludes 2.x
  ['pypi', '3.0', '>2.0,<=3.0', true], // upper inclusive
  ['pypi', '2.0', '>2.0,<=3.0', false], // lower exclusive
  ['pypi', '1.0.post1', '>=1.0', true], // post-release is greater than base
  ['pypi', '1.0.dev1', '>=1.0', false], // dev release of 1.0 is less than 1.0 (PEP 440)
  // POLICY-PENDING (owner decision on pypi prerelease handling; current behaviour pinned, not endorsed):
  ['pypi', '1.5rc1', '>=1.0,<2.0', true], // prerelease currently included; PEP 440 default would exclude
  ['pypi', '1.7.1', '>1.7', true], // PEP 440 example: >1.7 allows 1.7.1
  ['pypi', '1.7.0.post3', '>1.7.post2', true], // PEP 440 example: >1.7.post2 allows 1.7.0.post3
  ['pypi', '1.7.0', '>1.7.post2', false], // PEP 440 example: >1.7.post2 does not allow 1.7.0
  ['pypi', '1.7+local', '>1.7', false], // PEP 440: >V MUST NOT match a local version of V
  ['pypi', '1.1.post1', '== 1.1', false], // PEP 440 == example
  ['pypi', '1.1.post1', '== 1.1.*', true], // PEP 440 prefix match example
  ['pypi', '1.1.post1', '!= 1.1.post1', false], // PEP 440 != example
  ['pypi', '1.1.post1', '!= 1.1', true], // PEP 440 != example
  ['pypi', '1.1', '== 1.1.0', true], // PEP 440 zero padding
  ['pypi', '3.0', '~=2.2', false], // PEP 440 ~= example: 3.0 excluded
  ['pypi', '3.2.0', '~=3.1.2', false], // PEP 440 ~=3.1.2 excludes 3.2.0
  ['pypi', '3.1.3', '~=3.1.0, !=3.1.3', false], // PEP 440 example: ~=3.1.0,!=3.1.3 excludes 3.1.3
  // Pump 5: spec-agreeing rows. Each expected value is taken from the quoted spec text (PEP 440 / npm semver README); see docs/FORMAT.md, 'PEP 440 exclusive-bound deviations' and 'npm prerelease behaviour'.
  ['pypi', '1.9.9', '<2.0', true], // PEP 440 exclusive: release below bound
  ['pypi', '2.0', '<2.0', false], // PEP 440 exclusive: bound itself excluded
  ['pypi', '2.0.1', '>2.0', true], // PEP 440 exclusive: later release
  ['pypi', '2.0.dev1', '>=2.0', false], // PEP 440: dev release sorts before release
  ['pypi', '2.0.post1', '<=2.0', false], // PEP 440 inclusive: post-release of V is above V
  ['pypi', '2.0.post1', '==2.0.*', true], // PEP 440 prefix match ignores post segment
  ['pypi', '2.0', '!=2.0.*', false], // PEP 440 exclusion prefix matches 2.0
  ['pypi', '1.1', '==1.1.dev1', false], // PEP 440: dev release is not equal to base
  ['npm', '1.9.9', '>=1.0.0 || <0.5.0', true], // npm README: || is OR of comparator sets
  ['npm', '0.6.0', '>=1.0.0 || <0.5.0', false], // npm README: neither set satisfied
  ['npm', '1.0.0', '>1.0.0', false], // npm README: > is exclusive
  ['npm', '1.0.1', '>1.0.0', true], // npm README: > with greater patch
  ['npm', '2.0.0', '<2.0.0-0', false], // npm semver: 2.0.0 not below 2.0.0-0
  ['npm', '1.9.0', '1.x', true], // npm README: x-range
  ['npm', '1.2.3', '>= 1.2.3, < 1.3.0', true], // docs/FORMAT.md: comma and space AND
  // POLICY-PENDING (npm): npm README 'Prerelease Tags' excludes prereleases by default; current behaviour pinned, not endorsed; see docs/FORMAT.md.
  ['npm', '1.5.0-beta.1', '>=1.0.0 <2.0.0', true], // npm semver default would exclude a prerelease of an unrelated tuple
  // Pump 6 (PEP 440 exclusive ordered comparison, MUST NOT): these rows were KNOWN DEFECT pins in Pump 5 and are now the spec values.
  ['pypi', '2.0.0a1', '<2.0', false], // D2: <V must NOT allow a pre-release of V (zero-padded release).
  ['pypi', '2.0.post1', '>2.0', false], // D1: >V must NOT allow a post-release of V.
  ['pypi', '1.7.0.post1', '>1.7', false], // D1, PEP 440 spec example: >1.7 does not allow 1.7.0.post1.
  // Pump 6 boundary rows. Each expected value is a MUST-level rule, or a nearby valid case that must keep matching.
  ['pypi', '2.0.dev1', '<2.0', false], // D2: a developmental release is a pre-release ("Handling of pre-releases").
  ['pypi', '3.3.13rc1', '<3.3.13', false], // D2 on a real-record shape: rc of the fixed version is not below it.
  ['pypi', '2.0a1.post1', '>2.0a1', false], // D1 with pre-release V: a post-release of 2.0a1 is excluded.
  ['pypi', '2.0a0', '<2.0a1', true], // control: V is a pre-release, so pre-releases of V are not excluded.
  ['pypi', '2.0.dev0', '<2.0.dev1', true], // control: V is a developmental release, so its releases are not excluded.
  ['pypi', '2.0.dev1', '<2.0.dev1', false], // control: equal dev release is not below itself.
  ['pypi', '1.9', '<2.0', true], // control: final release below the bound.
  ['pypi', '1.9.post1', '<2.0', true], // control: post-release of a lower release is below the bound.
  ['pypi', '2.0.post1', '>2.0a1', true], // control: post of 2.0 is a post-release of a different release, not of 2.0a1.
  ['pypi', '1.7.1+local', '>1.7', true], // control: local label on a higher release does not block >V.
  ['pypi', '1.7.0.post3', '>1.7.post2', true], // control: V is a post-release, so post-releases of V are allowed (PEP 440 example).
  ['pypi', '1.7.0', '>1.7.post2', false], // control: PEP 440 example: >1.7.post2 does not allow 1.7.0.
  ['pypi', '1.7.0.post1', '>1.7.post2', false], // control: post1 sorts below post2.
  ['pypi', '2.0.post1', '>=2.0', true], // control: inclusive bound is not affected by the exclusive rule.
  // Pump 7 (D5): PEP 440 "Version matching". If the specifier carries a local label, candidates MUST
  // have an equal local label by strict string equality (after the spec's normalization: case-insensitive,
  // purely numeric local segments normalized as integers, alphanumeric segments kept as written).
  // A candidate with no local label, or a different one, does not match. Public-only specifiers ignore labels.
  // RED rows (currently wrong): candidates without the label or with another label must not match ==V+L.
  ['pypi', '1.0', '==1.0+abc', false], // D5: candidate without a local label does not match ==1.0+abc.
  ['pypi', '1.0+xyz', '==1.0+abc', false], // D5: different local label does not match.
  ['pypi', '1.0+2', '==1.0+01', false], // D5: numeric local segments normalize (01 == 1), so 2 != 1.
  ['pypi', '1.0+foo0100', '==1.0+foo100', false], // D5: integers inside an alphanumeric segment are not normalized.
  ['pypi', '1.0a1', '==1.0a1+abc', false], // D5: pre-release candidate with no label does not match.
  ['pypi', '1.0', '!=1.0+abc', true], // D5: != inverts the sense of ==V+L; a no-label candidate is not a match, so != holds.
  ['pypi', '1.0+xyz', '!=1.0+abc', true], // D5: a different label is not a match, so != holds.
  // Controls (must already pass): exact labels, case, normalization, padding, public-only specifiers, ===.
  ['pypi', '1.0+abc', '==1.0+abc', true], // control: exact label match.
  ['pypi', '1.0+ABC', '==1.0+abc', true], // control: labels are case-insensitive.
  ['pypi', '1.0+01', '==1.0+1', true], // control: numeric local segment normalizes (01 -> 1).
  ['pypi', '1.0+abc.1', '==1.0+abc.1', true], // control: multi-segment label, equal.
  ['pypi', '1.0+abc', '==1.0+abc.1', false], // D5 (RED): a label with fewer segments is a different label.
  ['pypi', '1.0.0+abc', '==1.0+abc', true], // control: zero padding on the public part, label equal.
  ['pypi', '1.1+abc', '==1.0+abc', false], // control: public part differs.
  ['pypi', '1.0a1+abc', '==1.0a1+abc', true], // control: pre-release with an equal label.
  ['pypi', '1.0+abc', '==1.0', true], // control: public-only specifier ignores the candidate label.
  ['pypi', '1.0', '==1.0', true], // control: plain equality unchanged.
  ['pypi', '1.0+abc', '!=1.0', false], // control: public-only != ignores the candidate label.
  ['pypi', '1.0+abc', '!=1.0+abc', false], // control: != with an equal label is not a match, so false.
  ['pypi', '1.1', '!=1.0+abc', true], // control: different public part is not a match, so != holds.
  ['pypi', '1.0', '===1.0+abc', false], // control: === is plain string equality, unchanged.
  ['pypi', '1.0+abc', '===1.0+abc', true], // control: === exact string equality, unchanged.
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
// An invalid range must never be evaluated to true/false: satisfiesRange throws (unknown).
for (const [ecosystem, version, range] of [
  ['pypi', '1.2.0', '~=1'],
  // Pump 7 (D5): malformed local specifiers fail closed; they are never evaluated as a match or miss.
  ['pypi', '1.0', '==1.0+'],
  ['pypi', '1.0+abc', '!=1.0+'],
  ['pypi', '1.0', '==1.0+ab cd'],
  ['npm', '1.0.0', 'garbage!!'],
  ['npm', '1.0.0', '*'],
  // Pump 4: caret and tilde are outside the documented npm subset (docs/FORMAT.md) and must fail closed.
  ['npm', '1.2.5', '^1.2.3'],
  ['npm', '1.2.9', '~1.2'],
]) {
  let thrown = null;
  let value;
  try {
    value = satisfiesRange(ecosystem, version, range);
  } catch (err) {
    thrown = err.message;
  }
  assert(
    thrown !== null,
    `range: satisfiesRange refuses invalid ${ecosystem} range "${range}" (unknown, not a match)`,
    `returned ${String(value)}`,
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

// --- schema parity: advisory.schema.json mirrors the GHSA-id rule -----------------
// FORMAT.md: the validator wins and the schema must mirror it. The GHSA-id rule
// is conditional logic, so pin its presence, structure, and pattern behavior here
// (the repo ships no JSON-Schema engine; this is the executable half of the mirror).
const advisorySchema = JSON.parse(readFileSync(join(ROOT, 'schema', 'advisory.schema.json'), 'utf8'));
const ghsaBranches = (advisorySchema.allOf ?? []).filter(
  (branch) => branch?.then?.properties?.id?.pattern?.includes('GHSA-'),
);
assert(ghsaBranches.length === 1, 'schema: exactly one GHSA-id conditional in allOf');
const ghsaIf = ghsaBranches[0]?.if;
assert(
  ghsaIf?.properties?.fixture?.const === false &&
    ghsaIf?.properties?.provenance?.properties?.source?.const === 'GHSA',
  'schema: GHSA conditional fires on real records with provenance.source GHSA',
);
const ghsaSchemaPattern = new RegExp(
  ghsaBranches[0]?.then?.properties?.id?.pattern ?? '($^)',
);
assert(
  ghsaSchemaPattern.test('GHSA-ab12-cd34-ef56') &&
    !ghsaSchemaPattern.test('CVE-2024-1234') &&
    !ghsaSchemaPattern.test('GHSA-abc'),
  'schema: GHSA pattern accepts GHSA ids and rejects non-GHSA ids',
);

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
