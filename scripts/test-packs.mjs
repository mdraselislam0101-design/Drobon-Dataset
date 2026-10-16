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
import { runLineTests } from './generate-assets.mjs';
import { evalDastCheck, lintRedos, validatePackFile, validatePackManifest, validatePackPath } from './validate-packs.mjs';
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

// --- 2b. detection quality: pos/neg floors + signal collisions ---------------
// Every rule must ship at least one positive and one negative executable
// test, and no two rules may share an identical detection signal, so batch
// quality is enforced by the harness instead of reviewer memory.
const ruleFiles = packFiles.filter((file) => !file.endsWith('pack.json'));
let qualityPos = 0;
let qualityNeg = 0;
const qualityOffenders = [];
const seenSignals = new Map();
const signalCollisions = [];
for (const file of ruleFiles) {
  const record = JSON.parse(readFileSync(file, 'utf8'));
  const tests = Array.isArray(record.tests) ? record.tests : [];
  const pos = tests.filter((t) => t.match === true).length;
  const neg = tests.filter((t) => t.match === false).length;
  qualityPos += pos;
  qualityNeg += neg;
  if (pos < 1 || neg < 1) qualityOffenders.push(`${record.id} (pos=${pos} neg=${neg})`);
  const langKey = [...(record.languages ?? [])].sort().join(',');
  const signals = (record.patterns ?? []).map((p) => `re:${langKey}::${p.source}::${p.flags ?? ''}`);
  if (record.check !== undefined) signals.push(`check:${JSON.stringify(record.check)}`);
  for (const signal of signals) {
    if (seenSignals.has(signal)) signalCollisions.push(`${record.id} ~= ${seenSignals.get(signal)}`);
    else seenSignals.set(signal, record.id);
  }
}
assert(
  qualityOffenders.length === 0,
  `quality: every rule ships >=1 positive and >=1 negative test (${ruleFiles.length} rules)`,
  qualityOffenders.join('; '),
);
assert(
  signalCollisions.length === 0,
  `quality: no duplicate detection signals (${seenSignals.size} unique)`,
  signalCollisions.join('; '),
);
assert(
  qualityPos >= ruleFiles.length && qualityNeg >= ruleFiles.length,
  `quality: ledger ${qualityPos} positive + ${qualityNeg} negative executable tests`,
  '',
);

// --- 3. negative: invalid pack fixtures rejected ----------------------------
const NEGATIVE = {
  'sast-bad-regex.json': 'invalid regex',
  'sast-failing-test.json': 'tests[#0]',
  'sast-nested-quantifier.json': 'nested quantifier',
  'sast-bad-id.json': 'must match',
  'sast-bad-cwe.json': 'cwe: must match',
  'secrets-bad-confidence.json': 'confidence',
  'secrets-missing-denylist.json': 'denylist: required unless matchOnlyEvidence',
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

// --- DAST evaluator edge cases (Pump 2 check kinds) ----------------------------
// Each row: [label, check, observation, expected]. Expected results are the
// documented contract in docs/PACKS.md; an unparseable or out-of-scope input
// must read as "no match", never as a finding.
const DAST_EDGE_CASES = [
  ['body: match on https page', { type: 'response-body-matches', valuePattern: 'Traceback' },
    { url: 'https://app.example/', status: 500, headers: {}, body: 'Traceback (most recent call last)' }, true],
  ['body: no body captured never matches', { type: 'response-body-matches', valuePattern: 'Traceback' },
    { url: 'https://app.example/', status: 500, headers: {} }, false],
  ['body: requireScheme https rejects http page', { type: 'response-body-matches', valuePattern: 'src', requireScheme: 'https' },
    { url: 'http://app.example/', status: 200, headers: {}, body: '<img src="x">' }, false],
  ['body: requireScheme https accepts https page', { type: 'response-body-matches', valuePattern: 'src', requireScheme: 'https' },
    { url: 'https://app.example/', status: 200, headers: {}, body: '<img src="x">' }, true],
  ['redirect: cross-host 302', { type: 'response-header-host-differs', header: 'Location' },
    { url: 'https://app.example/login', status: 302, headers: { Location: 'https://other.example/home' } }, true],
  ['redirect: relative target stays on host', { type: 'response-header-host-differs', header: 'Location' },
    { url: 'https://app.example/login', status: 302, headers: { Location: '/home' } }, false],
  ['redirect: 200 response is not a redirect', { type: 'response-header-host-differs', header: 'Location' },
    { url: 'https://app.example/login', status: 200, headers: { Location: 'https://other.example/' } }, false],
  ['redirect: javascript target is out of scope', { type: 'response-header-host-differs', header: 'Location' },
    { url: 'https://app.example/login', status: 302, headers: { Location: 'javascript:alert(1)' } }, false],
  ['redirect: missing header never matches', { type: 'response-header-host-differs', header: 'Location' },
    { url: 'https://app.example/login', status: 302, headers: {} }, false],
];
// --- Pump 3 DAST rows (negative, boundary, malformed, policy) ---------------
// Expected values follow the contract in docs/PACKS.md. Port and scheme are
// deliberately NOT part of the redirect host comparison (host-only policy).
const DAST_EDGE_CASES_P3 = [
  ['redirect: boundary 300 cross-host', { type: 'response-header-host-differs', header: 'Location' },
    { url: 'https://app.example/login', status: 300, headers: { Location: 'https://other.example/' } }, true],
  ['redirect: boundary 399 cross-host', { type: 'response-header-host-differs', header: 'Location' },
    { url: 'https://app.example/login', status: 399, headers: { Location: 'https://other.example/' } }, true],
  ['redirect: 400 is not a redirect', { type: 'response-header-host-differs', header: 'Location' },
    { url: 'https://app.example/login', status: 400, headers: { Location: 'https://other.example/' } }, false],
  ['redirect: 299 is not a redirect', { type: 'response-header-host-differs', header: 'Location' },
    { url: 'https://app.example/login', status: 299, headers: { Location: 'https://other.example/' } }, false],
  ['redirect: protocol-relative cross-host', { type: 'response-header-host-differs', header: 'Location' },
    { url: 'https://app.example/login', status: 303, headers: { Location: '//other.example/x' } }, true],
  ['redirect: userinfo host confusion is cross-host', { type: 'response-header-host-differs', header: 'Location' },
    { url: 'https://app.example/login', status: 302, headers: { Location: 'https://app.example@evil.example/' } }, true],
  ['redirect: subdomain is a different host', { type: 'response-header-host-differs', header: 'Location' },
    { url: 'https://app.example/login', status: 302, headers: { Location: 'https://evil.app.example/' } }, true],
  ['redirect: same host other port (host-only policy)', { type: 'response-header-host-differs', header: 'Location' },
    { url: 'https://app.example/login', status: 302, headers: { Location: 'https://app.example:8443/home' } }, false],
  ['redirect: same host scheme downgrade (host-only policy)', { type: 'response-header-host-differs', header: 'Location' },
    { url: 'https://app.example/login', status: 302, headers: { Location: 'http://app.example/home' } }, false],
  ['redirect: host comparison is case-insensitive', { type: 'response-header-host-differs', header: 'Location' },
    { url: 'https://app.example/login', status: 302, headers: { Location: 'https://APP.Example/home' } }, false],
  ['redirect: malformed target is unknown, not a match', { type: 'response-header-host-differs', header: 'Location' },
    { url: 'https://app.example/login', status: 302, headers: { Location: 'https://[bad/' } }, false],
  ['redirect: empty Location resolves to request host', { type: 'response-header-host-differs', header: 'Location' },
    { url: 'https://app.example/login', status: 302, headers: { Location: '' } }, false],
  ['redirect: lowercase header name is matched', { type: 'response-header-host-differs', header: 'Location' },
    { url: 'https://app.example/login', status: 302, headers: { location: 'https://other.example/' } }, true],
  ['http-url: uppercase scheme is http', { type: 'http-url' },
    { url: 'HTTP://app.example/', status: 200, headers: {} }, true],
  ['http-url: https is not http', { type: 'http-url' },
    { url: 'https://app.example/', status: 200, headers: {} }, false],
  ['missing-header: present but empty is not missing', { type: 'missing-response-header', header: 'X-Frame-Options' },
    { url: 'https://app.example/', status: 200, headers: { 'X-Frame-Options': '' } }, false],
  ['missing-header: lowercase name counts as present', { type: 'missing-response-header', header: 'X-Frame-Options' },
    { url: 'https://app.example/', status: 200, headers: { 'x-frame-options': 'DENY' } }, false],
  ['missing-header: absent header is missing', { type: 'missing-response-header', header: 'X-Frame-Options' },
    { url: 'https://app.example/', status: 200, headers: {} }, true],
  ['header-matches: absent header is no match', { type: 'response-header-matches', header: 'Server', valuePattern: 'nginx' },
    { url: 'https://app.example/', status: 200, headers: {} }, false],
  ['header-matches: value match is case-insensitive', { type: 'response-header-matches', header: 'Server', valuePattern: 'nginx' },
    { url: 'https://app.example/', status: 200, headers: { Server: 'NGINX/1.25' } }, true],
  ['header-matches: non-matching value', { type: 'response-header-matches', header: 'Server', valuePattern: 'nginx' },
    { url: 'https://app.example/', status: 200, headers: { Server: 'Apache' } }, false],
  ['missing-directive: directive present in HSTS', { type: 'response-header-missing-directive', header: 'Strict-Transport-Security', directive: 'preload' },
    { url: 'https://app.example/', status: 200, headers: { 'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload' } }, false],
  ['missing-directive: name prefix is not the directive', { type: 'response-header-missing-directive', header: 'Content-Security-Policy', directive: 'frame-ancestors' },
    { url: 'https://app.example/', status: 200, headers: { 'Content-Security-Policy': "default-src 'self'; frame-ancestors-x 'none'" } }, true],
  ['missing-directive: absent header counts as missing', { type: 'response-header-missing-directive', header: 'Content-Security-Policy', directive: 'frame-ancestors' },
    { url: 'https://app.example/', status: 200, headers: {} }, true],
  ['missing-directive: comma-separated list is split (Cache-Control)', { type: 'response-header-missing-directive', header: 'Cache-Control', directive: 'no-store' },
    { url: 'https://app.example/', status: 200, headers: { 'Cache-Control': 'no-cache, no-store' } }, false],
  ['missing-directive: first comma item is found', { type: 'response-header-missing-directive', header: 'Cache-Control', directive: 'no-cache' },
    { url: 'https://app.example/', status: 200, headers: { 'Cache-Control': 'no-cache, no-store' } }, false],
  ['missing-directive: comma list without the directive is missing', { type: 'response-header-missing-directive', header: 'Cache-Control', directive: 'max-age' },
    { url: 'https://app.example/', status: 200, headers: { 'Cache-Control': 'no-cache, no-store' } }, true],
  ['cookie: Secure present', { type: 'cookie-missing-flag', flag: 'Secure' },
    { url: 'https://app.example/', status: 200, headers: { 'Set-Cookie': 'sid=1; Path=/; Secure; HttpOnly' } }, false],
  ['cookie: one of two cookies lacks Secure', { type: 'cookie-missing-flag', flag: 'Secure' },
    { url: 'https://app.example/', status: 200, headers: { 'Set-Cookie': ['sid=1; Secure', 'pref=2; Path=/'] } }, true],
  ['cookie: SameSite is case-insensitive', { type: 'cookie-missing-flag', flag: 'SameSite' },
    { url: 'https://app.example/', status: 200, headers: { 'Set-Cookie': 'sid=1; samesite=lax' } }, false],
  ['cookie: flag name inside a value is not the flag', { type: 'cookie-missing-flag', flag: 'Secure' },
    { url: 'https://app.example/', status: 200, headers: { 'Set-Cookie': 'sid=Secure' } }, true],
  ['cookie: no Set-Cookie is no match', { type: 'cookie-missing-flag', flag: 'HttpOnly' },
    { url: 'https://app.example/', status: 200, headers: {} }, false],
  ['body: empty body never matches', { type: 'response-body-matches', valuePattern: 'Traceback' },
    { url: 'https://app.example/', status: 500, headers: {}, body: '' }, false],
  ['body: match is case-insensitive', { type: 'response-body-matches', valuePattern: 'traceback' },
    { url: 'https://app.example/', status: 500, headers: {}, body: 'TRACEBACK (most recent call last)' }, true],
  ['body: requireScheme http accepts http page', { type: 'response-body-matches', valuePattern: 'src', requireScheme: 'http' },
    { url: 'http://app.example/', status: 200, headers: {}, body: '<img src="x">' }, true],
  ['body: requireScheme https out-of-scope http page is no match', { type: 'response-body-matches', valuePattern: 'DEBUG\\s*=\\s*True', requireScheme: 'https' },
    { url: 'http://app.example/', status: 500, headers: {}, body: 'DEBUG = True' }, false],
];
// Pump 4: scheme/token/host edge rows. Each expected value follows the documented
// contract (docs/PACKS.md DAST table): schemes are case-insensitive, directive and
// flag tokens are exact, non-web Location schemes never count as a host change.
const DAST_EDGE_CASES_P4 = [
  ['p4 http-url: uppercase HTTP scheme matches', { type: 'http-url' }, { url: 'HTTP://app.example/', status: 200, headers: {} }, true],
  ['p4 http-url: https is no match', { type: 'http-url' }, { url: 'https://app.example/', status: 200, headers: {} }, false],
  ['p4 missing header: array values count as present', { type: 'missing-response-header', header: 'x-a' }, { url: 'https://a.example/', status: 200, headers: { 'X-A': ['a', 'b'] } }, false],
  ['p4 header-matches: array Set-Cookie any value', { type: 'response-header-matches', header: 'Set-Cookie', valuePattern: 'sid=' }, { url: 'https://a.example/', status: 200, headers: { 'Set-Cookie': ['x=1', 'sid=2'] } }, true],
  ['p4 cookie Secure: SecureX is not the Secure flag', { type: 'cookie-missing-flag', flag: 'Secure' }, { url: 'https://a.example/', status: 200, headers: { 'Set-Cookie': 'sid=1; SecureX' } }, true],
  ['p4 cookie SameSite: bare token without = is missing', { type: 'cookie-missing-flag', flag: 'SameSite' }, { url: 'https://a.example/', status: 200, headers: { 'Set-Cookie': 'sid=1; SameSite' } }, true],
  ['p4 cookie SameSite=Lax is present', { type: 'cookie-missing-flag', flag: 'SameSite' }, { url: 'https://a.example/', status: 200, headers: { 'Set-Cookie': 'sid=1; SameSite=Lax' } }, false],
  ['p4 body: observation without body is no match', { type: 'response-body-matches', valuePattern: 'x' }, { url: 'https://a.example/', status: 200, headers: {} }, false],
  ['p4 host-differs: uppercase scheme and host still differ', { type: 'response-header-host-differs', header: 'Location' }, { url: 'https://app.example/x', status: 302, headers: { Location: 'HTTPS://OTHER.example/' } }, true],
  ['p4 host-differs: ftp Location is not a web host', { type: 'response-header-host-differs', header: 'Location' }, { url: 'https://app.example/x', status: 302, headers: { Location: 'ftp://other.example/' } }, false],
  ['p4 directive: no-store substring in no-store-x is not the directive', { type: 'response-header-missing-directive', header: 'Cache-Control', directive: 'no-store' }, { url: 'https://a.example/', status: 200, headers: { 'Cache-Control': 'no-store-x' } }, true],
  ['p4 directive: comma-joined no-store is present', { type: 'response-header-missing-directive', header: 'Cache-Control', directive: 'no-store' }, { url: 'https://a.example/', status: 200, headers: { 'Cache-Control': 'no-cache,no-store' } }, false],
  ['p4 body requireScheme: uppercase HTTPS page is in scope', { type: 'response-body-matches', valuePattern: 'src', requireScheme: 'https' }, { url: 'HTTPS://app.example/', status: 200, headers: {}, body: '<img src="x">' }, true],
];
// Pump 5: rows for mutant coverage gaps found in Pump 5 (uppercase scheme on the observed URL).
const DAST_EDGE_CASES_P5 = [
  ['p5 host-differs: uppercase observed scheme and host still compare hosts', { type: 'response-header-host-differs', header: 'Location' }, { url: 'HTTPS://APP.example/login', status: 302, headers: { Location: 'https://other.example/' } }, true],
  ['p5 host-differs: uppercase observed scheme, same host is not a change', { type: 'response-header-host-differs', header: 'Location' }, { url: 'HTTPS://APP.example/login', status: 302, headers: { Location: 'https://app.example/home' } }, false],
];
for (const [label, check, observation, expected] of [...DAST_EDGE_CASES, ...DAST_EDGE_CASES_P3, ...DAST_EDGE_CASES_P4, ...DAST_EDGE_CASES_P5]) {
  let actual;
  let thrown = null;
  try {
    actual = evalDastCheck(check, observation);
  } catch (err) {
    thrown = err.message;
  }
  assert(thrown === null && actual === expected, `dast evaluator: ${label}`, thrown ?? `got ${String(actual)}`);
}

// --- Pump 6: secrets denylist veto at the rule layer (in-memory fixtures) ----
// The veto is applied by validate-packs.mjs (checkLineTests), not by the regex.
// Pattern mirrors (knowledge/patterns) execute the regex alone, so veto-only
// negatives MUST NOT be added to a pattern test path. Instead, the real
// DPK-SEC-007 pattern and denylist are combined with synthetic tests in memory;
// nothing is written to the repository and no rule or pattern file changes.
const SEC007 = JSON.parse(
  readFileSync(join(ROOT, 'packs', 'secrets', 'v1', 'rules', 'DPK-SEC-007.json'), 'utf8'),
);
// Values contain spaces so they do not read as credential-shaped literals outside
// packs/secrets (test-consistency's secret-assignment guard). The pattern only needs
// [^"']{4,}, so spacing does not change what the veto is exercised against.
const VETO_ROWS = [
  // [label, line, expected match]. Controls (true) prove the pattern still fires
  // when no denylist term is present; veto rows (false) prove suppression works.
  ['control: quoted password with no denylist term matches', 'db_password = "not a secret"', true],
  ['control: another quoted password with no denylist term matches', 'password = "plain text value"', true],
  ['veto exact uppercase EXAMPLE suppresses the match', 'password = "abc EXAMPLE zzzz"', false],
  ['veto case-insensitive: "Example" suppressed by EXAMPLE', 'password = "Example secret value"', false],
  ['veto exact lowercase changeme suppresses the match', 'password = "changeme prod 1234"', false],
  ['veto case-insensitive: CHANGEME suppressed by changeme', 'password = "CHANGEME prod 1234"', false],
];
// Each call pairs the row under test with a partner of the opposite expectation,
// so every call carries at least one positive and one negative test.
function checkVetoRow(line, match) {
  const partner = match
    ? { line: 'password = "ab"', match: false }
    : { line: 'db_password = "not a secret"', match: true };
  return validatePackFile({ ...SEC007, tests: [{ line, match }, partner] });
}
for (const [label, line, match] of VETO_ROWS) {
  const errors = checkVetoRow(line, match);
  assert(errors.length === 0, `secrets veto (rule layer): ${label}`, errors.join('; '));
}
// Harness self-check: a veto row labelled as a match must be rejected, so the
// rows above cannot pass vacuously.
const mislabelled = checkVetoRow('password = "abc EXAMPLE zzzz"', true);
assert(
  mislabelled.some((error) => error.includes('expected match=true')),
  'secrets veto (rule layer): mislabelled veto row is rejected by the validator',
  mislabelled.join('; ') || 'validator accepted a vetoed line as a match',
);

// --- Pump 7: generator denylist veto must match the documented contract ----------
// docs/PACKS.md: denylist entries are case-insensitive substrings, and validate-packs.mjs applies
// them that way. generate-assets.mjs runLineTests must agree, or a generated cell could be accepted
// by the generator and rejected by the validator (or the reverse). Pure function, no files written.
const GEN_SECRET_PATTERN = '(?:password|passwd|pwd)\\s*[:=]\\s*["\'][^"\']{4,}["\']';
const GEN_CASES = [
  // [label, line, expected match]. For expected true the generator must accept the line as a match.
  ['generator control: quoted password with no denylist term matches', 'db_password = "not a secret"', true],
  ['generator veto exact uppercase EXAMPLE', 'password = "abc EXAMPLE zzzz"', false],
  ['generator veto lowercase example (case-insensitive contract)', 'password = "example secret value"', false],
  ['generator veto mixed-case Example (case-insensitive contract)', 'password = "Example secret value"', false],
];
for (const [label, line, match] of GEN_CASES) {
  const result = runLineTests(GEN_SECRET_PATTERN, '', [{ line, match }], ['EXAMPLE']);
  assert(result === null, `generator/validator agree: ${label}`, result ?? '');
}
{
  // Harness self-check: a vetoed line labelled as a match must be reported, not silently accepted.
  const result = runLineTests(GEN_SECRET_PATTERN, '', [{ line: 'password = "example secret value"', match: true }], ['EXAMPLE']);
  assert(typeof result === 'string', 'generator/validator agree: vetoed line labelled as match is reported', String(result));
}

// --- Rule metadata semantics (Batch D, audit F-07) ---------------------------
// 1. SAST `languages` omission = universal (docs/PACKS.md contract): valid, and
//    the empty array stays invalid (1..10 bound) so "no languages" cannot be
//    spelled two ways. DPK-SAST-004 is the shipped example of the omission.
// 2. Secrets `denylist` is required for credential-value rules; only
//    evidence-only rules (matchOnlyEvidence: true, e.g. DPK-SEC-004 PEM
//    headers) may omit it. Enforced by validate-packs + fixture above.
{
  const sast004 = JSON.parse(readFileSync(join(ROOT, 'packs', 'sast', 'v1', 'rules', 'DPK-SAST-004.json'), 'utf8'));
  assert(!('languages' in sast004), 'metadata: DPK-SAST-004 omits languages (documented any-file contract)');
  const omittedOk = validatePackFile({ ...sast004 });
  assert(omittedOk.length === 0, 'metadata: languages-omitting SAST rule validates (universal semantics)', omittedOk.join('; '));
  const emptyBad = validatePackFile({ ...sast004, languages: [] });
  assert(emptyBad.some((e) => e.includes('languages: must have 1..')), 'metadata: empty languages array rejected (one spelling only)', emptyBad.join('; '));
  let secWithEvidenceOmittingDenylist = 0;
  let violations = [];
  for (const file of ruleFiles) {
    const rule = JSON.parse(readFileSync(file, 'utf8'));
    if (rule.schemaVersion !== 'drobon.pack.secrets/v1') continue;
    if (rule.matchOnlyEvidence === true) secWithEvidenceOmittingDenylist += 1;
    if (rule.denylist === undefined && rule.matchOnlyEvidence !== true) violations.push(rule.id);
  }
  assert(violations.length === 0, 'metadata: every credential-value secrets rule ships a denylist (or is evidence-only)', violations.join(','));
  assert(secWithEvidenceOmittingDenylist >= 1, 'metadata: evidence-only exemption is exercised by a shipped rule (DPK-SEC-004)');
  const redactViolations = ruleFiles
    .filter((file) => file.includes('packs/secrets'))
    .map((file) => JSON.parse(readFileSync(file, 'utf8')))
    .filter((rule) => rule.schemaVersion === 'drobon.pack.secrets/v1')
    .filter((rule) => rule.redact !== true)
    .map((rule) => rule.id);
  assert(redactViolations.length === 0, 'redaction contract: all secrets rules promise redact:true', redactViolations.join(','));
}

// --- DAST malformed-observation robustness -----------------------------------
// A runtime loader can feed the evaluator anything. The contract is total:
// evalDastCheck never throws on malformed observations; missing pieces behave
// as "nothing observed" and the check evaluates false.
{
  const MALFORMED = [
    ['no headers key', { url: 'http://a/', status: 200, body: '' }],
    ['headers null', { url: 'http://a/', status: 200, body: '', headers: null }],
    ['headers array', { url: 'http://a/', status: 200, body: '', headers: ['x'] }],
    ['no body key', { url: 'http://a/', status: 200, headers: {} }],
    ['url unparseable', { url: 'ht!tp://%%%', status: 200, body: '', headers: {} }],
    ['url non-string', { url: 42, status: 200, body: '', headers: {} }],
  ];
  for (const [label, observation] of MALFORMED) {
    for (const check of [
      { type: 'http-url' },
      { type: 'missing-response-header', header: 'X-Frame-Options' },
      { type: 'response-header-missing-directive', header: 'Content-Security-Policy', directive: 'frame-ancestors' },
      { type: 'response-header-matches', header: 'Server', valuePattern: 'nginx' },
      { type: 'cookie-missing-flag', flag: 'Secure' },
      { type: 'response-body-matches', valuePattern: 'admin' },
      { type: 'response-body-matches', valuePattern: 'admin', requireScheme: 'https' },
      { type: 'response-header-host-differs', header: 'Location' },
    ]) {
      let thrown = null;
      let hit = null;
      try {
        hit = evalDastCheck(check, observation);
      } catch (err) {
        thrown = err.message;
      }
      assert(thrown === null && typeof hit === 'boolean', `dast robustness: ${label} / ${check.type} never throws`, thrown ?? String(hit));
    }
  }
  // Absence of the sensitive header must still be a finding on an otherwise
  // well-formed observation with a null header map (robustness ≠ vacuous).
  assert(
    evalDastCheck({ type: 'missing-response-header', header: 'X-Frame-Options' }, { url: 'https://a/', headers: null }) === true,
    'dast robustness: missing-header finding survives a null header map',
  );
}

// --- summary -----------------------------------------------------------------
const total = passed + failed;
process.stdout.write(`pack-tests: ${failed === 0 ? 'PASS' : 'FAIL'} (${passed}/${total} passed)\n`);
process.exitCode = failed === 0 ? 0 : 1;
