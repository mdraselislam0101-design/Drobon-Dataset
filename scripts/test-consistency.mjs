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
 *     test/invalid-matrix/ MUST be rejected;
 *  9. the source registry validates + every record source resolves +
 *     the OSV seed list is well-formed (invalid-sources rejected);
 * 10. the corpus targets + roadmap + owner decisions validate as a set
 *     (invalid-corpus rejected);
 * 11. integrity manifests are deterministic + catch tampering (on a tmp
 *     copy), and the dedup recount agrees with CORPUS_TARGETS;
 * 12. the 4 ingestion gates load BLOCKED + requireGates() fail-closed
 *     matrix (single + multiple failures block, malformed file blocks);
 * 13. credential-leak scan (strict repo-wide + audited secrets fixtures).
 *
 * Usage: node scripts/test-consistency.mjs
 */
import { appendFileSync, cpSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateCwePath } from './validate-cwe.mjs';
import { validateMatrixPath } from './validate-matrix.mjs';
import { validateSourcesPath } from './validate-sources.mjs';
import { validateCorpusSet, validateCorpusTargetsPath, validateDecisionsPath, validateRoadmapPath } from './validate-corpus.mjs';
import { GATE_IDS, gatesSatisfied, loadGates, requireGates } from './ingestion-gates.mjs';
import { groupAdvisoryRecords, groupFiles } from './dedup-report.mjs';
import { computeManifest, verifyManifest } from './manifest.mjs';

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
  'cwe-wrong-url.json': 'canonical',
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
  'log-bad-row.json': 'ingestionLog',
  'pin-bad-id.json': 'unresolved',
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

// --- 9. source registry + seed list integrity ------------------------------------------
// Every record provenance.source must resolve to vuln-intel/sources.json
// (terms pointers + review status; pointers grant nothing), and the OSV
// seed package list must be well-formed (OSV ecosystem names, bounded
// trimmed names, no duplicates). (sources.json itself is excluded from
// record walks by the collectors below — it is registry metadata, not
// a record.)
const sourceRegistryErrors = validateSourcesPath(join(ROOT, 'vuln-intel', 'sources.json'));
assert(
  sourceRegistryErrors.length === 0,
  'positive: vuln-intel/sources.json validates',
  sourceRegistryErrors.join('; '),
);
if (sourceRegistryErrors.length === 0) {
  const registeredSources = new Set(
    readJson(join(ROOT, 'vuln-intel', 'sources.json')).sources.map((entry) => entry.id),
  );
  const unregisteredSources = [];
  for (const file of collectJsonFiles(join(ROOT, 'vuln-intel'))) {
    const record = readJson(file);
    const source = record.provenance?.source;
    if (!registeredSources.has(source)) {
      unregisteredSources.push(`${file.split('/').slice(-3).join('/')}: ${String(source)}`);
    }
  }
  assert(
    unregisteredSources.length === 0,
    'consistency: every record source resolves to sources.json',
    unregisteredSources.join('; '),
  );
}
const NEGATIVE_SOURCES = {
  'bad-status.json': 'status',
  'bad-url.json': 'https://',
};
for (const [name, needle] of Object.entries(NEGATIVE_SOURCES)) {
  const file = join(ROOT, 'test', 'invalid-sources', name);
  const errors = existsSync(file) ? validateSourcesPath(file) : [];
  const rejected = errors.length > 0 && errors.some((error) => error.includes(needle));
  assert(rejected, `negative: test/invalid-sources/${name} rejected (${needle})`, errors.join('; '));
}
function checkSeedList(doc) {
  const problems = [];
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) {
    return ['seed list: must be an object'];
  }
  for (const key of Object.keys(doc)) {
    if (!['_note', 'packages'].includes(key)) {
      problems.push(`seed list: unknown property "${key}"`);
    }
  }
  const packages = Array.isArray(doc.packages) ? doc.packages : [];
  if (!Array.isArray(doc.packages)) {
    problems.push('seed list: packages must be an array');
  }
  if (packages.length < 1 || packages.length > 500) {
    problems.push(`seed list: packages must have 1..500 entries (got ${packages.length})`);
  }
  const seen = new Set();
  packages.forEach((entry, index) => {
    const label = `packages[${index}]`;
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
      problems.push(`${label}: must be an object`);
      return;
    }
    if (entry.ecosystem !== 'npm' && entry.ecosystem !== 'PyPI') {
      problems.push(`${label}: ecosystem must be npm or PyPI (OSV names)`);
    }
    if (typeof entry.name !== 'string' || entry.name.length < 1 || entry.name.length > 214) {
      problems.push(`${label}: name must be 1..214 characters`);
    } else {
      let dirty = entry.name !== entry.name.trim();
      for (const char of entry.name) {
        const code = char.codePointAt(0) ?? 0;
        if (code < 0x20 || code === 0x7f) dirty = true;
      }
      if (dirty) {
        problems.push(`${label}: name must be trimmed and control-character-free`);
      }
    }
    const key = `${entry.ecosystem}|${entry.name}`;
    if (seen.has(key)) {
      problems.push(`${label}: duplicate ${key}`);
    }
    seen.add(key);
  });
  return problems;
}
const seedProblems = checkSeedList(readJson(join(ROOT, 'data', 'osv-seed-packages.json')));
assert(
  seedProblems.length === 0,
  'consistency: data/osv-seed-packages.json is well-formed',
  seedProblems.join('; '),
);
const syntheticSeed = {
  packages: [
    { ecosystem: 'npm', name: 'left-pad' },
    { ecosystem: 'npm', name: 'left-pad' },
    { ecosystem: 'rubygems', name: 'rails' },
  ],
  extra: true,
};
assert(
  checkSeedList(syntheticSeed).length === 3,
  'negative: seed list checker flags duplicates, bad ecosystems, and unknown keys',
  checkSeedList(syntheticSeed).join('; '),
);

// --- 10. corpus planning artifacts -------------------------------------------------
// The 100K planning set validates (counts recomputed from files, production
// claims gated on a LICENSE grant, volumes unquoted, redistribution
// unverified), and every fixture under test/invalid-corpus/ MUST be rejected.
const corpusSetErrors = validateCorpusSet(
  join(ROOT, 'docs', 'CORPUS_TARGETS.json'),
  join(ROOT, 'docs', 'SOURCE_ROADMAP.json'),
  join(ROOT, 'docs', 'OWNER_DECISIONS.json'),
  ROOT,
);
assert(
  corpusSetErrors.length === 0,
  'positive: corpus targets + roadmap + decisions validate as a set',
  corpusSetErrors.join('; '),
);
const NEGATIVE_CORPUS_TARGETS = {
  'counts-inflated.json': 'LICENSE',
};
for (const [name, needle] of Object.entries(NEGATIVE_CORPUS_TARGETS)) {
  const file = join(ROOT, 'test', 'invalid-corpus', name);
  const errors = existsSync(file) ? validateCorpusTargetsPath(file, ROOT) : [];
  const rejected = errors.length > 0 && errors.some((error) => error.includes(needle));
  assert(rejected, `negative: test/invalid-corpus/${name} rejected (${needle})`, errors.join('; '));
}
const NEGATIVE_CORPUS_ROADMAP = {
  'license-claimed.json': 'VERIFIED',
};
for (const [name, needle] of Object.entries(NEGATIVE_CORPUS_ROADMAP)) {
  const file = join(ROOT, 'test', 'invalid-corpus', name);
  const errors = existsSync(file) ? validateRoadmapPath(file) : [];
  const rejected = errors.length > 0 && errors.some((error) => error.includes(needle));
  assert(rejected, `negative: test/invalid-corpus/${name} rejected (${needle})`, errors.join('; '));
}
const NEGATIVE_CORPUS_DECISIONS = {
  'decisions-bad-entry.json': 'decider',
};
for (const [name, needle] of Object.entries(NEGATIVE_CORPUS_DECISIONS)) {
  const file = join(ROOT, 'test', 'invalid-corpus', name);
  const errors = existsSync(file) ? validateDecisionsPath(file) : [];
  const rejected = errors.length > 0 && errors.some((error) => error.includes(needle));
  assert(rejected, `negative: test/invalid-corpus/${name} rejected (${needle})`, errors.join('; '));
}

// --- 11. integrity manifests + dedup recount ------------------------------------------------
// G11: manifests are deterministic; tampered/missing/extra files fail loudly
// (all mutation happens on a tmp copy - the repo is never touched). G3: the
// dedup report groups the real tree into items; its count must equal the
// CORPUS_TARGETS advisory claim, and synthetic fixtures must group 4 files
// into 3 items.
const recordsManifestA = computeManifest(ROOT, 'records');
const recordsManifestB = computeManifest(ROOT, 'records');
assert(
  JSON.stringify(recordsManifestA) === JSON.stringify(recordsManifestB),
  'positive: records manifest is deterministic',
);
assert(
  verifyManifest(ROOT, recordsManifestA).ok,
  'positive: records manifest verifies against the tree',
);
const tamperRoot = mkdtempSync(join(tmpdir(), 'drobon-manifest-'));
cpSync(join(ROOT, 'vuln-intel'), join(tamperRoot, 'vuln-intel'), { recursive: true });
const tamperManifest = computeManifest(tamperRoot, 'records');
const tamperVictim = join(tamperRoot, tamperManifest.files[0].path);
appendFileSync(tamperVictim, ' ');
const tamperResult = verifyManifest(tamperRoot, tamperManifest);
assert(
  !tamperResult.ok && tamperResult.problems.length === 1 && tamperResult.problems[0].startsWith('tampered:'),
  'negative: manifest verification catches a tampered file',
  tamperResult.problems.join('; '),
);
rmSync(tamperRoot, { recursive: true, force: true });
const targetsDoc = readJson(join(ROOT, 'docs', 'CORPUS_TARGETS.json'));
const advisoryClaim = targetsDoc.categories.find((category) => category.id === 'advisory-record')?.validatedCount;
const dedupReal = groupAdvisoryRecords(ROOT);
assert(
  dedupReal.items.length === advisoryClaim,
  `consistency: dedup items (${dedupReal.items.length}) equal CORPUS_TARGETS advisory claim (${String(advisoryClaim)})`,
);
assert(
  dedupReal.files === 100 && dedupReal.multiFile.length === 9,
  `consistency: dedup real tree is 100 files / 9 multi-file tuples (got ${dedupReal.files}/${dedupReal.multiFile.length})`,
);
const dedupSynthetic = groupFiles(
  readdirSync(join(ROOT, 'test', 'dedup')).filter((name) => name.endsWith('.json')).map((name) => join(ROOT, 'test', 'dedup', name)),
  ROOT,
);
assert(
  dedupSynthetic.files === 4 && dedupSynthetic.items.length === 3 && dedupSynthetic.multiFile.length === 1,
  `negative: synthetic duplicates group 4 files into 3 items (got ${dedupSynthetic.files}/${dedupSynthetic.items.length}/${dedupSynthetic.multiFile.length})`,
);
assert(
  existsSync(join(ROOT, 'docs', 'LICENSE_REVIEW.md')),
  'positive: docs/LICENSE_REVIEW.md exists (registry report pointer)',
);


// --- 12. ingestion authorization gates ------------------------------------------------
// The four INGESTION_PLAN gates load BLOCKED, requireGates() names every
// missing gate, and the fail-closed matrix proves any missing gate (single
// or multiple) blocks production while a malformed file can never approve.
const gatesFile = join(ROOT, 'docs', 'INGESTION_GATES.json');
const loadedGates = loadGates(gatesFile);
assert(
  loadedGates.errors.length === 0,
  'positive: INGESTION_GATES.json parses + validates structurally',
  loadedGates.errors.join('; '),
);
const liveGates = gatesSatisfied(loadedGates.doc);
assert(
  !liveGates.ok && liveGates.missing.length === 4,
  'positive: all 4 production gates are BLOCKED (missing: ' + liveGates.missing.join(', ') + ')',
);
let liveBlockMessage = '';
try {
  requireGates(loadedGates.doc);
} catch (err) {
  liveBlockMessage = err.message;
}
assert(
  GATE_IDS.every((id) => liveBlockMessage.includes(id)) && liveBlockMessage.includes('BLOCKED'),
  'positive: requireGates() on the live file blocks naming GATE-1..GATE-4',
  liveBlockMessage,
);
for (const importer of ['import-ghsa.mjs', 'import-osv.mjs']) {
  const source = readFileSync(join(ROOT, 'scripts', importer), 'utf8');
  assert(
    source.includes("from './ingestion-gates.mjs'") && source.includes('requireGates();'),
    'positive: scripts/' + importer + ' enforces requireGates() at startup',
  );
}
function gatesDocWith(statuses) {
  return {
    schemaVersion: 'drobon.ingestion.gates/v1',
    note: 'synthetic gate matrix (test only)',
    gates: GATE_IDS.map((id, index) => ({
      id,
      title: 'gate ' + id,
      evidenceRequired: 'test evidence rule',
      validator: 'test',
      passCriteria: 'test pass rule',
      owner: 'test',
      status: statuses[index],
      statusEvidence: statuses[index] === 'SATISFIED' ? 'test evidence recorded' : 'test blocked',
      decidedAt: statuses[index] === 'SATISFIED' ? '2026-10-14' : null,
    })),
  };
}
function blockMessageFor(doc) {
  try {
    requireGates(doc);
    return 'ALLOWED (unexpected)';
  } catch (err) {
    return err.message;
  }
}
assert(
  requireGates(gatesDocWith(['SATISFIED', 'SATISFIED', 'SATISFIED', 'SATISFIED'])) === true,
  'gates matrix: 4/4 SATISFIED opens ingestion',
);
GATE_IDS.forEach((blockedId, blockedIndex) => {
  const statuses = ['SATISFIED', 'SATISFIED', 'SATISFIED', 'SATISFIED'];
  statuses[blockedIndex] = 'BLOCKED';
  const message = blockMessageFor(gatesDocWith(statuses));
  assert(
    message.includes(blockedId) && message.includes('BLOCKED'),
    'gates matrix: single failure ' + blockedId + ' blocks production',
    message,
  );
});
const multiMessage = blockMessageFor(gatesDocWith(['BLOCKED', 'SATISFIED', 'BLOCKED', 'SATISFIED']));
assert(
  multiMessage.includes('GATE-1') && multiMessage.includes('GATE-3') && !multiMessage.includes('GATE-2'),
  'gates matrix: multiple failures name exactly the blocked gates',
  multiMessage,
);
const corruptMessage = blockMessageFor({ schemaVersion: 'drobon.ingestion.gates/v1', gates: [] });
assert(
  corruptMessage.includes('gate file invalid'),
  'gates matrix: malformed gate file blocks (fail-closed)',
  corruptMessage,
);


// --- 13. credential-leak scan -------------------------------------------------------
// High-confidence secret shapes must appear NOWHERE except the documented
// secrets-detection fixtures (packs/secrets/**), whose credential-shaped
// test lines each carry a safety marker (EXAMPLE-style, placeholder-only, or
// a pinned reviewed value). Patterns are built from string fragments so this
// scanner cannot match its own source.
const SECRET_PATTERNS = [
  { name: 'pem-private-key', re: new RegExp('-----BEGIN (' + 'RSA |EC |OPENSSH )?PRIVATE KEY-----') },
  { name: 'aws-key-id', re: new RegExp('AK' + 'IA[0-9A-Z]{16}') },
  { name: 'github-token', re: new RegExp('ghp' + '_[A-Za-z0-9]{36}') },
  { name: 'slack-token', re: new RegExp('xox' + '[bap]-[A-Za-z0-9-]+') },
  {
    name: 'secret-assignment',
    re: new RegExp("(api[_-]?key|secret|passwd|password|token)\\s*[:=]\\s*['\"][A-Za-z0-9_\\-+/=]{12,}['\"]", 'i'),
  },
];
const FIXTURE_SAFE_MARKERS = [
  /EXAMPLE/i,
  /(.)\1{7,}/,
  /1234567890/,
  /sk_live_9f2d8c1e4b7a6f5d/,
  /"line": "-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"/,
];
function collectRepoTextFiles(root) {
  const found = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === '.git') continue;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile()) {
        try {
          const text = readFileSync(full, 'utf8');
          if (!text.includes('\0')) found.push(full);
        } catch {
          // Unreadable files are out of scope for a text scan.
        }
      }
    }
  };
  walk(root);
  return found.sort();
}
const strictViolations = [];
const fixtureFailures = [];
for (const file of collectRepoTextFiles(ROOT)) {
  const rel = file.slice(ROOT.length + 1);
  const inSecretsFixtures = rel === 'packs/secrets' || rel.startsWith('packs/secrets/');
  const lines = readFileSync(file, 'utf8').split('\n');
  lines.forEach((line, index) => {
    for (const pattern of SECRET_PATTERNS) {
      if (!pattern.re.test(line)) continue;
      if (!inSecretsFixtures) {
        strictViolations.push(`${rel}:${index + 1}:${pattern.name}`);
      } else if (!FIXTURE_SAFE_MARKERS.some((marker) => marker.test(line))) {
        fixtureFailures.push(`${rel}:${index + 1}:${pattern.name}: ${line.trim().slice(0, 80)}`);
      }
    }
  });
}
assert(
  strictViolations.length === 0,
  'positive: no credential shapes outside packs/secrets fixtures',
  strictViolations.slice(0, 5).join(' | '),
);
assert(
  fixtureFailures.length === 0,
  'positive: every secrets-fixture credential shape carries a safety marker',
  fixtureFailures.slice(0, 5).join(' | '),
);
const scannerPositives = [
  '-----BEGIN ' + 'RSA PRIVATE KEY-----',
  'AK' + 'IA1234567890ABCDEF',
  'ghp' + '_' + 'A'.repeat(36),
  'xox' + 'b-123456789012-abcdefghij',
  'api_key = "' + 'sk_live_9f2d8c1e4b7a6f5d00' + '"',
];
const scannerDead = SECRET_PATTERNS.filter((pattern, index) => !pattern.re.test(scannerPositives[index]));
assert(
  scannerDead.length === 0,
  'positive: leak scanner fires on all 5 synthetic credential shapes',
  scannerDead.map((pattern) => pattern.name).join(', '),
);
const scannerNegatives = ['no secrets here', 'token = "short"', 'see ghp_ docs', 'AKIA docs mention'];
const scannerFalseAlarms = [];
for (const line of scannerNegatives) {
  for (const pattern of SECRET_PATTERNS) {
    if (pattern.re.test(line)) scannerFalseAlarms.push(`${pattern.name} ~ ${line}`);
  }
}
assert(
  scannerFalseAlarms.length === 0,
  'positive: leak scanner stays silent on safe documentation lines',
  scannerFalseAlarms.join(' | '),
);

// --- summary --------------------------------------------------------------------
const total = passed + failed;
process.stdout.write(`consistency-tests: ${failed === 0 ? 'PASS' : 'FAIL'} (${passed}/${total} passed)\n`);
process.exitCode = failed === 0 ? 0 : 1;
