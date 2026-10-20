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
import { appendFileSync, cpSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateCwePath, CANONICAL_CWE_VERSION } from './validate-cwe.mjs';
import { validatePackFile } from './validate-packs.mjs';
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
const cweVersions = new Map();
for (const file of cweFiles) {
  const errors = validateCwePath(file);
  const record = errors.length === 0 ? readJson(file) : null;
  assert(errors.length === 0, `positive: ${file.split('/').slice(-3).join('/')} validates`, errors.join('; '));
  if (record !== null) {
    cweIds.add(record.id);
    cweVersions.set(record.id, record.cweVersion);
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

// --- 3b. CWE version metadata chain + legacy exception policy -----------------------
// Every applicable CWE ref must resolve to an entry that carries explicit valid
// version metadata equal to the repo-pinned canonical value. Failures name the
// offending asset. This is a repo-local consistency check only: no external CWE
// catalog is consulted, and nothing here is externally verified.
{
  const refVersionProblems = (refs) =>
    refs
      .filter((ref) => ref.cwe !== undefined)
      .filter((ref) => !cweIds.has(ref.cwe) || cweVersions.get(ref.cwe) !== CANONICAL_CWE_VERSION)
      .map((ref) => `${ref.asset} → ${ref.cwe}`);
  const realRefs = [
    ...packRuleFiles.map((file) => {
      const rule = readJson(file);
      return { asset: rule.id, cwe: rule.cwe };
    }),
    ...remediationFiles.map((file) => {
      const entry = readJson(file);
      return { asset: entry.ruleId, cwe: entry.standardId };
    }),
  ];
  const versionProblems = refVersionProblems(realRefs);
  assert(
    versionProblems.length === 0,
    `consistency: every CWE ref carries repo-pinned version metadata (${CANONICAL_CWE_VERSION})`,
    versionProblems.slice(0, 5).join(' | '),
  );
  // Negative self-check of the same predicate: absent targets and targets whose
  // entry lacks the canonical version are both flagged, with the asset named.
  const synthetic = [
    { asset: 'SYNTH-ABSENT', cwe: 'CWE-999999' },
    { asset: 'SYNTH-OMITTED', cwe: undefined },
  ];
  const syntheticFlagged = refVersionProblems(synthetic);
  assert(
    syntheticFlagged.length === 1 && syntheticFlagged[0].startsWith('SYNTH-ABSENT'),
    'negative: ref-version chain flags an absent CWE target and skips omitted refs',
    syntheticFlagged.join(' | '),
  );
  // Legacy exception policy (explicit + tested): "omit when uncertain" is the
  // only permitted exception to carrying a CWE ref (validate-packs accepts a
  // rule without `cwe`). Every PRESENT ref must resolve to a versioned entry
  // (asserted above). Zero pack rules currently use the exception — pin that.
  {
    const sample = readJson(packRuleFiles[0]);
    delete sample.cwe;
    const omitErrors = validatePackFile(sample).filter((error) => error.toLowerCase().includes('cwe'));
    assert(
      omitErrors.length === 0,
      'legacy exception policy: a CWE ref may be omitted ("omit when uncertain")',
      omitErrors.join('; '),
    );
    const omitted = packRuleFiles.map((file) => readJson(file)).filter((rule) => rule.cwe === undefined);
    assert(
      omitted.length === 0,
      'legacy exception policy: zero pack rules omit their CWE ref today (count pinned)',
      omitted.map((rule) => rule.id).join(', '),
    );
  }
  // Pin sync: the contract doc pin and the validator constant must agree.
  const contractDoc = readFileSync(join(ROOT, 'docs', 'DATASET_APP_CONTRACT.md'), 'utf8');
  assert(
    contractDoc.includes(`MITRE CWE ${CANONICAL_CWE_VERSION}`),
    `consistency: DATASET_APP_CONTRACT pins MITRE CWE ${CANONICAL_CWE_VERSION} (matches validate-cwe.mjs)`,
    'doc pin text missing',
  );
}

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

// --- 6b. pack/remediation/CWE count lines + retired cell reservations -------------------
// Count-sync tripwire: README pack, remediation and CWE counts must equal the tree.
// Manifest cells without a rule file must be exactly the retired reservations
// listed in docs/ASSET_METHODOLOGY.md (IDs are reserved, never reused).
const ruleIdsOnDisk = new Set(
  ['sast', 'secrets', 'dast'].flatMap((kind) =>
    readdirSync(join(ROOT, 'packs', kind, 'v1', 'rules')).map((file) => file.replace(/\.json$/, '')),
  ),
);
const readmeText = readFileSync(join(ROOT, 'README.md'), 'utf8');
const packLine = /\*\*(\d+) pack rules\*\* \((\d+) SAST \+ (\d+) secrets \+ (\d+) DAST\)/.exec(readmeText);
const remediationLine = /\*\*(\d+) remediation entries\*\*/.exec(readmeText);
const cweLine = /\*\*(\d+) CWE knowledge entries\*\*/.exec(readmeText);
const countPrefix = (prefix) => [...ruleIdsOnDisk].filter((id) => id.startsWith(prefix)).length;
const actualCounts = {
  packTotal: ruleIdsOnDisk.size,
  packSast: countPrefix('DPK-SAST-'),
  packSecrets: countPrefix('DPK-SEC-'),
  packDast: countPrefix('DPK-DAST-'),
  remediation: readdirSync(join(ROOT, 'knowledge', 'remediation')).filter((f) => f.endsWith('.json')).length,
  cwe: readdirSync(join(ROOT, 'knowledge', 'cwe')).filter((f) => f.endsWith('.json')).length,
};
assert(
  packLine !== null && remediationLine !== null && cweLine !== null,
  'count-sync: README keeps the pack, remediation and CWE count lines',
);
if (packLine !== null && remediationLine !== null && cweLine !== null) {
  const readmeCounts = {
    packTotal: Number(packLine[1]),
    packSast: Number(packLine[2]),
    packSecrets: Number(packLine[3]),
    packDast: Number(packLine[4]),
    remediation: Number(remediationLine[1]),
    cwe: Number(cweLine[1]),
  };
  const drifted = Object.keys(actualCounts).filter((key) => readmeCounts[key] !== actualCounts[key]);
  assert(
    drifted.length === 0,
    'count-sync: README pack/remediation/CWE counts match the tree',
    drifted.map((key) => `${key}: README ${readmeCounts[key]} vs tree ${actualCounts[key]}`).join('; '),
  );
}
const staleCountLine = /\*\*5 pack rules\*\* \((\d+) SAST \+ (\d+) secrets \+ (\d+) DAST\)/.exec(
  '**5 pack rules** (1 SAST + 2 secrets + 2 DAST)',
);
assert(
  staleCountLine !== null && Number(staleCountLine[1]) + Number(staleCountLine[2]) + Number(staleCountLine[3]) === 5,
  'negative: count-sync parser reads the split form of the pack line',
);
const assetMethodology = readFileSync(join(ROOT, 'docs', 'ASSET_METHODOLOGY.md'), 'utf8');
const retiredHeader = /Retired reservations \((\d+)\):/.exec(assetMethodology);
const retiredIds = assetMethodology.slice(retiredHeader?.index ?? 0).split(/\n\n/)[0].match(/DPK-(?:SAST|SEC|DAST)-\d+/g) ?? [];
const manifestCells = JSON.parse(readFileSync(join(ROOT, 'data', 'asset-cells', '.manifest.json'), 'utf8')).cells;
const missingRuleCells = Object.values(manifestCells)
  .map((cell) => cell.ruleId)
  .filter((id) => !ruleIdsOnDisk.has(id))
  .sort();
assert(retiredHeader !== null, 'retired-reservations: ASSET_METHODOLOGY.md documents the retired cell IDs');
assert(
  retiredHeader !== null &&
    Number(retiredHeader[1]) === retiredIds.length &&
    retiredIds.slice().sort().join(',') === missingRuleCells.join(','),
  'retired-reservations: manifest cells without rule files equal the documented retired list',
  `documented ${retiredIds.length}, manifest-missing ${missingRuleCells.length}`,
);

// --- 7. negative: invalid CWE fixtures rejected --------------------------------------
const NEGATIVE_CWE = {
  'cwe-leading-zero.json': 'id: must match',
  'cwe-wrong-url.json': 'canonical',
  'cwe-missing-version.json': 'missing required property "cweVersion"',
  'cwe-malformed-version.json': 'cweVersion: must match',
  'cwe-mismatched-version.json': 'repo-pinned catalog version',
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


const approvedStatusMessage = blockMessageFor(gatesDocWith(['SATISFIED', 'SATISFIED', 'SATISFIED', 'APPROVED']));
assert(
  approvedStatusMessage.includes('gate file invalid'),
  'gates matrix: unexpected status value blocks (fail-closed)',
  approvedStatusMessage,
);
const nullDocMessage = blockMessageFor(null);
assert(
  nullDocMessage.includes('gate file invalid'),
  'gates matrix: null gate doc blocks (fail-closed)',
  nullDocMessage,
);
const swappedDoc = gatesDocWith(['SATISFIED', 'SATISFIED', 'SATISFIED', 'SATISFIED']);
swappedDoc.gates[0].id = 'GATE-2';
swappedDoc.gates[1].id = 'GATE-1';
const swappedMessage = blockMessageFor(swappedDoc);
assert(
  swappedMessage.includes('gate file invalid'),
  'gates matrix: misordered/duplicate gate ids block (fail-closed)',
  swappedMessage,
);
const missingFileMessage = blockMessageFor(join(ROOT, 'docs', 'INGESTION_GATES.missing.json'));
assert(
  missingFileMessage.includes('cannot parse'),
  'gates matrix: missing gate file blocks (fail-closed)',
  missingFileMessage,
);
function runImporterBlocked(importer, args, outSubdir) {
  const sandbox = mkdtempSync(join(tmpdir(), 'drobon-gateprobe-'));
  const outDir = join(sandbox, outSubdir);
  let status = 0;
  let stderr = '';
  try {
    execFileSync('node', [join(ROOT, 'scripts', importer), ...args, '--out', outDir], {
      cwd: ROOT,
      stdio: ['ignore', 'ignore', 'pipe'],
    });
  } catch (err) {
    status = err.status ?? 1;
    stderr = String(err.stderr ?? '');
  }
  const wrote = existsSync(outDir);
  rmSync(sandbox, { recursive: true, force: true });
  return { status, stderr, wrote };
}
const ghsaProbe = runImporterBlocked('import-ghsa.mjs', ['--limit', 'not-a-number', '--ecosystem', 'bogus'], 'ghsa-out');
assert(
  ghsaProbe.status !== 0 && ghsaProbe.stderr.includes('BLOCKED') && !ghsaProbe.wrote,
  'gates live: import-ghsa fails on gates before args/network/write',
  'status=' + ghsaProbe.status + ' wrote=' + ghsaProbe.wrote + ' :: ' + ghsaProbe.stderr.trim().slice(0, 120),
);
const osvProbe = runImporterBlocked('import-osv.mjs', ['--packagesFile', 'does/not/exist.json'], 'osv-out');
assert(
  osvProbe.status !== 0 && osvProbe.stderr.includes('BLOCKED') && !osvProbe.wrote,
  'gates live: import-osv fails on gates before file-read/network/write',
  'status=' + osvProbe.status + ' wrote=' + osvProbe.wrote + ' :: ' + osvProbe.stderr.trim().slice(0, 120),
);
// --- 12b. determinism: generator outputs are byte-stable ---------------------------
// The manifest and dedup reporters claim deterministic output; re-running
// them must produce byte-identical stdout, guarding against timestamps,
// unsorted traversal, or map-ordering regressions.
function runToString(script, args) {
  // The manifest for the 1,299-rule tree is larger than Node's 1 MiB default
  // pipe buffer, so the buffer is raised. It is a transport limit, not an
  // assertion: the byte-identity comparison below is unchanged.
  return execFileSync('node', [join(ROOT, 'scripts', script), ...args], {
    cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
  });
}
const manifestRunA = runToString('manifest.mjs', ['--scope', 'all']);
const manifestRunB = runToString('manifest.mjs', ['--scope', 'all']);
assert(
  manifestRunA === manifestRunB && manifestRunA.length > 0,
  'determinism: manifest --scope all is byte-identical across runs',
  `lenA=${manifestRunA.length} lenB=${manifestRunB.length}`,
);
const dedupRunA = runToString('dedup-report.mjs', []);
const dedupRunB = runToString('dedup-report.mjs', []);
assert(
  dedupRunA === dedupRunB && dedupRunA.length > 0,
  'determinism: dedup-report is byte-identical across runs',
  `lenA=${dedupRunA.length} lenB=${dedupRunB.length}`,
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
// Evaluation fixtures are a second, deliberately narrower exemption surface.
// A credential-shaped line in data/eval-cases/*.json is exempt ONLY when the
// case declares synthetic:true AND testOnly:true, the line is fixture content
// (fixture.lines / observation header, body or URL) after JSON unescaping, and
// the line also carries a synthetic-shape marker (EXAMPLE / placeholder /
// repeated-character filler). Prose elsewhere in the same case (purpose,
// notes, provenance, limitations) stays strictly scanned, and unmarked fixture
// values fail closed. `null` means "not an eligible synthetic eval case".
const EVAL_CASE_PREFIX = 'data/eval-cases/';
function syntheticEvalCase(rel, text) {
  if (!rel.startsWith(EVAL_CASE_PREFIX) || !rel.endsWith('.json')) return null;
  let doc;
  try {
    doc = JSON.parse(text);
  } catch {
    return null;
  }
  if (doc?.synthetic !== true || doc?.testOnly !== true) return null;
  return doc;
}
function evalFixtureContent(doc) {
  const content = [];
  const add = (value) => {
    if (typeof value !== 'string') return;
    for (const line of value.split('\n')) {
      const trimmed = line.trim();
      if (trimmed.length >= 8) content.push(trimmed);
    }
  };
  const fixture = doc?.fixture && typeof doc.fixture === 'object' ? doc.fixture : {};
  if (Array.isArray(fixture.lines)) fixture.lines.forEach(add);
  const observation = fixture.observation && typeof fixture.observation === 'object' ? fixture.observation : null;
  if (observation) {
    add(observation.url);
    add(observation.body);
    for (const [name, value] of Object.entries(observation.headers ?? {})) {
      if (Array.isArray(value)) value.forEach((item) => add(`${name}: ${item}`));
      else add(`${name}: ${value}`);
    }
  }
  return content;
}
const normalizeScanLine = (line) => line.replace(/\\/g, '').replace(/,\s*$/, '');
function classifySecretMatch({ line, isSecretsFixture, evalDoc, evalContent }) {
  const marked = FIXTURE_SAFE_MARKERS.some((marker) => marker.test(line));
  if (isSecretsFixture) return marked ? 'fixture-marked' : 'fixture-unmarked';
  if (evalDoc) {
    const normalized = normalizeScanLine(line);
    const isFixtureContent = evalContent.some((content) => normalized.includes(content));
    if (isFixtureContent) return marked ? 'eval-fixture-marked' : 'eval-unmarked';
  }
  return 'strict';
}
const strictViolations = [];
const fixtureFailures = [];
const evalFixtureExemptions = [];
const evalFixtureFailures = [];
for (const file of collectRepoTextFiles(ROOT)) {
  const rel = file.slice(ROOT.length + 1);
  const text = readFileSync(file, 'utf8');
  const isSecretsFixture = rel === 'packs/secrets' || rel.startsWith('packs/secrets/');
  const evalDoc = syntheticEvalCase(rel, text);
  const evalContent = evalDoc ? evalFixtureContent(evalDoc) : [];
  text.split('\n').forEach((line, index) => {
    for (const pattern of SECRET_PATTERNS) {
      if (!pattern.re.test(line)) continue;
      const verdict = classifySecretMatch({ line, isSecretsFixture, evalDoc, evalContent });
      if (verdict === 'strict') {
        strictViolations.push(`${rel}:${index + 1}:${pattern.name}`);
      } else if (verdict === 'fixture-unmarked') {
        fixtureFailures.push(`${rel}:${index + 1}:${pattern.name}: ${line.trim().slice(0, 80)}`);
      } else if (verdict === 'eval-unmarked') {
        evalFixtureFailures.push(`${rel}:${index + 1}:${pattern.name}: ${line.trim().slice(0, 80)}`);
      } else if (verdict === 'eval-fixture-marked') {
        evalFixtureExemptions.push(`${rel}:${index + 1}:${pattern.name}`);
      }
    }
  });
}
assert(
  strictViolations.length === 0,
  'positive: no credential shapes outside packs/secrets fixtures and synthetic eval fixture content',
  strictViolations.slice(0, 5).join(' | '),
);
assert(
  fixtureFailures.length === 0,
  'positive: every secrets-fixture credential shape carries a safety marker',
  fixtureFailures.slice(0, 5).join(' | '),
);
assert(
  evalFixtureFailures.length === 0,
  'positive: every eval-case credential shape is marked synthetic fixture content',
  evalFixtureFailures.slice(0, 5).join(' | '),
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
// Probe the eval-case allowance itself: it must be opt-in by declaration
// (synthetic + testOnly), limited to verbatim fixture content, and absent
// everywhere else. A future fixture that inlines a live-shaped token into
// prose, or forgets the declarations, has to fail this scan.
const plantedToken = 'AK' + 'IA' + 'EXAMPLE' + '0'.repeat(9);
const unmarkedToken = 'AK' + 'IA' + 'Q7Z2M4X8C1V5B9N3';
const plantedCase = (overrides = {}) => ({
  schemaVersion: 'drobon.eval.case/v1',
  synthetic: true,
  testOnly: true,
  purpose: 'scanner probe only; contains no credential',
  notes: [`prose must never carry ${plantedToken} inline`],
  fixture: { name: 'probe.txt', lines: [`aws_access_key_id = "${plantedToken}"`] },
  ...overrides,
});
const probeVerdict = (rel, doc, line) => {
  const text = JSON.stringify(doc);
  const parsed = syntheticEvalCase(rel, text);
  return classifySecretMatch({
    line,
    isSecretsFixture: false,
    evalDoc: parsed,
    evalContent: parsed ? evalFixtureContent(parsed) : [],
  });
};
const plantedText = JSON.stringify(plantedCase(), null, 2);
const fixtureLine = plantedText.split('\n').find((line) => line.includes('aws_access_key_id'));
const proseLine = plantedText.split('\n').find((line) => line.includes('prose must never carry'));
const evalAllowanceProbes = [
  ['marked fixture content of a declared synthetic case is exempt',
    probeVerdict('data/eval-cases/PROBE-001.json', plantedCase(), fixtureLine) === 'eval-fixture-marked'],
  ['prose inside the same synthetic case stays strictly scanned',
    probeVerdict('data/eval-cases/PROBE-001.json', plantedCase(), proseLine) === 'strict'],
  ['synthetic:false is never exempt',
    probeVerdict('data/eval-cases/PROBE-002.json', plantedCase({ synthetic: false }), fixtureLine) === 'strict'],
  ['testOnly:false is never exempt',
    probeVerdict('data/eval-cases/PROBE-003.json', plantedCase({ testOnly: false }), fixtureLine) === 'strict'],
  ['a non-eval path is never exempt, even with the declarations',
    probeVerdict('docs/PROBE-004.json', plantedCase(), fixtureLine) === 'strict'],
  ['an unparseable eval-case file is never exempt',
    syntheticEvalCase('data/eval-cases/PROBE-005.json', `{"synthetic":true,"testOnly":true,`) === null],
  ['a secrets fixture line without a safety marker is still a failure',
    classifySecretMatch({ line: `key = "${unmarkedToken}"`, isSecretsFixture: true, evalDoc: null, evalContent: [] })
      === 'fixture-unmarked'],
  ['unmarked fixture content fails closed instead of being exempt', (() => {
    const doc = plantedCase({ fixture: { name: 'probe.txt', lines: [`aws_access_key_id = "${unmarkedToken}"`] } });
    const line = JSON.stringify(doc, null, 2).split('\n').find((entry) => entry.includes(unmarkedToken));
    return probeVerdict('data/eval-cases/PROBE-006.json', doc, line) === 'eval-unmarked';
  })()],
];
const evalAllowanceFailures = evalAllowanceProbes.filter(([, ok]) => !ok).map(([name]) => name);
assert(
  evalAllowanceFailures.length === 0,
  'positive: eval-case leak allowance is scoped to declared, marked synthetic fixture content',
  evalAllowanceFailures.join(' | '),
);

// --- generator fail-loud guard + quarantine invariant (Pump 3) ------------------
// The live quarantine list must stay empty. A sandboxed generator run with one cell
// that the schema rejects (languages[] "shell-posix") must exit non-zero and touch no
// file: previously generated assets are never silently removed.
const quarantineLive = readJson(join(ROOT, 'data', 'asset-cells', 'quarantine.json'));
assert(
  Array.isArray(quarantineLive.quarantined) && quarantineLive.quarantined.length === 0,
  'invariant: data/asset-cells/quarantine.json lists zero quarantined cells',
  JSON.stringify(quarantineLive.quarantined ?? null).slice(0, 200),
);
{
  const guardRoot = mkdtempSync(join(tmpdir(), 'drobon-genguard-'));
  cpSync(ROOT, guardRoot, {
    recursive: true,
    filter: (src) => !/[\\/]\.git([\\/]|$)/.test(src) && !/[\\/]node_modules([\\/]|$)/.test(src),
  });
  const countFiles = (dir) => readdirSync(dir, { withFileTypes: true }).reduce((n, e) => {
    const full = join(dir, e.name);
    return n + (e.isDirectory() ? countFiles(full) : 1);
  }, 0);
  const before = countFiles(join(guardRoot, 'packs')) + countFiles(join(guardRoot, 'knowledge'));
  const manifestBefore = readFileSync(join(guardRoot, 'data', 'asset-cells', '.manifest.json'), 'utf8');
  const cellPath = join(guardRoot, 'data', 'asset-cells', 'sast-calls-1.json');
  const cellText = readFileSync(cellPath, 'utf8');
  const key = '"shell": [';
  assert(cellText.includes(key), 'guard: sandbox cell carries the shell key to mutate');
  writeFileSync(cellPath, cellText.replace(key, '"shell-posix": ['));
  let exitCode = 0;
  let stderrText = '';
  try {
    execFileSync(process.execPath, [join(guardRoot, 'scripts', 'generate-assets.mjs')], { cwd: guardRoot, stdio: 'pipe' });
  } catch (err) {
    exitCode = typeof err.status === 'number' ? err.status : -1;
    stderrText = String(err.stderr ?? '');
  }
  const after = countFiles(join(guardRoot, 'packs')) + countFiles(join(guardRoot, 'knowledge'));
  const manifestAfter = readFileSync(join(guardRoot, 'data', 'asset-cells', '.manifest.json'), 'utf8');
  assert(
    exitCode !== 0 && stderrText.includes('quarantined'),
    'guard: generator exits non-zero when a cell is quarantined',
    `exit=${exitCode} stderr=${stderrText.slice(0, 120)}`,
  );
  assert(
    after === before && manifestAfter === manifestBefore,
    'guard: quarantined run removes or writes no assets and leaves the manifest untouched',
    `files ${before}->${after}`,
  );
  rmSync(guardRoot, { recursive: true, force: true });
}

// --- SAST duplicate review tripwires (Pump 3) -----------------------------------
// Groups = SAST rules that share an identical pattern source + flags. Same-language
// repeats are true duplicates and must stay at zero. The other two counts are review
// snapshots: a change means a new overlap appeared and must be re-classified, not
// silently accepted (see docs/PACKS.md, "SAST duplicate review").
{
  const sastDir = join(ROOT, 'packs', 'sast', 'v1', 'rules');
  const bySignature = new Map();
  for (const file of readdirSync(sastDir).filter((f) => f.endsWith('.json')).sort()) {
    const rule = JSON.parse(readFileSync(join(sastDir, file), 'utf8'));
    const key = JSON.stringify((rule.patterns ?? []).map((p) => [p.source, p.flags ?? '']));
    if (!bySignature.has(key)) bySignature.set(key, []);
    bySignature.get(key).push(rule);
  }
  const groups = [...bySignature.values()].filter((g) => g.length >= 2);
  const trueDuplicates = groups.filter((g) => new Set(g.map((r) => (r.languages ?? ['-'])[0])).size < g.length);
  const crossCwe = groups.filter((g) => new Set(g.map((r) => r.cwe)).size > 1);
  const possibleOverlap = groups.filter((g) => g.length >= 6);
  assert(
    trueDuplicates.length === 0,
    'dup-review: no SAST rule pair shares both a pattern and a language (TRUE_DUPLICATE = 0)',
    trueDuplicates.map((g) => g.map((r) => r.id).join('/')).join(' | '),
  );
  assert(
    groups.length === 34 && groups.reduce((a, g) => a + g.length, 0) === 91,
    'dup-review snapshot: 34 shared-pattern groups / 91 rules (re-classify if changed; Batch 4 Kotlin/Java language split reviewed; Phase 9 ruby backtick diverged from perl — language-native #{} interpolation; 2026-10-19 openssl dockerfile/shell pair and the AEGIS 2026-10-19 batches reviewed: no group member is a same-language duplicate, TRUE_DUPLICATE stays 0)',
    `${groups.length} groups / ${groups.reduce((a, g) => a + g.length, 0)} rules`,
  );
  assert(
    crossCwe.length === 13,
    'dup-review snapshot: 13 shared-pattern groups disagree on CWE (owner CWE review open)',
    `${crossCwe.length} groups`,
  );
  assert(
    possibleOverlap.length === 4,
    'dup-review snapshot: 4 POSSIBLE_OVERLAP groups (>=6 rules on a bare function name)',
    `${possibleOverlap.length} groups`,
  );
}

// --- four-UserType matrix tripwire (Pump 3) ------------------------------------
// docs/AUDIENCES.md §5 carries one machine-readable `matrix-counts:` line; it must
// equal the recomputed tree counts (no hand-typed numbers).
{
  const audText = readFileSync(join(ROOT, 'docs', 'AUDIENCES.md'), 'utf8');
  const line = /^matrix-counts: (.+)$/m.exec(audText);
  const jsonFiles = (dir) => readdirSync(join(ROOT, dir)).filter((f) => f.endsWith('.json'));
  const lessonFiles = jsonFiles('learning/lessons');
  const expected = {
    devLessons: lessonFiles.filter((f) => f.startsWith('lsn_dev_')).length,
    studentLessons: lessonFiles.length,
    securityTemplates: jsonFiles('assessments/templates').length,
    pentesterTemplates: jsonFiles('engagements').length,
    remediation: jsonFiles('knowledge/remediation').length,
    patterns: jsonFiles('knowledge/patterns').length,
    records: jsonFiles('knowledge/records').length,
    cwe: jsonFiles('knowledge/cwe').length,
  };
  const declared = line === null ? {} : Object.fromEntries(line[1].split(' ').map((kv) => kv.split('=')));
  const drift = Object.keys(expected).filter((k) => String(expected[k]) !== declared[k]);
  assert(line !== null, 'matrix: docs/AUDIENCES.md keeps the matrix-counts tripwire line');
  assert(
    drift.length === 0 && Object.keys(declared).length === Object.keys(expected).length,
    'matrix: AUDIENCES matrix counts equal the tree',
    drift.map((k) => `${k}: doc ${declared[k]} vs tree ${expected[k]}`).join('; '),
  );
}

// --- SAST language reachability tripwire (Pump 4) -------------------------------
// docs/PACKS.md carries the Main App catalog snapshot (id -> maturity) and one
// `reachability-counts:` line. The engine analyzes only PARTIAL, CONFIG_ANALYSIS and
// FULL families and gates a rule on rule.languages.includes(family) (no alias map).
// The counts are recomputed here from the rule files; the Main App is not read.
{
  const doc = readFileSync(join(ROOT, 'docs', 'PACKS.md'), 'utf8');
  const block = /^```app-language-catalog\n([\s\S]*?)\n```$/m.exec(doc);
  let catalog = null;
  try {
    catalog = block ? JSON.parse(block[1]) : null;
  } catch {
    catalog = null;
  }
  assert(
    catalog !== null && Object.keys(catalog).length === 53,
    'reachability: docs/PACKS.md keeps the 53-id app catalog snapshot',
  );
  const analyzed = new Set(
    Object.keys(catalog ?? {}).filter((id) => ['PARTIAL', 'CONFIG_ANALYSIS', 'FULL'].includes(catalog[id])),
  );
  const sastDir = join(ROOT, 'packs', 'sast', 'v1', 'rules');
  const sastRules = readdirSync(sastDir).filter((f) => f.endsWith('.json')).map((f) => readJson(join(sastDir, f)));
  let fully = 0;
  let partial = 0;
  let unreachable = 0;
  let noLanguages = 0;
  const ids = new Set();
  for (const rule of sastRules) {
    if (!Array.isArray(rule.languages)) {
      noLanguages++;
      continue;
    }
    rule.languages.forEach((id) => ids.add(id));
    const ok = rule.languages.filter((id) => analyzed.has(id)).length;
    if (ok === rule.languages.length) fully++;
    else if (ok > 0) partial++;
    else unreachable++;
  }
  const intersect = [...ids].filter((id) => catalog !== null && Object.hasOwn(catalog, id)).length;
  const got = { fully, partial, unreachable, noLanguages, ids: ids.size, intersect };
  const line = /^reachability-counts: (.+)$/m.exec(doc);
  const declared = line === null ? {} : Object.fromEntries(line[1].split(' ').map((kv) => kv.split('=')));
  const drift = Object.keys(got).filter((k) => String(got[k]) !== declared[k]);
  assert(line !== null, 'reachability: docs/PACKS.md keeps the reachability-counts tripwire line');
  assert(
    drift.length === 0 && Object.keys(declared).length === Object.keys(got).length,
    'reachability: PACKS.md reachability counts equal the SAST rules',
    drift.map((k) => `${k}: doc ${declared[k]} vs tree ${got[k]}`).join('; '),
  );

  // Pump 4 mapping regression: `hcl` is not a language id the engine can match; the
  // Terraform / HCL family is `terraform`. No SAST rule or pattern may carry `hcl`.
  const patDir = join(ROOT, 'knowledge', 'patterns');
  const patterns = readdirSync(patDir).filter((f) => f.endsWith('.json')).map((f) => readJson(join(patDir, f)));
  const hclRules = sastRules.filter((r) => (r.languages ?? []).includes('hcl')).map((r) => r.id);
  const hclPatterns = patterns.filter((p) => (p.targets ?? []).includes('hcl')).map((p) => p.id);
  assert(
    hclRules.length === 0 && hclPatterns.length === 0,
    'reachability: no SAST rule or pattern uses the unreachable id `hcl` (mapped to terraform)',
    `rules: ${hclRules.join(', ')}; patterns: ${hclPatterns.join(', ')}`,
  );
}

// --- summary --------------------------------------------------------------------
const total = passed + failed;
process.stdout.write(`consistency-tests: ${failed === 0 ? 'PASS' : 'FAIL'} (${passed}/${total} passed)\n`);
process.exitCode = failed === 0 ? 0 : 1;
