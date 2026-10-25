/**
 * Documentation-count drift gate (Phase 4.1.8 / Phase 8).
 *
 * Recomputes every count directly from files and fails when any
 * documentation statement drifts from the tree:
 *   - README.md data bullets
 *   - docs/CORPUS_GAP_REPORT.md status note (authoritative current counts)
 *   - docs/CAPABILITY_COVERAGE.md rule counts
 *   - docs/SCA_RULE_SCHEMA_PROPOSAL.md rule-pack total
 *   - docs/REQUIREMENTS_MATRIX.json inventory
 *   - docs/CORPUS_TARGETS.json validatedCount / verifiedProductionCount
 *   - docs/COMPLETION_MATRIX.json + docs/RELEASE_READINESS_MATRIX.json
 *     (vocabulary + cross-consistency, when present)
 *
 * Also enforces the PROVENANCE_POLICY.md §6 invariant: no category may be
 * production-verified while the repo LICENSE grant is absent.
 *
 * Read-only. Runs in `npm test`.
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const ROOT = resolve(new URL('.', import.meta.url).pathname, '..');

let passed = 0;
let failed = 0;
function assert(condition, name, detail = '') {
  if (condition) {
    passed += 1;
    process.stdout.write(`ok - ${name}\n`);
  } else {
    failed += 1;
    process.stdout.write(`NOT OK - ${name}${detail ? ` (${detail})` : ''}\n`);
  }
}

function read(rel) {
  return readFileSync(join(ROOT, rel), 'utf8');
}

function countFiles(rel, predicate) {
  const dir = join(ROOT, rel);
  if (!existsSync(dir)) return 0;
  return readdirSync(dir).filter(predicate ?? ((n) => n.endsWith('.json'))).length;
}

// --- recompute ground truth from files ---------------------------------------
const computed = {
  sast: countFiles('packs/sast/v1/rules'),
  secrets: countFiles('packs/secrets/v1/rules'),
  dast: countFiles('packs/dast/v1/rules'),
  sca: countFiles('packs/sca/v1/rules'),
  patterns: countFiles('knowledge/patterns'),
  records: countFiles('knowledge/records'),
  remediation: countFiles('knowledge/remediation'),
  cwe: countFiles('knowledge/cwe'),
  lessons: countFiles('learning/lessons'),
  assessmentTemplates: countFiles('assessments/templates'),
  engagements: countFiles('engagements'),
  advisoryFiles: countFiles('vuln-intel/npm') + countFiles('vuln-intel/pypi'),
  fixtures: countFiles('vuln-intel/npm/samples') + countFiles('vuln-intel/pypi/samples'),
};
computed.packs = computed.sast + computed.secrets + computed.dast + computed.sca;

// advisory identity items: (id, ecosystem, package) tuples
const identityTuples = new Set();
const advisoryIds = new Set();
for (const eco of ['npm', 'pypi']) {
  const dir = join(ROOT, 'vuln-intel', eco);
  if (!existsSync(dir)) continue;
  for (const name of readdirSync(dir).filter((n) => n.endsWith('.json'))) {
    const rec = JSON.parse(readFileSync(join(dir, name), 'utf8'));
    identityTuples.add(`${rec.id}|${rec.ecosystem}|${rec.package}`);
    advisoryIds.add(rec.id);
  }
}
computed.advisoryItems = identityTuples.size;
computed.advisoryIds = advisoryIds.size;

// --- 1. README.md ------------------------------------------------------------
{
  const readme = read('README.md');
  const num = (re, label) => {
    const m = re.exec(readme);
    return { found: m !== null, value: m === null ? null : Number(m[1]), label };
  };
  const rFiles = num(/(\d+) reviewed GHSA seed records/, 'ghsa files');
  assert(rFiles.found && rFiles.value === computed.advisoryFiles,
    `README: GHSA seed record files = ${computed.advisoryFiles}`, `got ${rFiles.value}`);
  const m = /(\d+) pack rules\** \((\d+) SAST \+ (\d+) secrets \+ (\d+) DAST \+ (\d+) SCA\)/.exec(readme);
  assert(m !== null
    && Number(m[1]) === computed.packs
    && Number(m[2]) === computed.sast
    && Number(m[3]) === computed.secrets
    && Number(m[4]) === computed.dast
    && Number(m[5]) === computed.sca,
    `README: pack rules = ${computed.packs} (${computed.sast}+${computed.secrets}+${computed.dast}+${computed.sca})`,
    m === null ? 'pattern missing' : m[0]);
  const rRem = num(/(\d+) remediation entries/, 'remediation');
  assert(rRem.found && rRem.value === computed.remediation,
    `README: remediation entries = ${computed.remediation}`, `got ${rRem.value}`);
  const rCwe = num(/(\d+) CWE knowledge entries/, 'cwe');
  assert(rCwe.found && rCwe.value === computed.cwe,
    `README: CWE entries = ${computed.cwe}`, `got ${rCwe.value}`);
  const m2 = /(\d+) audience starters\**: (\d+) executable lessons/.exec(readme);
  const m3 = /(\d+) assessment templates/.exec(readme);
  const m4 = /(\d+) passive-only engagement templates/.exec(readme);
  assert(m2 !== null && Number(m2[1]) === computed.lessons + computed.assessmentTemplates + computed.engagements
    && Number(m2[2]) === computed.lessons
    && m3 !== null && Number(m3[1]) === computed.assessmentTemplates
    && m4 !== null && Number(m4[1]) === computed.engagements,
    `README: audience starters = ${computed.lessons + computed.assessmentTemplates + computed.engagements}`,
    `${m2?.[0] ?? '?'} / ${m3?.[0] ?? '?'} / ${m4?.[0] ?? '?'}`);
  const m5 = /\*\*(\d+) unique GHSA advisory ids\*\* and \*\*(\d+) unique advisory-package items\*\*/.exec(readme);
  assert(m5 !== null && Number(m5[1]) === computed.advisoryIds && Number(m5[2]) === computed.advisoryItems,
    `README: counting vocabulary (ids ${computed.advisoryIds}, items ${computed.advisoryItems})`,
    m5?.[0] ?? 'pattern missing');
}

// --- 2. CORPUS_GAP_REPORT status note ---------------------------------------
{
  const gap = read('docs/CORPUS_GAP_REPORT.md');
  const checks = [
    [/SAST rules \*\*(\d+)\*\*/, computed.sast, 'gap-note: SAST'],
    [/secrets rules \*\*(\d+)\*\*/, computed.secrets, 'gap-note: secrets'],
    [/DAST rules \*\*(\d+)\*\*/, computed.dast, 'gap-note: DAST'],
    [/pack total \*\*(\d+)\*\*/, computed.packs, 'gap-note: pack total'],
    [/items (\d+)\*\* \((\d+) files \/ (\d+) unique GHSA ids/, 0, 'gap-note: advisory triple'],
    [/CWE \*\*(\d+)\*\*/, computed.cwe, 'gap-note: CWE'],
    [/remediation \*\*(\d+)\*\*/, computed.remediation, 'gap-note: remediation'],
    [/patterns \*\*(\d+)\*\*/, computed.patterns, 'gap-note: patterns'],
    [/records \*\*(\d+)\*\*/, computed.records, 'gap-note: records'],
    [/lessons \*\*(\d+)\*\*/, computed.lessons, 'gap-note: lessons'],
    [/assessment templates \*\*(\d+)\*\*/, computed.assessmentTemplates, 'gap-note: templates'],
    [/engagements \*\*(\d+)\*\*/, computed.engagements, 'gap-note: engagements'],
    [/provider vectors \*\*(\d+)\*\*/, 16, 'gap-note: vectors'],
    [/verified production \*\*(\d+)\*\*/, 0, 'gap-note: verified production'],
  ];
  for (const [re, want, label] of checks) {
    const m = re.exec(gap);
    if (label === 'gap-note: advisory triple') {
      assert(m !== null && Number(m[1]) === computed.advisoryItems
        && Number(m[2]) === computed.advisoryFiles
        && Number(m[3]) === computed.advisoryIds,
        `${label} = ${computed.advisoryItems}/${computed.advisoryFiles}/${computed.advisoryIds}`,
        m?.[0] ?? 'pattern missing');
    } else {
      assert(m !== null && Number(m[1]) === want, `${label} = ${want}`, m?.[0] ?? 'pattern missing');
    }
  }
}

// --- 3. CAPABILITY_COVERAGE + SCA proposal ----------------------------------
{
  const cap = read('docs/CAPABILITY_COVERAGE.md');
  const m1 = /(\d+) Dataset rules \(`DPK-SEC-\*`/.exec(cap);
  assert(m1 !== null && Number(m1[1]) === computed.secrets,
    `capability-coverage: secrets rules = ${computed.secrets}`, m1?.[0] ?? 'pattern missing');
  const m2 = /(\d+) Dataset rules over 7 closed check types/.exec(cap);
  assert(m2 !== null && Number(m2[1]) === computed.dast,
    `capability-coverage: dast rules = ${computed.dast}`, m2?.[0] ?? 'pattern missing');
  const m3 = /(\d+) Dataset rules \(`DPK-SAST-\*`\)/.exec(cap);
  assert(m3 !== null && Number(m3[1]) === computed.sast,
    `capability-coverage: sast rules = ${computed.sast}`, m3?.[0] ?? 'pattern missing');
  const sca = read('docs/SCA_RULE_SCHEMA_PROPOSAL.md');
  const m4 = /sca-pack: implemented = (\d+) rules/.exec(sca);
  assert(m4 !== null && Number(m4[1]) === computed.sca,
    `sca-schema: implemented rules = ${computed.sca}`, m4?.[0] ?? 'pattern missing');
}

// --- 4. REQUIREMENTS_MATRIX inventory ---------------------------------------
{
  const matrix = JSON.parse(read('docs/REQUIREMENTS_MATRIX.json'));
  const inv = matrix.inventory;
  const expect = {
    vulnIntelReal: computed.advisoryFiles,
    vulnIntelFixtures: computed.fixtures,
    vulnIntelNpmReal: countFiles('vuln-intel/npm'),
    vulnIntelPypiReal: countFiles('vuln-intel/pypi'),
    packsSast: computed.sast,
    packsSecrets: computed.secrets,
    packsDast: computed.dast,
    remediation: computed.remediation,
    cwe: computed.cwe,
    patterns: computed.patterns,
    records: computed.records,
    lessons: computed.lessons,
    assessmentTemplates: computed.assessmentTemplates,
    engagements: computed.engagements,
    vectors: 16,
  };
  for (const [key, want] of Object.entries(expect)) {
    assert(inv[key] === want, `matrix inventory ${key} = ${want}`, `got ${inv[key]}`);
  }
}

// --- 5. CORPUS_TARGETS validatedCounts + license invariant -------------------
{
  const targets = JSON.parse(read('docs/CORPUS_TARGETS.json'));
  const byId = Object.fromEntries(targets.categories.map((c) => [c.id, c]));
  const want = {
    'advisory-record': computed.advisoryItems,
    'sast-rule': computed.sast,
    'secrets-rule': computed.secrets,
    'dast-check': computed.dast,
    'cwe-entry': computed.cwe,
    'remediation-entry': computed.remediation,
    lesson: computed.lessons,
    'assessment-template': computed.assessmentTemplates,
    'engagement-aid': computed.engagements,
    'provider-vector': 16,
  };
  for (const [id, count] of Object.entries(want)) {
    assert(byId[id] !== undefined && byId[id].validatedCount === count,
      `corpus-targets ${id} validatedCount = ${count}`, `got ${byId[id]?.validatedCount}`);
    assert(byId[id] !== undefined && byId[id].verifiedProductionCount === 0,
      `corpus-targets ${id} verifiedProductionCount = 0 (no LICENSE grant)`, `got ${byId[id]?.verifiedProductionCount}`);
  }
  const hasLicense = ['LICENSE', 'LICENSE.md', 'COPYING', 'COPYING.md']
    .some((name) => existsSync(join(ROOT, name)));
  assert(!hasLicense, 'license invariant: no LICENSE file yet (matches LICENSE_DECISION_RECORD)');
}

// --- 6. COMPLETION_MATRIX + RELEASE_READINESS_MATRIX cross-consistency ------
{
  for (const file of ['docs/COMPLETION_MATRIX.json', 'docs/RELEASE_READINESS_MATRIX.json']) {
    assert(existsSync(join(ROOT, file)), `${file} exists`);
    if (!existsSync(join(ROOT, file))) continue;
    const doc = JSON.parse(read(file));
    const vocab = ['PASS', 'FAIL', 'BLOCKED', 'NOT_IMPLEMENTED', 'NOT_ASSESSED', 'NOT_APPLICABLE',
      'BLOCKED_OWNER_DECISION', 'BLOCKED_PRODUCTION_LOCK'];
    const statuses = [];
    const walk = (node) => {
      if (Array.isArray(node)) node.forEach(walk);
      else if (node && typeof node === 'object') {
        if (typeof node.status === 'string') statuses.push(node.status);
        Object.values(node).forEach(walk);
      }
    };
    walk(doc);
    assert(statuses.length > 0 && statuses.every((s) => vocab.includes(s)),
      `${file}: all statuses use the controlled vocabulary`, statuses.filter((s) => !vocab.includes(s)).join(','));
    assert(typeof doc.derivedFrom === 'object' && doc.derivedFrom !== null,
      `${file}: derivedFrom references existing registers`);
  }
  if (existsSync(join(ROOT, 'docs/RELEASE_READINESS_MATRIX.json'))) {
    const rel = JSON.parse(read('docs/RELEASE_READINESS_MATRIX.json'));
    const gates = Array.isArray(rel.gates) ? rel.gates : [];
    assert(gates.length >= 17, `release-readiness matrix has >= 17 gates (got ${gates.length})`);
    assert(gates.every((g) => typeof g.id === 'string' && typeof g.verificationCommand === 'string'
      && typeof g.status === 'string' && Array.isArray(g.evidence) && typeof g.lastVerified === 'string'),
      'release-readiness gates carry id/command/status/evidence/lastVerified');
    const licenseGate = gates.find((g) => g.id === 'G6');
    assert(licenseGate !== undefined && licenseGate.status === 'BLOCKED_OWNER_DECISION',
      'G6 licensing gate is BLOCKED_OWNER_DECISION while no grant exists', licenseGate?.status);
    const prodGate = gates.find((g) => g.id === 'G8');
    assert(prodGate !== undefined && prodGate.status === 'BLOCKED_PRODUCTION_LOCK',
      'G8 production-data gate is BLOCKED_PRODUCTION_LOCK', prodGate?.status);
  }
  if (existsSync(join(ROOT, 'docs/COMPLETION_MATRIX.json'))) {
    const comp = JSON.parse(read('docs/COMPLETION_MATRIX.json'));
    const items = Array.isArray(comp.items) ? comp.items : [];
    assert(items.length > 0 && items.every((it) => typeof it.id === 'string' && typeof it.domain === 'string'
      && typeof it.status === 'string' && typeof it.evidence === 'string'),
      `completion matrix items well-formed (got ${items.length})`);
    const notAssessed = items.filter((it) => it.status === 'NOT_ASSESSED');
    assert(notAssessed.every((it) => typeof it.limitation === 'string' && it.limitation.length > 0),
      'every NOT_ASSESSED item states its limitation');
  }
}

// --- 7. COVERAGE_MAP recomputed from rule files (stale-map gate) ------------
{
  const map = JSON.parse(read('docs/COVERAGE_MAP.json'));
  const rulesOf = (family) => readdirSync(join(ROOT, 'packs', family, 'v1', 'rules'))
    .filter((f) => f.endsWith('.json'))
    .map((f) => JSON.parse(readFileSync(join(ROOT, 'packs', family, 'v1', 'rules', f), 'utf8')));
  const sastRules = rulesOf('sast');
  const secretRules = rulesOf('secrets');
  const dastRules = rulesOf('dast');
  const catTally = (rules) => Object.fromEntries([...rules.reduce((m, r) => m.set(r.category, (m.get(r.category) ?? 0) + 1), new Map())].sort((a, b) => (a[0] < b[0] ? -1 : 1)));
  assert(map.domains.sast.rules === sastRules.length,
    `coverage-map: sast rules ${map.domains.sast.rules} match recomputed ${sastRules.length}`);
  assert(map.domains.sast.patterns === sastRules.reduce((n, r) => n + r.patterns.length, 0),
    'coverage-map: sast pattern total matches recomputed sum');
  assert(JSON.stringify(map.domains.sast.categories) === JSON.stringify(catTally(sastRules)),
    'coverage-map: sast category tally matches recomputed');
  assert(map.domains.sast.languageTagCount === new Set(sastRules.flatMap((r) => r.languages ?? [])).size,
    'coverage-map: sast language-tag count matches recomputed');
  assert(map.domains.sast.universalRulesOmittingLanguages === sastRules.filter((r) => !('languages' in r)).length,
    'coverage-map: universal-rule count matches recomputed');
  assert(map.domains.secrets.rules === secretRules.length,
    `coverage-map: secrets rules ${map.domains.secrets.rules} match recomputed ${secretRules.length}`);
  assert(JSON.stringify(map.domains.secrets.categories) === JSON.stringify(catTally(secretRules)),
    'coverage-map: secrets category tally matches recomputed');
  assert(map.domains.dast.rules === dastRules.length,
    `coverage-map: dast rules ${map.domains.dast.rules} match recomputed ${dastRules.length}`);
  assert(JSON.stringify(map.domains.dast.categories) === JSON.stringify(catTally(dastRules)),
    'coverage-map: dast category tally matches recomputed');
  const checkTally = Object.fromEntries([...dastRules.reduce((m, r) => m.set(r.check.type, (m.get(r.check.type) ?? 0) + 1), new Map())].sort((a, b) => (a[0] < b[0] ? -1 : 1)));
  assert(JSON.stringify(map.domains.dast.checkTypes) === JSON.stringify(checkTally),
    'coverage-map: dast check-type tally matches recomputed');
  // SCA seed tally recomputed exactly like test-consistency counts the corpus.
  const npmFiles = readdirSync(join(ROOT, 'vuln-intel', 'npm')).filter((f) => f.endsWith('.json'));
  const pypiFiles = readdirSync(join(ROOT, 'vuln-intel', 'pypi')).filter((f) => f.endsWith('.json'));
  const items = new Set();
  const ids = new Set();
  for (const [dir, files] of [['npm', npmFiles], ['pypi', pypiFiles]]) {
    for (const f of files) {
      const raw = JSON.parse(readFileSync(join(ROOT, 'vuln-intel', dir, f), 'utf8'));
      for (const record of Array.isArray(raw) ? raw : [raw]) {
        items.add(`${record.source}\u0000${record.id}\u0000${record.ecosystem}\u0000${record.package}`);
        ids.add(record.id);
      }
    }
  }
  assert(map.domains.sca.advisorySeedFiles === npmFiles.length + pypiFiles.length,
    `coverage-map: seed files ${map.domains.sca.advisorySeedFiles} match recomputed ${npmFiles.length + pypiFiles.length}`);
  assert(map.domains.sca.advisorySeedItems === items.size,
    `coverage-map: seed identity items ${map.domains.sca.advisorySeedItems} match recomputed ${items.size}`);
  assert(map.domains.advisory.advisories === ids.size,
    `coverage-map: unique advisory ids ${map.domains.advisory.advisories} match recomputed ${ids.size}`);
  // A resolved expansion moves to resolvedExpansions instead of vanishing: the
  // documented total may not shrink, so a shrinking blocked list has to be paid
  // for by a resolved entry, not by deletion.
  const resolvedCount = Array.isArray(map.resolvedExpansions) ? map.resolvedExpansions.length : 0;
  assert(Array.isArray(map.blockedExpansions) && map.blockedExpansions.length + resolvedCount >= 5
    && map.blockedExpansions.every((e) => typeof e.status === 'string' && typeof e.nextLegitimateStep === 'string' && e.nextLegitimateStep.length > 0),
    'coverage-map: every blocked expansion carries status + next legitimate step',
    `${map.blockedExpansions?.length ?? 0} blocked + ${resolvedCount} resolved`);
  assert(map.resolvedExpansions.every((e) => /^\d{4}-\d{2}-\d{2}$/.test(String(e.resolvedAt))
    && typeof e.resolution === 'string' && e.resolution.length > 40),
    'coverage-map: every resolved expansion records a date + a substantive resolution');
  assert(map.blockedExpansions.every((e) => e.status.startsWith('BLOCKED_') || e.status.endsWith('_BY_DESIGN') || e.status === 'UNREACHABLE_VOCAB'),
    'coverage-map: blocked-expansion statuses use honest vocabulary', '');
  assert(Array.isArray(map.verifiedGaps) && map.verifiedGaps.length >= 3,
    'coverage-map: verified gaps documented with next legitimate steps');
}

// --- 8. DROBON_COVERAGE_EVIDENCE.json counts recomputed (audit staleness gate)
if (existsSync(join(ROOT, 'DROBON_COVERAGE_EVIDENCE.json'))) {
  const ev = JSON.parse(read('DROBON_COVERAGE_EVIDENCE.json'));
  assert(ev.schemaVersion === 'drobon.coverage.evidence/v1', 'coverage-evidence: schemaVersion pinned');
  const reqs = Array.isArray(ev.requirements) ? ev.requirements : [];
  assert(reqs.length >= 50, `coverage-evidence: requirement ledger present (got ${reqs.length})`);
  const ids = reqs.map((r) => r.id);
  assert(new Set(ids).size === ids.length, 'coverage-evidence: requirement ids unique');
  const vocab = ['VERIFIED_FULL', 'VERIFIED_PARTIAL', 'IMPLEMENTED_NOT_VERIFIED', 'MISSING_DATASET',
    'MISSING_ENGINE_OR_INTEGRATION', 'NOT_IMPLEMENTED', 'BLOCKED_OWNER_DECISION', 'BLOCKED_LICENSE',
    'BLOCKED_PRODUCTION_LOCK', 'BLOCKED_EXTERNAL_DEPENDENCY', 'NOT_ASSESSED', 'NOT_APPLICABLE_WITH_JUSTIFICATION'];
  assert(reqs.every((r) => vocab.includes(r.status)),
    'coverage-evidence: status vocabulary respected', '');
  // every dataset-item count claim must match the tree
  const countFiles = (dir, re) => existsSync(join(ROOT, dir))
    ? readdirSync(join(ROOT, dir)).filter((f) => re.test(f)).length : 0;
  const claims = [
    ['sast rules', countFiles('packs/sast/v1/rules', /^DPK-.*\.json$/), 1000],
    ['secrets rules', countFiles('packs/secrets/v1/rules', /^DPK-.*\.json$/), 97],
    // Audit claims re-pinned 2026-10-21: DAST 306 -> 325 -> 367 -> 398 -> 500, knowledge trees
    // 1353 -> 1372 -> 1445 -> 1557 after app-surface batches 3, 4, 5 and 6. The pin is the *claim being audited*, so it moves only
    // when the tree moves and the ledger is updated in the same commit.
    ['dast rules', countFiles('packs/dast/v1/rules', /^DPK-.*\.json$/), 1007],
    ['sca rules', countFiles('packs/sca/v1/rules', /^DPK-.*\.json$/), 42],
    ['patterns', countFiles('knowledge/patterns', /^DPK-PAT-.*\.json$/), 2146],
    ['records', countFiles('knowledge/records', /^DPK-REC-.*\.json$/), 2146],
    ['remediation', countFiles('knowledge/remediation', /^DPK-.*\.json$/), 2146],
    ['cwe', countFiles('knowledge/cwe', /\.json$/), 100],
    ['lessons', countFiles('learning/lessons', /\.json$/), 6],
    ['templates', countFiles('assessments/templates', /\.json$/), 3],
    ['engagements', countFiles('engagements', /\.json$/), 2],
    ['advisory files', countFiles('vuln-intel/npm', /^GHSA-.*\.json$/) + countFiles('vuln-intel/pypi', /^GHSA-.*\.json$/), 100],
  ];
  for (const [label, actual, expected] of claims) {
    assert(actual === expected, `coverage-evidence recount: ${label} ${actual} == audit claim ${expected}`, '');
  }
  assert(ev.summary && typeof ev.summary.pct?.mainAppToDataset?.[0] === 'number',
    'coverage-evidence: percentages carry numerator/denominator triplets');
}

// --- 9. Phase 4 pins: capability matrix, agent architecture, any-file convention ----
{
  const cap = read('docs/CAPABILITY_COVERAGE.md');
  const mRem = /(\d+) remediation files/.exec(cap);
  assert(mRem !== null && Number(mRem[1]) === computed.remediation,
    `capability-coverage: remediation files = ${computed.remediation}`, mRem?.[0] ?? 'pattern missing');
  const mLsn = /(\d+) lessons \(/.exec(cap);
  assert(mLsn !== null && Number(mLsn[1]) === computed.lessons,
    `capability-coverage: lessons = ${computed.lessons}`, mLsn?.[0] ?? 'pattern missing');

  assert(existsSync(join(ROOT, 'docs', 'CAPABILITY_GAP_MATRIX.md')), 'capability-gap-matrix document exists');
  const cgm = read('docs/CAPABILITY_GAP_MATRIX.md');
  for (const status of ['VERIFIED', 'PARTIAL', 'NOT_IMPLEMENTED', 'NOT_VERIFIED', 'BLOCKED', 'NOT_APPLICABLE_WITH_REASON']) {
    assert(cgm.includes(status), `capability-gap-matrix uses status ${status}`);
  }
  assert((cgm.match(/CGM-[A-I]\d+/g) ?? []).length >= 40,
    'capability-gap-matrix carries >= 40 capability ids', String((cgm.match(/CGM-[A-I]\d+/g) ?? []).length));

  assert(existsSync(join(ROOT, 'docs', 'AGENT_ARCHITECTURE.md')), 'agent-architecture document exists');
  const ag = read('docs/AGENT_ARCHITECTURE.md');
  assert(ag.includes('no agent/model runtime is configured'),
    'agent-architecture states the no-runtime honesty line');
  assert(ag.includes('checkToolPermission') && ag.includes('checkBudget'),
    'agent-architecture documents the deterministic policy core');
  const pkg = JSON.parse(read('package.json'));
  assert(typeof pkg.scripts?.test === 'string' && pkg.scripts.test.includes('test-agent-policy'),
    'package.json test chain runs the agent-policy suite');

  // any-file convention (Phase 4): no SAST rule may carry the `universal` language id
  const sastDir = join(ROOT, 'packs', 'sast', 'v1', 'rules');
  const tagged = readdirSync(sastDir).filter((f) => f.endsWith('.json'))
    .map((f) => JSON.parse(readFileSync(join(sastDir, f), 'utf8')))
    .filter((r) => (r.languages ?? []).includes('universal')).map((r) => r.id);
  assert(tagged.length === 0, 'any-file convention: zero SAST rules carry the `universal` language id', tagged.join(','));
}

process.stdout.write(`\ndoc-drift: ${passed} passed, ${failed} failed\n`);
if (failed > 0) process.exitCode = 1;

const invokedAsScript =
  process.argv[1] !== undefined &&
  pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (invokedAsScript && failed > 0) {
  process.stderr.write('doc-drift: FAIL — documentation counts drifted from the tree\n');
}
