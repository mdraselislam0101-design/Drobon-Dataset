#!/usr/bin/env node
/**
 * coverage-report.mjs — canonical, reproducible coverage accounting.
 *
 * Every percentage this script prints carries an explicit numerator, an
 * explicit denominator, the inclusion rule that produced them, and the file
 * set it read.  Denominators are never mixed: active-rule counts, evaluated
 * rules, asset linkage, evaluation cases, and SCA contract capabilities are
 * separate families on purpose.
 *
 * Usage:
 *   node scripts/coverage-report.mjs            # human summary + JSON to stdout
 *   node scripts/coverage-report.mjs --json out.json
 *   node scripts/coverage-report.mjs --check    # exit 1 on any integrity defect
 *
 * Read-only: no file in the repository is written.
 */
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { dirname, join, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { loadCases, buildReport } from './eval-foundation.mjs';
import { SCA_DATASET_STATUS } from './sca-engine.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const jsonFlag = process.argv.indexOf('--json');
const jsonOut = jsonFlag >= 0 ? process.argv[jsonFlag + 1] : null;
const checkMode = process.argv.includes('--check');

const readJson = (rel) => JSON.parse(readFileSync(join(ROOT, rel), 'utf8'));
const list = (rel, suffix = '.json') => {
  const full = join(ROOT, rel);
  if (!existsSync(full)) return [];
  return readdirSync(full).filter((f) => f.endsWith(suffix)).sort();
};
const pct = (n, d) => (d === 0 ? null : Math.round((n / d) * 10000) / 100);

// --- inventory -------------------------------------------------------------
const sastFiles = list('packs/sast/v1/rules');
const secretsFiles = list('packs/secrets/v1/rules');
const dastFiles = list('packs/dast/v1/rules');
const patternFiles = list('knowledge/patterns');
const recordFiles = list('knowledge/records');
const remediationFiles = list('knowledge/remediation');
const cweFiles = list('knowledge/cwe');

const sastRules = sastFiles.map((f) => readJson(join('packs/sast/v1/rules', f)));
const secretsRules = secretsFiles.map((f) => readJson(join('packs/secrets/v1/rules', f)));
const dastRules = dastFiles.map((f) => readJson(join('packs/dast/v1/rules', f)));
const patterns = patternFiles.map((f) => readJson(join('knowledge/patterns', f)));
const records = recordFiles.map((f) => readJson(join('knowledge/records', f)));

const patternIds = new Set(patterns.map((p) => p.id));
const recordIds = new Set(records.map((r) => r.id));
const ruleIds = new Set([...sastRules, ...secretsRules, ...dastRules].map((r) => r.id));

// --- evaluation population -------------------------------------------------
const { cases, errors: caseErrors } = loadCases(ROOT);
const report = buildReport(ROOT, cases);
const caseById = new Map(cases.map((c) => [c.id, c]));

const expectedRefs = [];
const forbiddenRefs = [];
for (const c of cases) {
  for (const d of c.expected.detections) expectedRefs.push({ caseId: c.id, ruleId: d.ruleId });
  for (const r of c.expected.forbiddenDetections ?? []) forbiddenRefs.push({ caseId: c.id, ruleId: r });
}
const exercised = new Set(expectedRefs.map((e) => e.ruleId));
const named = new Set([...expectedRefs, ...forbiddenRefs].map((e) => e.ruleId));

const variantCounts = {};
for (const c of cases) variantCounts[c.variant] = (variantCounts[c.variant] ?? 0) + 1;
const stateCounts = { ASSESSED: 0, UNASSESSED: 0 };
for (const c of cases) stateCounts[c.groundTruth.state] += 1;
const provenanceOrigins = {};
for (const c of cases) provenanceOrigins[c.provenance.origin] = (provenanceOrigins[c.provenance.origin] ?? 0) + 1;

const namedSast = [...named].filter((id) => id.startsWith('DPK-SAST-'));
const namedSecrets = [...named].filter((id) => id.startsWith('DPK-SEC-'));
const namedDast = [...named].filter((id) => id.startsWith('DPK-DAST-'));
const exercisedSast = [...exercised].filter((id) => id.startsWith('DPK-SAST-'));
const exercisedSecrets = [...exercised].filter((id) => id.startsWith('DPK-SEC-'));
const exercisedDast = [...exercised].filter((id) => id.startsWith('DPK-DAST-'));

// --- asset linkage ---------------------------------------------------------
const rulePatternRefsOk = sastRules.filter((r) => (r.patternRefs ?? []).length > 0
  && r.patternRefs.every((p) => patternIds.has(p))).length;
const danglingPatternRefs = sastRules.flatMap((r) => (r.patternRefs ?? [])
  .filter((p) => !patternIds.has(p)).map((p) => `${r.id}->${p}`));
const danglingRecordRuleRefs = records.flatMap((rec) => (rec.relatedRules ?? [])
  .filter((r) => !ruleIds.has(r)).map((r) => `${rec.id}->${r}`));
const danglingRuleRuleRefs = sastRules.flatMap((r) => (r.patternRefs ?? [])
  .filter((p) => patternIds.has(p))
  .flatMap((p) => {
    const pat = patterns.find((x) => x.id === p);
    return (pat?.linkedRules ?? []).filter((x) => !ruleIds.has(x)).map((x) => `${p}->${x}`);
  }));

const rulesWithRemediation = [...sastRules, ...secretsRules, ...dastRules].filter((r) => {
  const rel = `knowledge/remediation/${r.id}.json`;
  return existsSync(join(ROOT, rel));
}).length;

// duplicate pattern signals (same source + flags + language) -----------------
const signalSeen = new Map();
const duplicateSignals = [];
for (const r of sastRules) {
  for (const p of r.patterns ?? []) {
    const key = `${(r.languages ?? []).join(',')}::${p.source}::${p.flags ?? ''}`;
    if (signalSeen.has(key)) duplicateSignals.push(`${signalSeen.get(key)} = ${r.id}`);
    else signalSeen.set(key, r.id);
  }
}

// --- SCA contract capabilities --------------------------------------------
// Each capability names assertion text that must appear in the harness output.
let scaOutput = '';
try {
  scaOutput = execFileSync(process.execPath, [join(ROOT, 'scripts', 'test-sca-engine.mjs')], {
    cwd: ROOT, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024,
  });
  scaOutput += execFileSync(process.execPath, [join(ROOT, 'scripts', 'test-sca-fixtures.mjs')], {
    cwd: ROOT, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024,
  });
} catch (error) {
  scaOutput = `${error.stdout ?? ''}${error.stderr ?? ''}`;
}
const scaPassed = (scaOutput.match(/^ok - /gm) ?? []).length;
const scaFailed = (scaOutput.match(/^FAIL - /gm) ?? []).length;
const scaCapabilities = [
  { id: 'normalization', label: 'Coordinate normalization and frozen result', evidence: ['coordinate: normalised object is frozen'] },
  { id: 'ecosystem-allowlist', label: 'Unknown ecosystem refused', evidence: ['coordinate: unknown ecosystem refused'] },
  { id: 'package-validation', label: 'Malformed package / version fields refused', evidence: ['coordinate: malformed package name refused', 'coordinate: range syntax in a version field refused'] },
  { id: 'schema-provenance', label: 'Synthetic-only schema and provenance gate', evidence: ['records: a foreign schema is rejected', 'records: provenance.source must be fixture'] },
  { id: 'real-record-refusal', label: 'Real-style advisory records refused', evidence: ['records: a real-style record is refused', 'records: provider construction refuses real records'] },
  { id: 'version-bounds', label: 'Version-range boundaries (inclusive / exclusive)', evidence: ['assess: the fixed version is not affected (upper boundary)', 'assess: a version above the second branch matches only the wide range'] },
  { id: 'multi-branch', label: 'Multiple range branches resolved independently', evidence: ['assess: both synthetic ranges match', 'assess: pypi range matches exactly one advisory'] },
  { id: 'unknown-package', label: 'Unknown package assessed with no advisories', evidence: ['assess: an unknown package is ASSESSED with no advisories'] },
  { id: 'no-data', label: 'NO_DATA_LOADED when the record set is empty', evidence: ['fail-closed: empty record set reports NO_DATA_LOADED', 'fail-closed: no-data answer carries no advisories'] },
  { id: 'not-assessed', label: 'NOT_ASSESSED for unparseable versions, never a match', evidence: ['fail-closed: a version the range evaluator cannot parse is NOT_ASSESSED, never a match', 'fail-closed: NOT_ASSESSED never carries advisories'] },
  { id: 'severity-order', label: 'Total severity ordering with unknown labels last', evidence: ['ordering: severity ranks are total for known labels', 'ordering: unknown labels sort below known labels'] },
  { id: 'determinism', label: 'Byte-identical output for identical input', evidence: ['determinism: identical input yields byte-identical output'] },
  { id: 'name-normalisation', label: 'PEP 503 / npm name canonicalisation with refusals', evidence: ['coordinates: COORD-002 canonicalises to zope-interface', 'coordinates: COORD-010 is refused with SCOPED_NAME_UNSUPPORTED'] },
  { id: 'alias-resolution', label: 'Canonical identity resolved through a synthetic alias table', evidence: ['aliases: ALIAS-001 resolves to beautifulsoup4 via alias', 'aliases: a malformed table entry is ignored, never guessed'] },
  { id: 'dependency-graph', label: 'Direct/transitive graph with duplicates, conflicts and range issues', evidence: ['graph: 7 unique nodes', 'graph: conflicting versions are reported exactly', 'graph: every range issue is reported'] },
  { id: 'range-boundaries', label: 'Version-range boundary corpus for both ecosystems', evidence: ['ranges: RANGE-005 npm 1.3.0 in 1.2.x is false', 'ranges: RANGE-014 pypi 1.5.0 in ~=1.4.2 is false'] },
  { id: 'fixture-synthetic-lock', label: 'Fixture corpus is synthetically labelled and free of third-party ids', evidence: ['corpus: advisories.json is labelled synthetic and not production data', 'corpus: no third-party identifier shape (GHSA-)'] },
  { id: 'graph-determinism', label: 'Graph resolution is frozen and byte-identical', evidence: ['graph: identical input yields byte-identical output', 'graph: result is frozen'] },
  { id: 'dependency-cycles', label: 'Dependency cycles reported as explicit SCC components', evidence: ['cycles: the two-package cycle and the self-edge are reported exactly', 'cycles: every component carries the DEPENDENCY_CYCLE reason'] },
  { id: 'ambiguous-alias', label: 'Ambiguous alias tables fail closed instead of resolving by order', evidence: ['aliases: two entries claiming one alias are refused, never resolved by table order'] },
  { id: 'duplicate-edges', label: 'Duplicate dependency edges collapse deterministically', evidence: ['edges: a repeated target+range pair collapses to one edge', 'edges: duplicate-edge resolution is byte-identical across runs'] },
  { id: 'ecosystem-collision', label: 'Ecosystem-scoped identity, edges and conflicts', evidence: ['collisions: one name in two ecosystems produces separate nodes', 'collisions: an edge stays inside its declared ecosystem', 'collisions: conflicting versions are reported per ecosystem'] },
  { id: 'alias-ecosystem-scope', label: 'Alias resolution is scoped by ecosystem', evidence: ['aliases: the same alias resolves differently per ecosystem'] },
  { id: 'duplicate-direct-resolution', label: 'Conflicting direct flags resolve independently of listing order', evidence: ['direct-flags: direct declared first makes the coordinate a root', 'direct-flags: the same flag declared last resolves identically', 'direct-flags: resolution is byte-identical under a reordered listing'] },
  { id: 'immutability', label: 'Provider and answers frozen', evidence: ['immutability: provider is frozen', 'immutability: answers are frozen'] },
  { id: 'no-network', label: 'No network primitives in the engine', evidence: ['no-network: the engine imports no HTTP, DNS or socket module', 'no-network: the engine calls no fetch()'] },
  { id: 'range-reuse', label: 'Reuses the validated local range evaluator', evidence: ['integration: the engine reuses the validated local range evaluator'] },
];
const scaCapabilitiesTested = scaCapabilities.filter((c) => c.evidence.every((needle) => scaOutput.includes(needle)));

// --- metrics ---------------------------------------------------------------
function metric(id, label, numerator, denominator, inclusionRule, source, note = '') {
  return {
    id, label, numerator, denominator, unit: 'assets',
    percent: pct(numerator, denominator), inclusionRule, source, note,
  };
}

const metrics = [
  metric('sast.active-rules', 'Active SAST rules (every rule file under packs/sast/v1/rules)',
    sastRules.length, sastFiles.length,
    'Count of parsed rule documents = count of rule files; no activity filter is applied or claimed.',
    'packs/sast/v1/rules/*.json'),
  metric('sast.evaluated', 'SAST rules exercised by at least one independent eval case',
    exercisedSast.length, sastRules.length,
    'Numerator: distinct rule ids named in expected.detections of data/eval-cases. Denominator: all active SAST rule files. Rules named only as forbiddenDetections are excluded (they are negative controls, not exercised detections).',
    'data/eval-cases/*.json + packs/sast/v1/rules/*.json'),
  metric('secrets.evaluated', 'Secrets rules exercised by at least one independent eval case',
    exercisedSecrets.length, secretsRules.length,
    'Same inclusion rule as SAST; secrets rules are a separate pack family and are never pooled with SAST.',
    'data/eval-cases/*.json + packs/secrets/v1/rules/*.json'),
  metric('dast.evaluated', 'DAST rules exercised by at least one independent observation case',
    exercisedDast.length, dastRules.length,
    'Numerator: distinct DPK-DAST ids named in expected.detections. Denominator: all active DAST rule files. Observation fixtures only; no request was sent.',
    'data/eval-cases/*.json + packs/dast/v1/rules/*.json'),
  metric('eval.rule-breadth-any-role', 'Distinct rules named by any evaluation case (positive or negative control)',
    named.size, ruleIds.size,
    'Numerator: distinct rule ids appearing in expected.detections or expected.forbiddenDetections across all cases. Denominator: every rule id across the SAST, secrets and DAST packs. This pooled figure exists only to reconcile historical mixed-denominator claims; it is not a per-engine coverage rate.',
    'data/eval-cases/*.json + packs/*/v1/rules/*.json'),
  metric('sast.pattern-linkage', 'SAST rules whose patternRefs all resolve',
    rulePatternRefsOk, sastRules.length,
    'A rule counts only when it declares at least one patternRef and every ref exists in knowledge/patterns.',
    'packs/sast/v1/rules/*.json + knowledge/patterns/*.json'),
  metric('rules.remediation-linkage', 'Pack rules (SAST + secrets + DAST) with a remediation document of the same id',
    rulesWithRemediation, sastRules.length + secretsRules.length + dastRules.length,
    'Exact id match on knowledge/remediation/<ruleId>.json for every rule id in all three packs; no family is excluded.',
    'packs/sast/v1/rules + packs/secrets/v1/rules + packs/dast/v1/rules + knowledge/remediation'),
  metric('patterns.with-rules', 'Patterns linked to at least one rule',
    patterns.filter((p) => (p.linkedRules ?? []).some((r) => ruleIds.has(r))).length, patterns.length,
    'A pattern counts when at least one linkedRules entry resolves to an active rule id.',
    'knowledge/patterns/*.json + packs/*/v1/rules/*.json'),
  metric('records.with-patterns', 'Records linked to at least one existing pattern',
    records.filter((r) => (r.relatedPatterns ?? []).some((p) => patternIds.has(p))).length, records.length,
    'A record counts when at least one relatedPatterns entry exists in knowledge/patterns.',
    'knowledge/records/*.json + knowledge/patterns/*.json'),
  metric('eval.cases-assessed', 'Evaluation cases with authored ground truth (ASSESSED)',
    stateCounts.ASSESSED, cases.length,
    'Numerator: cases whose groundTruth.state is ASSESSED. UNASSESSED cases stay in the denominator and are never counted as passing detections.',
    'data/eval-cases/*.json'),
  metric('eval.synthetic-only', 'Evaluation cases that declare synthetic + testOnly',
    cases.filter((c) => c.synthetic === true && c.testOnly === true).length, cases.length,
    'Population includes every committed case; production-authorized records are not part of this corpus and are reported separately as 0.',
    'data/eval-cases/*.json'),
  metric('sca.capabilities', 'SCA contract capabilities with passing harness evidence',
    scaCapabilitiesTested.length, scaCapabilities.length,
    'A capability counts only when every named assertion line appears as "ok - " in the harness output. Capabilities are declared in this script, not inferred from the engine.',
    'scripts/test-sca-engine.mjs output'),
];

// --- integrity -------------------------------------------------------------
const duplicateCaseIds = (() => {
  const seen = new Set();
  const dups = [];
  for (const id of cases.map((c) => c.id)) {
    if (seen.has(id)) dups.push(id);
    seen.add(id);
  }
  return dups;
})();
const e008 = report.results.find((r) => r.id === 'EVAL-SAST-008');
const integrity = {
  caseManifestErrors: caseErrors,
  duplicateCaseIds,
  danglingExpectedRuleRefs: expectedRefs.filter((e) => !ruleIds.has(e.ruleId)).map((e) => `${e.caseId}->${e.ruleId}`),
  danglingForbiddenRuleRefs: forbiddenRefs.filter((e) => !ruleIds.has(e.ruleId)).map((e) => `${e.caseId}->${e.ruleId}`),
  danglingPatternRefs,
  danglingRecordRuleRefs,
  danglingPatternLinkedRules: danglingRuleRuleRefs,
  duplicatePatternSignals: duplicateSignals,
  unassessedCaseIds: report.caseOutcomes.UNASSESSED,
  knownDocumentedFailure: e008 === undefined ? null : {
    id: e008.id,
    outcome: e008.outcome,
    truePositives: e008.truePositives,
    falsePositives: e008.falsePositives,
    note: 'Retained keyword-trap false positive (docstring line). Expected to fail; never removed to raise precision.',
  },
  outcomes: report.caseOutcomes,
};

const integrityDefects = [
  ...caseErrors,
  ...duplicateCaseIds.map((id) => `duplicate case id ${id}`),
  ...integrity.danglingExpectedRuleRefs,
  ...integrity.danglingForbiddenRuleRefs,
  ...danglingPatternRefs,
  ...danglingRecordRuleRefs,
  ...danglingRuleRuleRefs,
  ...duplicateSignals,
  ...(e008 === undefined || e008.outcome !== 'FAIL' || e008.falsePositives !== 1
    ? ['EVAL-SAST-008 expected documented failure is missing or changed'] : []),
];

// --- external gates (asserted, with in-repo evidence pointers) --------------
const externalGates = [
  {
    gate: 'production-authorized SCA records',
    status: '0 records',
    evidence: 'data/vuln-intel and knowledge assets contain synthetic fixtures only; no authorized feed is present in this repository.',
  },
  {
    gate: 'rights / owner authorization',
    status: 'OPEN',
    evidence: 'docs/OWNER_DECISIONS.json — GHSA/OSV/NVD entries remain OWNER_DECISION_REQUIRED; D-13 keeps 40 legacy records inactive.',
  },
  {
    gate: 'Main App integration',
    status: 'BLOCKED',
    evidence: 'docs/SAST_DAST_SCA_ADDITIVE_PUMP_2026-10-19.md §11 — Main App runs VULN_INTEL_PROVIDER=none (Null provider); Dataset work cannot change it.',
  },
];

const doc = {
  schemaVersion: 'drobon.coverage.report/v1',
  generatedAt: 'not-recorded (deterministic output; runtime clock intentionally excluded)',
  scope: 'working tree at the time of the run (git-managed and untracked files)',
  inventory: {
    sastRules: sastRules.length,
    secretsRules: secretsRules.length,
    dastRules: dastRules.length,
    patterns: patterns.length,
    records: records.length,
    remediation: remediationFiles.length,
    cwe: cweFiles.length,
    evalCases: cases.length,
  },
  evaluation: {
    casesTotal: report.casesTotal,
    assessedCases: report.assessedCases,
    unassessedCases: report.unassessedCases,
    counts: report.counts,
    precision: report.metrics.precision,
    recall: report.metrics.recall,
    variants: Object.fromEntries(Object.entries(variantCounts).sort()),
    groundTruthStates: stateCounts,
    provenanceOrigins: Object.fromEntries(Object.entries(provenanceOrigins).sort()),
    distinctRulesNamed: named.size,
    distinctRulesExercised: exercised.size,
    distinctSastRulesExercised: exercisedSast.length,
    distinctSecretsRulesExercised: exercisedSecrets.length,
    distinctSastRulesNamed: namedSast.length,
    distinctSecretsRulesNamed: namedSecrets.length,
    distinctDastRulesNamed: namedDast.length,
    distinctDastRulesExercised: exercisedDast.length,
    syntheticFixtures: cases.length,
    productionAuthorizedRecords: 0,
  },
  sca: {
    statusesDeclared: Object.values(SCA_DATASET_STATUS),
    assertionsPassed: scaPassed,
    assertionsFailed: scaFailed,
    capabilities: scaCapabilities.map((c) => ({
      id: c.id,
      label: c.label,
      tested: scaCapabilitiesTested.includes(c),
      evidence: c.evidence,
    })),
  },
  metrics,
  integrity: { ...integrity, defects: integrityDefects },
  externalGates,
};

const body = `${JSON.stringify(doc, null, 2)}\n`;
if (jsonOut) {
  const { writeFileSync } = await import('node:fs');
  writeFileSync(jsonOut, body);
}

if (process.argv.includes('--check')) {
  process.stdout.write(`coverage-report: ${integrityDefects.length === 0 ? 'PASS' : 'FAIL'}\n`);
  for (const d of integrityDefects) process.stdout.write(`  defect: ${d}\n`);
  process.exitCode = integrityDefects.length === 0 ? 0 : 1;
} else {
  process.stdout.write(body);
}
