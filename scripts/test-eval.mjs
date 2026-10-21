/**
 * test-eval.mjs — Phase 6 regression suite for the synthetic evaluation
 * foundation (scripts/eval-foundation.mjs + scripts/run-eval.mjs).
 *
 * Proves, with deterministic assertions:
 *   - malformed manifests / duplicate ids / missing expected outcomes /
 *     unsupported schemas / incomplete evidence are rejected with actionable
 *     errors naming the offending case;
 *   - the runner NEVER rewrites expected outcomes (file hashes pinned);
 *   - UNASSESSED ground truth is never counted as a successful detection;
 *   - a detection requires exact source evidence (rule + line + matched text),
 *     not mere keyword presence;
 *   - report output is deterministic (two runs byte-identical);
 *   - metrics cover only the assessed synthetic population and carry the
 *     non-extrapolation disclaimer.
 *
 * No network, no model, no agent runtime.
 */
import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  EVAL_CASE_SCHEMA,
  buildReport,
  evaluateCase,
  loadCases,
  sha256,
  validateCase,
} from './eval-foundation.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

let passed = 0;
let failed = 0;
function assert(condition, name, detail = '') {
  if (condition) {
    passed += 1;
    process.stdout.write(`ok - ${name}\n`);
  } else {
    failed += 1;
    process.stdout.write(`FAIL - ${name}\n`);
    if (detail) process.stdout.write(`    ${detail}\n`);
  }
}

// --- 1. committed corpus loads clean and the runner never rewrites it --------
const before = loadCases(ROOT);
assert(before.errors.length === 0, 'corpus: all committed cases load clean', before.errors.join(' | '));
  assert(before.cases.length >= 261, `corpus: at least 261 cases present (got ${before.cases.length})`);
// The report exceeds Node's 1 MiB default pipe buffer (244 cases already did;
// the corpus is now 1,588), so both full-run reads raise the buffer. The buffer
// is a transport limit, not an assertion: no expectation is relaxed here.
const runOnce = execFileSync(process.execPath, [join(ROOT, 'scripts', 'run-eval.mjs')], {
  cwd: ROOT,
  encoding: 'utf8',
  maxBuffer: 64 * 1024 * 1024,
});
const after = loadCases(ROOT);
assert(
  JSON.stringify(before.hashes) === JSON.stringify(after.hashes),
  'invariant: runner never rewrites case files (sha256 unchanged)',
  'hash drift detected',
);

// --- 2. report shape + honest scoring ---------------------------------------
const report = JSON.parse(runOnce);
assert(report.schemaVersion === 'drobon.eval.report/v1', 'report: schema version pinned');
assert(report.disclaimer.includes('not real-world effectiveness'), 'report: metrics disclaimer present');
assert(report.assessedCases + report.unassessedCases === report.casesTotal, 'report: assessed + unassessed = total');
const sast8 = report.results.find((r) => r.id === 'EVAL-SAST-008');
assert(
  sast8 !== undefined && sast8.outcome === 'FAIL' && sast8.falsePositives === 1 && sast8.truePositives === 1 && sast8.falseNegatives === 0,
  'honesty: keyword-trap case reports its documented docstring false positive (evidence-line precision)',
  JSON.stringify(sast8?.notes),
);
const unassessed = report.results.filter((r) => r.groundTruthState === 'UNASSESSED');
assert(
  unassessed.length >= 2 && unassessed.every((r) => r.outcome === 'UNASSESSED' && r.truePositives === 0),
  'invariant: UNASSESSED cases are never counted as successful detections',
  JSON.stringify(unassessed.map((r) => r.id)),
);
assert(
  report.metrics.scope.includes('assessed synthetic cases') && report.caseOutcomes.UNASSESSED.includes('EVAL-SAST-004'),
  'metrics: computed over assessed synthetic population only',
);
// Workstream B pin (DAST cumulative gap-closure pump, 2026-10-19): the UNASSESSED
// population is a fixed, documented set. Each member is ambiguous by design
// (commented-out code, unknown-callee dataflow, truncated snippets, a
// version-like token). Pinning the ids means a case can never silently drop out
// of the population, nor be quietly re-labelled ASSESSED to improve a metric.
const PINNED_UNASSESSED = [
  'EVAL-CMD-023', 'EVAL-CMD-024', 'EVAL-CMD-025',
  'EVAL-SAST-004', 'EVAL-SAST-007', 'EVAL-SAST-014', 'EVAL-SAST-015', 'EVAL-SAST-016',
  'EVAL-SEC-111', 'EVAL-SQL-027', 'EVAL-SQL-028',
].sort();
const unassessedIds = unassessed.map((r) => r.id).sort();
assert(
  JSON.stringify(unassessedIds) === JSON.stringify(PINNED_UNASSESSED),
  `invariant: the UNASSESSED population is exactly the ${PINNED_UNASSESSED.length} pinned cases`,
  JSON.stringify(unassessedIds),
);
assert(
  unassessed.every((r) => r.falsePositives === 0 && r.falseNegatives === 0 && r.actual.length === 0),
  'invariant: UNASSESSED cases contribute no TP, FP, FN and execute no detector',
  JSON.stringify(unassessed.filter((r) => r.falsePositives !== 0 || r.falseNegatives !== 0 || r.actual.length !== 0).map((r) => r.id)),
);
// Re-pinned 2026-10-21 (1336 -> 1353 -> 1365 -> 1379, +14 app-surface-2 positives) after the defensive DAST batch added 17
// independent positive cases and 2 ordinary-response controls; recomputed value
// comes from `node scripts/run-eval.mjs`, never from an edited expectation.
assert(
    report.counts.truePositives === 1379 && report.counts.falseNegatives === 0 && report.counts.falsePositives === 1,
    'metrics: population counts pinned (1379 TP / 0 FN / 1 documented FP — additive SAST/DAST breadth totals)',
  JSON.stringify(report.counts),
);

// Breadth ratchet: the independent evaluation layer must keep widening, never
// silently shrink. 169 = distinct rules exercised by positive expectations after the
// 2026-10-19 1000x batch and the ultimate-pump batch 4 (187 referenced once
// negative controls are counted).
{
  const exercised = new Set();
  for (const r of report.results) for (const e of r.expected) exercised.add(e.ruleId);
  assert(exercised.size >= 250, `breadth: >=250 distinct rules exercised by independent eval (got ${exercised.size})`);
  const withCases = new Set(report.results.flatMap((r) => r.expected.map((e) => e.ruleId)));
  const missing = [...withCases].filter((id) => !report.results.some((r) => r.expected.some((e) => e.ruleId === id)));
  assert(missing.length === 0, 'breadth: every named rule is exercised by at least one case');
}

// --- 3. evidence-grounded detection versus keyword match ---------------------
{
  const cases = loadCases(ROOT).cases;
  const base = cases.find((c) => c.id === 'EVAL-SAST-001');
  // Move the expected detection to the wrong line (keyword `cursor.execute`
  // does not even appear on line 3 in this fixture) — must be an FN.
  const wrongLine = JSON.parse(JSON.stringify(base));
  wrongLine.expected.detections = [{ ruleId: 'DPK-SAST-283', lineNo: 3, mustContain: '.execute(' }];
  const res = evaluateCase(ROOT, wrongLine);
  assert(
    res.falseNegatives === 1 && res.truePositives === 0,
    'evidence: detection at the wrong source line is a false negative (not a keyword match)',
    JSON.stringify(res.notes),
  );
  // Expecting the keyword without the exact matched text is also not evidence.
  const wrongText = JSON.parse(JSON.stringify(base));
  wrongText.expected.detections = [{ ruleId: 'DPK-SAST-283', lineNo: 2, mustContain: 'nonexistent-sink(' }];
  const res2 = evaluateCase(ROOT, wrongText);
  assert(
    res2.falseNegatives === 1 && res2.truePositives === 0,
    'evidence: matched text must contain the declared evidence substring',
    JSON.stringify(res2.notes),
  );
}

// --- 4. manifest regressions (malformed / duplicate / missing / unsupported) --
const VALID = {
  schemaVersion: EVAL_CASE_SCHEMA,
  id: 'EVAL-SAST-900',
  variant: 'positive',
  synthetic: true,
  testOnly: true,
  purpose: 'Validator self-check case used only inside the regression suite.',
  language: 'python',
  framework: null,
  mode: 'line-regex',
  groundTruth: { state: 'ASSESSED', class: 'issue-present', rationale: 'Self-check fixture with a declared sink shape.' },
  fixture: { name: 'synthetic.txt', lines: ['cursor.execute("SELECT " + col)'] },
  expected: { detections: [{ ruleId: 'DPK-SAST-283', lineNo: 1, mustContain: '.execute(' }] },
  limitations: ['Internal validator regression fixture.'],
  testCommand: 'node scripts/run-eval.mjs --case EVAL-SAST-900',
  provenance: { origin: 'original-authored', writtenFor: 'test-eval self-check', kind: 'synthetic test fixture', expectationAuthoredBeforeFirstRun: true },
};

function expectError(mutate, needle, name) {
  const copy = JSON.parse(JSON.stringify(VALID));
  mutate(copy);
  const errors = validateCase(copy);
  assert(errors.some((e) => e.includes(needle)), name, errors.join(' | '));
}
assert(validateCase(JSON.parse(JSON.stringify(VALID))).length === 0, 'negative-control: unmutated self-check case validates');
expectError((c) => { c.schemaVersion = 'drobon.eval.case/v99'; }, 'unsupported schema', 'regression: unsupported schema rejected');
expectError((c) => { c.expected = undefined; }, 'expected: required object', 'regression: missing expected outcomes rejected');
expectError((c) => { c.expected = { detections: [] }; }, 'must declare >=1 expected detection', 'regression: issue-present without detections rejected');
expectError((c) => { delete c.expected.detections[0].lineNo; }, 'lineNo: required', 'regression: incomplete evidence (no lineNo) rejected');
expectError((c) => { c.expected.detections[0].mustContain = 'ab'; }, 'mustContain: required evidence text', 'regression: truncated evidence text rejected');
expectError((c) => { c.synthetic = false; }, 'synthetic: must be true', 'regression: non-synthetic case rejected');
expectError((c) => { c.groundTruth = { state: 'ASSESSED', class: 'maybe', rationale: 'x'.repeat(11) }; }, 'groundTruth.class', 'regression: unknown ground-truth class rejected');
expectError((c) => { c.id = 'EVAL-1'; }, 'id: must match', 'regression: malformed case id rejected');

// Duplicate-id + malformed-JSON through loadCases on a tmp copy of the corpus.
{
  const scratch = mkdtempSync(join(tmpdir(), 'drobon-eval-load-'));
  try {
    mkdirSync(join(scratch, 'data'), { recursive: true });
    cpSync(join(ROOT, 'data', 'eval-cases'), join(scratch, 'data', 'eval-cases'), { recursive: true });
    const files = readdirSync(join(scratch, 'data', 'eval-cases')).filter((f) => f.endsWith('.json')).sort();
    // duplicate id: copy the first case under a new filename
    const dupSrc = readFileSync(join(scratch, 'data', 'eval-cases', files[0]), 'utf8');
    writeFileSync(join(scratch, 'data', 'eval-cases', 'zz-duplicate.json'), dupSrc);
    const dup = loadCases(scratch);
    assert(
      dup.errors.some((e) => e.includes('duplicate case id')),
      'regression: duplicate case ids rejected (naming the id)',
      dup.errors.join(' | '),
    );
    rmSync(join(scratch, 'data', 'eval-cases', 'zz-duplicate.json'));
    // malformed JSON
    writeFileSync(join(scratch, 'data', 'eval-cases', 'zz-broken.json'), '{not json');
    const broken = loadCases(scratch);
    assert(
      broken.errors.some((e) => e.includes('malformed JSON')),
      'regression: malformed JSON rejected (naming the file)',
      broken.errors.join(' | '),
    );
    rmSync(join(scratch, 'data', 'eval-cases', 'zz-broken.json'));
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

// --- 5. determinism: two full runs are byte-identical -------------------------
{
  const runTwice = execFileSync(process.execPath, [join(ROOT, 'scripts', 'run-eval.mjs')], {
    cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
  });
  assert(runOnce === runTwice, 'determinism: two runner executions are byte-identical');
  const inProcess = `${JSON.stringify(buildReport(ROOT, loadCases(ROOT).cases), null, 1)}\n`;
  assert(sha256(runOnce) === sha256(inProcess), 'determinism: in-process report matches runner output byte-identically');
}

// --- 6. Phase 7 Work A/G audit regressions (added BEFORE the fixes) -----------
{
  // D1: provenance must be REQUIRED and validated (origin/authoring fields).
  const noProv = JSON.parse(JSON.stringify(VALID));
  delete noProv.provenance;
  assert(
    validateCase(noProv).some((e) => e.includes('provenance')),
    'defect D1 regression: case without provenance is rejected',
    'provenance was optional in Phase 6 schema',
  );
  const badProv = JSON.parse(JSON.stringify(VALID));
  badProv.provenance = { origin: 'copied-from-somewhere' };
  assert(
    validateCase(badProv).some((e) => e.includes('provenance')),
    'defect D1 regression: incomplete provenance is rejected',
    validateCase(badProv).join(' | '),
  );
  const lateProv = JSON.parse(JSON.stringify(VALID));
  lateProv.provenance = { ...VALID.provenance, expectationAuthoredBeforeFirstRun: false };
  assert(
    validateCase(lateProv).some((e) => e.includes('expectationAuthoredBeforeFirstRun')),
    'defect D1 regression: expectations must be authored before first run (flag true)',
    validateCase(lateProv).join(' | '),
  );
  // D2: observation evidence must check the FULL mustContain (no 32-char truncation).
  {
    const obs = JSON.parse(JSON.stringify(loadCases(ROOT).cases.find((c) => c.id === 'EVAL-DAST-001')));
    obs.expected.detections[0].mustContain = 'http://shop.internal.test/checkout-and-more-suffix';
    // Full string is NOT in the observation; a truncated check would wrongly accept.
    const res = evaluateCase(ROOT, obs);
    assert(res.truePositives === 0, 'defect D2 regression: truncated evidence strings are not accepted',
      JSON.stringify(res));
  }
  // D3: expectedCwe must match the linked rule's declared CWE.
  {
    const scratchCwe = JSON.parse(JSON.stringify(VALID));
    scratchCwe.expected.expectedCwe = 'CWE-999';
    const scratch = mkdtempSync(join(tmpdir(), 'drobon-eval-cwe-'));
    try {
      mkdirSync(join(scratch, 'data'), { recursive: true });
      cpSync(join(ROOT, 'data', 'eval-cases'), join(scratch, 'data', 'eval-cases'), { recursive: true });
      writeFileSync(join(scratch, 'data', 'eval-cases', 'zz-bad-cwe.json'), JSON.stringify(scratchCwe));
      const res = loadCases(scratch, ROOT);
      assert(
        res.errors.some((e) => e.includes('CWE') && e.includes('DPK-SAST-283')),
        'defect D3 regression: expectedCwe disagreeing with rule.cwe is rejected (naming rule)',
        res.errors.join(' | ') || '(no error raised)',
      );
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  }
}

// --- 7. Phase 8 Work C/D: population separation + per-rule breakdown ----------
{
  const report = JSON.parse(runOnce);
  assert(report.metricsByCohort !== undefined && typeof report.metricsByCohort === 'object',
    'populations: report separates metrics by cohort (never one mixed score)');
  assert(report.metricsByCohort?.core !== undefined && report.metricsByCohort?.core?.assessedCases === 18,
    'populations: cohort "core" is the Phase 6/7 population (18 assessed) — never mixed',
    JSON.stringify(report.metricsByCohort));
  assert(
    report.metricsByCohort?.['sql-concat-xlang']?.counts.truePositives === 16
    && report.metricsByCohort?.['sql-concat-xlang']?.counts.falsePositives === 0,
    'populations: sql-concat-xlang cohort scored separately (16 TP / 0 FP)',
    JSON.stringify(report.metricsByCohort?.['sql-concat-xlang']));
  assert(
    report.metricsByCohort?.['cmd-injection']?.counts.truePositives === 13
    && report.metricsByCohort?.['cmd-injection']?.counts.falsePositives === 0,
    'populations: cmd-injection cohort scored separately (13 TP / 0 FP)',
    JSON.stringify(report.metricsByCohort?.['cmd-injection']));
  assert(
    report.metricsByCohort?.['secret-userinfo']?.counts.truePositives === 5
    && report.metricsByCohort?.['secret-userinfo']?.counts.falsePositives === 0,
    'populations: secret-userinfo cohort scored separately (5 TP / 0 FP)',
    JSON.stringify(report.metricsByCohort?.['secret-userinfo']));
  assert(report.byRule !== undefined && report.byLanguage !== undefined,
    'breakdown: per-rule and per-language results present');
  // Cohort labels: invalid cohort names rejected at load time.
  const badCohort = JSON.parse(JSON.stringify(VALID));
  badCohort.cohort = 'Bad Cohort!';
  assert(validateCase(badCohort).some((e) => e.includes('cohort')),
    'regression: malformed cohort label rejected', validateCase(badCohort).join(' | '));
  // DEFECT: no-issue cases with zero declared detectors never exercise the
  // detector — the FP trap is vacuous. ASSESSED cases must name >=1 detector.
  const vacuous = JSON.parse(JSON.stringify(VALID));
  vacuous.groundTruth = { state: 'ASSESSED', class: 'no-issue', rationale: 'Parameterized binding keeps SQL structure separate from data.' };
  vacuous.expected = { detections: [] };
  assert(
    validateCase(vacuous).some((e) => e.includes('detector')),
    'defect D4 regression: ASSESSED case without any named detector is rejected (vacuous FP trap)',
    validateCase(vacuous).join(' | ') || '(no error raised)',
  );
  // And committed no-issue cases must actually run their detector via
  // forbiddenDetections (or equivalent) — not pass by running nothing.
  {
    const committed = loadCases(ROOT).cases.filter(
      (c) => c.groundTruth.state === 'ASSESSED' && c.groundTruth.class === 'no-issue',
    );
    const vacuousLive = committed.filter((c) => (c.expected.detections.length + (c.expected.forbiddenDetections?.length ?? 0)) === 0);
    assert(
      vacuousLive.length === 0,
      'defect D4 regression: every committed no-issue case names its detector',
      vacuousLive.map((c) => c.id).join(', ') || '',
    );
  }
}

process.stdout.write(`\neval-tests: ${passed} passed, ${failed} failed\n`);
process.exit(failed === 0 ? 0 : 1);
