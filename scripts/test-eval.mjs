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
  assert(before.cases.length >= 22, `corpus: at least 22 cases present (got ${before.cases.length})`);
const runOnce = execFileSync(process.execPath, [join(ROOT, 'scripts', 'run-eval.mjs')], { cwd: ROOT, encoding: 'utf8' });
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
assert(
    report.counts.truePositives === 12 && report.counts.falseNegatives === 0 && report.counts.falsePositives === 1,
    'metrics: population counts pinned (12 TP / 0 FN / 1 documented FP — Phase 7 population)',
  JSON.stringify(report.counts),
);

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
  const runTwice = execFileSync(process.execPath, [join(ROOT, 'scripts', 'run-eval.mjs')], { cwd: ROOT, encoding: 'utf8' });
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

process.stdout.write(`\neval-tests: ${passed} passed, ${failed} failed\n`);
process.exit(failed === 0 ? 0 : 1);
