/**
 * eval-foundation.mjs — deterministic synthetic evaluation foundation (Phase 6).
 *
 * Implements the evaluation half of the W3 workflow (docs/AGENT_ARCHITECTURE.md
 * §3): evaluation cases declare ground truth and expected evidence BEFORE any
 * detector runs; this module loads, validates, and executes those cases against
 * the Dataset's own rule patterns and reports honest TP/FP/FN accounting.
 *
 * Hard invariants (regression-tested in scripts/test-eval.mjs):
 *   - Case files are read-only inputs. The runner never rewrites expected
 *     outcomes to match actual results (loadCases hashes are checked by tests).
 *   - Ground truth is authored in the case file (`groundTruth.state` =
 *     ASSESSED|UNASSESSED). UNASSESSED cases are never counted as successful
 *     detections and are excluded from precision/recall.
 *   - A detection counts only with EXACT evidence: rule id + fixture line
 *     number + declared `mustContain` text inside the actual matched text.
 *     A keyword hit on another line is not a detection (requirement 6).
 *   - All cases must be flagged `synthetic` + `testOnly`; they are never
 *     vulnerability intelligence and never enter corpus counts.
 *   - Output is deterministic (stable sort, fixed key order) and
 *     machine-readable (`drobon.eval.report/v1` JSON).
 *
 * No network, no model, no agent runtime: this module evaluates the
 * deterministic line/observation detectors that exist in packs/ today.
 */
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { evalDastCheck } from './validate-packs.mjs';

export const EVAL_CASE_SCHEMA = 'drobon.eval.case/v1';
export const EVAL_REPORT_SCHEMA = 'drobon.eval.report/v1';
export const EVAL_CASE_DIR = 'data/eval-cases';

/** Ground-truth states. Anything else is a schema error. */
export const GROUND_TRUTH_STATES = Object.freeze(['ASSESSED', 'UNASSESSED']);
/** Case variants (labels only; the runner does not interpret them). */
export const VARIANTS = Object.freeze(['positive', 'negative', 'boundary', 'near-miss', 'mutation']);
/** Analysis modes supported in this phase. */
export const MODES = Object.freeze(['line-regex', 'observation']);

/** sha256 helper used to prove the runner does not mutate case files. */
export function sha256(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

function fail(errors, path, message) {
  errors.push(`${path}: ${message}`);
}

/**
 * Validate one case object. Returns an array of actionable error strings
 * (empty = valid). Every failure names the offending case field.
 */
export function validateCase(value, idHint = '<case>') {
  const errors = [];
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return [`${idHint}: case must be an object`];
  }
  const id = typeof value.id === 'string' ? value.id : idHint;
  const allowed = [
    'schemaVersion', 'id', 'variant', 'synthetic', 'testOnly', 'purpose',
    'language', 'framework', 'mode', 'groundTruth', 'fixture', 'expected',
    'limitations', 'testCommand', 'provenance',
  ];
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) fail(errors, id, `unknown property "${key}"`);
  }
  if (value.schemaVersion !== EVAL_CASE_SCHEMA) {
    fail(errors, id, `schemaVersion: unsupported schema (want "${EVAL_CASE_SCHEMA}", got ${JSON.stringify(value.schemaVersion)})`);
  }
  if (typeof value.id !== 'string' || !/^EVAL-[A-Z]+-[0-9]{3}$/.test(value.id)) {
    fail(errors, id, 'id: must match ^EVAL-[A-Z]+-[0-9]{3}$');
  }
  if (!VARIANTS.includes(value.variant)) {
    fail(errors, id, `variant: must be one of ${VARIANTS.join('|')}`);
  }
  if (value.synthetic !== true) fail(errors, id, 'synthetic: must be true (cases are test-only, never real intelligence)');
  if (value.testOnly !== true) fail(errors, id, 'testOnly: must be true (cases are test-only, never real intelligence)');
  if (typeof value.purpose !== 'string' || value.purpose.length < 10 || value.purpose.length > 400) {
    fail(errors, id, 'purpose: 10..400 chars');
  }
  if (typeof value.language !== 'string' || value.language.length === 0) {
    fail(errors, id, 'language: required string');
  }
  if (!MODES.includes(value.mode)) {
    fail(errors, id, `mode: must be one of ${MODES.join('|')}`);
  }
  const gt = value.groundTruth;
  if (typeof gt !== 'object' || gt === null) {
    fail(errors, id, 'groundTruth: required object (authored before execution)');
  } else {
    if (!GROUND_TRUTH_STATES.includes(gt.state)) {
      fail(errors, id, `groundTruth.state: must be one of ${GROUND_TRUTH_STATES.join('|')}`);
    }
    if (gt.state === 'ASSESSED' && !['issue-present', 'no-issue'].includes(gt.class)) {
      fail(errors, id, 'groundTruth.class: ASSESSED cases need class "issue-present" or "no-issue"');
    }
    if (gt.state === 'UNASSESSED' && gt.class !== 'ambiguous') {
      fail(errors, id, 'groundTruth.class: UNASSESSED cases must use class "ambiguous"');
    }
    if (typeof gt.rationale !== 'string' || gt.rationale.length < 10) {
      fail(errors, id, 'groundTruth.rationale: required (>=10 chars) — ground truth must be justified');
    }
  }
  const fixture = value.fixture;
  if (typeof fixture !== 'object' || fixture === null) {
    fail(errors, id, 'fixture: required object');
  } else {
    if (typeof fixture.name !== 'string' || fixture.name.length === 0) {
      fail(errors, id, 'fixture.name: required string');
    }
    if (value.mode === 'observation') {
      if (typeof fixture.observation !== 'object' || fixture.observation === null || Array.isArray(fixture.observation)) {
        fail(errors, id, 'fixture.observation: required object for observation mode');
      }
      if (fixture.lines !== undefined && (!Array.isArray(fixture.lines) || fixture.lines.some((l) => typeof l !== 'string'))) {
        fail(errors, id, 'fixture.lines: must be an array of strings when present');
      }
    } else if (!Array.isArray(fixture.lines) || fixture.lines.length === 0 || fixture.lines.some((l) => typeof l !== 'string')) {
      fail(errors, id, 'fixture.lines: non-empty array of strings (line-regex mode)');
    }
  }
  const expected = value.expected;
  if (typeof expected !== 'object' || expected === null) {
    fail(errors, id, 'expected: required object (declared before execution)');
    return errors;
  }
  const detections = expected.detections;
  if (!Array.isArray(detections)) {
    fail(errors, id, 'expected.detections: required array (use [] for no-issue cases)');
  } else {
    detections.forEach((d, i) => {
      if (typeof d !== 'object' || d === null) {
        fail(errors, id, `expected.detections[${i}]: must be an object`);
        return;
      }
      if (typeof d.ruleId !== 'string' || d.ruleId.length === 0) {
        fail(errors, id, `expected.detections[${i}].ruleId: required`);
      }
      if (!Number.isInteger(d.lineNo) || d.lineNo < 1) {
        fail(errors, id, `expected.detections[${i}].lineNo: required positive integer (exact source evidence)`);
      }
      if (typeof d.mustContain !== 'string' || d.mustContain.length < 4) {
        fail(errors, id, `expected.detections[${i}].mustContain: required evidence text (>=4 chars)`);
      }
      if (value.mode !== 'observation' && Array.isArray(fixture?.lines) && Number.isInteger(d.lineNo) && d.lineNo > fixture.lines.length) {
        fail(errors, id, `expected.detections[${i}].lineNo: beyond fixture line count`);
      }
    });
  }
  if (expected.forbiddenDetections !== undefined
    && (!Array.isArray(expected.forbiddenDetections) || expected.forbiddenDetections.some((r) => typeof r !== 'string'))) {
    fail(errors, id, 'expected.forbiddenDetections: must be an array of rule ids');
  }
  if (expected.expectedCwe !== undefined && !/^CWE-[1-9][0-9]{0,5}$/.test(String(expected.expectedCwe))) {
    fail(errors, id, 'expected.expectedCwe: must match ^CWE-[1-9][0-9]{0,5}$');
  }
  if (gt?.state === 'ASSESSED' && gt.class === 'issue-present' && Array.isArray(detections) && detections.length === 0) {
    fail(errors, id, 'expected.detections: ASSESSED issue-present cases must declare >=1 expected detection');
  }
  if (gt?.state === 'ASSESSED' && gt.class === 'no-issue' && Array.isArray(detections) && detections.length > 0) {
    fail(errors, id, 'expected.detections: ASSESSED no-issue cases must declare zero expected detections');
  }
  if (!Array.isArray(value.limitations) || value.limitations.some((l) => typeof l !== 'string')) {
    fail(errors, id, 'limitations: required array of strings (known limits + uncertainty notes)');
  }
  if (typeof value.testCommand !== 'string' || !value.testCommand.includes(value.id)) {
    fail(errors, id, 'testCommand: required reproducible command naming the case id');
  }
  return errors;
}

/**
 * Load and validate every case under `root/data/eval-cases`. Duplicate ids,
 * malformed JSON and schema violations are hard errors naming the file.
 * Returns { cases, errors, hashes } — hashes map filename -> sha256 of the
 * raw bytes so tests can prove the runner never rewrote expectations.
 */
export function loadCases(root) {
  const dir = join(root, EVAL_CASE_DIR);
  const files = readdirSync(dir).filter((f) => f.endsWith('.json')).sort();
  const cases = [];
  const errors = [];
  const hashes = {};
  const seen = new Map();
  for (const file of files) {
    const raw = readFileSync(join(dir, file), 'utf8');
    hashes[file] = sha256(raw);
    let value;
    try {
      value = JSON.parse(raw);
    } catch (err) {
      errors.push(`${file}: malformed JSON (${err.message})`);
      continue;
    }
    const caseErrors = validateCase(value, file);
    errors.push(...caseErrors);
    if (caseErrors.length > 0) continue;
    if (seen.has(value.id)) {
      errors.push(`${file}: duplicate case id ${value.id} (also in ${seen.get(value.id)})`);
      continue;
    }
    seen.set(value.id, file);
    cases.push(value);
  }
  cases.sort((a, b) => (a.id < b.id ? -1 : 1));
  return { cases, errors, hashes };
}

/**
 * Collect the detectors a case exercises: every rule id named in
 * expected.detections plus expected.forbiddenDetections. Rules are loaded from
 * packs/ (the dataset's own detectors — never external logic).
 */
function loadRule(root, ruleId) {
  const kind = ruleId.includes('-SAST-') ? 'sast' : ruleId.includes('-SEC-') ? 'secrets' : ruleId.includes('-DAST-') ? 'dast' : null;
  if (kind === null) return null;
  try {
    return JSON.parse(readFileSync(join(root, 'packs', kind, 'v1', 'rules', `${ruleId}.json`), 'utf8'));
  } catch {
    return null;
  }
}

/**
 * Execute one validated case. Pure w.r.t. case data (read-only).
 *
 * Classification (ASSESSED cases only):
 *   - TP: an expected detection found with exact ruleId + lineNo and
 *     `mustContain` present in the actual matched text (evidence-grounded).
 *   - FN: an expected detection not found (or found without exact evidence).
 *   - FP: the detector matched a fixture line where ground truth declares no
 *     issue (any match for no-issue cases; unexpected lines for issue-present
 *     cases; any match of a forbiddenDetections rule).
 * UNASSESSED cases return outcome 'UNASSESSED' and contribute nothing.
 */
export function evaluateCase(root, testCase) {
  const gt = testCase.groundTruth;
  const result = {
    id: testCase.id,
    variant: testCase.variant,
    mode: testCase.mode,
    groundTruthState: gt.state,
    groundTruthClass: gt.class,
    outcome: 'UNASSESSED',
    truePositives: 0,
    falseNegatives: 0,
    falsePositives: 0,
    expected: testCase.expected.detections.map((d) => ({ ruleId: d.ruleId, lineNo: d.lineNo, mustContain: d.mustContain })),
    actual: [],
    notes: [],
  };
  const ruleIds = [
    ...testCase.expected.detections.map((d) => d.ruleId),
    ...(testCase.expected.forbiddenDetections ?? []),
  ];
  const uniqueRuleIds = [...new Set(ruleIds)].sort();

  if (testCase.mode === 'observation') {
    // Observation mode: each expected detection names a rule whose `check` is
    // evaluated against the fixture's declared observation object.
    for (const ruleId of uniqueRuleIds) {
      const rule = loadRule(root, ruleId);
      if (rule === null || rule.check === undefined) {
        result.notes.push(`detector ${ruleId}: not loadable as a DAST rule`);
        continue;
      }
      for (const exp of testCase.expected.detections.filter((d) => d.ruleId === ruleId)) {
        const observation = testCase.fixture.observation ?? {};
        const matched = evalDastCheck(rule.check, observation) === true;
        const evidenceOk = matched && JSON.stringify(observation).includes(exp.mustContain.slice(0, 32));
        if (evidenceOk || (matched && exp.mustContain === '*')) {
          result.actual.push({ ruleId, lineNo: exp.lineNo, matchedText: exp.mustContain });
        }
      }
    }
  } else {
    // line-regex mode: run each detector's declared pattern over fixture lines.
    for (const ruleId of uniqueRuleIds) {
      const rule = loadRule(root, ruleId);
      if (rule === null || rule.patterns === undefined) {
        result.notes.push(`detector ${ruleId}: not loadable as a line-regex rule`);
        continue;
      }
      const forbidden = (testCase.expected.forbiddenDetections ?? []).includes(ruleId);
      for (const [index, line] of testCase.fixture.lines.entries()) {
        const lineNo = index + 1;
        for (const pattern of rule.patterns) {
          // eslint-disable-next-line require-unicode-regexp
          const re = new RegExp(pattern.source, pattern.flags ?? '');
          const m = re.exec(line);
          if (m === null) continue;
          const record = { ruleId, lineNo, matchedText: m[0] };
          result.actual.push(record);
          if (forbidden) {
            result.notes.push(`forbidden detection ${ruleId} at line ${lineNo}`);
          }
        }
      }
    }
    result.actual.sort((a, b) => (a.ruleId < b.ruleId || (a.ruleId === b.ruleId && a.lineNo < b.lineNo) ? -1 : 1));
  }

  // Evidence-grounded matching against declared expectations.
  const remaining = [...result.expected];
  const matchedActual = new Set();
  for (const exp of [...remaining]) {
    const hitIndex = result.actual.findIndex((a, i) =>
      !matchedActual.has(i)
      && a.ruleId === exp.ruleId
      && a.lineNo === exp.lineNo
      && a.matchedText.includes(exp.mustContain));
    if (hitIndex >= 0) {
      matchedActual.add(hitIndex);
      remaining.splice(remaining.indexOf(exp), 1);
      if (gt.state === 'ASSESSED') result.truePositives += 1;
    } else if (gt.state === 'ASSESSED') {
      result.falseNegatives += 1;
      result.notes.push(`expected evidence not found: ${exp.ruleId} line ${exp.lineNo} containing ${JSON.stringify(exp.mustContain)}`);
    }
  }
  if (gt.state === 'ASSESSED') {
    const expectedLines = new Set(result.expected.map((e) => `${e.ruleId}:${e.lineNo}`));
    const forbidden = new Set(testCase.expected.forbiddenDetections ?? []);
    for (const [i, a] of result.actual.entries()) {
      if (matchedActual.has(i)) continue;
      const isForbiddenRule = forbidden.has(a.ruleId);
      const isUnexpectedLine = gt.class === 'no-issue' || !expectedLines.has(`${a.ruleId}:${a.lineNo}`);
      if (isForbiddenRule || isUnexpectedLine) {
        result.falsePositives += 1;
        result.notes.push(`false positive: ${a.ruleId} matched line ${a.lineNo} (${JSON.stringify(a.matchedText.slice(0, 40))}) where ground truth declares no issue`);
      }
    }
    result.outcome = result.falseNegatives === 0 && result.falsePositives === 0 ? 'PASS' : 'FAIL';
  } else {
    result.notes.push('ground truth UNASSESSED — observed detections recorded but not scored');
  }
  return result;
}

/**
 * Build the deterministic machine-readable report for a set of cases.
 * Metrics are computed over ASSESSED cases only and are explicitly labelled
 * as synthetic-population statistics.
 */
export function buildReport(root, cases) {
  const results = cases.map((c) => evaluateCase(root, c)).sort((a, b) => (a.id < b.id ? -1 : 1));
  const assessed = results.filter((r) => r.groundTruthState === 'ASSESSED');
  const unassessed = results.filter((r) => r.groundTruthState === 'UNASSESSED');
  const tp = assessed.reduce((n, r) => n + r.truePositives, 0);
  const fn = assessed.reduce((n, r) => n + r.falseNegatives, 0);
  const fp = assessed.reduce((n, r) => n + r.falsePositives, 0);
  const recall = tp + fn > 0 ? Number((tp / (tp + fn)).toFixed(4)) : null;
  const precision = tp + fp > 0 ? Number((tp / (tp + fp)).toFixed(4)) : null;
  return {
    schemaVersion: EVAL_REPORT_SCHEMA,
    population: 'synthetic evaluation cases in data/eval-cases (test-only fixtures; NOT real vulnerability intelligence)',
    disclaimer: 'Metrics describe this synthetic case population only. They are not real-world effectiveness estimates and must never be extrapolated.',
    casesTotal: results.length,
    assessedCases: assessed.length,
    unassessedCases: unassessed.length,
    counts: { truePositives: tp, falseNegatives: fn, falsePositives: fp },
    metrics: {
      scope: `${assessed.length} assessed synthetic cases (UNASSESSED excluded)`,
      recall,
      precision,
    },
    caseOutcomes: {
      PASS: assessed.filter((r) => r.outcome === 'PASS').map((r) => r.id),
      FAIL: assessed.filter((r) => r.outcome === 'FAIL').map((r) => r.id),
      UNASSESSED: unassessed.map((r) => r.id),
    },
    results,
  };
}
